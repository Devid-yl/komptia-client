"""
Validator du graphe DAG d'une automatisation Komptia.

Applique les regles de validation definies en docs/design_automations_dag.md §1.5 :

Deux niveaux de validation (importants pour l'UX) :
- `validate_structural` : appliquee a chaque save d'edge/node. Empeche les
  etats techniquement incoherents (cycles, types incompatibles, self-loop).
  Autorise les graphes en construction (orphelins, pas de source/sink).
- `validate_completeness` : appliquee au moment de l'activation (toggle
  Actif). Verifie qu'un workflow est pret a tourner (au moins une source,
  au moins un sink, pas d'orphelin, pas de double envoi email, etc.).

Tous les validators retournent `List[ValidationError]`. Aucune exception
n'est levee — c'est au caller de decider quoi faire des erreurs (rejet 400
avec liste, ou warning en bulk).

Design :
- **Pur** : aucune dependance sur la session DB. Prend des dicts ou des
  objets ORM charges (steps et edges eager-loaded). Testable en unite
  sans DB.
- **Generique** : ne hardcode AUCUN nom de table/colonne Sage. La seule
  connaissance metier est la signature des node types (NODE_TYPE_SIGNATURES
  ci-dessous), tiree du design doc.
- **Fail-closed** : type de node inconnu → validation KO avec suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Set, Tuple

# =============================================================================
# Signatures des types de nodes (cf. design_automations_dag.md §1.2)
# =============================================================================

# Chaque node type declare :
#   - `inputs` : types de donnees acceptes en entree (ou [] si source).
#   - `outputs` : types de donnees produits en sortie (ou [] si sink).
#   - `is_source` : True si node racine (pas de parent attendu).
#   - `is_sink` : True si node terminal (pas d'enfant attendu).
#
# Types de donnees : "workbook", "report_file", "trigger" (cf. §1.1).

NODE_TYPE_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # --- Sources (0 parent, produit workbook) ---
    # `trigger` ajoute en outputs : un step source peut emettre un signal
    # « j'ai fini » sans transmettre ses donnees au child (cf. data_type
    # "trigger" — sequencing pur). Les sources gardent `inputs=[]` (la
    # contrainte EDGE_TARGETS_SOURCE refuse toute arete entrante).
    "extract_sql": {
        "inputs": [],
        "outputs": ["workbook", "trigger"],
        "is_source": True,
        "is_sink": False,
    },
    "load_workbook": {
        "inputs": [],
        "outputs": ["workbook", "trigger"],
        "is_source": True,
        "is_sink": False,
    },
    "load_saved_query": {
        "inputs": [],
        "outputs": ["workbook", "trigger"],
        "is_source": True,
        "is_sink": False,
    },
    # --- Format (workbook -> workbook). format_copilot pilote par
    # instruction NL via le copilot_agent (sera etendu pour couvrir un
    # maximum d'actions automatisables — cf. docs/design_format_via_copilot.md).
    # `trigger` accepte en input : permet « format quand step X a fini »
    # sans recevoir les donnees de X (utile pour fan-in mixte).
    "format_copilot": {
        "inputs": ["workbook", "trigger"],
        "outputs": ["workbook", "trigger"],
        "is_source": False,
        "is_sink": False,
    },
    # --- Agent IA décideur (StepType.IRIS, livraison 2026-05-27) ---
    # Iris (le même que sur /iris) invoqué en backend headless pour PRENDRE
    # DES DÉCISIONS (router, skip steps aval, écrire variables interpolables,
    # abort). Il NE produit PAS de données : `Output = input_workbook tel quel`
    # (pass-through, cf. executor.py step_type=="iris"). Même contrat I/O que
    # format_copilot (workbook|trigger en in/out, ni source ni sink) — il
    # s'insère au milieu du DAG entre une source et les sorties.
    # A7-C1 : son ABSENCE de NODE_TYPE_SIGNATURES rendait toute automation iris
    # non-éditable (edge POST → UNKNOWN_NODE_TYPE 400) ET inactivable
    # (validate_structural court-circuite l'activation) alors que la palette
    # l'expose (available=True) et que l'executor l'implémente — promesse cassée.
    "iris": {
        "inputs": ["workbook", "trigger"],
        "outputs": ["workbook", "trigger"],
        "is_source": False,
        "is_sink": False,
    },
    # --- Sorties ---
    "report": {
        # Rapport PDF analyse par l'IA (mode unique). Le sink "report" est
        # terminal (pas d'enfant) ou alimente un email aval.
        "inputs": ["workbook", "trigger"],
        "outputs": ["report_file", "trigger"],
        "is_source": False,
        "is_sink": False,
    },
    "export_workbook": {
        # Export plat csv/excel (sans IA). Sink terminal ou alimente email.
        "inputs": ["workbook", "trigger"],
        "outputs": ["report_file", "trigger"],
        "is_source": False,
        "is_sink": False,
    },
    "email": {
        # Email accepte trois types d'inputs :
        # - report_file : PDF (report) ou xlsx/csv (export_workbook) deja
        #   ecrits sur disque par le sink amont → attaches tels quels.
        # - workbook   : produit en memoire par les sources/format. Le
        #   runtime convertit implicitement en xlsx tmp via
        #   `_generate_workbook_export` au moment de l'envoi (cf. executor
        #   step_type=="email"). UX : tirer un edge `Format → Email`
        #   marche directement, plus besoin d'inserer un Export
        #   intermediaire pour le 80% des cas.
        # - trigger    : sequencing pur — l'email s'envoie quand le parent
        #   a fini, mais sans piece jointe issue de ce parent (utile pour
        #   notifier sans inclure les donnees, ou attendre une autre
        #   branche du DAG avant d'envoyer).
        # Outputs : `trigger` permet « envoyer mail puis declencher step
        # suivant sans donnees » (cf. vision David : « ça ferait la meme
        # chose pour les sorties des étapes mail »).
        "inputs": ["report_file", "workbook", "trigger"],
        "outputs": ["trigger"],
        "is_source": False,
        "is_sink": True,
    },
    "email_wait_response": {
        # Envoi mail a UN destinataire avec lien tokenise puis ATTENTE
        # de la reponse externe. PAS un sink : produit un output workbook
        # contenant la reponse (texte + fichier upload converti en
        # classeur), exploitable par les steps suivants.
        # Inputs : meme contrat que `email` standard (workbook | report_file
        # converti en pj du mail si include_inputs_as_attachments=True ;
        # ignores sinon — la connection sert juste a sequencer).
        # Outputs : workbook (la reponse) ou trigger (juste signal de
        # completion).
        # is_sink=False : ce step a des outputs, donc peut alimenter
        # report/export/email/save_to_datastore en aval (ex : envoyer
        # au comptable demander un CSV, recevoir le CSV, le merger avec
        # une autre source, generer un rapport).
        "inputs": ["report_file", "workbook", "trigger"],
        "outputs": ["workbook", "trigger"],
        "is_source": False,
        "is_sink": False,
    },
    "save_to_datastore": {
        # Sauvegarde dans le datastore filesystem.
        # - workbook    → serialise en .afz.json (cas sources/format en amont)
        # - report_file → copy le fichier dans le datastore avec son
        #                 extension d'origine (cas archive PDF/Excel/CSV
        #                 depuis report ou export_workbook en amont)
        # - trigger     → sequencing pur (rien a sauvegarder, juste attendre).
        #                 Edge case rare mais coherent avec le pattern.
        # Sink terminal — pas d'aval (outputs=[]). Le fichier persiste
        # cross-execution et peut etre charge par un load_workbook d'un
        # autre workflow (cas .afz.json) ou consulte manuellement via
        # /datastore.
        "inputs": ["workbook", "report_file", "trigger"],
        "outputs": [],
        "is_source": False,
        "is_sink": True,
    },
}

# Types de nodes reconnus comme sinks pour la regle "au moins un sink".
# Tout ce qui produit un livrable (report PDF / export csv-excel / email /
# sauvegarde datastore) compte comme un sink valide.
TERMINAL_NODE_TYPES: frozenset = frozenset(
    {"email", "report", "export_workbook", "save_to_datastore"}
)


# =============================================================================
# Types publics
# =============================================================================


@dataclass(frozen=True)
class ValidationError:
    """Une erreur de validation du graphe.

    `code` est stable (parse-able par le frontend pour traductions).
    `message` est en francais, destine a l'utilisateur.
    `context` contient des ids/noms pour pointer precisement le probleme.
    """

    code: str
    message: str
    context: Dict[str, Any]


# =============================================================================
# Normalisation des entrees
# =============================================================================

# Un `Node` est un dict au minimum : {id, step_type, name}.
# Un `Edge` est un dict : {id, from_step_id, to_step_id, data_type}.
# On accepte aussi les objets ORM (AutomationStep, AutomationEdge) via
# duck-typing (attributs identiques).


def _node_attr(node: Any, key: str, default: Any = None) -> Any:
    if isinstance(node, dict):
        return node.get(key, default)
    return getattr(node, key, default)


def _edge_attr(edge: Any, key: str, default: Any = None) -> Any:
    if isinstance(edge, dict):
        return edge.get(key, default)
    return getattr(edge, key, default)


def _nodes_by_id(nodes: Iterable[Any]) -> Dict[int, Any]:
    return {int(_node_attr(n, "id")): n for n in nodes if _node_attr(n, "id") is not None}


# =============================================================================
# Helpers de detection
# =============================================================================


def _detect_cycles(edges: Iterable[Any], node_ids: Set[int]) -> List[Tuple[int, int]]:
    """DFS ITERATIF sur le graphe, retourne les back-edges detectees.

    Utilise une pile explicite plutot qu'une recursion Python pour eviter
    `RecursionError` sur un workflow avec 1000+ steps chaines (defaut
    sys.setrecursionlimit = 1000). Chaque edge dans le retour represente
    une back-edge (arete qui ferme un cycle).
    """
    # Construire la liste d'adjacence
    adj: Dict[int, List[Tuple[int, int]]] = {nid: [] for nid in node_ids}
    for edge in edges:
        frm = _edge_attr(edge, "from_step_id")
        to = _edge_attr(edge, "to_step_id")
        if frm is None or to is None:
            continue
        try:
            frm_int, to_int = int(frm), int(to)
        except (TypeError, ValueError):
            continue
        if frm_int in adj:
            adj[frm_int].append((frm_int, to_int))

    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[int, int] = {nid: WHITE for nid in node_ids}
    cycle_edges: Set[Tuple[int, int]] = set()

    # DFS iteratif : chaque entree de la pile est (node, iter_sur_voisins).
    # On passe en BLACK quand tous les voisins ont ete visites.
    for root in node_ids:
        if color.get(root) != WHITE:
            continue
        stack: List[Tuple[int, Any]] = [(root, iter(adj.get(root, [])))]
        color[root] = GRAY
        while stack:
            node, neighbors = stack[-1]
            advanced = False
            for frm, to in neighbors:
                if to not in color:
                    continue
                if color[to] == GRAY:
                    # Back-edge = cycle ferme
                    cycle_edges.add((frm, to))
                elif color[to] == WHITE:
                    color[to] = GRAY
                    stack.append((to, iter(adj.get(to, []))))
                    advanced = True
                    break
                # color[to] == BLACK : deja entierement visite, ignore
            if not advanced:
                color[node] = BLACK
                stack.pop()

    return list(cycle_edges)


def _reachable_from(start: int, adj: Dict[int, List[int]]) -> Set[int]:
    """BFS/DFS: renvoie l'ensemble des nodes atteignables depuis `start`."""
    seen: Set[int] = {start}
    stack = [start]
    while stack:
        cur = stack.pop()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


# =============================================================================
# Validation structurelle (appliquee a chaque save)
# =============================================================================


def validate_structural(
    nodes: Iterable[Any],
    edges: Iterable[Any],
) -> List[ValidationError]:
    """Verifie la structure du graphe a la sauvegarde.

    Regles (cf. docs/design_automations_dag.md §1.5) :
    1. Acyclique (pas de cycle)
    2. Pas d'edge vers un node inexistant
    3. Pas de self-loop (from_step_id == to_step_id)
    4. Types d'edges coherents avec les signatures source/cible
    5. Fan-in coherent : tous les parents d'un node ont le meme data_type
    6. Pas de duplication d'edge (meme (from, to))
    7. Type de node reconnu dans NODE_TYPE_SIGNATURES

    Ne verifie PAS (reserve a validate_completeness) :
    - Presence d'une source ou d'un sink (un graphe en construction peut
      etre temporairement sans source)
    - Orphelins (nodes isoles)
    - Collision destinataires email (multi-email overlap)
    """
    errors: List[ValidationError] = []

    nodes_list = list(nodes)
    edges_list = list(edges)

    nodes_by_id = _nodes_by_id(nodes_list)
    node_ids = set(nodes_by_id.keys())

    # --- 7. Type de node reconnu ---
    for node in nodes_list:
        step_type = _node_attr(node, "step_type")
        if step_type and step_type not in NODE_TYPE_SIGNATURES:
            errors.append(
                ValidationError(
                    code="UNKNOWN_NODE_TYPE",
                    message=(
                        f"Type de node inconnu: '{step_type}'. "
                        f"Types valides: {sorted(NODE_TYPE_SIGNATURES.keys())}"
                    ),
                    context={
                        "node_id": _node_attr(node, "id"),
                        "step_type": step_type,
                    },
                )
            )

    # --- 2. Edges vers nodes inexistants + 3. self-loops + 6. duplications ---
    seen_edges: Set[Tuple[int, int]] = set()
    for edge in edges_list:
        frm = _edge_attr(edge, "from_step_id")
        to = _edge_attr(edge, "to_step_id")
        if frm is None or to is None:
            errors.append(
                ValidationError(
                    code="EDGE_MISSING_ENDPOINT",
                    message="Arete sans source ou cible definie",
                    context={"edge_id": _edge_attr(edge, "id")},
                )
            )
            continue

        frm_int, to_int = int(frm), int(to)
        # 3. self-loop
        if frm_int == to_int:
            errors.append(
                ValidationError(
                    code="EDGE_SELF_LOOP",
                    message=f"Arete pointe vers elle-meme (node {frm_int})",
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "node_id": frm_int,
                    },
                )
            )
            continue

        # 2. endpoints existent
        if frm_int not in node_ids:
            errors.append(
                ValidationError(
                    code="EDGE_FROM_UNKNOWN",
                    message=f"Arete depuis node inexistant: {frm_int}",
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "node_id": frm_int,
                    },
                )
            )
            continue
        if to_int not in node_ids:
            errors.append(
                ValidationError(
                    code="EDGE_TO_UNKNOWN",
                    message=f"Arete vers node inexistant: {to_int}",
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "node_id": to_int,
                    },
                )
            )
            continue

        # 6. duplication
        key = (frm_int, to_int)
        if key in seen_edges:
            errors.append(
                ValidationError(
                    code="EDGE_DUPLICATE",
                    message=f"Arete dupliquee entre {frm_int} et {to_int}",
                    context={
                        "from_step_id": frm_int,
                        "to_step_id": to_int,
                    },
                )
            )
        seen_edges.add(key)

    # --- 1. Cycles ---
    cycle_pairs = _detect_cycles(edges_list, node_ids)
    for frm, to in cycle_pairs:
        errors.append(
            ValidationError(
                code="CYCLE_DETECTED",
                message=f"Cycle detecte via l'arete {frm} -> {to}",
                context={"from_step_id": frm, "to_step_id": to},
            )
        )

    # --- 4. Types d'edges coherents ---
    for edge in edges_list:
        frm = _edge_attr(edge, "from_step_id")
        to = _edge_attr(edge, "to_step_id")
        declared_type = _edge_attr(edge, "data_type")
        if frm is None or to is None or declared_type is None:
            continue
        frm_int, to_int = int(frm), int(to)
        if frm_int not in nodes_by_id or to_int not in nodes_by_id:
            continue  # deja signale plus haut

        src_type = _node_attr(nodes_by_id[frm_int], "step_type")
        dst_type = _node_attr(nodes_by_id[to_int], "step_type")
        src_sig = NODE_TYPE_SIGNATURES.get(src_type)
        dst_sig = NODE_TYPE_SIGNATURES.get(dst_type)

        if src_sig is None or dst_sig is None:
            continue  # type inconnu deja signale

        # --- Source produit-elle ce type ? ---
        # `outputs=[]` (sink) → aucune arete sortante ne peut etre valide.
        # `outputs` non vide mais sans `declared_type` → mismatch.
        if not src_sig["outputs"]:
            errors.append(
                ValidationError(
                    code="EDGE_FROM_SINK",
                    message=(
                        f"Arete sortante depuis un sink '{src_type}' interdite "
                        f"(les sinks ne produisent rien)"
                    ),
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "source_type": src_type,
                    },
                )
            )
        elif declared_type not in src_sig["outputs"]:
            errors.append(
                ValidationError(
                    code="EDGE_TYPE_MISMATCH_SOURCE",
                    message=(
                        f"Arete de type '{declared_type}' mais le node source "
                        f"'{src_type}' produit {src_sig['outputs']}"
                    ),
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "declared_type": declared_type,
                        "source_outputs": src_sig["outputs"],
                    },
                )
            )

        # --- Cible accepte-t-elle ce type ? ---
        # `inputs=[]` (source) → aucune arete entrante ne peut etre valide.
        # **Pre-existant cassé** : avant le fix de cette session, le check
        # etait `if dst_sig["inputs"] and declared_type not in dst_sig["inputs"]`
        # → liste vide etait falsy → check skip → 28 faux positifs autorisaient
        # `extract_sql -> extract_sql`, `report -> load_workbook`, etc. Le
        # runtime ignorait silencieusement le workbook recu, mais l'utilisateur
        # croyait que les donnees passaient. Cf. /brainstorm 2026-05-07.
        if not dst_sig["inputs"]:
            errors.append(
                ValidationError(
                    code="EDGE_TARGETS_SOURCE",
                    message=(
                        f"Arete entrante vers une source '{dst_type}' interdite "
                        f"(les sources n'acceptent pas de parent)"
                    ),
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "target_type": dst_type,
                    },
                )
            )
        elif declared_type not in dst_sig["inputs"]:
            errors.append(
                ValidationError(
                    code="EDGE_TYPE_MISMATCH_TARGET",
                    message=(
                        f"Arete de type '{declared_type}' mais le node cible "
                        f"'{dst_type}' accepte {dst_sig['inputs']}"
                    ),
                    context={
                        "edge_id": _edge_attr(edge, "id"),
                        "declared_type": declared_type,
                        "target_inputs": dst_sig["inputs"],
                    },
                )
            )

    # --- 5. Fan-in coherent (tous les parents d'un node ont meme data_type) ---
    # Note : `trigger` est exclu du check parce qu'il represente un
    # sequencing pur (pas de transmission de donnees). Mixer un parent
    # `workbook` avec un parent `trigger` est autorise et coherent : le
    # node recoit les donnees du parent workbook + attend la completion
    # du parent trigger avant de demarrer. Sans cette exception, on
    # forcerait l'utilisateur a lever artificiellement la difference de
    # types entre branches du DAG.
    parents_by_node: Dict[int, List[Tuple[Any, str]]] = {}
    for edge in edges_list:
        to = _edge_attr(edge, "to_step_id")
        dtype = _edge_attr(edge, "data_type")
        if to is None or dtype is None:
            continue
        parents_by_node.setdefault(int(to), []).append((edge, dtype))
    for node_id, parent_edges in parents_by_node.items():
        # Exclure trigger du check : seuls les data_types reels (workbook,
        # report_file) doivent etre coherents entre eux.
        types_set = {dtype for _, dtype in parent_edges if dtype != "trigger"}
        if len(types_set) > 1:
            errors.append(
                ValidationError(
                    code="FAN_IN_MIXED_TYPES",
                    message=(
                        f"Node {node_id} recoit des aretes de types differents: "
                        f"{sorted(types_set)}. Tous les parents doivent avoir le meme type."
                    ),
                    context={
                        "node_id": node_id,
                        "types": sorted(types_set),
                    },
                )
            )

    return errors


# =============================================================================
# Validation de completude (appliquee a l'activation)
# =============================================================================


def validate_completeness(
    nodes: Iterable[Any],
    edges: Iterable[Any],
) -> List[ValidationError]:
    """Verifie qu'un workflow est pret a tourner.

    Presume que `validate_structural` a deja passe (cycles, types, etc.).
    Ajoute les verifications de presence :
    1. Au moins une source (node sans parent avec `is_source=True` ou sans parent)
    2. Au moins un sink (node sans enfant terminal : email/report, ou analyse)
    3. Pas de node orphelin (tout node atteignable depuis une source)
    4. Double envoi detecte (2+ nodes email avec destinataires qui se
       recouvrent — cf. §3.4)
    5. Email-loops : un node email qui pointe vers un webhook du meme
       workflow (cf. §3.8)
    6. Collisions de tab_label entre sources qui convergent vers le meme
       format (cf. §3.2) — warning non fatal
    """
    errors: List[ValidationError] = []

    nodes_list = list(nodes)
    edges_list = list(edges)
    nodes_by_id = _nodes_by_id(nodes_list)
    node_ids = set(nodes_by_id.keys())

    # --- 0. Step types non-disponibles (Phase 3d : format_copilot stub) ---
    # Refuse l'activation si un node utilise un type marque
    # `available=False` dans STEP_TYPE_META. Defense-in-depth contre un
    # workflow construit avant que le type soit disable, ou un import
    # JSON manuel qui contournerait la palette frontend.
    try:
        from app.models.automation_step import STEP_TYPE_META, AutomationStep, StepType

        for nid in node_ids:
            stype = _node_attr(nodes_by_id[nid], "step_type")
            try:
                meta = STEP_TYPE_META.get(StepType(stype))
            except (ValueError, TypeError):
                meta = None
            if meta and meta.get("available", True) is False:
                errors.append(
                    ValidationError(
                        code="STEP_TYPE_NOT_AVAILABLE",
                        message=(
                            f"Le type d'etape '{stype}' n'est pas encore disponible "
                            "pour activation. Voir documentation."
                        ),
                        context={"node_id": nid, "step_type": stype},
                    )
                )

        # Verification des `required` fields a l'activation. Phase 3b-2 : la
        # creation/edition cote canvas accepte des configs vides
        # (`partial=True`) pour permettre le drag-drop progressif. C'est ici
        # qu'on rattrape : un node avec un required manquant ne peut pas
        # passer en active. Le check delegue a `AutomationStep.validate()`
        # pour eviter la duplication de logique entre creation et activation.
        for nid in node_ids:
            node = nodes_by_id[nid]
            # Real-review #6 cycle 23 : skip les steps `is_enabled=False`.
            # Le runtime DAG les ignore complètement (cf. `dag_executor.py`
            # disabled_ids → propagated skipped). Si on les valide ici, on
            # bloque l'activation pour une auto où un step désactivé a une
            # config incomplète — alors qu'au runtime il ne tournerait jamais.
            # Default to enabled if attribute absent (rétro-compat dicts API
            # qui n'envoient pas is_enabled).
            is_enabled = _node_attr(node, "is_enabled", True)
            if is_enabled is False:
                continue
            stype = _node_attr(node, "step_type")
            cfg = _node_attr(node, "config") or {}
            try:
                # Stub minimal : on instancie un AutomationStep transient
                # sans toucher a la session DB (les noeuds passes peuvent
                # etre des ORM ou des dicts d'API). On reutilise sa methode
                # de validation pour rester DRY.
                stub = AutomationStep(
                    step_type=stype if isinstance(stype, str) else getattr(stype, "value", ""),
                    config=cfg if isinstance(cfg, dict) else {},
                )
                stub_errors = stub.validate(partial=False)
            except (ValueError, TypeError):
                stub_errors = []
            for err_msg in stub_errors:
                errors.append(
                    ValidationError(
                        code="STEP_CONFIG_INCOMPLETE",
                        message=(f"Etape '{_node_attr(node, 'name', stype)}' : " f"{err_msg}"),
                        context={
                            "node_id": nid,
                            "step_type": (
                                stype
                                if isinstance(stype, str)
                                else getattr(stype, "value", str(stype))
                            ),
                        },
                    )
                )

            # #63 (A7-F2-résidu) + V8 (2026-06-10) — Type-check générique des
            # champs typés string/text/select. Un tel champ qui reçoit une LISTE
            # (import/API hand-édité ; le canvas envoie toujours un string) passe
            # ``validate(partial=False)`` puis CRASHE au runtime (executor :
            # ``value.strip()`` → AttributeError sur une list). On rattrape à
            # l'activation, génériquement — TOUS les step_types, TOUS les champs
            # string (pas un patch spécial ``email.to``).
            #
            # V8 : étendu aux champs NON-``required`` (avant, seuls les required
            # étaient type-checkés → ``report.title`` / ``report.prompt`` /
            # ``export_workbook.filename`` (string non-required) passaient en
            # liste et crashaient au run, executor.py:3167/3228/4069). La
            # PRÉSENCE des required reste déléguée à ``validate()`` ci-dessus ;
            # ici on ne valide QUE le TYPE d'une valeur PRÉSENTE (absent/vide →
            # ``continue``), donc étendre aux non-required n'impose aucune
            # présence — ça empêche juste un type faux de passer silencieusement.
            try:
                _meta_t = STEP_TYPE_META.get(StepType(stype)) if isinstance(stype, str) else None
            except (ValueError, TypeError):
                _meta_t = None
            for _fname, _fspec in (_meta_t or {}).get("config_schema", {}).items():
                if not isinstance(_fspec, dict):
                    continue
                if _fspec.get("type") not in ("string", "text", "select"):
                    continue
                _val = cfg.get(_fname)
                if _val is None or _val == "":
                    continue  # absent/vide : présence des required gérée par validate()
                if not isinstance(_val, str):
                    errors.append(
                        ValidationError(
                            code="STEP_CONFIG_INCOMPLETE",
                            message=(
                                f"Etape '{_node_attr(node, 'name', stype)}' : le champ "
                                f"'{_fspec.get('label', _fname)}' doit etre du texte "
                                f"(recu : {type(_val).__name__})."
                            ),
                            context={
                                "node_id": nid,
                                "step_type": (
                                    stype
                                    if isinstance(stype, str)
                                    else getattr(stype, "value", str(stype))
                                ),
                            },
                        )
                    )
    except ImportError:
        # Import circulaire defensif : si le model n'est pas chargeable
        # (ex: tests isoles), on skip ce check (les autres validations
        # restent en place).
        pass

    # Construire les adjacences (toutes edges, tous nodes — utilisees par les
    # checks email_* en aval qui valident la config statique).
    out_adj: Dict[int, List[int]] = {nid: [] for nid in node_ids}
    in_adj: Dict[int, List[int]] = {nid: [] for nid in node_ids}
    for edge in edges_list:
        frm = _edge_attr(edge, "from_step_id")
        to = _edge_attr(edge, "to_step_id")
        if frm is None or to is None:
            continue
        if int(frm) in node_ids and int(to) in node_ids:
            out_adj[int(frm)].append(int(to))
            in_adj[int(to)].append(int(frm))

    # Finding 1779251680-10 : aligner sources/sinks/reachability sur le
    # runtime DAG (dag_executor.py) qui ignore is_enabled=False et poisonne
    # les subtrees. Sans filtrage, une auto avec une source désactivée
    # passait la validation puis ne tournait pas silencieusement.
    # Convention is_enabled : meme pattern que L614 (STEP_CONFIG_INCOMPLETE).
    # `is not False` → None et True traités comme enabled (rétro-compat dicts
    # API qui n'envoient pas le champ).
    enabled_node_ids: Set[int] = {
        nid for nid in node_ids if _node_attr(nodes_by_id[nid], "is_enabled", True) is not False
    }
    # Adjacence enabled-only : une edge n'est considérée que si SES DEUX
    # extrémités sont enabled. Sinon la reachability marcherait à travers
    # les disabled (incohérent avec le poison runtime).
    out_adj_enabled: Dict[int, List[int]] = {nid: [] for nid in enabled_node_ids}
    in_adj_enabled: Dict[int, List[int]] = {nid: [] for nid in enabled_node_ids}
    for nid, children in out_adj.items():
        if nid not in enabled_node_ids:
            continue
        for child in children:
            if child in enabled_node_ids:
                out_adj_enabled[nid].append(child)
                in_adj_enabled[child].append(nid)

    # --- 1. Au moins une source enabled ---
    sources = [
        nid
        for nid in enabled_node_ids
        if not in_adj_enabled.get(nid)
        and NODE_TYPE_SIGNATURES.get(_node_attr(nodes_by_id[nid], "step_type"), {}).get("is_source")
    ]
    if not sources:
        errors.append(
            ValidationError(
                code="NO_SOURCE",
                message="Le workflow doit contenir au moins un node source (extract_*)",
                context={},
            )
        )

    # --- 2. Au moins un sink enabled (terminal : email, report, ...) ---
    # Utilise out_adj_enabled : un node peut etre terminal au runtime meme
    # s'il a une edge sortante vers un node disabled (qui ne tournera pas).
    sinks = [
        nid
        for nid in enabled_node_ids
        if (
            _node_attr(nodes_by_id[nid], "step_type") in TERMINAL_NODE_TYPES
            and not out_adj_enabled.get(nid)
        )
    ]
    if not sinks:
        errors.append(
            ValidationError(
                code="NO_SINK",
                message=(
                    "Le workflow doit contenir au moins un node terminal (email ou report) "
                    "sans enfant"
                ),
                context={},
            )
        )

    # --- 3. Pas de node orphelin (tout node enabled atteignable depuis une source) ---
    # Reachability via out_adj_enabled : un node atteignable uniquement par
    # un chemin traversant un disabled est inactionnable au runtime → orphan.
    reachable: Set[int] = set()
    for src in sources:
        reachable.update(_reachable_from(src, out_adj_enabled))
    orphans = enabled_node_ids - reachable
    # Si aucune source, tous les nodes sont "orphelins" — on ne redouble pas
    # l'erreur, NO_SOURCE a deja ete signale.
    if sources and orphans:
        for nid in sorted(orphans):
            errors.append(
                ValidationError(
                    code="ORPHAN_NODE",
                    message=(
                        f"Node {nid} ('{_node_attr(nodes_by_id[nid], 'name', '?')}') "
                        f"n'est pas atteignable depuis une source"
                    ),
                    context={
                        "node_id": nid,
                        "step_type": _node_attr(nodes_by_id[nid], "step_type"),
                    },
                )
            )

    # --- 4. Double envoi (email destinataires qui se recouvrent) ---
    # #24 fix 2026-06-11 — ne considérer que les steps email ENABLED. Avant, ce
    # bloc itérait ``node_ids`` (TOUS), donc un step email DÉSACTIVÉ (ignoré au
    # runtime DAG) déclenchait à tort EMAIL_NO_RECIPIENT (config vide bloque
    # l'activation) ET EMAIL_DOUBLE_DELIVERY (ses destinataires « recouvrent »
    # un email actif = faux positif). On réutilise ``enabled_node_ids`` (SSoT
    # déjà calculé L737), cohérent avec le check STEP_CONFIG_INCOMPLETE (L632)
    # et l'adjacence enabled-only de la reachability.
    email_nodes = [
        (nid, nodes_by_id[nid])
        for nid in node_ids
        if nid in enabled_node_ids
        and _node_attr(nodes_by_id[nid], "step_type") == "email"
    ]
    email_recipients: List[Tuple[int, Set[str]]] = []
    for nid, node in email_nodes:
        cfg = _node_attr(node, "config") or {}
        recips: Set[str] = set()
        for key in ("to", "cc", "bcc", "recipients"):
            val = cfg.get(key)
            if isinstance(val, list):
                # Filtre POST-strip pour rejeter les whitespace-only (`" "`,
                # `"\t"`) qui passaient avant le check `if v` (truthy non-vide).
                # Sans ça, un user qui tape un espace voit recips non-vide
                # et l'activation acceptait silencieusement → crash runtime.
                for v in val:
                    if not v:
                        continue
                    cleaned = str(v).strip().lower()
                    if cleaned:
                        recips.add(cleaned)
            elif isinstance(val, str) and val.strip():
                recips.add(val.strip().lower())
        email_recipients.append((nid, recips))

    # --- 4a. Au moins UN destinataire par node email (composite required) ---
    # STEP_TYPE_META.email.config_schema ne marque aucun champ `required=True`
    # car ils sont alternatifs (to / cc / bcc / liste de diffusion). C'est ici
    # qu'on rattrape le check : un email sans aucun destinataire passerait
    # validate(partial=False) silencieusement et planterait au runtime avec
    # une erreur cryptique. On bloque l'activation tôt.
    for nid, recs in email_recipients:
        cfg = _node_attr(nodes_by_id[nid], "config") or {}
        has_distribution_list = bool(cfg.get("from_distribution_list_id"))
        if not recs and not has_distribution_list:
            errors.append(
                ValidationError(
                    code="EMAIL_NO_RECIPIENT",
                    message=(
                        f"Etape email '{_node_attr(nodes_by_id[nid], 'name', '?')}': "
                        "au moins un destinataire est requis (to, cc, bcc, ou liste de diffusion)."
                    ),
                    context={"node_id": nid, "step_type": "email"},
                )
            )

    for i, (nid_a, recs_a) in enumerate(email_recipients):
        for nid_b, recs_b in email_recipients[i + 1 :]:
            overlap = recs_a & recs_b
            if overlap:
                errors.append(
                    ValidationError(
                        code="EMAIL_DOUBLE_DELIVERY",
                        message=(
                            f"Destinataires en commun entre nodes email {nid_a} et {nid_b}: "
                            f"{sorted(overlap)}. Risque de double envoi."
                        ),
                        context={
                            "node_a_id": nid_a,
                            "node_b_id": nid_b,
                            "shared_recipients": sorted(overlap),
                        },
                    )
                )

    # --- 5. Email vers webhook du meme workflow (boucle) ---
    # Heuristique : si un node email a un destinataire qui contient
    # "/webhook/" et un token, on signale.
    for nid, recs in email_recipients:
        for r in recs:
            if "/webhook/" in r:
                errors.append(
                    ValidationError(
                        code="EMAIL_WEBHOOK_LOOP",
                        message=(
                            f"Node email {nid} envoie vers une URL de type webhook ('{r}'). "
                            f"Risque de boucle infinie si elle re-declenche ce workflow."
                        ),
                        context={"node_id": nid, "recipient": r},
                    )
                )

    # -------------------------------------------------------------------------
    # NOTE : la regle "collision de tab_label sur node `format`" du design §3.2
    # est reportee a la Phase 2. Le node type `format` n'existe pas encore
    # dans NODE_TYPE_SIGNATURES (il sera ajoute quand le copilot_agent sera
    # integre comme node de transformation executable). Implementer la regle
    # maintenant serait du code mort (filtre sur un type absent). A reactiver
    # quand `format` sera ajoute aux signatures et a l'enum StepType.
    # -------------------------------------------------------------------------

    return errors


# =============================================================================
# Facade : combiner les deux validations
# =============================================================================


def validate_all(
    nodes: Iterable[Any],
    edges: Iterable[Any],
    *,
    for_activation: bool = False,
) -> List[ValidationError]:
    """Applique la validation structurelle, puis (optionnel) la completude.

    Args:
        nodes: Liste des AutomationStep ou dicts equivalents.
        edges: Liste des AutomationEdge ou dicts equivalents.
        for_activation: Si True, applique aussi validate_completeness.
            Appeler True quand l'utilisateur tente de passer le workflow
            en is_active=True.

    Returns:
        Liste d'erreurs (vide si tout passe).
    """
    nodes_list = list(nodes)
    edges_list = list(edges)

    structural_errors = validate_structural(nodes_list, edges_list)
    if not for_activation:
        return structural_errors

    # Ne pas executer la completude si la structure est deja cassee — les
    # messages seraient trompeurs.
    if structural_errors:
        return structural_errors

    return validate_completeness(nodes_list, edges_list)


# =============================================================================
# Helper : format JSON pour API
# =============================================================================


def errors_to_json(errors: List[ValidationError]) -> List[Dict[str, Any]]:
    """Serialise les erreurs pour une response API."""
    return [{"code": err.code, "message": err.message, "context": err.context} for err in errors]
