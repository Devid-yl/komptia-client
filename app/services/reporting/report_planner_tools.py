"""Tools du report-planner agent — JSON schemas + handlers.

Pattern emprunté à ``app/services/ai/copilot_tools.py`` mais adapté aux
datasets génériques (``[{id, label, columns, rows}]``) consommés par le
report-AI — pas au format ``.afz.json`` du copilot.

Pourquoi un tool-loop pour le reporting ?
    Le mode oneshot (cf. ``llm_report_planner.plan_report``) sérialise tous
    les datasets en markdown dans UN SEUL prompt, ce qui plafonne au
    ``max_input_tokens`` du modèle actif (~2K sur Haiku 4.5, ~190K sur
    Sonnet 4). Pour un classeur de 100K+ lignes, l'utilisateur reçoit un
    400 « Données trop volumineuses ». Avec ce tool-loop, le LLM accède
    aux données en lazy via ``read_dataset_sample`` (60 lignes/call) ou
    en agrégé via ``aggregate_dataset`` (group-by Python sur la liste
    réelle de rows — scale O(n) jusqu'au cap mémoire de l'agent).

Les helpers d'agrégation/filtrage sont 100% Python (pas de SQL) car les
datasets peuvent venir d'Excel ou CSV uploadés (pas seulement SQL Server).
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Limites — alignées avec copilot_tools quand applicable + cohérentes avec
# llm_report_planner._validate_plan / _validate_section / _validate_chart.
# ---------------------------------------------------------------------------

#: Cap dur sur le nombre de lignes retournées par ``read_dataset_sample`` en
#: un seul appel. Aligné avec ``copilot_tools.handle_read_tab_rows`` (60).
#: L'LLM doit paginer s'il veut plus.
READ_SAMPLE_HARD_CAP = 60

#: Cap sur le nombre de valeurs distinctes échantillonnées par colonne
#: dans ``inspect_dataset``. Aligné avec ``copilot_workbook_loader._COL_DISTINCT_MAX_VALUES``.
INSPECT_DISTINCT_MAX_VALUES = 30

#: Scan max pour calculer ``distinct_count`` exact dans ``inspect_dataset``.
#: Au-delà, on s'arrête et on retourne une borne basse + ``distinct_truncated=True``.
#: Aligné avec ``copilot_workbook_loader._COL_DISTINCT_SCAN_LIMIT``.
INSPECT_SCAN_LIMIT = 5000

#: Cap dur sur le nombre de groupes retournés par ``aggregate_dataset``.
#: Au-delà, on tronque et on flag ``truncated=True``. Évite un OOM si l'LLM
#: groupe par une colonne haute-cardinalité (ex : email).
AGGREGATE_MAX_GROUPS = 1000

#: Cap dur sur le nombre de sections émises (cohérent avec
#: ``llm_report_planner._MAX_SECTIONS``).
MAX_SECTIONS_EMITTED = 20

#: Cap dur sur la longueur de l'intro (cohérent avec
#: ``llm_report_planner._MAX_INTRODUCTION_LEN``).
MAX_INTRO_LEN = 4000

#: Cap dur sur la longueur d'un titre (cohérent avec
#: ``llm_report_planner._MAX_TITLE_LEN``).
MAX_TITLE_LEN = 200


def _cap_with_notice(text: str, limit: int) -> str:
    """Tronque ``text`` à ``limit`` en SIGNALANT la coupe (#55 review).

    Le mode agent pré-coupait intro/titre EN SILENCE ici ; le marqueur n'arrivait
    donc jamais (la valeur arrivait déjà ≤ limit au validateur aval). On signale
    dès la pré-coupe avec le marqueur SSoT partagé de ``llm_report_planner``.
    Le double-marquage éventuel au ``_validate_plan`` aval se résout en UN seul
    marqueur : ``value[:limit]`` strip le marqueur posé au-delà de ``limit`` puis
    le ré-appose. Import paresseux pour éviter tout cycle au chargement module.
    """
    if not isinstance(text, str) or len(text) <= limit:
        return text
    from app.services.reporting.llm_report_planner import TRUNCATION_NOTICE

    return text[:limit] + TRUNCATION_NOTICE


# ---------------------------------------------------------------------------
# Tool definitions — Anthropic JSON Schema format, compatible OpenAI tool-calling.
# ---------------------------------------------------------------------------

REPORT_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_datasets",
        "description": (
            "Liste tous les jeux de données disponibles avec leurs métadonnées "
            "(id, label, nombre de lignes, colonnes). Ne retourne PAS les "
            "lignes elles-mêmes. Appelle ceci en PREMIER pour comprendre la "
            "structure avant toute analyse."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "inspect_dataset",
        "description": (
            "Inspecte la structure d'un dataset : pour chaque colonne, retourne "
            "le type détecté (numeric/text/date), le nombre de valeurs "
            "distinctes (capé à 5000 lignes scannées), un échantillon de "
            "30 valeurs distinctes max (texte) ou min/max (numérique). "
            "Utile pour décider d'une stratégie d'agrégation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dataset_id": {
                    "type": "integer",
                    "description": "id du dataset (cf. list_datasets)",
                },
            },
            "required": ["dataset_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "read_dataset_sample",
        "description": (
            "Lit un échantillon de lignes d'un dataset, indices 0-based, "
            "fenêtre [row_start, row_end) (Python slice — end exclusif). "
            "Cap dur à 60 lignes par appel. Pour explorer un gros dataset "
            "(>200 lignes), utilise plutôt aggregate_dataset ou count_rows_dataset "
            "— ne tente PAS de paginer toutes les lignes une par une."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dataset_id": {"type": "integer"},
                "row_start": {"type": "integer", "minimum": 0},
                "row_end": {"type": "integer", "minimum": 0},
            },
            "required": ["dataset_id", "row_start", "row_end"],
            "additionalProperties": False,
        },
    },
    {
        "name": "aggregate_dataset",
        "description": (
            "Agrège un dataset : group_by sur N colonnes catégorielles, "
            "calcule sum/avg/min/max/count d'une colonne numérique. "
            "Filtres optionnels via ``where`` (égalité simple par défaut). "
            "Retourne max 1000 groupes (tronqué si dépassé). C'est l'outil "
            "PRINCIPAL pour analyser un dataset volumineux — préfère-le à "
            "read_dataset_sample dès que row_count > 100."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dataset_id": {"type": "integer"},
                "group_by": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Liste de noms de colonnes (peut être vide pour un agrégat global)",
                },
                "value_column": {
                    "type": ["string", "null"],
                    "description": "Colonne numérique à agréger. Null/omis si agg='count'.",
                },
                "agg": {
                    "type": "string",
                    "enum": ["sum", "avg", "min", "max", "count"],
                },
                "where": {
                    "type": "object",
                    "description": (
                        "Filtres égalité par colonne, ex {'region': 'IDF'}. "
                        "Optionnel — si absent, agrège tout le dataset."
                    ),
                    "additionalProperties": True,
                },
            },
            "required": ["dataset_id", "group_by", "agg"],
            "additionalProperties": False,
        },
    },
    {
        "name": "count_rows_dataset",
        "description": (
            "Compte les lignes d'un dataset, avec filtres optionnels. "
            "Retourne aussi le total non-filtré pour mise en perspective. "
            "Très peu coûteux — appelle-le librement."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "dataset_id": {"type": "integer"},
                "where": {
                    "type": "object",
                    "description": "Filtres égalité par colonne, optionnel.",
                    "additionalProperties": True,
                },
            },
            "required": ["dataset_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "emit_report_intro",
        "description": (
            "Émet le paragraphe d'introduction du rapport (optionnel). Cap 4000 "
            "caractères. Appelable une seule fois — le 2e appel écrase le 1er."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "emit_report_section",
        "description": (
            "Émet une section du rapport. Inclut titre, dataset_id de référence, "
            "description courte, graphiques pré-agrégés (bar/line/pie au format "
            "final, valeurs déjà calculées), et commentary libre. Max 20 "
            "sections au total — au-delà l'appel retourne ok=false."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Titre de la section (≤200 chars)"},
                "dataset_id": {
                    "type": "integer",
                    "description": "Doit correspondre à un id existant",
                },
                "description": {
                    "type": ["string", "null"],
                    "description": "Description courte (≤1000 chars), null si pas pertinent",
                },
                "charts": {
                    "type": "array",
                    "description": (
                        "Graphiques pré-agrégés. Formats supportés : "
                        "{type:'bar', title, bars:[{label, value}]} | "
                        "{type:'line', title, series:[{name, points:[{x,y}]}]} | "
                        "{type:'pie', title, slices:[{label, value}]}. "
                        "Liste vide [] si aucun graphique pertinent."
                    ),
                    "items": {"type": "object"},
                },
                "commentary": {
                    "type": "string",
                    "description": "Analyse libre, longueur libre (cap 20000 chars).",
                },
            },
            "required": ["title", "dataset_id", "charts", "commentary"],
            "additionalProperties": False,
        },
    },
    {
        "name": "finalize_report",
        "description": (
            "Termine le rapport en fournissant son titre. C'est l'unique "
            "moyen de signaler la fin de l'analyse — appelle ce tool quand "
            "tu as émis toutes les sections nécessaires. Après ça, la boucle "
            "s'arrête et le rapport est compilé en PDF."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Titre du rapport (≤200 chars)"},
            },
            "required": ["title"],
            "additionalProperties": False,
        },
    },
]


# ---------------------------------------------------------------------------
# Agent state — partagé entre les handlers, mis à jour par les emit_*.
# ---------------------------------------------------------------------------


@dataclass
class ReportAgentState:
    """État mutable d'un run du report agent.

    Le caller (``run_report_agent``) en construit UNE instance par run.
    Les handlers la lisent (datasets) et la mutent (emitted_*, finalized).
    """

    # Datasets indexés par id pour O(1) lookup
    datasets_by_id: Dict[int, Dict[str, Any]]

    # Fonction de restauration de l'anonymisation (du proxy unifié) appliquée
    # à la fin sur le plan complet, pas turn-par-turn (cohérent avec oneshot).
    restore_fn: Callable[[Any], Any]

    # Outputs accumulés via les tools emit_*
    emitted_title: Optional[str] = None
    emitted_intro: Optional[str] = None
    emitted_sections: List[Dict[str, Any]] = field(default_factory=list)

    # Signal terminal : finalize_report appelé → boucle break
    finalized: bool = False

    # #56 review (Moyen f) — nombre de sections que le LLM a tenté d'émettre mais
    # qui ont été REFUSÉES au cap MAX_SECTIONS_EMITTED. En mode agent, c'est le
    # vrai limiteur (≠ cut de _validate_plan) ; on le propage en sections_omitted
    # pour que la note « rapport partiel » du PDF s'affiche aussi dans ce mode.
    sections_refused: int = 0

    # Compteurs de progression (info / debugging — pas critique fonctionnellement)
    turn_count: int = 0
    tool_call_counts: Dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


#: Note injectée dans les tool results quand le dataset SOURCE est tronqué (chargé
#: partiellement au-delà du cap de lignes — flag ``truncated`` posé par le builder de
#: datasets, ex. ``reports.py:_build_one_dataset``). DISTINCT du ``truncated`` interne
#: d'un tool (cap de groupes d'``aggregate``, limite de scan d'``inspect``). Sans cette
#: remontée (#27 / A3-F1c), le planner agrège/compte sur un SOUS-ENSEMBLE en croyant
#: voir tout le dataset → chiffres faux SILENCIEUX dans le rapport.
_SOURCE_TRUNCATION_NOTE = (
    "⚠ Dataset source TRONQUÉ : il n'a été chargé que partiellement (cap de lignes "
    "atteint à la source). Ce résultat ne porte donc que sur les lignes disponibles — "
    "le total réel est SUPÉRIEUR et tout agrégat/comptage est PARTIEL. Mentionne "
    "explicitement cette troncature dans le rapport."
)


def handle_list_datasets(_input: Dict[str, Any], state: ReportAgentState) -> Dict[str, Any]:
    """Retourne juste les métadonnées — jamais les rows."""
    return {
        "datasets": [
            {
                "id": ds_id,
                "label": ds.get("label", f"Dataset {ds_id}"),
                "row_count": ds.get("row_count", len(ds.get("rows") or [])),
                "columns": list(ds.get("columns") or []),
                # #27 — remonte la troncature SOURCE (≠ tool-level) au planner.
                "source_truncated": bool(ds.get("truncated")),
            }
            for ds_id, ds in sorted(state.datasets_by_id.items())
        ]
    }


# Patterns de date courants (ISO + variantes FR avec ou sans heure).
# Vérifié AVANT le test numeric pour éviter qu'une colonne date avec une
# poignée de valeurs numériques (ex: "1.5" infiltré) bascule en "numeric".
# Review #14 du 2026-05-09.
_DATE_PATTERNS = (
    re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z?)?$"),  # ISO
    re.compile(r"^\d{2}/\d{2}/\d{4}$"),  # JJ/MM/AAAA (FR)
    re.compile(r"^\d{2}-\d{2}-\d{4}$"),  # JJ-MM-AAAA
)


def _looks_like_date(v: Any) -> bool:
    """True si la valeur ressemble à un timestamp/date courant (ISO/FR)."""
    if isinstance(v, str):
        s = v.strip()
        return any(p.match(s) for p in _DATE_PATTERNS)
    # On peut recevoir des date/datetime Python via SQL Server / Decimal —
    # type-check sur le nom plutôt que d'importer datetime (évite cycles).
    type_name = type(v).__name__
    return type_name in ("date", "datetime", "Timestamp", "DateTime")


def _detect_column_type(values: List[Any]) -> str:
    """Heuristique : date > numeric > text. Test date EN PREMIER pour
    éviter qu'une colonne 'date' avec un float égaré bascule en numeric.
    """
    non_null = [v for v in values if v is not None and v != ""]
    if not non_null:
        return "empty"

    # Test date avant numeric : si >= 80% des non-null matchent un pattern
    # date, on classe comme date — même si quelques valeurs sont des floats.
    date_count = sum(1 for v in non_null if _looks_like_date(v))
    if date_count >= int(0.8 * len(non_null)):
        return "date"

    numeric_count = 0
    for v in non_null:
        if isinstance(v, bool):  # bool est sous-classe de int — exclure
            continue
        if isinstance(v, (int, float, Decimal)):  # Decimal = colonnes MONEY/DECIMAL Sage (#139)
            numeric_count += 1
            continue
        if isinstance(v, str):
            try:
                float(v.replace(",", ".").strip())
                numeric_count += 1
            except (ValueError, AttributeError):
                pass
    if numeric_count >= int(0.8 * len(non_null)):
        return "numeric"
    return "text"


def handle_inspect_dataset(tool_input: Dict[str, Any], state: ReportAgentState) -> Dict[str, Any]:
    ds_id = tool_input.get("dataset_id")
    if ds_id not in state.datasets_by_id:
        return {
            "error": f"dataset_id {ds_id} introuvable",
            "available_ids": list(state.datasets_by_id.keys()),
        }

    ds = state.datasets_by_id[ds_id]
    rows = ds.get("rows") or []
    columns = list(ds.get("columns") or [])
    scan_rows = rows[:INSPECT_SCAN_LIMIT]
    distinct_truncated = len(rows) > INSPECT_SCAN_LIMIT

    columns_info: List[Dict[str, Any]] = []
    for col in columns:
        values = [row.get(col) if isinstance(row, dict) else None for row in scan_rows]
        col_type = _detect_column_type(values)

        non_null_vals = [v for v in values if v is not None and v != ""]
        has_nulls = len(non_null_vals) < len(values)

        info: Dict[str, Any] = {
            "name": col,
            "type": col_type,
            "has_nulls": has_nulls,
        }

        if col_type == "numeric":
            numeric_vals: List[float] = []
            for v in non_null_vals:
                if isinstance(v, bool):
                    continue
                if isinstance(v, (int, float, Decimal)):  # Decimal = MONEY/DECIMAL (#139)
                    numeric_vals.append(float(v))
                elif isinstance(v, str):
                    try:
                        numeric_vals.append(float(v.replace(",", ".").strip()))
                    except ValueError:
                        pass
            if numeric_vals:
                info["min"] = min(numeric_vals)
                info["max"] = max(numeric_vals)
        else:
            seen: Dict[Any, int] = {}
            for v in non_null_vals:
                # Hashable check pour les dict/list rares
                try:
                    seen[v] = seen.get(v, 0) + 1
                except TypeError:
                    continue
                if len(seen) > INSPECT_DISTINCT_MAX_VALUES * 10:
                    break  # plus de scan inutile, on a clairement haute-cardinalité
            top = sorted(seen.items(), key=lambda kv: -kv[1])[:INSPECT_DISTINCT_MAX_VALUES]
            info["distinct_count"] = len(seen)
            info["distinct_count_truncated"] = (
                distinct_truncated or len(seen) > INSPECT_DISTINCT_MAX_VALUES * 10
            )
            info["distinct_sample"] = [v for v, _ in top]

        columns_info.append(info)

    return {
        "dataset_id": ds_id,
        "label": ds.get("label", f"Dataset {ds_id}"),
        "row_count": ds.get("row_count", len(rows)),
        "scanned_for_inspect": len(scan_rows),
        "scan_truncated": distinct_truncated,
        # #27 — troncature SOURCE (≠ scan_truncated, qui est la limite d'inspect).
        "source_truncated": bool(ds.get("truncated")),
        "columns": columns_info,
    }


def handle_read_dataset_sample(
    tool_input: Dict[str, Any], state: ReportAgentState
) -> Dict[str, Any]:
    ds_id = tool_input.get("dataset_id")
    if ds_id not in state.datasets_by_id:
        return {
            "error": f"dataset_id {ds_id} introuvable",
            "available_ids": list(state.datasets_by_id.keys()),
        }

    ds = state.datasets_by_id[ds_id]
    rows = ds.get("rows") or []
    total = len(rows)

    raw_start = tool_input.get("row_start", 0)
    raw_end = tool_input.get("row_end", 0)
    try:
        start = max(0, int(raw_start))
        end = max(start, int(raw_end))
    except (TypeError, ValueError):
        return {"error": "row_start et row_end doivent être des entiers"}

    # Cap dur 60 lignes — l'LLM doit paginer s'il veut plus, mais on l'incite
    # plutôt à utiliser aggregate_dataset.
    if end - start > READ_SAMPLE_HARD_CAP:
        end = start + READ_SAMPLE_HARD_CAP

    end = min(end, total)
    sample_rows = rows[start:end]

    return {
        "dataset_id": ds_id,
        "row_start": start,
        "row_end": end,
        "row_count_total": total,
        "rows_returned": len(sample_rows),
        "rows": sample_rows,
        # #27 — l'échantillon provient d'un dataset tronqué à la source.
        "source_truncated": bool(ds.get("truncated")),
        "next_start": end if end < total else None,
        "hint": (
            None
            if total <= READ_SAMPLE_HARD_CAP * 3
            else "Dataset volumineux — préfère aggregate_dataset à des reads successifs"
        ),
    }


_FILTER_SCALAR_TYPES = (str, int, float, bool, type(None))


def _matches_where(row: Dict[str, Any], where: Dict[str, Any]) -> bool:
    """Filtre simple : égalité stricte sur chaque clé. Si la clé n'existe
    pas dans la row, le filtre échoue (pas de match silencieux).

    Hardening (review #2 du 2026-05-09) :
    - ``NaN`` rejeté explicitement : ``float('nan') != float('nan')``
      retourne ``True`` en Python — sans cette garde, un LLM compromis
      qui passe ``where={"col": NaN}`` ferait passer TOUS les rows
      (puisque actual != NaN est toujours True) → données fausses
      silencieuses.
    - Types complexes (dict/list/set/objects) refusés : on ne supporte
      que les scalaires comme valeur de filtre, fail-closed.
    """
    for col, expected in where.items():
        # NaN : refuser explicitement (NaN != tout, y compris lui-même)
        if isinstance(expected, float) and math.isnan(expected):
            return False
        # Types complexes : fail-closed (le filtre n'a aucun sens)
        if not isinstance(expected, _FILTER_SCALAR_TYPES):
            return False
        actual = row.get(col)
        # Si actual est NaN, refuse aussi (même raison)
        if isinstance(actual, float) and math.isnan(actual):
            return False
        if actual != expected:
            return False
    return True


def _coerce_numeric(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    # ``Decimal`` : les colonnes monétaires SQL Server (DECIMAL/MONEY/NUMERIC)
    # arrivent en ``decimal.Decimal`` via pyodbc. Sans cette branche, elles
    # tombaient dans ``return None`` final → droppées des agrégats sum/avg/min/max
    # (somme d'argent = 0.0 SILENCIEUX dans les rapports). #139 (WF-1).
    if isinstance(value, (int, float, Decimal)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.replace(",", ".").strip())
        except ValueError:
            return None
    return None


def handle_aggregate_dataset(tool_input: Dict[str, Any], state: ReportAgentState) -> Dict[str, Any]:
    ds_id = tool_input.get("dataset_id")
    if ds_id not in state.datasets_by_id:
        return {
            "error": f"dataset_id {ds_id} introuvable",
            "available_ids": list(state.datasets_by_id.keys()),
        }

    ds = state.datasets_by_id[ds_id]
    rows = ds.get("rows") or []
    columns = set(ds.get("columns") or [])

    group_by = tool_input.get("group_by") or []
    value_column = tool_input.get("value_column")
    agg = (tool_input.get("agg") or "").strip().lower()
    where = tool_input.get("where") or {}

    if agg not in {"sum", "avg", "min", "max", "count"}:
        return {"error": f"agg invalide '{agg}' (attendu : sum/avg/min/max/count)"}

    if not isinstance(group_by, list):
        return {"error": "group_by doit être une liste de noms de colonnes"}

    unknown_cols = [c for c in group_by if c not in columns]
    if unknown_cols:
        return {
            "error": f"Colonnes inconnues dans group_by : {unknown_cols}",
            "available_columns": sorted(columns),
        }

    if agg != "count" and not value_column:
        return {"error": f"value_column requis pour agg='{agg}'"}

    if value_column and value_column not in columns:
        return {
            "error": f"Colonne value_column inconnue : '{value_column}'",
            "available_columns": sorted(columns),
        }

    # Single-pass O(n) accumulator
    groups: Dict[tuple, Dict[str, Any]] = {}
    rows_processed = 0
    rows_filtered_out = 0
    numeric_skipped = 0
    rows_skipped_over_cap = 0  # rows non comptées car nouveau groupe au-dessus du cap
    distinct_keys_over_cap: set = set()

    for row in rows:
        if not isinstance(row, dict):
            continue
        if where and not _matches_where(row, where):
            rows_filtered_out += 1
            continue
        rows_processed += 1

        key = tuple(row.get(col) for col in group_by) if group_by else ()

        if key not in groups:
            if len(groups) >= AGGREGATE_MAX_GROUPS:
                # Cap atteint — ignore les nouveaux groupes. Pour ne PAS faire
                # croire au LLM qu'il a vu toutes les données, on track les
                # rows skippées et le nombre approximatif de groupes au-delà
                # du cap (review #6 du 2026-05-09 — pas de cap silencieux).
                rows_skipped_over_cap += 1
                # Bound le set lui-même à éviter qu'il grossisse à l'infini :
                # 5000 clés distinctes au-delà du cap = signal "haute cardinalité",
                # plus besoin de précision.
                if len(distinct_keys_over_cap) < 5000:
                    distinct_keys_over_cap.add(key)
                continue
            groups[key] = {
                "_count": 0,
                "_numeric_count": 0,
                "_sum": 0.0,
                "_min": None,
                "_max": None,
            }

        bucket = groups[key]
        bucket["_count"] += 1

        if agg != "count" and value_column:
            num = _coerce_numeric(row.get(value_column))
            if num is None:
                numeric_skipped += 1
                continue
            # ``_numeric_count`` = nb de valeurs RÉELLEMENT numériques (≠ ``_count``
            # qui compte toutes les lignes du groupe). avg DOIT diviser par
            # ``_numeric_count`` sinon la moyenne est diluée par les lignes
            # non-numériques/NULL (avg silencieusement faux). #140 (WF-2).
            bucket["_numeric_count"] += 1
            bucket["_sum"] += num
            bucket["_min"] = num if bucket["_min"] is None else min(bucket["_min"], num)
            bucket["_max"] = num if bucket["_max"] is None else max(bucket["_max"], num)

    # Construit la sortie
    out_groups: List[Dict[str, Any]] = []
    for key, bucket in groups.items():
        key_dict = {col: key[i] for i, col in enumerate(group_by)} if group_by else {}
        if agg == "count":
            value: Any = bucket["_count"]
        elif agg == "sum":
            value = bucket["_sum"]
        elif agg == "avg":
            # Diviser par le nb de valeurs NUMÉRIQUES, pas par le nb de lignes
            # (sinon moyenne diluée par les non-numériques/NULL — #140 WF-2).
            value = (
                (bucket["_sum"] / bucket["_numeric_count"])
                if bucket["_numeric_count"]
                else None
            )
        elif agg == "min":
            value = bucket["_min"]
        elif agg == "max":
            value = bucket["_max"]
        else:
            value = None
        out_groups.append({"key": key_dict, "value": value, "count": bucket["_count"]})

    # Tri stable : par valeur décroissante (top-N visuel friendly), puis par clé
    def _sort_key(g: Dict[str, Any]) -> Any:
        v = g.get("value")
        if isinstance(v, (int, float)):
            return (-v, str(g.get("key")))
        return (0, str(g.get("key")))

    out_groups.sort(key=_sort_key)

    truncated = len(groups) >= AGGREGATE_MAX_GROUPS

    result: Dict[str, Any] = {
        "dataset_id": ds_id,
        "agg": agg,
        "group_by": group_by,
        "value_column": value_column,
        "rows_processed": rows_processed,
        "rows_filtered_out": rows_filtered_out,
        "numeric_skipped": numeric_skipped,
        "groups_count": len(out_groups),
        "groups": out_groups,
        "truncated": truncated,
        # #27 — un agrégat sur un dataset tronqué À LA SOURCE est PARTIEL (≠
        # ``truncated`` ci-dessus = cap de GROUPES). Cas données-fausses le plus
        # critique : sum/avg présentés comme exhaustifs alors qu'ils ne portent que
        # sur les lignes chargées.
        "source_truncated": bool(ds.get("truncated")),
    }
    if ds.get("truncated"):
        result["source_truncation_warning"] = _SOURCE_TRUNCATION_NOTE
    if truncated:
        # Visibilité explicite : combien de rows + de groupes distincts sont
        # passés à la trappe. L'LLM peut décider de raffiner sa requête (ex.
        # ajouter un where pour réduire la cardinalité) plutôt que d'analyser
        # un échantillon partiel en croyant avoir tout vu.
        result["rows_skipped_over_cap"] = rows_skipped_over_cap
        result["distinct_keys_over_cap_estimate"] = len(distinct_keys_over_cap)
        result["truncation_warning"] = (
            f"Cap {AGGREGATE_MAX_GROUPS} groupes atteint — au moins "
            f"{len(distinct_keys_over_cap)} groupes supplémentaires ignorés "
            f"({rows_skipped_over_cap} rows). Affine ta requête (where/group_by "
            "moins large) si tu veux une vue exhaustive."
        )
    return result


def handle_count_rows_dataset(
    tool_input: Dict[str, Any], state: ReportAgentState
) -> Dict[str, Any]:
    ds_id = tool_input.get("dataset_id")
    if ds_id not in state.datasets_by_id:
        return {
            "error": f"dataset_id {ds_id} introuvable",
            "available_ids": list(state.datasets_by_id.keys()),
        }

    ds = state.datasets_by_id[ds_id]
    rows = ds.get("rows") or []
    where = tool_input.get("where") or {}

    # #27 — un comptage sur un dataset tronqué à la source est une BORNE BASSE
    # (le vrai total dépasse les lignes chargées).
    src_trunc = bool(ds.get("truncated"))
    if not where:
        out: Dict[str, Any] = {
            "dataset_id": ds_id,
            "count": len(rows),
            "total": len(rows),
            "source_truncated": src_trunc,
        }
    else:
        matching = sum(1 for row in rows if isinstance(row, dict) and _matches_where(row, where))
        out = {
            "dataset_id": ds_id,
            "count": matching,
            "total": len(rows),
            "filter": where,
            "source_truncated": src_trunc,
        }
    if src_trunc:
        out["source_truncation_warning"] = _SOURCE_TRUNCATION_NOTE
    return out


def handle_emit_report_intro(tool_input: Dict[str, Any], state: ReportAgentState) -> Dict[str, Any]:
    text = tool_input.get("text")
    if not isinstance(text, str) or not text.strip():
        return {"ok": False, "reason": "text vide ou non-string"}

    # Review #7 du 2026-05-09 : signaler explicitement l'écrasement plutôt
    # que de remplacer en silence. Le LLM peut ainsi corriger sa stratégie
    # (ne pas re-émettre une intro déjà posée) ou comprendre que sa 1re
    # intro a été conservée s'il préfère.
    overwritten = state.emitted_intro is not None
    if overwritten:
        logger.warning(
            "report_planner_agent: emit_report_intro appelé 2 fois, intro précédente écrasée"
        )
    state.emitted_intro = _cap_with_notice(text, MAX_INTRO_LEN)
    return {
        "ok": True,
        "stored_chars": len(state.emitted_intro),
        "overwritten": overwritten,
        "note": (
            "Intro existante écrasée — n'appelle ce tool qu'une seule fois par rapport"
            if overwritten
            else None
        ),
    }


def handle_emit_report_section(
    tool_input: Dict[str, Any], state: ReportAgentState
) -> Dict[str, Any]:
    if len(state.emitted_sections) >= MAX_SECTIONS_EMITTED:
        # #56 review — compter le refus pour le surfacer dans le PDF final.
        state.sections_refused += 1
        return {"ok": False, "reason": f"max_sections_reached ({MAX_SECTIONS_EMITTED})"}

    title = tool_input.get("title")
    if not isinstance(title, str) or not title.strip():
        return {"ok": False, "reason": "title vide ou non-string"}

    dataset_id = tool_input.get("dataset_id")
    if dataset_id not in state.datasets_by_id:
        return {
            "ok": False,
            "reason": f"dataset_id {dataset_id} invalide",
            "available_ids": list(state.datasets_by_id.keys()),
        }

    charts = tool_input.get("charts")
    if not isinstance(charts, list):
        return {"ok": False, "reason": "charts doit être une liste (vide [] si rien)"}

    commentary = tool_input.get("commentary")
    if not isinstance(commentary, str):
        return {"ok": False, "reason": "commentary doit être une string"}

    # On stocke en brut (anonymisé via le proxy en amont). Le validateur
    # de llm_report_planner._validate_section nettoiera et tronquera lors
    # de la construction finale du ReportPlan.
    section = {
        "title": _cap_with_notice(title.strip(), MAX_TITLE_LEN),
        "dataset_id": dataset_id,
        "description": tool_input.get("description"),
        "charts": charts,
        "commentary": commentary,
    }
    state.emitted_sections.append(section)
    return {
        "ok": True,
        "section_index": len(state.emitted_sections) - 1,
        "total_sections": len(state.emitted_sections),
    }


def handle_finalize_report(tool_input: Dict[str, Any], state: ReportAgentState) -> Dict[str, Any]:
    title = tool_input.get("title")
    if not isinstance(title, str) or not title.strip():
        return {"ok": False, "reason": "title vide ou non-string"}
    if not state.emitted_sections:
        return {
            "ok": False,
            "reason": "Aucune section émise — appelle emit_report_section au moins une fois avant finalize_report",
        }
    state.emitted_title = _cap_with_notice(title.strip(), MAX_TITLE_LEN)
    state.finalized = True
    return {
        "ok": True,
        "title": state.emitted_title,
        "sections_emitted": len(state.emitted_sections),
        "has_intro": state.emitted_intro is not None,
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_HANDLERS: Dict[str, Callable[[Dict[str, Any], ReportAgentState], Dict[str, Any]]] = {
    "list_datasets": handle_list_datasets,
    "inspect_dataset": handle_inspect_dataset,
    "read_dataset_sample": handle_read_dataset_sample,
    "aggregate_dataset": handle_aggregate_dataset,
    "count_rows_dataset": handle_count_rows_dataset,
    "emit_report_intro": handle_emit_report_intro,
    "emit_report_section": handle_emit_report_section,
    "finalize_report": handle_finalize_report,
}


def dispatch_report_tool(
    tool_name: str, tool_input: Dict[str, Any], state: ReportAgentState
) -> Dict[str, Any]:
    """Route un appel tool vers son handler. Inconnu → erreur structurée
    (le LLM la verra dans le tool_result et pourra réessayer).
    """
    state.tool_call_counts[tool_name] = state.tool_call_counts.get(tool_name, 0) + 1

    handler = _HANDLERS.get(tool_name)
    if handler is None:
        logger.warning("report_planner_agent: tool inconnu '%s'", tool_name)
        return {
            "error": f"Tool inconnu : {tool_name}",
            "available_tools": list(_HANDLERS.keys()),
        }
    try:
        return handler(tool_input or {}, state)
    except Exception as exc:  # noqa: BLE001 — dernière barrière, le LLM lit l'erreur
        logger.error(
            "report_planner_agent: handler %s a levé une exception: %s",
            tool_name,
            exc,
            exc_info=True,
        )
        return {"error": f"Erreur interne du tool {tool_name}: {type(exc).__name__}"}
