"""Transformations pures-Python appliquées aux résultats SQL réels.

Le LLM Analyst décide la "recette" (kind + params). Le système applique cette
recette mécaniquement ici — déterministe, testable, zéro SQL halluciné.

Recettes supportées :

    passthrough        → {type: "table", columns, rows}
    scalar_aggregate   → {type: "kpi", value, label}
    groupby            → {type: "chart", labels, datasets}  (bar/pie/donut)
    time_series        → {type: "chart", labels, datasets}  (line/area)

La forme de retour est alignée sur ce que `_transform_sql_to_chart` /
`_transform_sql_to_kpi` produisent déjà côté ``dashboard_builder_service``,
afin que le frontend n'ait rien à changer.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import date, datetime
from typing import Any

VALID_TRANSFORM_KINDS = frozenset(
    {
        "passthrough",
        "scalar_aggregate",
        "scalar_from_column",  # extrait un rollup déjà présent dans la data
        "groupby",
        "groupby_2d",  # 2 catégories + 1 mesure → multi-série
        "time_series",
        "time_series_multi",  # 1 date + 1 série + 1 mesure → multi-ligne
        "top_n_2d",  # top-N de category × series (même forme que groupby_2d)
    }
)
VALID_AGGS = frozenset({"sum", "avg", "count", "min", "max"})
VALID_BUCKETS = frozenset({"day", "week", "month", "quarter", "year"})
VALID_SORTS = frozenset({"asc", "desc", "none"})


class TransformationError(Exception):
    """Soulevée quand une recette fait référence à une colonne/op absente."""


# ------------------------------------------------------------------
# Helpers numériques
# ------------------------------------------------------------------


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else None
    if isinstance(value, str):
        try:
            n = float(value.strip().replace(",", "."))
        except ValueError:
            return None
        return n if math.isfinite(n) else None
    try:
        n = float(value)  # Decimal, etc.
    except (TypeError, ValueError):
        return None
    return n if math.isfinite(n) else None


def _col_index(columns: list[str], name: str) -> int:
    try:
        return columns.index(name)
    except ValueError as exc:
        raise TransformationError(
            f"Colonne inconnue dans la recette : {name!r}. " f"Colonnes disponibles : {columns}"
        ) from exc


def _aggregate(values: list[float], agg: str) -> float | int:
    if not values:
        return 0
    if agg == "sum":
        return sum(values)
    if agg == "avg":
        return sum(values) / len(values)
    if agg == "count":
        return len(values)
    if agg == "min":
        return min(values)
    if agg == "max":
        return max(values)
    raise TransformationError(f"Agrégation inconnue : {agg!r}")


# ------------------------------------------------------------------
# Bucket de date
# ------------------------------------------------------------------


def _to_date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        s = value.strip()
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d",
        ):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
    return None


def _bucket_label(dt: datetime, bucket: str) -> str:
    """Retourne un label trié de façon naturelle (sort alphabétique = ordre temporel)."""
    if bucket == "day":
        return dt.strftime("%Y-%m-%d")
    if bucket == "week":
        iso_year, iso_week, _ = dt.isocalendar()
        return f"{iso_year:04d}-S{iso_week:02d}"
    if bucket == "month":
        return dt.strftime("%Y-%m")
    if bucket == "quarter":
        q = (dt.month - 1) // 3 + 1
        return f"{dt.year}-T{q}"
    if bucket == "year":
        return dt.strftime("%Y")
    raise TransformationError(f"Bucket inconnu : {bucket!r}")


# ------------------------------------------------------------------
# Transformation applier
# ------------------------------------------------------------------


def apply_transformation(
    columns: list[str], rows: list[list[Any]], recipe: dict[str, Any] | None
) -> dict[str, Any]:
    """Applique la recette au résultat SQL brut.

    Args:
        columns: noms des colonnes
        rows: données réelles (lignes de listes)
        recipe: dict {"kind": …, "params": …} ou None/vide → passthrough

    Returns:
        Dict au format attendu par le frontend (même schéma que
        ``_transform_sql_to_chart`` / ``_transform_sql_to_kpi`` pour
        éviter tout changement de contrat front).

    Raises:
        TransformationError si la recette référence une colonne inexistante
        ou un paramètre invalide.
    """
    if not recipe:
        return _passthrough(columns, rows)

    kind = recipe.get("kind")
    if kind not in VALID_TRANSFORM_KINDS:
        raise TransformationError(f"Recette de type inconnu : {kind!r}")

    params = recipe.get("params") or {}

    if kind == "passthrough":
        return _passthrough(columns, rows)
    if kind == "scalar_aggregate":
        return _scalar_aggregate(columns, rows, params)
    if kind == "scalar_from_column":
        return _scalar_from_column(columns, rows, params)
    if kind == "groupby":
        return _groupby(columns, rows, params)
    if kind == "groupby_2d":
        return _groupby_2d(columns, rows, params)
    if kind == "time_series":
        return _time_series(columns, rows, params)
    if kind == "time_series_multi":
        return _time_series_multi(columns, rows, params)
    if kind == "top_n_2d":
        return _top_n_2d(columns, rows, params)

    # Défense — normalement inaccessible puisque validé au-dessus
    raise TransformationError(f"Kind non géré : {kind!r}")


def _passthrough(columns: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    return {"type": "table", "columns": list(columns), "rows": [list(r) for r in rows]}


def _scalar_aggregate(
    columns: list[str], rows: list[list[Any]], params: dict[str, Any]
) -> dict[str, Any]:
    """Produit un KPI à partir d'une colonne numérique + agg."""
    col = params.get("column") or params.get("value_col")
    agg = (params.get("agg") or "sum").lower()
    if not isinstance(col, str) or not col:
        raise TransformationError("scalar_aggregate: 'column' manquant")
    if agg not in VALID_AGGS:
        raise TransformationError(f"scalar_aggregate: agg inconnu {agg!r}")

    # Cas particulier : count peut opérer sur toutes les lignes
    if agg == "count":
        # count(*) = nb lignes ; count(colonne) = nb valeurs non-null
        if col == "*":
            value: float | int = len(rows)
        else:
            idx = _col_index(columns, col)
            value = sum(1 for r in rows if idx < len(r) and r[idx] not in (None, ""))
    else:
        idx = _col_index(columns, col)
        nums = [f for r in rows if (f := _to_float(r[idx] if idx < len(r) else None)) is not None]
        value = _aggregate(nums, agg)

    label = params.get("label") or col
    return {
        "type": "kpi",
        "value": value,
        "label": label,
    }


def _groupby(columns: list[str], rows: list[list[Any]], params: dict[str, Any]) -> dict[str, Any]:
    """Agrège par catégorie → forme chart {labels, datasets:[{label, data}]}."""
    category_col = params.get("category_col") or params.get("category")
    value_col = params.get("value_col") or params.get("value")
    agg = (params.get("agg") or "sum").lower()
    sort = (params.get("sort") or "desc").lower()
    limit = params.get("limit")
    try:
        limit = int(limit) if limit is not None else None
    except (TypeError, ValueError):
        limit = None

    if not isinstance(category_col, str) or not category_col:
        raise TransformationError("groupby: 'category_col' manquant")
    if agg not in VALID_AGGS:
        raise TransformationError(f"groupby: agg inconnu {agg!r}")
    if sort not in VALID_SORTS:
        raise TransformationError(f"groupby: sort inconnu {sort!r}")

    cat_idx = _col_index(columns, category_col)

    # count(*) ne requiert pas de colonne numérique
    if agg == "count" and (value_col in (None, "*", "")):
        buckets: dict[Any, list[float]] = defaultdict(list)
        for r in rows:
            cat = r[cat_idx] if cat_idx < len(r) else None
            if cat in (None, ""):
                continue
            buckets[cat].append(1.0)
    else:
        if not isinstance(value_col, str) or not value_col:
            raise TransformationError("groupby: 'value_col' manquant pour cette agg")
        val_idx = _col_index(columns, value_col)
        buckets = defaultdict(list)
        for r in rows:
            cat = r[cat_idx] if cat_idx < len(r) else None
            if cat in (None, ""):
                continue
            num = _to_float(r[val_idx] if val_idx < len(r) else None)
            if num is None:
                continue
            buckets[cat].append(num)

    aggregated = [(cat, _aggregate(vals, agg)) for cat, vals in buckets.items()]
    if sort == "desc":
        aggregated.sort(key=lambda x: x[1], reverse=True)
    elif sort == "asc":
        aggregated.sort(key=lambda x: x[1])

    if limit is not None and limit > 0:
        aggregated = aggregated[:limit]

    labels = [str(c) for c, _ in aggregated]
    data = [v for _, v in aggregated]
    series_label = params.get("label") or (value_col if value_col else "count")
    return {
        "type": "chart",
        "labels": labels,
        "datasets": [{"label": series_label, "data": data}],
    }


def _time_series(
    columns: list[str], rows: list[list[Any]], params: dict[str, Any]
) -> dict[str, Any]:
    """Bucket par période → forme chart pour line/area."""
    date_col = params.get("date_col") or params.get("x_col")
    value_col = params.get("value_col") or params.get("y_col")
    agg = (params.get("agg") or "sum").lower()
    bucket = (params.get("bucket") or "month").lower()

    if not isinstance(date_col, str) or not date_col:
        raise TransformationError("time_series: 'date_col' manquant")
    if agg not in VALID_AGGS:
        raise TransformationError(f"time_series: agg inconnu {agg!r}")
    if bucket not in VALID_BUCKETS:
        raise TransformationError(f"time_series: bucket inconnu {bucket!r}")

    d_idx = _col_index(columns, date_col)

    if agg == "count" and (value_col in (None, "*", "")):
        buckets: dict[str, list[float]] = defaultdict(list)
        for r in rows:
            dt = _to_date(r[d_idx] if d_idx < len(r) else None)
            if dt is None:
                continue
            buckets[_bucket_label(dt, bucket)].append(1.0)
    else:
        if not isinstance(value_col, str) or not value_col:
            raise TransformationError("time_series: 'value_col' manquant")
        v_idx = _col_index(columns, value_col)
        buckets = defaultdict(list)
        for r in rows:
            dt = _to_date(r[d_idx] if d_idx < len(r) else None)
            if dt is None:
                continue
            num = _to_float(r[v_idx] if v_idx < len(r) else None)
            if num is None:
                continue
            buckets[_bucket_label(dt, bucket)].append(num)

    # Tri chronologique : les labels ont été conçus pour se trier alphabétique-
    # ment dans l'ordre temporel (2024-01 < 2024-02 ; 2024-T1 < 2024-T2 ; …)
    sorted_keys = sorted(buckets.keys())
    labels = list(sorted_keys)
    data = [_aggregate(buckets[k], agg) for k in sorted_keys]
    series_label = params.get("label") or (value_col if value_col else "count")
    return {
        "type": "chart",
        "labels": labels,
        "datasets": [{"label": series_label, "data": data}],
    }


# ------------------------------------------------------------------
# scalar_from_column : extrait un rollup déjà présent dans une colonne
# ------------------------------------------------------------------


def _scalar_from_column(
    columns: list[str], rows: list[list[Any]], params: dict[str, Any]
) -> dict[str, Any]:
    """KPI depuis une colonne déjà pré-agrégée par le SQL.

    Utile pour des requêtes qui contiennent des fenêtres ``SUM() OVER ()``
    ou tout autre rollup côté SQL. Prend la valeur de la PREMIÈRE ligne,
    optionnellement filtrée sur une autre colonne (``filter_col`` =
    ``filter_value``).

    Params:
        column         : colonne à lire (obligatoire)
        label          : label du KPI (optionnel, défaut = nom colonne)
        filter_col     : colonne pour filtrer (optionnel)
        filter_value   : valeur attendue dans filter_col (optionnel)
    """
    col = params.get("column") or params.get("value_col")
    if not isinstance(col, str) or not col:
        raise TransformationError("scalar_from_column: 'column' manquant")
    idx = _col_index(columns, col)

    filter_col = params.get("filter_col")
    filter_val = params.get("filter_value")
    if isinstance(filter_col, str) and filter_col:
        f_idx = _col_index(columns, filter_col)
        # Cherche la 1re ligne où filter_col == filter_value (équivalence str)
        target = None
        for r in rows:
            if f_idx < len(r) and str(r[f_idx]) == str(filter_val):
                target = r
                break
    else:
        target = rows[0] if rows else None

    if target is None or idx >= len(target):
        return {"type": "kpi", "value": 0, "label": params.get("label") or col}
    value = _to_float(target[idx])
    if value is None:
        # Colonne non numérique → on passe la valeur brute (affichée telle quelle)
        value = target[idx]
    return {
        "type": "kpi",
        "value": value,
        "label": params.get("label") or col,
    }


# ------------------------------------------------------------------
# groupby_2d : 2 catégories + 1 mesure → multi-série pour chart grouped/stacked
# ------------------------------------------------------------------


def _groupby_2d(
    columns: list[str], rows: list[list[Any]], params: dict[str, Any]
) -> dict[str, Any]:
    """Pivote par (category, series) : produit {labels: [cat…], datasets: [{label: serie, data:[…]}, …]}.

    Les ``labels`` sont la dimension X (catégorie principale). Chaque
    ``dataset`` est une série sur la seconde dimension. Parfait pour
    grouped bar / stacked bar : 2 dimensions × 1 mesure (ex. ventes
    catégorie × période, montants client × région).
    """
    category_col = params.get("category_col")
    series_col = params.get("series_col")
    value_col = params.get("value_col")
    agg = (params.get("agg") or "sum").lower()
    sort = (params.get("sort") or "desc").lower()
    limit = params.get("limit")
    try:
        limit = int(limit) if limit is not None else None
    except (TypeError, ValueError):
        limit = None

    if not isinstance(category_col, str) or not category_col:
        raise TransformationError("groupby_2d: 'category_col' manquant")
    if not isinstance(series_col, str) or not series_col:
        raise TransformationError("groupby_2d: 'series_col' manquant")
    if agg not in VALID_AGGS:
        raise TransformationError(f"groupby_2d: agg inconnu {agg!r}")
    if sort not in VALID_SORTS:
        raise TransformationError(f"groupby_2d: sort inconnu {sort!r}")

    cat_idx = _col_index(columns, category_col)
    ser_idx = _col_index(columns, series_col)
    # count sans value_col accepté
    use_count_only = agg == "count" and (value_col in (None, "*", ""))
    val_idx = None if use_count_only else _col_index(columns, value_col)

    # (cat, serie) → list[valeurs]
    buckets: dict[tuple[Any, Any], list[float]] = defaultdict(list)
    for r in rows:
        cat = r[cat_idx] if cat_idx < len(r) else None
        ser = r[ser_idx] if ser_idx < len(r) else None
        if cat in (None, "") or ser in (None, ""):
            continue
        if use_count_only:
            buckets[(cat, ser)].append(1.0)
        else:
            num = _to_float(r[val_idx] if val_idx < len(r) else None)  # type: ignore[arg-type]
            if num is None:
                continue
            buckets[(cat, ser)].append(num)

    if not buckets:
        return {"type": "chart", "labels": [], "datasets": []}

    # Totaux par catégorie (pour trier labels + appliquer limit)
    cat_totals: dict[Any, float] = defaultdict(float)
    for (cat, _ser), vals in buckets.items():
        cat_totals[cat] += float(_aggregate(vals, agg))

    if sort == "desc":
        ordered_cats = sorted(cat_totals, key=lambda c: cat_totals[c], reverse=True)
    elif sort == "asc":
        ordered_cats = sorted(cat_totals, key=lambda c: cat_totals[c])
    else:
        # insertion-order (Python 3.7+ preserve dict insertion)
        ordered_cats = list(cat_totals.keys())

    if limit is not None and limit > 0:
        ordered_cats = ordered_cats[:limit]

    # Séries triées par ordre alphabétique stable (pour qu'une période
    # antérieure s'affiche avant une période postérieure quand les labels
    # se trient alphabétiquement = chronologiquement).
    all_series = sorted({s for (_c, s) in buckets.keys()}, key=lambda x: str(x))

    # Cap de sécurité : au-dessus de ``max_series`` séries (défaut 6), la
    # légende devient illisible + le plot est poussé sur le côté. On garde
    # les top séries par total et on regroupe le reste en "Autres".
    try:
        max_series = int(params.get("max_series") or 6)
    except (TypeError, ValueError):
        max_series = 6
    if max_series > 0 and len(all_series) > max_series:
        series_totals: dict[Any, float] = defaultdict(float)
        for (_c, s), vals in buckets.items():
            series_totals[s] += float(_aggregate(vals, agg))
        top_series = sorted(series_totals, key=lambda x: series_totals[x], reverse=True)[
            :max_series
        ]
        other_series = [s for s in all_series if s not in set(top_series)]
        all_series = sorted(top_series, key=lambda x: str(x))
        # Fusionne les buckets des séries "Autres" par catégorie
        if other_series:
            other_key = "Autres"
            for cat in ordered_cats:
                combined: list[float] = []
                for s in other_series:
                    combined.extend(buckets.get((cat, s), []))
                    buckets.pop((cat, s), None)
                if combined:
                    buckets[(cat, other_key)] = combined
            all_series.append(other_key)

    datasets: list[dict[str, Any]] = []
    for serie in all_series:
        data = []
        for cat in ordered_cats:
            vals = buckets.get((cat, serie))
            data.append(_aggregate(vals, agg) if vals else 0)
        datasets.append({"label": str(serie), "data": data})

    return {
        "type": "chart",
        "labels": [str(c) for c in ordered_cats],
        "datasets": datasets,
    }


# ------------------------------------------------------------------
# top_n_2d : raccourci sémantique — groupby_2d avec limite courte
# ------------------------------------------------------------------


def _top_n_2d(columns: list[str], rows: list[list[Any]], params: dict[str, Any]) -> dict[str, Any]:
    """Alias de groupby_2d avec une limite par défaut basse (top N). Permet au
    LLM d'exprimer explicitement son intention "podium" sans avoir à répéter
    limit=10 partout."""
    merged = dict(params)
    merged.setdefault("limit", 10)
    merged.setdefault("sort", "desc")
    return _groupby_2d(columns, rows, merged)


# ------------------------------------------------------------------
# time_series_multi : 1 date + 1 série + 1 mesure → multi-ligne
# ------------------------------------------------------------------


def _time_series_multi(
    columns: list[str], rows: list[list[Any]], params: dict[str, Any]
) -> dict[str, Any]:
    """Multi-series time series. Exemple : évolution des montants PAR expert-comptable.

    Params:
        date_col     : colonne temporelle (obligatoire)
        series_col   : colonne catégorielle portant les séries (obligatoire)
        value_col    : colonne numérique à agréger (obligatoire sauf agg=count)
        agg          : sum / avg / count / min / max
        bucket       : day / week / month / quarter / year
        max_series   : limite le nombre de séries (default 6) — top séries par
                       total desc, les autres groupées sous "Autres".
    """
    date_col = params.get("date_col")
    series_col = params.get("series_col")
    value_col = params.get("value_col")
    agg = (params.get("agg") or "sum").lower()
    bucket = (params.get("bucket") or "month").lower()
    try:
        max_series = int(params.get("max_series") or 6)
    except (TypeError, ValueError):
        max_series = 6

    if not isinstance(date_col, str) or not date_col:
        raise TransformationError("time_series_multi: 'date_col' manquant")
    if not isinstance(series_col, str) or not series_col:
        raise TransformationError("time_series_multi: 'series_col' manquant")
    if agg not in VALID_AGGS:
        raise TransformationError(f"time_series_multi: agg inconnu {agg!r}")
    if bucket not in VALID_BUCKETS:
        raise TransformationError(f"time_series_multi: bucket inconnu {bucket!r}")

    d_idx = _col_index(columns, date_col)
    s_idx = _col_index(columns, series_col)
    use_count_only = agg == "count" and (value_col in (None, "*", ""))
    v_idx = None if use_count_only else _col_index(columns, value_col)

    # (bucket_label, serie) → list[val]
    buckets: dict[tuple[str, Any], list[float]] = defaultdict(list)
    for r in rows:
        dt = _to_date(r[d_idx] if d_idx < len(r) else None)
        ser = r[s_idx] if s_idx < len(r) else None
        if dt is None or ser in (None, ""):
            continue
        blabel = _bucket_label(dt, bucket)
        if use_count_only:
            buckets[(blabel, ser)].append(1.0)
        else:
            num = _to_float(r[v_idx] if v_idx < len(r) else None)  # type: ignore[arg-type]
            if num is None:
                continue
            buckets[(blabel, ser)].append(num)

    if not buckets:
        return {"type": "chart", "labels": [], "datasets": []}

    all_labels = sorted({b for (b, _s) in buckets.keys()})
    all_series = list({s for (_b, s) in buckets.keys()})

    # Si trop de séries : garde les top par total, regroupe le reste en "Autres"
    series_totals: dict[Any, float] = defaultdict(float)
    for (_b, s), vals in buckets.items():
        series_totals[s] += float(_aggregate(vals, agg))
    top_series = sorted(series_totals, key=lambda x: series_totals[x], reverse=True)[:max_series]
    top_set = set(top_series)
    other_series = [s for s in all_series if s not in top_set]

    datasets: list[dict[str, Any]] = []
    for serie in top_series:
        data = [
            _aggregate(buckets.get((lbl, serie), []), agg) if buckets.get((lbl, serie)) else 0
            for lbl in all_labels
        ]
        datasets.append({"label": str(serie), "data": data})

    if other_series:
        other_data = []
        for lbl in all_labels:
            combined: list[float] = []
            for s in other_series:
                combined.extend(buckets.get((lbl, s), []))
            other_data.append(_aggregate(combined, agg) if combined else 0)
        datasets.append({"label": "Autres", "data": other_data})

    return {
        "type": "chart",
        "labels": all_labels,
        "datasets": datasets,
    }


# ------------------------------------------------------------------
# Validation défensive (utilisée côté handler avant persistance)
# ------------------------------------------------------------------


def validate_recipe(recipe: Any, columns: list[str]) -> dict[str, Any] | None:
    """Valide la recette et normalise ses champs.

    Retourne une recette propre ou None si invalide (fallback = passthrough
    côté appelant). Ne soulève jamais d'exception — le but est de dégrader
    gracieusement plutôt que de casser la création d'un widget.
    """
    if recipe in (None, {}):
        return None
    if not isinstance(recipe, dict):
        return None

    kind = recipe.get("kind")
    if kind not in VALID_TRANSFORM_KINDS:
        return None
    if kind == "passthrough":
        return {"kind": "passthrough", "params": {}}

    params = recipe.get("params") or {}
    if not isinstance(params, dict):
        return None

    clean: dict[str, Any] = {}

    def _col_ok(name: Any) -> str | None:
        if not isinstance(name, str):
            return None
        s = name.strip()
        return s if s and (s in columns or s == "*") else None

    if kind == "scalar_aggregate":
        col = _col_ok(params.get("column") or params.get("value_col"))
        if col is None and (params.get("agg") or "").lower() != "count":
            return None
        agg = (params.get("agg") or "sum").lower()
        if agg not in VALID_AGGS:
            return None
        clean["column"] = col or "*"
        clean["agg"] = agg
        if isinstance(params.get("label"), str):
            clean["label"] = params["label"].strip()[:120]
        return {"kind": "scalar_aggregate", "params": clean}

    if kind == "groupby":
        cat = _col_ok(params.get("category_col") or params.get("category"))
        if cat is None:
            return None
        clean["category_col"] = cat
        agg = (params.get("agg") or "sum").lower()
        if agg not in VALID_AGGS:
            return None
        clean["agg"] = agg
        val = _col_ok(params.get("value_col") or params.get("value"))
        if val is not None:
            clean["value_col"] = val
        elif agg != "count":
            return None
        sort = (params.get("sort") or "desc").lower()
        clean["sort"] = sort if sort in VALID_SORTS else "desc"
        if (lim := params.get("limit")) is not None:
            try:
                lim_i = int(lim)
                if 0 < lim_i <= 100:
                    clean["limit"] = lim_i
            except (TypeError, ValueError):
                pass
        if isinstance(params.get("label"), str):
            clean["label"] = params["label"].strip()[:120]
        return {"kind": "groupby", "params": clean}

    if kind == "time_series":
        d = _col_ok(params.get("date_col") or params.get("x_col"))
        if d is None:
            return None
        clean["date_col"] = d
        agg = (params.get("agg") or "sum").lower()
        if agg not in VALID_AGGS:
            return None
        clean["agg"] = agg
        val = _col_ok(params.get("value_col") or params.get("y_col"))
        if val is not None:
            clean["value_col"] = val
        elif agg != "count":
            return None
        bucket = (params.get("bucket") or "month").lower()
        clean["bucket"] = bucket if bucket in VALID_BUCKETS else "month"
        if isinstance(params.get("label"), str):
            clean["label"] = params["label"].strip()[:120]
        return {"kind": "time_series", "params": clean}

    if kind == "scalar_from_column":
        col = _col_ok(params.get("column") or params.get("value_col"))
        if col is None:
            return None
        clean["column"] = col
        if isinstance(params.get("label"), str):
            clean["label"] = params["label"].strip()[:120]
        # Filtre optionnel : col + valeur attendue
        fc = _col_ok(params.get("filter_col"))
        if fc and params.get("filter_value") is not None:
            clean["filter_col"] = fc
            fv = params.get("filter_value")
            if isinstance(fv, (str, int, float)) and not isinstance(fv, bool):
                clean["filter_value"] = fv
        return {"kind": "scalar_from_column", "params": clean}

    if kind in ("groupby_2d", "top_n_2d"):
        cat = _col_ok(params.get("category_col"))
        ser = _col_ok(params.get("series_col"))
        if cat is None or ser is None or cat == ser:
            return None
        clean["category_col"] = cat
        clean["series_col"] = ser
        agg = (params.get("agg") or "sum").lower()
        if agg not in VALID_AGGS:
            return None
        clean["agg"] = agg
        val = _col_ok(params.get("value_col"))
        if val is not None:
            clean["value_col"] = val
        elif agg != "count":
            return None
        sort = (params.get("sort") or "desc").lower()
        clean["sort"] = sort if sort in VALID_SORTS else "desc"
        if (lim := params.get("limit")) is not None:
            try:
                lim_i = int(lim)
                if 0 < lim_i <= 100:
                    clean["limit"] = lim_i
            except (TypeError, ValueError):
                pass
        return {"kind": kind, "params": clean}

    if kind == "time_series_multi":
        d = _col_ok(params.get("date_col"))
        ser = _col_ok(params.get("series_col"))
        if d is None or ser is None or d == ser:
            return None
        clean["date_col"] = d
        clean["series_col"] = ser
        agg = (params.get("agg") or "sum").lower()
        if agg not in VALID_AGGS:
            return None
        clean["agg"] = agg
        val = _col_ok(params.get("value_col"))
        if val is not None:
            clean["value_col"] = val
        elif agg != "count":
            return None
        bucket = (params.get("bucket") or "month").lower()
        clean["bucket"] = bucket if bucket in VALID_BUCKETS else "month"
        if (ms := params.get("max_series")) is not None:
            try:
                ms_i = int(ms)
                if 1 <= ms_i <= 10:
                    clean["max_series"] = ms_i
            except (TypeError, ValueError):
                pass
        return {"kind": "time_series_multi", "params": clean}

    return None
