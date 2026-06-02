"""Profilage pur-Python d'un résultat SQL (colonnes + lignes).

Le but : produire un JSON compact, déterministe et pas cher (aucun appel LLM)
qui décrit la forme des données — types, cardinalité, stats numériques, plage
de dates, top valeurs catégorielles.

Ce profile est ce qu'on envoie ensuite au LLM "Analyst" (après obfuscation
Niveau 2) pour qu'il décide : quel type de viz, faut-il agréger, sur quelles
colonnes.

Le système prépare, le LLM décide — cf. principe Gladys.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from datetime import date, datetime
from typing import Any

_MAX_TOP_VALUES = 5  # Nombre de valeurs les plus fréquentes remontées par colonne
_MAX_STRING_LEN_IN_TOP = 60  # Éviter qu'une seule cellule énorme explose le profile
_NUMERIC_CARDINALITY_CAP = 200  # Au-delà on ne calcule plus top values (utile pour float continus)


_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?)?$")


def _is_numeric(value: Any) -> bool:
    """Vrai si la valeur est un nombre FINI — bool exclu (JSON les sérialise comme int)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return math.isfinite(value)
    if isinstance(value, str):
        s = value.strip().replace(",", ".")
        if not s or s in ("-", "+", "."):
            return False
        try:
            n = float(s)
        except ValueError:
            return False
        return math.isfinite(n)
    # Decimal / autres numeric-like (psycopg returns Decimal) — on essaie float()
    try:
        n = float(value)  # type: ignore[arg-type]
        return math.isfinite(n)
    except (TypeError, ValueError):
        return False


def _to_float(value: Any) -> float | None:
    """Coerce best-effort to float, None si échec."""
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
        n = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return n if math.isfinite(n) else None


def _is_date_like(value: Any) -> bool:
    if isinstance(value, (date, datetime)):
        return True
    if isinstance(value, str):
        return bool(_DATE_RE.match(value.strip()))
    return False


def _to_datetime(value: Any) -> datetime | None:
    """Coerce best-effort to datetime. Retourne None si échec."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        s = value.strip()
        # Formats tolérés : ISO 8601, avec ou sans heure
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


def _classify_column(values: list[Any]) -> str:
    """Retourne le type dominant d'une colonne : numeric | date | text | mixed | empty."""
    if not values:
        return "empty"
    numeric = 0
    temporal = 0
    textual = 0
    total = 0
    for v in values:
        if v is None or v == "":
            continue
        total += 1
        if _is_numeric(v):
            numeric += 1
        elif _is_date_like(v):
            temporal += 1
        else:
            textual += 1
    if total == 0:
        return "empty"
    # Seuil 80 % — même règle que le front pour cohérence
    if numeric / total >= 0.8:
        return "numeric"
    if temporal / total >= 0.8:
        return "date"
    if textual / total >= 0.8:
        return "text"
    return "mixed"


def _numeric_stats(values: list[Any]) -> dict[str, Any] | None:
    """min, max, sum, mean sur les valeurs coercible en float."""
    nums: list[float] = []
    for v in values:
        f = _to_float(v)
        if f is not None:
            nums.append(f)
    if not nums:
        return None
    total = sum(nums)
    return {
        "count": len(nums),
        "min": min(nums),
        "max": max(nums),
        "sum": total,
        "mean": total / len(nums),
    }


def _date_range(values: list[Any]) -> dict[str, str] | None:
    dts = [dt for v in values if (dt := _to_datetime(v)) is not None]
    if not dts:
        return None
    mn, mx = min(dts), max(dts)
    return {
        "min": mn.isoformat(timespec="seconds"),
        "max": mx.isoformat(timespec="seconds"),
        "span_days": max(0, (mx.date() - mn.date()).days),
    }


def _top_values(values: list[Any], limit: int = _MAX_TOP_VALUES) -> list[dict[str, Any]]:
    """Top-N valeurs les plus fréquentes (exclut None/"")."""
    filtered: list[Any] = []
    for v in values:
        if v is None or v == "":
            continue
        # Tronque les chaînes monstres pour pas exploser le profile envoyé au LLM
        if isinstance(v, str) and len(v) > _MAX_STRING_LEN_IN_TOP:
            filtered.append(v[:_MAX_STRING_LEN_IN_TOP] + "…")
        else:
            # Clé hachable : on stringify les dates/Decimal
            try:
                hash(v)
                filtered.append(v)
            except TypeError:
                filtered.append(str(v))
    counter = Counter(filtered)
    return [{"value": val, "count": cnt} for val, cnt in counter.most_common(limit)]


def profile_columns(columns: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    """Construit un profile compact des données SQL.

    Args:
        columns: noms des colonnes (ordre du SELECT)
        rows: lignes sous forme de listes indexées par colonne

    Returns:
        {
          "row_count": int,
          "columns": [
            {
              "name": str,
              "type": "numeric|date|text|mixed|empty",
              "cardinality": int,          # valeurs distinctes non-null
              "null_count": int,
              "numeric_stats": {...}|None, # si type = numeric
              "date_range": {...}|None,    # si type = date
              "top_values": [...],         # top-5, omis si cardinalité > cap
            }, …
          ],
        }
    """
    row_count = len(rows)
    out_columns: list[dict[str, Any]] = []

    for i, col in enumerate(columns):
        values = [row[i] if i < len(row) else None for row in rows]
        non_null = [v for v in values if v is not None and v != ""]
        dominant = _classify_column(values)
        # Cardinalité sur le VALEURS HASHABLES seulement (sinon set() fail)
        try:
            card = len({v for v in non_null})
        except TypeError:
            card = len({str(v) for v in non_null})

        col_info: dict[str, Any] = {
            "name": col,
            "type": dominant,
            "cardinality": card,
            "null_count": row_count - len(non_null),
        }

        if dominant == "numeric":
            stats = _numeric_stats(values)
            if stats:
                col_info["numeric_stats"] = stats
            # Détection ROLLUP : une colonne numérique dont la cardinalité est
            # très basse par rapport au row_count est presque certainement un
            # résultat de window function (SUM OVER PARTITION BY…) — la même
            # valeur se répète sur plusieurs lignes. SUM/AVG naïf = résultat
            # faux (double-comptage). On signale la colonne pour que le
            # Composer la traite via ``scalar_from_column`` au lieu de
            # ``scalar_aggregate``.
            if row_count >= 3 and len(non_null) >= 2:
                rollup_ratio = card / max(1, len(non_null))
                # Seuil : au-dessus de 3 répétitions moyennes par valeur
                # distinct ET cardinalité absolue faible → probable rollup.
                if rollup_ratio <= 0.4 and card <= max(10, row_count // 3):
                    col_info["likely_rollup"] = True

        if dominant == "date":
            rng = _date_range(values)
            if rng:
                col_info["date_range"] = rng

        # Top values : pour catégoriels + mixed. Pour numérique seulement si
        # cardinalité basse (éviter de remonter un float continu).
        if dominant in ("text", "mixed") or (
            dominant == "numeric" and card <= _NUMERIC_CARDINALITY_CAP
        ):
            col_info["top_values"] = _top_values(values)

        out_columns.append(col_info)

    return {
        "row_count": row_count,
        "columns": out_columns,
    }


def columns_by_role(profile: dict[str, Any]) -> dict[str, list[str]]:
    """Helper : regroupe les colonnes par rôle analytique pour guider l'Analyst.

    - measure    : colonnes numériques (candidates à SUM/AVG)
    - date       : colonnes temporelles (candidates à axe X line chart)
    - category   : text/mixed avec cardinalité faible (≤ 20) — bar/pie
    - id         : cardinalité ≈ row_count (colonne identifiante)
    """
    row_count = profile.get("row_count", 0) or 1
    roles: dict[str, list[str]] = {
        "measure": [],
        "date": [],
        "category": [],
        "id": [],
        "other": [],
    }
    for c in profile.get("columns", []):
        name, ctype, card = c["name"], c.get("type"), c.get("cardinality", 0)
        if ctype == "numeric":
            roles["measure"].append(name)
        elif ctype == "date":
            roles["date"].append(name)
        elif ctype in ("text", "mixed"):
            if row_count and card >= row_count * 0.9:
                roles["id"].append(name)
            elif card <= 20:
                roles["category"].append(name)
            else:
                roles["other"].append(name)
        else:
            roles["other"].append(name)
    return roles


