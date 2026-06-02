"""
Renderer de graphiques depuis des données PRÉ-AGRÉGÉES fournies par le LLM.

Contrairement à ChartBuilder qui reçoit des données brutes et tente de deviner
comment les tracer, ce module prend directement les données finales :
- Bar : liste de (label, value)
- Line : liste de séries, chaque série est (name, points[(x, y)])
- Pie : liste de (label, value)

Le LLM voit les données brutes, fait l'agrégation/groupage dans sa tête, et
nous donne le rendu final. Résultat : graphiques toujours pertinents.
"""

from __future__ import annotations

import math
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib

matplotlib.use("Agg")  # Backend sans affichage
import matplotlib.pyplot as plt

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Palette cohérente avec ChartBuilder
_COLORS = [
    "#366092",  # Bleu principal
    "#2ecc71",  # Vert
    "#e74c3c",  # Rouge
    "#f39c12",  # Orange
    "#9b59b6",  # Violet
    "#1abc9c",  # Turquoise
    "#34495e",  # Gris foncé
    "#e67e22",  # Orange foncé
    "#3498db",  # Bleu clair
    "#16a085",  # Vert foncé
]

# Caps pour éviter des graphiques illisibles ou des abus LLM
_MAX_BARS = 30
_MAX_SLICES = 10
_MAX_SERIES = 8
_MAX_POINTS_PER_SERIES = 100


def _safe_float(val: Any) -> Optional[float]:
    """Convert to finite float (rejects None, NaN, +/-inf, bool)."""
    if val is None or isinstance(val, bool):
        return None
    try:
        f = float(val)
    except (ValueError, TypeError):
        return None
    if not math.isfinite(f):  # rejects NaN and infinities
        return None
    return f


def _make_temp_png() -> Path:
    fd, name = tempfile.mkstemp(suffix=".png")
    import os

    os.close(fd)
    return Path(name)


def render_aggregated_chart(cfg: Dict[str, Any]) -> Optional[Path]:
    """Render a chart from a pre-aggregated config. Returns PNG path or None on failure.

    cfg schema (one of):
        {type: "bar", title, bars: [{label, value}], x_label?, y_label?}
        {type: "line", title, series: [{name, points: [{x, y}]}], x_label?, y_label?}
        {type: "pie", title, slices: [{label, value}]}
    """
    try:
        ctype = cfg.get("type") or cfg.get("chart_type")
        if ctype == "bar":
            return _render_bar(cfg)
        if ctype == "line":
            return _render_line(cfg)
        if ctype == "pie":
            return _render_pie(cfg)
        logger.warning("render_aggregated_chart: type inconnu '%s'", ctype)
        return None
    except Exception as e:
        logger.warning("render_aggregated_chart failed: %s", e, exc_info=True)
        return None


def _render_bar(cfg: Dict[str, Any]) -> Optional[Path]:
    bars = cfg.get("bars") or []
    if not bars:
        return None

    # Clean + cap
    clean: List[tuple] = []
    for b in bars[:_MAX_BARS]:
        if not isinstance(b, dict):
            continue
        label = str(b.get("label", ""))[:60]
        val = _safe_float(b.get("value"))
        if val is None:
            continue
        clean.append((label, val))
    if not clean:
        return None

    labels = [c[0] for c in clean]
    values = [c[1] for c in clean]

    # Adaptive figure width for many bars
    width = max(7, min(14, 0.45 * len(labels) + 5))
    fig, ax = plt.subplots(figsize=(width, 5), dpi=150)
    bars_drawn = ax.bar(
        range(len(labels)), values, color=_COLORS[0], edgecolor="white", linewidth=1.2
    )
    ax.set_xticks(range(len(labels)))
    rotation = 0 if max(len(l) for l in labels) <= 8 and len(labels) <= 10 else 30
    ax.set_xticklabels(labels, rotation=rotation, ha="right" if rotation else "center")
    if cfg.get("x_label"):
        ax.set_xlabel(str(cfg["x_label"])[:80])
    if cfg.get("y_label"):
        ax.set_ylabel(str(cfg["y_label"])[:80])
    if cfg.get("title"):
        ax.set_title(str(cfg["title"])[:120], fontsize=12, pad=14)
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Value labels on top of bars (only if not too many)
    if len(labels) <= 20:
        for rect, v in zip(bars_drawn, values):
            ax.text(
                rect.get_x() + rect.get_width() / 2,
                rect.get_height(),
                _fmt_number(v),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#333",
            )

    fig.tight_layout()
    out = _make_temp_png()
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


def _render_line(cfg: Dict[str, Any]) -> Optional[Path]:
    series_raw = cfg.get("series") or []
    if not series_raw:
        return None

    # Clean + cap
    clean_series: List[Dict[str, Any]] = []
    for s in series_raw[:_MAX_SERIES]:
        if not isinstance(s, dict):
            continue
        name = str(s.get("name", ""))[:60]
        points_raw = s.get("points") or []
        points: List[tuple] = []
        for p in points_raw[:_MAX_POINTS_PER_SERIES]:
            if not isinstance(p, dict):
                continue
            x = p.get("x")
            y = _safe_float(p.get("y"))
            if x is None or y is None:
                continue
            points.append((str(x)[:60], y))
        if len(points) >= 2:  # need at least 2 points for a line
            clean_series.append({"name": name, "points": points})

    if not clean_series:
        return None

    # Determine a stable x-axis: union of x values from all series, in order of first appearance
    x_order: List[str] = []
    seen = set()
    for s in clean_series:
        for x, _ in s["points"]:
            if x not in seen:
                seen.add(x)
                x_order.append(x)

    width = max(8, min(14, 0.4 * len(x_order) + 6))
    fig, ax = plt.subplots(figsize=(width, 5), dpi=150)

    for i, s in enumerate(clean_series):
        color = _COLORS[i % len(_COLORS)]
        # Detect duplicate x within this series before the dict comp silently
        # keeps only the last y (axe 5 CLAUDE.md — données fausses sans signal).
        # On loggue UNIQUEMENT les compteurs et l'index de série (PAS les valeurs
        # x ni le nom de série) pour ne pas leaker de PII Sage dans les logs
        # (contrat confidentialité G CLAUDE.md — logs sans PII non anonymisés).
        seen_xs: set = set()
        duplicate_set: set = set()
        for x, _ in s["points"]:
            if x in seen_xs:
                duplicate_set.add(x)
            else:
                seen_xs.add(x)
        if duplicate_set:
            logger.warning(
                "_render_line: doublons d'x ignorés dans la série #%d "
                "(silent dedup, seul le dernier y conservé) : "
                "%d valeur(s) x distincte(s) en collision",
                i + 1,
                len(duplicate_set),
            )
        # Map points by x for this series
        points_by_x = {x: y for x, y in s["points"]}
        xs = list(range(len(x_order)))
        ys = [points_by_x.get(x) for x in x_order]  # None = gap
        # Filter out None while keeping position
        filtered_xs = [xi for xi, yi in zip(xs, ys) if yi is not None]
        filtered_ys = [yi for yi in ys if yi is not None]
        if not filtered_xs:
            continue
        ax.plot(
            filtered_xs,
            filtered_ys,
            marker="o",
            linewidth=2,
            color=color,
            label=s["name"] or f"Série {i + 1}",
            markersize=5,
        )

    ax.set_xticks(range(len(x_order)))
    rotation = 0 if max(len(x) for x in x_order) <= 10 and len(x_order) <= 12 else 30
    ax.set_xticklabels(x_order, rotation=rotation, ha="right" if rotation else "center")
    if cfg.get("x_label"):
        ax.set_xlabel(str(cfg["x_label"])[:80])
    if cfg.get("y_label"):
        ax.set_ylabel(str(cfg["y_label"])[:80])
    if cfg.get("title"):
        ax.set_title(str(cfg["title"])[:120], fontsize=12, pad=14)
    ax.grid(axis="y", linestyle=":", alpha=0.4)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if len(clean_series) > 1:
        ax.legend(loc="best", fontsize=9, framealpha=0.95)

    fig.tight_layout()
    out = _make_temp_png()
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


def _render_pie(cfg: Dict[str, Any]) -> Optional[Path]:
    slices_raw = cfg.get("slices") or []
    if not slices_raw:
        return None

    clean: List[tuple] = []
    for s in slices_raw[:_MAX_SLICES]:
        if not isinstance(s, dict):
            continue
        label = str(s.get("label", ""))[:40]
        val = _safe_float(s.get("value"))
        if val is None or val <= 0:
            continue
        clean.append((label, val))
    if not clean:
        return None

    labels = [c[0] for c in clean]
    values = [c[1] for c in clean]

    fig, ax = plt.subplots(figsize=(8, 6), dpi=150)
    colors = _COLORS[: len(labels)]
    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=90,
        colors=colors,
        pctdistance=0.75,
        wedgeprops={"edgecolor": "white", "linewidth": 1.5},
    )
    for t in autotexts:
        t.set_color("white")
        t.set_fontweight("bold")
        t.set_fontsize(9)
    if cfg.get("title"):
        ax.set_title(str(cfg["title"])[:120], fontsize=12, pad=14)

    fig.tight_layout()
    out = _make_temp_png()
    fig.savefig(out, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return out


def _fmt_number(v: float) -> str:
    """Short number formatter (1234.5 → '1,2k')."""
    if abs(v) >= 1_000_000:
        return f"{v / 1_000_000:.1f}M".replace(".0M", "M")
    if abs(v) >= 1_000:
        return f"{v / 1_000:.1f}k".replace(".0k", "k")
    if abs(v) >= 10:
        return f"{v:.0f}"
    return f"{v:.1f}"
