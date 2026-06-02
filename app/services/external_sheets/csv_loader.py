"""Charge des fichiers CSV avec détection d'encodage et de séparateur."""

from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import List, Optional

import tornado.web

logger = logging.getLogger(__name__)

DEFAULT_MAX_ROWS = 50000
ENCODING_CANDIDATES = ("utf-8-sig", "utf-8", "latin-1")
SNIFF_DELIMITERS = ";,\t|"
SNIFF_SAMPLE_SIZE = 64 * 1024


def _detect_encoding(raw: bytes, hint: Optional[str] = None) -> str:
    """Essaie successivement plusieurs encodages jusqu'à trouver un décodage propre."""
    if hint:
        try:
            raw.decode(hint)
            return hint
        except (UnicodeDecodeError, LookupError):
            pass
    for enc in ENCODING_CANDIDATES:
        try:
            raw.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    return "latin-1"


def _detect_separator(text: str, hint: Optional[str] = None) -> str:
    """Utilise csv.Sniffer avec fallback `;` (courant en France)."""
    if hint:
        return hint
    sample = text[:SNIFF_SAMPLE_SIZE]
    if not sample.strip():
        return ";"
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=SNIFF_DELIMITERS)
        return dialect.delimiter
    except csv.Error:
        return ";"


def _dedupe_columns(columns: List[str]) -> List[str]:
    seen: dict[str, int] = {}
    result = []
    for col in columns:
        base = col if col else ""
        if base not in seen:
            seen[base] = 1
            result.append(base)
        else:
            seen[base] += 1
            result.append(f"{base} ({seen[base]})")
    return result


def load_csv_file(
    path: Path,
    encoding: Optional[str] = None,
    separator: Optional[str] = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> dict:
    """Charge un fichier CSV et retourne un dict compatible format classeur.

    Returns:
        {
            "columns": list[str],
            "rows": list[list[str]],
            "row_count": int,
            "truncated": bool,
            "detected_encoding": str,
            "detected_separator": str,
            "merges": [],
        }
    """
    if not path.exists() or not path.is_file():
        raise tornado.web.HTTPError(404, "Fichier CSV introuvable")

    if max_rows <= 0:
        max_rows = DEFAULT_MAX_ROWS

    try:
        raw = path.read_bytes()
    except OSError as e:
        logger.warning("Lecture CSV %s échouée: %s", path, e)
        raise tornado.web.HTTPError(400, "Fichier CSV illisible")

    if not raw:
        return {
            "columns": [],
            "rows": [],
            "row_count": 0,
            "truncated": False,
            "detected_encoding": encoding or "utf-8",
            "detected_separator": separator or ",",
            "merges": [],
        }

    detected_encoding = _detect_encoding(raw, encoding)
    try:
        text = raw.decode(detected_encoding)
    except UnicodeDecodeError:
        text = raw.decode(detected_encoding, errors="replace")

    detected_separator = _detect_separator(text, separator)

    truncated = False
    try:
        reader = csv.reader(io.StringIO(text), delimiter=detected_separator)
        header_row = next(reader, None)
        if header_row is None:
            return {
                "columns": [],
                "rows": [],
                "row_count": 0,
                "truncated": False,
                "detected_encoding": detected_encoding,
                "detected_separator": detected_separator,
                "merges": [],
            }
        data_rows: List[List[str]] = []
        for row in reader:
            if len(data_rows) >= max_rows:
                truncated = True
                break
            data_rows.append(row)
    except csv.Error as e:
        logger.warning("Parse CSV %s échoué: %s", path, e)
        raise tornado.web.HTTPError(400, "Fichier CSV mal formé")

    max_cols = len(header_row)
    for row in data_rows:
        if len(row) > max_cols:
            max_cols = len(row)

    columns_raw = [
        (cell.strip() if cell and cell.strip() else f"Colonne {i + 1}")
        for i, cell in enumerate(header_row)
    ]
    while len(columns_raw) < max_cols:
        columns_raw.append(f"Colonne {len(columns_raw) + 1}")
    columns = _dedupe_columns(columns_raw)

    normalized_rows: List[List[str]] = []
    for row in data_rows:
        if len(row) < max_cols:
            row = row + [""] * (max_cols - len(row))
        elif len(row) > max_cols:
            row = row[:max_cols]
        normalized_rows.append(list(row))

    return {
        "columns": columns,
        "rows": normalized_rows,
        "row_count": len(normalized_rows),
        "truncated": truncated,
        "detected_encoding": detected_encoding,
        "detected_separator": detected_separator,
        "merges": [],
    }
