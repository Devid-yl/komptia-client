"""Lecture et extraction de données depuis les classeurs Komptia (.afz.json).

Les classeurs sont stockés dans `data/datastore/<user_id>/` sous forme de
fichiers JSON multi-onglets avec cellDetails (drill-down SQL par cellule).

Ce module centralise les helpers (anciennement dupliqués dans reports.py)
pour que les pages /iris, /datastore et /reports partagent la même logique.

Format `.afz.json`:
    {
        "version": 1,
        "app": "komptia",
        "tabs": [
            {
                "label": "Résultat (119)",
                "columns": [...],
                "rows": [[...], ...],
                "totalRowCount": 147,
                "sql": "SELECT ...",
                "cellDetails": {
                    "2,1": {
                        "columns": [...],
                        "rows": [...],
                        "sql": "..."
                    }
                }
            }
        ]
    }
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import tornado.web

from app.utils.gzip_safe import GunzipError, gunzip_first_member, is_gzip_magic
from app.utils.logger import get_logger

logger = get_logger(__name__)

# SOURCE UNIQUE de toutes les limites de classeur = le quota de stockage par
# user défini par l'admin (/admin/performance → STORAGE_QUOTA_PER_USER_BYTES),
# résolu au runtime via ``storage_manager.get_storage_quota_bytes[_sync]``.
# Plus AUCUN cap de décompression hardcodé : ni taille disque, ni taille
# décompressée. Le quota borne les deux (et donc aussi la RAM de décompression —
# cf. la docstring de get_storage_quota_bytes : l'admin dimensionne vs conteneur).


def decode_afz_bytes(
    raw: bytes,
    *,
    source: str = "",
    max_decompressed_bytes: Optional[int] = None,
) -> Any:
    """Décode des octets ``.afz.json`` (gzip transparent) → objet JSON parsé.

    SINGLE SOURCE OF TRUTH pour transformer des octets de classeur en données :
    web UI (``_load_json_sync``), automation (``workbook_loader``), copilot, scan
    anonymisation, cleanup job. Détecte le gzip (magic bytes), décompresse en
    streaming BORNÉ + TOLÉRANT aux octets de queue (cf. ``gunzip_first_member``),
    puis ``json.loads``. Rétrocompat : les classeurs ante-gzip (JSON brut) passent
    directement par ``json.loads``.

    Lève ``json.JSONDecodeError`` sur TOUT échec (décompression bornée/tronquée OU
    parsing JSON) — contrat conservé pour les callers existants qui l'attrapent
    déjà (``read_classeur``, ``workbook_loader``). Un échec de décompression est
    aussi loggé en WARNING avec la cause réelle (diagnostic — auparavant avalé).

    Borne de décompression : ``max_decompressed_bytes`` si fourni, sinon le quota
    de stockage admin (SSoT, version sync cache-only car on peut être dans un
    thread). Plus aucun cap hardcodé.
    """
    if max_decompressed_bytes is None:
        from app.services.storage_manager import get_storage_quota_bytes_sync

        cap = get_storage_quota_bytes_sync()
    else:
        cap = max_decompressed_bytes
    if is_gzip_magic(raw):
        try:
            raw = gunzip_first_member(raw, cap)
        except GunzipError as exc:
            logger.warning("Décompression .afz.json échouée (%s) : %s", source or "?", exc)
            raise json.JSONDecodeError(
                f"Gzip décompression échouée : {exc}", source or "<gzip>", 0
            ) from exc
    return json.loads(raw.decode("utf-8"))


def _load_json_sync(path: Path) -> Any:
    """Charge un .afz.json depuis le disque, transparent gzip ou brut.

    Lit les octets puis délègue à :func:`decode_afz_bytes` (SSoT) qui détecte le
    gzip, décompresse de façon bornée + tolérante, et parse le JSON. Rétrocompat
    avec les classeurs créés avant le refacto gzip — aucune migration nécessaire.
    """
    with open(path, "rb") as f:
        raw = f.read()
    return decode_afz_bytes(raw, source=str(path))


async def read_classeur(user_id: int, filename: str) -> dict:
    """Charge un fichier .afz.json pour un utilisateur donné.

    Réutilise le pattern datastore (_user_dir + _safe_path) pour isoler
    les classeurs par utilisateur et bloquer les path traversal.

    Raises HTTPError pour fichier manquant, invalide ou trop volumineux.
    """
    from app.handlers.datastore import _safe_path, _user_dir
    from app.services.storage_manager import get_storage_quota_bytes

    if not filename.endswith(".json"):
        raise tornado.web.HTTPError(400, "Fichier non supporte (doit etre .json)")

    user_dir = _user_dir(user_id)
    target = _safe_path(user_dir, filename)
    if target is None or not target.exists() or not target.is_file():
        raise tornado.web.HTTPError(404, "Classeur introuvable")

    # SOURCE UNIQUE : le quota admin borne la taille (un fichier ne peut pas
    # dépasser le quota total du user). Décompression bornée par le même quota
    # (cf. _load_json_sync → decode_afz_bytes → get_storage_quota_bytes_sync).
    quota = await get_storage_quota_bytes()
    size = target.stat().st_size
    if size > quota:
        raise tornado.web.HTTPError(
            413, f"Classeur trop volumineux (max {quota // (1024 * 1024)} Mo)"
        )

    try:
        data = await asyncio.to_thread(_load_json_sync, target)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Erreur lecture classeur %s: %s", filename, e)
        raise tornado.web.HTTPError(400, "Impossible de lire le classeur")

    if not isinstance(data, dict):
        raise tornado.web.HTTPError(400, "Format de classeur invalide (pas un objet)")
    tabs = data.get("tabs")
    if not isinstance(tabs, list):
        raise tornado.web.HTTPError(400, "Format de classeur invalide (tabs manquant)")
    if not all(isinstance(t, dict) for t in tabs):
        raise tornado.web.HTTPError(400, "Format de classeur invalide (onglet non-objet)")

    return data


def rows_to_dicts(rows: list, columns: list) -> list:
    """Convertit des rows en format array vers une liste de dicts alignés sur columns."""
    if not rows or not columns:
        return []
    result = []
    for row in rows:
        if isinstance(row, dict):
            result.append(row)
        elif isinstance(row, list):
            result.append({col: row[i] if i < len(row) else None for i, col in enumerate(columns)})
    return result


def extract_source_data(
    tab: Dict[str, Any], cell_key: Optional[str]
) -> Tuple[list, list, str, str]:
    """Extrait columns/rows/label depuis un onglet ou une cellule drill-down.

    Returns: (columns, rows, label, source_sql)
    Raises: HTTPError(400) pour validation échouée.
    """
    if cell_key:
        cell_details = tab.get("cellDetails") or {}
        if not isinstance(cell_details, dict) or cell_key not in cell_details:
            raise tornado.web.HTTPError(400, f"Tableau '{cell_key}' introuvable")
        cell = cell_details[cell_key]
        if not isinstance(cell, dict):
            raise tornado.web.HTTPError(400, "Tableau drill-down invalide")
        columns = cell.get("columns") or []
        rows = cell.get("rows") or []
        source_sql = cell.get("sql", "")
        tab_label = tab.get("label", "Feuille")
        try:
            ordered_keys = list(cell_details.keys())
            position = ordered_keys.index(cell_key) + 1
            label = f"{tab_label} — tableau {position}"
        except ValueError:
            label = f"{tab_label} — tableau"
    else:
        columns = tab.get("columns") or []
        rows = tab.get("rows") or []
        source_sql = tab.get("sql", "")
        label = tab.get("label", "Feuille")

    if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns):
        raise tornado.web.HTTPError(400, "Colonnes invalides")
    if not isinstance(rows, list):
        raise tornado.web.HTTPError(400, "Données invalides (rows doit être une liste)")
    if not rows or not columns:
        raise tornado.web.HTTPError(400, "Source de données vide")
    if len(columns) != len(set(columns)):
        raise tornado.web.HTTPError(
            400, "Colonnes dupliquées détectées — impossible de générer le rapport"
        )

    return columns, rows, label, source_sql


def list_classeurs_sync(user_dir: Path, include_hidden: bool = False) -> list:
    """Scanne le datastore utilisateur pour les fichiers de type classeur.

    Appelé via asyncio.to_thread depuis les handlers.
    Retourne liste de {filename, name, size, modified}.

    ``include_hidden=False`` (défaut) exclut les dossiers cachés — notamment
    ``.widgets/`` (classeurs internes des widgets grille de dashboard) : ils
    ne doivent PAS apparaître dans les pickers (/api/workbooks,
    /api/reports/classeurs) car leurs rows sont des snapshots figés au
    dernier save du widget — les consommer comme source = données périmées
    silencieuses. ``include_hidden=True`` est réservé aux jobs système qui
    doivent voir TOUT le datastore (cleanup anonymisation : les termes
    vivant uniquement dans un classeur de widget seraient sinon purgés
    comme orphelins).
    """
    results = []
    for p in user_dir.rglob("*.json"):
        if not p.is_file():
            continue
        if not include_hidden:
            try:
                rel_parts = p.relative_to(user_dir).parts
            except ValueError:
                continue
            if any(part.startswith(".") for part in rel_parts):
                continue
        name_lower = p.name.lower()
        if "classeur" not in name_lower and ".afz" not in name_lower:
            continue
        try:
            rel = p.relative_to(user_dir)
            stat = p.stat()
            results.append(
                {
                    "filename": str(rel),
                    "name": p.name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                }
            )
        except (ValueError, OSError):
            continue
    return results


async def read_tab_data(user_id: int, filename: str, tab_index: int, max_rows: int = 50000) -> dict:
    """Retourne les données complètes d'un onglet d'un classeur.

    Utilisé par /api/workbooks/tab-data pour alimenter la result area d'un
    autre classeur. Tronque à max_rows pour limiter la charge mémoire navigateur.

    Returns:
        {
            "label": str,
            "columns": list[str],
            "rows": list[list],
            "row_count": int,
            "total_row_count": int,
            "truncated": bool,
            "sql": str,
            "cellDetails": dict,
        }
    """
    data = await read_classeur(user_id, filename)
    tabs = data.get("tabs", [])
    if not isinstance(tab_index, int) or tab_index < 0 or tab_index >= len(tabs):
        raise tornado.web.HTTPError(400, "tab_index hors limites")

    tab = tabs[tab_index]
    columns = tab.get("columns") or []
    rows = tab.get("rows") or []
    total_row_count = tab.get("totalRowCount", len(rows))
    truncated = False
    if isinstance(rows, list) and len(rows) > max_rows:
        rows = rows[:max_rows]
        truncated = True

    return {
        "label": tab.get("label", f"Feuille {tab_index + 1}"),
        "columns": columns if isinstance(columns, list) else [],
        "rows": rows if isinstance(rows, list) else [],
        "row_count": len(rows) if isinstance(rows, list) else 0,
        "total_row_count": total_row_count,
        "truncated": truncated,
        "sql": tab.get("sql", ""),
        "cellDetails": tab.get("cellDetails", {}) or {},
    }
