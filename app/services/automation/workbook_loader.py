"""Loader de classeurs depuis le datastore + parser de sélecteur d'onglets.

D3 phase 3 (cycle 21) : extrait des méthodes ``_load_workbook_from_datastore``
et ``_parse_tabs_selector`` de :class:`AutomationExecutor`. Aucune dépendance
au runtime executor — uniquement au datastore handler et aux parsers
external_sheets.

Sécurité (anti path-traversal) : :func:`_safe_path` du module datastore
bloque les chemins absolus, traversals (``..``) et symlinks. Cap mémoire
50 MB par fichier sur la taille COMPRESSÉE (``MAX_LOAD_WORKBOOK_BYTES``,
configurable) pour prévenir les OOM au PARSING openpyxl/CSV (axe distinct).
La décompression des ``.afz.json`` est, elle, bornée par le quota de stockage
admin (SSoT) via le helper partagé ``decode_afz_bytes`` — plus aucun cap de
décompression hardcodé.

Formats supportés :
* ``.afz.json`` / ``.json`` : format natif Komptia multi-onglets
* ``.xlsx`` / ``.xls`` : converti via openpyxl + defusedxml
* ``.csv`` : converti avec auto-detection encoding/séparateur
"""

from __future__ import annotations

import asyncio
import json as _json
import os
from typing import Any, Dict, List

from app.utils.logger import get_logger

# Cluster-J 2026-05-26 — cap mémoire défense-en-profondeur sur la taille
# COMPRESSÉE du fichier avant PARSING (openpyxl/CSV). Protège contre un .xlsx/
# .csv malicieux qui exploserait en RAM au parsing. ⚠️ Axe DISTINCT du quota
# admin : pour les ``.afz.json``, la borne de DÉCOMPRESSION est désormais le
# quota de stockage admin (SSoT) via ``decode_afz_bytes`` — plus aucun cap de
# décompression hardcodé. Ce cap-ci reste un garde-fou parsing technique, PAS un
# plafond admin (cf. ``feedback_no_double_cap``). Configurable via env.
MAX_LOAD_WORKBOOK_BYTES = int(os.environ.get("KOMPTIA_WORKBOOK_LOAD_MAX_MB", "50")) * 1024 * 1024

logger = get_logger(__name__)

# Cap LIGNES sur le parsing Excel/CSV en step load_workbook. Aligné avec
# DEFAULT_MAX_ROWS des loaders external_sheets. Configurable via env (doctrine
# ``feedback_no_double_cap`` — pas de cap caché). Quand atteint, les loaders
# retournent ``truncated=True`` : on PROPAGE ce flag au tab + log WARNING
# (cf. A3-F1 — ne JAMAIS tronquer en silence : les agrégats/rapports en aval
# seraient calculés sur un sous-ensemble sans aucun avertissement).
LOAD_WORKBOOK_MAX_ROWS = int(os.environ.get("KOMPTIA_WORKBOOK_LOAD_MAX_ROWS", "50000"))


async def load_workbook_from_datastore(
    user_id: int,
    relative_path: str,
    step_name: str,
) -> Dict[str, Any]:
    """Charge un classeur Komptia depuis le datastore d'un utilisateur.

    Formats supportés :
    - ``.afz.json`` (ou ``.json``) : format natif multi-onglets — lu tel
      quel (le format est déjà celui qu'attend le DAG executor).
    - ``.xlsx`` / ``.xls`` : converti en workbook 1 onglet via
      ``load_excel_sheet`` du module external_sheets (parser openpyxl
      + defusedxml, cap mémoire enforce).
    - ``.csv`` : converti en workbook 1 onglet via ``load_csv_file``
      (auto-detect encoding + separator, cap mémoire enforce).

    Sécurité :
    - ``_safe_path`` (datastore.py) bloque les path-traversal (..),
      les chemins absolus et les liens symboliques. Le user est isolé
      dans son ``_user_dir(user_id)``.
    - Échec fail-closed : ValueError détaillée si fichier introuvable,
      format non supporté ou parsing échoue.

    Retourne un workbook au format ``{"tabs": [...]}`` que les autres
    steps DAG peuvent consommer.
    """
    from app.handlers.datastore import _safe_path, _user_dir

    if not relative_path:
        raise ValueError(f"Etape '{step_name}' (load_workbook): chemin de fichier manquant")

    user_dir = _user_dir(user_id)
    target = _safe_path(user_dir, relative_path)
    if target is None:
        raise ValueError(
            f"Etape '{step_name}' (load_workbook): chemin '{relative_path}' "
            "rejete (path-traversal, absolute ou symlink)"
        )
    if not target.exists() or not target.is_file():
        raise ValueError(
            f"Etape '{step_name}' (load_workbook): fichier '{relative_path}' "
            "introuvable dans /datastore"
        )

    # Cap mémoire AVANT tout parsing : évite OOM sur fichier malicieux.
    # Porte sur la taille COMPRESSÉE (MAX_LOAD_WORKBOOK_BYTES = 50 MB par défaut) ;
    # la borne décompressée est gérée en aval par decode_afz_bytes.
    try:
        file_size = target.stat().st_size
    except OSError as exc:
        raise ValueError(
            f"Etape '{step_name}' (load_workbook): impossible de stat "
            f"'{relative_path}' ({exc.__class__.__name__})"
        ) from exc
    if file_size > MAX_LOAD_WORKBOOK_BYTES:
        raise ValueError(
            f"Etape '{step_name}' (load_workbook): fichier "
            f"'{relative_path}' trop volumineux ({file_size} octets > "
            f"{MAX_LOAD_WORKBOOK_BYTES})"
        )

    suffix = target.suffix.lower()
    # On reconnait .afz.json (composé) et .json (simple). On évite le
    # piège "fichier.afz" sans .json final qu'un user aurait pu créer.
    is_json = target.name.endswith(".afz.json") or suffix == ".json"

    if is_json:
        try:
            # SINGLE SOURCE OF TRUTH : ``classeur.reader.decode_afz_bytes`` —
            # détection gzip (magic bytes 0x1f 0x8b), décompression BORNÉE +
            # TOLÉRANTE aux octets de queue, puis json.loads. Auparavant ce code
            # ré-implémentait ``_load_json_sync`` inline avec ``gzip.decompress``
            # (sans borne RAM + fragile aux octets de queue → BadGzipFile sur un
            # classeur pourtant valide). On délègue désormais au helper partagé.
            from app.services.classeur.reader import decode_afz_bytes

            raw_bytes = await asyncio.to_thread(target.read_bytes)

            # gzip.decompress + json.loads peuvent bloquer l'event loop
            # 100-500ms sur un workbook volumineux → thread worker pour ne pas
            # bloquer Tornado (autres handlers + WS preview restent réactifs).
            data = await asyncio.to_thread(decode_afz_bytes, raw_bytes, source=relative_path)
        except (OSError, _json.JSONDecodeError, ValueError) as exc:
            raise ValueError(
                f"Etape '{step_name}' (load_workbook): impossible de lire "
                f"'{relative_path}' ({exc.__class__.__name__})"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("tabs"), list):
            raise ValueError(
                f"Etape '{step_name}' (load_workbook): '{relative_path}' "
                "n'est pas un classeur valide (tabs[] manquant)"
            )
        # On normalise un minimum pour que le DAG executor puisse
        # consommer sans surprise (label par défaut, rows/columns liste).
        tabs_norm: List[Dict[str, Any]] = []
        for idx, t in enumerate(data["tabs"]):
            if not isinstance(t, dict):
                continue
            tabs_norm.append(
                {
                    "label": t.get("label") or f"Onglet {idx + 1}",
                    "columns": list(t.get("columns") or []),
                    "rows": list(t.get("rows") or []),
                    "sql": t.get("sql") or "",
                    # #133 — préserver la troncature SOURCE persistée dans le .afz.json.
                    # Les branches .xlsx/.csv posent déjà `truncated` (l.202/237) ; cette
                    # whitelist de reload le DROPPAIT → un classeur sauvegardé tronqué
                    # rechargé en automation perdait le flag → agrégats du rapport faux
                    # silencieux (la whitelist ne doit pas raboter un booléen structurel).
                    "truncated": bool(t.get("truncated")),
                }
            )
        if not tabs_norm:
            raise ValueError(
                f"Etape '{step_name}' (load_workbook): '{relative_path}' "
                "ne contient aucun onglet exploitable"
            )
        return {"tabs": tabs_norm}

    if suffix in (".xlsx", ".xls"):
        from app.services.external_sheets import load_excel_sheet

        try:
            # first_row_as_header=True : convention Excel standard.
            # sheet_name=None : 1ère feuille (l'utilisateur splitte les
            # feuilles via plusieurs steps load_workbook si besoin).
            result = await asyncio.to_thread(
                load_excel_sheet, target, None, LOAD_WORKBOOK_MAX_ROWS, True
            )
        except Exception as exc:
            raise ValueError(
                f"Etape '{step_name}' (load_workbook): echec parsing "
                f"Excel '{relative_path}' ({exc.__class__.__name__})"
            ) from exc
        _truncated = bool(result.get("truncated"))
        if _truncated:
            logger.warning(
                "Etape '%s' (load_workbook): Excel '%s' TRONQUÉ à %d lignes — le "
                "fichier en contient davantage. Les agrégats/rapports en aval "
                "porteront sur ce sous-ensemble. Flag `truncated` propagé au tab.",
                step_name,
                relative_path,
                LOAD_WORKBOOK_MAX_ROWS,
            )
        return {
            "tabs": [
                {
                    "label": result.get("sheet_name") or target.stem,
                    "columns": list(result.get("columns") or []),
                    "rows": list(result.get("rows") or []),
                    "sql": "",
                    "truncated": _truncated,
                }
            ]
        }

    if suffix == ".csv":
        from app.services.external_sheets import load_csv_file

        try:
            # encoding=None / separator=None : auto-detection.
            result = await asyncio.to_thread(
                load_csv_file, target, None, None, LOAD_WORKBOOK_MAX_ROWS
            )
        except Exception as exc:
            raise ValueError(
                f"Etape '{step_name}' (load_workbook): echec parsing "
                f"CSV '{relative_path}' ({exc.__class__.__name__})"
            ) from exc
        _truncated = bool(result.get("truncated"))
        if _truncated:
            logger.warning(
                "Etape '%s' (load_workbook): CSV '%s' TRONQUÉ à %d lignes — le "
                "fichier en contient davantage. Les agrégats/rapports en aval "
                "porteront sur ce sous-ensemble. Flag `truncated` propagé au tab.",
                step_name,
                relative_path,
                LOAD_WORKBOOK_MAX_ROWS,
            )
        return {
            "tabs": [
                {
                    "label": target.stem,
                    "columns": list(result.get("columns") or []),
                    "rows": list(result.get("rows") or []),
                    "sql": "",
                    "truncated": _truncated,
                }
            ]
        }

    raise ValueError(
        f"Etape '{step_name}' (load_workbook): extension '{suffix}' non "
        "supportee. Formats acceptes : .afz.json, .json, .xlsx, .xls, .csv"
    )


def parse_tabs_selector(raw: Any, all_tabs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse le sélecteur d'onglets pour export_workbook.

    Formats acceptés :
    - ``"all"`` / vide / ``None``  → tous les onglets
    - ``"0,2,3"``                  → onglets aux indices indiqués
    - liste d'indices              → idem (pour souplesse JSON)

    Indices hors limites sont silencieusement ignorés. Si aucun indice
    valide, lève ValueError (anti silent-empty-export).
    """
    if raw is None:
        return list(all_tabs)
    if isinstance(raw, str):
        value = raw.strip().lower()
        # TABS-1 — sentinel explicite « tout décoché » émis par le picker
        # frontend (workbook_tabs_multi_picker). DOIT être distinct de « tous » :
        # on refuse fail-closed au lieu d'exporter silencieusement TOUS les
        # onglets. (``""`` legacy reste « tous » pour compat des configs
        # existantes ; le picker n'émet plus jamais ``""``.)
        if value == "none":
            raise ValueError(
                "Aucun onglet sélectionné pour l'export. Cochez « Tous » ou au "
                "moins un onglet dans la configuration de l'étape."
            )
        if value in ("", "all", "*"):
            return list(all_tabs)
        try:
            indices = [int(p.strip()) for p in raw.split(",") if p.strip()]
        except ValueError:
            raise ValueError(
                f"Selecteur d'onglets invalide : '{raw}'. "
                "Attendu : 'all' ou liste d'indices ('0,2,3')"
            )
    elif isinstance(raw, list):
        try:
            indices = [int(i) for i in raw]
        except (TypeError, ValueError):
            raise ValueError(f"Selecteur d'onglets invalide : {raw}. Indices entiers attendus")
    else:
        raise ValueError(f"Selecteur d'onglets invalide (type {type(raw).__name__})")

    selected: List[Dict[str, Any]] = []
    for i in indices:
        if 0 <= i < len(all_tabs):
            selected.append(all_tabs[i])
    if not selected:
        raise ValueError(
            f"Selecteur d'onglets '{raw}' ne reference aucun onglet existant "
            f"(workbook a {len(all_tabs)} onglet(s))"
        )
    return selected


__all__ = (
    "MAX_LOAD_WORKBOOK_BYTES",
    "load_workbook_from_datastore",
    "parse_tabs_selector",
)
