"""Stockage du classeur (.afz.json) d'un widget grille de dashboard.

Un widget grille peut être sauvegardé comme un VRAI classeur Komptia (même
format que /datastore : tabs, feuilles SQL via ``externalSource``, feuilles
manuelles, mise en forme, cellDetails) — c'est la source de vérité du widget
en « mode classeur ». Les fichiers vivent dans le datastore de l'utilisateur
sous un sous-dossier caché (``.widgets/`` — les dotfolders sont filtrés du
listing /datastore, cf. ``DatastoreListAPIHandler``), comptent dans son quota
de stockage (FileMetadata/UserStorage) et sont écrasés à chaque sauvegarde
(un fichier par widget → pas de croissance non bornée).

Réutilise le backend datastore existant (SSoT) :
- ``_user_dir`` / ``_safe_path`` (mêmes imports que ``classeur/reader.py``),
- gzip déterministe ``mtime=0`` (parité upload datastore),
- ``decode_afz_bytes`` (gunzip + cap quota anti zip-bomb),
- ``StorageManager`` + ``retry_on_locked`` pour quota/métadonnées.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import weakref
from pathlib import Path
from typing import Optional, Tuple

from app.core.database import get_session
from app.core.db_retry import retry_on_locked
from app.services.classeur.reader import decode_afz_bytes
from app.services.storage_manager import StorageManager, calculate_hash_from_bytes
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Sous-dossier (caché du listing /datastore) des classeurs de widgets.
_WIDGETS_SUBDIR = ".widgets"

#: Plafond de sécurité sur la taille DÉCOMPRESSÉE du JSON d'un classeur de
#: widget (anti bombe gzip — revue adv. 2026-06-10). Le quota disque admin
#: borne déjà la décompression côté lecture ; au SAVE on borne plus serré :
#: aucune grille réelle (sérialisée par le navigateur, qui plafonne bien
#: avant) n'approche cette taille, alors qu'une bombe 500 Ko → quota entier
#: pouvait allouer plusieurs Gio de RAM par requête. Dépassement = erreur
#: explicite (GunzipTooLargeError → 400), jamais de troncature silencieuse.
MAX_WORKBOOK_JSON_BYTES = 200 * 1024 * 1024  # 200 Mio

# ── Verrou par widget (anti lost-update) ────────────────────────────────────
# Sérialise les sections critiques lecture-hash → écriture-fichier (save
# manuel If-Match) et load → patch → save (_sync_workbook_sql_sheets) pour un
# même widget : sans verrou, deux PUT concurrents du même owner (deux onglets,
# revue adv. 2026-06-10 TOCTOU) passent tous deux le check If-Match puis
# s'écrasent en silence. Tornado est mono-process → asyncio.Lock suffit.
# WeakValueDictionary : pas de croissance non bornée (axe 21) — une entrée
# disparaît dès qu'aucune coroutine ne tient/attend le verrou.
_widget_locks: "weakref.WeakValueDictionary[tuple, asyncio.Lock]" = weakref.WeakValueDictionary()


def widget_lock(user_id: int, dashboard_id: int, widget_id: int) -> asyncio.Lock:
    """Verrou partagé pour toutes les écritures du classeur d'un widget."""
    key = (int(user_id), int(dashboard_id), int(widget_id))
    lock = _widget_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _widget_locks[key] = lock
    return lock


class WorkbookQuotaError(Exception):
    """Quota de stockage dépassé — message utilisateur dans ``str(exc)``."""


class WorkbookConflictError(Exception):
    """If-Match en échec : le classeur a été modifié ailleurs (autre onglet)."""


def workbook_rel_path(dashboard_id: int, widget_id: int) -> str:
    """Chemin relatif (POSIX) du classeur d'un widget dans le datastore user.

    Déterministe (ids uniquement, aucun input utilisateur) → pas de
    traversal possible ; ``_safe_path`` re-vérifie quand même (défense en
    profondeur).
    """
    return f"{_WIDGETS_SUBDIR}/dash{int(dashboard_id)}-w{int(widget_id)}.afz.json"


def _resolve_target(user_id: int, rel_path: str) -> Optional[Path]:
    # Import tardif : datastore.py importe beaucoup de modules au boot ;
    # même précédent que app/services/classeur/reader.py.
    from app.handlers.datastore import _safe_path, _user_dir

    return _safe_path(_user_dir(user_id), rel_path)


async def _register_upload(
    user_id: int, target: Path, rel_path: str, *, file_size: int, file_hash: str
) -> None:
    async def _coro() -> None:
        async with get_session() as db:
            mgr = StorageManager(db, _datastore_root())
            await mgr.register_upload(
                user_id, target, rel_path, file_size=file_size, file_hash=file_hash
            )

    await retry_on_locked(
        _coro, max_attempts=5, operation_name=f"widget_workbook.register_upload[{rel_path}]"
    )


async def _register_deletion(user_id: int, rel_path: str) -> None:
    async def _coro() -> None:
        async with get_session() as db:
            mgr = StorageManager(db, _datastore_root())
            await mgr.register_deletion(user_id, rel_path)

    await retry_on_locked(
        _coro, max_attempts=5, operation_name=f"widget_workbook.register_deletion[{rel_path}]"
    )


def _datastore_root() -> Path:
    from app.handlers.datastore import DATASTORE_DIR

    return DATASTORE_DIR


async def check_quota(user_id: int, size_bytes: int) -> Tuple[bool, Optional[str]]:
    """Vérifie le quota AVANT écriture (même contrat que l'upload datastore)."""
    async with get_session() as db:
        mgr = StorageManager(db, _datastore_root())
        return await mgr.check_quota(user_id, size_bytes)


async def save_workbook(
    user_id: int, dashboard_id: int, widget_id: int, data: dict
) -> Tuple[str, str]:
    """Écrit le classeur (gzip déterministe, écriture atomique) + quota/méta.

    Retourne ``(rel_path, file_hash)``. Lève :class:`WorkbookQuotaError` si
    le quota utilisateur est dépassé, ``ValueError`` si le chemin est invalide.
    """
    rel_path = workbook_rel_path(dashboard_id, widget_id)
    target = _resolve_target(user_id, rel_path)
    if target is None:
        raise ValueError("Chemin de classeur widget invalide.")

    raw = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
    body = await asyncio.to_thread(lambda: gzip.compress(raw, compresslevel=6, mtime=0))

    can_upload, quota_msg = await check_quota(user_id, len(body))
    if not can_upload:
        raise WorkbookQuotaError(quota_msg or "Quota de stockage dépassé.")

    existed = target.exists()
    await asyncio.to_thread(target.parent.mkdir, parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    try:
        await asyncio.to_thread(tmp.write_bytes, body)
        await asyncio.to_thread(os.replace, str(tmp), str(target))
    except Exception:
        try:
            if tmp.exists():
                await asyncio.to_thread(tmp.unlink)
        except OSError:
            pass
        raise

    file_hash = calculate_hash_from_bytes(body)
    # Quota/méta : remplacer = deletion (ancienne taille) + upload (nouvelle).
    # Une panne entre les deux dérive le compteur — réconcilié par
    # ``StorageManager.sync_user_storage`` (même classe de tolérance que
    # l'upload datastore).
    if existed:
        await _register_deletion(user_id, rel_path)
    await _register_upload(user_id, target, rel_path, file_size=len(body), file_hash=file_hash)
    logger.info(
        "Classeur widget sauvegardé : %s (%d octets gzip) user=%s", rel_path, len(body), user_id
    )
    return rel_path, file_hash


async def load_workbook(user_id: int, dashboard_id: int, widget_id: int) -> Optional[dict]:
    """Lit le classeur d'un widget. ``None`` si absent/corrompu (fail-graceful :
    le caller retombe sur le mode legacy ``config.query``/``extra_tabs``)."""
    rel_path = workbook_rel_path(dashboard_id, widget_id)
    target = _resolve_target(user_id, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return None
    try:
        raw = await asyncio.to_thread(target.read_bytes)
        data = await asyncio.to_thread(decode_afz_bytes, raw, source=rel_path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        logger.warning("Classeur widget illisible (%s) : %s", rel_path, exc)
        return None
    if not isinstance(data, dict) or not isinstance(data.get("tabs"), list):
        logger.warning("Classeur widget au format invalide : %s", rel_path)
        return None
    if not all(isinstance(t, dict) for t in data["tabs"]):
        logger.warning("Classeur widget : onglet non-objet : %s", rel_path)
        return None
    return data


async def load_workbook_with_hash(
    user_id: int, dashboard_id: int, widget_id: int
) -> Tuple[Optional[dict], Optional[str]]:
    """Comme :func:`load_workbook` mais retourne aussi le SHA-256 des octets
    sur disque (une seule lecture fichier — sert l'If-Match côté frontend)."""
    rel_path = workbook_rel_path(dashboard_id, widget_id)
    target = _resolve_target(user_id, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return None, None
    try:
        raw = await asyncio.to_thread(target.read_bytes)
        data = await asyncio.to_thread(decode_afz_bytes, raw, source=rel_path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        logger.warning("Classeur widget illisible (%s) : %s", rel_path, exc)
        return None, None
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("tabs"), list)
        or not all(isinstance(t, dict) for t in data["tabs"])
    ):
        logger.warning("Classeur widget au format invalide : %s", rel_path)
        return None, None
    return data, calculate_hash_from_bytes(raw)


async def current_hash(user_id: int, dashboard_id: int, widget_id: int) -> Optional[str]:
    """SHA-256 des octets ACTUELS sur disque (pour If-Match cross-onglets)."""
    rel_path = workbook_rel_path(dashboard_id, widget_id)
    target = _resolve_target(user_id, rel_path)
    if target is None or not target.exists() or not target.is_file():
        return None
    try:
        raw = await asyncio.to_thread(target.read_bytes)
    except OSError:
        return None
    return calculate_hash_from_bytes(raw)


async def delete_workbook(user_id: int, dashboard_id: int, widget_id: int) -> bool:
    """Supprime le classeur d'un widget (fichier + quota/méta). Idempotent."""
    rel_path = workbook_rel_path(dashboard_id, widget_id)
    target = _resolve_target(user_id, rel_path)
    if target is None or not target.exists():
        return False
    try:
        await asyncio.to_thread(target.unlink)
    except OSError as exc:
        logger.warning("Suppression classeur widget échouée (%s) : %s", rel_path, exc)
        return False
    try:
        await _register_deletion(user_id, rel_path)
    except Exception:  # noqa: BLE001 — quota réconcilié par sync_user_storage
        logger.warning("Désenregistrement quota échoué : %s", rel_path, exc_info=True)
    return True


async def delete_dashboard_workbooks(user_id: int, dashboard_id: int) -> int:
    """Supprime tous les classeurs de widgets d'un dashboard. Retourne le compte."""
    from app.handlers.datastore import _user_dir

    widgets_dir = _user_dir(user_id) / _WIDGETS_SUBDIR
    if not widgets_dir.is_dir():
        return 0
    prefix = f"dash{int(dashboard_id)}-w"
    count = 0
    try:
        children = await asyncio.to_thread(lambda: list(widgets_dir.iterdir()))
    except OSError:
        return 0
    for child in children:
        if not child.name.startswith(prefix) or not child.name.endswith(".afz.json"):
            continue
        rel_path = f"{_WIDGETS_SUBDIR}/{child.name}"
        try:
            await asyncio.to_thread(child.unlink)
        except OSError:
            continue
        try:
            await _register_deletion(user_id, rel_path)
        except Exception:  # noqa: BLE001
            logger.warning("Désenregistrement quota échoué : %s", rel_path, exc_info=True)
        count += 1
    return count


async def copy_workbook(
    user_id: int,
    src_dashboard_id: int,
    src_widget_id: int,
    dst_dashboard_id: int,
    dst_widget_id: int,
) -> Optional[str]:
    """Copie le classeur d'un widget vers un autre (clone de dashboard).

    Retourne le ``rel_path`` destination, ou ``None`` si la source n'existe
    pas / la copie échoue (le caller retire alors ``workbook_file`` du clone
    → fallback legacy propre, jamais de pointeur partagé entre widgets).
    """
    src_rel = workbook_rel_path(src_dashboard_id, src_widget_id)
    src = _resolve_target(user_id, src_rel)
    if src is None or not src.exists() or not src.is_file():
        return None
    dst_rel = workbook_rel_path(dst_dashboard_id, dst_widget_id)
    dst = _resolve_target(user_id, dst_rel)
    if dst is None:
        return None
    try:
        body = await asyncio.to_thread(src.read_bytes)
    except OSError as exc:
        logger.warning("Copie classeur widget : lecture source échouée (%s) : %s", src_rel, exc)
        return None

    can_upload, _quota_msg = await check_quota(user_id, len(body))
    if not can_upload:
        logger.warning("Copie classeur widget refusée (quota) : %s → %s", src_rel, dst_rel)
        return None

    await asyncio.to_thread(dst.parent.mkdir, parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".tmp")
    try:
        await asyncio.to_thread(tmp.write_bytes, body)
        await asyncio.to_thread(os.replace, str(tmp), str(dst))
    except Exception:  # noqa: BLE001
        try:
            if tmp.exists():
                await asyncio.to_thread(tmp.unlink)
        except OSError:
            pass
        logger.warning("Copie classeur widget échouée : %s → %s", src_rel, dst_rel, exc_info=True)
        return None
    await _register_upload(
        user_id, dst, dst_rel, file_size=len(body), file_hash=calculate_hash_from_bytes(body)
    )
    return dst_rel


def extract_sql_sheets(data: dict) -> list[dict]:
    """Feuilles SQL d'un classeur : onglets avec ``externalSource.type='sql_query'``.

    Contrat « le SQL gagne » : SEULES ces feuilles sont ré-exécutées au
    chargement (contrat explicite posé par la grille — feuille principale et
    onglets « Requête SQL »). Les feuilles snapshot (drill-down, feuilles
    manuelles, imports) gardent leurs données sauvegardées.

    Retourne ``[{"index": i, "label": str, "query": str}]`` dans l'ordre.
    """
    out: list[dict] = []
    tabs = data.get("tabs") or []
    for i, tab in enumerate(tabs):
        if not isinstance(tab, dict):
            continue
        src = tab.get("externalSource")
        if not isinstance(src, dict) or src.get("type") != "sql_query":
            continue
        query = src.get("query")
        if not isinstance(query, str) or not query.strip():
            continue
        out.append({"index": i, "label": str(tab.get("label") or ""), "query": query})
    return out
