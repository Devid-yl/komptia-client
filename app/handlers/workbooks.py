"""Handlers HTTP pour les classeurs Komptia (.afz.json) et l'import de feuilles externes.

Six endpoints JSON :

* ``GET  /api/workbooks``                      — liste des classeurs du user
* ``GET  /api/workbooks/tabs``                 — métadonnées des onglets
* ``GET  /api/workbooks/tab-data``             — données complètes d'un onglet
* ``POST /api/external-sheets/excel/sheets``   — liste des onglets d'un .xlsx
* ``POST /api/external-sheets/excel/load``     — charge un onglet Excel
* ``POST /api/external-sheets/csv/load``       — charge un fichier CSV

Garanties senior (OWASP API Security Top 10 2023 + ASVS v5 + CWE + CLAUDE.md)
-----------------------------------------------------------------------------

1. **Fail-closed authz (API1/API5:2023)** — tous les handlers héritent de
   :class:`AuthenticatedHandler` (rejet ``401`` en ``prepare`` pour anonyme).
   Aucun ``if not user: ...`` inline — cf. ``findings/GLOBAL_FINDINGS.md``
   ``[DUP] Authentification manuelle dupliquée``. Le décorateur
   ``@authenticated`` est conservé en défense en profondeur sur chaque
   méthode (si jamais un sous-classement casse ``AuthenticatedHandler``).

2. **Rate-limiting (API4:2023 Unrestricted Resource Consumption)** — chaque
   endpoint est protégé par :class:`RateLimiter`. Trois paliers distincts :

   * ``_RATE_MAX_LIST`` (60/min) — listage peu coûteux (scan de répertoire).
   * ``_RATE_MAX_READ`` (60/min) — lecture d'un .afz.json (I/O bornée).
   * ``_RATE_MAX_LOAD`` (20/min) — parsing Excel/CSV (CPU + RAM en threadpool).

   Le rate-limit est porté par la classe de base :class:`_WorkbooksAPIBase`
   — pas de ``self.check()`` dupliqué dans 6 endroits.

3. **Anti-DoS parsing (API4:2023)** —

   * ``_MAX_EXCEL_FILE_SIZE`` / ``_MAX_CSV_FILE_SIZE`` (30 MiB) bornent le
     budget RAM côté threadpool. Un .xlsx plus gros est rejeté en ``413``
     AVANT même d'ouvrir le classeur (``stat`` seul, pas de ``load``).
   * ``_BODY_MAX_BYTES`` (64 KiB) borne le JSON d'entrée — les 3 POST
     n'ont que quelques champs string courts, 64 KiB couvre large. Un
     body plus gros est rejeté en ``413`` avant ``json.loads``.
   * ``_MAX_IMPORT_ROWS`` (1 milliard = "pas de cap caller") borne le
     tableau retourné au front. La vraie borne RAM est en fait
     ``_MAX_EXCEL_FILE_SIZE`` / ``_MAX_CSV_FILE_SIZE`` (taille du FICHIER
     source) — un xlsx de 30 MiB ne peut techniquement pas contenir plus
     de ~1M lignes (limite spec OOXML), un csv de 30 MiB ~500k. Le cap
     row-count est donc cosmétique au-dessus du cap fichier.
   * ``_MAX_PATH_LEN`` (260) borne la longueur du ``rel_path`` — au-dessus
     c'est suspect (NTFS limite historique + couvre 99.99% des usages).

4. **Path traversal (CWE-22) — triple défense** —

   a) ``_safe_path`` (délégué à ``app.handlers.datastore``) rejette ``..``,
      NUL-bytes, et vérifie ``Path.is_relative_to(user_dir_resolved)`` ;
   b) longueur ``rel_path`` bornée à 260 caractères (CWE-73 précurseur) ;
   c) rejet des caractères de contrôle (CRLF = CWE-93) dans ``rel_path``,
      ``sheet_name``, ``encoding``, ``separator`` avant tout usage.

5. **XML security (CWE-776 Recursive Entity References)** — openpyxl
   parse du XML pour les .xlsx. Par défaut (sans ``defusedxml``) il est
   vulnérable aux billion-laughs / quadratic blowup / XXE (cf. openpyxl
   docs). ``requirements.txt`` inclut ``defusedxml>=0.7.1`` ; openpyxl
   >= 3.1 active automatiquement les parseurs sûrs quand le paquet est
   importable (``openpyxl.DEFUSEDXML is True``). Si l'install manque, un
   ``logger.warning`` est émis au module-load (signal ops, pas blocage —
   le cap ``_MAX_EXCEL_FILE_SIZE`` reste la défense primaire).

6. **Erreurs déterministes (CWE-209)** — aucun ``str(exception)`` au client.
   Tous les messages utilisateur sont des ``Final[str]`` centralisés dans
   :class:`_Messages`. Les détails partent dans les logs structurés via
   ``logger.exception`` / ``logger.warning`` avec ``extra={"request_id"}``
   pour corrélation ops. Les ``tornado.web.HTTPError`` déjà remontées par
   les services (``_safe_path``, loaders Excel/CSV) transitent telles
   quelles — elles portent leur propre message client sanitisé.

7. **Validation stricte (API3:2023)** — ``_parse_bounded_int`` clampe
   ``max_rows`` dans ``]0, _MAX_IMPORT_ROWS]`` (valeur invalide → défaut,
   jamais d'erreur silencieuse) ; ``_parse_bounded_str`` strip + cap + null
   si vide. Les extensions (``.xlsx`` / ``.xls`` / ``.csv``) sont vérifiées
   côté handler AVANT ``asyncio.to_thread`` pour que l'erreur arrive
   instantanément (pas d'ouverture de filehandle pour rien).

8. **Imports top-level** — plus aucun ``from app.handlers.datastore import
   _user_dir, _safe_path`` en corps de fonction. Pas de cycle (datastore
   ne dépend pas de workbooks), donc les imports sont en tête de module
   — cohérent avec ``findings/GLOBAL_FINDINGS.md`` ``[DUP] Imports lazy``.

9. **Réponse JSON UTF-8** — :meth:`BaseHandler.write_json` utilise
   ``ensure_ascii=False``, préserve les caractères accentués des labels
   FR (``Feuille``, ``Colonne``) sans les échapper.

Consommateurs principaux : composant ``ExternalSheetsPicker`` (pages iris,
datastore, reports) — ajout de feuilles au result area ou à la génération
de rapports.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Final

import tornado.web

from app.handlers.base import AuthenticatedHandler, authenticated
from app.handlers.datastore import _safe_path, _user_dir
from app.services.classeur.reader import (
    list_classeurs_sync,
    read_classeur,
    read_tab_data,
)
from app.services.external_sheets import (
    list_excel_sheets,
    load_csv_file,
    load_excel_sheet,
)
from app.services.reporting.llm_limits import estimate_tokens
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Constantes (toutes ``Final`` + justification — pas de magic number)
# ════════════════════════════════════════════════════════════════════════

#: Nombre max de classeurs retournés par ``GET /api/workbooks``. 200 couvre
#: un usage intensif (un user actif a rarement > 50 classeurs) et borne la
#: payload JSON à ~30 KiB même avec des labels longs. Au-delà, pagination
#: à envisager — voir ``findings/EPICS.md`` si le besoin apparaît.
_MAX_WORKBOOK_LISTING: Final[int] = 200

#: Plafond des lignes retournées par ``tab-data``/``excel/load``/``csv/load``.
#: Convention Komptia : pas de hard cap technique côté row count — la valeur
#: 1 milliard = sentinelle "pas de limite caller".
#:
#: **Important : la VRAIE protection RAM** vient de ``_MAX_EXCEL_FILE_SIZE``
#: (30 MiB) et ``_MAX_CSV_FILE_SIZE`` (30 MiB) — le fichier source ne peut
#: pas dépasser, donc le nombre de lignes possible est borné indirectement :
#:   * xlsx 30 MiB → max ~1M lignes (limite spec OOXML 1 048 576 de toute
#:     façon) ; pic RAM openpyxl ``read_only=False`` ~ 2-8 GiB pour gros style.
#:   * csv 30 MiB → max ~500k lignes ; pic RAM ~4× taille fichier en str Py.
#:
#: **NOTE frontend** : ``static/js/components/external_sheets_picker.js`` ne
#: passe PAS de ``max_rows`` dans les body POST → tous les imports prod
#: utilisent ce default. Avant le refacto (50_000), les imports xlsx/csv
#: étaient silencieusement tronqués. Désormais : 0 troncation, l'iris-grid
#: reçoit tout. Pour un fichier 30 MiB le rendu peut être lourd — virtual
#: scrolling à prévoir (cf. todo T7 du panorama caps).
_MAX_IMPORT_ROWS: Final[int] = 1_000_000_000

#: Taille max d'un .xlsx/.xls acceptée. openpyxl charge le classeur en RAM
#: (``read_only=False`` pour exposer ``merged_cells.ranges``), donc ce cap
#: borne directement le pic mémoire côté threadpool. 30 MiB couvre des
#: feuilles avec ~500 000 cellules — au-delà le user doit filtrer/splitter.
_MAX_EXCEL_FILE_SIZE: Final[int] = 30 * 1024 * 1024

#: Taille max d'un .csv. Le loader décode le fichier entier avant parse
#: (``raw.decode(...)``) pour détecter l'encodage — ce cap borne la RAM
#: avant détection. Même ordre de grandeur que l'Excel pour cohérence UX.
_MAX_CSV_FILE_SIZE: Final[int] = 30 * 1024 * 1024

#: Taille max du body JSON des POST. Les 3 POST n'ont que quelques champs
#: courts (``path``, ``sheet_name``, ``encoding``, ``separator``, …) —
#: 64 KiB est déjà généreux. Au-delà = attaque event-loop-block ou bug.
_BODY_MAX_BYTES: Final[int] = 64 * 1024

#: Longueur max d'un ``rel_path``. 260 correspond à la limite historique
#: NTFS (MAX_PATH) — un path plus long est soit un bug soit un fuzzer.
_MAX_PATH_LEN: Final[int] = 260

#: Longueur max du ``sheet_name`` Excel (spec officielle : 31 caractères).
#: 255 couvre les variantes observées (lib tierce, fichier corrompu) sans
#: devenir un vecteur d'injection log.
_MAX_SHEET_NAME_LEN: Final[int] = 255

#: Longueur max d'un nom d'encodage (``utf-8-sig`` = 9 chars, marge
#: généreuse à 32 pour couvrir ``iso-8859-15`` et variantes).
_MAX_ENCODING_LEN: Final[int] = 32

#: Longueur max du séparateur CSV (``|``, ``\t``, ``;;`` custom) — 4
#: accepte les séparateurs multi-chars non standards sans permettre un
#: payload de contrôle camouflé en "séparateur".
_MAX_SEPARATOR_LEN: Final[int] = 4

#: Rate-limit listage (60/min/user). Scan de répertoire, très peu coûteux.
#: Couvre un polling UI agressif (1/s) tout en bloquant un script boucle.
_RATE_MAX_LIST: Final[int] = 60

#: Rate-limit lecture classeur (60/min/user). ``read_classeur`` lit un
#: fichier JSON (~MiB), bornée par ``MAX_CLASSEUR_SIZE``. Similaire à list.
_RATE_MAX_READ: Final[int] = 60

#: Rate-limit chargement Excel/CSV (20/min/user). Parse CPU + RAM en
#: threadpool — plus lent que la lecture JSON, mais reste faisable 1×/3s
#: pour un usage humain. Au-delà, script ou attaque.
_RATE_MAX_LOAD: Final[int] = 20

#: Fenêtre (secondes) du sliding-window — unifiée à 60 secondes pour les
#: trois paliers. Cohérent avec templates/saved_queries/webhooks.
_RATE_WINDOW: Final[int] = 60

#: Clé de rate-limit pour un user non-identifié — ne devrait jamais être
#: atteinte (:class:`AuthenticatedHandler` rejette anonyme). Défense en
#: profondeur si un futur refactor débranche le guard.
_ANON_RATE_KEY: Final[str] = "workbooks:_anon_"


# ════════════════════════════════════════════════════════════════════════
# defusedxml — signal ops (voir module docstring §5)
# ════════════════════════════════════════════════════════════════════════

try:
    import defusedxml  # noqa: F401 — importable ⇒ openpyxl active parseurs sûrs

    _DEFUSEDXML_AVAILABLE: Final[bool] = True
except ImportError:  # pragma: no cover — env CI peut ne pas l'avoir installé
    _DEFUSEDXML_AVAILABLE = False
    logger.warning(
        "defusedxml absent — openpyxl utilise le parser XML stdlib, "
        "vulnerable aux XXE/billion-laughs. Install: pip install defusedxml"
    )


# ════════════════════════════════════════════════════════════════════════
# Singleton rate-limiter (thread-safe via lock interne)
# ════════════════════════════════════════════════════════════════════════

_rate_limiter: Final[RateLimiter] = RateLimiter()


# ════════════════════════════════════════════════════════════════════════
# Messages utilisateur centralisés (FR, ton cohérent avec le reste du projet)
# ════════════════════════════════════════════════════════════════════════


class _Messages:
    """Messages d'erreur client. ``Final[str]`` pour stabilité/testabilité.

    Centraliser ici (pattern aligné sur ``templates.py``, ``webhooks.py``,
    ``saved_queries.py``, ``result_assistant.py``, ``settings.py``,
    ``base.py``) : (1) facilite l'audit sécurité — aucun message n'est
    construit par concaténation avec un input utilisateur (élimine CWE-209
    + CWE-117) ; (2) prépare l'i18n future ; (3) permet aux tests
    d'importer les constantes plutôt que dupliquer des littéraux fragiles.
    """

    PATH_REQUIRED: Final[str] = "Le chemin du fichier est requis."
    PATH_INVALID: Final[str] = "Chemin invalide."
    FILENAME_REQUIRED: Final[str] = "Le nom du classeur est requis."
    FILE_NOT_FOUND: Final[str] = "Fichier introuvable."
    FILE_TOO_LARGE: Final[str] = "Fichier trop volumineux."
    BODY_TOO_LARGE: Final[str] = "Requête trop volumineuse."
    TAB_INDEX_INVALID: Final[str] = "Index d'onglet invalide."
    EXCEL_FORMAT_UNSUPPORTED: Final[str] = "Format non supporté (attendu .xlsx ou .xls)."
    CSV_FORMAT_UNSUPPORTED: Final[str] = "Format non supporté (attendu .csv)."
    EXCEL_UNREADABLE: Final[str] = "Fichier Excel illisible ou corrompu."
    CSV_UNREADABLE: Final[str] = "Fichier CSV illisible ou corrompu."
    RATE_LIMITED: Final[str] = "Trop de requêtes — patientez quelques secondes."


# ════════════════════════════════════════════════════════════════════════
# Helpers purs (pas de ``self``, testables hors handler)
# ════════════════════════════════════════════════════════════════════════


def _contains_control_chars(value: str) -> bool:
    """``True`` si ``value`` contient CR, LF, NUL ou tout caractère < 0x20.

    Prévient CWE-93 (CRLF injection dans un header log/filesystem) et
    CWE-158 (null byte truncation). Utilisé avant de propager un input
    utilisateur vers ``logger`` / ``Path`` / nom de feuille Excel.
    """
    return any(ord(c) < 0x20 or c == "\x7f" for c in value)


def _parse_required_path(body: dict[str, Any]) -> str:
    """Extrait ``body["path"]``, normalise et valide.

    * ``None``/vide → ``HTTPError(400, PATH_REQUIRED)``.
    * Type non-string → ``HTTPError(400, PATH_INVALID)``.
    * CRLF/NUL/contrôle → ``HTTPError(400, PATH_INVALID)``.
    * Longueur > ``_MAX_PATH_LEN`` → tronqué (``_safe_path`` invalidera
      ensuite si incohérent).
    """
    raw = body.get("path")
    if raw is None:
        raise tornado.web.HTTPError(400, _Messages.PATH_REQUIRED)
    if not isinstance(raw, str):
        raise tornado.web.HTTPError(400, _Messages.PATH_INVALID)
    cleaned = raw.strip()
    if not cleaned:
        raise tornado.web.HTTPError(400, _Messages.PATH_REQUIRED)
    if _contains_control_chars(cleaned):
        raise tornado.web.HTTPError(400, _Messages.PATH_INVALID)
    return cleaned[:_MAX_PATH_LEN]


def _parse_bounded_int(
    raw: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Convertit ``raw`` en ``int`` clampé dans ``[minimum, maximum]``.

    * ``None``/type incompatible → ``default``.
    * En dehors de ``[minimum, maximum]`` → ``default`` (pas d'erreur
      utilisateur — ces bornes sont opérationnelles, pas fonctionnelles).

    Choix senior : ``max_rows`` n'est pas un paramètre métier — c'est un
    garde-fou serveur. Un user qui envoie ``99999999`` ne doit pas voir
    une 400, on clamp et on lui envoie ``_MAX_IMPORT_ROWS`` lignes. Le
    comportement est documenté côté API (``estimated_tokens`` reflète
    la vraie taille retournée).
    """
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    if value < minimum or value > maximum:
        return default
    return value


def _parse_bounded_str(raw: Any, *, max_len: int) -> str | None:
    """Convertit ``raw`` en ``str`` tronquée à ``max_len`` ou ``None``.

    * ``None`` / "" → ``None`` (absent, pas une valeur vide).
    * Type non-string → ``str(raw)[:max_len]`` (best-effort, les loaders
      traiteront la valeur comme opaque).
    * Contrôle/CRLF → ``None`` (defense-in-depth : une sheet_name
      contenant ``\\r\\n`` pourrait corrompre un header d'export).
    """
    if raw is None:
        return None
    text = raw if isinstance(raw, str) else str(raw)
    text = text.strip()
    if not text:
        return None
    if _contains_control_chars(text):
        return None
    return text[:max_len]


def _resolve_user_path(
    user_id: int,
    rel_path: str,
    max_size: int | None = None,
) -> Path:
    """Résout ``rel_path`` dans le datastore du user (anti path-traversal).

    Raises:
        ``HTTPError(400)`` si ``rel_path`` vide ou hors du dossier user.
        ``HTTPError(404)`` si le fichier n'existe pas / n'est pas régulier.
        ``HTTPError(413)`` si ``max_size`` est fourni et ``file.size >
        max_size``.

    Pas de ``str(exc)`` remonté au client — les HTTPError portent un
    message client sain (FR, sans détail filesystem).
    """
    if not rel_path:
        raise tornado.web.HTTPError(400, _Messages.PATH_REQUIRED)

    user_dir = _user_dir(user_id)
    target = _safe_path(user_dir, rel_path)
    if target is None:
        raise tornado.web.HTTPError(400, _Messages.PATH_INVALID)
    if not target.exists() or not target.is_file():
        raise tornado.web.HTTPError(404, _Messages.FILE_NOT_FOUND)

    if max_size is not None:
        try:
            size = target.stat().st_size
        except OSError as exc:
            # Permission changée pile au moment du stat, fs remounted, etc.
            # Remonte en 404 (le fichier n'est plus "accessible") plutôt
            # qu'un 5xx opaque — c'est bien plus informatif côté UI.
            raise tornado.web.HTTPError(404, _Messages.FILE_NOT_FOUND) from exc
        if size > max_size:
            raise tornado.web.HTTPError(413, _Messages.FILE_TOO_LARGE)

    return target


def _build_tab_metadata(idx: int, tab: dict[str, Any]) -> dict[str, Any]:
    """Construit le dict de métadonnées pour UN onglet d'un classeur.

    Factorisé depuis :meth:`WorkbookTabsHandler.get` pour rester testable
    sans HTTP context. Défensif : tolère un ``cellDetails`` qui ne serait
    pas un dict (classeur corrompu), retourne des métadonnées minimales
    plutôt que de crasher.
    """
    cell_details = tab.get("cellDetails") or {}
    if not isinstance(cell_details, dict):
        cell_details = {}

    has_rows = bool(tab.get("rows"))
    has_cells = bool(cell_details)
    is_unusable = not has_rows and not has_cells

    tab_tokens = 0
    if has_rows:
        columns = tab.get("columns") or []
        rows = tab.get("rows") or []
        tab_tokens = estimate_tokens({"columns": columns, "rows": rows})

    cells_meta: list[dict[str, Any]] = []
    for cell_key, cell in cell_details.items():
        if not isinstance(cell, dict):
            continue
        cell_tokens = estimate_tokens(
            {
                "columns": cell.get("columns") or [],
                "rows": cell.get("rows") or [],
            }
        )
        cells_meta.append(
            {
                "key": cell_key,
                "row_count": cell.get("row_count", len(cell.get("rows", []))),
                "estimated_tokens": cell_tokens,
            }
        )

    return {
        "index": idx,
        "label": tab.get("label", f"Feuille {idx + 1}"),
        "has_sql": bool(tab.get("sql")),
        "row_count": tab.get("totalRowCount", len(tab.get("rows", []))),
        "columns": tab.get("columns", []),
        "is_blank": tab.get("isBlankSheet", False),
        "is_unusable": is_unusable,
        "estimated_tokens": tab_tokens,
        "cells": cells_meta,
        "cell_drill_count": len(cells_meta),
        "cell_drill_keys": [c["key"] for c in cells_meta],
    }


# ════════════════════════════════════════════════════════════════════════
# Handlers — base commune + 6 endpoints
# ════════════════════════════════════════════════════════════════════════


class _WorkbooksAPIBase(AuthenticatedHandler):
    """Base commune : rate-limit + pré-checks body pour les POST.

    Rejet anonyme hérité de :class:`AuthenticatedHandler` (``401`` JSON en
    ``prepare``). Les sous-classes conservent ``@authenticated`` sur leurs
    méthodes en défense en profondeur (pattern ``templates.py``).
    """

    def _check_rate(self, max_requests: int) -> None:
        """Applique le sliding-window rate-limit scopé par user_id.

        Clé : ``"workbooks:<user_id>"`` ou ``_ANON_RATE_KEY`` (guard
        n'aurait jamais dû être atteint). Message FR en cas de 429 via
        :class:`_Messages`.
        """
        user = self.current_user
        user_id = getattr(user, "id", None) if user is not None else None
        key = f"workbooks:{user_id}" if user_id is not None else _ANON_RATE_KEY
        if not _rate_limiter.check(
            key,
            max_requests=max_requests,
            window_seconds=_RATE_WINDOW,
        ):
            raise tornado.web.HTTPError(429, _Messages.RATE_LIMITED)

    def _reject_oversize_body(self) -> None:
        """Refuse un body POST > ``_BODY_MAX_BYTES`` avant ``get_json_body``.

        Premier filet : Content-Length (facile à spoofer mais bloque le
        cas honnête du bug UI). Deuxième filet : ``len(request.body)``
        après Tornado a lu le body — borne réelle avant ``json.loads``.
        """
        raw_length = self.request.headers.get("Content-Length")
        if raw_length is not None:
            try:
                declared = int(raw_length)
            except (TypeError, ValueError):
                declared = 0
            if declared > _BODY_MAX_BYTES:
                raise tornado.web.HTTPError(413, _Messages.BODY_TOO_LARGE)
        if len(self.request.body) > _BODY_MAX_BYTES:
            raise tornado.web.HTTPError(413, _Messages.BODY_TOO_LARGE)


class ListWorkbooksHandler(_WorkbooksAPIBase):
    """``GET /api/workbooks`` — Liste des classeurs ``.afz.json`` du user."""

    @authenticated
    async def get(self) -> None:
        self._check_rate(_RATE_MAX_LIST)
        user = self.current_user
        user_dir = _user_dir(user.id)

        classeurs = await asyncio.to_thread(list_classeurs_sync, user_dir)
        classeurs.sort(key=lambda c: c["modified"], reverse=True)
        classeurs = classeurs[:_MAX_WORKBOOK_LISTING]
        self.write_json({"success": True, "classeurs": classeurs})


class WorkbookTabsHandler(_WorkbooksAPIBase):
    """``GET /api/workbooks/tabs?filename=...`` — Métadonnées des onglets."""

    @authenticated
    async def get(self) -> None:
        self._check_rate(_RATE_MAX_READ)
        user = self.current_user
        filename = self.get_argument("filename", "").strip()
        if not filename:
            raise tornado.web.HTTPError(400, _Messages.FILENAME_REQUIRED)
        if _contains_control_chars(filename):
            raise tornado.web.HTTPError(400, _Messages.PATH_INVALID)
        filename = filename[:_MAX_PATH_LEN]

        data = await read_classeur(user.id, filename)

        tabs_meta = [_build_tab_metadata(idx, tab) for idx, tab in enumerate(data.get("tabs", []))]
        self.write_json({"success": True, "filename": filename, "tabs": tabs_meta})


class WorkbookTabDataHandler(_WorkbooksAPIBase):
    """``GET /api/workbooks/tab-data?filename=...&tab_index=N`` — Données onglet."""

    @authenticated
    async def get(self) -> None:
        self._check_rate(_RATE_MAX_READ)
        user = self.current_user

        filename = self.get_argument("filename", "").strip()
        if not filename:
            raise tornado.web.HTTPError(400, _Messages.FILENAME_REQUIRED)
        if _contains_control_chars(filename):
            raise tornado.web.HTTPError(400, _Messages.PATH_INVALID)
        filename = filename[:_MAX_PATH_LEN]

        try:
            tab_index = int(self.get_argument("tab_index"))
        except (ValueError, tornado.web.MissingArgumentError) as exc:
            raise tornado.web.HTTPError(400, _Messages.TAB_INDEX_INVALID) from exc

        max_rows = _parse_bounded_int(
            self.get_argument("max_rows", None),
            default=_MAX_IMPORT_ROWS,
            minimum=1,
            maximum=_MAX_IMPORT_ROWS,
        )

        data = await read_tab_data(user.id, filename, tab_index, max_rows=max_rows)
        self.write_json({"success": True, **data})


class ListExcelSheetsHandler(_WorkbooksAPIBase):
    """``POST /api/external-sheets/excel/sheets`` — Liste les onglets d'un .xlsx."""

    @authenticated
    async def post(self) -> None:
        self._check_rate(_RATE_MAX_LOAD)
        self._reject_oversize_body()

        user = self.current_user
        body = self.get_json_body() or {}
        path_rel = _parse_required_path(body)
        target = _resolve_user_path(user.id, path_rel, max_size=_MAX_EXCEL_FILE_SIZE)

        if target.suffix.lower() not in (".xlsx", ".xls"):
            raise tornado.web.HTTPError(400, _Messages.EXCEL_FORMAT_UNSUPPORTED)

        try:
            sheets = await asyncio.to_thread(list_excel_sheets, target)
        except tornado.web.HTTPError:
            raise
        except (OSError, ValueError, KeyError) as exc:
            logger.warning(
                "Liste onglets Excel %r impossible : %s",
                path_rel,
                exc.__class__.__name__,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.EXCEL_UNREADABLE) from exc
        except Exception as exc:  # noqa: BLE001 — parseur tiers opaque
            logger.exception(
                "Liste onglets Excel %r : exception inattendue",
                path_rel,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.EXCEL_UNREADABLE) from exc

        self.write_json({"success": True, "sheets": sheets})


class LoadExcelSheetHandler(_WorkbooksAPIBase):
    """``POST /api/external-sheets/excel/load`` — Charge un onglet Excel."""

    @authenticated
    async def post(self) -> None:
        self._check_rate(_RATE_MAX_LOAD)
        self._reject_oversize_body()

        user = self.current_user
        body = self.get_json_body() or {}

        path_rel = _parse_required_path(body)
        sheet_name = _parse_bounded_str(body.get("sheet_name"), max_len=_MAX_SHEET_NAME_LEN)
        max_rows = _parse_bounded_int(
            body.get("max_rows"),
            default=_MAX_IMPORT_ROWS,
            minimum=1,
            maximum=_MAX_IMPORT_ROWS,
        )
        first_row_as_header = bool(body.get("first_row_as_header", False))

        target = _resolve_user_path(user.id, path_rel, max_size=_MAX_EXCEL_FILE_SIZE)
        if target.suffix.lower() not in (".xlsx", ".xls"):
            raise tornado.web.HTTPError(400, _Messages.EXCEL_FORMAT_UNSUPPORTED)

        try:
            result = await asyncio.to_thread(
                load_excel_sheet,
                target,
                sheet_name,
                max_rows,
                first_row_as_header,
            )
        except tornado.web.HTTPError:
            raise
        except (OSError, ValueError, KeyError) as exc:
            logger.warning(
                "Chargement Excel %r (sheet=%r) impossible : %s",
                path_rel,
                sheet_name,
                exc.__class__.__name__,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.EXCEL_UNREADABLE) from exc
        except Exception as exc:  # noqa: BLE001 — parseur tiers opaque
            logger.exception(
                "Chargement Excel %r : exception inattendue",
                path_rel,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.EXCEL_UNREADABLE) from exc

        tokens = estimate_tokens({"columns": result["columns"], "rows": result["rows"]})
        self.write_json({"success": True, "estimated_tokens": tokens, **result})


class LoadCsvFileHandler(_WorkbooksAPIBase):
    """``POST /api/external-sheets/csv/load`` — Charge un fichier CSV."""

    @authenticated
    async def post(self) -> None:
        self._check_rate(_RATE_MAX_LOAD)
        self._reject_oversize_body()

        user = self.current_user
        body = self.get_json_body() or {}

        path_rel = _parse_required_path(body)
        encoding = _parse_bounded_str(body.get("encoding"), max_len=_MAX_ENCODING_LEN)
        separator = _parse_bounded_str(body.get("separator"), max_len=_MAX_SEPARATOR_LEN)
        max_rows = _parse_bounded_int(
            body.get("max_rows"),
            default=_MAX_IMPORT_ROWS,
            minimum=1,
            maximum=_MAX_IMPORT_ROWS,
        )

        target = _resolve_user_path(user.id, path_rel, max_size=_MAX_CSV_FILE_SIZE)
        if target.suffix.lower() != ".csv":
            raise tornado.web.HTTPError(400, _Messages.CSV_FORMAT_UNSUPPORTED)

        try:
            result = await asyncio.to_thread(load_csv_file, target, encoding, separator, max_rows)
        except tornado.web.HTTPError:
            raise
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            logger.warning(
                "Chargement CSV %r impossible : %s",
                path_rel,
                exc.__class__.__name__,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.CSV_UNREADABLE) from exc
        except Exception as exc:  # noqa: BLE001 — parseur stdlib opaque
            logger.exception(
                "Chargement CSV %r : exception inattendue",
                path_rel,
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "user_id": user.id,
                },
            )
            raise tornado.web.HTTPError(400, _Messages.CSV_UNREADABLE) from exc

        tokens = estimate_tokens({"columns": result["columns"], "rows": result["rows"]})
        self.write_json({"success": True, "estimated_tokens": tokens, **result})
