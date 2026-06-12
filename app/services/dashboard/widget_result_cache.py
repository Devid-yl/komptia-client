"""Cache de RÉSULTATS pour les widgets de dashboard (≠ ``query_cache.py``).

``app/services/query_cache.py`` cache le SQL **généré** (question NL → chaîne
SQL) pour le pipeline Iris. Ce module-ci cache les **résultats** d'exécution des
widgets de dashboard (les lignes renvoyées par Sage), pour qu'un dashboard
ré-ouvert ne re-lance PAS la même requête lourde à chaque fois.

Incident fondateur (2026-06-08) : un widget « grid » portant une requête
analytique lourde (rentabilité par dossier, ~6 scans de Production) re-tournait
30-90 s à CHAQUE ``GET /api/dashboards/:id/data`` — aucun cache, exécution
séquentielle. Résultat ressenti : « ça prend du temps de ouf ».

Doctrine de conception (cf. CLAUDE.md, mémoire ``feedback_page_review_methodology``) :

- **Isolation cross-user (axe 18)** : la clé inclut TOUJOURS ``user_id``. Un
  résultat mis en cache pour un user n'est JAMAIS servi à un autre. Même si les
  dashboards sont owner-only en amont, on garde la défense en profondeur — un
  cache partagé entre users sur des données financières serait une fuite.
- **Pas de donnée fausse silencieuse (règle consequences #5)** : on ne cache
  QUE les résultats réussis (jamais une réponse ``{"error": ...}`` — sinon une
  erreur Sage transitoire resterait collée ``ttl`` secondes). Et chaque hit
  porte une métadonnée ``_cache`` (``cached_at`` / ``age_seconds``) pour que le
  frontend affiche « données d'il y a X s » — la péremption est VISIBLE, jamais
  silencieuse.
- **Croissance bornée (axe 21)** : LRU borné en nombre d'entrées ET cap de
  lignes par entrée (un grid de 500 000 lignes ne doit pas saturer la RAM). TTL
  d'éviction. Tout est configurable par env (source unique, documentée).
- **Invalidation par contenu** : la clé hashe la requête SQL + le type + les
  filtres + la période. Éditer le SQL d'un widget change la clé → cache miss →
  données fraîches, sans hook d'invalidation explicite. Le TTL court couvre la
  fraîcheur des données Sage elles-mêmes.

Le cache est **désactivable** : ``KOMPTIA_DASHBOARD_CACHE_TTL_SECONDS=0`` → tout
passe en direct (comportement d'avant ce module).
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    """Lit un int d'env avec fallback robuste (valeur corrompue → défaut).

    Tolère absence / non-numérique / négatif → ``default``. ``minimum`` borne
    le plancher (ex: ``max_rows_per_entry`` ne doit pas être négatif). On NE
    hardcode pas un magic number éparpillé : ces 3 réglages ont une source
    unique (l'env), défaut documenté ici.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning("%s='%s' non entier — fallback %d", name, raw, default)
        return default
    return val if val >= minimum else default


# ── Réglages (source unique = env, défauts conservateurs) ────────────────────
#: Durée de vie d'une entrée. 0 → cache DÉSACTIVÉ (tout en direct). Défaut 60 s :
#: une analyse financière ne change pas à la seconde, et un bouton « rafraîchir »
#: (``?refresh=1``) force le recalcul. Promouvable en réglage admin plus tard
#: (cohérent avec la doctrine « admin = source unique » de /admin/database).
_TTL_SECONDS = _env_int("KOMPTIA_DASHBOARD_CACHE_TTL_SECONDS", 60)
#: Nb max d'entrées (LRU). Borne le nombre de résultats gardés simultanément.
_MAX_ENTRIES = _env_int("KOMPTIA_DASHBOARD_CACHE_MAX_ENTRIES", 128, minimum=1)
#: Cap de lignes par entrée. Au-delà, on NE cache PAS (grid massif → on laisse
#: le virtual scrolling /iris gérer, on ne sature pas la RAM serveur). Borne le
#: pire-cas mémoire à ~ _MAX_ENTRIES × _MAX_ROWS_PER_ENTRY lignes.
_MAX_ROWS_PER_ENTRY = _env_int("KOMPTIA_DASHBOARD_CACHE_MAX_ROWS_PER_ENTRY", 5000, minimum=1)


def _result_weight(result: Dict[str, Any]) -> int:
    """Poids approximatif d'un résultat de widget, TOUTES formes confondues.

    Couvre 'rows' (grid/table), 'datasets' + leur 'data' (chart) et 'labels'
    (chart). Sert au cap de taille du cache : la borne ne doit JAMAIS dépendre
    d'un cap appliqué ailleurs (le 500 du fetch). Un KPI scalaire pèse ~0.
    """
    weight = 0
    rows = result.get("rows")
    if isinstance(rows, list):
        weight += len(rows)
    datasets = result.get("datasets")
    if isinstance(datasets, list):
        weight += len(datasets)
        for d in datasets:
            if isinstance(d, dict) and isinstance(d.get("data"), list):
                weight += len(d["data"])
    labels = result.get("labels")
    if isinstance(labels, list):
        weight += len(labels)
    # Onglets SQL additionnels d'un widget grille (clé 'tabs') et classeur
    # hydraté (mode classeur, clé 'workbook.tabs') : leurs rows portent le
    # vrai volume — sans ça, une entrée géante passerait sous le cap RAM.
    tabs = result.get("tabs")
    if isinstance(tabs, list):
        for t in tabs:
            if isinstance(t, dict) and isinstance(t.get("rows"), list):
                weight += len(t["rows"])
    workbook = result.get("workbook")
    if isinstance(workbook, dict) and isinstance(workbook.get("tabs"), list):
        for t in workbook["tabs"]:
            if isinstance(t, dict) and isinstance(t.get("rows"), list):
                weight += len(t["rows"])
    return weight


class WidgetResultCache:
    """Cache LRU+TTL des résultats de widgets, keyé par user.

    Thread-safe (``RLock``) par cohérence avec ``query_cache.QueryCache`` —
    Tornado est mono-thread async, mais l'exécution Sage passe par un
    ThreadPoolExecutor ; le verrou garantit qu'aucune lecture/écriture
    concurrente ne corrompt l'``OrderedDict`` si l'usage évolue.
    """

    def __init__(
        self,
        ttl_seconds: int = _TTL_SECONDS,
        max_entries: int = _MAX_ENTRIES,
        max_rows_per_entry: int = _MAX_ROWS_PER_ENTRY,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.max_rows_per_entry = max_rows_per_entry
        # value = (résultat_dict, expire_at_monotonic, cached_at_wall)
        self._cache: "OrderedDict[str, Tuple[Dict[str, Any], float, float]]" = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    @property
    def enabled(self) -> bool:
        """``False`` si TTL ≤ 0 → tout passe en direct (cache no-op)."""
        return self.ttl_seconds > 0

    @staticmethod
    def make_key(
        user_id: Any,
        dashboard_id: Any,
        widget_id: Any,
        *,
        query: str,
        widget_type: str,
        chart_type: Optional[str],
        period: Any,
        filter_state: Optional[dict],
        drill_filters: Optional[dict],
        version: Any = None,
    ) -> str:
        """Clé de cache déterministe et ISOLÉE par user.

        ``user_id`` est le 1er composant (isolation cross-user, axe 18). La
        requête SQL est hashée telle quelle : éditer le SQL d'un widget change
        la clé → invalidation implicite. ``version`` (ex: ``widget.updated_at``)
        ajoute une ceinture/bretelles pour les changements de config hors-SQL.

        ``json.dumps(..., sort_keys=True, default=str)`` rend les filtres/drill
        ordre-indépendants et sérialise les types exotiques (dates) sans crash.
        """
        try:
            filters_repr = json.dumps(filter_state or {}, sort_keys=True, default=str)
            drill_repr = json.dumps(drill_filters or {}, sort_keys=True, default=str)
        except (TypeError, ValueError):
            # Filtre non sérialisable (ne devrait pas arriver) → préfixe
            # ``repr:`` : un repr ne peut JAMAIS égaler une chaîne json.dumps
            # (happy path), donc pas de collision inter-encodage silencieuse.
            filters_repr = "repr:" + repr(filter_state)
            drill_repr = "repr:" + repr(drill_filters)
        # JSON (encodage injectif) plutot que join : delimite chaque
        # composant (guillemets/virgules/echappement) -> pas de collision
        # de cle entre users meme a IDs accoles (anti fuite cross-user).
        payload = json.dumps(
            [
                str(user_id),
                str(dashboard_id),
                str(widget_id),
                str(version),
                widget_type or "",
                chart_type or "",
                str(period),
                query or "",
                filters_repr,
                drill_repr,
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retourne une COPIE du résultat caché (avec méta ``_cache``) ou None.

        On renvoie une COPIE PROFONDE (``deepcopy``) + on ré-injecte ``_cache`` à
        chaque hit pour que l'``age_seconds`` soit calculé au moment du hit (pas
        figé à la mise en cache). La copie profonde est volontaire : ``rows`` est
        une liste de listes ; une copie superficielle la PARTAGERAIT avec
        l'entrée cachée → une mutation en aval corromprait silencieusement le
        cache (règle consequences #5). Coût négligeable (quelques ms sur ≤5000
        lignes) face aux 30-90 s d'une requête Sage.
        """
        if not self.enabled:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            result, expire_at, cached_at_wall = entry
            if now >= expire_at:
                # Expiré → éviction immédiate
                del self._cache[key]
                self._misses += 1
                return None
            self._cache.move_to_end(key)  # LRU
            self._hits += 1
            age = max(0, int(time.time() - cached_at_wall))
            out = copy.deepcopy(result)
            out["_cache"] = {"cached_at": cached_at_wall, "age_seconds": age}
            return out

    def set(self, key: str, result: Dict[str, Any]) -> bool:
        """Met en cache un résultat RÉUSSI. Retourne ``True`` si caché.

        Refuse (retourne ``False`` sans cacher) si :
        - cache désactivé (TTL ≤ 0),
        - ``result`` porte une clé ``error`` (ne jamais cacher un échec),
        - le résultat dépasse ``max_rows_per_entry`` (anti-saturation RAM).
        """
        if not self.enabled or not isinstance(result, dict):
            return False
        if "error" in result:
            return False
        # Cap de POIDS (anti-saturation RAM) couvrant TOUTES les formes
        # porteuses de volume — pas seulement 'rows'. Sinon un chart
        # 'datasets'/'labels' massif passerait sous le radar : la borne du
        # cache ne doit pas dépendre d'un cap externe (le 500 du fetch).
        weight = _result_weight(result)
        if weight > self.max_rows_per_entry:
            logger.debug(
                "Widget result trop volumineux pour le cache (poids %d > %d) — non caché",
                weight,
                self.max_rows_per_entry,
            )
            return False
        now = time.monotonic()
        cached_at_wall = time.time()
        with self._lock:
            # Évince le plus ancien si plein (et clé nouvelle)
            if len(self._cache) >= self.max_entries and key not in self._cache:
                self._cache.popitem(last=False)
            # Copie PROFONDE (symétrique du deepcopy en lecture) : ``dict()``
            # partagerait les listes imbriquées (rows/datasets) avec l'objet du
            # caller → une mutation en aval corromprait l'entrée pour tout le
            # TTL (donnée fausse silencieuse). La copie profonde isole le cache.
            self._cache[key] = (copy.deepcopy(result), now + self.ttl_seconds, cached_at_wall)
            self._cache.move_to_end(key)
        return True

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._cache),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "max_rows_per_entry": self.max_rows_per_entry,
                "hit_rate": (self._hits / total) if total else 0.0,
                "enabled": self.enabled,
            }


# ── Singleton process-wide ───────────────────────────────────────────────────
_global_result_cache: Optional[WidgetResultCache] = None
_singleton_lock = threading.Lock()


def get_widget_result_cache() -> WidgetResultCache:
    """Instance globale (lazy, thread-safe)."""
    global _global_result_cache
    if _global_result_cache is None:
        with _singleton_lock:
            if _global_result_cache is None:
                _global_result_cache = WidgetResultCache()
                logger.info(
                    "WidgetResultCache initialisé (ttl=%ds, max_entries=%d, "
                    "max_rows/entrée=%d, enabled=%s)",
                    _global_result_cache.ttl_seconds,
                    _global_result_cache.max_entries,
                    _global_result_cache.max_rows_per_entry,
                    _global_result_cache.enabled,
                )
    return _global_result_cache
