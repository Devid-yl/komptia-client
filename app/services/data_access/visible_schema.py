"""Source unique de vérité du schéma BDD visible par un utilisateur donné.

**Promesse architecturale** : tout call-site (SQL ou LLM) qui a besoin de
savoir "ce que cet user peut voir dans la BDD" passe par :func:`build_user_schema_view`
et consomme la :class:`UserSchemaView` retournée. Aucun autre chemin
n'accède au schéma filtré. C'est ce qui garantit que le mode invisible
ne peut pas être contourné par oubli — il n'y a pas d'autre fonction
publique qui expose la liste des tables/colonnes accessibles.

**Architecture** :

- Le **cœur** : la dataclass :class:`UserSchemaView`, immutable.
- L'**entrée** : :func:`build_user_schema_view` qui matérialise la vue
  à partir des règles ``DataAccessRule`` + de l'inventaire schéma stocké
  dans ``TrainingData``.
- Le **cache** : TTL 60s par ``user_id``, invalidé en event-based par
  :func:`invalidate_view_cache` (appelée par ``enforcer.invalidate_user``).
- Le **fail-closed** : en cas d'erreur de chargement, retourne une vue
  vide (``visible_tables=frozenset()``) — l'utilisateur ne voit rien
  plutôt que tout. **Note V0** : si l'enforcement global est OFF, ce
  fail-closed est neutralisé (cf. ``UserSchemaView.enforcement_active``).

**Évolution prévue** (Phase 2.1) : ajouter le calcul du closure transitif
des dépendances vues/fonctions/synonymes via le champ ``TrainingData.depends_on``.
Aujourd'hui (V0), la vue inclut uniquement les tables atomiques connues
en BDD — équivalent fonctionnel à l'état avant ce refactor, le temps que
la Phase 1 (sync étendu) soit en place.

**Anti-patterns à éviter** :

- Lire directement ``TrainingData`` ou ``DataAccessRule`` pour construire
  un contexte LLM ou un check SQL → utiliser cette vue.
- Cacher la vue ailleurs que dans ce module → un seul cache, une seule
  invalidation.
- Muter une ``UserSchemaView`` après construction → elle est immutable
  par design ; faire un :func:`build_user_schema_view` pour reconstruire.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple

from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Garde-fou anti-cycle pour le BFS de :func:`_compute_transitive_closure`.
#: Une vue qui dépend transitivement de plus de 50 niveaux d'objets est
#: une anomalie (cycle ou schéma pathologique). On stoppe et on logue.
_CLOSURE_MAX_ITERATIONS: int = 50

#: **Phase 2.1.ter (#88)** — Cache process-local de l'inventaire
#: ``obj_to_deps`` (mapping ``view/function/synonym → dependencies``)
#: chargé depuis ``TrainingData``. Sans ce cache, chaque appel à
#: :func:`_compute_transitive_closure` ré-exécute la même query SELECT
#: sur ``TrainingData`` — coûteux quand N users avec règles actives
#: rafraîchissent leurs views simultanément (par exemple après une
#: invalidation broadcast). Le cache divise par N le nombre de
#: queries pour la fenêtre TTL.
#:
#: Invalidation : event-based via :func:`invalidate_obj_to_deps_cache`
#: appelée depuis le sync schéma (quand une VIEW/FUNCTION/SYNONYM est
#: ajoutée/modifiée/désactivée). TTL fallback ``_OBJ_TO_DEPS_TTL`` en
#: filet de sécurité (60s, aligné avec :data:`_CACHE_TTL_SECONDS` du
#: cache UserSchemaView).
#:
#: Tuple ``(timestamp_seconds, dict)`` pour TTL + atomicité de lecture
#: (un seul tuple lookup = pas de race avec une invalidation partielle).
_OBJ_TO_DEPS_CACHE: Optional[tuple[float, Dict[str, Optional[FrozenSet[str]]]]] = None
_OBJ_TO_DEPS_TTL: int = 60


def invalidate_obj_to_deps_cache() -> None:
    """Invalide le cache process-local de ``obj_to_deps``.

    À appeler depuis le sync schéma quand une VIEW/FUNCTION/SYNONYM est
    ajoutée/modifiée/désactivée — sinon les nouvelles dépendances
    n'apparaîtront dans la closure qu'après expiration du TTL (60s).
    """
    global _OBJ_TO_DEPS_CACHE
    _OBJ_TO_DEPS_CACHE = None
    logger.debug("invalidate_obj_to_deps_cache: cache vidé")


def _normalize_object_name(raw: Any) -> str:
    """Normalise un nom d'objet BDD pour comparaison case-insensitive.

    **Phase 2.1 fix #7 (CRITICAL review)** : SQL Server expose les noms
    sous diverses formes selon le call-site source :

    - ``F_SALAIRES`` (bare, depuis ``tbl.name`` sqlglot)
    - ``[F_SALAIRES]`` (avec crochets, depuis SSMS scripting)
    - ``[dbo].[F_SALAIRES]`` (qualifié schema, depuis ``sys.synonyms.base_object_name``)
    - ``dbo.F_SALAIRES`` (qualifié non-bracketé)
    - ``  F_SALAIRES  `` (avec whitespace inattendu)

    Sans normalisation symétrique, un ``depends_on=["[dbo].[F_SALAIRES]"]``
    (cible synonyme SQL Server) ne matche pas ``rules.denied_tables={"F_SALAIRES"}``,
    et la closure laisse passer une vue dont la cible est interdite —
    contournement silencieux de la promesse mode invisible.

    Stratégie : strip whitespace → strip brackets ``[``/``]`` → ne garder
    que la portion après le dernier ``.`` (schema préfixé) → UPPERCASE.

    Args:
        raw: Valeur brute (string ou autre — tolère int/None pour
            robustesse, retourne string vide dans ce cas).

    Returns:
        Nom normalisé UPPERCASE sans schema/brackets, ou ``""`` si
        l'input est invalide.
    """
    if raw is None:
        return ""
    try:
        s = str(raw).strip()
    except Exception:
        return ""
    if not s:
        return ""
    # Strip brackets autour de chaque segment (gère `[dbo].[F_X]` → `dbo.F_X`)
    s = s.replace("[", "").replace("]", "")
    # Garder uniquement la portion après le dernier '.' (`dbo.F_X` → `F_X`)
    if "." in s:
        s = s.rsplit(".", 1)[-1]
    # Strip whitespace résiduel + upper
    return s.strip().upper()


# ---------------------------------------------------------------------------
# Types immutables
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RowFilterDescriptor:
    """Description immutable d'un row-filter à injecter au WHERE.

    Contrairement au tuple anonyme utilisé par l'enforcer V0, cette
    structure typée rend les call-sites plus lisibles et permet
    d'évoluer (ajout de méta : opérateur autre que IN, etc.) sans
    casser les consommateurs.
    """

    #: Nom de la table CIBLE, normalisé en UPPERCASE.
    table: str
    #: Nom de la colonne sur laquelle injecter le filtre, UPPERCASE.
    column: str
    #: Valeurs autorisées (sera traduit en ``IN (v1, v2, ...)``). Tuple
    #: immutable pour que la ``UserSchemaView`` soit safely hashable.
    allowed_values: Tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class UserSchemaView:
    """Vue immutable du schéma BDD telle qu'un utilisateur peut la voir.

    **Source unique de vérité** consommée par :

    - L'enforcer SQL pour décider d'accepter/refuser une requête
      (cf. :func:`app.services.data_access.enforcer.check_sql_access`).
    - Les call-sites LLM pour construire un contexte schéma filtré
      (cf. ``llm_context.build_llm_schema_context``, à venir Phase 4.1).

    La vue est calculée à chaque modification de règles (cache invalidé
    en event-based) ou à expiration TTL (60s).

    **Sémantique** :

    - ``is_admin=True`` OU ``enforcement_active=False`` →
      ``visible_tables`` contient l'inventaire complet (la vue ne filtre
      rien). Les consommateurs peuvent vérifier ``has_restrictions``
      pour court-circuiter le filtrage par perf si pas nécessaire.
    - Sinon → ``visible_tables`` est l'intersection (inventaire − interdits).
    - ``columns_by_table`` est défini **uniquement** pour les tables dans
      ``visible_tables``. Une table absente de ``visible_tables`` n'a
      pas d'entrée dans ``columns_by_table``.
    """

    #: ID de l'utilisateur (None ou -1 = anonyme / pas d'identité).
    user_id: int

    #: True si l'user est admin (bypass de tout filtre).
    is_admin: bool

    #: True si le toggle global ``data_access_enforcement_enabled`` est ON.
    #: False → la vue n'applique aucun filtre (mode legacy).
    enforcement_active: bool

    #: Ensemble des tables visibles par cet user. UPPERCASE.
    #: Inclut, à terme (Phase 2.1), les vues/fonctions/synonymes non
    #: dépendants de tables interdites.
    visible_tables: FrozenSet[str]

    #: Pour chaque table visible : l'ensemble des colonnes visibles.
    #: Une table sans entrée = colonnes inconnues (on les laisse passer
    #: dans le doute, car on n'a pas le DDL parsé pour cette table).
    columns_by_table: Dict[str, FrozenSet[str]] = field(default_factory=dict)

    #: Filtres ligne à injecter au WHERE pour les tables concernées.
    row_filters: Tuple[RowFilterDescriptor, ...] = ()

    #: Flag interne posé par le builder : True si l'user avait au moins
    #: une règle ``DataAccessRule`` active au moment du build (deny ou row).
    #: Permet à :prop:`has_restrictions` de retourner True même quand la
    #: vue n'a que des denied_tables (pas de row_filter explicite).
    has_active_rules: bool = False

    #: Map ``{TABLE_UP: frozenset(COL_UP)}`` des colonnes explicitement
    #: deny par règle ``DataAccessRule``. Distinct de ``columns_by_table``
    #: (qui liste les colonnes VISIBLES connues via DDL serveur). Source
    #: de vérité pour les call-sites qui ont une autre source de schéma
    #: (YAML, fichiers locaux) que ce que la BDD serveur connaît :
    #: SchemaLoader doit croiser cette map AVANT d'exposer une colonne
    #: pour éviter le leak quand le DDL serveur ne contient pas une
    #: colonne PII mais que le YAML local l'expose.
    #: Phase α.2 BLOCKING fix #2.
    denied_columns: Dict[str, FrozenSet[str]] = field(default_factory=dict)

    #: **Phase 2.2 (#45)** — Sur-ensemble strict de ``rules.denied_tables``
    #: étendu par :func:`_compute_transitive_closure`. Inclut les tables
    #: atomiques explicitement deny PLUS les VIEW/FUNCTION/SYNONYM qui
    #: en dépendent transitivement via ``TrainingData.depends_on``.
    #:
    #: **Consommée par** :func:`enforcer.check_sql_access` pour bloquer
    #: les objets dérivés qui n'apparaissent pas dans
    #: ``rules.denied_tables`` (atomiques) mais sont interdits par
    #: closure.
    #:
    #: **Vide** pour :data:`EMPTY_VIEW`, les admins, et les users sans
    #: règle. Les consumers doivent retomber sur ``rules.denied_tables``
    #: dans ce cas (fail-soft).
    denied_tables_with_closure: FrozenSet[str] = frozenset()

    @property
    def has_restrictions(self) -> bool:
        """True si la vue applique au moins un filtre observable.

        Permet aux consommateurs de court-circuiter rapidement le
        filtrage si l'user est admin / enforcement off / aucune règle.

        **Garantie** : si False, l'user voit l'inventaire complet sans
        modification (équivalent admin). Si True, AU MOINS une règle
        est appliquée — soit une table cachée, soit une colonne cachée,
        soit un row_filter actif, soit la vue est :data:`EMPTY_VIEW`
        (fail-closed anonyme / shape invalide).

        **Phase α.3 fix BLOCKING #1** : sans la 3ème clause
        ``or not self.visible_tables``, :data:`EMPTY_VIEW`
        (``has_active_rules=False, row_filters=()``) renvoyait False
        ici — les call-sites qui faisaient ``if not view.has_restrictions:
        return all_tables`` leakaient l'inventaire complet pour un user
        anonyme / mal sérialisé. Désormais EMPTY_VIEW = filtre activé,
        donc ``can_see_table`` retourne False pour tout → ``[]``
        fail-closed naturel.

        Note de cohérence : un user sans règle a ``visible_tables``
        peuplé par l'inventaire complet (cf. ``_build_view_from_db``),
        donc la 3ème clause ne se déclenche QUE pour EMPTY_VIEW.
        """
        if self.is_admin or not self.enforcement_active:
            return False
        return (
            self.has_active_rules
            or bool(self.row_filters)
            or not self.visible_tables  # EMPTY_VIEW guard
        )

    def can_see_table(self, table_name: str) -> bool:
        """True si cet user peut référencer cette table dans une SQL ou
        en voir l'existence dans un contexte LLM."""
        if not self.enforcement_active or self.is_admin:
            return True
        return table_name.upper() in self.visible_tables

    def can_see_column(self, table_name: str, column_name: str) -> bool:
        """True si cet user peut référencer cette colonne.

        Comportement :

        1. Si admin / enforcement off → True (bypass).
        2. Si la table n'est pas visible → False.
        3. Si la colonne est dans ``denied_columns[table]`` (règle deny
           explicite) → False (fail-closed strict, indépendant du DDL).
        4. Si DDL connu via ``columns_by_table`` ET colonne pas listée
           → False.
        5. Si DDL inconnu (table absente de ``columns_by_table``) ET
           pas de règle deny sur cette colonne → True (permissif).

        L'étape 3 (Phase α.2 BLOCKING fix #2) garantit qu'une colonne
        deny par règle est CACHÉE même si la BDD serveur ne connaît pas
        cette colonne — important pour SchemaLoader qui consomme aussi
        un YAML local potentiellement plus riche que la BDD.
        """
        if not self.enforcement_active or self.is_admin:
            return True
        table_up = table_name.upper()
        if table_up not in self.visible_tables:
            return False
        col_up = column_name.upper()
        # Fail-closed strict via règles deny brutes (indépendant du DDL).
        denied = self.denied_columns.get(table_up)
        if denied is not None and col_up in denied:
            return False
        # Sinon, consulter le DDL si connu, fail-open si inconnu.
        cols = self.columns_by_table.get(table_up)
        if cols is None:
            return True  # DDL inconnu, pas de règle deny → permissif
        return col_up in cols

    def row_filters_for_table(self, table_name: str) -> Tuple[RowFilterDescriptor, ...]:
        """Retourne les row_filters qui concernent une table donnée."""
        if not self.enforcement_active or self.is_admin:
            return ()
        table_up = table_name.upper()
        return tuple(rf for rf in self.row_filters if rf.table == table_up)

    def denied_columns_flat(self) -> FrozenSet[str]:
        """Ensemble plat des noms de colonnes interdites — Phase 3.3.

        Sera matérialisé au build une fois que la garde-fou pré-LLM
        sera en place. V0 : retourne frozenset vide (le hook 3.3 n'est
        pas encore branché, donc personne ne consomme).
        """
        return frozenset()


#: Vue spéciale "anonyme / pas d'utilisateur identifiable". Aucune table
#: visible — fail-closed strict pour ce cas. Les call-sites SYSTEM utilisent
#: leur propre bypass via ``enforcer.SYSTEM_USER``, ils ne passent pas par
#: cette vue.
EMPTY_VIEW: UserSchemaView = UserSchemaView(
    user_id=-1,
    is_admin=False,
    enforcement_active=True,
    visible_tables=frozenset(),
    columns_by_table={},
    row_filters=(),
)


# ---------------------------------------------------------------------------
# Cache TTL + invalidation
# ---------------------------------------------------------------------------


_CACHE_TTL_SECONDS: int = 60
#: **Bornage LRU pour anti-growth** (Bug 2026-05-26 Agent 4 DA-M5).
#: Avant : ``Dict`` non borné = croissance linéaire avec le nombre d'users
#: actifs. À 10K users (multi-cabinet futur), la mémoire grossissait
#: sans frein. Cap raisonnable : 2000 entrées (5× l'estimation Komptia
#: single-cabinet, suffisant pour multi-cabinet moyen). L'invalidation
#: explicite via ``invalidate_view_cache`` reste prioritaire ; le LRU
#: éviction est un filet de sécurité quand l'admin oublie d'invalider
#: (cas du schema sync qui touche N tables → N invalidations).
_VIEW_CACHE_MAX_ENTRIES: int = 2000
#: ``{user_id: (timestamp_monotonic, view)}``.
#: Cache séparé de celui de ``enforcer._CACHE`` mais invalidé en chaîne :
#: ``enforcer.invalidate_user`` appelle :func:`invalidate_view_cache`
#: (import lazy pour éviter la dépendance circulaire).
#: ``OrderedDict`` pour pouvoir éjecter le plus ancien sur overflow
#: (LRU-like — utilise ``move_to_end`` à chaque hit pour vraiment LRU).
from collections import OrderedDict

_VIEW_CACHE: "OrderedDict[int, Tuple[float, UserSchemaView]]" = OrderedDict()


def _set_view_cache(user_id: int, value: Tuple[float, UserSchemaView]) -> None:
    """Insère une entrée dans ``_VIEW_CACHE`` avec éviction LRU.

    Si la taille dépasse ``_VIEW_CACHE_MAX_ENTRIES``, retire la plus
    ancienne entrée (``popitem(last=False)``). Bug 2026-05-26 (DA-M5).
    """
    _VIEW_CACHE[user_id] = value
    _VIEW_CACHE.move_to_end(user_id)
    while len(_VIEW_CACHE) > _VIEW_CACHE_MAX_ENTRIES:
        try:
            _VIEW_CACHE.popitem(last=False)  # FIFO eviction
        except KeyError:  # race possible — defensive
            break

#: **Phase 2.1.bis (#87) — Locks PAR user_id (au lieu d'un lock global).**
#:
#: Avant : 1 seul ``asyncio.Lock`` partagé → si N users différents font
#: un cache miss simultanément (par exemple juste après un sync schéma
#: qui a invalidé tout le cache), ils s'attendent en série. Pénalité
#: O(N) sur la latence des 1ères requêtes après invalidation.
#:
#: Après : 1 lock par user_id → les builds de users DIFFÉRENTS tournent
#: en parallèle. Les builds simultanés du MÊME user sont toujours
#: sérialisés (1 seul fait le travail BDD, les autres lisent le cache
#: après).
#:
#: ``_VIEW_CACHE_LOCKS_MUTEX`` protège uniquement la **création** d'un
#: nouveau lock dans le dict (anti race "2 coroutines créent 2 locks
#: différents pour le même user"). Le mutex est libéré dès que le lock
#: du user est obtenu — pas gardé pendant le build (sinon on perd le
#: bénéfice de la granularité).
_VIEW_CACHE_LOCKS: Dict[int, asyncio.Lock] = {}
_VIEW_CACHE_LOCKS_MUTEX = asyncio.Lock()


async def _get_user_lock(user_id: int) -> asyncio.Lock:
    """Retourne le lock dédié à ``user_id``, en le créant si nécessaire."""
    lock = _VIEW_CACHE_LOCKS.get(user_id)
    if lock is not None:
        return lock
    async with _VIEW_CACHE_LOCKS_MUTEX:
        # Re-check après acquire (un autre a peut-être créé entre-temps)
        lock = _VIEW_CACHE_LOCKS.get(user_id)
        if lock is None:
            lock = asyncio.Lock()
            _VIEW_CACHE_LOCKS[user_id] = lock
        return lock


def invalidate_view_cache(user_id: int) -> None:
    """Invalide l'entrée cache pour un user.

    Appelée par :func:`enforcer.invalidate_user` et par les handlers
    admin qui modifient les règles d'un user. Atomique (dict.pop est
    thread-safe en CPython).
    """
    _VIEW_CACHE.pop(user_id, None)


def invalidate_all_view_cache() -> None:
    """Vide tout le cache. Appelé sur changement du toggle global ou
    sur sync schéma terminé (l'inventaire des tables peut avoir changé)."""
    _VIEW_CACHE.clear()


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


async def build_user_schema_view(user: Any) -> UserSchemaView:
    """Construit ou récupère depuis le cache la vue immutable d'un user.

    **Source unique de vérité** : tout call-site qui a besoin de savoir
    ce que cet user peut voir DOIT passer par cette fonction. Aucun
    autre chemin n'est valide.

    Args:
        user: instance ``User`` (avec ``id`` et ``role``) ou ``None``
            (anonyme — retourne :data:`EMPTY_VIEW`).

    Returns:
        :class:`UserSchemaView` immutable. La même instance peut être
        retournée à plusieurs appelants dans la fenêtre TTL — c'est
        safe car immutable.

    **Fail-closed** : en cas d'erreur de chargement BDD (timeout,
    schéma corrompu, etc.), retourne :data:`EMPTY_VIEW` plutôt que de
    bypasser. Le bug est loggé en ERROR pour diagnostic.

    **Phase 2.1 (closure transitif)** : depuis #44, la vue inclut désormais
    la fermeture transitive des dépendances. Si l'admin pose
    ``deny F_SALAIRES``, toute VIEW / FUNCTION / SYNONYM qui référence
    (directement ou en chaîne) ``F_SALAIRES`` est automatiquement ajoutée
    aux ``denied_tables`` calculées et n'apparaît PAS dans ``visible_tables``.
    Voir :func:`_compute_transitive_closure` pour l'algorithme.
    """
    if user is None:
        return EMPTY_VIEW

    user_id = getattr(user, "id", None)
    if user_id is None:
        return EMPTY_VIEW

    # Cache hit chemin rapide
    now = time.monotonic()
    cached = _VIEW_CACHE.get(user_id)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    # **Phase 2.1.bis (#87)** — Cache miss → build sous lock PAR user_id
    # (au lieu d'un lock global). Permet aux builds de users différents de
    # tourner en parallèle. Re-check après acquire pour le cas où un autre
    # build du MÊME user a terminé entre le 1er check et l'acquisition.
    user_lock = await _get_user_lock(user_id)
    async with user_lock:
        cached = _VIEW_CACHE.get(user_id)
        if cached is not None and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
            return cached[1]

        try:
            view = await _build_view_from_db(user, user_id)
        except Exception as exc:
            logger.error(
                "visible_schema: build_user_schema_view(user_id=%s) failed "
                "— fail-closed avec EMPTY_VIEW: %s",
                user_id,
                exc,
                exc_info=True,
            )
            view = EMPTY_VIEW

        # Bug 2026-05-26 (DA-M5) : passe par le helper LRU plutôt que
        # ``_VIEW_CACHE[user_id] = ...`` direct. Le helper gère l'éviction
        # de la plus ancienne entrée quand on dépasse le cap.
        _set_view_cache(user_id, (time.monotonic(), view))
        return view


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _build_view_from_db(user: Any, user_id: int) -> UserSchemaView:
    """Charge l'inventaire schéma + les règles utilisateur et compose la vue.

    Sépare la logique pour faciliter les tests (mockable) et la
    réutilisation. Le contrat : retourne une :class:`UserSchemaView`
    valide, ou lève — le caller (``build_user_schema_view``) attrape
    et fail-closed.
    """
    # Imports lazy pour éviter la dépendance circulaire avec enforcer
    # qui importera invalidate_view_cache depuis ce module.
    from app.services.data_access import enforcer as _enforcer

    # Mode admin → vue complète. On peut court-circuiter le chargement
    # de l'inventaire (l'admin n'a rien à filtrer), mais on doit quand
    # même peupler ``visible_tables`` pour que les call-sites LLM aient
    # l'inventaire complet à exposer au LLM.
    is_admin = _enforcer.is_user_exempt(user)
    enforcement_active = await _enforcer.is_enforcement_enabled()

    if is_admin or not enforcement_active:
        all_tables, all_columns = await _load_schema_inventory()
        return UserSchemaView(
            user_id=user_id,
            is_admin=is_admin,
            enforcement_active=enforcement_active,
            visible_tables=frozenset(all_tables),
            columns_by_table={t: frozenset(c) for t, c in all_columns.items()},
            row_filters=(),
        )

    # Mode user restreint
    rules = await _enforcer.load_rules_for_user(user_id)
    if rules.is_empty:
        # User sans règle → vue complète (l'admin n'a pas posé de
        # restriction donc on laisse tout). Cohérent avec le comportement
        # actuel de l'enforcer.
        all_tables, all_columns = await _load_schema_inventory()
        return UserSchemaView(
            user_id=user_id,
            is_admin=False,
            enforcement_active=True,
            visible_tables=frozenset(all_tables),
            columns_by_table={t: frozenset(c) for t, c in all_columns.items()},
            row_filters=(),
        )

    # Calcul des éléments visibles : inventaire moins les interdits
    all_tables, all_columns = await _load_schema_inventory()

    # Inclut row_filters tables dans visible_tables même si pas de DDL
    # connu — la table existe (puisqu'on a une règle dessus), donc visible.
    row_filter_tables = {t for (t, _c, _v) in rules.row_filters}

    # Phase 2.1 (#44) — Closure transitif. Si une table T est denied et
    # qu'une vue V dépend de T, alors V est aussi denied. Itéré sur le
    # graph stocké dans ``TrainingData.depends_on`` pour les types
    # VIEW / FUNCTION / SYNONYM.
    denied_after_closure = await _compute_transitive_closure(rules.denied_tables)

    # visible_tables = (inventaire ∪ tables avec row_filter) − denied (closure)
    candidate = set(all_tables) | row_filter_tables
    visible_tables = frozenset(t for t in candidate if t not in denied_after_closure)

    # columns_by_table : pour chaque table visible avec DDL connu, on
    # retire les colonnes deny. Les tables sans DDL connu n'ont pas
    # d'entrée (= permissif côté ``can_see_column``).
    columns_by_table: Dict[str, FrozenSet[str]] = {}
    for table_up in visible_tables:
        cols_known = all_columns.get(table_up)
        if cols_known is None:
            continue  # DDL inconnu, on n'entre rien
        denied_cols = rules.denied_columns.get(table_up, set())
        visible_cols = frozenset(c for c in cols_known if c not in denied_cols)
        columns_by_table[table_up] = visible_cols

    # row_filters : on convertit les tuples en RowFilterDescriptor
    row_filters = tuple(
        RowFilterDescriptor(
            table=t,
            column=c,
            allowed_values=tuple(v),
        )
        for (t, c, v) in rules.row_filters
    )

    # Phase α.2 BLOCKING fix #2 — Matérialiser les denied_columns brutes
    # pour que les call-sites avec une source de schéma autre que la BDD
    # (typiquement SchemaLoader+YAML) puissent croiser et fail-closed
    # sur une colonne deny même quand le DDL serveur ne la connaît pas.
    denied_columns_frozen: Dict[str, FrozenSet[str]] = {
        t: frozenset(cols) for t, cols in rules.denied_columns.items()
    }

    return UserSchemaView(
        user_id=user_id,
        is_admin=False,
        enforcement_active=True,
        visible_tables=visible_tables,
        columns_by_table=columns_by_table,
        row_filters=row_filters,
        has_active_rules=True,  # on est arrivé ici car rules.is_empty == False
        denied_columns=denied_columns_frozen,
        denied_tables_with_closure=frozenset(denied_after_closure),
    )


async def _compute_transitive_closure(initial_denied: Set[str]) -> Set[str]:
    """Étend ``initial_denied`` avec la fermeture transitive des dépendances.

    **Phase 2.1 (#44)** — algorithme de fermeture sur le graph stocké dans
    ``TrainingData.depends_on``. Si une table T est dans ``initial_denied``,
    et qu'une VIEW / FUNCTION / SYNONYM V a ``T`` dans ses dépendances,
    alors V est ajoutée. Le processus est itéré jusqu'à stabilisation
    (point fixe) pour gérer les chaînes (V2 → V1 → T).

    **Sémantique précise** :

    - ``initial_denied`` est attendu **déjà en UPPERCASE** (contrat
      :class:`_UserRules`). On le respecte ; on normalise UPPERCASE les
      lectures BDD côté ce builder.
    - ``depends_on=None`` (parser sqlglot a échoué OU objet pré-Phase 1.5
      sans backfill) → **fail-closed** : l'objet est ajouté à la closure
      dès qu'il y a au moins une règle deny. Sécurité avant tout — un
      objet dont on ne connaît pas les dépendances ne peut pas être prouvé
      safe. On logue WARNING pour diagnostic.
    - ``depends_on=[]`` (parser a parsé mais 0 dépendance) → objet
      autonome, jamais bloqué par la closure (sauf s'il est lui-même
      dans ``initial_denied``, ce qui ne devrait pas arriver pour un
      objet dérivé).
    - **Cycles** : protégés par :data:`_CLOSURE_MAX_ITERATIONS`. Une
      vue qui dépend de plus de 50 niveaux est anormale — on logue
      WARNING et on stoppe avec ce qu'on a.

    **Fail-closed sur erreur de chargement** : si la lecture BDD échoue
    (timeout, schéma corrompu, etc.), on retourne ``initial_denied`` tel
    quel (pas d'extension) + log ERROR. Komptia continue de fonctionner
    mais perd la protection closure pour cette session. Le caller
    (``_build_view_from_db``) est lui-même wrappé fail-closed dans
    :func:`build_user_schema_view` — donc en cas de double échec on
    retombe sur :data:`EMPTY_VIEW`.

    Args:
        initial_denied: Tables atomiques bloquées par règles directes.
            UPPERCASE. Peut être vide → court-circuit immédiat.

    Returns:
        :class:`set` étendu (copie). Inclut ``initial_denied`` + tous
        les objets dérivés qui en dépendent transitivement. Tous en
        UPPERCASE.
    """
    # Court-circuit O(1) : pas de règle deny → pas de closure à calculer.
    if not initial_denied:
        return set()

    # Imports lazy (cohérent avec _load_schema_inventory) — évite la
    # dépendance circulaire au boot quand la BDD n'est pas encore prête.
    # **Phase 2.1.ter (#88) — Cache process-local TTL 60s.** Avant ce
    # cache, chaque appel rejouait la query SELECT TrainingData →
    # coûteux quand N users avec règles actives rafraîchissent leurs
    # views simultanément. Avec le cache, 1 query par fenêtre TTL.
    global _OBJ_TO_DEPS_CACHE
    import time as _time

    now = _time.time()
    obj_to_deps: Optional[Dict[str, Optional[FrozenSet[str]]]] = None
    if _OBJ_TO_DEPS_CACHE is not None:
        cached_ts, cached_map = _OBJ_TO_DEPS_CACHE
        if (now - cached_ts) < _OBJ_TO_DEPS_TTL:
            obj_to_deps = cached_map

    if obj_to_deps is None:
        # Cache miss → query BDD + repopule le cache.
        # Phase 2.1 fix #6 (CRITICAL review) — un ImportError ici signifie
        # une régression sérieuse (refactor du modèle / renommage de classe).
        # On NE catche PAS : on laisse propager vers ``build_user_schema_view``
        # qui fail-closed via EMPTY_VIEW. Mieux qu'un fail-soft silencieux
        # qui désactiverait la closure pour tous les users post-upgrade.
        from sqlalchemy import select as sa_select

        from app.core.database import get_session
        from app.models.training_data import TrainingData, TrainingDataType

        try:
            async with get_session() as session:
                stmt = sa_select(
                    TrainingData.table_name,
                    TrainingData.depends_on,
                ).where(
                    TrainingData.data_type.in_(
                        (
                            TrainingDataType.VIEW.value,
                            TrainingDataType.FUNCTION.value,
                            TrainingDataType.SYNONYM.value,
                        )
                    ),
                    TrainingData.is_active.is_(True),
                )
                rows = (await session.execute(stmt)).all()
        except Exception as exc:
            logger.error(
                "visible_schema._compute_transitive_closure: BDD load failed "
                "(user a des règles mais la closure ne s'applique pas — "
                "objets dérivés possiblement visibles): %s",
                exc,
                exc_info=True,
            )
            # Fail-soft : on garde initial_denied. Komptia fonctionne, mais
            # la protection closure est dégradée jusqu'à ce que la BDD
            # revienne. Logué pour qu'on le voie en monitoring.
            return set(initial_denied)

        # Construction de l'index obj_up → deps_up_set (ou None si inconnu).
        # On filtre les rows sans table_name (sécurité défensive — le sync ne
        # devrait pas en produire mais on robustifie).
        obj_to_deps = {}
        for table_name, deps in rows:
            name_up = _normalize_object_name(table_name)
            if not name_up:
                continue
            if deps is None:
                # Parser sqlglot a échoué OU objet pré-backfill : on marque
                # explicitement comme "inconnu" pour le fail-closed.
                obj_to_deps[name_up] = None
            else:
                try:
                    # Phase 2.1 fix #7 — normaliser chaque dep (strip schema
                    # prefix + brackets + UPPER) pour matcher robustement les
                    # ``denied_tables`` de l'enforcer (qui sont déjà UPPER
                    # sans schema/bracket via :func:`enforcer._load_rules_from_db`).
                    deps_norm = frozenset(n for n in (_normalize_object_name(d) for d in deps) if n)
                except TypeError:
                    # ``deps`` n'est pas itérable (corruption JSON / type
                    # inattendu). Traiter comme inconnu (fail-closed).
                    logger.warning(
                        "visible_schema._compute_transitive_closure: "
                        "depends_on non itérable pour %s, fail-closed",
                        name_up,
                    )
                    obj_to_deps[name_up] = None
                    continue
                obj_to_deps[name_up] = deps_norm

        # Met en cache pour les prochains appels dans la fenêtre TTL.
        _OBJ_TO_DEPS_CACHE = (now, obj_to_deps)
        logger.debug(
            "visible_schema._compute_transitive_closure: obj_to_deps "
            "construit (%d objets) et caché",
            len(obj_to_deps),
        )

    # BFS itératif jusqu'à point fixe. À chaque itération, on ajoute les
    # objets dont au moins une dep est déjà dans ``closed`` (tables
    # atomiques denied OU vues/fonctions/synonymes déjà bloqués par
    # transitivité). Garde-fou :data:`_CLOSURE_MAX_ITERATIONS` en cas
    # de cycle pathologique.
    closed: Set[str] = set(initial_denied)
    unresolved_unknown_deps: list[str] = []  # pour log diagnostique

    for iteration in range(_CLOSURE_MAX_ITERATIONS):
        changed = False
        for name_up, deps in obj_to_deps.items():
            if name_up in closed:
                continue
            if deps is None:
                # Fail-closed : deps inconnues + user a des règles → bloque.
                # On ne le fait QU'à la 1ère itération pour ne pas
                # spammer les logs (le résultat est idempotent).
                if iteration == 0:
                    unresolved_unknown_deps.append(name_up)
                closed.add(name_up)
                changed = True
                continue
            if deps & closed:
                closed.add(name_up)
                changed = True
        if not changed:
            break
    else:
        logger.warning(
            "visible_schema._compute_transitive_closure: "
            "max_iterations=%d atteint — cycle suspect dans depends_on. "
            "Closure partielle utilisée (%d objets bloqués).",
            _CLOSURE_MAX_ITERATIONS,
            len(closed),
        )

    if unresolved_unknown_deps:
        # Log groupé (1 ligne) plutôt que 1 par objet — évite le spam.
        sample = sorted(unresolved_unknown_deps)[:10]
        logger.warning(
            "visible_schema._compute_transitive_closure: %d objet(s) "
            "dérivé(s) sans depends_on connu → fail-closed (échantillon: %s). "
            "Re-synchroniser le schéma pour peupler depends_on.",
            len(unresolved_unknown_deps),
            ", ".join(sample),
        )

    return closed


async def _load_schema_inventory() -> Tuple[FrozenSet[str], Dict[str, FrozenSet[str]]]:
    """Charge l'inventaire des tables et colonnes connues depuis ``TrainingData``.

    **Phase 2.1 fix #1 (BLOCKING review)** : charge maintenant les
    ``data_type IN (DDL, VIEW, FUNCTION, SYNONYM)``. Sans ça, après la
    migration Phase 1.6 (#43) qui re-classifie les vues en ``data_type=VIEW``,
    aucune vue n'était dans ``visible_tables`` — ni bloquée, ni légitime —
    rendant la closure transitive inopérante en pratique.

    L'extraction de colonnes via ``extract_columns_from_ddl`` est tentée
    pour tous les types, mais en pratique elle ne matche que les
    ``CREATE TABLE``. Pour les VIEW/FUNCTION/SYNONYM, l'entrée
    ``columns_by_table`` reste absente → ``can_see_column`` retourne True
    par défaut (permissif sur DDL inconnu), ce qui est conservateur en
    UX et safe en sécurité (la table elle-même est filtrée si denied).

    Retourne ``(tables_uppercase, {table_up: frozenset(cols_up)})``.

    En cas d'erreur (BDD non initialisée, table TrainingData vide, etc.),
    logue en ERROR et retourne ``(frozenset(), {})``. Le caller
    (``_build_view_from_db``) retombe alors sur une vue avec
    ``visible_tables=frozenset()`` ce qui, pour un user avec règles,
    déclenche ``has_restrictions=True`` (EMPTY_VIEW guard) — fail-closed.
    """
    try:
        from sqlalchemy import select as sa_select

        from app.core.database import get_session
        from app.models.training_data import TrainingData, TrainingDataType
        from app.services.data_access.schema_utils import extract_columns_from_ddl

        async with get_session() as session:
            stmt = sa_select(TrainingData.table_name, TrainingData.content).where(
                TrainingData.data_type.in_(
                    (
                        TrainingDataType.DDL.value,
                        TrainingDataType.VIEW.value,
                        TrainingDataType.FUNCTION.value,
                        TrainingDataType.SYNONYM.value,
                    )
                ),
                TrainingData.is_active.is_(True),
            )
            rows = (await session.execute(stmt)).all()

        tables: set[str] = set()
        columns: Dict[str, FrozenSet[str]] = {}
        for table_name, content in rows:
            if not table_name:
                continue
            table_up = table_name.strip().upper()
            tables.add(table_up)
            # Tentative d'extraction des colonnes — fonctionne pour CREATE TABLE,
            # retourne vide pour CREATE VIEW/FUNCTION/SYNONYM (sémantique
            # actuelle de extract_columns_from_ddl).
            if content:
                cols = extract_columns_from_ddl(content)
                if cols:
                    columns[table_up] = frozenset(c.upper() for c in cols)

        return frozenset(tables), columns
    except Exception as exc:
        # Phase 2.1 review #10 — logger en ERROR (pas WARNING) : un
        # inventaire vide silencieux est trop dangereux à masquer. Le
        # caller fail-closed via EMPTY_VIEW guard.
        logger.error(
            "visible_schema: chargement de l'inventaire schéma échoué "
            "— les users avec règles verront un schéma vide (fail-closed): %s",
            exc,
            exc_info=True,
        )
        return frozenset(), {}
