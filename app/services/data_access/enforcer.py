"""Application runtime des règles d'accès aux données (RLS).

**Rôle** : transformer une SQL utilisateur AVANT exécution selon les règles
``DataAccessRule`` configurées pour cet utilisateur. Trois opérations :

1. **Validation pre-flight** (:func:`check_sql_access`) : la SQL référence-t-elle
   une table ou colonne interdite ? Si oui, rejet avec message.
2. **Injection de filtres** (:func:`apply_row_filters`) : ajout d'un
   ``WHERE col IN (...)`` aux scopes ``row``. Composition AST via sqlglot
   pour résister aux SQL exotiques (CTE, sous-requêtes, alias).
3. **Filtrage du contexte LLM** (:func:`filter_table_catalogue`) : retire
   les tables interdites de la liste exposée à Iris pour qu'il ne les
   propose pas dans ses requêtes (defense-in-depth).

**Stratégies** :

- **Deny wins** sur conflit (fail-closed). Si une règle ``deny`` et une
  règle ``allow`` matchent la même cible, ``deny`` l'emporte.
- **Admin bypass** : ``user.role == ADMIN`` court-circuite tout. Empêche
  l'auto-blocage administrateur.
- **Toggle global off** : si ``data_access_enforcement_enabled`` est
  ``False``, l'enforcer ne fait RIEN (compat des déploiements existants).
- **Cache mémoire TTL 60s par user_id**, invalidé manuellement par les
  handlers admin sur écriture. Pas de bus pub/sub : on assume mono-process
  (Tornado worker unique). Pour scaler, remplacer par Redis.

**Génériquement** : aucun nom de table/colonne hardcodé. Tout vient des
règles configurées et du schéma local (``TrainingData``).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sentinel "appel système" + exception de refus
# ---------------------------------------------------------------------------


class _SystemCallSentinel:
    """Sentinel marquant un appel système (sync schema, métadata,
    introspection interne) qui ne dépend pas d'un user authentifié et qui
    doit BYPASSER l'enforcement RLS.

    Usage : ``executor.execute(sql, user=enforcer.SYSTEM_USER)``.

    **À n'utiliser QUE pour des opérations véritablement système** (sync,
    boot, métadata, jobs background). Si vous êtes dans un path qui sert
    une requête utilisateur, propagez le user réel — pas ce sentinel.
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover
        return "<enforcer.SYSTEM_USER>"


#: Sentinel exposé pour les call-sites système. Voir docstring de la classe.
SYSTEM_USER: _SystemCallSentinel = _SystemCallSentinel()


def is_system_call(user: Any) -> bool:
    """True si ``user`` est le sentinel système (bypass RLS)."""
    return isinstance(user, _SystemCallSentinel)


class DataAccessDeniedError(Exception):
    """Levée par les exécuteurs SQL quand l'enforcement refuse une requête.

    Contrairement à :class:`AccessDecision` (qui est une donnée passive
    retournée par ``check_sql_access``), cette exception propage le refus
    à travers les couches d'exécution (``query_executor.execute`` →
    handlers/services). Les handlers Tornado qui exécutent du SQL devraient
    catch cette exception et la mapper en 403/422 avec le message au user.

    Attributs :
        user_message : message en français adapté à l'utilisateur final.
        blocking_table / blocking_column : quoi a déclenché le refus (debug).
    """

    def __init__(
        self,
        user_message: str,
        *,
        blocking_table: Optional[str] = None,
        blocking_column: Optional[str] = None,
        reason: str = "",
    ) -> None:
        super().__init__(user_message)
        self.user_message = user_message
        self.blocking_table = blocking_table
        self.blocking_column = blocking_column
        self.reason = reason


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AccessDecision:
    """Résultat d'une vérification d'accès SQL."""

    allowed: bool
    reason: str = ""
    user_message: str = ""
    blocking_table: Optional[str] = None
    blocking_column: Optional[str] = None

    @property
    def is_denied(self) -> bool:
        return not self.allowed


_ALLOWED_DECISION = AccessDecision(allowed=True)


@dataclass(slots=True)
class _UserRules:
    """Règles compilées d'un utilisateur, prêtes pour le runtime.

    Les noms de tables/colonnes sont normalisés en UPPERCASE pour matcher
    indépendamment de la casse utilisée dans la SQL (SQL Server est
    case-insensitive sur les identifiants).

    ``is_error`` (Bug 2026-05-26 Agent 4 DA-C1) : True si la lecture BDD
    a échoué pour cet user (SQLite verrouillée, fichier corrompu, etc.).
    Le runtime ne sait pas dans quel état est cet user → on force
    ``should_filter_for=True`` (fail-closed) jusqu'à ce qu'un read réussi
    arrive. Avant le fix, on retournait silencieusement ``_UserRules()``
    vide qui équivaut sémantiquement à "user sans restrictions" — la
    promesse architecturale du mode invisible était inversée.
    """

    user_id: int
    has_any_allow_rule: bool = False
    denied_tables: Set[str] = field(default_factory=set)
    allowed_tables: Set[str] = field(default_factory=set)
    # {TABLE_UP: {COL_UP, ...}}
    denied_columns: Dict[str, Set[str]] = field(default_factory=dict)
    # [(TABLE_UP, COL_UP, [val1, val2, ...]), ...] — row filters cumulables
    row_filters: List[Tuple[str, str, List[Any]]] = field(default_factory=list)
    # Sentinel "erreur BDD au chargement" — fail-closed (cf. docstring class).
    is_error: bool = False

    @property
    def is_empty(self) -> bool:
        return (
            not self.denied_tables
            and not self.allowed_tables
            and not self.denied_columns
            and not self.row_filters
        )


# ---------------------------------------------------------------------------
# Cache (TTL + invalidation event-based)
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS: int = 60
#: ``{user_id: (timestamp, _UserRules)}`` — protégé par ``_CACHE_LOCK``.
_CACHE: Dict[int, Tuple[float, _UserRules]] = {}
_CACHE_LOCK = asyncio.Lock()

#: P5.2 (audit 2026-05-26) — Strong-ref pour les tasks fire-and-forget de
#: ``_audit_log_fail_closed`` (cf. ``feedback_asyncio_create_task_strong_ref.md``
#: 2026-05-22 : Python 3.12+ GC les tasks sans référence forte avant
#: complétion → log audit perdu silencieusement). Le set est nettoyé via
#: ``done_callback`` posé dans ``_spawn_fail_closed_audit_log``.
_FAIL_CLOSED_AUDIT_TASKS: "set[asyncio.Task[None]]" = set()


def _spawn_fail_closed_audit_log(user_id: int, exc: BaseException) -> None:
    """Spawn une task fire-and-forget qui pose un ``audit_logs`` pour le
    fail-closed ``data_access_load_failed``.

    **P5.2 (audit 2026-05-26)** : sans cette ligne d'audit, l'admin n'avait
    aucune métrique pour monitorer la fréquence des fail-closed sur
    ``load_rules_for_user`` (= BDD locked / corrompue) — l'ERROR log était
    la seule trace, impossible de monter un dashboard ou une alerte.

    Strong-ref garantie (Python 3.12+ GC issue) : la task est stockée dans
    ``_FAIL_CLOSED_AUDIT_TASKS`` et retirée via ``done_callback`` à la fin.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Pas de loop courant (path sync ou shutdown) → on skip silencieusement.
        # La log ERROR ci-dessus a déjà capturé l'incident.
        return
    task = loop.create_task(
        _audit_log_fail_closed(user_id, exc),
        name=f"audit_log_data_access_fail_closed_user_{user_id}",
    )
    _FAIL_CLOSED_AUDIT_TASKS.add(task)
    task.add_done_callback(_FAIL_CLOSED_AUDIT_TASKS.discard)


async def _audit_log_fail_closed(user_id: int, exc: BaseException) -> None:
    """Coroutine fire-and-forget qui pose l'entrée ``audit_logs`` du fail-closed.

    **Defensive** : si l'insertion crash (BDD elle-même down — cas vicieux où
    audit_logs est dans la même BDD que les rules qui ont fail), on log et
    on swallow. Ne JAMAIS re-raise dans une task fire-and-forget non awaited.
    """
    try:
        import json as _json

        from app.core.database import get_session
        from app.models.audit import AuditLog

        async with get_session() as session:
            entry = AuditLog(
                user_id=user_id,
                action="data_access_load_failed",
                details=_json.dumps(
                    {
                        "exception_type": type(exc).__name__,
                        "exception_message": str(exc)[:500],
                    },
                    ensure_ascii=False,
                ),
            )
            session.add(entry)
            await session.commit()
    except Exception as audit_exc:  # noqa: BLE001
        # Si même l'audit log crash (BDD complètement down), on log et on
        # passe. Le fail-closed côté load_rules reste actif côté caller.
        logger.warning(
            "audit_log_data_access_fail_closed: pose audit_log échouée "
            "(BDD locked/down ?) — fail-closed maintenu côté caller : %s",
            audit_exc,
        )

#: ``{user_id: (timestamp, bool)}`` — court-circuit O(1) pour Phase α.
#: Sépare du cache rules pour permettre une réponse rapide
#: ``should_filter_for(user)`` SANS charger les détails des règles. Une fois
#: que ``user_has_any_active_rule`` a déclenché un load, on bénéficie aussi
#: du cache détaillé via ``load_rules_for_user`` (TTL identique).
_HAS_RULES_CACHE: Dict[int, Tuple[float, bool]] = {}

#: Token de version O(1) des règles d'accès (par user + époque globale). Bumpé à
#: chaque invalidation. Sert aux caches EN AVAL (ex: résultats dashboard) pour
#: invalider AUTOMATIQUEMENT au changement de droits — sinon un résultat déjà
#: filtré resterait servi jusqu'à son propre TTL (sur-exposition de données au
#: même user). Époque dans une liste = mutable sans ``global``.
_RULES_VERSION: Dict[int, int] = {}
_RULES_VERSION_EPOCH: list = [0]


def rules_cache_token(user_id: int) -> str:
    """Token opaque qui CHANGE dès que les règles d'accès du user (ou le toggle
    global) changent. À injecter dans la clé d'un cache aval pour invalidation
    automatique au changement de droits. O(1), aucun accès BDD. Cast invalide →
    sentinelle ``-1`` (toujours déterministe, jamais d'exception)."""
    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        uid = -1
    return f"{_RULES_VERSION_EPOCH[0]}:{_RULES_VERSION.get(uid, 0)}"


def invalidate_user(user_id: int) -> None:
    """Invalide l'entrée cache pour un user (appelé par les handlers admin
    sur PUT/DELETE/POST de règles).

    **CONTRAT D'APPEL** : doit être invoqué STRICTEMENT APRÈS le commit BDD
    de la modification des règles. Sinon, une coroutine concurrente qui
    appelle ``load_rules_for_user`` entre le ``DELETE/INSERT`` et le
    ``COMMIT`` peut re-cacher les ANCIENNES valeurs pour 60s.

    Pas de Lock ici : opérations atomiques sur dict CPython, et l'invalidation
    n'est pas dans le path critique (acceptable de courir avec un load
    en cours — le load suivant relira la BDD).

    **Ordre d'invalidation** : on vide les caches "consommés en aval"
    (``_HAS_RULES_CACHE``, ``_VIEW_CACHE``) AVANT le cache "source"
    ``_CACHE``. Pourquoi : un consommateur Phase α (``should_filter_for``)
    hit ``_HAS_RULES_CACHE`` en priorité ; si on popait ``_CACHE``
    d'abord, une coroutine concurrente pourrait reload ``_CACHE`` AVANT
    que ``_HAS_RULES_CACHE`` ne soit vidé, recachant l'ancienne réponse
    pour 60s. En vidant d'abord les caches consommés, on garantit
    qu'aucun consommateur ne servira une réponse périmée même en cas de
    race entre invalidation et load.

    Propage l'invalidation à :mod:`visible_schema` qui matérialise la
    ``UserSchemaView``. Import lazy pour éviter la dépendance circulaire.
    """
    # 1) Caches "down-stream" (consommés par Phase α) en premier.
    # Bug 2026-05-26 (Agent 4 DA-M3) : avant, on faisait juste ``pop``,
    # ce qui ouvrait une fenêtre 60s pendant laquelle ``should_filter_for``
    # retournait False (= bypass) pour le user X tant qu'aucune nouvelle
    # requête n'avait re-peuplé le cache. Maintenant on pré-warm
    # immédiatement à ``True`` (= fail-closed conservateur) : tant que
    # la BDD n'est pas re-lue, on filtre pour sécurité. La prochaine
    # ``load_rules_for_user(X)`` écrasera ce pré-warm avec la vraie valeur.
    # Coût : 1 requête potentielle de "filtrage pour rien" pour un user
    # qui n'a effectivement pas de règle — acceptable vs leak de schéma.
    _HAS_RULES_CACHE[user_id] = (time.monotonic(), True)
    try:
        from app.services.data_access.visible_schema import invalidate_view_cache

        invalidate_view_cache(user_id)
    except ImportError:
        # Module pas encore disponible (boot très précoce) — acceptable,
        # le cache visible_schema sera de toute façon vide.
        pass
    # 2) Cache "source" en dernier — re-populé par le prochain
    # ``load_rules_for_user`` qui lira la BDD post-commit (frais).
    _CACHE.pop(user_id, None)
    # 3) Bump du token de version → invalide les caches AVAL (résultats
    # dashboard) qui incluent ce token dans leur clé. O(1), sans exception.
    try:
        _RULES_VERSION[int(user_id)] = _RULES_VERSION.get(int(user_id), 0) + 1
    except (TypeError, ValueError):
        pass


def invalidate_all() -> None:
    """Vide tout le cache (appelé sur changement du toggle global).

    Même ordre d'invalidation que :func:`invalidate_user` : down-stream
    avant up-stream. Propage à :mod:`visible_schema`.
    """
    _HAS_RULES_CACHE.clear()
    try:
        from app.services.data_access.visible_schema import invalidate_all_view_cache

        invalidate_all_view_cache()
    except ImportError:
        pass
    _CACHE.clear()
    # Époque globale bumpée → invalide TOUS les tokens aval d'un coup (les
    # entrées de cache dashboard portant l'ancienne époque ne seront plus hit).
    _RULES_VERSION_EPOCH[0] += 1
    _RULES_VERSION.clear()


# ---------------------------------------------------------------------------
# Configuration toggles (lecture du flag global et bypass admin)
# ---------------------------------------------------------------------------


async def is_enforcement_enabled() -> bool:
    """Renvoie toujours ``True`` (décision produit 2026-05-18 : David).

    Historiquement gated par ``ai_config.data_access_enforcement_enabled``
    (toggle admin dans ``/admin/ai-config``). Le toggle a été retiré le
    2026-05-18 : « si les règles sont là c'est qu'il faut les appliquer ».
    Les règles définies dans ``/admin/data-access`` sont désormais
    inconditionnellement appliquées au runtime (les admins continuent à
    bypass via :func:`is_user_exempt`, sémantique inchangée).

    La fonction est conservée comme point de réintroduction futur d'un
    toggle si le produit évolue. La clé BDD
    ``DATA_ACCESS_ENFORCEMENT_ENABLED`` reste lue par d'autres call-sites
    mais n'a plus d'effet sur l'enforcement RLS.
    """
    return True


def is_user_exempt(user: Any) -> bool:
    """Renvoie True si l'utilisateur bypasse l'enforcement (admin).

    Accepte aussi un user None ou sans rôle : dans ces cas, NON exempt
    (on n'autorise pas un user "fantôme" à bypass).
    """
    if user is None:
        return False
    role = getattr(user, "role", None)
    if role is None:
        return False
    # Tolère role = enum UserRole.ADMIN ou string "admin"
    role_value = getattr(role, "value", role)
    return str(role_value).lower() == "admin"


# ---------------------------------------------------------------------------
# Loading des règles
# ---------------------------------------------------------------------------


async def _load_rules_from_db(user_id: int) -> _UserRules:
    """Lit la BDD et compile les règles en ``_UserRules``."""
    from app.core.database import get_session
    from app.models.data_access_rule import DataAccessEffect, DataAccessScope
    from app.services.data_access.repository import list_rules_for_user

    compiled = _UserRules(user_id=user_id)
    async with get_session() as session:
        rules = await list_rules_for_user(session, user_id)

    for rule in rules:
        table_up = rule.table_name.strip().upper()
        col_up = (rule.column_name or "").strip().upper() or None

        if rule.scope_type == DataAccessScope.TABLE:
            if rule.effect == DataAccessEffect.DENY:
                compiled.denied_tables.add(table_up)
            else:
                compiled.allowed_tables.add(table_up)
                compiled.has_any_allow_rule = True
        elif rule.scope_type == DataAccessScope.COLUMN:
            if col_up is None:
                # Anomalie : column scope sans column_name. Skipped, on log.
                logger.warning(
                    "data_access rule id=%s scope=column sans column_name " "— ignorée",
                    rule.id,
                )
                continue
            if rule.effect == DataAccessEffect.DENY:
                compiled.denied_columns.setdefault(table_up, set()).add(col_up)
            else:
                # Une règle "allow column" est rare (le default est allow).
                # Pour l'instant, on stocke pour future utilisation mais
                # on ne fait pas de contrôle "must be in allow list".
                compiled.has_any_allow_rule = True
        elif rule.scope_type == DataAccessScope.ROW:
            if col_up is None:
                logger.warning(
                    "data_access rule id=%s scope=row sans column_name " "— ignorée",
                    rule.id,
                )
                continue
            if not isinstance(rule.allowed_values, list) or not rule.allowed_values:
                logger.warning(
                    "data_access rule id=%s scope=row sans allowed_values " "— ignorée",
                    rule.id,
                )
                continue
            # Pour scope row, l'effet sémantique est : restreindre aux
            # valeurs listées. ``effect=allow`` est la seule lecture
            # logique. ``deny`` ici (= "interdire ces valeurs") n'est PAS
            # supporté V1 (compliquerait le composition WHERE NOT IN).
            if rule.effect == DataAccessEffect.ALLOW:
                compiled.row_filters.append((table_up, col_up, list(rule.allowed_values)))
                compiled.has_any_allow_rule = True
            else:
                logger.warning(
                    "data_access rule id=%s scope=row effect=deny non "
                    "supporté V1 — ignorée. Utilisez effect=allow + "
                    "liste des valeurs autorisées.",
                    rule.id,
                )
    return compiled


async def load_rules_for_user(user_id: int) -> _UserRules:
    """Récupère les règles compilées d'un utilisateur (cache TTL).

    En cas d'erreur de lecture BDD : retourne ``_UserRules(is_error=True)``,
    qui force ``should_filter_for=True`` côté caller (= **vrai fail-closed
    sémantique**). La réponse erreur n'est PAS cachée → la prochaine requête
    re-tentera le chargement. Le risque "60s de bypass" devient "1 requête
    de bypass" (et même celle-là est filtrée parce que ``is_error=True``).

    Bug 2026-05-26 (Agent 4 DA-C1) : avant, l'erreur retournait
    ``_UserRules()`` vide qui était cachée 60s, ce qui équivalait à
    "user sans restrictions" → bypass du mode invisible pendant 1 minute.
    Le commentaire historique parlait de "fail-closed = règles vides"
    mais c'était une inversion sémantique (vide = bypass, pas filtrage).
    """
    if user_id is None:
        return _UserRules(user_id=-1)

    now = time.monotonic()
    cached = _CACHE.get(user_id)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    async with _CACHE_LOCK:
        # Re-check après acquire (autre coroutine a peut-être chargé)
        cached = _CACHE.get(user_id)
        if cached is not None and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
            return cached[1]
        try:
            compiled = await _load_rules_from_db(user_id)
        except Exception as exc:
            logger.error(
                "data_access: load_rules_for_user(user_id=%s) failed: %s",
                user_id,
                exc,
                exc_info=True,
            )
            # P5.2 (audit 2026-05-26) — Pose une entrée ``audit_logs``
            # fire-and-forget pour donner à l'admin une métrique
            # « fail-closed events / heure » via /admin/data-access. Avant :
            # la log ERROR ci-dessus était la seule trace → invisible sans
            # grep, impossible de monter un dashboard / alerte. Maintenant :
            # ligne audit_log queryable côté observabilité.
            #
            # Fire-and-forget avec strong-ref (cf.
            # feedback_asyncio_create_task_strong_ref.md 2026-05-22) pour
            # éviter le GC silencieux Python 3.12+.
            _spawn_fail_closed_audit_log(user_id, exc)
            # Sentinel fail-closed — NE PAS cacher pour permettre retry
            # immédiat au prochain call. Le caller (should_filter_for,
            # user_has_any_active_rule) checkera ``is_error`` et fail-closed.
            return _UserRules(user_id=user_id, is_error=True)
        _CACHE[user_id] = (time.monotonic(), compiled)
        # Synchroniser le cache court-circuit Phase α : si on a payé le coût
        # de charger les règles, on peut bénéficier gratuitement de la
        # réponse pour ``user_has_any_active_rule`` jusqu'à la prochaine
        # invalidation.
        _HAS_RULES_CACHE[user_id] = (
            time.monotonic(),
            not compiled.is_empty,
        )
        return compiled


# ---------------------------------------------------------------------------
# Phase α — Court-circuit "faut-il filtrer pour cet user ?"
# ---------------------------------------------------------------------------


async def user_has_any_active_rule(user_id: Any) -> bool:
    """Réponse O(1) (cache) à la question : cet user a-t-il AU MOINS UNE
    règle ``DataAccessRule`` active ?

    **Pourquoi ce helper** : Phase α exige que TOUS les call-sites qui lisent
    le schéma (training_store, SchemaLoader, connector wrapper) passent par
    un filtre. Pour ne pas pénaliser les 95% d'utilisateurs sans restriction,
    on a besoin d'un check ultra-rapide avant de matérialiser une
    :class:`~app.services.data_access.visible_schema.UserSchemaView`.

    Cache TTL 60s (aligné sur ``load_rules_for_user``). Invalidé en cascade
    par :func:`invalidate_user` quand un admin modifie les règles.

    Comportements limites :

    - ``user_id`` None / négatif / non-int → ``False`` (pas d'identité).
    - Erreur BDD au load → ``False`` (cohérent avec le fail-closed de
      ``load_rules_for_user`` : aucune règle compilée = pas de filtre).
    - Cache miss → déclenche un ``load_rules_for_user`` qui peuple les 2
      caches simultanément.
    """
    if user_id is None:
        return False
    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        return False
    if user_id_int < 0:
        return False

    now = time.monotonic()
    cached = _HAS_RULES_CACHE.get(user_id_int)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    # Cache miss : on load les règles compilées. ``load_rules_for_user`` peut
    # aussi peupler ``_HAS_RULES_CACHE`` en interne (idempotent — dict[k]=v
    # n'est pas additif). Si quelqu'un patche ``load_rules_for_user`` dans
    # un test, on garantit quand même la mise en cache ici.
    compiled = await load_rules_for_user(user_id_int)
    # Bug 2026-05-26 (DA-C1) : sur erreur BDD, ``compiled.is_error=True``
    # → on retourne True (= "user a des règles à appliquer" du point de
    # vue de should_filter_for). Le filtre SQL et le schema-view qui
    # appellent ensuite ``_load_rules_from_db`` retomberont aussi sur
    # ``is_error`` et matérialiseront ``EMPTY_VIEW`` → vrai fail-closed.
    # NE PAS cacher la réponse erreur : on re-tente au prochain call.
    if compiled.is_error:
        return True
    has_any = not compiled.is_empty
    _HAS_RULES_CACHE[user_id_int] = (time.monotonic(), has_any)
    return has_any


async def should_filter_for(user: Any) -> bool:
    """Court-circuit O(1) consommé par les call-sites Phase α (training_store,
    SchemaLoader, connector wrapper, etc.) AVANT de matérialiser une
    :class:`~app.services.data_access.visible_schema.UserSchemaView`.

    Returns ``False`` (= ne PAS filtrer, comportement legacy) si :

    - ``user`` est ``None`` → call-site legacy non migré ou contexte hors
      requête (sync, boot, job background) ; on ne casse rien.
    - ``user`` est :data:`SYSTEM_USER` → opération système confirmée.
    - ``user`` est admin (``is_user_exempt``) → bypass admin.
    - L'enforcement global est OFF (réserve future : aujourd'hui il est
      toujours ON, mais on garde le check pour cohérence avec les autres
      helpers de ce module).
    - L'user n'a aucune règle active (cache TTL 60s).

    Returns ``True`` sinon — l'appelant doit matérialiser la
    ``UserSchemaView`` et filtrer son output.

    **Note importante** : ``user=None`` retourne ``False`` (pas de filtre).
    C'est intentionnel pour ne pas casser les call-sites pas encore migrés
    (Phase α.4 les propage progressivement). La vraie protection
    fail-closed reste l'enforcer SQL ``check_sql_access`` au moment de
    l'exécution — un schéma "trop large" exposé au LLM ne fait pas leak
    de données tant que l'enforcer bloque la SQL résultante. Filtrer le
    schéma n'est qu'une couche supplémentaire (mode invisible LLM).

    **Fail-closed sur shape invalide** : si ``user`` n'est PAS ``None``
    et n'est PAS le sentinel, mais N'A NI ``id`` NI ``role`` exploitables
    (e.g. ``user=dict``, ``user=str``, ``user=int``, ``user=<MagicMock>``
    sans attributs configurés), on retourne ``True`` (filtrer) avec un
    WARNING log. Sinon, un caller qui désérialise mal son user (JWT en
    dict, etc.) bypasserait silencieusement TOUT le mode invisible. La
    bonne contre-mesure est de filtrer "comme un anonyme" :
    ``build_user_schema_view(user)`` retournera ``EMPTY_VIEW`` →
    fail-closed naturel.
    """
    if user is None:
        return False
    if is_system_call(user):
        return False
    if not await is_enforcement_enabled():
        return False

    # Détection shape invalide : un objet User attendu a au moins ``id`` ou
    # ``role``. Si AUCUN des deux n'est défini en tant qu'attribut, c'est
    # un dict / str / type non documenté → fail-closed à True.
    _SENTINEL = object()
    has_id = getattr(user, "id", _SENTINEL) is not _SENTINEL
    has_role = getattr(user, "role", _SENTINEL) is not _SENTINEL
    if not has_id and not has_role:
        logger.warning(
            "data_access.should_filter_for: user de shape invalide "
            "(type=%s, repr=%r) — fail-closed à True (le caller passera "
            "via EMPTY_VIEW). Migrer le call-site pour propager un objet "
            "User typé.",
            type(user).__name__,
            user,
        )
        return True

    if is_user_exempt(user):
        return False
    user_id = getattr(user, "id", None)
    if user_id is None:
        # L'user a un ``role`` mais pas d'``id`` : objet partiel anormal
        # mais on l'a vu admin/non-admin via ``is_user_exempt``. Si on
        # arrive ici c'est qu'il N'est pas admin. On fail-closed à True
        # pour ne pas leaker ; le caller filtrera via EMPTY_VIEW.
        logger.warning(
            "data_access.should_filter_for: user sans 'id' (type=%s) — " "fail-closed à True.",
            type(user).__name__,
        )
        return True
    return await user_has_any_active_rule(user_id)


# ---------------------------------------------------------------------------
# SQL parsing (sqlglot)
# ---------------------------------------------------------------------------

#: Strip des hints T-SQL (``WITH (NOLOCK)`` etc.) avant parsing — sqlglot peut
#: les rejeter sur certains patterns. Aligné sur ``agent_tools._TSQL_HINT_RE``.
_TSQL_HINT_RE = re.compile(
    r"\bWITH\s*\(\s*[A-Za-z_][A-Za-z0-9_,\s]*\)",
    re.IGNORECASE,
)


#: Détecte un `SELECT *` ou `SELECT alias.*` dans la SQL (mais pas
#: `COUNT(*)`, `func(*)`). Heuristique suffisante pour bloquer les
#: bypass column-deny via wildcard. Une SQL avec `SELECT * FROM ...`
#: déclenche le fail-closed.
_SELECT_STAR_RE = re.compile(
    r"SELECT\s+(?:DISTINCT\s+)?(?:TOP\s+\d+\s+)?(?:[\w\[\]]+\.)?\*",
    re.IGNORECASE,
)


#: Détecte les patterns dynamic SQL : ``EXEC sp_executesql N'...'``,
#: ``EXEC ('SELECT...')``, ``EXECUTE ('...')``. sqlglot ne descend pas
#: dans la chaîne, donc on fail-closed quand on les voit avec règles
#: actives. Phase 6.1 finding 2026-05-18.
_DYNAMIC_EXEC_RE = re.compile(
    r"\b(?:EXEC|EXECUTE)\s*(?:\(|N?'|sp_executesql\b)",
    re.IGNORECASE,
)

#: **Phase 2.2.bis (#90)** — Patterns SQL Server **non-analysables par
#: sqlglot** qui permettent d'exécuter du SQL contre des objets ou
#: serveurs distants sans que les noms apparaissent dans l'AST :
#:
#: - ``OPENROWSET(BULK '...', ...)`` — ouvre un rowset ad-hoc depuis un
#:   fichier ou une chaîne de connexion. Le nom de table cible peut
#:   être dans une chaîne. Bypass complet de l'analyse statique.
#: - ``OPENQUERY(linked_server, 'SELECT * FROM F_SECRET')`` — exécute
#:   une SQL sur un linked server. Le SQL passé en chaîne n'est pas
#:   analysé par sqlglot.
#: - ``EXECUTE AS USER='name'`` / ``EXECUTE AS LOGIN='name'`` — change
#:   le contexte d'exécution SQL Server. Combiné avec d'autres
#:   patterns, peut bypass les checks de notre enforcer (qui se base
#:   sur le user authentifié Komptia, pas le contexte SQL Server).
#:
#: Defense-in-depth : on fail-closed dès qu'un de ces patterns est vu
#: avec règles actives, même si le SQL semble innocent (sqlglot ne
#: peut PAS prouver l'innocence).
_OPENROWSET_RE = re.compile(r"\bOPENROWSET\s*\(", re.IGNORECASE)
_OPENQUERY_RE = re.compile(r"\bOPENQUERY\s*\(", re.IGNORECASE)
#: **Phase 2.2.bis fix CRITICAL #1 review** — ``OPENDATASOURCE(...)``
#: appartient à la même famille que OPENROWSET/OPENQUERY (linked server
#: ad-hoc) et est explicitement banni partout ailleurs dans la codebase
#: (``iris_oneshot._FORBIDDEN_KEYWORDS_RE``, ``write_validator``,
#: ``drilldown``, ``sql_validator``). Oubli initial corrigé.
_OPENDATASOURCE_RE = re.compile(r"\bOPENDATASOURCE\s*\(", re.IGNORECASE)
_EXECUTE_AS_RE = re.compile(r"\bEXECUTE\s+AS\b", re.IGNORECASE)

#: **Phase 2.2.quater (#93)** — Patterns SQL Server **dangereux** au sens
#: large : ils ne sont pas du SELECT légitime sur le schéma utilisateur.
#: Un utilisateur Komptia ne devrait JAMAIS pouvoir exécuter ces
#: instructions via Iris, copilot, ou un drilldown manuel.
#:
#: - ``WAITFOR DELAY '00:00:30'`` — délai serveur (DOS time-based blind).
#: - ``WAITFOR TIME '23:59:59'`` — attente jusqu'à heure (idem DOS).
#: - ``BACKUP DATABASE ... TO DISK = '...'`` — exfiltration du dump
#:   complet de la BDD (et donc des tables/colonnes interdites).
#: - ``RESTORE DATABASE/LOG`` — écrasement de la BDD (ATAQUE).
#: - ``xp_cmdshell '...'`` — exécution shell OS via SQL Server (RCE).
#: - ``sp_OACreate/sp_OAMethod`` — OLE automation (RCE via objets COM).
#: - ``sp_executesql`` — déjà couvert par ``_DYNAMIC_EXEC_RE`` mais doublé
#:   ici en defense-in-depth (regex word boundary plus strict).
#:
#: Ces patterns sont **génériques SQL Server**, pas spécifiques aux RLS
#: data_access. Mais leur présence dans une SQL user-facing est une
#: anomalie qui doit fail-closed pour éviter tout bypass de l'enforcer
#: ou DoS du serveur.
_WAITFOR_RE = re.compile(r"\bWAITFOR\s+(?:DELAY|TIME)\b", re.IGNORECASE)
_BACKUP_RE = re.compile(r"\bBACKUP\s+(?:DATABASE|LOG|CERTIFICATE)\b", re.IGNORECASE)
_RESTORE_RE = re.compile(
    r"\bRESTORE\s+(?:DATABASE|LOG|FILELISTONLY|HEADERONLY|VERIFYONLY)\b", re.IGNORECASE
)
_XP_CMDSHELL_RE = re.compile(r"\bxp_cmdshell\b", re.IGNORECASE)
_OLE_AUTOMATION_RE = re.compile(
    r"\bsp_OA(?:Create|Method|GetProperty|SetProperty|Destroy|Stop|GetErrorInfo)\b", re.IGNORECASE
)

#: **Phase 2.2.quater fix BLOCKING adversarial review** — Patterns
#: supplémentaires identifiés par la review du bundle hardening :
#:
#: - ``BULK INSERT F_X FROM 'share.csv'`` — lit un fichier réseau et
#:   insère dans une table : peut être combiné avec un nom de fichier
#:   contrôlé pour exfiltration.
#: - ``OPEN SYMMETRIC KEY / OPEN MASTER KEY`` — déchiffrement de
#:   credentials Sage stockés chiffrés dans la BDD.
#: - ``DBCC SHOW_STATISTICS / DBCC ...`` — commandes admin SQL Server.
#:   ``SHOW_STATISTICS`` peut fuir des distributions de colonnes denied.
#: - ``KILL <spid>`` — termine une session SQL Server (DoS sur d'autres
#:   users).
#: - ``GRANT/REVOKE/DENY`` (sur objets SQL Server) — escalation de
#:   privilèges SQL Server contournant l'enforcer Komptia.
#: - ``RECONFIGURE`` — confirme un changement ``sp_configure``,
#:   typiquement pour activer ``xp_cmdshell``.
_BULK_INSERT_RE = re.compile(r"\bBULK\s+INSERT\b", re.IGNORECASE)
_OPEN_KEY_RE = re.compile(r"\bOPEN\s+(?:SYMMETRIC|MASTER)\s+KEY\b", re.IGNORECASE)
_DBCC_RE = re.compile(r"\bDBCC\s+[A-Z_]+", re.IGNORECASE)
_KILL_RE = re.compile(r"\bKILL\s+(?:\d+|@\w+)\b", re.IGNORECASE)
_GRANT_REVOKE_DENY_RE = re.compile(
    r"\b(?:GRANT|REVOKE|DENY)\s+(?:SELECT|INSERT|UPDATE|DELETE|EXECUTE|CONTROL|ALTER|ALL)\b",
    re.IGNORECASE,
)
_RECONFIGURE_RE = re.compile(r"\bRECONFIGURE\b", re.IGNORECASE)


def _sql_is_dangerous_universal(sql: str) -> bool:
    """**Phase 2.2.quinquies (#94)** — True si la SQL contient un
    pattern dangereux SQL Server **universel** (toujours risqué,
    quelle que soit la configuration RLS).

    Couvre les patterns qui sont :

    - **RCE** (Remote Code Execution) — ``xp_cmdshell``, ``sp_OACreate``
      / ``sp_OAMethod`` (OLE Automation).
    - **Exfiltration** — ``BACKUP DATABASE/LOG``, ``BULK INSERT`` depuis
      un share réseau.
    - **Écrasement** — ``RESTORE DATABASE/LOG``.
    - **Decryption** — ``OPEN SYMMETRIC/MASTER KEY``.
    - **DoS** — ``WAITFOR DELAY/TIME``, ``KILL <spid>``.
    - **Escalation privileges SQL Server** — ``GRANT/REVOKE/DENY`` (les
      perms accordées ici contournent l'enforcer Komptia côté DB).
    - **Reconfiguration** — ``RECONFIGURE`` (typiquement après
      ``sp_configure 'xp_cmdshell', 1``).
    - **Diagnostics admin** — ``DBCC`` (``SHOW_STATISTICS`` peut fuir
      des distributions de colonnes interdites).

    **Distinction avec :func:`_sql_uses_dynamic_exec`** : cette fonction
    couvre les patterns RLS-dynamic (``OPENROWSET``, ``EXECUTE AS``,
    ``sp_executesql``) qui ne sont pas analysables statiquement et
    contournent uniquement le RLS Komptia. ``_sql_is_dangerous_universal``
    couvre les patterns qui sont dangereux **indépendamment de l'enforcer
    Komptia** — ils ne devraient JAMAIS apparaître dans une SQL légitime
    générée par Iris/copilot/analyse.

    Strip-then-scan pour empêcher le bypass via commentaires inline.
    """
    if not isinstance(sql, str):
        return False
    cleaned = _strip_for_parse(sql)
    return (
        # RCE
        _XP_CMDSHELL_RE.search(cleaned) is not None
        or _OLE_AUTOMATION_RE.search(cleaned) is not None
        # Exfiltration / écrasement
        or _BACKUP_RE.search(cleaned) is not None
        or _RESTORE_RE.search(cleaned) is not None
        or _BULK_INSERT_RE.search(cleaned) is not None
        # Decryption
        or _OPEN_KEY_RE.search(cleaned) is not None
        # DoS
        or _WAITFOR_RE.search(cleaned) is not None
        or _KILL_RE.search(cleaned) is not None
        # Escalation SQL Server
        or _GRANT_REVOKE_DENY_RE.search(cleaned) is not None
        # Reconfiguration
        or _RECONFIGURE_RE.search(cleaned) is not None
        # Diagnostics admin
        or _DBCC_RE.search(cleaned) is not None
    )


def _sql_uses_dynamic_exec(sql: str) -> bool:
    """True si la SQL utilise un pattern **non-analysable statiquement**
    qui contournerait l'enforcer RLS Komptia.

    Couvre (Phase 6.1 + 2.2.bis + fixes review) :

    1. ``EXEC`` / ``EXECUTE`` avec chaîne dynamique
       (``sp_executesql`` ou ``EXEC ('...')``)
    2. ``OPENROWSET(...)`` (linked server / fichier ad-hoc)
    3. ``OPENQUERY(linked_server, '...')`` (SQL sur linked server)
    4. ``OPENDATASOURCE(...)`` (linked server ad-hoc, cousin
       d'OPENROWSET)
    5. ``EXECUTE AS USER/LOGIN/CALLER`` (changement de contexte SQL
       Server qui contourne notre enforcer applicatif)

    **Phase 2.2.quinquies (#94) — Découplage** : les patterns RCE/
    exfiltration/DoS/escalation/etc. **migrés** vers
    :func:`_sql_is_dangerous_universal` qui les bloque pour TOUS les
    users (même sans règle RLS). Cette fonction se concentre uniquement
    sur les bypass RLS — patterns qui permettent de référencer une
    table denied via une chaîne masquant le nom à sqlglot.

    **Phase 2.2.bis fix BLOCKING review** : strip-then-scan empêche
    le bypass via commentaires inline (``EXECUTE/*x*/AS USER='x'``).

    Garde defense-in-depth : ces patterns ne sont pas analysables
    statiquement par sqlglot — on fail-closed plutôt que de risquer
    un bypass via une chaîne masquant un nom de table interdit ou un
    changement de contexte qui contournerait l'enforcer.
    """
    if not isinstance(sql, str):
        return False
    # Strip-then-scan : empêche le bypass via commentaires inline
    cleaned = _strip_for_parse(sql)
    return (
        _DYNAMIC_EXEC_RE.search(cleaned) is not None
        or _OPENROWSET_RE.search(cleaned) is not None
        or _OPENQUERY_RE.search(cleaned) is not None
        or _OPENDATASOURCE_RE.search(cleaned) is not None
        or _EXECUTE_AS_RE.search(cleaned) is not None
    )


def _sql_uses_wildcard(sql: str) -> bool:
    """True si la SQL contient un `SELECT *` ou `SELECT alias.*`.

    Faux positif possible : un commentaire SQL `-- SELECT * FROM...`. On
    accepte ce risque car il déclenche un fail-closed (refus) — le pire
    cas est un message d'erreur pour l'user, pas un leak.
    """
    if not isinstance(sql, str):
        return False
    return _SELECT_STAR_RE.search(sql) is not None


def _strip_for_parse(sql: str) -> str:
    """Retire commentaires + hints avant parsing sqlglot.

    **Phase 2.2.bis fix BLOCKING** : on remplace les commentaires par un
    ESPACE au lieu de les supprimer purement. Sans ce changement, un
    attaquant pouvait écrire ``EXECUTE/*x*/AS USER='admin'`` qui devenait
    après strip ``EXECUTEAS USER='admin'`` (les deux tokens collés) — le
    regex ``\\bEXECUTE\\s+AS\\b`` ne matchait alors plus. Avec le
    remplacement par espace, le strip produit ``EXECUTE AS USER='admin'``
    qui est correctement détecté par le guard dynamic-SQL.

    sqlglot lui-même tolère des espaces additionnels sans changement
    d'AST (whitespace-insensitive sur les tokens), donc le parse n'est
    pas affecté.
    """
    if not isinstance(sql, str):
        return ""
    cleaned = sql
    try:
        cleaned = _TSQL_HINT_RE.sub(" ", cleaned)
        cleaned = re.sub(r"--[^\n]*", " ", cleaned)
        cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)
    except re.error:
        return sql
    return cleaned


def extract_shadow_names(sql: str) -> Set[str]:
    """Extrait tous les **noms d'alias** déclarés dans une SQL pouvant
    masquer un identifiant — CTE ET subqueries aliasées.

    **Phase 2.2.ter (#92) + fix BLOCKING review** — Le shadowing peut
    s'opérer de plusieurs façons en SQL Server, pas seulement via CTE.
    Tous ces patterns retournent un identifiant local qui prend le pas
    sur une table physique du même nom :

    1. **CTE** (``WITH F_SECRET AS (...) SELECT * FROM F_SECRET``)
       sqlglot crée un ``exp.CTE`` avec ``alias_or_name="F_SECRET"``.
    2. **Subquery FROM** (``SELECT * FROM (SELECT 1) AS F_SECRET``)
       sqlglot crée un ``exp.Subquery`` (pas une Table) avec
       ``alias_or_name="F_SECRET"`` — invisible des
       ``find_all(exp.Table)``.
    3. **Subquery JOIN** (``FROM F_OK JOIN (SELECT 1) F_SECRET ON ...``)
       idem ``exp.Subquery`` avec alias dans le contexte JOIN.

    Sans cette extension, un user contournait trivialement une règle
    ``deny F_SECRET`` en réécrivant son CTE en subquery aliasée. Le
    BLOCKING identifié par l'adversarial review Phase 2.2.ter.

    Retourne un set UPPERCASE des **noms d'alias** trouvés. Si sqlglot
    échoue : ``set()`` — caller doit traiter comme "pas de shadow
    détecté" (fail-open ici car le parse aura échoué en amont dans
    :func:`check_sql_access`, qui fail-closed sur parse failure +
    règles actives).
    """
    if not sql or not isinstance(sql, str):
        return set()

    cleaned = _strip_for_parse(sql)
    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        return set()

    try:
        parsed = sqlglot.parse_one(cleaned, dialect="tsql")
    except Exception:
        return set()
    if parsed is None:
        return set()

    shadow_names: Set[str] = set()
    try:
        # CTE (WITH alias AS ...)
        for cte in parsed.find_all(exp.CTE):
            alias = getattr(cte, "alias_or_name", None)
            if alias:
                shadow_names.add(alias.upper())
        # Subquery aliasée (FROM (SELECT...) AS alias, JOIN (...) alias)
        for sq in parsed.find_all(exp.Subquery):
            alias = getattr(sq, "alias_or_name", None)
            if alias:
                shadow_names.add(alias.upper())
    except Exception as exc:
        logger.warning("extract_shadow_names: walk failed: %s", exc)

    return shadow_names


# Alias de rétro-compat : ancienne API publique de Phase 2.2.ter v1.
# Le seul caller historique (check_sql_access) consomme désormais
# `extract_shadow_names`. Si du code externe importe encore
# `extract_cte_names`, il reçoit la version étendue (sur-ensemble).
extract_cte_names = extract_shadow_names


def extract_tables_and_columns(
    sql: str,
) -> Tuple[Set[str], Dict[str, Set[str]]]:
    """Extrait les tables et colonnes RÉFÉRENCÉES par une SQL.

    Retourne ``(tables_uppercased, {table_up: {col_up, ...}})``.

    - Les **CTE** sont exclues du set "tables" (ce sont des aliases internes,
      pas des tables physiques).
    - Les **alias** sont résolus côté table (``F_TABLE AS t1`` → ``F_TABLE``).
    - Les **colonnes** avec préfixe table (``t1.col``) sont attribuées à la
      bonne table via résolution d'alias quand possible. Sans préfixe,
      attribuées à ``"*"`` (table inconnue).
    - **Fail-closed** : si sqlglot échoue ou n'est pas dispo, on retourne
      ``(set(), {})`` — l'appelant doit traiter ça comme "rien d'extrait"
      et **refuser la SQL** (fail-closed). C'est le contrat.
    """
    if not sql or not isinstance(sql, str):
        return set(), {}

    cleaned = _strip_for_parse(sql)
    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        logger.error("data_access: sqlglot unavailable, fail-closed.")
        return set(), {}

    try:
        parsed = sqlglot.parse_one(cleaned, dialect="tsql")
    except Exception as exc:
        logger.warning("data_access: sqlglot parse failed: %s", exc)
        return set(), {}
    if parsed is None:
        return set(), {}

    # Indexer les CTE (à exclure du set tables)
    cte_names: Set[str] = set()
    try:
        for cte in parsed.find_all(exp.CTE):
            alias = getattr(cte, "alias_or_name", None)
            if alias:
                cte_names.add(alias.upper())
    except Exception:
        pass

    # Indexer alias → vraie table
    # ``alias_up: table_up``
    alias_to_table: Dict[str, str] = {}
    real_tables: Set[str] = set()
    try:
        for tbl in parsed.find_all(exp.Table):
            name = (getattr(tbl, "name", None) or "").strip()
            if not name:
                continue
            name_up = name.upper()
            if name_up in cte_names:
                continue
            real_tables.add(name_up)
            alias = getattr(tbl, "alias_or_name", None)
            if alias:
                alias_up = alias.upper()
                # Le ``alias_or_name`` retourne le nom si pas d'alias —
                # on stocke quand même pour les références ``T.col`` non aliasées.
                alias_to_table.setdefault(alias_up, name_up)
    except Exception as exc:
        logger.warning("data_access: alias indexing failed: %s", exc)

    # Indexer colonnes
    cols_by_table: Dict[str, Set[str]] = {}
    try:
        for col in parsed.find_all(exp.Column):
            col_name = (getattr(col, "name", None) or "").strip()
            if not col_name or col_name == "*":
                continue
            col_up = col_name.upper()
            tbl_prefix = (getattr(col, "table", None) or "").strip()
            if tbl_prefix:
                tbl_up = tbl_prefix.upper()
                # Résoudre alias si présent
                resolved = alias_to_table.get(tbl_up, tbl_up)
                if resolved in cte_names:
                    continue
                cols_by_table.setdefault(resolved, set()).add(col_up)
            else:
                # Colonne sans préfixe : on ne sait pas à quelle table elle
                # appartient. Stockée sous "*" pour usage informatif.
                cols_by_table.setdefault("*", set()).add(col_up)
    except Exception as exc:
        logger.warning("data_access: column indexing failed: %s", exc)

    return real_tables, cols_by_table


# ---------------------------------------------------------------------------
# Public : check_sql_access
# ---------------------------------------------------------------------------


def _build_user_message(table: str, column: Optional[str]) -> str:
    """Construit le message générique retourné au user pour un refus
    table/colonne.

    **Mode invisible** : ne mentionne JAMAIS le nom réel de la table ou
    de la colonne. Le nom réel reste dans ``AccessDecision.blocking_table``/
    ``blocking_column`` pour le debug admin et pour le garde-fou pré-LLM
    (cf. Phase 3.3), mais le message-utilisateur est ambigu.

    Les args ``table``/``column`` sont conservés en signature pour les
    callers historiques mais ne sont **pas** insérés dans le message.
    """
    from app.services.data_access.error_messages import (
        GenericMessageKind,
        make_generic_message,
    )

    kind = GenericMessageKind.COLUMN_NOT_VISIBLE if column else GenericMessageKind.TABLE_NOT_VISIBLE
    return make_generic_message(kind)


async def check_sql_access(sql: str, user: Any) -> AccessDecision:
    """Vérifie qu'un user a le droit d'exécuter ``sql``.

    Retourne :

    - :data:`_ALLOWED_DECISION` si tout est OK ou si enforcement off ou si
      user est admin.
    - :class:`AccessDecision` ``allowed=False`` avec ``user_message`` clair
      si une table ou colonne interdite est référencée.

    Cas particulier "fail-closed sur parse failure" : si sqlglot ne parvient
    pas à extraire les tables/colonnes ET que l'user a au moins une règle
    ``deny``, on **refuse** par sécurité. Sans aucune règle deny, on laisse
    passer (sinon on casserait toute SQL exotique pour un user non
    contraint).
    """
    if not await is_enforcement_enabled():
        return _ALLOWED_DECISION

    # **Phase 2.2.quinquies (#94) — Garde universelle AVANT le bypass admin.**
    # Les patterns dangereux universels (xp_cmdshell, BACKUP, BULK INSERT,
    # GRANT/REVOKE, OPEN KEY, WAITFOR, KILL, DBCC, RECONFIGURE, OLE
    # Automation) ne devraient JAMAIS apparaître dans une SQL légitime
    # générée par Iris/copilot/analyse, **même pour un admin**. Bloquer
    # ces patterns au plus tôt :
    #
    # - **RCE** via xp_cmdshell / sp_OA* est indépendant de l'enforcer
    #   RLS — c'est un risque OS direct.
    # - **Exfiltration** via BACKUP DATABASE bypass aussi le RLS car le
    #   dump file contient TOUTES les tables, denied incluses.
    # - **Escalation** via GRANT côté SQL Server permet à l'attaquant de
    #   gagner des perms qui survivent à notre check applicatif.
    #
    # Décision UX : on retourne un message générique « commande non
    # autorisée » sans mentionner le pattern exact (defense-in-depth
    # contre l'oracle d'information).
    if _sql_is_dangerous_universal(sql):
        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        logger.warning(
            "check_sql_access: SQL dangereux universel refusé "
            "user_id=%s (xp_cmdshell/BACKUP/GRANT/etc.)",
            getattr(user, "id", None),
        )
        return AccessDecision(
            allowed=False,
            reason="SQL contient un pattern universellement dangereux (RCE/exfiltration/escalation)",
            user_message=make_generic_message(GenericMessageKind.UNPARSEABLE_SQL),
        )

    if is_user_exempt(user):
        return _ALLOWED_DECISION

    user_id = getattr(user, "id", None)
    if user_id is None:
        # Anonyme dans un path qui devrait être authentifié — fail-closed.
        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        return AccessDecision(
            allowed=False,
            reason="user anonyme dans path authentifié",
            user_message=make_generic_message(GenericMessageKind.AUTH_REQUIRED),
        )

    rules = await load_rules_for_user(user_id)
    if rules.is_error:
        # Bug 2026-05-26 (DA-C1) : erreur BDD au chargement des règles —
        # fail-closed strict. On ne sait pas si l'user a des restrictions
        # ou non → on refuse l'accès SQL (équivalent EMPTY_VIEW). À la
        # prochaine requête (cache non posé), on re-tentera le chargement.
        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        logger.warning(
            "check_sql_access: fail-closed user_id=%s (load_rules_for_user "
            "a échoué — BDD locked ou corrompue). Le SQL est refusé jusqu'à "
            "ce qu'un read réussi mette le cache à jour.",
            getattr(user, "id", None),
        )
        return AccessDecision(
            allowed=False,
            reason="Erreur de chargement des règles d'accès (fail-closed). Retry.",
            user_message=make_generic_message(GenericMessageKind.UNPARSEABLE_SQL),
        )

    if rules.is_empty:
        # Aucune règle configurée → on laisse passer (admin a choisi de ne
        # pas restreindre cet user). C'est différent du "fail-closed total"
        # qui casserait la migration.
        return _ALLOWED_DECISION

    # Phase 2.2 (#45) — Charger la ``UserSchemaView`` pour bénéficier de
    # la closure transitive (Phase 2.1). Si l'admin pose ``deny F_SALAIRES``,
    # ``view.denied_tables_with_closure`` inclut aussi ``V_SALAIRES_RECAP``
    # (la vue qui dépend de F_SALAIRES). Sans cette étape, l'enforcer SQL
    # ne saurait pas bloquer la requête sur la vue dérivée — contournement
    # silencieux du mode invisible.
    #
    # **Stratégie d'UNION (fix BLOCKING review Phase 2.2)** :
    # ``effective_denied = rules.denied_tables ∪ view.denied_tables_with_closure``.
    # Un ternaire « view si non-vide, sinon rules » serait vulnérable à une
    # désynchronisation transitoire entre ``_CACHE`` et ``_VIEW_CACHE``
    # pendant ``invalidate_user`` : l'ordre d'invalidation est
    # ``_HAS_RULES_CACHE → _VIEW_CACHE → _CACHE``, donc entre les étapes 2
    # et 3 une coroutine peut hit ``_CACHE`` OLD et construire une view
    # avec une closure stale qui ne contient pas la nouvelle règle. En
    # prenant l'UNION, on a la garantie que **toute table atomique
    # ``rules.denied_tables`` reste bloquée**, quelle que soit la
    # fraîcheur de la view. La closure est un BONUS additif, pas un
    # remplacement.
    #
    # **Fail-soft** : si le build de la view lève (BDD lente, schéma
    # corrompu), on garde ``rules.denied_tables`` seul (closure dégradée
    # mais Komptia continue de bloquer les atomiques).
    try:
        from app.services.data_access.visible_schema import build_user_schema_view

        view = await build_user_schema_view(user)
        effective_denied: Set[str] = set(rules.denied_tables) | set(view.denied_tables_with_closure)
    except Exception as exc:
        logger.warning(
            "check_sql_access: build_user_schema_view failed for user_id=%s, "
            "fallback sur rules.denied_tables (closure dégradée): %s",
            user_id,
            exc,
        )
        effective_denied = set(rules.denied_tables)

    # ── Garde anti-dynamic SQL (Phase 6.1 finding) ──
    # ``EXEC sp_executesql N'SELECT ...'`` ou ``EXEC ('...')`` permettent
    # d'exécuter du SQL dont les tables référencées sont dans une chaîne
    # — sqlglot ne descend pas dans la chaîne, donc ``extract_tables``
    # rate les références. Un user avec règles actives pourrait alors
    # contourner le check via ``EXEC N'SELECT * FROM F_INTERDITE'``.
    # Fail-closed : si la SQL contient un pattern dynamic, on refuse.
    if _sql_uses_dynamic_exec(sql):
        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        return AccessDecision(
            allowed=False,
            reason="EXEC dynamic SQL non analysable avec règles actives",
            user_message=make_generic_message(GenericMessageKind.UNPARSEABLE_SQL),
        )

    real_tables, cols_by_table = extract_tables_and_columns(sql)

    # ── Phase 2.2.ter (#92) — Garde anti-shadowing (CTE + subquery) ──
    # Un user peut tenter de bypass ``deny F_SALAIRES`` via plusieurs
    # patterns équivalents :
    #
    #   1. CTE : ``WITH F_SALAIRES AS (SELECT 1) SELECT * FROM F_SALAIRES``
    #   2. Subquery FROM : ``SELECT * FROM (SELECT 1) AS F_SALAIRES``
    #   3. Subquery JOIN : ``FROM F_OK JOIN (SELECT 1) F_SALAIRES ON ...``
    #
    # Dans tous les cas, l'identifiant local prend le pas sur la table
    # physique : ``extract_tables_and_columns`` exclut F_SALAIRES de
    # ``real_tables`` (résolu vers l'alias local). Sans ce check, le
    # check denied_tables atomique passe → bypass.
    #
    # Fix BLOCKING review : ``extract_shadow_names`` couvre CTE ET
    # subquery aliasée. Fail-closed dès qu'un alias porte le nom d'un
    # objet dans ``effective_denied`` (atomique OU closure transitive).
    shadow_names = extract_shadow_names(sql)
    if shadow_names:
        shadowed = shadow_names & effective_denied
        if shadowed:
            from app.services.data_access.error_messages import (
                GenericMessageKind,
                make_generic_message,
            )

            blocking_name = sorted(shadowed)[0]
            return AccessDecision(
                allowed=False,
                reason=(f"alias '{blocking_name}' shadow un objet interdit " "(CTE ou subquery)"),
                user_message=make_generic_message(GenericMessageKind.TABLE_NOT_VISIBLE),
                blocking_table=blocking_name,
            )

    # Cas pathologique : pas d'extraction (parse failed) ET règles
    # actives → on bloque par prudence (fail-closed).
    # Inclut row_filters : un user qui n'a QUE des row_filters voit
    # apply_row_filters fail-open sur parse failure, donc check_sql_access
    # DOIT bloquer ici sinon la SQL part SANS filtre vers Sage.
    if not real_tables and (rules.denied_tables or rules.denied_columns or rules.row_filters):
        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        return AccessDecision(
            allowed=False,
            reason="parse SQL impossible avec règles d'accès actives",
            user_message=make_generic_message(GenericMessageKind.UNPARSEABLE_SQL),
        )

    # Garde anti-`SELECT *` quand user a des denied_columns sur une des
    # tables concernées : le `*` court-circuite la résolution colonne par
    # colonne et permet de récupérer une colonne deny via wildcard.
    # Détection basique mais suffisante : présence de "*" dans la SQL +
    # au moins une table avec column-deny dans le scope.
    if rules.denied_columns and _sql_uses_wildcard(sql):
        for table_up in real_tables:
            if table_up in rules.denied_columns:
                blocking_col = sorted(rules.denied_columns[table_up])[0]
                from app.services.data_access.error_messages import (
                    GenericMessageKind,
                    make_generic_message,
                )

                return AccessDecision(
                    allowed=False,
                    reason=(f"SELECT * sur {table_up} avec column-deny actif " f"({blocking_col})"),
                    user_message=make_generic_message(GenericMessageKind.WILDCARD_BLOCKED),
                    blocking_table=table_up,
                    blocking_column=blocking_col,
                )

    # Vérification table-level deny (Phase 2.2 : consomme la closure
    # transitive via ``effective_denied`` calculée ci-dessus).
    for table_up in real_tables:
        if table_up in effective_denied:
            return AccessDecision(
                allowed=False,
                reason=f"table {table_up} dans denied_tables (closure)",
                user_message=_build_user_message(table_up, None),
                blocking_table=table_up,
            )

    # Vérification table-level allow-list (si l'user a configuré au moins
    # une allow rule de scope=table → liste blanche stricte sur les tables
    # avec règle. Les tables sans règle restent autorisées par défaut.)
    # NOTE V1 : on ne fait PAS de "deny par défaut sur les tables non
    # listées" car ça casse trop de cas. On reste compositionnel : seules
    # les règles explicites s'appliquent.

    # Vérification column-level deny
    for table_up, cols in cols_by_table.items():
        if table_up == "*":
            continue  # colonnes sans préfixe, ignorées (info incomplète)
        denied_cols = rules.denied_columns.get(table_up)
        if not denied_cols:
            continue
        intersect = cols & denied_cols
        if intersect:
            blocking_col = sorted(intersect)[0]
            return AccessDecision(
                allowed=False,
                reason=(f"colonne {table_up}.{blocking_col} dans denied_columns"),
                user_message=_build_user_message(table_up, blocking_col),
                blocking_table=table_up,
                blocking_column=blocking_col,
            )

    # Cas "colonne sans préfixe" mais une seule table dans la SQL :
    # on peut alors résoudre le préfixe implicitement.
    if "*" in cols_by_table and len(real_tables) == 1:
        only_table = next(iter(real_tables))
        denied_cols = rules.denied_columns.get(only_table)
        if denied_cols:
            unprefixed = cols_by_table["*"]
            intersect = unprefixed & denied_cols
            if intersect:
                blocking_col = sorted(intersect)[0]
                return AccessDecision(
                    allowed=False,
                    reason=(
                        f"colonne {only_table}.{blocking_col} (sans préfixe) "
                        f"dans denied_columns"
                    ),
                    user_message=_build_user_message(only_table, blocking_col),
                    blocking_table=only_table,
                    blocking_column=blocking_col,
                )

    return _ALLOWED_DECISION


# ---------------------------------------------------------------------------
# Public : apply_row_filters
# ---------------------------------------------------------------------------


async def apply_row_filters(sql: str, user: Any) -> str:
    """Injecte les filtres ``WHERE col IN (...)`` configurés pour l'user.

    Pour chaque tuple ``(table_up, col_up, allowed_values)`` dans les
    row_filters, et pour chaque ``SELECT`` qui référence cette table dans
    sa clause FROM ou ses JOINs, ajoute la condition à la clause WHERE
    (composée en ``AND`` si WHERE existant).

    Si sqlglot échoue → retourne la SQL inchangée (fail-open ici, car
    ``check_sql_access`` aura déjà refusé sur parse failure si nécessaire).

    Retourne la SQL transformée. Idempotent si appelé deux fois (la
    condition est ajoutée à chaque appel — donc à éviter — mais
    sémantiquement équivalente).
    """
    if not await is_enforcement_enabled():
        return sql
    if is_user_exempt(user):
        return sql
    user_id = getattr(user, "id", None)
    if user_id is None:
        return sql
    rules = await load_rules_for_user(user_id)
    if not rules.row_filters:
        return sql

    # **Phase 2.3 (#46) — Décision documentée : ``apply_row_filters`` ne
    # consomme PAS ``UserSchemaView.row_filters``.** On garde
    # ``rules.row_filters`` (tuple direct depuis ``_UserRules``) comme
    # source unique pour ce call-site.
    #
    # **Pourquoi** :
    #
    # 1. La closure transitive ne s'applique pas aux row_filters par
    #    contrat (un filtre métier ``F_DOSSIER.CODE IN (...)`` ne se
    #    propage PAS aux vues qui référencent F_DOSSIER). Donc
    #    ``view.row_filters`` ≡ projection typée de ``rules.row_filters``
    #    sans extension. Aucun gain sécurité à passer par la view.
    #
    # 2. Réintroduire le pattern « ternaire view-ou-rules » créerait
    #    EXACTEMENT le bug BLOCKING que la Phase 2.2 review a identifié
    #    pour ``check_sql_access`` (cf. ``feedback_invisible_mode_patterns.md``
    #    et test ``test_check_access_union_not_replacement_protects_against_stale_closure``).
    #    Et pour row_filters, l'UNION défensive est ambiguë : si rules a
    #    ``(F_T, COL, [D1])`` et view a ``(F_T, COL, [D1, D2])``, on
    #    devrait prendre quoi (intersection ? union ? plus récent ?).
    #    Trop de surface d'attaque sans bénéfice clair.
    #
    # 3. ``rules.row_filters`` est la source FRESH par contrat
    #    invalidate-after-commit (cf. doc ``invalidate_user``). Tout
    #    consumer qui veut la version la plus récente lit ``rules``.
    #
    # **Conséquence** : ``apply_row_filters`` et ``check_sql_access``
    # consomment des sources différentes (rules vs view.denied_tables_with_closure)
    # — c'est intentionnel. ``check_sql_access`` a besoin de la closure
    # pour bloquer les vues dérivées ; ``apply_row_filters`` n'en a pas
    # besoin (filtres atomiques).
    effective_row_filters = rules.row_filters

    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        logger.error("data_access: sqlglot unavailable, row filters skipped.")
        return sql

    cleaned = _strip_for_parse(sql)
    try:
        parsed = sqlglot.parse_one(cleaned, dialect="tsql")
    except Exception as exc:
        logger.warning(
            "data_access: parse failed for row_filters, sql unchanged: %s",
            exc,
        )
        return sql
    if parsed is None:
        return sql

    # CTE names (à exclure : on ne peut pas filtrer sur l'aliasing CTE,
    # le CTE est censé déjà filtrer)
    cte_names: Set[str] = set()
    try:
        for cte in parsed.find_all(exp.CTE):
            alias = getattr(cte, "alias_or_name", None)
            if alias:
                cte_names.add(alias.upper())
    except Exception:
        pass

    # Pour chaque SELECT, regarder ses tables (FROM + JOINs DIRECTS).
    # Si une table touchée a un row_filter, ajouter la condition au WHERE.
    try:
        for select in parsed.find_all(exp.Select):
            tables_in_scope: Dict[str, str] = {}  # alias_up: table_up
            from_clause = select.args.get("from") or select.args.get("from_")
            if from_clause is not None:
                tbl = from_clause.this
                if isinstance(tbl, exp.Table):
                    name = (getattr(tbl, "name", None) or "").upper()
                    if name and name not in cte_names:
                        alias = (getattr(tbl, "alias_or_name", None) or name).upper()
                        tables_in_scope[alias] = name
            for join in select.args.get("joins") or []:
                tbl = getattr(join, "this", None)
                if isinstance(tbl, exp.Table):
                    name = (getattr(tbl, "name", None) or "").upper()
                    if name and name not in cte_names:
                        alias = (getattr(tbl, "alias_or_name", None) or name).upper()
                        tables_in_scope[alias] = name

            # Pour chaque row_filter, voir s'il s'applique à une des tables
            # in scope. Si oui, construire et ajouter la condition POUR
            # CHAQUE alias matchant (self-join : FROM T a JOIN T b ON ...
            # → la condition doit être appliquée à `a` ET à `b` sinon
            # l'un des deux côtés du JOIN reste non-filtré).
            # Phase 2.3 (#46) — consomme ``effective_row_filters`` (issus
            # de la view ou fallback rules) au lieu de ``rules.row_filters``
            # direct.
            for table_up, col_up, allowed_values in effective_row_filters:
                # Re-validation defense-in-depth : si la liste a été
                # corrompue/vidée entre le load et l'application,
                # ne PAS injecter une condition `IN ()` invalide.
                if not allowed_values:
                    logger.warning(
                        "data_access: row_filter avec allowed_values vide "
                        "ignoré (user=%s table=%s col=%s)",
                        user_id,
                        table_up,
                        col_up,
                    )
                    continue
                # Trouver TOUS les aliases qui pointent vers cette table.
                aliases_to_filter = [
                    alias for alias, real in tables_in_scope.items() if real == table_up
                ]
                if not aliases_to_filter:
                    continue  # cette table n'est pas dans ce SELECT
                value_nodes = [
                    (
                        exp.Literal.string(str(v))
                        if isinstance(v, str)
                        else (
                            exp.Literal.number(v)
                            if isinstance(v, (int, float)) and not isinstance(v, bool)
                            else exp.Literal.string(str(v))
                        )
                    )
                    for v in allowed_values
                ]
                for alias_to_use in aliases_to_filter:
                    column_node = exp.Column(
                        this=exp.to_identifier(col_up),
                        table=exp.to_identifier(alias_to_use),
                    )
                    in_expr = exp.In(this=column_node, expressions=list(value_nodes))
                    existing_where = select.args.get("where")
                    if existing_where is None:
                        select.set("where", exp.Where(this=in_expr))
                    else:
                        composed = exp.And(this=existing_where.this, expression=in_expr)
                        existing_where.set("this", composed)
                    logger.debug(
                        "data_access: row filter injected user=%s "
                        "table=%s col=%s alias=%s values=%d",
                        user_id,
                        table_up,
                        col_up,
                        alias_to_use,
                        len(allowed_values),
                    )
    except _RowFilterError:
        raise
    except Exception as exc:
        # Si l'injection AST échoue alors qu'on devait poser un row filter,
        # on remonte l'erreur — le caller (``enforce_sql``) doit refuser
        # plutôt que d'exécuter une SQL non filtrée. Fail-closed.
        logger.warning(
            "data_access: row filter injection raised (will deny query): %s",
            exc,
            exc_info=True,
        )
        raise _RowFilterError("Échec de l'application des filtres d'accès à la requête.") from exc

    try:
        return parsed.sql(dialect="tsql")
    except Exception as exc:
        # Le rendering du SQL transformé échoue → on ne peut pas exécuter
        # la SQL filtrée, et on REFUSE de retourner la SQL originale (qui
        # serait un bypass silencieux du row filter). Fail-closed.
        logger.warning(
            "data_access: rendering transformed SQL failed (will deny query): %s",
            exc,
        )
        raise _RowFilterError(
            "Échec de la transformation de la requête pour appliquer les " "filtres d'accès."
        ) from exc


class _RowFilterError(Exception):
    """Erreur interne d'injection des row filters — caught par
    ``enforce_sql`` pour produire une AccessDecision denied."""


# ---------------------------------------------------------------------------
# Combiné : enforce_sql
# ---------------------------------------------------------------------------


async def enforce_sql(sql: str, user: Any) -> Tuple[str, AccessDecision]:
    """Combine ``check_sql_access`` + ``apply_row_filters``.

    Returns :
        (transformed_sql, decision)

    Si decision.is_denied, la SQL n'est pas transformée — l'appelant doit
    refuser l'exécution avec ``decision.user_message``.

    Si ``apply_row_filters`` échoue (parse / rendering AST) alors qu'un
    row_filter devait être appliqué, on retourne une **decision denied**
    — JAMAIS une SQL non filtrée. C'est le contrat fail-closed.
    """
    decision = await check_sql_access(sql, user)
    if decision.is_denied:
        return sql, decision
    try:
        transformed = await apply_row_filters(sql, user)
    except _RowFilterError as exc:
        import uuid as _uuid

        from app.services.data_access.error_messages import (
            GenericMessageKind,
            make_generic_message,
        )

        # P5.2 (audit 2026-05-26) — Avant : le ``reason`` contenait juste
        # ``f"row filter injection failed: {exc}"`` qui ne remontait pas dans
        # les logs admin (AccessDecision.reason est consommé en debug par
        # check_sql_access mais perdu côté caller). Conséquence : l'admin
        # voyait juste ``user_message`` générique mode-invisible sans savoir
        # si c'était (a) un crash sqlglot AST malformé (b) une valeur PII
        # corrompue (c) un timeout intra-injection. Maintenant : on génère
        # un ``correlation_id`` UUID, on logge en WARNING côté serveur AVEC
        # ce CID, et on l'inclut dans ``reason`` pour permettre à l'admin de
        # ``grep`` ses logs et corréler.
        correlation_id = _uuid.uuid4().hex[:12]
        logger.warning(
            "data_access._RowFilterError [cid=%s] user_id=%s: %s — "
            "SQL refusé fail-closed",
            correlation_id,
            getattr(user, "id", "?"),
            exc,
            exc_info=True,
        )
        # Le message interne de ``_RowFilterError`` peut contenir des
        # détails sensibles (nom de colonne du row_filter). On le garde
        # uniquement pour la trace ``reason`` côté audit, mais le
        # ``user_message`` part en générique (invariant invisible).
        return sql, AccessDecision(
            allowed=False,
            reason=f"row filter injection failed [cid={correlation_id}]: {exc}",
            user_message=make_generic_message(GenericMessageKind.ROW_FILTER_FAILURE),
        )
    return transformed, decision


# ---------------------------------------------------------------------------
# Public : filter_table_catalogue (defense-in-depth contexte LLM)
# ---------------------------------------------------------------------------


async def filter_table_catalogue(
    table_names: List[str],
    user: Any,
) -> List[str]:
    """Retire d'une liste de tables celles que l'user n'a pas le droit de voir.

    Utilisé par ``agent_knowledge._get_table_catalogue`` pour ne pas exposer
    à Iris des tables que l'user ne peut de toute façon pas requêter.

    **Phase 2.4 (#91)** — Consomme désormais la closure transitive
    (`UserSchemaView.denied_tables_with_closure`) pour CACHER aussi les
    vues/fonctions/synonymes dérivés d'une table denied. Sans cette
    extension, le LLM voyait encore ``V_SALAIRES_RECAP`` dans son
    catalogue alors qu'il dépend de ``F_SALAIRES`` (interdite) → leak
    indirect via l'IA + mauvaise UX (l'user apprend de l'existence).

    **Stratégie d'UNION** (cohérence Phase 2.2) : ``effective_denied =
    rules.denied_tables ∪ view.denied_tables_with_closure``. Garantit que
    toute table atomique reste filtrée même si la view est stale entre
    deux invalidations.

    Comportement :

    - Enforcement off → liste inchangée.
    - User admin → liste inchangée.
    - User avec règles deny → tables ET dérivés filtrés.
    - User sans règle → liste inchangée (court-circuit perf : closure
      ne peut rien ajouter si pas de table atomique deny).
    """
    # Phase 2.4 review CRITICAL #2 — bypass système EXPLICITE (cohérent
    # avec check_table_access). Avant, le bypass fonctionnait par accident
    # via ``getattr(user, "id", None) is None`` — fragile à un refactor.
    if is_system_call(user):
        return list(table_names)
    if not await is_enforcement_enabled():
        return list(table_names)
    if is_user_exempt(user):
        return list(table_names)
    user_id = getattr(user, "id", None)
    if user_id is None:
        return list(table_names)
    rules = await load_rules_for_user(user_id)
    if rules.is_error:
        # Bug 2026-05-26 (DA-C1) : erreur BDD au chargement des règles —
        # fail-closed strict pour ce helper. On masque TOUTES les tables
        # (catalogue vide) jusqu'à ce qu'un read réussi remplisse le cache.
        # Préfère masquer un user légitime quelques secondes plutôt que
        # de leaker des tables qu'il aurait peut-être pas le droit de voir.
        logger.warning(
            "filter_table_catalogue: fail-closed user_id=%s (load_rules a "
            "échoué) — catalogue masqué jusqu'au retry.",
            user_id,
        )
        return []
    if not rules.denied_tables:
        # Court-circuit : sans table atomique deny, la closure est vide
        # (par contrat : closure ⊇ rules.denied_tables, donc closure=∅
        # implique pas de filtrage).
        return list(table_names)

    # Phase 2.4 — UNION avec la closure transitive
    try:
        from app.services.data_access.visible_schema import build_user_schema_view

        view = await build_user_schema_view(user)
        effective_denied = set(rules.denied_tables) | set(view.denied_tables_with_closure)
    except Exception as exc:
        logger.warning(
            "filter_table_catalogue: build_user_schema_view failed for "
            "user_id=%s, fallback rules.denied_tables (closure dégradée): %s",
            user_id,
            exc,
        )
        effective_denied = set(rules.denied_tables)

    return [t for t in table_names if t.strip().upper() not in effective_denied]


async def filter_table_columns(
    table_name: str,
    columns: List[str],
    user: Any,
) -> List[str]:
    """Retire d'une liste de colonnes celles que l'user n'a pas le droit
    de voir pour une table donnée.

    Utilisé par ``agent_knowledge`` (ou tout builder de prompt LLM) pour
    masquer les colonnes interdites du contexte exposé à Iris.

    **Phase 2.4 (#91)** — Si la table elle-même est interdite par closure
    transitive (vue dérivée), TOUTES ses colonnes sont masquées
    (retourne ``[]``). Avant Phase 2.4, le caller pouvait exposer les
    colonnes d'une vue dérivée pensant que seules les colonnes
    explicitement deny devaient être filtrées. Comportement aligné avec
    `UserSchemaView.can_see_column`.
    """
    # Phase 2.4 review CRITICAL #2 — bypass système EXPLICITE.
    if is_system_call(user):
        return list(columns)
    if not await is_enforcement_enabled():
        return list(columns)
    if is_user_exempt(user):
        return list(columns)
    user_id = getattr(user, "id", None)
    if user_id is None:
        return list(columns)
    rules = await load_rules_for_user(user_id)
    if rules.is_error:
        # Bug 2026-05-26 (DA-C1) : erreur BDD au chargement — fail-closed.
        # Aucune colonne exposée jusqu'au retry (cache non posé).
        logger.warning(
            "filter_table_columns: fail-closed user_id=%s table=%s "
            "(load_rules a échoué) — toutes colonnes masquées.",
            user_id,
            table_name,
        )
        return []
    # Phase 2.4 review CRITICAL #1 — court-circuit perf cohérent avec
    # check_table_access. Sans aucune règle, pas la peine de charger la
    # view (cold path BDD pour rien). Économise N appels view pour un
    # parcours Iris qui filter_table_columns sur N tables.
    if rules.is_empty:
        return list(columns)
    table_up = table_name.strip().upper()

    # Phase 2.4 — guard closure : si la table est denied (atomique OU via
    # closure transitive), retourne liste vide (table cachée → colonnes
    # cachées). Fail-soft : si build_user_schema_view foire, on retombe
    # sur rules.denied_tables pour le guard.
    try:
        from app.services.data_access.visible_schema import build_user_schema_view

        view = await build_user_schema_view(user)
        effective_denied = set(rules.denied_tables) | set(view.denied_tables_with_closure)
    except Exception as exc:
        logger.warning(
            "filter_table_columns: build_user_schema_view failed for "
            "user_id=%s table=%s, fallback rules.denied_tables: %s",
            user_id,
            table_up,
            exc,
        )
        effective_denied = set(rules.denied_tables)

    if table_up in effective_denied:
        return []  # table cachée → aucune colonne exposée

    denied = rules.denied_columns.get(table_up)
    if not denied:
        return list(columns)
    return [c for c in columns if c.strip().upper() not in denied]


# ---------------------------------------------------------------------------
# Helper centralisé pour les exécuteurs SQL
# ---------------------------------------------------------------------------


async def check_table_access(
    table_name: str,
    user: Any,
    *,
    columns: Optional[List[str]] = None,
) -> AccessDecision:
    """Vérifie l'accès à UNE table (et optionnellement à des colonnes) sans
    parser de SQL. Utile pour les tools qui interrogent une table par son
    nom (peek, introspect, get_database_schema en mode `exact`,
    check_join_compatibility, etc.).

    Comportement :

    - SYSTEM_USER → allowed.
    - Enforcement off → allowed.
    - User admin → allowed.
    - Sinon : check `denied_tables` puis `denied_columns` (si `columns` fourni).

    Idéalement appelé avant la construction de la SQL — économise un round-trip
    sqlglot.
    """
    if is_system_call(user):
        return _ALLOWED_DECISION
    if not await is_enforcement_enabled():
        return _ALLOWED_DECISION
    if is_user_exempt(user):
        return _ALLOWED_DECISION
    user_id = getattr(user, "id", None)
    if user_id is None:
        return AccessDecision(
            allowed=False,
            reason="user anonyme",
            user_message="Authentification requise.",
        )
    rules = await load_rules_for_user(user_id)
    if rules.is_empty:
        return _ALLOWED_DECISION
    table_up = (table_name or "").strip().upper()
    if not table_up:
        return _ALLOWED_DECISION

    # Phase 2.4 (#91) — UNION avec closure pour bloquer aussi les vues
    # dérivées (cohérent avec check_sql_access Phase 2.2). Fail-soft sur
    # erreur build view → fallback rules.denied_tables.
    try:
        from app.services.data_access.visible_schema import build_user_schema_view

        view = await build_user_schema_view(user)
        effective_denied = set(rules.denied_tables) | set(view.denied_tables_with_closure)
    except Exception as exc:
        logger.warning(
            "check_table_access: build_user_schema_view failed for "
            "user_id=%s, fallback rules.denied_tables: %s",
            user_id,
            exc,
        )
        effective_denied = set(rules.denied_tables)

    if table_up in effective_denied:
        return AccessDecision(
            allowed=False,
            reason=f"table {table_up} dans denied_tables (closure)",
            user_message=_build_user_message(table_up, None),
            blocking_table=table_up,
        )
    if columns:
        denied_cols = rules.denied_columns.get(table_up)
        if denied_cols:
            for col in columns:
                col_up = (col or "").strip().upper()
                if col_up and col_up in denied_cols:
                    return AccessDecision(
                        allowed=False,
                        reason=(f"colonne {table_up}.{col_up} dans denied_columns"),
                        user_message=_build_user_message(table_up, col_up),
                        blocking_table=table_up,
                        blocking_column=col_up,
                    )
    return _ALLOWED_DECISION


async def assert_table_access(
    table_name: str,
    user: Any,
    *,
    columns: Optional[List[str]] = None,
) -> None:
    """Variante "raise" de :func:`check_table_access` — utile dans les tools
    qui catch ``DataAccessDeniedError`` pour formatter la réponse.
    """
    decision = await check_table_access(table_name, user, columns=columns)
    if decision.is_denied:
        raise DataAccessDeniedError(
            decision.user_message,
            blocking_table=decision.blocking_table,
            blocking_column=decision.blocking_column,
            reason=decision.reason,
        )


async def enforce_for_executor(
    sql: str,
    user: Any,
    *,
    source: str = "unknown",
) -> str:
    """Hook appelé par ``query_executor.execute()`` (et tout autre exécuteur
    SQL) AVANT d'envoyer la requête à la BDD source.

    Logique :

    - ``user`` est :data:`SYSTEM_USER` (sentinel) → bypass complet
      (sync schema, métadata, jobs background).
    - Enforcement off ou user admin → SQL inchangée.
    - Sinon → ``enforce_sql`` (check + apply). Si denied → raise
      :class:`DataAccessDeniedError`.
    - ``user`` est ``None`` ALORS QUE l'enforcement est ON → log WARNING
      et laisse passer (compat des call-sites legacy non-migrés). C'est
      un signal qu'il manque une propagation de user quelque part.

    Retourne la SQL transformée (avec WHERE filters injectés si row_filter
    matchant) ou inchangée.
    """
    if is_system_call(user):
        return sql
    if not await is_enforcement_enabled():
        return sql
    if is_user_exempt(user):
        return sql
    if user is None:
        logger.warning(
            "data_access: SQL exec sans user fourni alors que "
            "l'enforcement est actif (source=%s) — RLS skip. "
            "Migrer le call-site pour propager le user.",
            source,
        )
        return sql
    sql_transformed, decision = await enforce_sql(sql, user)
    if decision.is_denied:
        raise DataAccessDeniedError(
            decision.user_message,
            blocking_table=decision.blocking_table,
            blocking_column=decision.blocking_column,
            reason=decision.reason,
        )
    return sql_transformed
