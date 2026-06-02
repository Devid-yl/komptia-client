"""Diff temporel des résultats de requête NL→SQL (T30).

Quand un utilisateur répète une question similaire à une question déjà
exécutée (recall-IDF élevé sur l'historique ``AIPerformanceLog``),
calculer le delta entre les deux ensembles de rows résultats : rows
ajoutées, supprimées, valeurs modifiées par cellule.

Architecture (cohérente avec ``question_diff.py``)
--------------------------------------------------

Trois briques découplées qui composent un workflow de diff temporel :

1. :func:`find_previous_search` (DB, async) — retrouve l'AIPerformanceLog
   le plus récent dont la ``question`` matche la courante avec
   recall-IDF ≥ ``DIFF_RECALL_THRESHOLD``. Strictement isolé par
   ``user_id``. Filtre ``status == SUCCESS`` et ``sql_validated IS NOT
   NULL`` pour ne comparer que des runs valides.

2. :func:`compute_result_diff` (pur, sync) — diff entre 2 listes de
   rows (dicts). Set-based pour ``added``/``removed`` (order-insensitive
   par construction). ``modified`` est UNIQUEMENT calculé si
   ``key_columns`` est fourni explicitement — pas d'auto-détection
   (les faux ``modified`` sont pires qu'une absence de signal). Sans
   key, une row qui change même 1 cellule devient
   ``added`` + ``removed``.

3. :func:`format_result_diff_for_ui` — sérialise le diff en dict
   JSON-friendly avec truncation pour l'envoi front (gros datasets).

Et un helper de persistance optionnel :

4. :func:`persist_query_diff` — insert un ``QueryDiffHistory`` row à
   partir du diff calculé. Le caller décide quand (eager après
   exécution / lazy à la demande UI).

Pas de pandas
-------------

Pure Python set-based hashing. Pandas serait surdimensionné (~0.5s
import à froid + complexité ``compare()`` qui exige même shape/index)
et ne couvre pas mieux les cas standards (rows = list[dict]).

Pas d'auto-détection de key
---------------------------

Auto-détecter une "PK candidate" est tentant (1ʳᵉ colonne unique +
non-null) mais produit des faux ``modified`` quand la BDD source
expose une "fausse" PK technique (ex: ``rowid`` SQLite changeant à
chaque exec). Le caller — qui connaît la sémantique de la requête —
fournit ``key_columns`` explicitement, ou se contente du set-based
pur. Cohérent avec la règle Komptia "Code > Prompt" : c'est le
caller (système) qui décide.

Threshold aligné single source of truth
---------------------------------------

``DIFF_RECALL_THRESHOLD = FRESH_REUSE_MIN_SCORE`` (importé depuis
``question_diff``). Un changement de seuil profite aux deux modules.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from app.core import clock

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import ensure_utc
from app.services.ai.question_diff import FRESH_REUSE_MIN_SCORE
from app.services.ai.training_store import SimpleTextSearch

logger = logging.getLogger(__name__)


DIFF_RECALL_THRESHOLD: float = FRESH_REUSE_MIN_SCORE
"""Seuil minimal de recall-IDF pour considérer 2 questions « répétées ».

Aligné sur :data:`app.services.ai.question_diff.FRESH_REUSE_MIN_SCORE`
pour garantir un comportement cohérent : si une paire est jugée
suffisamment proche pour réutiliser le SQL validé, elle l'est aussi
pour calculer un diff de résultats.
"""

DIFF_LOOKBACK_DAYS: int = 30
"""Profondeur historique par défaut pour la recherche de question similaire."""

DIFF_LOOKBACK_LIMIT: int = 50
"""Nombre max de rows AIPerformanceLog à scorer (perf, lookback récent)."""

DEFAULT_UI_MAX_ROWS: int = 100
"""Limite de rows envoyées au frontend (anti-grosses payloads JSON)."""


@dataclass
class ResultDiff:
    """Résultat d'un diff entre 2 ensembles de rows.

    Tous les champs sont initialisés à des valeurs vides safe — un
    ``ResultDiff()`` est valide et signifie "aucun changement".
    """

    added: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[Dict[str, Any]] = field(default_factory=list)
    modified: List[Dict[str, Any]] = field(default_factory=list)
    key_columns: Optional[List[str]] = None
    schema_changed: bool = False
    summary: Dict[str, int] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        """``True`` si aucun changement détecté."""
        return not (self.added or self.removed or self.modified)


# ──────────────────────────────────────────────────────────────────────
# Helpers privés (hashing / signatures de row)
# ──────────────────────────────────────────────────────────────────────


def _to_hashable(value: Any) -> Any:
    """Coerce une valeur arbitraire en hashable pour set/dict keys.

    Règles :

    * ``None`` : tel quel.
    * ``bool`` : taggé ``("bool", True/False)`` pour le distinguer de
      ``int(0/1)`` (sinon ``True == 1`` produit la même signature
      qu'un BOOLEAN True et un INTEGER 1, sémantiquement différents
      pour une cellule typée).
    * ``int`` / ``float`` / ``str`` : tels quels (déjà hashables).
    * ``datetime`` : ISO string ; tz-aware coercé en UTC pour éviter
      qu'un même instant exprimé en 2 timezones produise 2 buckets
      (cas : SQL Server retourne tz-naive, PostgreSQL tz-aware).
    * ``list`` / ``tuple`` : tuple récursif.
    * ``dict`` : tuple sorted des items (récursif). Keys coercées en
      str pour permettre le sort sur dicts à keys mixtes (int+str).
    * Reste (``Decimal``, ``date``, objets SQLAlchemy Row, etc.) :
      ``str(value)``.

    Cette fonction est CRITIQUE pour la correction du diff :

    - ``Decimal('100.50') == Decimal('100.50')`` → str identique →
      même bucket.
    - ``True`` ≠ ``1`` (préservation de la sémantique BOOLEAN/INTEGER).
    - ``datetime(...,UTC)`` == naïf représentant le même instant si
      tagué via ``ensure_utc`` côté caller.
    """
    if value is None:
        return None
    # IMPORTANT : tester bool AVANT int (bool est sous-classe d'int)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float, str)):
        return value
    if isinstance(value, datetime):
        normalized = ensure_utc(value)
        return normalized.isoformat() if normalized is not None else None
    if isinstance(value, (list, tuple)):
        return tuple(_to_hashable(v) for v in value)
    if isinstance(value, dict):
        # Coerce keys en str pour permettre sort sur dicts mixtes.
        return tuple(sorted((str(k), _to_hashable(v)) for k, v in value.items()))
    return str(value)


def _row_signature(row: Dict[str, Any], cols: Optional[List[str]] = None) -> Tuple:
    """Signature hashable d'une row sur ``cols`` (ou toutes les keys
    de ``row`` triées si ``cols`` est ``None``).

    Sortie : tuple de paires ``(col, hashable_value)`` triées par
    ``col`` — garantit que 2 rows avec mêmes données mais ordre
    d'insertion différent produisent la MÊME signature.
    """
    keys = sorted(cols) if cols is not None else sorted(row.keys())
    return tuple((k, _to_hashable(row.get(k))) for k in keys)


def _all_columns(rows: List[Dict[str, Any]]) -> set:
    """Union des keys de toutes les rows (pas seulement la 1ʳᵉ).

    Couvre le cas réel où des rows hétérogènes arrivent (driver SQL
    qui omet une col NULL, dict.get côté caller, etc.). Sans cette
    union, le hashing ignorait silencieusement les cols absentes de
    ``rows[0]`` → diff faussé.
    """
    if not rows:
        return set()
    cols: set = set()
    for r in rows:
        cols.update(r.keys())
    return cols


def _common_columns(
    rows_a: List[Dict[str, Any]], rows_b: List[Dict[str, Any]]
) -> Tuple[List[str], bool]:
    """Retourne (intersection des cols, schema_changed).

    Calcul sur l'UNION des keys de toutes les rows de chaque liste
    (pas seulement la 1ʳᵉ — cf. :func:`_all_columns` pour le contexte).

    Si l'une des listes est vide, on prend les cols de l'autre (ou
    [] si les deux vides) — le ``schema_changed`` ne s'applique que
    si LES DEUX listes sont non vides ET ont des cols différentes.
    """
    if not rows_a and not rows_b:
        return ([], False)
    cols_a = _all_columns(rows_a)
    cols_b = _all_columns(rows_b)
    if not rows_a:
        return (sorted(cols_b), False)
    if not rows_b:
        return (sorted(cols_a), False)
    schema_changed = cols_a != cols_b
    return (sorted(cols_a & cols_b), schema_changed)


# ──────────────────────────────────────────────────────────────────────
# API publique : compute_result_diff
# ──────────────────────────────────────────────────────────────────────


def compute_result_diff(
    rows_current: Optional[List[Dict[str, Any]]],
    rows_previous: Optional[List[Dict[str, Any]]],
    *,
    key_columns: Optional[List[str]] = None,
) -> ResultDiff:
    """Diff structuré entre 2 listes de dict-rows.

    Args:
        rows_current: rows de l'exécution courante. ``None`` traité
            comme liste vide (fail-safe).
        rows_previous: rows de l'exécution précédente. ``None`` idem.
        key_columns: colonnes formant la clé d'identité d'une row.
            Si fourni (et non vide), on calcule ``modified`` (cellules
            qui ont changé pour la même clé) en plus de
            ``added``/``removed``. Si ``None`` ou ``[]``, set-based
            pur : ``added``/``removed`` seulement (``modified=[]``).

    Returns:
        :class:`ResultDiff` avec compteurs dans ``.summary`` et flag
        ``.schema_changed`` si les schemas des 2 ensembles diffèrent.

    Comportement edge cases :

    - Listes vides ou ``None`` : retourne ``ResultDiff()`` vide.
    - Schema drift (cols différentes entre 2 runs) : utilise
      l'INTERSECTION des cols pour le hashing/match, pose
      ``schema_changed=True`` (signal au caller pour wording UI
      "structure changed").
    - Order-insensitive (set-based hashing).
    - Valeurs non hashables (``datetime``, ``Decimal``, ``date``) :
      converties via :func:`_to_hashable` (typiquement ``str()``).
    - ``key_columns`` contient une col absente du schema common :
      la valeur sera ``None`` dans la clé tuple (groupe par "clé
      partielle" — possible mais signal d'erreur côté caller).
    """
    rows_current = rows_current or []
    rows_previous = rows_previous or []

    common_cols, schema_changed = _common_columns(rows_current, rows_previous)

    # Pour le hashing en mode set-based, on utilise l'UNION des cols
    # afin que des rows hétérogènes (ex: une row avec col 'extra' et
    # une autre sans) produisent des signatures distinctes. Sinon, le
    # hashing ignorait silencieusement les cols absentes de la 1ʳᵉ row.
    union_cols = sorted(_all_columns(rows_current) | _all_columns(rows_previous))

    # Dédupliquer + tri stable des key_columns pour invariance vs
    # ordre passé par le caller (les 2 ordres "['a','b']" et
    # "['b','a']" doivent produire le même bucketing).
    effective_keys: Optional[List[str]] = None
    if key_columns:
        seen: set = set()
        deduped: List[str] = []
        for k in key_columns:
            if k not in seen:
                seen.add(k)
                deduped.append(k)
        if len(deduped) != len(key_columns):
            logger.warning(
                "compute_result_diff: key_columns contient des doublons %r — "
                "déduplication appliquée",
                key_columns,
            )
        effective_keys = sorted(deduped)

    diff = ResultDiff(
        key_columns=effective_keys,
        schema_changed=schema_changed,
    )

    # ── Mode key-based : added/removed/modified ─────────────────────
    if effective_keys:
        idx_curr: Dict[Tuple, Dict[str, Any]] = {}
        curr_collisions = 0
        for r in rows_current:
            k = tuple(_to_hashable(r.get(c)) for c in effective_keys)
            if k in idx_curr:
                curr_collisions += 1
            idx_curr[k] = r
        idx_prev: Dict[Tuple, Dict[str, Any]] = {}
        prev_collisions = 0
        for r in rows_previous:
            k = tuple(_to_hashable(r.get(c)) for c in effective_keys)
            if k in idx_prev:
                prev_collisions += 1
            idx_prev[k] = r

        if curr_collisions or prev_collisions:
            logger.warning(
                "compute_result_diff: key_columns=%r non-unique — "
                "collisions current=%d, previous=%d. Diff sous-comptera.",
                effective_keys,
                curr_collisions,
                prev_collisions,
            )

        keys_curr = set(idx_curr.keys())
        keys_prev = set(idx_prev.keys())

        for k in sorted(keys_curr - keys_prev, key=lambda kk: tuple(str(x) for x in kk)):
            diff.added.append(idx_curr[k])
        for k in sorted(keys_prev - keys_curr, key=lambda kk: tuple(str(x) for x in kk)):
            diff.removed.append(idx_prev[k])

        # Cells modifiées : pour chaque key commune, comparer chaque
        # col commune (hors key_columns elles-mêmes).
        non_key_common = [c for c in common_cols if c not in effective_keys]
        for k in sorted(keys_curr & keys_prev, key=lambda kk: tuple(str(x) for x in kk)):
            r_curr = idx_curr[k]
            r_prev = idx_prev[k]
            cell_changes: Dict[str, Dict[str, Any]] = {}
            for col in non_key_common:
                vc = r_curr.get(col)
                vp = r_prev.get(col)
                if _to_hashable(vc) != _to_hashable(vp):
                    cell_changes[col] = {"prev": vp, "curr": vc}
            if cell_changes:
                diff.modified.append(
                    {
                        "key": dict(zip(effective_keys, k)),
                        "changes": cell_changes,
                    }
                )
    else:
        # ── Mode set-based pur : added/removed seulement ─────────
        # Counter sur les signatures pour détecter les collisions
        # (rows identiques dans une même liste) au lieu de set qui
        # masquerait les doublons.
        # Hash sur UNION des cols pour que les rows hétérogènes
        # produisent des signatures distinctes.
        sig_curr_count: Counter = Counter()
        sig_curr_first: Dict[Tuple, Dict[str, Any]] = {}
        for r in rows_current:
            s = _row_signature(r, union_cols)
            sig_curr_count[s] += 1
            sig_curr_first.setdefault(s, r)
        sig_prev_count: Counter = Counter()
        sig_prev_first: Dict[Tuple, Dict[str, Any]] = {}
        for r in rows_previous:
            s = _row_signature(r, union_cols)
            sig_prev_count[s] += 1
            sig_prev_first.setdefault(s, r)

        curr_dups = sum(c - 1 for c in sig_curr_count.values() if c > 1)
        prev_dups = sum(c - 1 for c in sig_prev_count.values() if c > 1)
        if curr_dups or prev_dups:
            logger.warning(
                "compute_result_diff: signatures dupliquées en mode set-based "
                "(current=%d, previous=%d) — set-based va sous-compter.",
                curr_dups,
                prev_dups,
            )

        # Diff par multiplicité : si une signature apparaît N fois dans
        # current et M fois dans previous, alors :
        # - max(N - M, 0) rows ajoutées
        # - max(M - N, 0) rows supprimées
        # Cas dégénéré inclus : sig absente d'une liste = count 0.
        all_sigs = set(sig_curr_count.keys()) | set(sig_prev_count.keys())
        for s in all_sigs:
            n_curr = sig_curr_count.get(s, 0)
            n_prev = sig_prev_count.get(s, 0)
            if n_curr > n_prev:
                row = sig_curr_first.get(s) or sig_prev_first.get(s)
                if row is not None:
                    diff.added.extend([row] * (n_curr - n_prev))
            elif n_prev > n_curr:
                row = sig_prev_first.get(s) or sig_curr_first.get(s)
                if row is not None:
                    diff.removed.extend([row] * (n_prev - n_curr))

    diff.summary = {
        "added": len(diff.added),
        "removed": len(diff.removed),
        "modified": len(diff.modified),
        "rows_current_total": len(rows_current),
        "rows_previous_total": len(rows_previous),
    }
    return diff


# ──────────────────────────────────────────────────────────────────────
# API publique : find_previous_search (DB)
# ──────────────────────────────────────────────────────────────────────


async def find_previous_search(
    *,
    user_id: int,
    current_question: str,
    session: AsyncSession,
    recall_threshold: float = DIFF_RECALL_THRESHOLD,
    exclude_log_id: Optional[int] = None,
    lookback_days: int = DIFF_LOOKBACK_DAYS,
    limit: int = DIFF_LOOKBACK_LIMIT,
) -> Optional[Tuple[Any, float]]:
    """Trouve le ``AIPerformanceLog`` le plus pertinent à comparer.

    Critères de filtrage SQL (avant scoring) :

    * ``user_id == user_id`` (isolation cross-user — jamais de fuite).
    * ``status == QueryStatus.SUCCESS`` (un run cassé n'est pas une
      référence valide).
    * ``sql_validated IS NOT NULL`` (le SQL a été exécuté avec succès).
    * ``created_at >= now - lookback_days`` (pertinence temporelle).
    * ``id != exclude_log_id`` si fourni (typiquement le log courant).

    Scoring :

    * Recall-IDF (:meth:`SimpleTextSearch.compute_query_recall_idf`)
      sur les questions filtrées.
    * Best-match si score ≥ ``recall_threshold``.

    Args:
        user_id: utilisateur courant (isolation).
        current_question: question NL à matcher.
        session: session SQLAlchemy async.
        recall_threshold: seuil minimal (default
            :data:`DIFF_RECALL_THRESHOLD` = 0.50).
        exclude_log_id: id à exclure (typiquement le log courant).
        lookback_days: profondeur historique en jours.
        limit: nombre max de candidats à charger en mémoire.

    Returns:
        ``(log, score)`` du meilleur match si ≥ ``recall_threshold``,
        sinon ``None``.

    Pas de side-effect (read-only). Pas de logs (le caller décide
    de tracer ou non — différents call sites ont différentes
    politiques de log).
    """
    # Import lazy : évite de charger les modèles au load du package
    # ``app.services.ai`` (qui doit rester léger pour les tests).
    from app.models.ai_performance import AIPerformanceLog, QueryStatus

    if not current_question or not isinstance(current_question, str):
        return None
    if user_id is None:
        return None
    if not 0.0 <= recall_threshold <= 1.0:
        raise ValueError(f"recall_threshold doit être dans [0.0, 1.0], reçu {recall_threshold!r}")
    if lookback_days <= 0 or limit <= 0:
        raise ValueError(f"lookback_days ({lookback_days}) et limit ({limit}) doivent être > 0")

    # Datetime tz fix : la colonne ``AIPerformanceLog.created_at`` est
    # ``DateTime`` SANS ``timezone=True`` → SQLite/aiosqlite revient
    # tz-naive. On utilise un cutoff naïf pour éviter le mismatch
    # tz-aware/tz-naive (TypeError sur certains drivers).
    cutoff = clock.naive_utc() - timedelta(days=lookback_days)
    stmt = (
        select(
            AIPerformanceLog.id,
            AIPerformanceLog.question,
            AIPerformanceLog.created_at,
        )
        .where(
            AIPerformanceLog.user_id == user_id,
            AIPerformanceLog.status == QueryStatus.SUCCESS,
            AIPerformanceLog.sql_validated.isnot(None),
            AIPerformanceLog.created_at >= cutoff,
        )
        .order_by(AIPerformanceLog.created_at.desc())
        .limit(limit)
    )
    if exclude_log_id is not None:
        stmt = stmt.where(AIPerformanceLog.id != exclude_log_id)

    result = await session.execute(stmt)
    rows = list(result.all())
    if not rows:
        return None

    query_tokens = SimpleTextSearch.tokenize(current_question)
    if not query_tokens:
        return None

    docs = [SimpleTextSearch.tokenize(r.question or "") for r in rows]
    scores = SimpleTextSearch.compute_query_recall_idf(query_tokens, docs)

    # Tie-breaker : à score égal, le PLUS RÉCENT gagne. La query est
    # ``ORDER BY created_at DESC`` donc le 1ʳᵉ row d'un score donné est
    # le plus récent ; on garde le 1ʳᵉ atteint via comparaison stricte.
    best_idx = -1
    best_score = -1.0
    for i, s in enumerate(scores):
        if s >= recall_threshold and s > best_score:
            best_score = s
            best_idx = i

    if best_idx < 0:
        return None

    # 2ᵉ query pour récupérer le row complet (économie RAM au scoring).
    best_id = rows[best_idx].id
    fetch_stmt = select(AIPerformanceLog).where(AIPerformanceLog.id == best_id)
    fetch_result = await session.execute(fetch_stmt)
    best_log = fetch_result.scalar_one_or_none()
    if best_log is None:
        # Race rare : le log a été purgé entre les 2 queries. Fail-safe.
        return None
    return (best_log, float(best_score))


# ──────────────────────────────────────────────────────────────────────
# API publique : format_result_diff_for_ui
# ──────────────────────────────────────────────────────────────────────


def _serialize_value(v: Any) -> Any:
    """Sérialise une valeur en JSON-friendly (recursive).

    ``datetime`` → ISO 8601 string. ``Decimal`` / ``date`` /
    autres → ``str()``. ``list``/``dict`` → recursive. Native
    types passthrough.
    """
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, (list, tuple)):
        return [_serialize_value(x) for x in v]
    if isinstance(v, dict):
        return {k: _serialize_value(val) for k, val in v.items()}
    return str(v)


def _serialize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _serialize_value(v) for k, v in row.items()}


def format_result_diff_for_ui(
    diff: ResultDiff, *, max_rows: int = DEFAULT_UI_MAX_ROWS
) -> Dict[str, Any]:
    """Sérialise un :class:`ResultDiff` en dict JSON-friendly.

    Truncate ``added``/``removed``/``modified`` à ``max_rows`` chacun
    pour borner la taille du payload front (typiquement ≤ 1 MB).
    Les compteurs ``*_total`` permettent au front d'afficher
    "Voir 150 rows ajoutées (10 affichées)".

    ``datetime``, ``Decimal`` et types non-JSON sont sérialisés via
    :func:`_serialize_value`.
    """
    if max_rows is None or max_rows < 0:
        max_rows = 0
    return {
        "added": [_serialize_row(r) for r in diff.added[:max_rows]],
        "added_truncated": len(diff.added) > max_rows,
        "added_total": len(diff.added),
        "removed": [_serialize_row(r) for r in diff.removed[:max_rows]],
        "removed_truncated": len(diff.removed) > max_rows,
        "removed_total": len(diff.removed),
        "modified": [
            {
                "key": _serialize_row(m["key"]),
                "changes": {
                    col: {
                        "prev": _serialize_value(c["prev"]),
                        "curr": _serialize_value(c["curr"]),
                    }
                    for col, c in m["changes"].items()
                },
            }
            for m in diff.modified[:max_rows]
        ],
        "modified_truncated": len(diff.modified) > max_rows,
        "modified_total": len(diff.modified),
        "key_columns": diff.key_columns,
        "schema_changed": diff.schema_changed,
        "summary": dict(diff.summary),
    }


# ──────────────────────────────────────────────────────────────────────
# API publique : persist_query_diff (DB)
# ──────────────────────────────────────────────────────────────────────


async def persist_query_diff(
    *,
    session: AsyncSession,
    user_id: Optional[int],
    search_id_current: int,
    search_id_prev: int,
    diff: ResultDiff,
    recall_score: Optional[float] = None,
    max_rows_for_storage: int = DEFAULT_UI_MAX_ROWS,
) -> Any:
    """Insert un ``QueryDiffHistory`` row à partir d'un diff.

    Le caller décide quand persister (typiquement eager après
    exécution, ou lazy au moment où l'UI demande).

    Args:
        session: AsyncSession (le caller gère commit/rollback).
        user_id: utilisateur (peut être ``None`` si erase RGPD).
        search_id_current: id du log AI courant.
        search_id_prev: id du log AI précédent.
        diff: diff calculé.
        recall_score: score recall-IDF entre les 2 questions.
        max_rows_for_storage: limite truncate avant stockage JSON
            (par défaut DEFAULT_UI_MAX_ROWS — bornée pour éviter
            que la BDD locale ne grossisse sur de grosses requêtes).

    Returns:
        L'instance ``QueryDiffHistory`` ajoutée à la session
        (flush appelé pour obtenir l'id, pas de commit).

    Le diff est sérialisé via :func:`format_result_diff_for_ui` —
    cohérent avec ce que l'UI consomme.

    Validations fail-fast :

    * ``search_id_current != search_id_prev`` (un diff de soi-même
      est sémantiquement absurde).
    * ``recall_score`` dans ``[0.0, 1.0]`` si fourni.
    """
    from app.models.query_diff_history import QueryDiffHistory

    if search_id_current == search_id_prev:
        raise ValueError(
            "search_id_current et search_id_prev doivent être différents "
            "(un diff de soi-même n'a pas de sens)"
        )
    if recall_score is not None and not 0.0 <= recall_score <= 1.0:
        raise ValueError(f"recall_score doit être dans [0.0, 1.0], reçu {recall_score!r}")

    record = QueryDiffHistory(
        user_id=user_id,
        search_id_current=search_id_current,
        search_id_prev=search_id_prev,
        recall_score=recall_score,
        added_count=len(diff.added),
        removed_count=len(diff.removed),
        modified_count=len(diff.modified),
        diff_json=format_result_diff_for_ui(diff, max_rows=max_rows_for_storage),
    )
    session.add(record)
    await session.flush()
    return record


__all__ = [
    "DEFAULT_UI_MAX_ROWS",
    "DIFF_LOOKBACK_DAYS",
    "DIFF_LOOKBACK_LIMIT",
    "DIFF_RECALL_THRESHOLD",
    "ResultDiff",
    "compute_result_diff",
    "find_previous_search",
    "format_result_diff_for_ui",
    "persist_query_diff",
]
