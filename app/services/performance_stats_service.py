"""
Service de statistiques de performance application.

Fournit les metriques pour le dashboard performances:
- Taux de reussite et volumes
- Temps de reponse (percentiles P50/P90/P99)
- Evolution quotidienne
- Distribution des temps de reponse
- Requetes recentes
"""

import logging
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta

from sqlalchemy import select, func, case, desc

from app.constants import WEEK_DAYS
from app.core import clock
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.models.search_history import SearchHistory
from app.services.query_cache import get_cache
from app.core.database import get_session

logger = logging.getLogger(__name__)

# Bug 2026-05-26 (Agent 3 P-2) : cap dur sur le nombre de rows chargées en
# RAM pour P50/P90/P99. Au-delà de ~50k, les percentiles sont statistiquement
# stables — pas besoin de plomber la RAM avec 3.6M rows × auto-refresh × N
# admins. ``ORDER BY created_at DESC LIMIT`` garde les plus récents (les plus
# représentatifs des changements de stack/perf).
_PERCENTILES_MAX_SAMPLES: int = 50_000

# Bug 2026-05-26 (Agent 3 P-3 CRITIQUE) : cache TTL court pour
# ``get_overview`` et ``get_percentiles``. ``/admin/performance`` fait un
# ``location.reload()`` toutes les 30s × N admins, chaque reload déclenchant
# 8 BDD queries. Sans cache, 3 admins = 24 BDD queries / 30s en steady state
# alors que les données ne changent pas significativement seconde à seconde.
# TTL 25s : inférieur au polling 30s pour que les admins en désynchronisation
# bénéficient du cache (1er admin pollue le cache, les suivants lisent). Les
# admins synchronisés se partagent un seul appel BDD au lieu de N.
# Le ``CacheClearHandler`` invalide explicitement via ``clear_perf_caches()``.
_PERF_CACHE_TTL_SECONDS: float = 25.0
_overview_cache: Dict[int, Tuple[Dict[str, Any], float]] = {}
_percentiles_cache: Dict[int, Tuple[Dict[str, float], float]] = {}


def clear_perf_caches() -> None:
    """Invalide les caches TTL de :class:`PerformanceStatsService`.

    Branché par :class:`app.handlers.performance.CacheClearHandler` (POST
    ``/api/performance/clear-cache``) — quand l'admin demande un "vider
    cache", il doit voir les valeurs fraîches au prochain reload.

    ⚠️ DOCTRINE MULTI-WORKER (ADV-6 — adversarial review 2026-05-26) :
    ces caches sont des globals AU NIVEAU DU PROCESS Python. Komptia tourne
    en SINGLE-PROCESS Tornado par défaut (cf. ``main.py`` + CLAUDE.md),
    donc ce ``clear()`` vide le cache pour TOUS les admins simultanés.

    Si jamais Komptia bascule sur un déploiement multi-worker (gunicorn
    fork, Tornado --num-processes > 1), CE CACHE FUITERA — chaque worker
    aura sa propre instance et ``CacheClearHandler`` ne videra que le
    worker qui reçoit la requête. Les autres admins verront encore le
    cache 25s. Solutions à ce moment-là :
    1. Stocker le cache dans SQLite (table ``perf_cache``) avec TTL en
       colonne — accessible par tous les workers.
    2. Brancher un broadcast IPC (zmq, Redis pub/sub) qui dit aux autres
       workers « clear maintenant ».
    3. Documenter la limitation et accepter la fenêtre 25s de divergence.

    En attendant : Komptia reste single-process, c'est OK.
    """
    _overview_cache.clear()
    _percentiles_cache.clear()


def _percentile(sorted_data: List[float], p: float) -> float:
    """Calcule le percentile p d'une liste triee."""
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    return sorted_data[f] + (sorted_data[c] - sorted_data[f]) * (k - f)


class PerformanceStatsService:
    """Service de statistiques pour le dashboard performance application."""

    async def get_overview(self, days: int = WEEK_DAYS) -> Dict[str, Any]:
        """Vue d'ensemble des performances (avec cache TTL court P-3).

        Bug 2026-05-26 (P-3 CRITIQUE) : avant ce cache, chaque
        ``location.reload()`` du dashboard rechargeait 5 BDD queries depuis
        cette méthode. À 30s × 3 admins simultanés = 30 queries/30s sur des
        données qui ne bougent pas seconde à seconde. Cache TTL 25s — voir
        ``_PERF_CACHE_TTL_SECONDS``.
        """
        days = min(max(days, 1), 365)
        since = clock.now() - timedelta(days=days)

        now_mono = time.monotonic()
        cached = _overview_cache.get(days)
        if cached is not None:
            payload, ts = cached
            if (now_mono - ts) < _PERF_CACHE_TTL_SECONDS:
                # ``cache_stats`` n'est pas figé — on rafraîchit ce sous-champ
                # à chaque hit pour que les jauges du dashboard reflètent
                # l'état RÉCENT du LRU (pas une photo de 25s).
                fresh = dict(payload)
                fresh["cache_stats"] = get_cache().stats()
                return fresh

        async with get_session() as session:
            # Bug 2026-05-26 (P-1a MOYEN) : compte sur 2 tables car
            # ``SearchHistory`` est la table legacy (plus écrite par aucun
            # module — vérifié ``grep "SearchHistory(" app/`` = 0 hits) et
            # ``AIPerformanceLog`` est la nouvelle SSoT alimentée par
            # ``llm_call_tracker``. Pendant la transition, on union les
            # deux pour que le dashboard reflète aussi les anciennes lignes
            # SearchHistory déjà en BDD prod. La doctrine Komptia "single
            # source of truth" sera honorée quand un script de migration
            # batch-copiera SearchHistory → AIPerformanceLog (à venir).
            # Les caches TTL P-3 + le cap P-2 protègent la perf de ce
            # double round-trip.

            # Total et succes (toutes periodes)
            totals_old = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(case((SearchHistory.success == True, 1), else_=0)).label(  # noqa: E712
                        "successes"
                    ),
                ).select_from(SearchHistory)
            )
            row_old = totals_old.first()
            total_old = row_old.total or 0
            successes_old = row_old.successes or 0

            totals_new = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                ).select_from(AIPerformanceLog)
            )
            row_new = totals_new.first()
            total_new = row_new.total or 0
            successes_new = row_new.successes or 0

            total = total_old + total_new
            successes = successes_old + successes_new

            # Recentes (fenetre temporelle)
            recent_old = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(case((SearchHistory.success == True, 1), else_=0)).label(  # noqa: E712
                        "successes"
                    ),
                )
                .select_from(SearchHistory)
                .where(SearchHistory.created_at >= since)
            )
            recent_row_old = recent_old.first()
            recent_total_old = recent_row_old.total or 0

            recent_new = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                )
                .select_from(AIPerformanceLog)
                .where(AIPerformanceLog.created_at >= since)
            )
            recent_row_new = recent_new.first()
            recent_total_new = recent_row_new.total or 0

            recent_total = recent_total_old + recent_total_new

            # Temps moyens (hors null) — moyenne PONDÉRÉE des 2 sources pour
            # éviter qu'une table vide tire la moyenne globale à 0.
            avg_q_old = await session.execute(
                select(
                    func.avg(SearchHistory.execution_time).label("exec"),
                    func.avg(SearchHistory.generation_time).label("gen"),
                    func.count(SearchHistory.id).label("n"),
                ).where(
                    SearchHistory.created_at >= since,
                    SearchHistory.execution_time.isnot(None),
                )
            )
            avg_row_old = avg_q_old.first()
            avg_q_new = await session.execute(
                select(
                    func.avg(AIPerformanceLog.execution_time).label("exec"),
                    func.avg(AIPerformanceLog.generation_time).label("gen"),
                    func.count(AIPerformanceLog.id).label("n"),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.execution_time.isnot(None),
                )
            )
            avg_row_new = avg_q_new.first()

            # Helper local : moyenne pondérée (a*na + b*nb) / (na + nb)
            def _weighted_avg(a, na, b, nb):
                if (na + nb) == 0:
                    return 0
                a_val = float(a or 0) * (na or 0)
                b_val = float(b or 0) * (nb or 0)
                return (a_val + b_val) / float(na + nb)

            avg_execution = _weighted_avg(
                avg_row_old[0], avg_row_old[2], avg_row_new[0], avg_row_new[2]
            )
            avg_generation = _weighted_avg(
                avg_row_old[1], avg_row_old[2], avg_row_new[1], avg_row_new[2]
            )

            # Taux < 10s — somme des 2 sources
            under_10s_old = await session.execute(
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.created_at >= since,
                    SearchHistory.execution_time.isnot(None),
                    SearchHistory.generation_time.isnot(None),
                    (SearchHistory.execution_time + SearchHistory.generation_time) < 10,
                )
            )
            under_10s_new = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.execution_time.isnot(None),
                    AIPerformanceLog.generation_time.isnot(None),
                    (AIPerformanceLog.execution_time + AIPerformanceLog.generation_time) < 10,
                )
            )
            under_10s = (under_10s_old.scalar() or 0) + (under_10s_new.scalar() or 0)

            total_with_times_old_q = await session.execute(
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.created_at >= since,
                    SearchHistory.execution_time.isnot(None),
                    SearchHistory.generation_time.isnot(None),
                )
            )
            total_with_times_new_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.execution_time.isnot(None),
                    AIPerformanceLog.generation_time.isnot(None),
                )
            )
            total_with_times = (total_with_times_old_q.scalar() or 0) + (
                total_with_times_new_q.scalar() or 0
            )

            success_rate = (successes / total * 100) if total > 0 else 0
            under_10s_rate = (under_10s / total_with_times * 100) if total_with_times > 0 else 0

            cache_stats = get_cache().stats()

            payload = {
                "period_days": days,
                "total_searches": total,
                "successful_searches": successes,
                "success_rate": round(success_rate, 1),
                "recent_count": recent_total,
                "avg_execution": round(avg_execution, 2),
                "avg_generation": round(avg_generation, 2),
                "under_10s_rate": round(under_10s_rate, 1),
                "cache_stats": cache_stats,
            }
            # Stocker dans le cache (sans le ``cache_stats`` figé — il est
            # rafraîchi à chaque hit, voir branche hit ci-dessus).
            _overview_cache[days] = (
                {k: v for k, v in payload.items() if k != "cache_stats"},
                now_mono,
            )
            return payload

    async def get_percentiles(self, days: int = WEEK_DAYS) -> Dict[str, float]:
        """Calcule les percentiles P50/P90/P99 pour generation et execution.

        Bug 2026-05-26 (Agent 3 P-2) : avant, pas de LIMIT. Sur 365j × 10k
        req/j = 3.6M rows × 2 floats = 30 MB RAM par appel. Auto-refresh 30s
        × 3 admins = 12 listes en RAM simultanément. Cap à
        ``_PERCENTILES_MAX_SAMPLES`` (50k) : P50/P90/P99 sont statistiquement
        stables au-delà de quelques milliers d'échantillons. ``ORDER BY
        created_at DESC`` garantit qu'on garde les N plus récents — les
        plus représentatifs des changements de stack.

        Bug 2026-05-26 (P-3 CRITIQUE) : cache TTL 25s — voir
        ``_PERF_CACHE_TTL_SECONDS``. Sans cache, 3 admins polling à 30s =
        3 sorts Python de 50k floats / 30s. Avec cache : 1 sort partagé.
        """
        days = min(max(days, 1), 365)
        since = clock.now() - timedelta(days=days)

        now_mono = time.monotonic()
        cached = _percentiles_cache.get(days)
        if cached is not None:
            payload, ts = cached
            if (now_mono - ts) < _PERF_CACHE_TTL_SECONDS:
                return payload

        async with get_session() as session:
            # P-1b (2026-05-26) : dual-source — collecte les samples des 2
            # tables avant sort+percentile. Cap _PERCENTILES_MAX_SAMPLES par
            # table pour borner la RAM (max 2 × 50k = 100k floats — OK).
            result_old = await session.execute(
                select(
                    SearchHistory.execution_time,
                    SearchHistory.generation_time,
                )
                .where(SearchHistory.created_at >= since)
                .order_by(SearchHistory.created_at.desc())
                .limit(_PERCENTILES_MAX_SAMPLES)
            )
            rows_old = result_old.all()

            result_new = await session.execute(
                select(
                    AIPerformanceLog.execution_time,
                    AIPerformanceLog.generation_time,
                )
                .where(AIPerformanceLog.created_at >= since)
                .order_by(AIPerformanceLog.created_at.desc())
                .limit(_PERCENTILES_MAX_SAMPLES)
            )
            rows_new = result_new.all()

            # Union puis sort. Le calcul de percentile sur l'union donne le
            # percentile réel de l'activité agrégée — pas une moyenne des
            # percentiles individuels (qui serait statistiquement incorrect).
            exec_times = sorted(
                [r[0] for r in rows_old if r[0] is not None]
                + [r[0] for r in rows_new if r[0] is not None]
            )
            gen_times = sorted(
                [r[1] for r in rows_old if r[1] is not None]
                + [r[1] for r in rows_new if r[1] is not None]
            )

            payload = {
                "exec_p50": round(_percentile(exec_times, 50), 2),
                "exec_p90": round(_percentile(exec_times, 90), 2),
                "exec_p99": round(_percentile(exec_times, 99), 2),
                "gen_p50": round(_percentile(gen_times, 50), 2),
                "gen_p90": round(_percentile(gen_times, 90), 2),
                "gen_p99": round(_percentile(gen_times, 99), 2),
            }
            _percentiles_cache[days] = (payload, now_mono)
            return payload

    async def get_daily_stats(self, days: int = WEEK_DAYS) -> List[Dict[str, Any]]:
        """Statistiques quotidiennes pour le graphique d'evolution.

        Bug 2026-05-26 (P-1b) : dual-source — agrège les groupements par
        jour sur les 2 tables (SearchHistory legacy + AIPerformanceLog).
        Merge dict-style par day-key, puis pondération des moyennes.
        """
        days = min(max(days, 1), 365)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            result_old = await session.execute(
                select(
                    func.date(SearchHistory.created_at).label("day"),
                    func.count().label("total"),
                    func.sum(case((SearchHistory.success == True, 1), else_=0)).label(  # noqa: E712
                        "successes"
                    ),
                    func.avg(SearchHistory.execution_time).label("avg_exec"),
                    func.avg(SearchHistory.generation_time).label("avg_gen"),
                )
                .where(SearchHistory.created_at >= since)
                .group_by(func.date(SearchHistory.created_at))
            )
            result_new = await session.execute(
                select(
                    func.date(AIPerformanceLog.created_at).label("day"),
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                    func.avg(AIPerformanceLog.execution_time).label("avg_exec"),
                    func.avg(AIPerformanceLog.generation_time).label("avg_gen"),
                )
                .where(AIPerformanceLog.created_at >= since)
                .group_by(func.date(AIPerformanceLog.created_at))
            )

            # Merge par day-key. Accumulateur ``daily[day_str] = {n_old, n_new,
            # ok_old, ok_new, sum_exec, sum_gen}`` puis on calcule la moyenne
            # pondérée à la fin.
            daily: Dict[str, Dict[str, float]] = {}
            for row in result_old.all():
                key = str(row.day)
                bucket = daily.setdefault(
                    key,
                    {
                        "total": 0,
                        "successes": 0,
                        "sum_exec": 0.0,
                        "n_exec": 0,
                        "sum_gen": 0.0,
                        "n_gen": 0,
                    },
                )
                n = row.total or 0
                bucket["total"] += n
                bucket["successes"] += row.successes or 0
                if row.avg_exec is not None and n > 0:
                    bucket["sum_exec"] += float(row.avg_exec) * n
                    bucket["n_exec"] += n
                if row.avg_gen is not None and n > 0:
                    bucket["sum_gen"] += float(row.avg_gen) * n
                    bucket["n_gen"] += n
            for row in result_new.all():
                key = str(row.day)
                bucket = daily.setdefault(
                    key,
                    {
                        "total": 0,
                        "successes": 0,
                        "sum_exec": 0.0,
                        "n_exec": 0,
                        "sum_gen": 0.0,
                        "n_gen": 0,
                    },
                )
                n = row.total or 0
                bucket["total"] += n
                bucket["successes"] += row.successes or 0
                if row.avg_exec is not None and n > 0:
                    bucket["sum_exec"] += float(row.avg_exec) * n
                    bucket["n_exec"] += n
                if row.avg_gen is not None and n > 0:
                    bucket["sum_gen"] += float(row.avg_gen) * n
                    bucket["n_gen"] += n

            output = []
            for day_str in sorted(daily.keys()):
                b = daily[day_str]
                total = int(b["total"])
                successes = int(b["successes"])
                avg_exec = (b["sum_exec"] / b["n_exec"]) if b["n_exec"] > 0 else 0
                avg_gen = (b["sum_gen"] / b["n_gen"]) if b["n_gen"] > 0 else 0
                output.append(
                    {
                        "date": day_str,
                        "total": total,
                        "success": successes,
                        "failed": total - successes,
                        "avg_exec": round(avg_exec, 2),
                        "avg_gen": round(avg_gen, 2),
                    }
                )
            return output

    async def get_time_distribution(self, days: int = WEEK_DAYS) -> Dict[str, int]:
        """Distribution des temps de reponse pour le graphique doughnut."""
        days = min(max(days, 1), 365)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            # P-1b (2026-05-26) : dual-source — agrège les buckets sur les 2
            # tables. Pas de risque RAM (les lignes ne sont pas chargées en
            # liste, on itère le curseur).
            result_old = await session.execute(
                select(
                    SearchHistory.execution_time,
                    SearchHistory.generation_time,
                ).where(
                    SearchHistory.created_at >= since,
                    SearchHistory.execution_time.isnot(None),
                    SearchHistory.generation_time.isnot(None),
                )
            )
            result_new = await session.execute(
                select(
                    AIPerformanceLog.execution_time,
                    AIPerformanceLog.generation_time,
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.execution_time.isnot(None),
                    AIPerformanceLog.generation_time.isnot(None),
                )
            )

            buckets = {"under_1s": 0, "1_to_3s": 0, "3_to_5s": 0, "over_5s": 0}

            def _bucketize(rows_iter):
                for row in rows_iter:
                    total_time = (row[0] or 0) + (row[1] or 0)
                    if total_time < 1:
                        buckets["under_1s"] += 1
                    elif total_time < 3:
                        buckets["1_to_3s"] += 1
                    elif total_time < 5:
                        buckets["3_to_5s"] += 1
                    else:
                        buckets["over_5s"] += 1

            _bucketize(result_old.all())
            _bucketize(result_new.all())

            return buckets

    async def get_recent_queries(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Recupere les requetes recentes avec formatage.

        Bug 2026-05-26 (ADV-2 CRITIQUE — adversarial review) : avant ce fix,
        cette méthode lisait UNIQUEMENT SearchHistory alors que get_overview/
        percentiles/daily/distribution avaient été migrés dual-source (P-1).
        Conséquence : le widget "requêtes récentes" affichait [] quand
        AIPerformanceLog portait le trafic. Maintenant : union des 2 sources,
        tri global, limit.
        """
        limit = min(max(limit, 1), 100)
        async with get_session() as session:
            # Fetch LIMIT par table puis merge in-Python : SQLite ne supporte
            # pas UNION ALL + ORDER BY + LIMIT trivialement avec SQLAlchemy.
            # Au pire 2×limit rows en mémoire = max 200. Trivial.
            result_old = await session.execute(
                select(SearchHistory).order_by(desc(SearchHistory.created_at)).limit(limit)
            )
            rows_old = result_old.scalars().all()
            result_new = await session.execute(
                select(AIPerformanceLog).order_by(desc(AIPerformanceLog.created_at)).limit(limit)
            )
            rows_new = result_new.scalars().all()

            def _format_old(q):
                return {
                    "question": q.question,
                    "success": q.success,
                    "execution_time": q.execution_time,
                    "generation_time": q.generation_time,
                    "total_time": round((q.execution_time or 0) + (q.generation_time or 0), 2),
                    "model_used": q.model_used or "-",
                    "created_at_raw": q.created_at,
                    "created_at": q.created_at.strftime("%d/%m %H:%M") if q.created_at else "-",
                }

            def _format_new(q):
                return {
                    "question": q.question,
                    "success": q.status == QueryStatus.SUCCESS,
                    "execution_time": q.execution_time,
                    "generation_time": q.generation_time,
                    "total_time": round((q.execution_time or 0) + (q.generation_time or 0), 2),
                    "model_used": q.model_name or "-",
                    "created_at_raw": q.created_at,
                    "created_at": q.created_at.strftime("%d/%m %H:%M") if q.created_at else "-",
                }

            merged = [_format_old(q) for q in rows_old] + [_format_new(q) for q in rows_new]

            # Tri global descendant puis cap au limit demandé. ``created_at_raw``
            # est le datetime (pas la string formatée) pour un tri correct.
            #
            # Bug 2026-05-26 (ADV-14) : SQLite stocke les datetime en TEXT
            # SANS tzinfo. Quand SQLAlchemy lit, on récupère un datetime NAIVE.
            # Si une row a ``created_at=None`` (seed script, migration
            # manuelle), le sort crash ``TypeError: can't compare offset-naive
            # and offset-aware`` si le fallback est aware. On normalize TOUS
            # les datetimes en naive AVANT le sort.
            def _sort_key(d):
                v = d.get("created_at_raw")
                if v is None:
                    return datetime.min
                # Strip tzinfo si présent (homogénéise naive vs aware)
                if v.tzinfo is not None:
                    return v.replace(tzinfo=None)
                return v

            merged.sort(key=_sort_key, reverse=True)
            # Purge le champ raw avant retour (pas utile pour le template).
            for d in merged:
                d.pop("created_at_raw", None)
            return merged[:limit]


# Singleton
_service: Optional[PerformanceStatsService] = None


def get_performance_stats_service() -> PerformanceStatsService:
    """Singleton PerformanceStatsService."""
    global _service
    if _service is None:
        _service = PerformanceStatsService()
    return _service
