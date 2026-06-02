"""
Service de statistiques de performance IA.

Fournit les métriques pour le dashboard de performances:
- Taux de réussite global et par modèle
- Temps de réponse (percentiles)
- Comparaison entre modèles
- Évolution dans le temps
- Impact du RAG sur la précision
"""

from typing import Dict, Any, List, Optional
from datetime import timedelta

from sqlalchemy import select, func, case, desc, or_

from app.core import clock
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.models.training_data import TrainingData
from app.models.user import User
from app.core.database import get_session
from app.utils.logger import get_logger
from app.utils.redaction import redact_pii_best_effort

logger = get_logger(__name__)

# Limites de validation des parametres
_MAX_DAYS = 3650
_MAX_LIMIT = 1000

# Bug 2026-05-26 (Agent 3 AI-6) : cap dur sur le nombre de rows chargées en
# RAM pour le calcul P95 latence. Au-delà, P95 est statistiquement stable —
# pas la peine de plomber la RAM avec un dataset 5-ans×N-modèles. 100k rows
# × ~50 bytes (provider+model+float) = ~5 MB max par appel page-load.
_P95_MAX_SAMPLES: int = 100_000


def _is_consumption_row_filter():
    """SSoT filter "vraies consommations LLM" — exclut ``vanna_business_log``.

    Bug 2026-05-26 (AI-4 + ADV-3) : ce caller pose un row "métier" sans
    tokens consommés (juste pour tracer un log applicatif). Inclure dans
    les KPIs créerait un dénominateur biaisé (taux de succès, latence
    moyenne, etc.). Helper module-level extrait pour appliquer le filtre
    sur TOUTES les méthodes du service de manière cohérente (avant ADV-3,
    seules 3/7 méthodes l'appliquaient → divergence inter-widgets).

    Forme SQL : ``caller IS NULL OR caller != 'vanna_business_log'``.
    Le ``IS NULL`` couvre les rows historiques antérieures à
    l'instrumentation ``caller``.
    """
    return or_(
        AIPerformanceLog.caller.is_(None),
        AIPerformanceLog.caller != "vanna_business_log",
    )


class AIStatsService:
    """
    Service de statistiques pour le dashboard performances IA.
    """

    @staticmethod
    def _validate_days(days: int) -> int:
        """Valide et borne le parametre days."""
        if not isinstance(days, int) or days <= 0:
            return 30
        return min(days, _MAX_DAYS)

    @staticmethod
    def _validate_limit(limit: int) -> int:
        """Valide et borne le parametre limit."""
        if not isinstance(limit, int) or limit <= 0:
            return 20
        return min(limit, _MAX_LIMIT)

    async def get_overview(self, days: int = 30) -> Dict[str, Any]:
        """
        Vue d'ensemble des performances IA.

        Args:
            days: Nombre de jours à analyser

        Returns:
            Statistiques globales
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        # Filtre commun : exclut les rows "business-only" (caller=
        # "vanna_business_log"). Bug 2026-05-26 (AI-4) + ADV-16 SSoT —
        # utilise le helper module-level extrait par ADV-3.
        is_consumption_row = _is_consumption_row_filter()

        async with get_session() as session:
            # Total requêtes
            total_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    is_consumption_row,
                )
            )
            total = total_q.scalar() or 0

            # Succès
            success_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.status == QueryStatus.SUCCESS,
                    is_consumption_row,
                )
            )
            successes = success_q.scalar() or 0

            # Depuis le cache
            cache_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == True,  # noqa: E712
                    is_consumption_row,
                )
            )
            cache_hits = cache_q.scalar() or 0

            # Temps moyen
            avg_time_q = await session.execute(
                select(
                    func.avg(AIPerformanceLog.total_time),
                    func.avg(AIPerformanceLog.generation_time),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.status == QueryStatus.SUCCESS,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
            )
            avg_row = avg_time_q.first()
            avg_total = avg_row[0] or 0
            avg_generation = avg_row[1] or 0

            # Feedback positif
            pos_feedback_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.user_feedback == "positive",
                    is_consumption_row,
                )
            )
            positive_feedback = pos_feedback_q.scalar() or 0

            neg_feedback_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.user_feedback == "negative",
                    is_consumption_row,
                )
            )
            negative_feedback = neg_feedback_q.scalar() or 0

            # Requêtes avec RAG
            rag_q = await session.execute(
                select(func.count())
                .select_from(AIPerformanceLog)
                .where(
                    AIPerformanceLog.created_at >= since,
                    (AIPerformanceLog.rag_ddl_count > 0)
                    | (AIPerformanceLog.rag_doc_count > 0)
                    | (AIPerformanceLog.rag_example_count > 0),
                    is_consumption_row,
                )
            )
            rag_count = rag_q.scalar() or 0

            # Tokens totaux
            tokens_q = await session.execute(
                select(
                    func.sum(AIPerformanceLog.total_tokens),
                    func.sum(AIPerformanceLog.prompt_tokens),
                    func.sum(AIPerformanceLog.completion_tokens),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    is_consumption_row,
                )
            )
            tokens_row = tokens_q.first()

            # Training data stats
            training_q = await session.execute(
                select(TrainingData.data_type, func.count().label("count"))
                .where(TrainingData.is_active == True)  # noqa: E712
                .group_by(TrainingData.data_type)
            )
            training_stats = {row[0].value: row[1] for row in training_q.all()}

            success_rate = (successes / total * 100) if total > 0 else 0
            feedback_total = positive_feedback + negative_feedback
            satisfaction_rate = (
                (positive_feedback / feedback_total * 100) if feedback_total > 0 else 0
            )

            return {
                "period_days": days,
                "total_queries": total,
                "successful_queries": successes,
                "success_rate": round(success_rate, 1),
                "cache_hits": cache_hits,
                "cache_rate": round((cache_hits / total * 100) if total > 0 else 0, 1),
                "avg_total_time": round(avg_total, 2),
                "avg_generation_time": round(avg_generation, 2),
                "rag_usage_rate": round((rag_count / total * 100) if total > 0 else 0, 1),
                "positive_feedback": positive_feedback,
                "negative_feedback": negative_feedback,
                "satisfaction_rate": round(satisfaction_rate, 1),
                "total_tokens": tokens_row[0] or 0,
                "prompt_tokens": tokens_row[1] or 0,
                "completion_tokens": tokens_row[2] or 0,
                "training_data": {
                    "ddl": training_stats.get("ddl", 0),
                    "documentation": training_stats.get("documentation", 0),
                    "question_sql": training_stats.get("question_sql", 0),
                    "total": sum(training_stats.values()),
                },
            }

    async def get_model_comparison(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Compare les performances entre modèles.

        Returns:
            Liste des modèles avec métriques
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            result = await session.execute(
                select(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                    func.avg(AIPerformanceLog.generation_time).label("avg_gen_time"),
                    func.avg(AIPerformanceLog.total_time).label("avg_total_time"),
                    func.avg(AIPerformanceLog.total_tokens).label("avg_tokens"),
                    func.sum(
                        case((AIPerformanceLog.user_feedback == "positive", 1), else_=0)
                    ).label("positive_fb"),
                    func.sum(
                        case((AIPerformanceLog.user_feedback == "negative", 1), else_=0)
                    ).label("negative_fb"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    # ADV-3 (2026-05-26) : exclut vanna_business_log pour
                    # cohérence avec get_overview/get_usage_stats.
                    _is_consumption_row_filter(),
                )
                .group_by(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                )
                .order_by(desc("total"))
            )

            models = []
            for row in result.all():
                total = row.total or 0
                successes = row.successes or 0
                pos = row.positive_fb or 0
                neg = row.negative_fb or 0
                fb_total = pos + neg

                models.append(
                    {
                        "provider": row.model_provider,
                        "model": row.model_name,
                        "total_queries": total,
                        "success_rate": round((successes / total * 100) if total > 0 else 0, 1),
                        "avg_generation_time": round(row.avg_gen_time or 0, 2),
                        "avg_total_time": round(row.avg_total_time or 0, 2),
                        "avg_tokens": int(row.avg_tokens or 0),
                        "satisfaction_rate": round(
                            (pos / fb_total * 100) if fb_total > 0 else 0, 1
                        ),
                        "positive_feedback": pos,
                        "negative_feedback": neg,
                    }
                )

            return models

    async def get_daily_stats(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Statistiques quotidiennes pour les graphiques.

        Returns:
            Liste de stats par jour
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            result = await session.execute(
                select(
                    func.date(AIPerformanceLog.created_at).label("day"),
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                    func.avg(AIPerformanceLog.total_time).label("avg_time"),
                    func.sum(
                        case((AIPerformanceLog.user_feedback == "positive", 1), else_=0)
                    ).label("positive"),
                    func.sum(
                        case((AIPerformanceLog.user_feedback == "negative", 1), else_=0)
                    ).label("negative"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    _is_consumption_row_filter(),  # ADV-3 (2026-05-26)
                )
                .group_by(func.date(AIPerformanceLog.created_at))
                .order_by("day")
            )

            return [
                {
                    "date": str(row.day),
                    "total": row.total or 0,
                    "successes": row.successes or 0,
                    "success_rate": round(((row.successes or 0) / (row.total or 1)) * 100, 1),
                    "avg_time": round(row.avg_time or 0, 2),
                    "positive_feedback": row.positive or 0,
                    "negative_feedback": row.negative or 0,
                }
                for row in result.all()
            ]

    async def get_error_breakdown(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Répartition des erreurs par type.
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            result = await session.execute(
                select(
                    AIPerformanceLog.status,
                    func.count().label("count"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.status != QueryStatus.SUCCESS,
                    _is_consumption_row_filter(),  # ADV-3 (2026-05-26)
                )
                .group_by(AIPerformanceLog.status)
                .order_by(desc("count"))
            )

            return [
                {
                    "status": row.status.value,
                    "count": row.count,
                }
                for row in result.all()
            ]

    @staticmethod
    def _redact_feedback_comment(comment: Optional[str]) -> Optional[str]:
        """Redacte un ``feedback_comment`` user libre avant exposition admin.

        Bug 2026-05-26 (Agent 3 brainstorm AI-3) : ``feedback_comment`` est
        un texte libre saisi par l'utilisateur (ex: "le client X paie en
        retard"). Affiché tel quel dans le ``title=`` du badge feedback
        sur ``/admin/ai-performance``, il leak des PII vers TOUS les admins.

        SSoT 2026-05-26 (AI-2) : la logique est centralisée dans
        :func:`app.utils.redaction.redact_pii_best_effort`. Cette méthode
        reste l'API publique du service mais délègue au helper SSoT.
        """
        return redact_pii_best_effort(comment)

    async def get_recent_queries(
        self,
        limit: int = 20,
        status: Optional[str] = None,
        model_name: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Récupère les requêtes récentes (avec redaction PII feedback).

        Bug 2026-05-26 (AI-13 MOYEN) : avant ce fix, le handler ne supportait
        que ``status``. L'admin ne pouvait pas filtrer par modèle ou user
        pour investiguer les anomalies (ex: « Pourquoi user X a-t-il 30%
        d'échecs sur claude-haiku ? »).
        Fix : ajout des params ``model_name`` (exact match sur ``model_name``)
        et ``user_id`` (filtre user_id strict).
        """
        limit = self._validate_limit(limit)
        async with get_session() as session:
            query = select(AIPerformanceLog).order_by(AIPerformanceLog.created_at.desc())

            if status:
                try:
                    query = query.where(AIPerformanceLog.status == QueryStatus(status))
                except ValueError:
                    return []  # Invalid status → no results

            if model_name:
                # Exact match : l'admin choisit dans une liste = pas de risque
                # de typo. Pas de LIKE (anti-DoS par wildcard).
                query = query.where(AIPerformanceLog.model_name == model_name)

            if user_id is not None:
                query = query.where(AIPerformanceLog.user_id == user_id)

            query = query.limit(limit)
            result = await session.execute(query)
            logs = result.scalars().all()

            # Bug 2026-05-26 (AI-3) : redacte ``feedback_comment`` avant
            # exposition admin pour éviter leak PII via title= du badge UI.
            output: List[Dict[str, Any]] = []
            for log in logs:
                d = log.to_dict()
                if "feedback_comment" in d:
                    d["feedback_comment"] = self._redact_feedback_comment(d["feedback_comment"])
                output.append(d)
            return output

    async def get_usage_stats(self, days: int = 30) -> Dict[str, Any]:
        """
        Statistiques de consommation API : tokens, coûts estimés, par modèle,
        par feature (caller) et par jour.

        Source : ``AIPerformanceLog`` — alimenté par le hook central
        ``llm_call_tracker`` à chaque appel LLM (Iris, sync, copilote,
        automations, anonymizer, dashboards, reporting, …). Cf.
        ``app/services/ai/llm_call_tracker.py``.

        Coût : utilise ``cost_usd_snapshot`` (figé à l'écriture) en
        priorité, fallback recompute via pricing courant si NULL.
        Distinction NULL vs 0 : NULL = modèle non priced à l'époque,
        0.0 = vraiment 0$ (rare). On warne explicitement les modèles
        non priced pour pousser l'admin à les configurer.

        Filtre ``vanna_business_log`` : ce caller pose un row "métier"
        (sql_generated, RAG counts) sans tokens — on l'exclut des stats
        de consommation pour éviter de gonfler le compte de requêtes
        sans contrepartie tokens.
        """
        from app.constants_ai import get_pricing_for_model

        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        # Filtre commun (ADV-16 SSoT) : exclut les rows "business-only"
        # via le helper module-level. Doc complète sur le helper.
        is_consumption_row = _is_consumption_row_filter()

        async with get_session() as session:
            # Totaux globaux
            totals_q = await session.execute(
                select(
                    func.count().label("total_requests"),
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.total_tokens).label("total_tokens"),
                    func.sum(AIPerformanceLog.cost_usd_snapshot).label("cost_snapshot"),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
            )
            totals = totals_q.first()

            # Par modèle — enrichi avec latence (avg/max via SQL, P95
            # calculé en Python car SQLite n'a pas PERCENTILE_CONT) +
            # breakdown tokens cache_read/cache_creation/thinking
            # (P3 #18 + #20). Champs `latency_*` et `*_tokens_extra`
            # ajoutés en backward-compat (les anciens consommateurs
            # n'utilisent pas ces clés).
            by_model_q = await session.execute(
                select(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                    func.count().label("requests"),
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.total_tokens).label("total_tokens"),
                    func.sum(AIPerformanceLog.cost_usd_snapshot).label("cost_snapshot"),
                    # Latence — avg + max via SQL. AVG SQLite ignore les
                    # NULL automatiquement, mais COUNT() inclut les NULL,
                    # donc avg(NULL) ne vient PAS plomber la moyenne.
                    # Cohérence avec le P95 Python qui filtre `isnot(None)`
                    # plus bas — sinon avg/p95 divergeraient silencieusement
                    # (P95 < avg = mathématiquement impossible mais visible
                    # dans les data si bases différentes).
                    func.avg(AIPerformanceLog.total_time).label("latency_avg"),
                    func.max(AIPerformanceLog.total_time).label("latency_max"),
                    # Breakdown tokens — déjà stocké, jamais affiché jusqu'ici
                    func.sum(AIPerformanceLog.cache_read_tokens).label("cache_read_tokens"),
                    func.sum(AIPerformanceLog.cache_creation_tokens).label("cache_creation_tokens"),
                    func.sum(AIPerformanceLog.thinking_tokens).label("thinking_tokens"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
                .group_by(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                )
                .order_by(desc("total_tokens"))
            )

            # P95 latence par modèle — SQLite n'a pas PERCENTILE_CONT, on
            # calcule en Python via ``statistics.quantiles``. Récupère
            # uniquement la colonne ``total_time`` (un float par row,
            # léger en mémoire — sur 100K rows ~800 KB).
            #
            # Bug 2026-05-26 (Agent 3 AI-6) : avant, pas de LIMIT. À 365j
            # × 1M req = 8 MB OK aujourd'hui mais pas borné. Sur 5 ans à
            # 10 req/s, ça monterait à ~100 MB en RAM par appel page-load.
            # Cap à _P95_MAX_SAMPLES (100k) : P95 reste statistiquement
            # stable au-delà de quelques milliers d'échantillons —
            # économie RAM massive sans dégrader la métrique.
            # ``ORDER BY created_at DESC`` garantit qu'on garde les N plus
            # récents (les plus représentatifs des changements de stack).
            p95_q = await session.execute(
                select(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                    AIPerformanceLog.total_time,
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712,
                    is_consumption_row,
                    AIPerformanceLog.total_time.isnot(None),
                )
                .order_by(AIPerformanceLog.created_at.desc())
                .limit(_P95_MAX_SAMPLES)
            )
            p95_buckets: Dict[tuple, List[float]] = {}
            for row in p95_q.all():
                key = (row.model_provider, row.model_name)
                p95_buckets.setdefault(key, []).append(float(row.total_time))

            # by_model_q a SUM(cost_usd_snapshot) — mais si UNE row du
            # group a snapshot NULL, elle n'est pas comptée dans la somme.
            # Pour récupérer la part NULL, on fait une seconde query qui
            # somme les tokens uniquement pour les rows snapshot=NULL.
            # IMPORTANT : on charge les **5 buckets** (prompt + cache_read +
            # cache_creation + completion + thinking) pour aligner le
            # recompute sur la formule canonique du hook
            # ``_compute_cost_snapshot`` (cf. ``llm_call_tracker.py:286-291``).
            # Sans cache_creation, le recompute sous-estime silencieusement
            # le coût (Anthropic facture cache_creation à 125% du prix input).
            # Bug catché par adversarial 2026-05-15 (P3 #20 BLOQUANT).
            null_snapshot_q = await session.execute(
                select(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.cache_read_tokens).label("cache_read"),
                    func.sum(AIPerformanceLog.cache_creation_tokens).label("cache_creation"),
                    func.sum(AIPerformanceLog.thinking_tokens).label("thinking"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                    AIPerformanceLog.cost_usd_snapshot.is_(None),
                )
                .group_by(
                    AIPerformanceLog.model_provider,
                    AIPerformanceLog.model_name,
                )
            )
            null_by_model: Dict[tuple, Dict[str, int]] = {
                (r.model_provider, r.model_name): {
                    "prompt": r.prompt_tokens or 0,
                    "completion": r.completion_tokens or 0,
                    "cache_read": r.cache_read or 0,
                    "cache_creation": r.cache_creation or 0,
                    "thinking": r.thinking or 0,
                }
                for r in null_snapshot_q.all()
            }

            models = []
            total_cost = 0.0
            warned_unknown: set[str] = set()
            for row in by_model_q.all():
                p_tok = row.prompt_tokens or 0
                c_tok = row.completion_tokens or 0
                # Coût total = snapshots somme déjà fait par SQL +
                # recompute pour les rows snapshot=NULL via pricing courant.
                snapshot_cost = float(row.cost_snapshot or 0.0)
                null_buckets = null_by_model.get((row.model_provider, row.model_name))
                recomputed_cost = 0.0
                if null_buckets:
                    pricing = get_pricing_for_model(row.model_name)
                    if pricing is None:
                        if row.model_name and row.model_name not in warned_unknown:
                            logger.warning(
                                "Pricing inconnu pour modèle %r — coût recompute "
                                "à 0 pour rows snapshot=NULL. Configurer le prix "
                                "via /admin/ai-models pour refléter la réalité.",
                                row.model_name,
                            )
                            warned_unknown.add(row.model_name)
                        pricing = {"input": 0.0, "output": 0.0}
                    # MÊME formule que le hook ``_compute_cost_snapshot`` —
                    # 5 buckets distincts car cache_creation et cache_read
                    # ont des prix différents (Anthropic : cache_creation =
                    # 125% input, cache_read = 10% input). Si on agrège
                    # cache_creation dans input on sous-estime de ~25% le
                    # coût pour les sessions cache-heavy.
                    input_price = float(pricing.get("input", 0.0))
                    output_price = float(pricing.get("output", 0.0))
                    cache_read_price = float(pricing.get("cache_read", 0.0)) or input_price
                    cache_creation_price = float(pricing.get("cache_creation", 0.0)) or input_price
                    recomputed_cost = (
                        null_buckets["prompt"] * input_price / 1_000_000
                        + null_buckets["cache_read"] * cache_read_price / 1_000_000
                        + null_buckets["cache_creation"] * cache_creation_price / 1_000_000
                        + (null_buckets["completion"] + null_buckets["thinking"])
                        * output_price
                        / 1_000_000
                    )
                cost = snapshot_cost + recomputed_cost
                total_cost += cost
                # Ne pas afficher les modèles sans tokens enregistrés
                if (row.total_tokens or 0) == 0:
                    continue
                # P95 latence : calculé en Python sur la liste des
                # total_time du modèle. Fallback ``None`` si <2 samples
                # (statistics.quantiles requiert ≥2). Évite plantage
                # silencieux sur modèle avec 1 seul appel.
                key = (row.model_provider, row.model_name)
                samples = p95_buckets.get(key, [])
                p95_value: Optional[float] = None
                if len(samples) >= 2:
                    try:
                        # n=20 → quantile index 18 = P95 (0-indexed = P5,P10,...,P95)
                        import statistics

                        quantiles_20 = statistics.quantiles(samples, n=20)
                        p95_value = round(float(quantiles_20[18]), 3)
                    except statistics.StatisticsError:
                        p95_value = None
                elif len(samples) == 1:
                    p95_value = round(samples[0], 3)
                models.append(
                    {
                        "provider": row.model_provider or "",
                        "model": row.model_name or "",
                        "requests": row.requests or 0,
                        "prompt_tokens": p_tok,
                        "completion_tokens": c_tok,
                        "total_tokens": row.total_tokens or 0,
                        "estimated_cost_usd": round(cost, 4),
                        # P3 #18 — latence (secondes)
                        "latency_avg_s": round(float(row.latency_avg or 0.0), 3),
                        "latency_p95_s": p95_value,
                        "latency_max_s": round(float(row.latency_max or 0.0), 3),
                        # P3 #20 — breakdown tokens (cache + thinking)
                        "cache_read_tokens": int(row.cache_read_tokens or 0),
                        "cache_creation_tokens": int(row.cache_creation_tokens or 0),
                        "thinking_tokens": int(row.thinking_tokens or 0),
                    }
                )

            # Par caller (NEW — breakdown "consommation par feature").
            # Permet à l'admin de voir où partent les tokens : Iris, sync,
            # copilote, automations, dashboards, reporting, …
            # Enrichi avec breakdown des erreurs séparé en 2 catégories
            # (review adversariale 2026-05-15 P3 #19) :
            #   - ``llm_errors`` = LLM_ERROR + TIMEOUT (vraies erreurs LLM
            #     côté provider — modèle/réseau/timeout). Signal pour
            #     l'admin "le LLM dégrade". Affiché comme badge.
            #   - ``business_errors`` = VALIDATION_ERROR + EXECUTION_ERROR
            #     (le LLM a fait son taf mais le SQL a échoué côté Sage,
            #     ou la validation post-LLM a refusé). Pas une faute du
            #     modèle — info détaillée mais pas badgée.
            # Sans cette distinction, un admin voit "iris_main 8% err"
            # et change de modèle alors que c'est Sage qui rejette.
            by_caller_q = await session.execute(
                select(
                    AIPerformanceLog.caller,
                    func.count().label("requests"),
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.total_tokens).label("total_tokens"),
                    func.sum(AIPerformanceLog.cost_usd_snapshot).label("cost_snapshot"),
                    # Vraies erreurs LLM (provider down, timeout, modèle KO)
                    func.sum(
                        case(
                            (
                                AIPerformanceLog.status.in_(
                                    [QueryStatus.LLM_ERROR, QueryStatus.TIMEOUT]
                                ),
                                1,
                            ),
                            else_=0,
                        )
                    ).label("llm_errors"),
                    # Erreurs métier (LLM a généré quelque chose mais
                    # validation/exécution a échoué — typiquement SQL
                    # mal formé pour la BDD source).
                    func.sum(
                        case(
                            (
                                AIPerformanceLog.status.in_(
                                    [
                                        QueryStatus.VALIDATION_ERROR,
                                        QueryStatus.EXECUTION_ERROR,
                                    ]
                                ),
                                1,
                            ),
                            else_=0,
                        )
                    ).label("business_errors"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
                .group_by(AIPerformanceLog.caller)
                .order_by(desc("total_tokens"))
            )
            callers: List[Dict[str, Any]] = []
            for row in by_caller_q.all():
                if (row.total_tokens or 0) == 0 and not row.caller:
                    continue
                requests_count = row.requests or 0
                llm_err = int(row.llm_errors or 0)
                biz_err = int(row.business_errors or 0)
                # Taux d'erreur LLM = signal pour le badge UI. Calculé
                # uniquement si on a un échantillon significatif (≥5
                # requêtes) pour éviter "100% err" sur 1 timeout aléatoire.
                # Cf. doctrine SLO observability (Honeycomb, Datadog).
                if requests_count >= 5:
                    llm_error_rate_pct: Optional[float] = round((llm_err / requests_count) * 100, 1)
                else:
                    llm_error_rate_pct = None  # Trop peu de samples → no-verdict
                callers.append(
                    {
                        "caller": row.caller or "(non attribué)",
                        "requests": requests_count,
                        "prompt_tokens": row.prompt_tokens or 0,
                        "completion_tokens": row.completion_tokens or 0,
                        "total_tokens": row.total_tokens or 0,
                        "estimated_cost_usd": round(float(row.cost_snapshot or 0.0), 4),
                        # P3 #19 — séparation vraies erreurs LLM vs erreurs
                        # métier (cf. review 2026-05-15)
                        "llm_errors": llm_err,
                        "business_errors": biz_err,
                        "llm_error_rate_pct": llm_error_rate_pct,
                    }
                )

            # Par jour (pour le graphique)
            daily_q = await session.execute(
                select(
                    func.date(AIPerformanceLog.created_at).label("day"),
                    func.count().label("requests"),
                    func.sum(AIPerformanceLog.total_tokens).label("tokens"),
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.cost_usd_snapshot).label("cost_snapshot"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
                .group_by(func.date(AIPerformanceLog.created_at))
                .order_by("day")
            )

            daily = []
            for row in daily_q.all():
                daily.append(
                    {
                        "date": str(row.day),
                        "requests": row.requests or 0,
                        "tokens": row.tokens or 0,
                        "prompt_tokens": row.prompt_tokens or 0,
                        "completion_tokens": row.completion_tokens or 0,
                        "estimated_cost_usd": round(float(row.cost_snapshot or 0.0), 4),
                    }
                )

            # Total cost : la somme par modèle ``total_cost`` est déjà
            # snapshot + recompute_for_NULL → c'est la vraie valeur.
            # ``totals.cost_snapshot`` ignorerait les NULLs (sous-comptage)
            # — on ne l'utilise plus comme source de vérité.
            #
            # Bug 2026-05-26 (Agent 3 AI-5 critique — denial-of-wallet caché) :
            # avant, les modèles non-priced (``pricing is None``) donnaient
            # un recompute à 0$ silencieux. Seul un warning log mentionnait
            # le problème — l'admin sur le dashboard voyait juste un coût
            # sous-estimé sans signal. Maintenant on propage la liste des
            # modèles non-priced (``unknown_pricing_models``) dans la réponse
            # pour que le handler/template puisse alerter l'admin et le
            # rediriger vers ``/admin/ai-models`` pour configurer le prix.
            return {
                "period_days": days,
                "total_requests": totals.total_requests or 0,
                "prompt_tokens": totals.prompt_tokens or 0,
                "completion_tokens": totals.completion_tokens or 0,
                "total_tokens": totals.total_tokens or 0,
                "estimated_total_cost_usd": round(total_cost, 4),
                "unknown_pricing_models": sorted(warned_unknown),
                "by_model": models,
                "by_caller": callers,
                "daily": daily,
            }

    async def get_usage_by_user(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Consommation API par utilisateur : requêtes, tokens, coût estimé.
        Permet à l'admin d'identifier qui consomme le plus.
        """
        from app.constants_ai import get_pricing_for_model

        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            result = await session.execute(
                select(
                    AIPerformanceLog.user_id,
                    User.username,
                    func.count().label("requests"),
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.total_tokens).label("total_tokens"),
                    func.avg(AIPerformanceLog.total_time).label("avg_time"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                )
                .outerjoin(User, AIPerformanceLog.user_id == User.id)
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                )
                .group_by(AIPerformanceLog.user_id, User.username)
                .order_by(desc("total_tokens"))
            )

            # Calcul de coût par utilisateur. Priorité au snapshot figé,
            # recompute via pricing courant uniquement pour les rows
            # snapshot=NULL. Formule alignée avec ``_compute_cost_snapshot``
            # (input = prompt + cache_read, output = completion + thinking)
            # pour cohérence entre snapshot et recompute.
            cost_snap_q = await session.execute(
                select(
                    AIPerformanceLog.user_id,
                    func.sum(AIPerformanceLog.cost_usd_snapshot).label("snap_cost"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                )
                .group_by(AIPerformanceLog.user_id)
            )
            user_costs: Dict[int, float] = {
                (r.user_id or 0): float(r.snap_cost or 0.0) for r in cost_snap_q.all()
            }

            # Recompute pour les rows snapshot=NULL.
            # 5 buckets distincts (cf. ``get_usage_stats`` plus haut et
            # ``_compute_cost_snapshot`` du hook) — sinon sous-estimation
            # silencieuse du coût pour les sessions cache-heavy.
            cost_q = await session.execute(
                select(
                    AIPerformanceLog.user_id,
                    AIPerformanceLog.model_name,
                    func.sum(AIPerformanceLog.prompt_tokens).label("prompt_tokens"),
                    func.sum(AIPerformanceLog.completion_tokens).label("completion_tokens"),
                    func.sum(AIPerformanceLog.cache_read_tokens).label("cache_read"),
                    func.sum(AIPerformanceLog.cache_creation_tokens).label("cache_creation"),
                    func.sum(AIPerformanceLog.thinking_tokens).label("thinking"),
                )
                .where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    AIPerformanceLog.cost_usd_snapshot.is_(None),
                )
                .group_by(AIPerformanceLog.user_id, AIPerformanceLog.model_name)
            )
            for crow in cost_q.all():
                uid = crow.user_id or 0
                pricing = get_pricing_for_model(crow.model_name) or {
                    "input": 0.0,
                    "output": 0.0,
                }
                input_price = float(pricing.get("input", 0.0))
                output_price = float(pricing.get("output", 0.0))
                cache_read_price = float(pricing.get("cache_read", 0.0)) or input_price
                cache_creation_price = float(pricing.get("cache_creation", 0.0)) or input_price
                cost = (
                    (crow.prompt_tokens or 0) * input_price / 1_000_000
                    + (crow.cache_read or 0) * cache_read_price / 1_000_000
                    + (crow.cache_creation or 0) * cache_creation_price / 1_000_000
                    + ((crow.completion_tokens or 0) + (crow.thinking or 0))
                    * output_price
                    / 1_000_000
                )
                user_costs[uid] = user_costs.get(uid, 0.0) + cost

            users = []
            for row in result.all():
                uid = row.user_id or 0
                total = row.requests or 0
                successes = row.successes or 0
                users.append(
                    {
                        "user_id": row.user_id,
                        "username": row.username or "Système",
                        "requests": total,
                        "prompt_tokens": row.prompt_tokens or 0,
                        "completion_tokens": row.completion_tokens or 0,
                        "total_tokens": row.total_tokens or 0,
                        "estimated_cost_usd": round(user_costs.get(uid, 0.0), 4),
                        "avg_time": round(row.avg_time or 0, 2),
                        "success_rate": round((successes / total * 100) if total > 0 else 0, 1),
                    }
                )

            return users

    async def get_dashboard_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Métriques additionnelles pour le dashboard ``/admin/ai-config`` :

        - **Budget mensuel** : compare la dépense du mois courant à
          ``KOMPTIA_LLM_BUDGET_USD_MONTH`` (env var, optionnel). Retourne
          ``{budget_usd, spent_usd, percent, status}`` où status =
          ``"unset"|"ok"|"warning"|"exceeded"``. Seuil warning = 80%.
          **TZ : mois calendaire UTC** (aligné sur la facturation cloud
          providers — Anthropic/OpenAI facturent en UTC). Côté France
          (UTC+1/+2), peut décaler de 1-2h aux changements de mois.
          C'est documenté dans le tooltip UI.
        - **Fallback compteur** : nombre d'appels qui ont basculé sur le
          LLM local (``model_provider="local"`` dans ``AIPerformanceLog``)
          sur les ``days`` derniers jours. Permet à l'admin de savoir si
          Ollama a déjà servi.

        Endpoint exposé : ``GET /api/ai/usage`` enrichi
        (cf. ``AIUsageAPIHandler``).

        Note champ ORM : la colonne BDD s'appelle ``model_provider``
        (cf. ``app/models/ai_performance.py:60``), PAS ``provider_name``
        (qui est juste le paramètre de fonction du tracker, mappé vers
        ``model_provider`` à l'écriture). Bug catché par adversarial
        review 2026-05-15.
        """
        import os

        days = self._validate_days(days)

        # Filtre commun (ADV-16 SSoT) : exclut les rows "business-only"
        # via le helper module-level. Garantit la cohérence avec banner
        # "budget mensuel" et KPI "Coût total".
        is_consumption_row = _is_consumption_row_filter()

        # ---- Fallback compteur (sur la fenêtre `days`) ----
        # Bug 2026-05-26 (Agent 3 AI-1) : avant, ``model_provider == "local"``
        # hardcodé. Si l'admin renomme le provider local fallback via
        # ``register_local_fallback(..., name="ollama_3b")``, le compteur
        # cassait silencieusement. Maintenant lit dynamiquement le nom via
        # ``get_local_provider_name()`` + rétro-compat des rows historiques
        # écrites avec ``"local"`` via ``IN ({current_name, "local"})``.
        from app.services.ai.llm_providers import get_llm_manager

        local_provider_name = get_llm_manager().get_local_provider_name()
        # Set pour dédup si current_name == "local" (cas par défaut).
        fallback_provider_names = {local_provider_name, "local"}

        since_days = clock.now() - timedelta(days=days)
        async with get_session() as session:
            fb_count_q = await session.execute(
                select(func.count()).where(
                    AIPerformanceLog.created_at >= since_days,
                    AIPerformanceLog.model_provider.in_(fallback_provider_names),
                )
            )
            fallback_count = int(fb_count_q.scalar() or 0)

            # Last fallback timestamp (UTC) — utile pour "dernier fallback :
            # il y a X heures" côté UI. None si jamais déclenché.
            fb_last_q = await session.execute(
                select(func.max(AIPerformanceLog.created_at)).where(
                    AIPerformanceLog.model_provider.in_(fallback_provider_names),
                )
            )
            last_fallback_at = fb_last_q.scalar()

            # ---- Budget mensuel (calendar month UTC) ----
            now = clock.now()
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            spent_q = await session.execute(
                select(func.sum(AIPerformanceLog.cost_usd_snapshot)).where(
                    AIPerformanceLog.created_at >= month_start,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    is_consumption_row,
                )
            )
            spent_usd = float(spent_q.scalar() or 0.0)

        # Lecture env var avec fallback safe (str invalide → unset).
        budget_raw = os.environ.get("KOMPTIA_LLM_BUDGET_USD_MONTH")
        budget_usd: Optional[float] = None
        try:
            if budget_raw is not None and budget_raw.strip():
                parsed = float(budget_raw)
                if parsed > 0:
                    budget_usd = parsed
        except (ValueError, TypeError):
            budget_usd = None

        if budget_usd is None:
            budget_status = "unset"
            budget_percent: Optional[float] = None
        else:
            budget_percent = round((spent_usd / budget_usd) * 100, 1)
            if spent_usd >= budget_usd:
                budget_status = "exceeded"
            elif budget_percent >= 80:
                budget_status = "warning"
            else:
                budget_status = "ok"

        return {
            "monthly_budget": {
                "budget_usd": budget_usd,
                "spent_usd": round(spent_usd, 4),
                "percent": budget_percent,
                "status": budget_status,
                "month_start_iso": month_start.isoformat(),
            },
            "fallback": {
                "count_period": fallback_count,
                "period_days": days,
                "last_at_iso": (last_fallback_at.isoformat() if last_fallback_at else None),
            },
        }

    async def get_rag_impact(self, days: int = 30) -> Dict[str, Any]:
        """
        Mesure l'impact du RAG sur les performances.

        Compare les requêtes avec et sans contexte RAG.
        """
        days = self._validate_days(days)
        since = clock.now() - timedelta(days=days)

        async with get_session() as session:
            # Avec RAG (au moins un item RAG)
            with_rag = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                    func.avg(AIPerformanceLog.generation_time).label("avg_time"),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    (AIPerformanceLog.rag_example_count > 0)
                    | (AIPerformanceLog.rag_ddl_count > 0)
                    | (AIPerformanceLog.rag_doc_count > 0),
                    _is_consumption_row_filter(),  # ADV-3 (2026-05-26)
                )
            )

            # Sans RAG
            without_rag = await session.execute(
                select(
                    func.count().label("total"),
                    func.sum(
                        case((AIPerformanceLog.status == QueryStatus.SUCCESS, 1), else_=0)
                    ).label("successes"),
                    func.avg(AIPerformanceLog.generation_time).label("avg_time"),
                ).where(
                    AIPerformanceLog.created_at >= since,
                    AIPerformanceLog.from_cache == False,  # noqa: E712
                    AIPerformanceLog.rag_example_count == 0,
                    AIPerformanceLog.rag_ddl_count == 0,
                    AIPerformanceLog.rag_doc_count == 0,
                    _is_consumption_row_filter(),  # ADV-3 (2026-05-26)
                )
            )

            wr = with_rag.first()
            wor = without_rag.first()

            return {
                "with_rag": {
                    "total": wr.total or 0,
                    "success_rate": round(((wr.successes or 0) / (wr.total or 1)) * 100, 1),
                    "avg_time": round(wr.avg_time or 0, 2),
                },
                "without_rag": {
                    "total": wor.total or 0,
                    "success_rate": round(((wor.successes or 0) / (wor.total or 1)) * 100, 1),
                    "avg_time": round(wor.avg_time or 0, 2),
                },
            }


# Singleton
_stats_service: Optional[AIStatsService] = None


def get_ai_stats_service() -> AIStatsService:
    """Singleton AIStatsService."""
    global _stats_service
    if _stats_service is None:
        _stats_service = AIStatsService()
    return _stats_service
