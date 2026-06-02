"""Handlers du dashboard de *performance applicative* (non-IA).

Distinct de :class:`app.handlers.ai_admin.AIPerformanceDashboardHandler`, qui
couvre les métriques de l'agent IA. Ce module agrège l'état du process, du
stockage local, de la BDD source (Sage ou équivalent), du cache de génération
SQL, de la santé des providers LLM et de l'activité système — tout ce qui
permet à un admin de diagnostiquer la plateforme *autour* de l'IA.

Règles de conception
--------------------
1. **Thin presenter** — aucun I/O BDD direct. Les données proviennent de
   :class:`app.services.performance_stats_service.PerformanceStatsService` et
   :class:`app.services.system_health_service.SystemHealthService`, qui sont
   déjà fail-safe.
2. **Fallback neutre** — si un appel service échoue (SQL error, timeout), le
   handler construit un dict de structure garantie (``_EMPTY_*``) plutôt que
   de planter le template.
3. **Rate-limit réutilisable** — les boutons "Tester maintenant" sont
   protégés par l'implémentation partagée :class:`RateLimiter` (sliding
   window, thread-safe, cleanup automatique). Pas de dict module-level muté
   à la main — évite la fuite mémoire long-running (CWE-400).
4. **Fail-closed** — un utilisateur sans ``id`` (cas anormal en session
   valide, defense-in-depth) ne contourne **jamais** le cooldown ; l'appel
   est bloqué avec un message générique.
5. **Sémantique HTTP** — les erreurs serveur renvoient ``500`` (pas 200 avec
   ``success=false``) pour que les sondes/APM détectent correctement
   l'incident.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Final, TypedDict

from sqlalchemy.exc import SQLAlchemyError

from app.constants import DASHBOARD_PERIODS_DAYS, DEFAULT_DASHBOARD_PERIOD_DAYS
from app.core import clock
from app.handlers.base import BaseHandler, admin_required
from app.services.performance_stats_service import get_performance_stats_service
from app.services.query_cache import get_cache
from app.services.system_health_service import get_system_health_service
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.template_helpers import to_dict_object

logger = get_logger(__name__)


# ── Constantes de configuration UI ────────────────────────────────────────

#: Périodes d'analyse proposées dans l'UI (jours). SSoT :
#: ``app.constants.DASHBOARD_PERIODS_DAYS`` — partagée avec
#: ``ai_admin.py``. Bug 2026-05-26 (AI-11) : avant, dupliquée ici et là.
#: Test garde ``tests/unit/test_dashboard_periods_ssot.py`` verrouille
#: l'alignement.
_ALLOWED_PERIODS: Final[tuple[int, ...]] = DASHBOARD_PERIODS_DAYS
_DEFAULT_PERIOD: Final[int] = DEFAULT_DASHBOARD_PERIOD_DAYS

#: Délai minimum entre deux pings manuels d'un même utilisateur. Protège la
#: BDD source et les providers LLM d'un admin (ou d'un script authentifié
#: admin) qui spammerait le bouton « Tester maintenant ».
_PING_COOLDOWN_SECONDS: Final[int] = 5

#: Rate limiter partagé pour les endpoints de ping manuels. Une seule
#: instance pour tous les ``kind`` — la clé ``"{user_id}:{kind}"`` suffit à
#: isoler les cooldowns Sage vs LLM par utilisateur.
_ping_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limiter pour ``CacheClearHandler.post``. Bug 2026-05-26 (Agent 3
#: P-5 moyen) : avant, aucun rate-limit → un XSS dans une autre page admin
#: pouvait POSTer ``/api/cache/clear`` en boucle (XSRF est posé automatiquement
#: par le cookie). Cap : 3 clears / 5 min / user. Suffit pour les usages
#: légitimes (test admin) et bloque un script qui spammerait.
_cache_clear_rate_limiter: Final[RateLimiter] = RateLimiter()
_CACHE_CLEAR_MAX_REQUESTS: Final[int] = 3
_CACHE_CLEAR_WINDOW_SECONDS: Final[int] = 300

# ── Seuils de recommandations ─────────────────────────────────────────────
# Valeurs issues des SLA internes discutés avec l'équipe produit. Toute
# modification doit passer par une revue — ce sont des indicateurs
# "tolérance opérationnelle", pas des constantes techniques.

#: Cache hit rate considéré « excellent » (vert UI).
_CACHE_HIT_EXCELLENT_PCT: Final[int] = 50
#: Cache hit rate considéré « acceptable » (orange UI). En-dessous = rouge.
_CACHE_HIT_ACCEPTABLE_PCT: Final[int] = 30
#: Seuil p99 exécution SQL au-delà duquel on recommande un audit.
_EXEC_P99_ALERT_SECONDS: Final[float] = 10.0
#: Taux d'échec automations déclenchant une alerte.
_EXECUTIONS_FAILURE_ALERT_PCT: Final[float] = 10.0
#: Taux d'échec emails déclenchant une alerte SMTP.
_EMAILS_FAILURE_ALERT_PCT: Final[float] = 5.0
#: Échantillon minimum pour calculer un taux fiable. Bug 2026-05-26 (P-10) :
#: sans seuil, 1 échec sur 3 executions = 33% = alerte (faux positif).
#: Pratique SLO (Honeycomb/Datadog) : N >= 5. Aligné côté AI sur
#: ``app/services/ai/stats_service.py:665`` (``requests_count >= 5``).
_MIN_SAMPLES_FOR_RATE_ALERT: Final[int] = 5


# ── TypedDict : contrats explicites entre services et template ────────────


class _CacheStats(TypedDict, total=False):
    hits: int
    misses: int
    size: int
    max_size: int
    hit_rate: float
    ttl_seconds: int


class _OverviewDict(TypedDict, total=False):
    period_days: int
    total_searches: int
    successful_searches: int
    success_rate: float
    recent_count: int
    avg_execution: float
    avg_generation: float
    under_10s_rate: float
    cache_stats: _CacheStats


class _PercentilesDict(TypedDict, total=False):
    exec_p50: float
    exec_p90: float
    exec_p99: float
    gen_p50: float
    gen_p90: float
    gen_p99: float


class _ActivityDict(TypedDict, total=False):
    period_days: int
    audit_events: int
    emails_sent: int
    emails_failed: int
    emails_failure_rate: float
    executions_total: int
    executions_failed: int
    executions_failure_rate: float
    searches_total: int


class _Recommendation(TypedDict):
    level: str  # "warning" | "success"
    text: str


class _OverallStatus(TypedDict):
    level: str  # "ok" | "warning" | "critical"
    label: str
    sublabel: str
    alert_count: int
    banner_class: str
    dot_class: str
    badge_class: str


# ── Valeurs neutres garanties pour le template (mode dégradé) ─────────────

_EMPTY_OVERVIEW: Final[_OverviewDict] = {
    "period_days": _DEFAULT_PERIOD,
    "total_searches": 0,
    "successful_searches": 0,
    "success_rate": 0.0,
    "recent_count": 0,
    "avg_execution": 0.0,
    "avg_generation": 0.0,
    "under_10s_rate": 0.0,
    "cache_stats": {
        "hits": 0,
        "misses": 0,
        "size": 0,
        "max_size": 0,
        "hit_rate": 0.0,
        "ttl_seconds": 0,
    },
}
_EMPTY_PERCENTILES: Final[_PercentilesDict] = {
    "exec_p50": 0.0,
    "exec_p90": 0.0,
    "exec_p99": 0.0,
    "gen_p50": 0.0,
    "gen_p90": 0.0,
    "gen_p99": 0.0,
}
_EMPTY_DISTRIBUTION: Final[dict[str, int]] = {
    "under_1s": 0,
    "1_to_3s": 0,
    "3_to_5s": 0,
    "over_5s": 0,
}
_EMPTY_ACTIVITY: Final[_ActivityDict] = {
    "period_days": _DEFAULT_PERIOD,
    "audit_events": 0,
    "emails_sent": 0,
    "emails_failed": 0,
    "emails_failure_rate": 0.0,
    "executions_total": 0,
    "executions_failed": 0,
    "executions_failure_rate": 0.0,
    "searches_total": 0,
}
_EMPTY_STORAGE: Final[dict[str, Any]] = {
    "path": "-",
    "size_bytes": 0,
    "size_human": "-",
    "encryption_key_configured": False,
    "tables": [],
}


class _Messages:
    """Strings client centralisées (FR, vouvoiement implicite côté admin).

    Garder tout au même endroit facilite (a) l'audit de sécurité — pas de
    drift entre handlers, (b) la future i18n, (c) les tests qui peuvent
    importer ces constantes plutôt que hardcoder leurs assertions.
    """

    INVALID_PERIOD: Final[str] = "Période invalide. Valeurs acceptées : {values}"
    STATS_LOAD_ERROR: Final[str] = "Erreur de chargement des statistiques."
    CACHE_CLEAR_ERROR: Final[str] = "Erreur lors du vidage du cache."
    CACHE_CLEARED: Final[str] = "Cache vidé ({count} entrée(s) supprimée(s))."
    RATE_LIMITED: Final[str] = "Trop de tests rapprochés — réessayez dans {wait:.0f}s."
    UNKNOWN_USER: Final[str] = "Utilisateur non identifié."
    SAGE_BADGE_OK: Final[str] = "Opérationnel"
    SAGE_BADGE_DOWN: Final[str] = "Indisponible"
    ALL_GREEN: Final[str] = "Tous les indicateurs systèmes sont au vert."

    # Recommandations (messages longs)
    REC_SAGE_DOWN: Final[str] = (
        "La base source (Sage) ne répond pas — toutes les requêtes IA vont "
        "échouer. Vérifier le réseau, les credentials et la configuration ODBC."
    )
    REC_ALL_PROVIDERS_DOWN: Final[str] = (
        "Aucun provider LLM ne répond — les appels à Iris vont échouer. "
        "Vérifier les clés API et /admin/ai-config."
    )
    REC_SOME_PROVIDER_DOWN: Final[str] = (
        "Provider LLM en panne : {names}. Le basculement vers les autres "
        "providers doit compenser, mais à vérifier."
    )
    REC_CACHE_SATURATED: Final[str] = (
        "Le cache de requêtes est saturé ({size}/{max}). Augmenter "
        "``max_size`` ou réduire le TTL pour libérer de la place."
    )
    REC_CACHE_LOW_HIT: Final[str] = (
        "Cache hit rate faible ({hit_pct:.1f}%). Les questions des "
        "utilisateurs sont peu répétitives, ou le TTL est trop court."
    )
    REC_EXEC_P99_HIGH: Final[str] = (
        "P99 d'exécution SQL = {p99:.1f}s. Identifier les requêtes lentes "
        "(manque d'index, JOIN cartésien…)."
    )
    REC_EXECUTIONS_FAILURE: Final[str] = (
        "Automations en échec : {rate:.1f}% sur la période. Inspecter les " "logs d'exécution."
    )
    REC_EMAILS_FAILURE: Final[str] = (
        "Emails en échec : {rate:.1f}%. Vérifier la configuration SMTP."
    )
    OVERALL_INCIDENT_BOTH: Final[str] = (
        "BDD source + providers LLM indisponibles — Iris est inopérant."
    )
    OVERALL_INCIDENT_SAGE: Final[str] = "La base source ne répond pas — requêtes IA indisponibles."
    OVERALL_INCIDENT_PROVIDERS: Final[str] = (
        "Tous les providers LLM sont down — Iris ne peut plus répondre."
    )
    OVERALL_WARNING_SUB: Final[str] = "Action recommandée — voir la section Recommandations."
    OVERALL_INCIDENT_LABEL: Final[str] = "Incident détecté"
    OVERALL_OK_LABEL: Final[str] = "Système opérationnel"


# ── Helpers purs (testables sans Tornado) ─────────────────────────────────


def _parse_days(raw: str | None) -> tuple[int, bool]:
    """Renvoie ``(days, is_valid)``.

    ``is_valid=False`` lorsque ``raw`` est non null mais ne fait pas partie
    de :data:`_ALLOWED_PERIODS`. Le handler HTML applique silencieusement la
    valeur par défaut (pas de redirect : ça perdrait les autres query
    params) ; le handler API renvoie 400 pour refuser clairement.
    """
    if raw is None:
        return _DEFAULT_PERIOD, True
    try:
        n = int(raw)
    except (ValueError, TypeError):
        return _DEFAULT_PERIOD, False
    if n not in _ALLOWED_PERIODS:
        return _DEFAULT_PERIOD, False
    return n, True


def _hit_rate_class(hit_rate_pct: float) -> str:
    """Classe Tailwind pour le badge de taux de cache (en %).

    Seuils alignés sur :data:`_CACHE_HIT_EXCELLENT_PCT` /
    :data:`_CACHE_HIT_ACCEPTABLE_PCT` pour rester cohérent avec les
    recommandations textuelles affichées plus bas dans la page.
    """
    if hit_rate_pct >= _CACHE_HIT_EXCELLENT_PCT:
        return "text-emerald-600"
    if hit_rate_pct >= _CACHE_HIT_ACCEPTABLE_PCT:
        return "text-amber-600"
    return "text-red-600"


def _fr_alerts_label(n: int) -> str:
    """Accord singulier/pluriel pour le label d'alertes (``"N alerte(s)"``)."""
    if n <= 1:
        return f"{n} alerte active"
    return f"{n} alertes actives"


def _build_recommendations(
    *,
    perf_overview: _OverviewDict,
    percentiles: _PercentilesDict,
    activity: _ActivityDict,
    sage_status: dict[str, Any],
    providers_health: dict[str, Any] | None = None,
) -> list[_Recommendation]:
    """Construit la liste de recommandations à afficher dans le dashboard.

    Implémentation déclarative : chaque règle est une fonction qui retourne
    un :class:`_Recommendation` ou ``None``. Ajouter une règle = ajouter une
    fonction dans :data:`_rules` — pas de ``if/elif`` éparpillé.
    """
    cache = perf_overview.get("cache_stats") or {}
    hit_rate_pct = float(cache.get("hit_rate", 0) or 0) * 100
    cache_size = int(cache.get("size", 0) or 0)
    cache_max = int(cache.get("max_size", 1) or 1)

    def rule_sage_down() -> _Recommendation | None:
        if sage_status.get("ok"):
            return None
        return {"level": "warning", "text": _Messages.REC_SAGE_DOWN}

    def rule_providers() -> _Recommendation | None:
        if not providers_health:
            return None
        providers = providers_health.get("providers") or []
        if providers and not providers_health.get("any_ok"):
            return {"level": "warning", "text": _Messages.REC_ALL_PROVIDERS_DOWN}
        down = [p for p in providers if not p.get("ok")]
        if down:
            names = ", ".join(p.get("name", "?") for p in down)
            return {
                "level": "warning",
                "text": _Messages.REC_SOME_PROVIDER_DOWN.format(names=names),
            }
        return None

    def rule_cache_saturated() -> _Recommendation | None:
        if cache_max > 0 and cache_size >= cache_max:
            return {
                "level": "warning",
                "text": _Messages.REC_CACHE_SATURATED.format(size=cache_size, max=cache_max),
            }
        return None

    def rule_cache_low_hit() -> _Recommendation | None:
        # Si le cache est saturé on a déjà signalé le problème — éviter le
        # double message.
        if cache_max > 0 and cache_size >= cache_max:
            return None
        if cache_size > 0 and hit_rate_pct < _CACHE_HIT_ACCEPTABLE_PCT:
            return {
                "level": "warning",
                "text": _Messages.REC_CACHE_LOW_HIT.format(hit_pct=hit_rate_pct),
            }
        return None

    def rule_exec_p99() -> _Recommendation | None:
        p99 = float(percentiles.get("exec_p99") or 0)
        if p99 > _EXEC_P99_ALERT_SECONDS:
            return {
                "level": "warning",
                "text": _Messages.REC_EXEC_P99_HIGH.format(p99=p99),
            }
        return None

    def rule_executions_failure() -> _Recommendation | None:
        # P-10 : ne PAS alerter avec moins de _MIN_SAMPLES_FOR_RATE_ALERT
        # échantillons. 1 échec / 3 = 33% qui déclencherait l'alerte = faux
        # positif. Pratique SLO standard (Honeycomb/Datadog).
        total = int(activity.get("executions_total") or 0)
        if total < _MIN_SAMPLES_FOR_RATE_ALERT:
            return None
        rate = float(activity.get("executions_failure_rate") or 0)
        if rate > _EXECUTIONS_FAILURE_ALERT_PCT:
            return {
                "level": "warning",
                "text": _Messages.REC_EXECUTIONS_FAILURE.format(rate=rate),
            }
        return None

    def rule_emails_failure() -> _Recommendation | None:
        # P-10 : idem ``rule_executions_failure``.
        sent = int(activity.get("emails_sent") or 0)
        failed = int(activity.get("emails_failed") or 0)
        if (sent + failed) < _MIN_SAMPLES_FOR_RATE_ALERT:
            return None
        rate = float(activity.get("emails_failure_rate") or 0)
        if rate > _EMAILS_FAILURE_ALERT_PCT:
            return {
                "level": "warning",
                "text": _Messages.REC_EMAILS_FAILURE.format(rate=rate),
            }
        return None

    rules = (
        rule_sage_down,
        rule_providers,
        rule_cache_saturated,
        rule_cache_low_hit,
        rule_exec_p99,
        rule_executions_failure,
        rule_emails_failure,
    )
    recos: list[_Recommendation] = [r for r in (rule() for rule in rules) if r]
    if not recos:
        recos.append({"level": "success", "text": _Messages.ALL_GREEN})
    return recos


def _build_overall_status(
    *,
    recommendations: list[_Recommendation],
    sage_status: dict[str, Any],
    providers_health: dict[str, Any] | None = None,
) -> _OverallStatus:
    """Calcule l'état de santé global à afficher dans le bandeau de tête.

    Trois niveaux :

    * ``critical`` — BDD source OU tous les providers LLM sont down. La
      chaîne IA est cassée, Iris ne peut rien faire.
    * ``warning``  — au moins une recommandation active (cache saturé,
      latence P99, automations ou emails en échec, un provider parmi
      plusieurs down…).
    * ``ok``       — aucune alerte.

    Les classes CSS sont pré-calculées ici pour éviter la logique dans le
    template (Tornado n'a pas ``{% set %}`` propre).
    """
    alert_count = sum(1 for r in recommendations if r.get("level") != "success")

    all_providers_down = False
    providers_configured = False
    if providers_health:
        providers_list = providers_health.get("providers") or []
        providers_configured = bool(providers_list)
        if providers_configured and not providers_health.get("any_ok"):
            all_providers_down = True

    sage_down = not sage_status.get("ok")

    if sage_down or all_providers_down:
        if sage_down and all_providers_down:
            sub = _Messages.OVERALL_INCIDENT_BOTH
        elif sage_down:
            sub = _Messages.OVERALL_INCIDENT_SAGE
        else:
            sub = _Messages.OVERALL_INCIDENT_PROVIDERS
        return {
            "level": "critical",
            "label": _Messages.OVERALL_INCIDENT_LABEL,
            "sublabel": sub,
            "alert_count": alert_count,
            "banner_class": "bg-red-50 border-red-200",
            "dot_class": "bg-red-500",
            "badge_class": "badge-error",
        }
    if alert_count > 0:
        return {
            "level": "warning",
            "label": _fr_alerts_label(alert_count),
            "sublabel": _Messages.OVERALL_WARNING_SUB,
            "alert_count": alert_count,
            "banner_class": "bg-amber-50 border-amber-200",
            "dot_class": "bg-amber-500",
            "badge_class": "badge-warning",
        }
    return {
        "level": "ok",
        "label": _Messages.OVERALL_OK_LABEL,
        "sublabel": _Messages.ALL_GREEN,
        "alert_count": 0,
        "banner_class": "bg-emerald-50 border-emerald-200",
        "dot_class": "bg-emerald-500",
        "badge_class": "badge-success",
    }


def _empty_overview_for(days: int) -> _OverviewDict:
    """Retourne une copie de :data:`_EMPTY_OVERVIEW` avec ``period_days``
    positionné à ``days``. Copie indispensable : le dict constante ne doit
    jamais être muté en place par le handler."""
    clone: _OverviewDict = copy.deepcopy(_EMPTY_OVERVIEW)
    clone["period_days"] = days
    return clone


def _empty_activity_for(days: int) -> _ActivityDict:
    """Idem pour :data:`_EMPTY_ACTIVITY`."""
    clone: _ActivityDict = copy.deepcopy(_EMPTY_ACTIVITY)
    clone["period_days"] = days
    return clone


def _log_username(user: Any) -> str:
    """Retourne un username sûr à insérer dans les logs.

    Protège contre CWE-117 (log injection) si un admin a réussi à
    positionner un ``username`` contenant ``\\n`` ou ``\\r`` — cas peu
    probable (l'admin se doxxe lui-même) mais defense-in-depth : l'observabilité
    dépend de l'intégrité des lignes de log.
    """
    raw = getattr(user, "username", None)
    if not isinstance(raw, str) or not raw:
        return "?"
    cleaned = raw.replace("\n", "\\n").replace("\r", "\\r")
    # Cap raisonnable : un username légitime dépasse rarement 64 car.
    return cleaned[:64]


# ── Cooldown des endpoints de ping ────────────────────────────────────────


def _check_ping_cooldown(user_id: int | None, kind: str) -> float | None:
    """Renvoie le temps d'attente restant en secondes, ou ``None`` si la
    requête peut passer.

    Clé : ``"{user_id}:{kind}"`` — isolement par utilisateur *et* par cible
    (Sage ≠ LLM providers). Implémenté sur :class:`RateLimiter`, donc
    thread-safe et auto-nettoyé.

    **Fail-closed** : si ``user_id`` est ``None`` (session corrompue ou
    utilisateur supprimé pendant la session), on refuse par défaut — mieux
    vaut bloquer un cas légitime rare qu'ouvrir un bypass du cooldown.
    """
    if user_id is None:
        return float(_PING_COOLDOWN_SECONDS)
    key = f"{user_id}:{kind}"
    allowed = _ping_rate_limiter.check(key, max_requests=1, window_seconds=_PING_COOLDOWN_SECONDS)
    if allowed:
        return None
    return float(_PING_COOLDOWN_SECONDS)


# ── Handlers ──────────────────────────────────────────────────────────────


class PerformanceStatsHandler(BaseHandler):
    """Rend le dashboard de performance applicative (admin only).

    GET ``/admin/performance?days=7|30|90``.
    """

    @admin_required
    async def get(self) -> None:
        # ``?days=14`` (hors allow-list) → on prend silencieusement la valeur
        # par défaut. Pas de redirect 302 : ça perdrait les autres query
        # params et créerait une incohérence avec le handler API.
        days, _ = _parse_days(self.get_argument("days", None))

        perf_data = await self._collect_perf_data(days)
        sys_data = await self._collect_system_data(days)

        recommendations = _build_recommendations(
            perf_overview=perf_data["overview"],
            percentiles=perf_data["percentiles"],
            activity=sys_data["activity"],
            sage_status=sys_data["sage_status"],
            providers_health=sys_data["providers_health"],
        )
        overall_status = _build_overall_status(
            recommendations=recommendations,
            sage_status=sys_data["sage_status"],
            providers_health=sys_data["providers_health"],
        )

        ui_extras = self._build_ui_extras(
            overview=perf_data["overview"], sage_status=sys_data["sage_status"]
        )

        # Timestamp ISO-8601 UTC ; le template l'utilise via un ticker JS
        # « il y a N secondes » (pas de locale côté Python).
        last_updated_iso = clock.now().isoformat()

        # Quota stockage par utilisateur (config admin globale, SSoT
        # AIConfig.STORAGE_QUOTA_PER_USER_BYTES). Affiché en Mo dans l'UI.
        storage_quota_mb = await self._get_storage_quota_mb()
        # Taille max par fichier uploadé (SSoT AIConfig.MAX_UPLOAD_SIZE_BYTES,
        # même source que les call-sites runtime). Affichée en Mo dans l'UI.
        max_upload_size_mb = await self._get_max_upload_size_mb()

        self.render(
            "admin/performance.html",
            user=self.current_user,
            current_days=days,
            allowed_periods=list(_ALLOWED_PERIODS),
            overview=to_dict_object(perf_data["overview"]),
            percentiles=to_dict_object(perf_data["percentiles"]),
            time_distribution_json=json.dumps(perf_data["time_distribution"], ensure_ascii=False),
            daily_stats_json=json.dumps(perf_data["daily_stats"], ensure_ascii=False, default=str),
            process_info=to_dict_object(sys_data["process_info"]),
            storage=to_dict_object(sys_data["storage"]),
            storage_quota_mb=storage_quota_mb,
            max_upload_size_mb=max_upload_size_mb,
            sage_status=to_dict_object(sys_data["sage_status"]),
            last_sync=to_dict_object(sys_data["last_sync"]),
            activity=to_dict_object(sys_data["activity"]),
            recommendations=to_dict_object(recommendations),
            ui=to_dict_object(ui_extras),
            overall_status=to_dict_object(overall_status),
            providers_health=to_dict_object(sys_data["providers_health"]),
            active_conversations=sys_data["active_conversations"],
            last_updated_iso=last_updated_iso,
        )

    async def _get_storage_quota_mb(self) -> int:
        """Lit le quota stockage par-user depuis AIConfig et le convertit en Mo.

        Fallback : valeur par défaut de ``DEFAULT_AI_CONFIG`` (SSoT) — pas
        un nombre magique. Bug 2026-05-26 (P-6) : avant, ``return 500``
        était hardcodé ici alors que la VRAIE default vit dans
        ``app/models/ai_config.py::DEFAULT_AI_CONFIG[STORAGE_QUOTA_PER_USER_BYTES]``.
        Si l'admin change la default dans le dict, ce fallback suit
        automatiquement (single source of truth).
        """
        from app.models.ai_config import (
            DEFAULT_AI_CONFIG,
            AIConfigKey,
        )

        try:
            from app.services.ai.config_service import get_ai_config_service

            svc = get_ai_config_service()
            value = await svc.get(AIConfigKey.STORAGE_QUOTA_PER_USER_BYTES)
            if value is not None and isinstance(value, int) and value > 0:
                return value // (1024 * 1024)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning(
                "Lecture quota storage échouée (fallback default DEFAULT_AI_CONFIG) : %s",
                exc,
            )
        # SSoT : lit la default depuis DEFAULT_AI_CONFIG. Convertit bytes→Mo.
        fallback_bytes = DEFAULT_AI_CONFIG[AIConfigKey.STORAGE_QUOTA_PER_USER_BYTES]["value"]
        return int(fallback_bytes) // (1024 * 1024)

    async def _get_max_upload_size_mb(self) -> int:
        """Taille max par fichier uploadé (octets→Mo) pour l'affichage UI.

        Délègue au SSoT ``config_service.get_max_upload_size_bytes()`` — même
        source que les call-sites d'upload runtime, donc l'UI ne peut pas
        afficher une limite différente de celle réellement appliquée.
        """
        from app.services.ai.config_service import get_max_upload_size_bytes

        return (await get_max_upload_size_bytes()) // (1024 * 1024)

    async def _collect_perf_data(self, days: int) -> dict[str, Any]:
        """Appelle ``PerformanceStatsService`` avec fallback dégradé.

        En cas de ``SQLAlchemyError``, l'ensemble du bloc perf retombe sur
        les dicts neutres — le template doit toujours pouvoir rendre.
        """
        perf = get_performance_stats_service()
        try:
            overview = await perf.get_overview(days=days)
            percentiles = await perf.get_percentiles(days=days)
            time_distribution = await perf.get_time_distribution(days=days)
        except SQLAlchemyError:
            logger.error("perf_stats: SQL error", exc_info=True)
            overview = _empty_overview_for(days)
            percentiles = copy.deepcopy(_EMPTY_PERCENTILES)
            time_distribution = copy.deepcopy(_EMPTY_DISTRIBUTION)

        try:
            daily_stats = await perf.get_daily_stats(days=days)
        except SQLAlchemyError:
            logger.error("perf_stats: daily_stats SQL error", exc_info=True)
            daily_stats = []

        # Garantit que le template peut faire ``overview['cache_stats']['x']``
        # même si la couche service renvoie ``None`` ou omet la clé.
        if not isinstance(overview.get("cache_stats"), dict):
            overview["cache_stats"] = copy.deepcopy(_EMPTY_OVERVIEW["cache_stats"])
        return {
            "overview": overview,
            "percentiles": percentiles,
            "time_distribution": time_distribution,
            "daily_stats": daily_stats,
        }

    async def _collect_system_data(self, days: int) -> dict[str, Any]:
        """Collecte les blocs service-health. Chaque appel a son fallback."""
        sys_svc = get_system_health_service()

        process_info = sys_svc.get_process_info()

        try:
            storage = await sys_svc.get_local_storage_info()
        except SQLAlchemyError:
            logger.error("storage info: SQL error", exc_info=True)
            storage = copy.deepcopy(_EMPTY_STORAGE)
        except OSError:
            logger.error("storage info: OS error", exc_info=True)
            storage = copy.deepcopy(_EMPTY_STORAGE)

        # Les méthodes ci-dessous sont déjà fail-safe côté service (elles ne
        # lèvent jamais) — pas de try/except redondant.
        sage_status = await sys_svc.get_source_db_status()
        last_sync = await sys_svc.get_last_schema_sync()
        providers_health = await sys_svc.get_llm_providers_health()
        active_conversations = await sys_svc.get_active_conversations()

        try:
            activity = await sys_svc.get_activity_counts(days=days)
        except SQLAlchemyError:
            logger.error("activity counts: SQL error", exc_info=True)
            activity = _empty_activity_for(days)
        return {
            "process_info": process_info,
            "storage": storage,
            "sage_status": sage_status,
            "last_sync": last_sync,
            "activity": activity,
            "providers_health": providers_health,
            "active_conversations": active_conversations,
        }

    @staticmethod
    def _build_ui_extras(*, overview: _OverviewDict, sage_status: dict[str, Any]) -> dict[str, Any]:
        cache_stats = overview.get("cache_stats") or {}
        cache_hit_pct = float(cache_stats.get("hit_rate", 0) or 0) * 100
        sage_ok = bool(sage_status.get("ok"))
        return {
            "cache_hit_pct": round(cache_hit_pct, 1),
            "cache_hit_class": _hit_rate_class(cache_hit_pct),
            "sage_badge_class": "badge-success" if sage_ok else "badge-error",
            "sage_badge_label": (_Messages.SAGE_BADGE_OK if sage_ok else _Messages.SAGE_BADGE_DOWN),
        }


class PerformanceStatsAPIHandler(BaseHandler):
    """API JSON (admin only) pour les statistiques de performance."""

    @admin_required
    async def get(self) -> None:
        days, is_valid_days = _parse_days(self.get_argument("days", None))
        if not is_valid_days:
            self.write_json(
                {
                    "success": False,
                    "error": _Messages.INVALID_PERIOD.format(
                        values=", ".join(map(str, _ALLOWED_PERIODS))
                    ),
                },
                status=400,
            )
            return

        perf = get_performance_stats_service()
        sys_svc = get_system_health_service()

        try:
            overview = await perf.get_overview(days=days)
            percentiles = await perf.get_percentiles(days=days)
        except SQLAlchemyError:
            logger.error("API perf stats: SQL error", exc_info=True)
            # 500 plutôt que 200 + success=false : les APM/monitoring
            # attendent un 5xx pour lever une alerte.
            self.write_json(
                {"success": False, "error": _Messages.STATS_LOAD_ERROR},
                status=500,
            )
            return

        process_info = sys_svc.get_process_info()
        sage_status = await sys_svc.get_source_db_status()
        try:
            activity = await sys_svc.get_activity_counts(days=days)
        except SQLAlchemyError:
            logger.error("API perf stats: activity SQL error", exc_info=True)
            activity = _empty_activity_for(days)

        providers_health = await sys_svc.get_llm_providers_health()
        active_conversations = await sys_svc.get_active_conversations()

        self.write_json(
            {
                "success": True,
                "stats": {**overview, **percentiles},
                "process": process_info,
                "sage": sage_status,
                "activity": activity,
                "providers": providers_health,
                "active_conversations": active_conversations,
                "last_updated": clock.now().isoformat(),
            }
        )


class CacheClearHandler(BaseHandler):
    """Vide le cache LRU des requêtes SQL générées (admin only).

    Bug 2026-05-26 (Agent 3 P-5) : rate-limit ajouté pour bloquer le
    spam si un XSS dans une autre page admin parvenait à POST en boucle.
    """

    @admin_required
    async def post(self) -> None:
        # Bug P-5 : rate-limit anti-spam (1 user = max 3 clear / 5 min).
        user_id = getattr(self.current_user, "id", None)
        rate_key = f"{user_id or 'anon'}:cache_clear"
        if not _cache_clear_rate_limiter.check(
            rate_key,
            max_requests=_CACHE_CLEAR_MAX_REQUESTS,
            window_seconds=_CACHE_CLEAR_WINDOW_SECONDS,
        ):
            self.write_json(
                {
                    "success": False,
                    "error": (
                        "Trop de vidages de cache rapprochés "
                        f"(limite : {_CACHE_CLEAR_MAX_REQUESTS} par "
                        f"{_CACHE_CLEAR_WINDOW_SECONDS // 60} minutes)."
                    ),
                },
                status=429,
            )
            return

        try:
            cache = get_cache()
            stats_before = cache.stats()
            cache.clear()
            # P-3 (2026-05-26) : invalide aussi les caches TTL de la
            # vue d'ensemble / percentiles, sinon l'admin verrait le
            # cache LRU vide mais les KPIs encore figés 25s.
            from app.services.performance_stats_service import (
                clear_perf_caches as _clear_perf_caches,
            )

            _clear_perf_caches()
        except (RuntimeError, OSError):
            logger.error("cache clear failed", exc_info=True)
            self.write_json(
                {"success": False, "error": _Messages.CACHE_CLEAR_ERROR},
                status=500,
            )
            return

        count = int(stats_before.get("size", 0) or 0)
        logger.info(
            "cache cleared by %s (%d entries)",
            _log_username(self.current_user),
            count,
        )
        self.write_json(
            {
                "success": True,
                "message": _Messages.CACHE_CLEARED.format(count=count),
            }
        )


class _PingHandlerBase(BaseHandler):
    """Base partagée aux handlers « Tester maintenant » (Sage + LLM).

    Factorise la logique cooldown + structure de réponse. Les sous-classes
    n'ont qu'à fournir :

    * ``_kind`` — libellé logique pour la clé de rate-limit.
    * ``_do_ping`` — coroutine qui effectue le ping et retourne le dict
      à inclure dans la réponse JSON (clé libre).
    """

    _kind: str = ""
    _response_key: str = ""

    async def _do_ping(self) -> dict[str, Any]:  # pragma: no cover - override
        raise NotImplementedError

    def _log_ping_result(self, result: dict[str, Any]) -> None:
        """Log structuré du résultat — surchargeable pour formatage custom."""
        logger.info(
            "manual ping '%s' by %s → %s",
            self._kind,
            _log_username(self.current_user),
            result,
        )

    async def _handle(self) -> None:
        user = self.current_user
        user_id = getattr(user, "id", None)
        wait = _check_ping_cooldown(user_id, self._kind)
        if wait is not None:
            self.write_json(
                {
                    "success": False,
                    "error": _Messages.RATE_LIMITED.format(wait=wait),
                },
                status=429,
            )
            return
        result = await self._do_ping()
        self._log_ping_result(result)
        self.write_json({"success": True, self._response_key: result})


class SourceDBPingHandler(_PingHandlerBase):
    """Force un ping frais de la BDD source — bypass du cache 30 s."""

    _kind = "source_db"
    _response_key = "status"

    async def _do_ping(self) -> dict[str, Any]:
        sys_svc = get_system_health_service()
        sys_svc.invalidate_source_db_cache()
        # get_source_db_status est déjà fail-safe.
        return await sys_svc.get_source_db_status()

    def _log_ping_result(self, result: dict[str, Any]) -> None:
        logger.info(
            "ping source_db by %s: ok=%s latency=%sms",
            _log_username(self.current_user),
            result.get("ok"),
            result.get("latency_ms"),
        )

    @admin_required
    async def post(self) -> None:
        await self._handle()


class LLMProvidersPingHandler(_PingHandlerBase):
    """Force un ping frais des providers LLM — bypass du cache 5 min."""

    _kind = "llm_providers"
    _response_key = "health"

    async def _do_ping(self) -> dict[str, Any]:
        sys_svc = get_system_health_service()
        sys_svc.invalidate_llm_providers_cache()
        return await sys_svc.get_llm_providers_health(force_refresh=True)

    def _log_ping_result(self, result: dict[str, Any]) -> None:
        providers = result.get("providers") or []
        logger.info(
            "ping llm_providers by %s: any_ok=%s providers=%d",
            _log_username(self.current_user),
            result.get("any_ok"),
            len(providers),
        )

    @admin_required
    async def post(self) -> None:
        await self._handle()
