"""Handlers admin pour le dashboard IA (Iris) et l'entraînement.

Sommaire :

- Pages HTML :
  - :class:`AIPerformanceDashboardHandler` — dashboard des performances IA.
  - :class:`AITrainingPageHandler` — gestion des données d'entraînement.

- API REST JSON :
  - :class:`AIStatsAPIHandler` — overview + comparaison modèles + quotidien.
  - :class:`AIRecentQueriesAPIHandler` — requêtes récentes filtrables.
  - :class:`AITrainingDataAPIHandler` — liste + création de training data.
  - :class:`AITrainingDataItemHandler` — update/soft-delete d'un record.
  - :class:`AITrainingPendingAPIHandler` — liste des items à valider.
  - :class:`AITrainingApproveHandler` / :class:`AITrainingRejectHandler`.
  - :class:`AISchemaTablesAPIHandler` — autocomplete des noms de tables.
  - :class:`AISchemaSyncAPIHandler` — sync du schéma + historique.
  - :class:`AIModelsAPIHandler` — modèles LLM + health check.
  - :class:`AIFeedbackAPIHandler` / :class:`AIFeedbackExportHandler`.
  - :class:`AIUsageAPIHandler` — consommation API IA.

Règles qui traversent ce module :

- Toutes les APIs répondent en JSON ; les erreurs utilisateur en ``4xx`` avec
  un message actionnable en français, les erreurs système en ``5xx`` sans
  détail technique exposé au client.
- Les helpers de sécurité de sortie (XSS dans ``<script>``, CSV formula
  injection) vivent dans :mod:`app.utils.output_safety` — cohérence et
  testabilité.
- Les imports se font au sommet du module. Les imports locaux dans une
  méthode ne sont utilisés que pour casser un cycle documenté.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Final

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.core.exceptions import SageConnectionError, SQLValidationError

from app.constants import (
    DASHBOARD_PERIODS_DAYS,
    DASHBOARD_RECENT_LIMIT,
    DEFAULT_PER_PAGE,
)
from app.constants_ai import PRICING_CURRENCY_CODE, PRICING_CURRENCY_SYMBOL
from app.core.database import get_session
from app.handlers.base import BaseHandler, admin_required, require_role
from app.handlers.base import is_admin as _is_admin
from app.models.ai_performance import AIPerformanceLog, QueryStatus
from app.models.training_data import TrainingDataType
from app.models.user import User, UserRole
from app.services.ai.llm_providers import ensure_providers_from_db, get_llm_manager
from app.services.ai.schema_sync import get_sync_service
from app.services.ai.stats_service import get_ai_stats_service
from app.services.ai.training_store import BUSINESS_CONTEXT_CATEGORY, get_training_store
from app.services.audit.audit_log import audit_event
from app.utils.output_safety import csv_safe_cell, safe_json_for_script
from app.utils.redaction import (
    EXPORT_QUESTION_MAX_LEN,
    EXPORT_SQL_MAX_LEN,
    redact_pii_best_effort,
)
from app.utils.template_helpers import to_dict_object

logger = logging.getLogger(__name__)


# ==========================================================================
# Constantes module — limites, allow-lists, paliers de couleurs
# ==========================================================================

# Périodes de stats autorisées dans l'URL du dashboard. SSoT :
# ``app.constants.DASHBOARD_PERIODS_DAYS`` — partagée avec ``performance.py``.
# Bug 2026-05-26 (AI-11) : avant, dupliquée sur les 2 sites avec risque de
# drift. ``_DEFAULT_PERIOD`` reste à 30j ici (vs 7j côté ``performance.py``)
# parce que la fenêtre AI-perf est plus utile en monthly-view (volume LLM
# trop faible sur 7j) — divergence INTENTIONNELLE.
_ALLOWED_PERIODS: Final[tuple[int, ...]] = DASHBOARD_PERIODS_DAYS
_DEFAULT_PERIOD: Final[int] = 30

# Bornes sur les paramètres JSON admin, destinées à empêcher un payload
# malicieux (ou un bug UI) de saturer la mémoire ou la BDD.
_MAX_PERIOD_DAYS: Final[int] = 365
_MAX_LIMIT_ROWS: Final[int] = 200
_MAX_OFFSET_ROWS: Final[int] = 1_000_000
_MAX_CONTENT_BYTES: Final[int] = 200_000
_MAX_TAGS_LIST: Final[int] = 100
_MAX_TAG_BYTES: Final[int] = 256
_MAX_PRIORITY: Final[int] = 1_000
_MIN_PRIORITY: Final[int] = -1_000

# Filtrage des requêtes récentes — allow-list stricte pour éviter que le
# service reçoive une chaîne arbitraire en paramètre ``status``.
# DÉRIVÉE de l'enum ``QueryStatus`` (SSoT) : l'ancien hardcode
# ``{"success", "failure", "timeout"}`` divergeait (#129) — ``"failure"`` n'est
# PAS un ``QueryStatus`` valide (→ ``QueryStatus("failure")`` levait, service
# renvoyait [] silencieusement) et les vrais statuts d'erreur
# (``validation_error``/``execution_error``/``llm_error``) étaient rejetés 400,
# donc INFILTRABLES par l'admin. La dérivation garantit que toute valeur passant
# le gate handler est résoluble par le service + auto-sync si l'enum évolue.
_ALLOWED_QUERY_STATUSES: Final[frozenset[str]] = frozenset(s.value for s in QueryStatus)

# Types de data training supportés par PUT (ordre d'écriture du message 400).
_TRAINING_PUT_TYPES: Final[tuple[str, ...]] = (
    "business_context",
    "documentation",
    "ddl",
    "question_sql",
)

# Rate → classe Tailwind pour le dashboard. Paliers alignés avec
# ``templates/admin/ai_performance.html``. Centralisé ici car Tornado
# templates n'ont pas de ``{% set %}`` et on évite la dérive entre KPIs.
_RATE_GOOD_THRESHOLD: Final[float] = 90.0
_RATE_WARN_THRESHOLD: Final[float] = 70.0
_RATE_CLASS_GOOD: Final[str] = "text-emerald-600"
_RATE_CLASS_WARN: Final[str] = "text-amber-600"
_RATE_CLASS_BAD: Final[str] = "text-red-600"
_RATE_CLASS_UNKNOWN: Final[str] = "text-gray-400"

# Export CSV — limite pour garder l'export pratiquement utilisable en
# mémoire. Un export complet hors de cette limite passera par un futur
# endpoint streamé (voir EPIC:AI-FEEDBACK-STREAM).
_EXPORT_MAX_ROWS: Final[int] = 10_000

# Allow-list pour le filtre de l'export feedback.
_FEEDBACK_EXPORT_TYPES: Final[frozenset[str]] = frozenset({"all", "positive", "negative"})

# Feedback utilisateur : deux polarités, rien d'autre.
_FEEDBACK_POLARITIES: Final[frozenset[str]] = frozenset({"positive", "negative"})

# Sources de sync schéma supportées par le POST.
_SYNC_SOURCES: Final[frozenset[str]] = frozenset({"yaml", "sage"})

# Valeurs par défaut sûres pour le contexte du template dashboard. Toute
# nouvelle clé consommée par le template DOIT aussi figurer ici pour ne pas
# casser l'affichage en mode dégradé (exception dans la collecte des stats).
_EMPTY_OVERVIEW: Final[dict[str, Any]] = {
    "period_days": _DEFAULT_PERIOD,
    "total_queries": 0,
    "successful_queries": 0,
    "success_rate": 0.0,
    "cache_hits": 0,
    "cache_rate": 0.0,
    "avg_total_time": 0.0,
    "avg_generation_time": 0.0,
    "rag_usage_rate": 0.0,
    "positive_feedback": 0,
    "negative_feedback": 0,
    "satisfaction_rate": 0.0,
    "total_tokens": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "training_data": {"ddl": 0, "documentation": 0, "question_sql": 0, "total": 0},
}
_EMPTY_USAGE: Final[dict[str, Any]] = {
    "period_days": _DEFAULT_PERIOD,
    "total_requests": 0,
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "total_tokens": 0,
    "estimated_total_cost_usd": 0.0,
    "by_model": [],
    "daily": [],
}


# ==========================================================================
# Helpers locaux au module
# ==========================================================================


def _rate_color_class(rate: float | None, total_queries: int | None) -> str:
    """Retourne la classe Tailwind du palier d'un taux (0-100 %).

    Convention partagée avec ``templates/admin/ai_performance.html`` :

    - ≥ 90 → vert
    - ≥ 70 → ambre
    - < 70 → rouge
    - ``rate`` inconnu ou ``total_queries`` nul → gris (absence de donnée)
    """
    if not total_queries or rate is None:
        return _RATE_CLASS_UNKNOWN
    if rate >= _RATE_GOOD_THRESHOLD:
        return _RATE_CLASS_GOOD
    if rate >= _RATE_WARN_THRESHOLD:
        return _RATE_CLASS_WARN
    return _RATE_CLASS_BAD


def _resolve_training_type(raw: str | None) -> tuple[TrainingDataType | None, str | None, bool]:
    """Traduit un ``data_type`` reçu en ``(type SQL, category, valide)``.

    Règles :

    - ``None`` / chaîne vide → pas de filtre, tous types (``valide=True``).
    - ``"business_context"`` → type ``DOCUMENTATION`` + filtre category sur
      la constante :data:`BUSINESS_CONTEXT_CATEGORY` (route implicite).
    - Valeur de l'enum :class:`TrainingDataType` → type correspondant.
    - Toute autre valeur → ``(None, None, False)`` : le caller doit renvoyer
      400 plutôt que de dumper la liste complète (bug silencieux classique).
    """
    if raw is None or raw == "":
        return None, None, True
    if raw == "business_context":
        return TrainingDataType.DOCUMENTATION, BUSINESS_CONTEXT_CATEGORY, True
    try:
        return TrainingDataType(raw), None, True
    except (ValueError, KeyError):
        return None, None, False


def _coerce_tags(raw: Any) -> list[str] | None:
    """Garantit que ``tags`` arrive aux services sous ``list[str] | None``.

    Le front envoie toujours une liste. On reste tolérant aux clients qui
    enverraient une chaîne CSV (scripts externes, cURL). ``None`` signifie
    « champ non modifié » et est propagé tel quel.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, str):
        return [token.strip() for token in raw.split(",") if token.strip()]
    raise ValueError("tags doit être une liste ou une chaîne CSV")


def _validate_tags_tables(raw: Any) -> list[str]:
    """Valide et normalise ``tags_tables`` pour un ``business_context``.

    Règles :

    - Liste non vide.
    - Au plus :data:`_MAX_TAGS_LIST` éléments.
    - Chaque élément est une chaîne non vide ≤ :data:`_MAX_TAG_BYTES` octets.

    Lève :class:`ValueError` avec un message français explicite sinon.
    """
    if not isinstance(raw, list) or not raw:
        raise ValueError("tags_tables doit être une liste non vide")
    if len(raw) > _MAX_TAGS_LIST:
        raise ValueError(f"tags_tables ne peut pas dépasser {_MAX_TAGS_LIST} éléments")
    cleaned: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("chaque tag doit être une chaîne non vide")
        stripped = item.strip()
        if len(stripped.encode("utf-8")) > _MAX_TAG_BYTES:
            raise ValueError(f"chaque tag doit faire ≤ {_MAX_TAG_BYTES} octets")
        cleaned.append(stripped)
    return cleaned


def _validate_content_size(content: Any, *, field: str = "content") -> None:
    """Refuse les chaînes excessives (DoS mémoire/BDD).

    Ne modifie pas la valeur, lève :class:`ValueError` sinon — le handler
    convertit en 400 via son catch standard.
    """
    if content is None:
        return
    if not isinstance(content, str):
        raise ValueError(f"{field} doit être une chaîne de caractères")
    if len(content.encode("utf-8")) > _MAX_CONTENT_BYTES:
        raise ValueError(f"{field} dépasse {_MAX_CONTENT_BYTES} octets")


def _parse_int_arg(value: str | None, *, default: int, minimum: int, maximum: int) -> int:
    """Parse un ``get_argument`` en int clamp entre ``minimum`` et ``maximum``.

    Retombe sur ``default`` si la valeur est manquante ou invalide — la
    politique clamp-silent est cohérente avec la convention déjà en place
    dans les APIs stats (un client qui envoie ``days=abc`` ne casse pas).
    """
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _build_feedback_trends(daily_stats: list[dict[str, Any]], days: int) -> list[dict[str, Any]]:
    """Remplit les jours sans activité avec 0 pour une courbe continue.

    Les timestamps SQL étant stockés en UTC (``func.date(created_at)``), on
    pivote sur le "aujourd'hui" UTC. Le template expose la timezone pour
    éviter toute ambiguïté d'affichage.
    """
    stats_by_date = {entry.get("date"): entry for entry in daily_stats if entry.get("date")}
    today_utc = clock.now().date()
    trends: list[dict[str, Any]] = []
    for delta in range(days - 1, -1, -1):
        day = (today_utc - timedelta(days=delta)).isoformat()
        bucket = stats_by_date.get(day)
        trends.append(
            {
                "date": day,
                "positive": (bucket.get("positive_feedback", 0) if bucket else 0),
                "negative": (bucket.get("negative_feedback", 0) if bucket else 0),
            }
        )
    return trends


def _format_recent_query(raw: dict[str, Any]) -> dict[str, Any]:
    """Ajoute aux colonnes ORM brutes les champs dérivés attendus du template.

    - ``success`` : booléen lisible plutôt que ``status == "success"``.
    - ``attempts`` : placeholder (toujours 1 pour l'instant, colonne future).
    - ``rag_used`` : vrai dès qu'un des compteurs RAG > 0.
    - ``created_at_formatted`` : DD/MM HH:MM dans la timezone **du serveur**
      (fallback si aucune tz user ; les timestamps bruts restent ISO UTC).
    """
    formatted: dict[str, Any] = dict(raw)
    formatted["success"] = raw.get("status") == "success"
    formatted["attempts"] = 1
    formatted["rag_used"] = (
        (raw.get("rag_ddl_count") or 0) > 0
        or (raw.get("rag_doc_count") or 0) > 0
        or (raw.get("rag_example_count") or 0) > 0
    )

    created_at = raw.get("created_at")
    if created_at:
        try:
            dt = datetime.fromisoformat(created_at)
            if dt.tzinfo is not None:
                dt = dt.astimezone()
            formatted["created_at_formatted"] = dt.strftime("%d/%m %H:%M")
        except (TypeError, ValueError):
            formatted["created_at_formatted"] = "-"
    else:
        formatted["created_at_formatted"] = "-"
    return formatted


def _format_iso_date(raw: str | None, *, include_time: bool = False) -> str:
    """Formate ``YYYY-MM-DDTHH:MM:SS`` en ``DD/MM/YYYY`` (± heure).

    Retourne ``"-"`` si ``raw`` est falsy ou trop court pour être parsé.
    """
    if not raw or len(raw) < 10:
        return "-"
    try:
        year, month, day = raw[:10].split("-")
        formatted = f"{day}/{month}/{year}"
        if include_time and len(raw) >= 16:
            formatted += f" {raw[11:16]}"
        return formatted
    except (ValueError, IndexError):
        return raw[:16].replace("T", " ") if include_time else raw[:10]


def _write_json_error(handler: BaseHandler, status: int, message: str) -> None:
    """Réponse JSON ``{"error": <message>}`` + code HTTP.

    Centralisé pour éviter la dérive entre handlers et permettre un jour
    d'enrichir facilement (ajout d'un code machine, d'un request_id…).
    """
    handler.set_status(status)
    handler.write({"error": message})


def _parse_int_path_or_400(handler: BaseHandler, raw: str) -> int | None:
    """Parse un segment d'URL en int, écrit 400 et retourne ``None`` sinon."""
    try:
        return int(raw)
    except (TypeError, ValueError):
        _write_json_error(handler, 400, "ID invalide")
        return None


async def _block_if_data_access_referenced(handler: BaseHandler, store: Any, tid: int) -> bool:
    """Bloque (409) le soft-delete d'un ``TrainingData`` référencé par des
    ``DataAccessRule`` actives.

    Sans ce guard, la closure transitive du mode invisible perd silencieusement
    le nœud et des vues dérivées ne sont plus bloquées pour les users denied
    (Bug DA-C3). **Source unique** pour les DEUX entry points de soft-delete
    (``AITrainingDataItemHandler.delete`` ET ``AITrainingRejectHandler.post``) —
    sans ça, reject bypassait le guard appliqué par delete.

    Retourne ``True`` (et a déjà écrit la réponse 409) si le soft-delete doit
    être bloqué ; ``False`` si aucune règle ne référence l'objet (delete permis).
    """
    references = await store.find_data_access_references(tid)
    if not references:
        return False
    rule_ids = sorted({r["rule_id"] for r in references})
    impacted_users = sorted({r["user_id"] for r in references})
    # ``write_json(..., status=409)`` pose le 409 EN MÊME TEMPS que le corps.
    # (Ne PAS faire set_status(409) puis write_json(...) sans status : write_json
    # ré-applique set_status(200) par défaut → écraserait le 409 en 200.)
    handler.write_json(
        {
            "success": False,
            "error": (
                f"Cette donnée d'entraînement est référencée par "
                f"{len(references)} règle(s) data-access actives "
                f"sur {len(impacted_users)} utilisateur(s). "
                "Retirer les règles d'abord via /admin/data-access "
                "OU recréer un nouveau DDL équivalent avant suppression."
            ),
            "blocking_rule_ids": rule_ids,
            "impacted_user_ids": impacted_users,
        },
        status=409,
    )
    return True


_OLLAMA_MODEL_NAME_RE = __import__("re").compile(r"^[a-zA-Z0-9._:/\-]{1,128}$")


def _is_safe_ollama_model_name(name: str) -> bool:
    """Validation defense-in-depth d'un nom de modèle Ollama.

    La regex seule (``[a-zA-Z0-9._:/\\-]``) accepte des tags Ollama
    légitimes comme ``phi3:mini`` ou ``library/qwen2.5:3b``, mais
    aussi ``../etc/passwd`` (les ``.`` et ``/`` sont nécessaires
    pour les vraies tags). Ce helper ajoute une couche :

    - Refuser les substrings ``..`` et ``//`` (traversal / path
      collapsing). Ollama ne devrait jamais les générer dans une
      tag réelle.
    - Refuser les noms commençant par ``.`` ou ``/`` (path absolu /
      hidden file). Aucune tag Ollama ne commence ainsi.
    - Refuser les noms se terminant par ``/`` ou ``:`` (tag tronquée).

    Le code HTTP appelle ``/api/delete`` / ``/api/pull`` avec ce nom
    dans le body JSON — il n'y a pas d'exécution shell directe, mais
    Ollama internally translates le nom en chemin disque pour le
    blob storage, donc on durcit côté caller par précaution.
    """
    if not name or not _OLLAMA_MODEL_NAME_RE.match(name):
        return False
    if ".." in name or "//" in name:
        return False
    if name.startswith(".") or name.startswith("/"):
        return False
    if name.endswith("/") or name.endswith(":"):
        return False
    return True


# ==========================================================================
# Pages HTML
# ==========================================================================


class AIPerformanceDashboardHandler(BaseHandler):
    """Page HTML — dashboard de performances IA.

    ``GET /admin/ai-performance?days=7|30|90``
    """

    @admin_required
    async def get(self) -> None:
        user = self.current_user

        # Lire la période demandée. Si la valeur est hors allow-list, on
        # redirige vers la valeur par défaut pour garder l'URL cohérente
        # avec le contenu affiché (un bookmark ``?days=14`` sera corrigé
        # visiblement).
        raw_days = self.get_argument("days", None)
        if raw_days is None:
            days = _DEFAULT_PERIOD
        else:
            try:
                parsed = int(raw_days)
            except (TypeError, ValueError):
                parsed = None
            if parsed not in _ALLOWED_PERIODS:
                self.redirect(f"/admin/ai-performance?days={_DEFAULT_PERIOD}")
                return
            days = parsed

        context = await self._build_dashboard_context(days)
        self.render(
            "admin/ai_performance.html",
            user=user,
            stats=to_dict_object(context["overview"]),
            overview=to_dict_object(context["overview"]),
            model_comparison=to_dict_object(context["model_comparison"]),
            recent_queries=to_dict_object(context["recent_queries"]),
            training_stats=to_dict_object(context["training_stats"]),
            providers_list=to_dict_object(context["providers_list"]),
            error_breakdown=to_dict_object(context["error_breakdown"]),
            usage_stats=to_dict_object(context["usage_stats"]),
            evolution_data=safe_json_for_script(context["evolution_data"]),
            feedback_trends=safe_json_for_script(context["feedback_trends"]),
            rag_stats=safe_json_for_script(context["rag_stats"]),
            current_days=days,
            allowed_periods=list(_ALLOWED_PERIODS),
            # AI-7 (2026-05-26) : SSoT devise — template ne hardcode plus ``$``.
            pricing_currency_code=PRICING_CURRENCY_CODE,
            pricing_currency_symbol=PRICING_CURRENCY_SYMBOL,
            # AI-10 (2026-05-26) : ticker "Dernière mise à jour" — l'admin
            # voit la fraîcheur des données. Le JS shared (ticker.js / pattern
            # /admin/performance) lit ``data-ts`` et calcule le delta relatif.
            last_updated_iso=clock.now().isoformat(),
            page_title="Performance Iris",
        )

    async def _build_dashboard_context(self, days: int) -> dict[str, Any]:
        """Agrège les 7 sources de stats + précalcule les dérivés du template.

        Tous les appels de service sont dans un ``try/except`` unique : la
        page est « tout ou rien ». En cas d'échec, on retourne le contexte
        vide (clés de :data:`_EMPTY_OVERVIEW` préservées) pour que le
        template n'explose pas sur une ``KeyError``.
        """
        try:
            stats_service = get_ai_stats_service()
            overview = await stats_service.get_overview(days=days)
            model_comparison = await stats_service.get_model_comparison(days=days)
            recent_queries = await stats_service.get_recent_queries(limit=DEFAULT_PER_PAGE)
            daily_stats = await stats_service.get_daily_stats(days=days)
            rag_impact = await stats_service.get_rag_impact(days=days)
            error_breakdown = await stats_service.get_error_breakdown(days=days)
            usage_stats = await stats_service.get_usage_stats(days=days)

            evolution_data = [
                {
                    "date": entry["date"],
                    "success": entry.get("successes", 0),
                    "failed": entry.get("total", 0) - entry.get("successes", 0),
                }
                for entry in daily_stats
            ]
            feedback_trends = _build_feedback_trends(daily_stats, days)

            # Defensive nested gets — un service qui renverrait une
            # structure partielle ne doit pas casser toute la page.
            rag_stats = {
                "with_rag": rag_impact.get("with_rag", {}).get("total", 0),
                "without_rag": rag_impact.get("without_rag", {}).get("total", 0),
            }

            recent_queries = [_format_recent_query(q) for q in recent_queries]

            training_store = get_training_store()
            training_stats = await training_store.get_stats()

            # health_check_all() est cachée 5min côté manager — pas de coût
            # significatif sur les rechargements rapprochés.
            # On convertit en liste côté handler pour éviter que
            # ``DictObject.keys()`` soit shadow par une clé littéralement
            # nommée ``keys``/``items``/``values`` — fragilité du wrapper.
            llm_manager = get_llm_manager()
            providers_health_raw = await llm_manager.health_check_all()
            providers_list = [
                {"name": name, "ok": bool(ok)} for name, ok in sorted(providers_health_raw.items())
            ]

            # Précalcule des dérivés pour le template (Tornado n'a pas
            # ``{% set %}``) — arithmétique défensive contre les ``None``.
            overview["success_rate_class"] = _rate_color_class(
                overview.get("success_rate"), overview.get("total_queries", 0)
            )
            overview["fb_total"] = int(overview.get("positive_feedback") or 0) + int(
                overview.get("negative_feedback") or 0
            )
            for model in model_comparison:
                model["success_rate_class"] = _rate_color_class(
                    model.get("success_rate"), model.get("total_queries", 0)
                )
                model["fb_total"] = int(model.get("positive_feedback") or 0) + int(
                    model.get("negative_feedback") or 0
                )

            return {
                "overview": overview,
                "model_comparison": model_comparison,
                "recent_queries": recent_queries,
                "training_stats": training_stats,
                "providers_list": providers_list,
                "error_breakdown": error_breakdown,
                "usage_stats": usage_stats,
                "evolution_data": evolution_data,
                "feedback_trends": feedback_trends,
                "rag_stats": rag_stats,
            }
        except (SQLAlchemyError, KeyError, ValueError, ConnectionError, OSError):
            logger.error("Erreur chargement stats IA", exc_info=True)
            fallback_overview = dict(_EMPTY_OVERVIEW)
            fallback_overview["success_rate_class"] = _RATE_CLASS_UNKNOWN
            fallback_overview["fb_total"] = 0
            return {
                "overview": fallback_overview,
                "model_comparison": [],
                "recent_queries": [],
                "training_stats": {},
                "providers_list": [],
                "error_breakdown": [],
                "usage_stats": dict(_EMPTY_USAGE),
                "evolution_data": [],
                "feedback_trends": [],
                "rag_stats": {"with_rag": 0, "without_rag": 0},
            }


class AITrainingPageHandler(BaseHandler):
    """Page HTML — gestion des données d'entraînement IA.

    ``GET /admin/ai-training?type=<type>&page=<n>``
    """

    @admin_required
    async def get(self) -> None:
        user = self.current_user
        training_store = get_training_store()
        stats = await training_store.get_stats()

        raw_type = self.get_argument("type", None)
        data_type, category_filter, valid_type = _resolve_training_type(raw_type)
        if not valid_type:
            # Filtre inconnu → on n'affiche pas tout silencieusement : on
            # redirige vers la vue sans filtre avec un log dédié. L'admin
            # voit alors la liste complète, et le journal garde trace.
            logger.info("AITrainingPage: type inconnu '%s' — reset du filtre", raw_type)
            self.redirect("/admin/ai-training")
            return

        try:
            page = int(self.get_argument("page", 1))
        except (TypeError, ValueError):
            page = 1
        per_page = DEFAULT_PER_PAGE

        total_count = (
            await training_store.count_training_data(data_type=data_type, category=category_filter)
            or 0
        )
        total_pages = max(1, -(-total_count // per_page))  # ceil
        page = max(1, min(page, total_pages))

        training_data = await training_store.get_all_training_data(
            data_type=data_type,
            limit=per_page,
            offset=(page - 1) * per_page,
            category=category_filter,
        )

        for item in training_data:
            date_str = item.get("updated_at") or item.get("created_at") or ""
            item["formatted_date"] = _format_iso_date(date_str)

        sync_service = get_sync_service()
        sync_history = await sync_service.get_sync_history(limit=DASHBOARD_RECENT_LIMIT)
        for sync in sync_history:
            sync["created_at_formatted"] = _format_iso_date(
                sync.get("created_at"), include_time=True
            )

        self.render(
            "admin/ai_training.html",
            user=user,
            stats=to_dict_object(stats),
            training_data=to_dict_object(training_data),
            sync_history=to_dict_object(sync_history),
            current_type=raw_type,
            current_page=page,
            total_count=total_count,
            total_pages=total_pages,
            page_title="Entraînement IA",
            # Bug 2026-05-26 (Agent 4 AT-M8) : XSS via ``</script>`` dans
            # un nom de table. ``json_encode`` (Tornado natif) n'échappe
            # PAS la séquence ``</`` qui peut sortir d'une balise ``<script>``.
            # ``safe_json_for_script`` (output_safety.py) échappe en ``\\u003c``.
            # Le template lit ``safe_json`` comme alias court.
            safe_json=safe_json_for_script,
        )


# ==========================================================================
# APIs de lecture — stats et requêtes
# ==========================================================================


class AIStatsAPIHandler(BaseHandler):
    """``GET /api/ai/stats?days=<n>`` — statistiques IA agrégées."""

    @admin_required
    async def get(self) -> None:
        days = _parse_int_arg(
            self.get_argument("days", None),
            default=_DEFAULT_PERIOD,
            minimum=1,
            maximum=_MAX_PERIOD_DAYS,
        )
        stats_service = get_ai_stats_service()
        try:
            overview = await stats_service.get_overview(days=days)
            model_comparison = await stats_service.get_model_comparison(days=days)
            daily_stats = await stats_service.get_daily_stats(days=days)
            error_breakdown = await stats_service.get_error_breakdown(days=days)
            rag_impact = await stats_service.get_rag_impact(days=days)
        except SQLAlchemyError:
            logger.error("Stats API: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement des statistiques.")
            return

        self.write(
            {
                "success": True,
                "overview": overview,
                "model_comparison": model_comparison,
                "daily_stats": daily_stats,
                "error_breakdown": error_breakdown,
                "rag_impact": rag_impact,
            }
        )


class AIRecentQueriesAPIHandler(BaseHandler):
    """``GET /api/ai/queries?limit=<n>&status=<s>&model=<m>&user_id=<id>``.

    Bug 2026-05-26 (AI-13 MOYEN) : ajout des filtres ``model`` et ``user_id``
    pour permettre à l'admin d'investiguer les anomalies (ex: échecs par
    modèle, requêtes d'un user spécifique).
    """

    #: Cap sur la longueur du paramètre ``model`` pour anti-DoS sur regex/
    #: index BDD (un model_name légitime ne dépasse pas ~50 chars).
    _MODEL_PARAM_MAX_LEN: Final[int] = 100

    @admin_required
    async def get(self) -> None:
        limit = _parse_int_arg(
            self.get_argument("limit", None),
            default=20,
            minimum=1,
            maximum=_MAX_LIMIT_ROWS,
        )
        status_raw = self.get_argument("status", None)
        if status_raw is not None and status_raw not in _ALLOWED_QUERY_STATUSES:
            _write_json_error(
                self,
                400,
                f"status invalide. Attendu : {', '.join(sorted(_ALLOWED_QUERY_STATUSES))}.",
            )
            return

        # AI-13 (2026-05-26) : filtre par modèle. Cap longueur anti-DoS.
        model_raw = self.get_argument("model", None)
        if model_raw is not None:
            model_raw = model_raw.strip()
            if not model_raw:
                model_raw = None
            elif len(model_raw) > self._MODEL_PARAM_MAX_LEN:
                _write_json_error(
                    self,
                    400,
                    f"Nom de modèle trop long (max {self._MODEL_PARAM_MAX_LEN}).",
                )
                return

        # AI-13 : filtre par user_id (entier strict, anti-injection).
        user_id_raw = self.get_argument("user_id", None)
        user_id_int: int | None = None
        if user_id_raw is not None and user_id_raw.strip():
            try:
                user_id_int = int(user_id_raw)
                if user_id_int < 1:
                    raise ValueError
            except (TypeError, ValueError):
                _write_json_error(self, 400, "user_id invalide (entier positif attendu).")
                return

        try:
            queries = await get_ai_stats_service().get_recent_queries(
                limit=limit,
                status=status_raw,
                model_name=model_raw,
                user_id=user_id_int,
            )
        except SQLAlchemyError:
            logger.error("Recent queries API: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement des requêtes.")
            return

        self.write({"success": True, "queries": queries})


class AIUsageAPIHandler(BaseHandler):
    """``GET /api/ai/usage?days=<n>`` — consommation API IA (tokens, coûts)."""

    @admin_required
    async def get(self) -> None:
        days = _parse_int_arg(
            self.get_argument("days", None),
            default=_DEFAULT_PERIOD,
            minimum=1,
            maximum=_MAX_PERIOD_DAYS,
        )
        try:
            stats_service = get_ai_stats_service()
            usage = await stats_service.get_usage_stats(days=days)
            by_user = await stats_service.get_usage_by_user(days=days)
            # Métriques additionnelles : budget mensuel + fallback compteur
            # (P2 #16 + #17). Best-effort : si le calcul échoue, on logue
            # mais on retourne quand même les stats principales — l'admin
            # ne doit pas perdre la consommation API à cause d'une métrique
            # secondaire.
            try:
                extras = await stats_service.get_dashboard_metrics(days=days)
            except SQLAlchemyError:
                logger.warning("Usage API: get_dashboard_metrics échoué", exc_info=True)
                extras = {}
        except SQLAlchemyError:
            logger.error("Usage API: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement de la consommation.")
            return
        self.write({"success": True, **usage, "by_user": by_user, **extras})


# ==========================================================================
# APIs CRUD — données d'entraînement
# ==========================================================================


class AITrainingDataAPIHandler(BaseHandler):
    """``GET`` / ``POST /api/ai/training`` — liste et création de training data."""

    @admin_required
    async def get(self) -> None:
        raw_type = self.get_argument("type", None)
        data_type, category_filter, valid_type = _resolve_training_type(raw_type)
        if not valid_type:
            _write_json_error(
                self,
                400,
                "Type de données invalide. Attendu : ddl, documentation, question_sql, "
                "ou business_context.",
            )
            return

        limit = _parse_int_arg(
            self.get_argument("limit", None),
            default=50,
            minimum=1,
            maximum=_MAX_LIMIT_ROWS,
        )
        offset = _parse_int_arg(
            self.get_argument("offset", None),
            default=0,
            minimum=0,
            maximum=_MAX_OFFSET_ROWS,
        )

        store = get_training_store()
        try:
            data = await store.get_all_training_data(
                data_type=data_type,
                limit=limit,
                offset=offset,
                category=category_filter,
            )
            stats = await store.get_stats()
        except SQLAlchemyError:
            logger.error("Training data GET: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement.")
            return

        self.write({"success": True, "data": data, "stats": stats})

    @admin_required
    async def post(self) -> None:
        try:
            body = self.load_json_body(max_bytes=_MAX_CONTENT_BYTES * 2)
        except ValueError as exc:
            _write_json_error(self, 400, str(exc))
            return

        data_type = body.get("type")
        user = self.current_user
        store = get_training_store()

        try:
            if data_type == "ddl":
                content = body.get("content", "")
                _validate_content_size(content, field="content")
                record_id = await store.add_ddl(
                    ddl=content,
                    table_name=body.get("table_name"),
                    user_id=user.id,
                )
            elif data_type == "documentation":
                content = body.get("content", "")
                _validate_content_size(content, field="content")
                tags = _coerce_tags(body.get("tags"))
                record_id = await store.add_documentation(
                    doc=content,
                    category=body.get("category"),
                    tags=tags,
                    user_id=user.id,
                )
            elif data_type == "question_sql":
                question = body.get("question", "")
                sql = body.get("sql", "")
                _validate_content_size(question, field="question")
                _validate_content_size(sql, field="sql")
                tags = _coerce_tags(body.get("tags"))
                record_id = await store.add_question_sql(
                    question=question,
                    sql=sql,
                    tags=tags,
                    quality_score=body.get("quality_score", 1.0),
                    user_id=user.id,
                )
            elif data_type == "business_context":
                content = body.get("content", "")
                _validate_content_size(content, field="content")
                tags_tables = _validate_tags_tables(body.get("tags_tables"))
                priority = int(body.get("priority", 0))
                if priority < _MIN_PRIORITY or priority > _MAX_PRIORITY:
                    raise ValueError(f"priority doit être entre {_MIN_PRIORITY} et {_MAX_PRIORITY}")
                record_id = await store.add_business_context(
                    content=content,
                    tags_tables=tags_tables,
                    priority=priority,
                    user_id=user.id,
                )
            else:
                _write_json_error(self, 400, "Type de données invalide")
                return
        except (KeyError, TypeError) as exc:
            logger.warning("Training POST: champ manquant %s", exc)
            _write_json_error(self, 400, "Données invalides ou champs manquants")
            return
        except ValueError as exc:
            logger.warning("Training POST: validation — %s", exc)
            _write_json_error(self, 400, f"Données invalides : {exc}")
            return
        except SQLValidationError as exc:
            # Bug n°4 fix (2026-05-26) : dry-run sur Sage a échoué.
            # 422 Unprocessable Entity = la requête est bien formée mais
            # son contenu (le SQL) est sémantiquement invalide pour le
            # serveur cible. L'admin/user voit le message exact du
            # serveur pour corriger.
            logger.warning("Training POST: SQL dry-run rejected — %s", exc)
            _write_json_error(self, 422, str(exc))
            return
        except SageConnectionError:
            logger.warning("Training POST: serveur source injoignable (dry-run)")
            _write_json_error(
                self,
                503,
                "Serveur de données source injoignable — réessayez. "
                "(Problème réseau, pas votre requête.)",
            )
            return
        except SQLAlchemyError:
            logger.error("Training POST: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors de l'ajout")
            return

        self.write({"success": True, "id": record_id})

    # ``_load_json_body`` promu dans ``BaseHandler.load_json_body`` (bug
    # 2026-05-26 AT-M7 — SSoT). Les call-sites passent ``max_bytes=
    # _MAX_CONTENT_BYTES * 2`` pour conserver la borne historique.


class AITrainingDataItemHandler(BaseHandler):
    """``PUT`` / ``DELETE /api/ai/training/<id>`` — update / soft-delete."""

    @admin_required
    async def delete(self, training_id: str) -> None:
        tid = _parse_int_path_or_400(self, training_id)
        if tid is None:
            return
        try:
            store = get_training_store()
            # Bug DA-C3 : bloque (409) si des DataAccessRule actives référencent
            # l'objet — sinon la closure transitive du mode invisible perd le
            # nœud → vues dérivées exposées aux users denied. Helper partagé
            # avec AITrainingRejectHandler (SSoT du guard, cf. #27).
            if await _block_if_data_access_referenced(self, store, tid):
                return
            deleted = await store.delete_training_data(tid)
        except SQLAlchemyError:
            logger.error("Training DELETE: erreur BDD id=%s", training_id, exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors de la suppression")
            return
        if not deleted:
            _write_json_error(self, 404, "Donnée non trouvée ou déjà désactivée")
            return
        self.write({"success": True})

    @admin_required
    async def put(self, training_id: str) -> None:
        """Met à jour une donnée d'entraînement — dispatch par ``type``.

        Types supportés (source : :data:`_TRAINING_PUT_TYPES`) :

        - ``business_context`` : content, tags_tables, priority, promote_to_manual
        - ``documentation``    : content, category, tags
        - ``ddl``              : content, table_name
        - ``question_sql``     : question, sql, tags, quality_score

        Le ``type`` est obligatoire dans le body pour éviter toute
        ambiguïté — le serveur ne devine pas quel genre de record il édite.
        """
        tid = _parse_int_path_or_400(self, training_id)
        if tid is None:
            return
        try:
            body = self.load_json_body(max_bytes=_MAX_CONTENT_BYTES * 2)
        except ValueError as exc:
            _write_json_error(self, 400, str(exc))
            return

        data_type = body.get("type")
        if data_type not in _TRAINING_PUT_TYPES:
            _write_json_error(
                self,
                400,
                "Type invalide. Attendu : " + ", ".join(_TRAINING_PUT_TYPES) + ".",
            )
            return

        # Bug 2026-05-26 (Agent 4 AT-M1) : verrou optimiste OPT-IN via
        # ``If-Unmodified-Since`` (header HTTP standard) ou ``if_unmodified_since``
        # (body kwarg). Si le caller fournit la valeur ``updated_at`` qu'il a
        # lue, on vérifie que l'enregistrement n'a pas bougé entre-temps.
        # Sinon 409 Conflict.
        # Rétro-compat : si AUCUN check fourni, on garde le comportement
        # last-write-wins legacy (pas de breaking).
        store = get_training_store()
        if_unmodified_since_header = self.request.headers.get("If-Unmodified-Since")
        if_unmodified_since_body = body.get("if_unmodified_since")
        if_unmodified_since = if_unmodified_since_body or if_unmodified_since_header
        if if_unmodified_since:
            # On charge le record pour comparer updated_at.
            try:
                from app.core.database import get_session
                from app.models.training_data import TrainingData
                from sqlalchemy import select

                async with get_session() as session:
                    record = (
                        await session.execute(select(TrainingData).where(TrainingData.id == tid))
                    ).scalar_one_or_none()
                if record is None:
                    _write_json_error(self, 404, "Donnée non trouvée")
                    return
                # Compare via ISO ; le client envoie updated_at qu'il a lu.
                current_iso = record.updated_at.isoformat() if record.updated_at else None
                if current_iso != if_unmodified_since:
                    # status=409 passé à write_json (et PAS set_status(409) avant
                    # un write_json sans status, qui ré-appliquerait 200). #28.
                    self.write_json(
                        {
                            "success": False,
                            "error": (
                                "Cette donnée a été modifiée par un autre "
                                "administrateur depuis votre dernier chargement. "
                                "Rechargez la page pour voir les changements."
                            ),
                            "current_updated_at": current_iso,
                        },
                        status=409,
                    )
                    return
            except SQLAlchemyError:
                logger.error(
                    "Training PUT: erreur BDD au check optimistic lock id=%s",
                    training_id,
                    exc_info=True,
                )
                _write_json_error(self, 500, "Erreur interne")
                return

        try:
            if data_type == "business_context":
                updated = await self._update_business_context(store, tid, body)
            elif data_type == "documentation":
                updated = await self._update_documentation(store, tid, body)
            elif data_type == "ddl":
                updated = await self._update_ddl(store, tid, body)
            else:  # question_sql — ordre de _TRAINING_PUT_TYPES garanti
                updated = await self._update_question_sql(store, tid, body)
        except ValueError as exc:
            logger.warning("Training PUT: validation — %s", exc)
            _write_json_error(self, 400, f"Données invalides : {exc}")
            return
        except SQLValidationError as exc:
            logger.warning("Training PUT: SQL refusé par le serveur — %s", exc)
            _write_json_error(self, 422, f"SQL refusé : {exc}")
            return
        except SageConnectionError:
            logger.warning("Training PUT: serveur source injoignable (dry-run)")
            _write_json_error(self, 503, "Serveur de données source injoignable — réessayez.")
            return
        except SQLAlchemyError:
            logger.error("Training PUT: erreur BDD id=%s", training_id, exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors de la mise à jour")
            return

        if not updated:
            _write_json_error(
                self,
                404,
                "Donnée non trouvée ou type incompatible "
                "(ex. : PUT documentation sur un record DDL).",
            )
            return

        self.write({"success": True, "id": tid, "type": data_type})

    # ``_load_json_body`` promu dans ``BaseHandler.load_json_body`` (bug
    # 2026-05-26 AT-M7 — SSoT, alias supprimé ici).

    # ── Dispatchers par type (statiques, testables en isolation) ────────

    @staticmethod
    async def _update_business_context(store: Any, record_id: int, body: dict[str, Any]) -> bool:
        content = body.get("content")
        tags_tables = body.get("tags_tables")
        priority = body.get("priority")
        promote = bool(body.get("promote_to_manual", False))

        if content is None and tags_tables is None and priority is None and not promote:
            raise ValueError("Aucun champ à modifier")

        _validate_content_size(content, field="content")
        clean_tags_tables: list[str] | None = None
        if tags_tables is not None:
            clean_tags_tables = _validate_tags_tables(tags_tables)
        if priority is not None:
            priority = int(priority)
            if priority < _MIN_PRIORITY or priority > _MAX_PRIORITY:
                raise ValueError(f"priority doit être entre {_MIN_PRIORITY} et {_MAX_PRIORITY}")

        return await store.update_business_context(
            record_id=record_id,
            content=content,
            tags_tables=clean_tags_tables,
            priority=priority,
            promote_to_manual=promote,
        )

    @staticmethod
    async def _update_documentation(store: Any, record_id: int, body: dict[str, Any]) -> bool:
        content = body.get("content")
        category = body.get("category")
        tags_raw = body.get("tags")
        if content is None and category is None and tags_raw is None:
            raise ValueError("Aucun champ à modifier")
        _validate_content_size(content, field="content")
        tags = _coerce_tags(tags_raw)
        return await store.update_documentation(
            record_id=record_id, content=content, category=category, tags=tags
        )

    @staticmethod
    async def _update_ddl(store: Any, record_id: int, body: dict[str, Any]) -> bool:
        content = body.get("content")
        table_name = body.get("table_name")
        tags_raw = body.get("tags")
        if content is None and table_name is None and tags_raw is None:
            raise ValueError("Aucun champ à modifier")
        _validate_content_size(content, field="content")
        tags = _coerce_tags(tags_raw)
        return await store.update_ddl(
            record_id=record_id, content=content, table_name=table_name, tags=tags
        )

    @staticmethod
    async def _update_question_sql(store: Any, record_id: int, body: dict[str, Any]) -> bool:
        question = body.get("question")
        sql = body.get("sql")
        tags_raw = body.get("tags")
        quality_score = body.get("quality_score")
        if question is None and sql is None and tags_raw is None and quality_score is None:
            raise ValueError("Aucun champ à modifier")
        _validate_content_size(question, field="question")
        _validate_content_size(sql, field="sql")
        tags = _coerce_tags(tags_raw)
        return await store.update_question_sql(
            record_id=record_id,
            question=question,
            sql=sql,
            tags=tags,
            quality_score=quality_score,
        )


class AITrainingPendingAPIHandler(BaseHandler):
    """``GET /api/ai/training/pending`` — items en attente de validation admin."""

    @admin_required
    async def get(self) -> None:
        limit = _parse_int_arg(
            self.get_argument("limit", None),
            default=50,
            minimum=1,
            maximum=_MAX_LIMIT_ROWS,
        )
        offset = _parse_int_arg(
            self.get_argument("offset", None),
            default=0,
            minimum=0,
            maximum=_MAX_OFFSET_ROWS,
        )
        store = get_training_store()
        try:
            pending = await store.get_pending_reviews(limit=limit, offset=offset)
            count = await store.count_pending_reviews()
        except SQLAlchemyError:
            logger.error("Training pending: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne")
            return
        self.write({"success": True, "data": pending, "total": count})


class AITrainingApproveHandler(BaseHandler):
    """``POST /api/ai/training/<id>/approve`` — approuve un item pending."""

    @admin_required
    async def post(self, training_id: str) -> None:
        tid = _parse_int_path_or_400(self, training_id)
        if tid is None:
            return
        store = get_training_store()
        try:
            approved = await store.approve_training_data(tid)
        except (ValueError, SQLValidationError) as exc:
            logger.warning("Training approve: SQL refusé id=%s — %s", training_id, exc)
            _write_json_error(self, 422, f"SQL refusé, approbation annulée : {exc}")
            return
        except SageConnectionError:
            logger.warning("Training approve: serveur source injoignable id=%s", training_id)
            _write_json_error(
                self, 503, "Serveur de données source injoignable — réessayez l'approbation."
            )
            return
        except SQLAlchemyError:
            logger.error("Training approve: erreur BDD id=%s", training_id, exc_info=True)
            _write_json_error(self, 500, "Erreur interne")
            return
        if approved:
            self.write({"success": True, "message": "Donnée approuvée et activée."})
        else:
            _write_json_error(self, 404, "Donnée non trouvée ou déjà approuvée.")


class AITrainingRejectHandler(BaseHandler):
    """``POST /api/ai/training/<id>/reject`` — soft-delete d'un item pending."""

    @admin_required
    async def post(self, training_id: str) -> None:
        tid = _parse_int_path_or_400(self, training_id)
        if tid is None:
            return
        store = get_training_store()
        try:
            # Même guard DA-C3 que le DELETE : reject est aussi un soft-delete,
            # il ne doit pas casser silencieusement la closure du mode invisible
            # (#27). SSoT via le helper partagé.
            if await _block_if_data_access_referenced(self, store, tid):
                return
            deleted = await store.delete_training_data(tid)
        except SQLAlchemyError:
            logger.error("Training reject: erreur BDD id=%s", training_id, exc_info=True)
            _write_json_error(self, 500, "Erreur interne")
            return
        if not deleted:
            _write_json_error(self, 404, "Donnée non trouvée ou déjà désactivée.")
            return
        self.write({"success": True, "message": "Donnée rejetée et désactivée."})


class AITrainingAutoRewritesAPIHandler(BaseHandler):
    """``GET /api/ai/training/auto-rewrites`` — liste des paires Q/SQL qui ont
    été réécrites automatiquement par la pipeline feature #7 (changement
    de version du serveur SQL Server). Permet à l'admin de reviewer les
    rewrites (notamment celles marquées ``needs_human_review``).

    Le champ ``extra_metadata.auto_rewrite`` contient :

    * ``rewritten_at`` (ISO 8601), ``from_version``, ``to_version``
    * ``broken_capabilities`` (liste des capabilities qui ont déclenché
      la réécriture)
    * ``old_sql`` (backup pour rollback)
    * ``model_used``, ``success``, ``needs_human_review``, ``error``

    Filtres query string :

    * ``?status=needs_review`` — uniquement les rewrites flaggées
      pour review humaine (success=False + needs_human_review=True).
    * ``?status=success`` — uniquement les rewrites réussies.
    * Sans filtre → toutes les paires avec ``auto_rewrite``.
    """

    @admin_required
    async def get(self) -> None:
        status_filter = (self.get_argument("status", "") or "").strip().lower()
        if status_filter and status_filter not in ("success", "needs_review"):
            _write_json_error(
                self,
                400,
                "status invalide. Attendu : 'success' ou 'needs_review'.",
            )
            return

        from app.models.training_data import TrainingData, TrainingDataType
        from app.core.database import get_session

        try:
            async with get_session() as session:
                # SELECT projection min — on n'a besoin que des champs
                # utiles à l'admin UX (pas tout l'ORM hydrate).
                stmt = select(
                    TrainingData.id,
                    TrainingData.question,
                    TrainingData.sql,
                    TrainingData.is_active,
                    TrainingData.pending_review,
                    TrainingData.extra_metadata,
                    TrainingData.updated_at,
                ).where(
                    TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                )
                rows = (await session.execute(stmt)).all()
        except SQLAlchemyError:
            logger.error("Auto-rewrites GET: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement.")
            return

        items = []
        for row in rows:
            (
                row_id,
                row_question,
                row_sql,
                row_is_active,
                row_pending_review,
                row_extra,
                row_updated_at,
            ) = row
            extra = row_extra or {}
            auto = extra.get("auto_rewrite")
            if not isinstance(auto, dict):
                continue
            # Filtrage status optionnel
            if status_filter == "success":
                if not auto.get("success"):
                    continue
            elif status_filter == "needs_review":
                if auto.get("success") or not auto.get("needs_human_review"):
                    continue
            items.append(
                {
                    "id": int(row_id),
                    "question": row_question or "",
                    "current_sql": row_sql or "",
                    "is_active": bool(row_is_active),
                    "pending_review": bool(row_pending_review),
                    "updated_at": (row_updated_at.isoformat() if row_updated_at else None),
                    "auto_rewrite": auto,
                }
            )

        # Sorted by most recent rewrite first (rewritten_at desc).
        items.sort(
            key=lambda i: i["auto_rewrite"].get("rewritten_at") or "",
            reverse=True,
        )
        self.write({"success": True, "count": len(items), "items": items})


class AITrainingRollbackRewriteHandler(BaseHandler):
    """``POST /api/ai/training/<id>/rollback-rewrite`` — restaure le SQL
    d'origine d'une paire qui a été auto-réécrite par feature #7.

    L'ancien SQL est lu depuis ``extra_metadata.auto_rewrite.old_sql``
    (backup posé par la pipeline). Le ``pending_review`` est remis à
    ``False`` (paire revue par admin = OK). Un audit log est créé
    pour traçabilité.

    Erreurs :

    * 404 si la paire n'existe pas
    * 422 si la paire n'a pas de backup ``auto_rewrite.old_sql``
      (jamais été réécrite)
    """

    @admin_required
    async def post(self, training_id: str) -> None:
        tid = _parse_int_path_or_400(self, training_id)
        if tid is None:
            return

        from app.models.training_data import TrainingData
        from app.models.audit import AuditLog, AuditAction
        from app.core.database import get_session

        try:
            async with get_session() as session:
                pair = (
                    await session.execute(select(TrainingData).where(TrainingData.id == tid))
                ).scalar_one_or_none()
                if pair is None:
                    _write_json_error(self, 404, "Paire Q/SQL introuvable.")
                    return
                extra = dict(pair.extra_metadata or {})
                auto = extra.get("auto_rewrite")
                if not isinstance(auto, dict) or not auto.get("old_sql"):
                    _write_json_error(
                        self,
                        422,
                        "Cette paire n'a pas de SQL d'origine sauvegardé "
                        "(jamais réécrite automatiquement).",
                    )
                    return
                # Garde anti double-rollback : si la paire a déjà été restaurée,
                # un second rollback ré-écraserait un éventuel ré-édit manuel
                # intervenu depuis. On refuse (409) et on invite à recharger.
                if auto.get("rolled_back"):
                    _write_json_error(
                        self,
                        409,
                        "Cette paire a déjà été restaurée. Rechargez la page "
                        "pour voir l'état actuel.",
                    )
                    return

                old_sql = auto["old_sql"]
                # Restaurer l'ancien SQL.
                pair.sql = old_sql
                pair.content = f"Question: {pair.question or ''}\nSQL: {old_sql}"
                pair.pending_review = False
                # Marquer le rollback dans l'historique (sans perdre
                # l'info de la rewrite précédente). DEEP-COPY via json
                # pour garantir que SQLAlchemy détecte la mutation
                # (par défaut, la classe JSON ne track pas les mutations
                # in-place sur dicts nested — Mutable.as_mutable n'est
                # pas wiré sur cette colonne).
                import json as _json

                new_auto = dict(auto)
                new_auto["rolled_back_at"] = clock.now().isoformat()
                new_auto["rolled_back"] = True
                new_extra = _json.loads(_json.dumps(extra))
                new_extra["auto_rewrite"] = new_auto
                pair.extra_metadata = new_extra

                # Audit log
                user = self.current_user
                session.add(
                    AuditLog.log_action(
                        action=AuditAction.TRAINING_DATA_AUTO_REWRITE,
                        user_id=user.id if user else None,
                        entity_type="training_data",
                        entity_id=tid,
                        details={
                            "action": "rollback",
                            "restored_sql": old_sql,
                            "previous_auto_rewrite": auto,
                        },
                    )
                )
                await session.commit()
        except SQLAlchemyError:
            logger.error("Rollback rewrite: erreur BDD id=%s", training_id, exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du rollback.")
            return

        self.write(
            {
                "success": True,
                "message": "SQL d'origine restauré.",
                "pair_id": tid,
            }
        )


# ==========================================================================
# APIs schéma et modèles
# ==========================================================================


class AISchemaTablesAPIHandler(BaseHandler):
    """``GET /api/ai/schema/tables`` — liste des tables connues (autocomplete UI).

    Stratégie fail-closed multi-source :

    1. Source de vérité : le connecteur BDD source (Sage ou équivalent).
    2. Fallback : schéma local (``schema_context.yaml`` / cache).
    3. Dernier recours : noms de tables connues du training store.

    Si tout échoue, on renvoie une liste vide — l'UI permet alors la saisie
    libre. Le champ ``source`` indique d'où provient la liste, pour le
    debug côté admin.
    """

    @admin_required
    async def get(self) -> None:
        tables: list[str] = []
        source = "empty"

        # 1. Connecteur BDD source
        try:
            # Lazy : évite un cycle import app.services.database.sage_connector
            # qui tire aujourd'hui app.core.database à l'init module.
            from app.services.database.sage_connector import get_sage_connector

            connector = get_sage_connector()
            # Phase α.4.E : handler admin → propager self.current_user
            # (admin → court-circuit naturel mais traçabilité audit).
            result = await connector.get_tables(user=self.current_user)
            if isinstance(result, list):
                tables = [t for t in result if isinstance(t, str) and t]
                if tables:
                    source = "sage"
        except (ConnectionError, OSError, SQLAlchemyError, RuntimeError, ValueError) as exc:
            logger.warning("schema/tables: connector indisponible — %s", exc)
        except Exception as exc:  # noqa: BLE001 — fallback filet final
            logger.warning("schema/tables: connector erreur inattendue — %s", exc, exc_info=True)

        # 2. Schéma local YAML
        if not tables:
            try:
                from app.services.ai.schema_loader import SchemaLoader
                from app.services.data_access.visible_schema import build_user_schema_view

                schema = SchemaLoader()
                # Phase α.4.E : matérialiser user_view (admin → has_restrictions=False).
                user_view = await build_user_schema_view(self.current_user)
                loaded = schema.get_tables(user_view=user_view)
                if isinstance(loaded, dict):
                    tables = list(loaded.keys())
                elif isinstance(loaded, list):
                    tables = list(loaded)
                if tables:
                    source = "yaml"
            except (FileNotFoundError, OSError, ValueError) as exc:
                logger.warning("schema/tables: schema_loader indisponible — %s", exc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("schema/tables: schema_loader inattendu — %s", exc, exc_info=True)

        # 3. Training store
        if not tables:
            try:
                store = get_training_store()
                # Phase α.4.E : propager user.
                tables = await store.get_all_table_names(user=self.current_user)
                if tables:
                    source = "training_store"
            except SQLAlchemyError as exc:
                logger.warning("schema/tables: training_store erreur — %s", exc)

        unique_tables = sorted({t for t in tables if isinstance(t, str) and t})
        self.write(
            {
                "success": True,
                "tables": unique_tables,
                "count": len(unique_tables),
                "source": source,
            }
        )


class AISchemaSyncAPIHandler(BaseHandler):
    """``POST /api/ai/schema-sync`` et ``GET /api/ai/schema-sync/history``."""

    @admin_required
    async def post(self) -> None:
        try:
            body = json.loads(self.request.body) if self.request.body else {}
        except (TypeError, ValueError) as exc:
            logger.warning("Sync schema: JSON invalide — %s", exc)
            _write_json_error(self, 400, "Requête mal formée (JSON invalide).")
            return
        if not isinstance(body, dict):
            _write_json_error(self, 400, "Le corps doit être un objet JSON.")
            return

        sync_source = body.get("source", "yaml")
        if sync_source not in _SYNC_SOURCES:
            _write_json_error(
                self,
                400,
                "source invalide. Attendu : " + ", ".join(sorted(_SYNC_SOURCES)) + ".",
            )
            return

        user = self.current_user
        sync_service = get_sync_service()

        try:
            if sync_source == "sage":
                result = await sync_service.sync_from_sage(user_id=user.id)
            else:
                result = await sync_service.sync_from_yaml(user_id=user.id, sync_type="manual")
        except RuntimeError as exc:
            logger.warning("Sync schema: lock conflict — %s", exc)
            self.set_status(409)
            self.write(
                {"error": ("Synchronisation déjà en cours. Réessayez dans quelques instants.")}
            )
            return
        except ValueError as exc:
            logger.warning("Sync schema: paramètre invalide — %s", exc)
            _write_json_error(self, 400, f"Paramètre invalide : {exc}")
            return
        except SQLAlchemyError:
            logger.error("Sync schema: erreur BDD", exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "error": (
                        "Erreur de base de données lors de la synchronisation. "
                        "La base locale peut être verrouillée. "
                        "Réessayez dans quelques instants."
                    )
                }
            )
            return

        self.write({"success": bool(result.get("success")), "result": result})

    @admin_required
    async def get(self) -> None:
        try:
            history = await get_sync_service().get_sync_history(limit=DEFAULT_PER_PAGE)
        except SQLAlchemyError:
            logger.error("Sync schema history: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du chargement de l'historique.")
            return
        self.write({"success": True, "history": history})


class AIModelsAPIHandler(BaseHandler):
    """``GET /api/ai/models[?provider=<name>]`` — modèles LLM disponibles."""

    @admin_required
    async def get(self) -> None:
        await ensure_providers_from_db()
        llm_manager = get_llm_manager()

        provider_name = self.get_argument("provider", None)
        if provider_name:
            await self._respond_for_provider(llm_manager, provider_name)
        else:
            await self._respond_for_all(llm_manager)

    async def _respond_for_provider(self, llm_manager: Any, provider_name: str) -> None:
        try:
            models = await llm_manager.list_models_for_provider(provider_name)
        except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
            logger.error("Modèles provider %s: erreur réseau/timeout", provider_name, exc_info=True)
            self.write(
                {
                    "success": False,
                    "error": self._provider_error_message(provider_name, exc),
                    "models": [],
                }
            )
            return
        self.write({"success": True, "provider": provider_name, "models": models})

    async def _respond_for_all(self, llm_manager: Any) -> None:
        try:
            all_models = await llm_manager.list_all_models()
            health = await llm_manager.health_check_all()
        except (ConnectionError, asyncio.TimeoutError, OSError):
            logger.error("Liste des modèles: erreur réseau/timeout", exc_info=True)
            _write_json_error(
                self, 503, "Les providers IA ne répondent pas. Réessayez dans un instant."
            )
            return
        self.write(
            {
                "success": True,
                "models": all_models,
                "health": health,
                "default_provider": llm_manager.default_provider_name,
                "default_model": llm_manager.default_model_name,
            }
        )

    @staticmethod
    def _provider_error_message(provider_name: str, exc: Exception) -> str:
        """Transforme une exception réseau en message utilisateur actionnable.

        L'analyse du message brut reste pragmatique : les libs LLM varient.
        """
        text = str(exc).lower()
        if isinstance(exc, asyncio.TimeoutError) or "timeout" in text:
            return (
                f"Le provider {provider_name} ne répond pas (timeout). "
                "Vérifiez votre connexion internet."
            )
        if "401" in text or "unauthorized" in text or "api key" in text:
            return f"Clé API invalide pour {provider_name}. Vérifiez la configuration."
        return (
            f"Impossible de contacter {provider_name}. "
            "Vérifiez votre connexion internet et la configuration."
        )


# ==========================================================================
# Feedback — soumission + export CSV
# ==========================================================================


class AIFeedbackAPIHandler(BaseHandler):
    """``POST /api/ai/feedback/<id>`` — soumettre un feedback utilisateur.

    Admin ⇒ le SQL validé est ajouté directement au training store.
    Non-admin ⇒ pending_review=True (l'item attend l'approbation admin).
    """

    @require_role("admin", "user")
    async def post(self, log_id: str) -> None:
        log_id_int = _parse_int_path_or_400(self, log_id)
        if log_id_int is None:
            return

        try:
            body = json.loads(self.request.body)
        except (TypeError, ValueError) as exc:
            logger.warning("Feedback: JSON invalide — %s", exc)
            _write_json_error(self, 400, "Données de feedback invalides")
            return
        if not isinstance(body, dict):
            _write_json_error(self, 400, "Le corps doit être un objet JSON")
            return

        feedback = body.get("feedback")
        if feedback not in _FEEDBACK_POLARITIES:
            _write_json_error(self, 400, "feedback doit être positive ou negative")
            return

        comment = body.get("comment")
        corrected_sql = body.get("corrected_sql")
        user = self.current_user
        # SSoT : helper base.is_admin (gère role enum ET string, fail-closed si
        # user None / sans role) au lieu d'une comparaison inline qui driftait.
        is_admin = _is_admin(user)

        try:
            natural_query, generated_sql = await self._persist_feedback(
                log_id_int,
                feedback=feedback,
                comment=comment,
                requester=user,
                is_admin=is_admin,
            )
        except LookupError:
            _write_json_error(self, 404, "Log non trouvé")
            return
        except SQLAlchemyError:
            logger.error("Feedback: erreur BDD log=%s", log_id_int, exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors du traitement du feedback")
            return

        training_added = False
        if feedback == "positive" and generated_sql:
            # ``corrected_sql or generated_sql`` aurait retombé sur
            # ``generated_sql`` pour une string vide / espaces — un admin
            # qui « vide » son correctif aurait enregistré l'original
            # silencieusement. On force la nullité explicite.
            sql_to_store = (
                corrected_sql
                if isinstance(corrected_sql, str) and corrected_sql.strip()
                else generated_sql
            )
            try:
                store = get_training_store()
                await store.add_question_sql(
                    question=natural_query or "",
                    sql=sql_to_store,
                    source="feedback",
                    user_id=user.id if user else None,
                    pending_review=not is_admin,
                )
                training_added = True
            except (SQLAlchemyError, ValueError):
                logger.exception("Feedback: ajout au training store échoué")

        self.write({"success": True, "training_added": training_added})

    async def _persist_feedback(
        self,
        log_id: int,
        *,
        feedback: str,
        comment: Any,
        requester: Any,
        is_admin: bool,
    ) -> tuple[str | None, str | None]:
        """Met à jour ``AIPerformanceLog`` et retourne ``(question, sql)``.

        Capture les deux valeurs **avant** commit car SQLAlchemy async
        expire les attributs après commit et le training store est appelé
        hors session. Lève :class:`LookupError` si le log n'existe pas
        (ou n'appartient pas au demandeur non-admin — cf. B5-F1).
        """
        async with get_session() as session:
            stmt = select(AIPerformanceLog).where(AIPerformanceLog.id == log_id)
            if not is_admin:
                # B5-F1 (isolation cross-user) : un non-admin ne peut donner un
                # feedback que sur SES propres logs. Sans ce filtre, il pourrait
                # (a) écraser le ``user_feedback``/``feedback_comment`` du log
                # d'un AUTRE user, et (b) injecter la question+SQL d'autrui dans
                # le training store (fuite cross-user + attribution faussée).
                # L'admin garde l'accès à tout (rôle de curation du training).
                # Le ``LookupError`` → 404 ne distingue pas "log inexistant" de
                # "log d'un autre" (anti-énumération).
                stmt = stmt.where(AIPerformanceLog.user_id == getattr(requester, "id", None))
            log_entry = (await session.execute(stmt)).scalar_one_or_none()
            if not log_entry:
                raise LookupError(f"log_id={log_id} introuvable")

            natural_query = log_entry.question
            generated_sql = log_entry.sql_generated

            log_entry.user_feedback = feedback
            log_entry.feedback_comment = comment
            await session.commit()

        return natural_query, generated_sql


class AIFeedbackExportHandler(BaseHandler):
    """``GET /api/ai/feedback/export?type=all|positive|negative`` — CSV."""

    # Entête du CSV (8 colonnes + 3 méta = 11 colonnes). Le nombre doit
    # rester égal à la ligne ``TRUNCATED`` émise en fin d'export.
    _CSV_HEADER: Final[tuple[str, ...]] = (
        "ID",
        "Date",
        "Utilisateur",
        "Question",
        "SQL généré",
        "Feedback",
        "Commentaire",
        "Statut",
        "Modèle",
        "Temps total (s)",
        "Corrigé",
    )

    @admin_required
    async def get(self) -> None:
        feedback_type = self.get_argument("type", "all")
        if feedback_type not in _FEEDBACK_EXPORT_TYPES:
            feedback_type = "all"

        try:
            logs, usernames, total_count = await self._collect_export_rows(feedback_type)
        except SQLAlchemyError:
            logger.error("Feedback export: erreur BDD", exc_info=True)
            _write_json_error(self, 500, "Erreur interne lors de l'export.")
            return

        # Bug 2026-05-26 (Agent 3 brainstorm AI-2 CRITIQUE) : avant ce fix,
        # ``question`` / ``sql_generated`` / ``feedback_comment`` étaient
        # exportés en clair vers TOUS les admins (CSV téléchargeable sans
        # trace). Ces 3 champs sont rédigés librement par l'utilisateur et
        # peuvent contenir des PII (emails, noms clients, montants, SIRET).
        #
        # On applique ``redact_pii_best_effort`` — le helper SSoT qui masque
        # emails + longs blocs numériques et tronque. Limites par champ :
        # - question : 500 chars (médiane <200, on garde large pour debug)
        # - sql_generated : 2000 chars (SELECT complexe possible)
        # - feedback_comment : 100 chars (signal seul, déjà tronqué côté UI)
        #
        # ⚠️ Cette redaction ne remplace PAS la pseudonymisation user-scoped
        # /data-privacy — elle bloque seulement les fuites triviales (un
        # admin ne peut pas charger le pseudonymizer du user d'origine).
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(self._CSV_HEADER)
        for log in logs:
            writer.writerow(
                [
                    log.id,
                    log.created_at.isoformat() if log.created_at else "",
                    csv_safe_cell(usernames.get(log.user_id, "") if log.user_id else ""),
                    csv_safe_cell(
                        redact_pii_best_effort(log.question or "", max_len=EXPORT_QUESTION_MAX_LEN)
                    ),
                    csv_safe_cell(
                        redact_pii_best_effort(log.sql_generated or "", max_len=EXPORT_SQL_MAX_LEN)
                    ),
                    log.user_feedback or "",
                    csv_safe_cell(redact_pii_best_effort(log.feedback_comment or "")),
                    log.status.value if log.status else "",
                    f"{log.model_provider}/{log.model_name}",
                    f"{log.total_time:.2f}" if log.total_time else "",
                    "Oui" if log.was_corrected else "Non",
                ]
            )

        truncated = total_count > _EXPORT_MAX_ROWS
        if truncated:
            # Ligne diagnostic sans données réelles — le consommateur doit
            # pouvoir la filtrer via le header HTTP ``X-Truncated`` qui
            # l'indique explicitement.
            writer.writerow(
                [
                    "TRUNCATED",
                    f"{total_count - _EXPORT_MAX_ROWS} lignes supplémentaires non exportées",
                ]
                + [""] * (len(self._CSV_HEADER) - 2)
            )

        # Audit log (AI-2) : trace forensic de chaque export pour pouvoir
        # corréler "fuite PII admin" à "qui a téléchargé quoi quand".
        # Best-effort — un échec d'audit ne doit pas bloquer l'export.
        exported_count = min(total_count, _EXPORT_MAX_ROWS)
        try:
            current_user = self.current_user
            user_id = getattr(current_user, "id", None) if current_user else None
            async with get_session() as audit_session:
                await audit_event(
                    audit_session,
                    user_id=user_id,
                    action="ai_feedback.export_csv",
                    entity_type="ai_performance_log",
                    entity_id=None,
                    details={
                        "feedback_type": feedback_type,
                        "total_count": int(total_count),
                        "exported": int(exported_count),
                        "truncated": bool(truncated),
                        "redacted": True,
                    },
                    ip_address=self.request.remote_ip,
                    user_agent=self.request.headers.get("User-Agent"),
                )
                await audit_session.commit()
        except (SQLAlchemyError, Exception) as exc:  # noqa: BLE001 - audit best-effort
            logger.warning("Feedback export: audit_event a échoué: %s", exc)

        filename_date = clock.now().strftime("%Y%m%d")
        self.set_header("Content-Type", "text/csv; charset=utf-8")
        self.set_header(
            "Content-Disposition",
            f'attachment; filename="ai_feedback_{filename_date}.csv"',
        )
        self.set_header("X-Total-Count", str(total_count))
        self.set_header("X-Truncated", "1" if truncated else "0")
        self.set_header("X-Export-Limit", str(_EXPORT_MAX_ROWS))
        # Header explicite : les clients peuvent vérifier que la redaction
        # a bien été appliquée (defense-in-depth pour audit).
        self.set_header("X-PII-Redacted", "1")
        self.write(output.getvalue())

    @staticmethod
    async def _collect_export_rows(
        feedback_type: str,
    ) -> tuple[list[AIPerformanceLog], dict[int, str], int]:
        """Charge les logs et la map ``user_id → username`` en une session.

        Retourne ``(logs, usernames, total_count)``. Le ``total_count``
        reflète la taille réelle avant troncature — les handlers l'utilisent
        pour les headers HTTP ``X-Truncated`` / ``X-Total-Count``.
        """
        async with get_session() as session:
            base_filter = [AIPerformanceLog.user_feedback.isnot(None)]
            if feedback_type != "all":
                base_filter.append(AIPerformanceLog.user_feedback == feedback_type)

            count_result = await session.execute(
                select(func.count()).select_from(AIPerformanceLog).where(*base_filter)
            )
            total_count = count_result.scalar() or 0

            query = (
                select(AIPerformanceLog)
                .where(*base_filter)
                .order_by(AIPerformanceLog.created_at.desc())
                .limit(_EXPORT_MAX_ROWS)
            )
            logs = list((await session.execute(query)).scalars().all())

            user_ids = {log.user_id for log in logs if log.user_id is not None}
            usernames: dict[int, str] = {}
            if user_ids:
                rows = await session.execute(
                    select(User.id, User.username).where(User.id.in_(user_ids))
                )
                usernames = {uid: uname for uid, uname in rows.all()}

        return logs, usernames, total_count


# Alias rétro-compatibilité : l'ancien nom reste importable pour éviter de
# casser une chaîne d'imports externes (pas d'usage dans la codebase à ce
# jour, mais le contrat public du module historique est ``*DeleteHandler``).
AITrainingDataDeleteHandler = AITrainingDataItemHandler


# ─────────────────────────────────────────────────────────────────────────
# Registre dynamique des modèles LLM — endpoints admin
# ─────────────────────────────────────────────────────────────────────────


class LlmModelRegistryHandler(BaseHandler):
    """``/api/admin/llm/models`` — listing du registre BDD + sync depuis API.

    GET   ``/api/admin/llm/models[?provider=anthropic]`` : liste depuis BDD.
    POST  ``/api/admin/llm/models/sync`` (body ``{provider}``) : déclenche
          la sync depuis l'API du provider, met à jour la BDD, retourne
          un compteur ``{inserted, updated, skipped_overridden}``.
    """

    @admin_required
    async def get(self) -> None:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        provider_filter = self.get_argument("provider", None)
        registry = get_llm_model_registry()
        async with self.db_session() as session:
            models = await registry.list_all(session, provider=provider_filter)
        self.write({"success": True, "models": models})


class LlmModelRegistrySyncHandler(BaseHandler):
    """``POST /api/admin/llm/models/sync`` — déclenche la sync registre BDD."""

    @admin_required
    async def post(self) -> None:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        body = self.request.body
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            _write_json_error(self, 400, "Body JSON invalide.")
            return
        provider_name = data.get("provider")
        if not isinstance(provider_name, str) or not provider_name.strip():
            _write_json_error(self, 400, "Champ 'provider' requis.")
            return
        await ensure_providers_from_db()
        registry = get_llm_model_registry()
        async with self.db_session() as session:
            stats = await registry.sync_from_provider(provider_name.strip(), session)
        self.write({"success": True, "stats": stats})


class LlmModelRegistryLitellmSyncHandler(BaseHandler):
    """``POST /api/admin/llm/models/sync-litellm`` — enrichit ``context_window`` /
    ``max_output_tokens`` des modèles BDD depuis le registre public LiteLLM.

    Pourquoi un endpoint séparé de ``/sync`` ? La sync provider (Anthropic,
    OpenAI) ne renvoie pas ces deux champs — il faut une source externe.
    LiteLLM est community-maintained, ~2700 modèles, à jour quasi-quotidien.

    Pas de payload requis. Optionnel : ``{"force_refresh": true}`` pour
    bypasser le cache disque 24h.
    """

    @admin_required
    async def post(self) -> None:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        force_refresh = False
        allow_regression = False
        body = self.request.body
        if body:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                _write_json_error(self, 400, "Body JSON invalide.")
                return
            # Body optionnel : ``{}`` toléré, mais un JSON valide non-objet
            # (``[1, 2]``, ``"x"``, ``42``) doit être rejeté en 400 avant
            # d'appeler ``.get`` qui lèverait AttributeError → 500.
            if not isinstance(data, dict):
                _write_json_error(self, 400, "Body doit être un objet JSON.")
                return
            force_refresh = bool(data.get("force_refresh"))
            allow_regression = bool(data.get("allow_regression"))
        registry = get_llm_model_registry()
        async with self.db_session() as session:
            stats = await registry.enrich_from_litellm(
                session,
                force_refresh=force_refresh,
                allow_regression=allow_regression,
            )
        self.write({"success": True, "stats": stats})


class LlmModelOverrideHandler(BaseHandler):
    """``PATCH /api/admin/llm/models/{name}`` — override manuel d'un modèle.

    Accepte les caractéristiques admin-éditables : ``context_window``,
    ``max_output_tokens``, ``input_price_per_mtok_usd``,
    ``output_price_per_mtok_usd``, ``supports_extended_thinking``,
    ``supports_prompt_caching``, ``supports_tool_use``, ``deprecated_at``.
    Set automatiquement ``manually_overridden=True`` (sync ne réécrit plus).
    """

    @admin_required
    async def patch(self, name: str) -> None:
        from sqlalchemy import select

        from app.models.llm_model import LlmModel
        from app.services.ai.llm_model_registry import get_llm_model_registry

        body = self.request.body
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            _write_json_error(self, 400, "Body JSON invalide.")
            return
        if not isinstance(data, dict):
            _write_json_error(self, 400, "Body doit être un objet JSON.")
            return

        # Bornes supérieures : garde-fou contre erreur de saisie admin
        # (un context_window à 10**9 ou un pricing à 999_999 USD/Mtok est
        # presque certainement une faute de frappe). 10M tokens couvre
        # largement les modèles 2026 (Sonnet 4.6 GA = 1M, Gemini 2M, Opus
        # futur 5M théorique). Pas de borne sur les flags bool.
        editable_int_bounds = {
            "context_window": 10_000_000,
            "max_output_tokens": 1_000_000,
        }
        editable_float_bounds = {
            "input_price_per_mtok_usd": 10_000.0,
            "output_price_per_mtok_usd": 10_000.0,
        }
        editable_bool = {
            "supports_extended_thinking",
            "supports_prompt_caching",
            "supports_tool_use",
        }

        async with self.db_session() as session:
            row = (
                await session.execute(select(LlmModel).where(LlmModel.name == name))
            ).scalar_one_or_none()
            if row is None:
                _write_json_error(self, 404, f"Modèle '{name}' introuvable.")
                return

            changed = False
            for key, upper in editable_int_bounds.items():
                if key in data:
                    val = data[key]
                    # Garde-fou : ``bool`` est un sous-type de ``int`` en
                    # Python, donc ``isinstance(True, int)`` → True. Sans
                    # exclusion, ``True`` passerait pour 1 et ``False`` pour
                    # 0 — un override ``max_output_tokens=False`` casserait
                    # silencieusement le runtime (val=0 → API rejette).
                    if not isinstance(val, int) or isinstance(val, bool) or val <= 0 or val > upper:
                        _write_json_error(
                            self,
                            400,
                            f"'{key}' doit être un entier dans ]0, {upper}] " f"(reçu : {val!r}).",
                        )
                        return
                    setattr(row, key, val)
                    changed = True
            for key, upper in editable_float_bounds.items():
                if key in data:
                    val = data[key]
                    # Pricing 0.0 LÉGITIME (free tier, modèle preview) → on
                    # accepte ``val >= 0``. Mais ``bool`` exclu : ``False``
                    # passerait pour 0.0, masquant un denial-of-wallet en
                    # zéroisant silencieusement la facturation.
                    if (
                        not isinstance(val, (int, float))
                        or isinstance(val, bool)
                        or val < 0
                        or val > upper
                    ):
                        _write_json_error(
                            self,
                            400,
                            f"'{key}' doit être un nombre dans [0, {upper}] " f"(reçu : {val!r}).",
                        )
                        return
                    setattr(row, key, float(val))
                    changed = True
            for key in editable_bool:
                if key in data:
                    val = data[key]
                    if not isinstance(val, bool):
                        _write_json_error(
                            self,
                            400,
                            f"'{key}' doit être un booléen (reçu : {val!r}).",
                        )
                        return
                    setattr(row, key, val)
                    changed = True
            if "deprecated" in data:
                if bool(data["deprecated"]):
                    row.deprecated_at = clock.now()
                else:
                    row.deprecated_at = None
                changed = True

            if changed:
                row.manually_overridden = True
                await session.commit()
                # Warm-up cache immédiat : sans ça, les helpers sync (ex:
                # ``constants_ai.get_max_tokens_for_model``) retombent sur le
                # static jusqu'au prochain ``_ensure_loaded`` async (qui peut
                # ne jamais arriver pendant un run agentic). On garantit que
                # l'override admin agit dès la prochaine lecture sync.
                registry = get_llm_model_registry()
                cache_warmed = True
                try:
                    await registry.reload_from_db(session)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "Override admin pour '%s' commit OK mais warm-up cache "
                        "échoué (%s) — l'override n'agira qu'au prochain reload.",
                        name,
                        exc,
                    )
                    cache_warmed = False
                self.write(
                    {
                        "success": True,
                        "model": row.to_dict(),
                        "cache_warmed": cache_warmed,
                    }
                )
                return

            self.write({"success": True, "model": row.to_dict()})


class LocalLlmInstallStatusHandler(BaseHandler):
    """``GET /api/admin/llm-local/install-status`` — détecte le binaire Ollama.

    Retourne :
    - ``installed`` (bool) : ``ollama`` est dans le PATH
    - ``version`` (str | null) : output de ``ollama --version`` si installé
    - ``running`` (bool) : le daemon tourne déjà (ping :11434)
    - ``binary_path`` (str | null) : path résolu (debug)

    Usage frontend : si pas installé → afficher lien vers ollama.com.
    Si installé mais pas running → afficher bouton "Démarrer Ollama".
    Si running → tout est OK, l'utilisateur peut télécharger un modèle.
    """

    @admin_required
    async def get(self) -> None:
        import shutil
        import subprocess

        result = {
            "installed": False,
            "version": None,
            "running": False,
            "binary_path": None,
        }
        binary = shutil.which("ollama")
        if binary:
            result["installed"] = True
            result["binary_path"] = binary
            try:
                # ``ollama --version`` est instant + sécurisé (pas d'argv user)
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [binary, "--version"],
                    capture_output=True,
                    timeout=5,
                    text=True,
                )
                if proc.returncode == 0 and proc.stdout:
                    result["version"] = proc.stdout.strip()[:200]
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("ollama --version échoué : %s", exc)

        # Ping daemon
        import httpx

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0)) as client:
                resp = await client.get("http://localhost:11434/api/tags")
                if resp.status_code == 200:
                    result["running"] = True
        except (httpx.RequestError, OSError):
            pass
        self.write(result)


class LocalLlmRestartHandler(BaseHandler):
    """``POST /api/admin/llm-local/restart`` — kill + relance Ollama.

    Utile quand le runner est en zombie (CPU 0%, ne répond plus) — bug
    courant sur Ollama < 0.7. ``pkill -9 ollama`` puis relance.
    """

    @admin_required
    async def post(self) -> None:
        import shutil
        import subprocess
        import asyncio as _asyncio

        binary = shutil.which("ollama")
        if not binary:
            _write_json_error(
                self,
                404,
                "Ollama n'est pas installé. Télécharger depuis https://ollama.com.",
            )
            return

        # Kill via subprocess (pkill avec timeout) — sécurisé car le
        # nom 'ollama' est constant, pas d'argv user.
        try:
            await _asyncio.to_thread(
                subprocess.run,
                ["pkill", "-9", "-f", "ollama"],
                capture_output=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("pkill ollama échoué : %s", exc)

        # Petite attente pour que les processes soient bien tués
        await _asyncio.sleep(1.5)

        # Relance via le même mécanisme que /start
        try:
            kwargs: Dict[str, Any] = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "stdin": subprocess.DEVNULL,
            }
            import os as _os

            if _os.name == "posix":
                kwargs["start_new_session"] = True
            else:
                kwargs["creationflags"] = 0x00000200
            subprocess.Popen([binary, "serve"], **kwargs)  # noqa: S603
        except OSError as exc:
            _write_json_error(self, 500, f"Relance Ollama échouée : {exc}")
            return

        # Poll que le daemon réponde (10s max, redémarrage = un peu lent)
        import httpx

        for _ in range(100):
            await _asyncio.sleep(0.1)
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(1.0)) as client:
                    resp = await client.get("http://localhost:11434/api/tags")
                    if resp.status_code == 200:
                        self.write({"success": True, "message": "Ollama redémarré."})
                        return
            except (httpx.RequestError, OSError):
                continue

        _write_json_error(
            self,
            504,
            "Ollama relancé mais ne répond pas après 10s. Réessayer.",
        )


class LocalLlmUpgradeHandler(BaseHandler):
    """``POST /api/admin/llm-local/upgrade`` — met à jour Ollama via brew.

    Cross-platform :
    - macOS avec brew : ``brew upgrade ollama``. Marche pour 90% des installs Mac.
    - Linux : exécute ``curl https://ollama.com/install.sh | sh`` (script officiel)
    - Windows : retourne 501 + lien manuel (pas de manager standard)
    """

    @admin_required
    async def post(self) -> None:
        import os as _os
        import shutil
        import subprocess
        import asyncio as _asyncio

        ollama_bin = shutil.which("ollama")
        if not ollama_bin:
            _write_json_error(
                self,
                404,
                "Ollama n'est pas installé.",
            )
            return

        # macOS : brew si disponible
        if _os.uname().sysname == "Darwin" and shutil.which("brew"):
            try:
                proc = await _asyncio.to_thread(
                    subprocess.run,
                    ["brew", "upgrade", "ollama"],
                    capture_output=True,
                    timeout=300,
                    text=True,
                )
                if proc.returncode != 0:
                    _write_json_error(
                        self,
                        500,
                        f"brew upgrade a échoué : {proc.stderr[:300]}",
                    )
                    return
                output = (proc.stdout or proc.stderr or "")[-500:]
                self.write(
                    {
                        "success": True,
                        "method": "brew",
                        "output": output,
                        "message": "Ollama mis à jour via Homebrew. Penser à redémarrer le daemon.",
                    }
                )
                return
            except subprocess.TimeoutExpired:
                _write_json_error(self, 504, "brew upgrade timeout (5min).")
                return
            except OSError as exc:
                _write_json_error(self, 500, f"brew upgrade erreur : {exc}")
                return

        # Linux : script officiel
        if _os.uname().sysname == "Linux":
            try:
                # Pipe curl → sh via shell=True. Le script vient d'un
                # domaine fixe (ollama.com), pas d'argv user.
                proc = await _asyncio.to_thread(
                    subprocess.run,
                    "curl -fsSL https://ollama.com/install.sh | sh",
                    shell=True,  # noqa: S602 — script officiel, pas d'input user
                    capture_output=True,
                    timeout=600,
                    text=True,
                )
                if proc.returncode != 0:
                    _write_json_error(
                        self,
                        500,
                        f"Script install.sh a échoué : {proc.stderr[:300]}",
                    )
                    return
                output = (proc.stdout or "")[-500:]
                self.write(
                    {
                        "success": True,
                        "method": "install.sh",
                        "output": output,
                        "message": "Ollama mis à jour via script officiel.",
                    }
                )
                return
            except subprocess.TimeoutExpired:
                _write_json_error(self, 504, "Script install timeout (10min).")
                return
            except OSError as exc:
                _write_json_error(self, 500, f"Install script erreur : {exc}")
                return

        # Windows ou OS inconnu — pas d'auto-upgrade
        _write_json_error(
            self,
            501,
            "Mise à jour automatique non supportée sur cet OS. "
            "Télécharger manuellement depuis https://ollama.com.",
        )


class LocalLlmStartHandler(BaseHandler):
    """``POST /api/admin/llm-local/start`` — lance ``ollama serve`` en background.

    Sécurité :
    - admin only (``@admin_required``)
    - binaire résolu via ``shutil.which`` (pas d'argv user)
    - argument fixe ``serve`` (pas contrôlable par le caller)
    - launch via ``subprocess.Popen`` détaché (pas attendu) — le daemon
      écoute sur localhost:11434 par défaut
    - vérification finale : ping le daemon dans les 5s, retourne success

    Si le daemon tourne déjà : retourne 200 + ``already_running: true``.
    Si binaire absent : 404 + lien install.
    """

    @admin_required
    async def post(self) -> None:
        import shutil
        import subprocess

        import httpx

        # Vérif rapide : déjà running ?
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(1.5)) as client:
                resp = await client.get("http://localhost:11434/api/tags")
                if resp.status_code == 200:
                    self.write(
                        {
                            "success": True,
                            "already_running": True,
                            "message": "Ollama tourne déjà.",
                        }
                    )
                    return
        except (httpx.RequestError, OSError):
            pass

        binary = shutil.which("ollama")
        if not binary:
            _write_json_error(
                self,
                404,
                "Ollama n'est pas installé. Télécharger depuis https://ollama.com puis "
                "relancer.",
            )
            return

        # Lance le daemon détaché. ``DEVNULL`` pour ne pas remplir le FD du
        # process Tornado. ``start_new_session`` détache le process (sur
        # Unix : nouveau session group ; sur Windows : flag CREATE_NEW_PROCESS_GROUP).
        try:
            kwargs: Dict[str, Any] = {
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "stdin": subprocess.DEVNULL,
            }
            import os as _os

            if _os.name == "posix":
                kwargs["start_new_session"] = True
            else:
                # Windows : CREATE_NEW_PROCESS_GROUP (0x00000200)
                kwargs["creationflags"] = 0x00000200
            subprocess.Popen([binary, "serve"], **kwargs)  # noqa: S603
        except OSError as exc:
            _write_json_error(self, 500, f"Lancement Ollama échoué : {exc}")
            return

        # Attend que le daemon réponde (poll 100ms × 50 = 5s max)
        import asyncio as _asyncio

        for _ in range(50):
            await _asyncio.sleep(0.1)
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(1.0)) as client:
                    resp = await client.get("http://localhost:11434/api/tags")
                    if resp.status_code == 200:
                        self.write(
                            {
                                "success": True,
                                "already_running": False,
                                "message": "Ollama démarré avec succès.",
                            }
                        )
                        return
            except (httpx.RequestError, OSError):
                continue

        _write_json_error(
            self,
            504,
            "Ollama lancé mais pas encore joignable après 5s. Réessayer " "dans quelques secondes.",
        )


class LocalLlmStatusHandler(BaseHandler):
    """``GET /api/admin/llm-local/status`` — sondage Ollama joignable + modèles installés.

    Permet à la page admin d'afficher en temps réel :
    - L'état du serveur Ollama (joignable / pas joignable / pas configuré)
    - La liste des modèles déjà téléchargés sur la machine

    Pas de dépendance au registre BDD ``LlmModel`` — on tape directement
    ``GET {base_url}/api/tags`` (endpoint Ollama natif). Si l'admin
    utilise un autre serveur OpenAI-compat (LM Studio, TGI), le endpoint
    peut ne pas exposer cette route → on retourne ``models: []`` + un
    flag ``ollama_native: false`` pour que l'UI ne casse pas.
    """

    @admin_required
    async def get(self) -> None:
        import httpx

        from app.services.ai.config_service import get_ai_config_service

        cs = get_ai_config_service()
        try:
            enabled = bool(await cs.get("local_llm_enabled"))
        except Exception:  # noqa: BLE001
            enabled = False
        base_url = (await cs.get("local_llm_base_url") or "http://localhost:11434/v1").rstrip("/")
        configured_model = await cs.get("local_llm_model") or ""

        # Ollama expose `/api/tags` (sans `/v1`). On retire `/v1` du
        # base_url s'il y est pour pinger l'API native.
        ollama_root = base_url[:-3] if base_url.endswith("/v1") else base_url
        result = {
            "enabled": enabled,
            "base_url": base_url,
            "configured_model": configured_model,
            "reachable": False,
            "ollama_native": False,
            "models": [],
            "error": None,
        }
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(5.0)) as client:
                resp = await client.get(f"{ollama_root}/api/tags")
                if resp.status_code == 200:
                    payload = resp.json()
                    if isinstance(payload, dict) and isinstance(payload.get("models"), list):
                        result["reachable"] = True
                        result["ollama_native"] = True
                        # Format Ollama : [{"name":"phi3:mini","size":...},...]
                        result["models"] = [
                            {
                                "name": m.get("name", ""),
                                "size_bytes": m.get("size"),
                                "modified_at": m.get("modified_at"),
                            }
                            for m in payload["models"]
                            if isinstance(m, dict) and m.get("name")
                        ]
                else:
                    # Endpoint répond mais pas Ollama natif (LM Studio, etc.)
                    # → on tente OpenAI /v1/models en fallback.
                    try:
                        resp_v1 = await client.get(f"{base_url}/models")
                        if resp_v1.status_code == 200:
                            v1 = resp_v1.json()
                            data = v1.get("data") if isinstance(v1, dict) else None
                            if isinstance(data, list):
                                result["reachable"] = True
                                result["models"] = [
                                    {"name": m.get("id", "")}
                                    for m in data
                                    if isinstance(m, dict) and m.get("id")
                                ]
                    except (httpx.RequestError, ValueError):
                        pass
        except (httpx.RequestError, OSError) as exc:
            result["error"] = str(exc)
        self.write(result)


class LocalLlmPullHandler(BaseHandler):
    """``POST /api/admin/llm-local/pull`` — déclenche un téléchargement Ollama.

    Body : ``{"model": "phi3:mini"}``. Retourne ``200`` quand le pull est
    terminé (réponse Ollama). Pour les très gros modèles (>5 Go), le
    timeout HTTP côté admin est de 30 min — au-delà l'admin doit
    télécharger via CLI ``ollama pull``.

    **Sécurité** : seul l'admin peut déclencher un pull (consomme du
    disque). Le ``model`` est validé contre une regex stricte (alphanum
    + ``: . - _ /``) pour éviter une injection commande shell — bien
    qu'on n'invoque pas le shell directement (POST HTTP vers Ollama),
    c'est defense-in-depth.
    """

    _MODEL_NAME_RE = _OLLAMA_MODEL_NAME_RE  # backward-compat (tests externes)
    _PULL_TIMEOUT_SECONDS = 30 * 60

    @admin_required
    async def post(self) -> None:
        import httpx

        from app.services.ai.config_service import get_ai_config_service

        body = self.request.body
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            _write_json_error(self, 400, "Body JSON invalide.")
            return
        model_name = (data.get("model") or "").strip()
        if not _is_safe_ollama_model_name(model_name):
            _write_json_error(
                self,
                400,
                "Nom de modèle invalide. Attendu : alphanum + : . - _ / "
                "(pas de '..', '//', ni début par '.' ou '/').",
            )
            return
        cs = get_ai_config_service()
        base_url = (await cs.get("local_llm_base_url") or "http://localhost:11434/v1").rstrip("/")
        ollama_root = base_url[:-3] if base_url.endswith("/v1") else base_url
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._PULL_TIMEOUT_SECONDS)
            ) as client:
                # Ollama ``/api/pull`` stream du progress en NDJSON. On
                # lit jusqu'à la fin (status: success) puis retourne.
                async with client.stream(
                    "POST",
                    f"{ollama_root}/api/pull",
                    json={"name": model_name, "stream": True},
                ) as resp:
                    if resp.status_code != 200:
                        body_err = await resp.aread()
                        _write_json_error(
                            self,
                            resp.status_code,
                            f"Ollama pull a échoué : {body_err.decode('utf-8', 'ignore')[:200]}",
                        )
                        return
                    last_status = ""
                    total_bytes = 0
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            evt = json.loads(line)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        last_status = evt.get("status", last_status)
                        if isinstance(evt.get("total"), int):
                            total_bytes = evt["total"]
                        if evt.get("error"):
                            _write_json_error(
                                self,
                                500,
                                f"Ollama pull error : {evt['error']}",
                            )
                            return
            self.write(
                {
                    "success": True,
                    "model": model_name,
                    "status": last_status or "success",
                    "size_bytes": total_bytes,
                }
            )
        except (httpx.TimeoutException, asyncio.TimeoutError):
            _write_json_error(
                self,
                504,
                f"Pull timeout après {self._PULL_TIMEOUT_SECONDS}s. "
                "Pour les très gros modèles, utiliser `ollama pull` en CLI.",
            )
        except (httpx.RequestError, OSError) as exc:
            _write_json_error(
                self,
                502,
                f"Impossible de joindre Ollama : {exc}",
            )


class LocalLlmDeleteHandler(BaseHandler):
    """``POST /api/admin/llm-local/delete`` — supprime un modèle Ollama du disque.

    Body : ``{"model": "phi3:mini"}``. Appelle ``DELETE /api/delete`` côté
    Ollama (libère plusieurs Go disque selon le modèle). Nettoie aussi :

    1. ``LlmModel`` BDD : retire l'entrée si présente (cohérence registre).
    2. ``ai_config.local_llm_model`` : reset à ``""`` si c'était le modèle
       actif (sinon prochain run LLM local plantera sur modèle inexistant).

    Pattern défensif aligné avec :class:`LocalLlmPullHandler` : whitelist
    regex sur le nom (alphanum + ``: . - _ /``), admin-only, best-effort
    sur la BDD (un échec cleanup ne bloque pas le succès Ollama).

    Codes :

    - 200 : modèle supprimé d'Ollama (+ stats BDD/config).
    - 400 : nom invalide.
    - 404 : modèle inconnu côté Ollama (idempotent — propage tel quel).
    - 502 : impossible de joindre Ollama (réseau / Ollama down).
    """

    _MODEL_NAME_RE = _OLLAMA_MODEL_NAME_RE  # backward-compat (tests externes)
    _DELETE_TIMEOUT_SECONDS = 30.0

    @admin_required
    async def post(self) -> None:
        import httpx

        from app.services.ai.config_service import get_ai_config_service

        body = self.request.body
        try:
            data = json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            _write_json_error(self, 400, "Body JSON invalide.")
            return
        if not isinstance(data, dict):
            _write_json_error(self, 400, "Body doit être un objet JSON.")
            return
        model_name = (data.get("model") or "").strip()
        if not _is_safe_ollama_model_name(model_name):
            _write_json_error(
                self,
                400,
                "Nom de modèle invalide. Attendu : alphanum + : . - _ / "
                "(pas de '..', '//', ni début par '.' ou '/').",
            )
            return

        cs = get_ai_config_service()
        base_url = (await cs.get("local_llm_base_url") or "http://localhost:11434/v1").rstrip("/")
        ollama_root = base_url[:-3] if base_url.endswith("/v1") else base_url

        # 1. Suppression côté Ollama.
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(self._DELETE_TIMEOUT_SECONDS)
            ) as client:
                resp = await client.request(
                    "DELETE",
                    f"{ollama_root}/api/delete",
                    json={"name": model_name},
                )
        except (httpx.TimeoutException, asyncio.TimeoutError):
            _write_json_error(
                self,
                504,
                f"Timeout après {self._DELETE_TIMEOUT_SECONDS:.0f}s sur Ollama.",
            )
            return
        except (httpx.RequestError, OSError) as exc:
            _write_json_error(
                self,
                502,
                f"Impossible de joindre Ollama : {exc}",
            )
            return

        if resp.status_code == 404:
            # Idempotence : modèle déjà absent côté Ollama. On nettoie
            # quand même la BDD et la config — l'admin a peut-être supprimé
            # via CLI et veut juste recoller les artefacts.
            pass
        elif resp.status_code not in (200, 204):
            body_err = resp.text or "?"
            _write_json_error(
                self,
                resp.status_code,
                f"Ollama delete a échoué : {body_err[:200]}",
            )
            return

        # 2. Cleanup BDD + config (best-effort, ne bloque pas la réponse).
        cleanup_stats: Dict[str, Any] = {
            "model_removed_from_registry": False,
            "config_reset": False,
        }
        try:
            from sqlalchemy import delete as sql_delete, select

            from app.models.llm_model import LlmModel

            async with self.db_session() as session:
                # Supprime l'entrée du registre si elle existe (idempotent).
                row = (
                    await session.scalars(select(LlmModel).where(LlmModel.name == model_name))
                ).first()
                if row is not None:
                    await session.execute(sql_delete(LlmModel).where(LlmModel.name == model_name))
                    cleanup_stats["model_removed_from_registry"] = True
                    # Recharge le cache mémoire du registre après suppression.
                    # Sans ça, ``invalidate()`` ne gardant plus que la dernière
                    # valeur connue (contrat 2026-06-02), le modèle supprimé
                    # resterait « ressuscité » pour les lecteurs SYNCHRONES
                    # (``get_field_sync`` → ``constants_ai``, chemin chaud des
                    # appels LLM) jusqu'à ce qu'un admin rouvre /admin/ai-models.
                    # Mirror du handler PATCH (warm-up post-commit). Cf. review
                    # adversariale 2026-06-02 (finding #2).
                    from app.services.ai.llm_model_registry import get_llm_model_registry

                    await session.commit()
                    await get_llm_model_registry().reload_from_db(session)
                    cleanup_stats["registry_cache_reloaded"] = True

            # Reset config si c'était le modèle actif (sinon le prochain
            # appel LLM local pointera sur un modèle inexistant → erreur).
            current_local_model = (await cs.get("local_llm_model") or "").strip()
            if current_local_model == model_name:
                await cs.set("local_llm_model", "")
                cleanup_stats["config_reset"] = True
                # Invalide le provider live : sans ça, `_local_fallback_model`
                # garde l'ancienne valeur en RAM et le prochain appel fallback
                # tente Ollama avec un modèle qui n'existe plus → 404 opaque.
                try:
                    from app.services.ai.llm_providers import (
                        _load_local_fallback_from_config,
                        get_llm_manager,
                    )

                    await _load_local_fallback_from_config(get_llm_manager(), cs)
                    cleanup_stats["runtime_provider_refreshed"] = True
                except Exception as refresh_exc:  # noqa: BLE001
                    logger.warning(
                        "LocalLlmDeleteHandler refresh provider runtime échec : %s",
                        refresh_exc,
                    )
                    cleanup_stats["runtime_provider_refresh_error"] = str(refresh_exc)[:200]
        except Exception as exc:  # noqa: BLE001
            # Best-effort : la suppression Ollama a réussi, on log mais
            # on ne fail pas la réponse (l'admin peut nettoyer manuellement
            # via /admin/ai-models).
            logger.warning(
                "LocalLlmDeleteHandler cleanup BDD/config échec (non bloquant) : %s",
                exc,
            )
            cleanup_stats["cleanup_error"] = str(exc)[:200]

        self.write(
            {
                "success": True,
                "model": model_name,
                "ollama_status": resp.status_code,
                "cleanup": cleanup_stats,
            }
        )


__all__ = [
    "AIFeedbackAPIHandler",
    "AIFeedbackExportHandler",
    "AIModelsAPIHandler",
    "AIPerformanceDashboardHandler",
    "AIRecentQueriesAPIHandler",
    "AISchemaSyncAPIHandler",
    "AISchemaTablesAPIHandler",
    "AIStatsAPIHandler",
    "AITrainingApproveHandler",
    "AITrainingAutoRewritesAPIHandler",
    "AITrainingDataAPIHandler",
    "AITrainingDataDeleteHandler",
    "AITrainingDataItemHandler",
    "AITrainingPageHandler",
    "AITrainingPendingAPIHandler",
    "AITrainingRejectHandler",
    "AITrainingRollbackRewriteHandler",
    "AIUsageAPIHandler",
    "LlmModelRegistryHandler",
    "LlmModelRegistrySyncHandler",
    "LlmModelOverrideHandler",
    "LocalLlmStatusHandler",
    "LocalLlmPullHandler",
    "LocalLlmDeleteHandler",
    "LocalLlmInstallStatusHandler",
    "LocalLlmStartHandler",
    "LocalLlmRestartHandler",
    "LocalLlmUpgradeHandler",
]
