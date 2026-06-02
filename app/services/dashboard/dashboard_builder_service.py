"""
Service pour le Dashboard Builder — CRUD dashboards + widgets + récupération de données.

Gère la création, modification, suppression des tableaux de bord personnalisables
et l'exécution des sources de données (métriques prédéfinies ou SQL).
"""

import csv
import io
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import clock
from app.utils.output_safety import csv_safe_cell, excel_safe_cell

logger = logging.getLogger(__name__)


# ── Métriques prédéfinies disponibles ──────────────────────────────────────
# Chaque métrique est un callable async(session, user_id, period_days) -> dict
# Le dict retourné contient les données adaptées au type de widget.

AVAILABLE_METRICS = {
    "total_searches": {
        "label": "Recherches totales",
        "description": "Nombre total de recherches Iris",
        "supports": ["kpi", "chart"],
    },
    "success_rate": {
        "label": "Taux de succès",
        "description": "Pourcentage de recherches réussies",
        "supports": ["kpi"],
    },
    "daily_searches": {
        "label": "Recherches par jour",
        "description": "Nombre de recherches par jour sur la période",
        "supports": ["chart"],
    },
    "execution_status": {
        "label": "Statut des exécutions",
        "description": "Répartition succès/échec des automatisations",
        "supports": ["chart"],
    },
    "active_automations": {
        "label": "Automatisations actives",
        "description": "Nombre d'automatisations actuellement actives",
        "supports": ["kpi"],
    },
    "total_reports": {
        "label": "Rapports générés",
        "description": "Nombre total de rapports",
        "supports": ["kpi"],
    },
    "total_contacts": {
        "label": "Contacts",
        "description": "Nombre de contacts enregistrés",
        "supports": ["kpi"],
    },
    "recent_searches": {
        "label": "Dernières recherches",
        "description": "Liste des recherches récentes",
        "supports": ["table"],
    },
    # ``top_users`` et ``avg_response_time`` ont été retirés en 2026-05-09
    # (BLOCKING #4-5 review consolidée). Ces métriques agrégeaient
    # ``SearchHistory`` / ``AIPerformanceLog`` sans filtre ``user_id`` →
    # tout user voyait les stats de tous les autres users. Komptia étant
    # multi-user sans partage cross-user, c'était un leak silencieux. Le
    # monitoring admin global passe par /dashboard (page distincte gatée
    # par rôle), pas par les dashboards configurables /dashboards.
}


async def _scrub_dashboard_data_for_user(
    data: dict,
    user: Any,
) -> dict:
    """**#140** — Scrubbe un dict de dashboard (déjà sérialisé par
    :meth:`Dashboard.to_dict` et enrichi de ``widgets``/``filters``)
    pour remplacer les noms de tables/colonnes interdits par ``[…]``.

    Cas couverts (mode invisible rétroactif) :

    - ``data["name"]`` — titre du dashboard, saisi par l'admin.
    - ``data["description"]`` — description, peut mentionner une table.
    - ``data["template_description"]`` — même rationale (templates).
    - Pour chaque widget de ``data["widgets"]`` :
        - ``widget["title"]`` — affiché en gras au-dessus du widget.
        - ``widget["data_source_config"]`` (selon ``data_source_type``):
            - ``"sql"`` → scrub ``query`` (le SQL est lu dans l'éditeur).
            - ``"static"`` → scrub ``title`` et ``content`` (texte libre).

    **Stratégie** : ``user=None``, admin, ou sans restrictions → no-op
    (court-circuit). Sinon délégation à :func:`scrub_text_for_user`
    pour chaque champ string identifié.

    **Fail-safe** : si une scrub crash, on retourne la valeur originale
    (cf. comportement de :func:`scrub_text_for_user`). On ne casse
    JAMAIS le rendu du dashboard pour un hoquet BDD.

    **CRITICAL — Isolation des dicts imbriqués** : ``Widget.to_dict()``
    retourne ``self.data_source_config`` PAR RÉFÉRENCE (c'est un
    ``Mapped[dict]`` SQLAlchemy partagé avec l'instance ORM en
    mémoire). Sans deep-copy, mes mutations ici corrompraient
    l'instance ORM (et potentiellement la BDD via
    ``MutableDict.changed()`` côté SQLAlchemy 2.0). On force donc une
    deep-copy des dicts imbriqués AVANT mutation. Pas de copie du
    wrapper data — il est déjà éphémère (créé par ``to_dict``).

    **Returns** : le même wrapper dict (mutation in-place + retour pour
    chaînage). Les inner dicts sont REMPLACÉS par des copies.
    """
    if user is None or not isinstance(data, dict):
        return data
    import copy

    from app.services.data_access.error_messages import scrub_text_for_user

    async def _maybe_scrub(text: Any) -> Any:
        if not isinstance(text, str) or not text:
            return text
        try:
            return await scrub_text_for_user(text, user, context_label="dashboard_persisted")
        except Exception:
            return text

    for top_field in ("name", "description", "template_description"):
        if top_field in data:
            data[top_field] = await _maybe_scrub(data.get(top_field))

    widgets = data.get("widgets")
    if isinstance(widgets, list):
        for idx, widget in enumerate(widgets):
            if not isinstance(widget, dict):
                continue
            widget["title"] = await _maybe_scrub(widget.get("title"))
            dsc_original = widget.get("data_source_config")
            if isinstance(dsc_original, dict):
                # Deep-copy avant mutation pour ne PAS corrompre
                # l'instance ORM partagée.
                dsc = copy.deepcopy(dsc_original)
                dst = widget.get("data_source_type")
                if dst == "sql":
                    dsc["query"] = await _maybe_scrub(dsc.get("query"))
                elif dst == "static":
                    dsc["title"] = await _maybe_scrub(dsc.get("title"))
                    dsc["content"] = await _maybe_scrub(dsc.get("content"))
                # metric : pas de free-text user, rien à scrubber.
                widget["data_source_config"] = dsc
    return data


class DashboardBuilderService:
    """Service pour gérer les dashboards personnalisables."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    # ── CRUD Dashboard ─────────────────────────────────────────────────────

    async def list_dashboards(
        self,
        session: AsyncSession,
        user_id: int,
        user: Any = None,
    ) -> list[dict]:
        """Liste les dashboards de l'utilisateur courant.

        Strict scope owner-only — aucun partage cross-user. Chaque user voit
        UNIQUEMENT ses propres dashboards (cf. tâche #29 : suppression du
        partage cross-user).

        **#140** — Si ``user`` est passé (objet User du caller), scrub
        les champs textuels (``name``, ``description``,
        ``template_description``) pour retirer les noms de tables
        denied. Sans ``user``, fallback comportement legacy (aucun
        scrub) pour les callers backend/scheduler qui n'ont pas de
        contexte utilisateur.
        """
        from app.models.dashboard import Dashboard

        stmt = (
            select(Dashboard)
            .where(
                Dashboard.user_id == user_id,
                Dashboard.is_template.is_(False),
            )
            .order_by(Dashboard.updated_at.desc())
        )
        result = await session.execute(stmt)
        dashboards = result.scalars().all()

        out = [d.to_dict() for d in dashboards]
        if user is not None:
            for item in out:
                await _scrub_dashboard_data_for_user(item, user)
        return out

    async def get_dashboard(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        user: Any = None,
    ) -> Optional[dict]:
        """Récupère un dashboard avec ses widgets (owner only).

        Retourne ``None`` si le dashboard n'existe pas OU s'il n'appartient
        pas au user courant — aucune distinction entre "introuvable" et
        "interdit" pour ne pas leaker l'existence cross-user (fail-closed).

        **#140** — Si ``user`` est passé, scrub les champs textuels
        sensibles (name/description/widget.title/widget.sql/widget.text)
        pour retirer les noms de tables denied. Le user étant le owner
        du dashboard, ce sont SES anciens widgets (créés avant la pose
        de la règle deny) qui leakent les noms désormais interdits.
        Sans ``user``, fallback comportement legacy (aucun scrub) pour
        les callers backend/scheduler.
        """
        from app.models.dashboard import Dashboard

        stmt = (
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .options(selectinload(Dashboard.filters))
            .where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        )
        result = await session.execute(stmt)
        dashboard = result.scalar_one_or_none()

        if not dashboard:
            return None

        data = dashboard.to_dict()
        data["widgets"] = [w.to_dict() for w in dashboard.widgets]
        data["filters"] = [f.to_dict() for f in dashboard.filters]
        if user is not None:
            await _scrub_dashboard_data_for_user(data, user)
        return data

    async def create_dashboard(
        self, session: AsyncSession, user_id: int, name: str, description: str = ""
    ) -> dict:
        """Crée un nouveau dashboard."""
        from app.models.dashboard import Dashboard

        if not name or not name.strip():
            raise ValueError("Le nom du dashboard est obligatoire.")

        name = name.strip()[:200]

        dashboard = Dashboard(
            name=name,
            description=description.strip()[:1000] if description else None,
            user_id=user_id,
        )
        session.add(dashboard)
        await session.flush()

        data = dashboard.to_dict()
        await session.commit()

        logger.info("Dashboard créé: id=%s, user=%s", data["id"], user_id)
        # Hook auto-scan anonymization (fire-and-forget) — alimente
        # /data/privacy sans attendre "Scanner mes données".
        from app.services.anonymization.auto_scan import schedule_target_rescan

        schedule_target_rescan(user_id, "dashboard", int(data["id"]))
        return data

    async def update_dashboard(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        updates: dict,
    ) -> Optional[dict]:
        """Met à jour un dashboard (nom, description) — owner only."""
        from app.models.dashboard import Dashboard

        stmt = select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        result = await session.execute(stmt)
        dashboard = result.scalar_one_or_none()

        if not dashboard:
            return None

        allowed_fields = {"name", "description"}
        for field, value in updates.items():
            if field not in allowed_fields:
                continue
            if field == "name":
                if not value or not str(value).strip():
                    raise ValueError("Le nom ne peut pas être vide.")
                value = str(value).strip()[:200]
            elif field == "description":
                value = str(value).strip()[:1000] if value else None
            setattr(dashboard, field, value)

        data = dashboard.to_dict()
        await session.commit()

        logger.info("Dashboard mis à jour: id=%s", dashboard_id)
        from app.services.anonymization.auto_scan import schedule_target_rescan

        schedule_target_rescan(user_id, "dashboard", dashboard_id)
        return data

    async def delete_dashboard(
        self, session: AsyncSession, dashboard_id: int, user_id: int
    ) -> bool:
        """Supprime un dashboard (cascade supprime les widgets)."""
        from app.models.dashboard import Dashboard

        stmt = select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        result = await session.execute(stmt)
        dashboard = result.scalar_one_or_none()

        if not dashboard:
            return False

        await session.delete(dashboard)
        await session.commit()

        logger.info("Dashboard supprimé: id=%s", dashboard_id)
        return True

    async def clone_dashboard(
        self, session: AsyncSession, dashboard_id: int, user_id: int
    ) -> Optional[dict]:
        """Clone un dashboard avec tous ses widgets (owner only).

        Retourne ``None`` si le dashboard n'existe pas OU s'il n'appartient
        pas au user courant. Aucun clonage cross-user — chaque user voit
        uniquement ses propres dashboards (cf. tâche #29).
        """
        from app.models.dashboard import Dashboard, DashboardWidget

        # Charger l'original avec widgets — strict ownership inclus dans le WHERE
        stmt = (
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .options(selectinload(Dashboard.filters))
            .where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        )
        result = await session.execute(stmt)
        original = result.scalar_one_or_none()

        if not original:
            return None

        # Capturer les données des widgets avant toute opération
        widget_configs = []
        for w in original.widgets:
            widget_configs.append(
                {
                    "title": w.title,
                    "widget_type": w.widget_type,
                    "chart_type": w.chart_type,
                    "data_source_type": w.data_source_type,
                    "data_source_config": w.data_source_config,
                    "col_span": w.col_span,
                    "position_order": w.position_order,
                    "style_config": w.style_config,
                }
            )

        # Créer le clone
        clone = Dashboard(
            name=f"{original.name} (copie)",
            description=original.description,
            user_id=user_id,
        )
        session.add(clone)
        await session.flush()

        # Cloner les widgets
        for wc in widget_configs:
            widget = DashboardWidget(dashboard_id=clone.id, **wc)
            session.add(widget)

        # Cloner les filtres
        from app.models.dashboard import DashboardFilter

        for f in original.filters:
            filter_clone = DashboardFilter(
                dashboard_id=clone.id,
                parameter_name=f.parameter_name,
                label=f.label,
                filter_type=f.filter_type,
                values_source=f.values_source,
                values_config=f.values_config,
                default_value=f.default_value,
                position_order=f.position_order,
            )
            session.add(filter_clone)

        data = clone.to_dict()
        await session.commit()

        logger.info("Dashboard cloné: original=%s → clone=%s", dashboard_id, data["id"])
        return data

    # ── CRUD Widgets ───────────────────────────────────────────────────────

    async def add_widget(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        widget_data: dict,
    ) -> Optional[dict]:
        """Ajoute un widget à un dashboard."""
        from app.models.dashboard import Dashboard, DashboardWidget

        # Vérifier ownership du dashboard
        stmt = select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        result = await session.execute(stmt)
        dashboard = result.scalar_one_or_none()
        if not dashboard:
            return None

        # Calculer position_order (prochain index)
        count_stmt = (
            select(func.count())
            .select_from(DashboardWidget)
            .where(DashboardWidget.dashboard_id == dashboard_id)
        )
        count_result = await session.execute(count_stmt)
        next_order = count_result.scalar() or 0

        # Normalisation : chart_type="" est équivalent à None (signal "auto")
        chart_type_raw = widget_data.get("chart_type")
        chart_type = chart_type_raw.strip() if isinstance(chart_type_raw, str) else chart_type_raw
        if chart_type in (None, "", "auto"):
            chart_type = None

        widget = DashboardWidget(
            dashboard_id=dashboard_id,
            title=str(widget_data.get("title", "")).strip()[:200],
            widget_type=widget_data.get("widget_type", "chart"),
            chart_type=chart_type,
            data_source_type=widget_data.get("data_source_type", "metric"),
            data_source_config=widget_data.get("data_source_config"),
            col_span=widget_data.get("col_span", 6),
            position_order=widget_data.get("position_order", next_order),
            style_config=widget_data.get("style_config"),
        )

        errors = widget.validate()
        if errors:
            raise ValueError("; ".join(errors))

        session.add(widget)
        await session.flush()
        data = widget.to_dict()
        await session.commit()

        logger.info("Widget ajouté: id=%s, dashboard=%s", data["id"], dashboard_id)
        from app.services.anonymization.auto_scan import schedule_target_rescan

        schedule_target_rescan(user_id, "dashboard", dashboard_id)
        return data

    async def update_widget(
        self,
        session: AsyncSession,
        widget_id: int,
        dashboard_id: int,
        user_id: int,
        updates: dict,
    ) -> Optional[dict]:
        """Met à jour un widget."""
        from app.models.dashboard import Dashboard, DashboardWidget

        # Vérifier ownership via dashboard
        stmt = (
            select(DashboardWidget)
            .join(Dashboard)
            .where(
                DashboardWidget.id == widget_id,
                DashboardWidget.dashboard_id == dashboard_id,
                Dashboard.user_id == user_id,
            )
        )
        result = await session.execute(stmt)
        widget = result.scalar_one_or_none()

        if not widget:
            return None

        allowed = {
            "title",
            "widget_type",
            "chart_type",
            "data_source_type",
            "data_source_config",
            "col_span",
            "position_order",
            "style_config",
        }
        for field, value in updates.items():
            if field not in allowed:
                continue
            if field == "title":
                value = str(value).strip()[:200]
            elif field == "col_span":
                try:
                    value = int(value) if value else 6
                except (ValueError, TypeError):
                    value = 6
            elif field == "position_order":
                try:
                    value = int(value) if value is not None else 0
                except (ValueError, TypeError):
                    value = 0
            elif field == "chart_type":
                # "" / "auto" → None (signal pour inférence automatique)
                if isinstance(value, str):
                    value = value.strip()
                if value in ("", "auto"):
                    value = None
            setattr(widget, field, value)

        errors = widget.validate()
        if errors:
            raise ValueError("; ".join(errors))

        data = widget.to_dict()
        await session.commit()

        logger.info("Widget mis à jour: id=%s", widget_id)
        from app.services.anonymization.auto_scan import schedule_target_rescan

        schedule_target_rescan(user_id, "dashboard", dashboard_id)
        return data

    async def delete_widget(
        self,
        session: AsyncSession,
        widget_id: int,
        dashboard_id: int,
        user_id: int,
    ) -> bool:
        """Supprime un widget."""
        from app.models.dashboard import Dashboard, DashboardWidget

        stmt = (
            select(DashboardWidget)
            .join(Dashboard)
            .where(
                DashboardWidget.id == widget_id,
                DashboardWidget.dashboard_id == dashboard_id,
                Dashboard.user_id == user_id,
            )
        )
        result = await session.execute(stmt)
        widget = result.scalar_one_or_none()

        if not widget:
            return False

        await session.delete(widget)
        await session.commit()

        logger.info("Widget supprimé: id=%s", widget_id)
        return True

    async def reorder_widgets(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        widget_order: list[int],
    ) -> bool:
        """Réordonne les widgets d'un dashboard.

        widget_order: liste d'IDs de widgets dans le nouvel ordre.
        """
        from app.models.dashboard import Dashboard, DashboardWidget

        # Vérifier ownership
        stmt = select(Dashboard).where(Dashboard.id == dashboard_id, Dashboard.user_id == user_id)
        result = await session.execute(stmt)
        if not result.scalar_one_or_none():
            return False

        # Mettre à jour l'ordre
        for position, widget_id in enumerate(widget_order):
            update_stmt = select(DashboardWidget).where(
                DashboardWidget.id == widget_id,
                DashboardWidget.dashboard_id == dashboard_id,
            )
            result = await session.execute(update_stmt)
            widget = result.scalar_one_or_none()
            if widget:
                widget.position_order = position

        await session.commit()
        logger.info("Widgets réordonnés: dashboard=%s", dashboard_id)
        return True

    # ── Trend computation ──────────────────────────────────────────────────

    @staticmethod
    def _build_trend(
        current: float, previous: float, higher_is_better: bool = True
    ) -> Optional[dict]:
        """Compare current vs previous period and return trend indicator.

        Returns None when no meaningful comparison is possible (previous == 0).
        """
        if previous is None or previous == 0:
            return None

        change_pct = round(((current - previous) / previous) * 100, 1)

        if abs(change_pct) < 0.1:
            return {"direction": "flat", "change_pct": 0, "sentiment": "neutral"}

        direction = "up" if change_pct > 0 else "down"
        if higher_is_better:
            sentiment = "positive" if change_pct > 0 else "negative"
        else:
            sentiment = "negative" if change_pct > 0 else "positive"

        return {
            "direction": direction,
            "change_pct": abs(change_pct),
            "sentiment": sentiment,
        }

    # ── Récupération de données pour les widgets ───────────────────────────

    async def get_widget_data(
        self,
        session: AsyncSession,
        widget_id: int,
        dashboard_id: int,
        user_id: int,
        user: Any = None,
    ) -> Optional[dict]:
        """Récupère les données d'un widget selon sa source (owner only)."""
        from app.models.dashboard import Dashboard, DashboardWidget

        stmt = (
            select(DashboardWidget)
            .join(Dashboard)
            .where(
                DashboardWidget.id == widget_id,
                DashboardWidget.dashboard_id == dashboard_id,
                Dashboard.user_id == user_id,
            )
        )
        result = await session.execute(stmt)
        widget = result.scalar_one_or_none()

        if not widget:
            return None

        config = widget.data_source_config or {}

        if widget.data_source_type == "metric":
            return await self._fetch_metric_data(session, config, widget.widget_type, user_id)
        elif widget.data_source_type == "sql":
            # Propage widget_type pour que le service choisisse le bon path
            # (grid → rendu brut + cap admin ; table/chart/kpi → 500 cap +
            # transform). Sans ça, un widget grid récupéré via cette méthode
            # tomberait silencieusement sur le path "table" (cap 500 + pas
            # de metadata row_count/truncated → régression d'affichage).
            return await self._fetch_sql_data(
                config,
                widget_type=widget.widget_type or "table",
                chart_type=widget.chart_type,
                user=user,
            )
        elif widget.data_source_type == "static":
            return self._fetch_static_data(config)
        else:
            return {"error": "Source de données inconnue."}

    async def get_all_widget_data(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        period_override: Optional[int] = None,
        filter_state: Optional[dict] = None,
        drill_filters: Optional[dict] = None,
        user: Any = None,
    ) -> dict[int, dict]:
        """Récupère les données de tous les widgets d'un dashboard."""
        from app.models.dashboard import Dashboard, DashboardWidget

        # Vérifier accès — strict owner only
        dash_stmt = select(Dashboard).where(
            Dashboard.id == dashboard_id, Dashboard.user_id == user_id
        )
        dash_result = await session.execute(dash_stmt)
        dashboard = dash_result.scalar_one_or_none()
        if not dashboard:
            return {}

        # Charger les widgets
        widget_stmt = (
            select(DashboardWidget)
            .where(DashboardWidget.dashboard_id == dashboard_id)
            .order_by(DashboardWidget.position_order)
        )
        widget_result = await session.execute(widget_stmt)
        widgets = widget_result.scalars().all()

        # Load filter definitions if filter_state is active
        filter_definitions = []
        if filter_state:
            from app.models.dashboard import DashboardFilter

            filt_stmt = select(DashboardFilter).where(DashboardFilter.dashboard_id == dashboard_id)
            filt_result = await session.execute(filt_stmt)
            filter_definitions = [f.to_dict() for f in filt_result.scalars().all()]

        data = {}
        for widget in widgets:
            config = widget.data_source_config or {}

            # Compute effective filters for this widget (respecting exclusions)
            effective_filters = None
            if filter_state and filter_definitions:
                excluded = set(config.get("excluded_filter_params", []))
                effective_filters = {k: v for k, v in filter_state.items() if k not in excluded}
                if not effective_filters:
                    effective_filters = None

            try:
                if widget.data_source_type == "metric":
                    effective_config = dict(config)
                    if period_override is not None:
                        effective_config["period"] = period_override
                    data[widget.id] = await self._fetch_metric_data(
                        session, effective_config, widget.widget_type, user_id
                    )
                elif widget.data_source_type == "sql":
                    # chart_type=None → inférence automatique côté transform
                    data[widget.id] = await self._fetch_sql_data(
                        config,
                        widget_type=widget.widget_type or "table",
                        chart_type=widget.chart_type,
                        filter_state=effective_filters,
                        filter_definitions=filter_definitions,
                        drill_filters=drill_filters,
                        user=user,
                    )
                elif widget.data_source_type == "static":
                    data[widget.id] = self._fetch_static_data(config)
                else:
                    data[widget.id] = {"error": "Source inconnue."}
            except Exception:
                logger.warning("Erreur récupération données widget %s", widget.id, exc_info=True)
                data[widget.id] = {"error": "Erreur lors de la récupération des données."}

        return data

    def _fetch_static_data(self, config: dict) -> dict:
        """Widget statique (widget_type='text', data_source_type='static').

        Pas de fetch externe : le contenu vit dans ``data_source_config``.
        Retourne un shape uniforme ``{type, title, content}`` que le frontend
        rend via ``textContent`` (zéro risque XSS).

        **Sync intentionnel** — pas d'I/O, contrairement à
        :meth:`_fetch_sql_data` et :meth:`_fetch_metric_data`. Si une
        évolution future ajoute du I/O (ex: anti-PII Ollama sur le contenu),
        cette méthode DOIT devenir async ET les 2 call-sites (``get_widget_data``
        et ``get_all_widget_data``) doivent être adaptés avec ``await``.

        **Defense-in-depth** : caps appliqués ici (truncate plutôt que reject),
        en plus de :meth:`DashboardWidget.validate`. Couvre 2 cas :
        - widget legacy créé avant l'introduction des caps (validate
          rejetterait à la création, mais pas à la lecture)
        - row inserté directement en BDD (SQL/script) qui bypasse validate
        - type mismatch dans config (dict/list au lieu de str) — on retourne
          une string vide plutôt que stringifier un repr Python qui
          confondrait l'utilisateur (``{'x': 1}`` affiché littéralement).
        """
        from app.models.dashboard import DashboardWidget

        cfg = config or {}
        raw_title = cfg.get("title")
        raw_content = cfg.get("content")
        # Type-safe : un dict/list dans config (BDD corrompue) → "" plutôt que repr.
        title = raw_title.strip() if isinstance(raw_title, str) else ""
        content = raw_content if isinstance(raw_content, str) else ""
        return {
            "type": "static",
            "title": title[: DashboardWidget.MAX_TEXT_WIDGET_TITLE_LEN],
            "content": content[: DashboardWidget.MAX_TEXT_WIDGET_CONTENT_LEN],
        }

    async def _fetch_metric_data(
        self,
        session: AsyncSession,
        config: dict,
        widget_type: str,
        user_id: int,
    ) -> dict:
        """Récupère les données d'une métrique prédéfinie."""
        metric_name = config.get("metric_name", "")
        try:
            period_days = min(max(int(config.get("period", 7)), 1), 365)
        except (ValueError, TypeError):
            period_days = 7

        if metric_name not in AVAILABLE_METRICS:
            return {"error": f"Métrique inconnue: {metric_name}"}

        try:
            return await self._execute_metric(session, metric_name, user_id, period_days)
        except Exception:
            logger.warning("Erreur métrique %s", metric_name, exc_info=True)
            return {"error": "Erreur lors du calcul de la métrique."}

    async def _execute_metric(
        self,
        session: AsyncSession,
        metric_name: str,
        user_id: int,
        period_days: int,
    ) -> dict:
        """Exécute une métrique prédéfinie et retourne les données formatées."""
        from app.models.automation import Automation
        from app.models.execution import Execution
        from app.models.search_history import SearchHistory

        cutoff = clock.now() - timedelta(days=period_days)

        if metric_name == "total_searches":
            stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= cutoff,
                )
            )
            result = await session.execute(stmt)
            count = result.scalar() or 0

            # Previous period for trend
            prev_start = cutoff - timedelta(days=period_days)
            prev_stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= prev_start,
                    SearchHistory.created_at < cutoff,
                )
            )
            prev_count = (await session.execute(prev_stmt)).scalar() or 0

            return {
                "type": "kpi",
                "value": count,
                "label": "Recherches",
                "trend": self._build_trend(count, prev_count, higher_is_better=True),
            }

        elif metric_name == "success_rate":
            total_stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= cutoff,
                )
            )
            total = (await session.execute(total_stmt)).scalar() or 0

            success_stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= cutoff,
                    SearchHistory.success.is_(True),
                )
            )
            success = (await session.execute(success_stmt)).scalar() or 0

            rate = round((success / total) * 100, 1) if total > 0 else 0

            # Previous period for trend
            prev_start = cutoff - timedelta(days=period_days)
            prev_total_stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= prev_start,
                    SearchHistory.created_at < cutoff,
                )
            )
            prev_total = (await session.execute(prev_total_stmt)).scalar() or 0

            prev_success_stmt = (
                select(func.count())
                .select_from(SearchHistory)
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= prev_start,
                    SearchHistory.created_at < cutoff,
                    SearchHistory.success.is_(True),
                )
            )
            prev_success = (await session.execute(prev_success_stmt)).scalar() or 0
            prev_rate = round((prev_success / prev_total) * 100, 1) if prev_total > 0 else 0

            return {
                "type": "kpi",
                "value": rate,
                "label": "Taux de succès",
                "unit": "%",
                "trend": self._build_trend(rate, prev_rate, higher_is_better=True),
            }

        elif metric_name == "daily_searches":
            # Single GROUP BY query instead of N+1 (was 1 query per day)
            from sqlalchemy import cast, Date as SADate

            stmt = (
                select(
                    cast(SearchHistory.created_at, SADate).label("day"),
                    func.count().label("cnt"),
                )
                .where(
                    SearchHistory.user_id == user_id,
                    SearchHistory.created_at >= cutoff,
                )
                .group_by(cast(SearchHistory.created_at, SADate))
            )
            result = await session.execute(stmt)
            counts_by_day = {row[0]: row[1] for row in result.all()}

            # Build full date range (fill missing days with 0)
            today = clock.now().date()
            rows = []
            for i in range(period_days - 1, -1, -1):
                day = today - timedelta(days=i)
                rows.append(
                    {
                        "date": day.strftime("%d/%m"),
                        "count": counts_by_day.get(day, 0),
                    }
                )
            return {
                "type": "chart",
                "labels": [r["date"] for r in rows],
                "datasets": [{"label": "Recherches", "data": [r["count"] for r in rows]}],
            }

        elif metric_name == "execution_status":
            stmt = (
                select(Execution.status, func.count())
                .join(Automation)
                .where(Automation.user_id == user_id)
                .group_by(Execution.status)
            )
            result = await session.execute(stmt)
            rows = result.all()
            labels = [r[0] or "inconnu" for r in rows]
            values = [r[1] for r in rows]
            return {"type": "chart", "labels": labels, "datasets": [{"data": values}]}

        elif metric_name == "active_automations":
            stmt = (
                select(func.count())
                .select_from(Automation)
                .where(Automation.user_id == user_id, Automation.is_active.is_(True))
            )
            count = (await session.execute(stmt)).scalar() or 0
            return {"type": "kpi", "value": count, "label": "Automatisations actives"}

        elif metric_name == "total_reports":
            from app.models.user_storage import FileMetadata

            stmt = (
                select(func.count())
                .select_from(FileMetadata)
                .where(FileMetadata.user_id == user_id)
            )
            count = (await session.execute(stmt)).scalar() or 0
            return {"type": "kpi", "value": count, "label": "Fichiers"}

        elif metric_name == "total_contacts":
            from app.services.contacts.contact_service import ContactService

            svc = ContactService()
            stats = await svc.get_stats(session, user_id)
            return {
                "type": "kpi",
                "value": stats.data.get("total_contacts", 0) if stats.success else 0,
                "label": "Contacts",
            }

        elif metric_name == "recent_searches":
            stmt = (
                select(
                    SearchHistory.question,
                    SearchHistory.success,
                    SearchHistory.created_at,
                )
                .where(SearchHistory.user_id == user_id)
                .order_by(SearchHistory.created_at.desc())
                .limit(10)
            )
            result = await session.execute(stmt)
            rows = result.all()
            return {
                "type": "table",
                "columns": ["Question", "Statut", "Date"],
                "rows": [
                    [
                        r[0][:80] if r[0] else "",
                        "OK" if r[1] else "Erreur",
                        r[2].strftime("%d/%m %H:%M") if r[2] else "",
                    ]
                    for r in rows
                ],
            }

        # ``top_users`` et ``avg_response_time`` retirés (BLOCKING #4-5
        # review). Defense-in-depth : un dashboard legacy stocké en BDD
        # avec un widget pointant vers ces metrics retournera une erreur
        # explicite plutôt qu'un agrégat cross-user. Le frontend doit
        # afficher cette erreur ou cacher le widget — pas de fail-open.
        if metric_name in ("top_users", "avg_response_time"):
            return {
                "error": (
                    f"Métrique '{metric_name}' retirée pour empêcher la fuite "
                    "cross-user. Modifiez le widget ou supprimez-le."
                )
            }

        return {"error": f"Métrique non implémentée: {metric_name}"}

    # ── Auto chart-type inference ───────────────────────────────────────
    # Heuristique déterministe (code > prompt) pour choisir le type de
    # graphique le plus adapté aux données retournées par une requête SQL,
    # quand l'utilisateur n'en a pas spécifié un. Activée uniquement si
    # `chart_type` est None/""/"auto" — les widgets existants avec un
    # chart_type explicite ne sont pas affectés.

    # Mots-clés temporels matchés par "token" (séparés par _ / espace / début / fin)
    # pour éviter les faux positifs du genre "created_by" → temporel.
    # On n'inclut PAS "created"/"updated"/"modified" parce qu'ils apparaissent
    # aussi dans des champs non-temporels (created_by, updated_by = auteurs).
    # La détection par VALEURS ISO couvre created_at/updated_at si nécessaire.
    _TEMPORAL_NAME_TOKENS = frozenset(
        {
            "date",
            "jour",
            "mois",
            "annee",
            "année",
            "ann",
            "year",
            "day",
            "time",
            "timestamp",
            "horodatage",
        }
    )

    @staticmethod
    def _is_numeric_column(rows: list[list], col_idx: int) -> bool:
        """Teste si une colonne est numérique d'après la 1ère valeur non-None.

        Rejette les booléens (même si bool() est un sous-type d'int) et les
        valeurs flottantes non-finies (NaN/±Inf), qui casseraient la
        sérialisation JSON côté réponse HTTP.
        """
        import math as _math

        for row in rows:
            if col_idx >= len(row):
                continue
            val = row[col_idx]
            if val is None:
                continue
            if isinstance(val, bool):
                return False
            try:
                parsed = float(val)
            except (ValueError, TypeError):
                return False
            return _math.isfinite(parsed)
        return False

    @classmethod
    def _name_has_temporal_token(cls, name: str) -> bool:
        """True si `name` contient un mot-clé temporel comme token séparé.

        Découpe sur non-alphanumériques (snake_case, kebab-case, espaces, …)
        puis teste chaque token contre la liste fermée. Évite "created_by" /
        "year_plan_author" etc. de déclencher à tort.
        """
        import re as _re

        if not name:
            return False
        tokens = _re.split(r"[^a-zA-Zàâäéèêëîïôöùûüç]+", name.lower())
        return any(tok in cls._TEMPORAL_NAME_TOKENS for tok in tokens if tok)

    @classmethod
    def _is_temporal_column(cls, columns: list[str], rows: list[list], col_idx: int) -> bool:
        """Détecte qu'une colonne représente du temps.

        Combine deux signaux :
        - Nom contient un mot-clé temporel (en tant que token séparé)
        - ≥80% des valeurs non-None / non-vides parsent comme ISO-date/datetime
        """
        if col_idx >= len(columns):
            return False
        if cls._name_has_temporal_token(str(columns[col_idx])):
            return True
        # Heuristique par valeurs : tente parse sur les 20 premières valeurs
        # utiles (non-None, non-whitespace-only).
        sample = []
        for row in rows[:60]:
            if col_idx >= len(row):
                continue
            val = row[col_idx]
            if val is None:
                continue
            if isinstance(val, str) and not val.strip():
                continue
            sample.append(val)
            if len(sample) >= 20:
                break
        if not sample:
            return False
        parsed = 0
        for val in sample:
            if isinstance(val, datetime):
                parsed += 1
                continue
            if not isinstance(val, str):
                continue
            s = val.strip()
            try:
                datetime.fromisoformat(s.replace("Z", "+00:00"))
                parsed += 1
            except ValueError:
                pass
        return (parsed / len(sample)) >= 0.8

    @classmethod
    def _infer_chart_type(cls, columns: list[str], rows: list[list]) -> str:
        """Choisit le meilleur chart_type à partir de la forme des données.

        Retourne une valeur de ``DashboardWidget.VALID_CHART_TYPES``.
        Règles :
        - Col temporelle (token du nom ou valeurs ISO) + col(s) numérique(s) → "line"
        - 1 catégorie + 1 numérique + 2..8 lignes → "pie" (plus lisible)
        - Catégorie + numérique(s) → "bar"
        - Fallback safe → "bar"

        Note : on NE renvoie PAS "scatter" automatiquement. ``_transform_sql_to_chart``
        utilise toujours la 1ère colonne comme labels (X) et les suivantes numériques
        comme séries (Y) — ce schéma n'est pas compatible avec scatter (qui veut
        X *et* Y numériques). L'utilisateur peut toujours choisir scatter manuellement
        via les paramètres avancés ; la détection auto reste côté "bar" pour éviter
        une visualisation trompeuse.
        """
        if not columns or not rows:
            return "bar"

        numeric_cols = [i for i in range(len(columns)) if cls._is_numeric_column(rows, i)]

        # 1ère colonne non-numérique = candidate "catégorie/axe X"
        if numeric_cols and 0 not in numeric_cols:
            if cls._is_temporal_column(columns, rows, 0):
                return "line"
            if len(numeric_cols) == 1 and 2 <= len(rows) <= 8:
                return "pie"
            return "bar"

        return "bar"

    def _transform_sql_to_chart(
        self,
        columns: list[str],
        rows: list[list],
        chart_type: Optional[str] = None,
    ) -> dict:
        """Transforme des résultats SQL tabulaires en format chart Plotly.

        Convention:
        - 1ère colonne → labels (axe X ou catégories)
        - Colonnes numériques restantes → datasets (séries Y)
        - Si aucune colonne numérique trouvée → fallback table

        ``chart_type`` peut être None / "" / "auto" → on infère le type
        depuis la forme des données. Sinon on respecte la valeur explicite.
        Le type effectif est inclus dans le dict retourné pour que le
        frontend puisse fallback dessus si le widget n'a pas de chart_type
        stocké.
        """
        effective_chart_type = (
            chart_type
            if chart_type and chart_type != "auto"
            else self._infer_chart_type(columns, rows)
        )

        if not columns or not rows:
            return {
                "type": "chart",
                "chart_type": effective_chart_type,
                "labels": [],
                "datasets": [],
            }

        labels = [str(row[0]) if row[0] is not None else "" for row in rows]

        # Une seule source de vérité pour "colonne numérique" : le helper.
        numeric_cols = [i for i in range(1, len(columns)) if self._is_numeric_column(rows, i)]

        # Aucune colonne numérique → fallback table
        if not numeric_cols:
            return {
                "type": "table",
                "columns": columns,
                "rows": rows,
            }

        datasets = []
        for col_idx in numeric_cols:
            col_name = columns[col_idx]
            values = []
            for row in rows:
                val = row[col_idx] if col_idx < len(row) else None
                if val is not None:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        values.append(0)
                else:
                    values.append(0)
            datasets.append({"label": col_name, "data": values})

        return {
            "type": "chart",
            "chart_type": effective_chart_type,
            "labels": labels,
            "datasets": datasets,
        }

    def _transform_sql_to_kpi(self, columns: list[str], rows: list[list]) -> dict:
        """Transforme des résultats SQL en format KPI (valeur unique).

        Convention:
        - 1ère colonne numérique de la 1ère ligne → valeur KPI
        - Nom de la colonne → label
        """
        if not columns or not rows:
            return {"type": "kpi", "value": 0, "label": "Aucune donnée"}

        first_row = rows[0]
        # Chercher la première valeur numérique
        for col_idx, col_name in enumerate(columns):
            val = first_row[col_idx] if col_idx < len(first_row) else None
            if val is not None:
                try:
                    numeric_val = float(val)
                    # Afficher en entier si c'est un entier
                    if numeric_val == int(numeric_val):
                        numeric_val = int(numeric_val)
                    return {"type": "kpi", "value": numeric_val, "label": col_name}
                except (ValueError, TypeError):
                    continue

        # Pas de valeur numérique → texte de la première cellule
        val = first_row[0] if first_row else "—"
        return {"type": "kpi", "value": str(val) if val is not None else "—", "label": columns[0]}

    async def _fetch_sql_data(
        self,
        config: dict,
        widget_type: str = "table",
        chart_type: Optional[str] = None,
        filter_state: Optional[dict] = None,
        filter_definitions: Optional[list[dict]] = None,
        drill_filters: Optional[dict] = None,
        user: Any = None,
    ) -> dict:
        """Exécute une requête SQL contre Sage et retourne les résultats.

        Le format de retour dépend de widget_type :
        - "table" → {type: "table", columns, rows}
        - "chart" → {type: "chart", labels, datasets}
        - "kpi"   → {type: "kpi", value, label}
        - "grid"  → {type: "grid", columns, rows, sql, row_count, truncated,
                    execution_time_ms} — copie conforme result area /iris.
                    Pas de transformation (rendu brut via SqlResultGrid).
                    max_rows respecte le cap admin (parité /iris), pas le
                    cap 500 des widgets agrégés.
        """
        query = config.get("query", "")
        if not query:
            return {"error": "Requête SQL vide."}

        # Validate SELECT-only (prevent writes from dashboard widgets).
        # Détection des verbes/patterns dangereux déléguée au validateur SSoT
        # ``check_sql_dangerous`` (app/services/ai/sql_validator) — déjà utilisé
        # par Iris/training_store. Il couvre PLUS que l'ancien blacklist inline :
        # 17 mots-clés (BACKUP/RESTORE/OPENROWSET/WAITFOR/SHUTDOWN…), les
        # préfixes de procédures (sp_/xp_), les patterns composites
        # (SELECT … INTO, BULK INSERT) ET le strip des commentaires SQL.
        # L'ancien blacklist laissait passer SELECT INTO / sp_ — or un user
        # (require_role "user") peut créer un widget SQL et la BDD connectée
        # n'est PAS garantie read-only (règle GÉNÉRICITÉ). Single source of
        # truth → pas de dérive entre ce guard et celui d'Iris.
        from app.services.ai.sql_validator import check_sql_dangerous

        stripped = query.strip().upper()
        if not stripped.startswith("SELECT") and not stripped.startswith("WITH"):
            return {"error": "Seules les requêtes SELECT sont autorisées."}
        if check_sql_dangerous(query):
            return {"error": "Seules les requêtes SELECT sont autorisées."}

        try:
            from app.services.database.query_executor import QueryExecutor

            executor = QueryExecutor()

            # Build combined WHERE clause from filters and drill-down
            effective_query = query
            sql_params = None
            where_parts = []
            all_params = []

            # 1. Regular dashboard filters
            if filter_state and filter_definitions:
                from app.services.dashboard.filter_service import build_sql_filter_clause

                where_clause, filter_params = build_sql_filter_clause(
                    filter_state, filter_definitions
                )
                if where_clause and filter_params:
                    where_parts.append(where_clause)
                    all_params.extend(filter_params)

            # 2. Drill-down filters (from chart click)
            if drill_filters:
                from app.services.dashboard.filter_service import build_drill_down_clause

                drill_clause, drill_params = build_drill_down_clause(drill_filters)
                if drill_clause:
                    where_parts.append(drill_clause)
                    all_params.extend(drill_params)

            if where_parts:
                combined_where = " AND ".join(where_parts)
                effective_query = f"SELECT * FROM ({query}) AS _wq WHERE {combined_where}"
                sql_params = tuple(all_params)

            # execute() returns QueryResult, supports params natively
            from app.services.data_access.enforcer import DataAccessDeniedError

            # Cap lignes :
            #  - widgets agrégés (chart/kpi/table) : 500 — protège le rendu front
            #    (Plotly + HTML statique deviennent injouables au-delà).
            #  - grid : None → cap admin via DatabaseConnection.max_rows
            #    (parité /iris, doctrine "no double cap" — la grille SqlResultGrid
            #    est conçue pour gérer les gros datasets via virtual scrolling).
            effective_max_rows = None if widget_type == "grid" else 500

            try:
                qr = await executor.execute(
                    effective_query,
                    params=sql_params,
                    max_rows=effective_max_rows,
                    user=user,
                    rls_source="dashboard_widget",
                    require_user=True,
                )
            except DataAccessDeniedError as exc:
                return {"error": exc.user_message, "blocked_by": "data_access_rule"}

            columns = qr.columns or []
            rows_as_dicts = qr.to_dicts()

            rows = (
                [[row.get(col) for col in columns] for row in rows_as_dicts]
                if rows_as_dicts
                else []
            )

            # ── Widget "grid" : retour brut, pas de transformation ni
            # d'aggrégation. Le frontend instancie GridTabManager direct
            # sur ces données (copie conforme de la result area /iris).
            # On expose row_count + truncated pour que l'UI puisse afficher
            # un badge "tronqué" cohérent avec /iris.
            if widget_type == "grid":
                return {
                    "type": "grid",
                    "columns": columns,
                    "rows": rows,
                    "sql": effective_query,
                    "row_count": getattr(qr, "row_count", len(rows)),
                    "truncated": bool(getattr(qr, "truncated", False)),
                    "execution_time_ms": getattr(qr, "execution_time_ms", 0),
                }

            # ── Pipeline v2 : si le widget a une transformation persistée
            # (décidée par l'Analyst LLM à la création), on la rejoue en
            # Python ici — la même recette, déterministe, à chaque refresh.
            # Les anciens widgets sans transformation passent dans le chemin
            # historique (backward-compat).
            recipe = config.get("transformation") if isinstance(config, dict) else None
            if recipe:
                try:
                    from app.services.dashboard.widget_planner.transformations import (
                        TransformationError,
                        apply_transformation,
                    )

                    result = apply_transformation(columns, rows, recipe)
                    # Attache le chart_type s'il était stocké dans la render_spec
                    # (utile pour le front quand le widget est de type chart).
                    render_spec = config.get("render_spec") if isinstance(config, dict) else None
                    if (
                        isinstance(render_spec, dict)
                        and result.get("type") == "chart"
                        and render_spec.get("chart_type")
                    ):
                        result["chart_type"] = render_spec["chart_type"]
                    return result
                except TransformationError as exc:
                    logger.warning(
                        "Widget transformation invalide : %s — fallback sur SQL brut",
                        exc,
                    )
                    # Fallback : on retombe sur le chemin historique ci-dessous

            # Chemin historique (pas de transformation persistée ou fallback)
            if widget_type == "chart" and rows:
                return self._transform_sql_to_chart(columns, rows, chart_type)
            elif widget_type == "kpi" and rows:
                return self._transform_sql_to_kpi(columns, rows)

            return {"type": "table", "columns": columns, "rows": rows}

        except Exception:
            logger.warning("Erreur exécution SQL widget", exc_info=True)
            return {"error": "Erreur lors de l'exécution de la requête SQL."}

    # ── Export ─────────────────────────────────────────────────────────────

    async def export_dashboard(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        fmt: str = "csv",
        period_override: Optional[int] = None,
        user: Any = None,
    ) -> Optional[tuple[str, bytes, str]]:
        """Exporte toutes les données d'un dashboard en CSV ou Excel (owner only).

        Returns:
            Tuple (filename, file_bytes, content_type) ou None si non trouvé
            ou si le dashboard n'appartient pas au user courant.
        """
        from app.models.dashboard import Dashboard

        # Vérifier accès — strict owner only
        dash_stmt = select(Dashboard).where(
            Dashboard.id == dashboard_id, Dashboard.user_id == user_id
        )
        dash_result = await session.execute(dash_stmt)
        dashboard = dash_result.scalar_one_or_none()
        if not dashboard:
            return None

        dash_name = dashboard.name

        # Récupérer toutes les données — ``user`` propagé pour l'enforcement
        # RLS data-access des widgets SQL (sinon ``user=None`` → bypass legacy
        # de l'executor → export de données Sage NON filtrées, fuite cross-
        # périmètre). Les widgets metric restent scopés via ``user_id``.
        all_data = await self.get_all_widget_data(
            session, dashboard_id, user_id, period_override=period_override, user=user
        )

        if fmt == "excel":
            return self._export_excel(dash_name, all_data, dashboard_id)
        else:
            return self._export_csv(dash_name, all_data, dashboard_id)

    def _export_csv(
        self, dash_name: str, all_data: dict, dashboard_id: int
    ) -> tuple[str, bytes, str]:
        """Génère un export CSV multi-widgets."""
        output = io.StringIO()
        writer = csv.writer(output)

        for widget_id_str, data in all_data.items():
            if data.get("error"):
                # Prod-loop task #16 — anti silent data loss : un widget en
                # erreur DOIT être rendu visible dans le fichier export, pas
                # silencieusement skipped (sinon décision business sur données
                # partielles + destinataire email reçoit un fichier tronqué).
                # csv_safe_cell : le message peut contenir du contenu pseudo-
                # utilisateur via exc.user_message (ligne 1263) → neutraliser
                # toute formule (=, +, -, @, \t, \r) avant écriture, sinon
                # OWASP CSV-injection vers les destinataires d'email.
                error_msg = csv_safe_cell(data.get("error") or "Erreur inconnue")
                writer.writerow([f"Widget {widget_id_str} — ÉCHEC DE RÉCUPÉRATION DES DONNÉES"])
                writer.writerow(["Erreur:", error_msg])
                writer.writerow([])  # separator
                continue

            data_type = data.get("type", "")
            widget_title = f"Widget {widget_id_str}"

            # csv_safe_cell sur TOUTES les cellules de données (pas seulement
            # le message d'erreur ci-dessus) : les valeurs viennent de la BDD
            # source (Sage) et peuvent commencer par =/+/-/@/\t/\r → formule
            # exécutée à l'ouverture Excel chez le destinataire de l'envoi
            # planifié (OWASP CSV-injection). Même neutralisation que la
            # branche if error: et que le helper to_csv_bytes (SSoT).
            if data_type == "kpi":
                writer.writerow([widget_title])
                writer.writerow(
                    [
                        csv_safe_cell(data.get("label", "Valeur")),
                        csv_safe_cell(data.get("value", "")),
                    ]
                )
                writer.writerow([])  # separator
            elif data_type == "table" or data_type == "grid":
                # Adversarial review CRIT-2 — 2026-05-26 : sans cette branche
                # 'grid', les widgets grid étaient silencieusement omis de
                # l'export (data_type == 'grid' ne matchait aucun elif →
                # silent data loss, exactement l'anti-pattern documenté par
                # le commentaire du if error: bloc ci-dessus). Le shape de
                # 'grid' est identique à 'table' (columns + rows) → même
                # rendu CSV.
                columns = data.get("columns", [])
                rows = data.get("rows", [])
                writer.writerow([widget_title])
                if columns:
                    writer.writerow([csv_safe_cell(c) for c in columns])
                for row in rows:
                    writer.writerow([csv_safe_cell(cell) for cell in row])
                writer.writerow([])  # separator
            elif data_type == "chart":
                labels = data.get("labels", [])
                datasets = data.get("datasets", [])
                writer.writerow([widget_title])
                # Header: Label + dataset names
                header = ["Label"] + [
                    ds.get("label", f"Serie {i + 1}") for i, ds in enumerate(datasets)
                ]
                writer.writerow([csv_safe_cell(h) for h in header])
                for idx, label in enumerate(labels):
                    row = [label]
                    for ds in datasets:
                        ds_data = ds.get("data", [])
                        row.append(ds_data[idx] if idx < len(ds_data) else "")
                    writer.writerow([csv_safe_cell(cell) for cell in row])
                writer.writerow([])  # separator

        content = output.getvalue()
        # BOM for Excel UTF-8 compatibility
        file_bytes = b"\xef\xbb\xbf" + content.encode("utf-8")
        safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in dash_name)[:50]
        filename = f"dashboard_{safe_name}.csv"
        return filename, file_bytes, "text/csv; charset=utf-8"

    def _export_excel(
        self, dash_name: str, all_data: dict, dashboard_id: int
    ) -> tuple[str, bytes, str]:
        """Génère un export Excel multi-widgets (un onglet par widget)."""
        try:
            import openpyxl
            from openpyxl.styles import Font, PatternFill
        except ImportError:
            logger.warning("openpyxl non disponible, fallback CSV")
            return self._export_csv(dash_name, all_data, dashboard_id)

        wb = openpyxl.Workbook()
        wb.remove(wb.active)

        header_font = Font(bold=True, color="FFFFFF")
        header_fill = PatternFill(start_color="4F46E5", end_color="4F46E5", fill_type="solid")
        sheet_idx = 0

        for widget_id_str, data in all_data.items():
            if data.get("error"):
                # Prod-loop task #16 — anti silent data loss : un widget en
                # erreur DOIT créer une feuille ÉCHEC visible (sinon le
                # destinataire d'un envoi planifié reçoit un Excel tronqué
                # sans signal). Cf. _export_csv pour le pendant CSV.
                # csv_safe_cell : openpyxl n'évalue pas les formules au
                # write, mais le destinataire peut re-exporter en CSV ; on
                # neutralise donc les préfixes formule par cohérence.
                error_msg = csv_safe_cell(data.get("error") or "Erreur inconnue")
                error_sheet_name = f"Widget {widget_id_str} ÉCHEC"[:31]
                ws = wb.create_sheet(title=error_sheet_name)
                sheet_idx += 1
                ws.append([f"Widget {widget_id_str} — ÉCHEC DE RÉCUPÉRATION DES DONNÉES"])
                ws.append(["Erreur:", error_msg])
                error_font = Font(bold=True, color="FF0000")
                for cell in ws[1]:
                    cell.font = error_font
                for col in ws.columns:
                    max_len = 0
                    col_letter = col[0].column_letter
                    for cell in col:
                        try:
                            if cell.value:
                                max_len = max(max_len, len(str(cell.value)))
                        except (TypeError, AttributeError):
                            pass
                    ws.column_dimensions[col_letter].width = min(max_len + 2, 50)
                continue

            data_type = data.get("type", "")
            sheet_name = f"Widget {widget_id_str}"[:31]
            ws = wb.create_sheet(title=sheet_name)
            sheet_idx += 1

            # excel_safe_cell sur les cellules de données : openpyxl écrit une
            # chaîne ``"=..."`` comme une FORMULE évaluée à l'ouverture →
            # même classe de CSV/formula-injection que le CSV. Variante
            # type-preserving (les nombres/dates restent natifs pour rester
            # sommables/graphables côté destinataire). Cf. output_safety.
            if data_type == "kpi":
                ws.append(
                    [
                        excel_safe_cell(data.get("label", "Valeur")),
                        excel_safe_cell(data.get("value", "")),
                    ]
                )
                for cell in ws[1]:
                    cell.font = header_font
                    cell.fill = header_fill
            elif data_type == "table" or data_type == "grid":
                # Voir _export_csv pour le pendant (adversarial CRIT-2).
                columns = data.get("columns", [])
                rows = data.get("rows", [])
                if columns:
                    ws.append([excel_safe_cell(c) for c in columns])
                    for cell in ws[1]:
                        cell.font = header_font
                        cell.fill = header_fill
                for row in rows:
                    ws.append([excel_safe_cell(cell) for cell in row])
            elif data_type == "chart":
                labels = data.get("labels", [])
                datasets = data.get("datasets", [])
                header = ["Label"] + [
                    ds.get("label", f"Serie {i + 1}") for i, ds in enumerate(datasets)
                ]
                ws.append([excel_safe_cell(h) for h in header])
                for cell in ws[1]:
                    cell.font = header_font
                    cell.fill = header_fill
                for idx, label in enumerate(labels):
                    row = [label]
                    for ds in datasets:
                        ds_data = ds.get("data", [])
                        row.append(ds_data[idx] if idx < len(ds_data) else "")
                    ws.append([excel_safe_cell(cell) for cell in row])

            # Auto-adjust column widths
            for col in ws.columns:
                max_len = 0
                col_letter = col[0].column_letter
                for cell in col:
                    try:
                        if cell.value:
                            max_len = max(max_len, len(str(cell.value)))
                    except (TypeError, AttributeError):
                        pass
                ws.column_dimensions[col_letter].width = min(max_len + 2, 50)

        if not wb.sheetnames:
            ws = wb.create_sheet(title="Vide")
            ws.append(["Aucune donnée disponible."])

        buf = io.BytesIO()
        wb.save(buf)
        file_bytes = buf.getvalue()

        safe_name = "".join(c if c.isalnum() or c in " _-" else "_" for c in dash_name)[:50]
        filename = f"dashboard_{safe_name}.xlsx"
        content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return filename, file_bytes, content_type

    # ── Utilitaires ────────────────────────────────────────────────────────

    def get_available_metrics(self) -> dict:
        """Retourne la liste des métriques prédéfinies disponibles."""
        return AVAILABLE_METRICS
