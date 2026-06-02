"""
Service pour les templates de dashboard — presets prêts à l'emploi.

Fournit des templates de dashboards prédéfinis que les utilisateurs
peuvent instancier en un clic. Chaque template définit un ensemble
de widgets pré-configurés avec des métriques ou requêtes SQL adaptées.
"""

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = logging.getLogger(__name__)


# ── Templates prédéfinis ─────────────────────────────────────────────────────
# Chaque template est un dict avec :
#   slug: identifiant unique
#   name: nom affiché
#   description: description courte
#   category: catégorie (general, automation, performance)
#   icon: nom d'icône SVG (utilisé côté frontend)
#   widgets: liste de configs widget (même structure que DashboardWidget)

DASHBOARD_TEMPLATES = [
    {
        "slug": "overview",
        "name": "Vue d'ensemble",
        "description": ("Dashboard général avec les KPIs essentiels et " "l'activité quotidienne."),
        "category": "general",
        "icon": "chart-pie",
        "widgets": [
            {
                "title": "Recherches totales",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_searches"},
                "col_span": 3,
                "position_order": 0,
                "style_config": {"colors": ["#4F46E5"]},
            },
            {
                "title": "Taux de succès",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "success_rate"},
                "col_span": 3,
                "position_order": 1,
                "style_config": {"colors": ["#10B981"]},
            },
            {
                "title": "Automatisations actives",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "active_automations"},
                "col_span": 3,
                "position_order": 2,
                "style_config": {"colors": ["#F59E0B"]},
            },
            {
                "title": "Contacts",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_contacts"},
                "col_span": 3,
                "position_order": 3,
                "style_config": {"colors": ["#8B5CF6"]},
            },
            {
                "title": "Activité quotidienne",
                "widget_type": "chart",
                "chart_type": "area",
                "data_source_type": "metric",
                "data_source_config": {
                    "metric_name": "daily_searches",
                    "period": "30d",
                },
                "col_span": 8,
                "position_order": 4,
                "style_config": {
                    "colors": ["#4F46E5"],
                    "show_legend": False,
                    "height": 300,
                },
            },
            {
                "title": "Statut des exécutions",
                "widget_type": "chart",
                "chart_type": "donut",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "execution_status"},
                "col_span": 4,
                "position_order": 5,
                "style_config": {
                    "colors": ["#10B981", "#EF4444"],
                    "show_legend": True,
                    "height": 300,
                },
            },
        ],
    },
    {
        "slug": "user-activity",
        "name": "Activité utilisateurs",
        "description": (
            "Suivi de l'activité des utilisateurs : recherches, " "classements et historique."
        ),
        "category": "general",
        "icon": "users",
        "widgets": [
            {
                "title": "Recherches totales",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_searches"},
                "col_span": 6,
                "position_order": 0,
                "style_config": {"colors": ["#4F46E5"]},
            },
            # Widgets ``avg_response_time`` et ``top_users`` retirés
            # 2026-05-09 (BLOCKING #4-5 review). Ces métriques agrégeaient
            # cross-user → leak silencieux. Le monitoring admin global
            # passe par /dashboard, pas par les dashboards configurables.
            {
                "title": "Rapports générés",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_reports"},
                "col_span": 6,
                "position_order": 1,
                "style_config": {"colors": ["#F59E0B"]},
            },
            {
                "title": "Recherches par jour",
                "widget_type": "chart",
                "chart_type": "line",
                "data_source_type": "metric",
                "data_source_config": {
                    "metric_name": "daily_searches",
                    "period": "30d",
                },
                "col_span": 12,
                "position_order": 2,
                "style_config": {
                    "colors": ["#4F46E5"],
                    "show_legend": False,
                    "height": 350,
                },
            },
            {
                "title": "Dernières recherches",
                "widget_type": "table",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "recent_searches"},
                "col_span": 12,
                "position_order": 3,
                "style_config": {},
            },
        ],
    },
    {
        "slug": "automation-tracking",
        "name": "Suivi des automatisations",
        "description": (
            "Surveillance des exécutions, taux de succès " "et état des pipelines automatisés."
        ),
        "category": "automation",
        "icon": "cog",
        "widgets": [
            {
                "title": "Automatisations actives",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "active_automations"},
                "col_span": 4,
                "position_order": 0,
                "style_config": {"colors": ["#10B981"]},
            },
            {
                "title": "Taux de succès",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "success_rate"},
                "col_span": 4,
                "position_order": 1,
                "style_config": {"colors": ["#4F46E5"]},
            },
            {
                "title": "Rapports générés",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_reports"},
                "col_span": 4,
                "position_order": 2,
                "style_config": {"colors": ["#F59E0B"]},
            },
            {
                "title": "Statut des exécutions",
                "widget_type": "chart",
                "chart_type": "pie",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "execution_status"},
                "col_span": 6,
                "position_order": 3,
                "style_config": {
                    "colors": ["#10B981", "#EF4444", "#F59E0B"],
                    "show_legend": True,
                    "height": 350,
                },
            },
            {
                "title": "Volume quotidien",
                "widget_type": "chart",
                "chart_type": "bar",
                "data_source_type": "metric",
                "data_source_config": {
                    "metric_name": "daily_searches",
                    "period": "14d",
                },
                "col_span": 6,
                "position_order": 4,
                "style_config": {
                    "colors": ["#4F46E5"],
                    "show_legend": False,
                    "height": 350,
                },
            },
        ],
    },
    {
        "slug": "performance",
        "name": "Performance système",
        "description": ("Indicateurs de performance : volumes et tendances."),
        "category": "performance",
        "icon": "lightning",
        "widgets": [
            # Widgets ``avg_response_time`` et ``top_users`` retirés
            # 2026-05-09 (BLOCKING #4-5 review). Métriques cross-user
            # remplacées par les variantes user-scoped.
            {
                "title": "Taux de succès",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "success_rate"},
                "col_span": 4,
                "position_order": 0,
                "style_config": {"colors": ["#10B981"]},
            },
            {
                "title": "Recherches totales",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_searches"},
                "col_span": 4,
                "position_order": 1,
                "style_config": {"colors": ["#4F46E5"]},
            },
            {
                "title": "Rapports générés",
                "widget_type": "kpi",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "total_reports"},
                "col_span": 4,
                "position_order": 2,
                "style_config": {"colors": ["#F59E0B"]},
            },
            {
                "title": "Tendance activité",
                "widget_type": "chart",
                "chart_type": "area",
                "data_source_type": "metric",
                "data_source_config": {
                    "metric_name": "daily_searches",
                    "period": "30d",
                },
                "col_span": 12,
                "position_order": 3,
                "style_config": {
                    "colors": ["#06B6D4", "#4F46E5"],
                    "show_legend": False,
                    "height": 300,
                },
            },
            {
                "title": "Exécutions automatisations",
                "widget_type": "chart",
                "chart_type": "donut",
                "data_source_type": "metric",
                "data_source_config": {"metric_name": "execution_status"},
                "col_span": 12,
                "position_order": 4,
                "style_config": {
                    "colors": ["#10B981", "#EF4444"],
                    "show_legend": True,
                    "height": 300,
                },
            },
        ],
    },
]

# Index par slug pour lookup rapide
_TEMPLATES_BY_SLUG = {t["slug"]: t for t in DASHBOARD_TEMPLATES}


class DashboardTemplateService:
    """Service pour gérer les templates de dashboard."""

    def list_templates(self) -> list[dict]:
        """Retourne la liste des templates disponibles (métadonnées uniquement)."""
        return [
            {
                "slug": t["slug"],
                "name": t["name"],
                "description": t["description"],
                "category": t["category"],
                "icon": t["icon"],
                "widget_count": len(t["widgets"]),
            }
            for t in DASHBOARD_TEMPLATES
        ]

    def get_template(self, slug: str) -> Optional[dict]:
        """Retourne un template par son slug (avec les widgets)."""
        return _TEMPLATES_BY_SLUG.get(slug)

    async def create_from_template(
        self,
        session: AsyncSession,
        user_id: int,
        slug: str,
        custom_name: str = "",
    ) -> Optional[dict]:
        """Crée un dashboard à partir d'un template.

        Retourne le dict du dashboard créé, ou None si le slug est inconnu.
        """
        from app.models.dashboard import Dashboard, DashboardWidget

        template = self.get_template(slug)
        if not template:
            return None

        name = (
            custom_name.strip()[:200] if custom_name and custom_name.strip() else template["name"]
        )

        dashboard = Dashboard(
            name=name,
            description=template["description"],
            user_id=user_id,
        )
        session.add(dashboard)
        await session.flush()

        for wt in template["widgets"]:
            widget = DashboardWidget(
                dashboard_id=dashboard.id,
                title=wt["title"],
                widget_type=wt["widget_type"],
                chart_type=wt.get("chart_type"),
                data_source_type=wt["data_source_type"],
                data_source_config=wt["data_source_config"],
                col_span=wt["col_span"],
                position_order=wt["position_order"],
                style_config=wt.get("style_config"),
            )
            session.add(widget)

        data = dashboard.to_dict()
        await session.commit()

        logger.info(
            "Dashboard créé depuis template '%s': id=%s, user=%s",
            slug,
            data["id"],
            user_id,
        )
        return data

    # ── User Templates (sauvegardés en BDD) ─────────────────────────────

    async def list_user_templates(
        self,
        session: AsyncSession,
        user_id: int,
    ) -> list[dict]:
        """Liste les templates créés par l'utilisateur courant (owner only).

        Strict scope owner-only — aucun partage cross-user (cf. tâche #29).
        """
        from app.models.dashboard import Dashboard

        stmt = (
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .where(
                Dashboard.is_template.is_(True),
                Dashboard.user_id == user_id,
            )
            .order_by(Dashboard.created_at.desc())
        )
        result = await session.execute(stmt)
        templates = result.scalars().all()

        items = []
        for t in templates:
            widget_count = len(t.widgets) if t.widgets else 0
            items.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "description": t.template_description or t.description or "",
                    "category": "user",
                    "icon": "template",
                    "widget_count": widget_count,
                    "user_id": t.user_id,
                    "is_mine": True,
                    "created_at": t.created_at.isoformat() if t.created_at else None,
                }
            )
        return items

    async def save_as_template(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        template_name: str = "",
        template_description: str = "",
    ) -> Optional[dict]:
        """Sauvegarde un dashboard comme modèle réutilisable.

        Crée une copie snapshot du dashboard (avec widgets et filtres)
        marquée is_template=True. Le dashboard original reste intact.

        Retourne le dict du template créé, ou None si dashboard introuvable.
        """
        from app.models.dashboard import Dashboard, DashboardWidget, DashboardFilter

        # Charger le dashboard source avec relations
        stmt = (
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .options(selectinload(Dashboard.filters))
            .where(Dashboard.id == dashboard_id)
        )
        result = await session.execute(stmt)
        original = result.scalar_one_or_none()

        if not original:
            return None
        if original.user_id != user_id:
            return None

        # Capturer les données AVANT toute opération (async safety)
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

        filter_configs = []
        for f in original.filters:
            filter_configs.append(
                {
                    "parameter_name": f.parameter_name,
                    "label": f.label,
                    "filter_type": f.filter_type,
                    "values_source": f.values_source,
                    "values_config": f.values_config,
                    "default_value": f.default_value,
                    "position_order": f.position_order,
                }
            )

        original_name = original.name
        original_description = original.description

        # Créer le template (copie snapshot)
        name = (
            template_name.strip()[:200]
            if template_name and template_name.strip()
            else original_name
        )
        desc = template_description.strip()[:500] if template_description else ""

        template = Dashboard(
            name=name,
            description=original_description,
            template_description=desc or None,
            user_id=user_id,
            is_template=True,
        )
        session.add(template)
        await session.flush()

        # Copier les widgets
        for wc in widget_configs:
            widget = DashboardWidget(dashboard_id=template.id, **wc)
            session.add(widget)

        # Copier les filtres
        for fc in filter_configs:
            filt = DashboardFilter(dashboard_id=template.id, **fc)
            session.add(filt)

        data = template.to_dict()
        data["widget_count"] = len(widget_configs)
        data["filter_count"] = len(filter_configs)
        await session.commit()

        logger.info(
            "Dashboard %s sauvegardé comme template: id=%s, user=%s",
            dashboard_id,
            data["id"],
            user_id,
        )
        return data

    async def create_from_user_template(
        self,
        session: AsyncSession,
        template_id: int,
        user_id: int,
        custom_name: str = "",
    ) -> Optional[dict]:
        """Crée un dashboard à partir d'un template utilisateur.

        Retourne le dict du dashboard créé, ou None si template introuvable
        ou non accessible.
        """
        from app.models.dashboard import Dashboard, DashboardWidget, DashboardFilter

        # Charger le template avec relations
        stmt = (
            select(Dashboard)
            .options(selectinload(Dashboard.widgets))
            .options(selectinload(Dashboard.filters))
            .where(
                Dashboard.id == template_id,
                Dashboard.is_template.is_(True),
            )
        )
        result = await session.execute(stmt)
        template = result.scalar_one_or_none()

        if not template:
            return None
        # Accessible seulement si owner — aucun partage cross-user (cf. tâche #29)
        if template.user_id != user_id:
            return None

        # Capturer les données (async safety)
        widget_configs = []
        for w in template.widgets:
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

        filter_configs = []
        for f in template.filters:
            filter_configs.append(
                {
                    "parameter_name": f.parameter_name,
                    "label": f.label,
                    "filter_type": f.filter_type,
                    "values_source": f.values_source,
                    "values_config": f.values_config,
                    "default_value": f.default_value,
                    "position_order": f.position_order,
                }
            )

        template_name = template.name
        template_desc = template.description

        name = custom_name.strip()[:200] if custom_name and custom_name.strip() else template_name

        dashboard = Dashboard(
            name=name,
            description=template_desc,
            user_id=user_id,
            is_template=False,
        )
        session.add(dashboard)
        await session.flush()

        for wc in widget_configs:
            widget = DashboardWidget(dashboard_id=dashboard.id, **wc)
            session.add(widget)

        for fc in filter_configs:
            filt = DashboardFilter(dashboard_id=dashboard.id, **fc)
            session.add(filt)

        data = dashboard.to_dict()
        await session.commit()

        logger.info(
            "Dashboard créé depuis user template %s: id=%s, user=%s",
            template_id,
            data["id"],
            user_id,
        )
        return data

    async def delete_user_template(
        self,
        session: AsyncSession,
        template_id: int,
        user_id: int,
    ) -> bool:
        """Supprime un template utilisateur. Owner-only.

        Retourne True si supprimé, False si introuvable ou non autorisé.
        """
        from app.models.dashboard import Dashboard

        stmt = select(Dashboard).where(
            Dashboard.id == template_id,
            Dashboard.is_template.is_(True),
        )
        result = await session.execute(stmt)
        template = result.scalar_one_or_none()

        if not template:
            return False
        if template.user_id != user_id:
            return False

        await session.delete(template)
        await session.commit()

        logger.info(
            "User template supprimé: id=%s, user=%s",
            template_id,
            user_id,
        )
        return True
