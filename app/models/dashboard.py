"""
Modèles Dashboard pour Komptia.

Représente un tableau de bord personnalisable avec des widgets configurables.
Chaque utilisateur peut créer plusieurs dashboards avec des graphiques,
KPIs et tableaux alimentés par des requêtes SQL ou des métriques prédéfinies.
"""

import re
from datetime import datetime
from typing import TYPE_CHECKING, ClassVar, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core import clock
from app.core.database import Base
from app.models.base import ensure_utc

if TYPE_CHECKING:
    from app.models.user import User  # noqa: F401

# Schedule types supportés (identiques au scheduler d'automations)
VALID_SCHEDULE_TYPES = ("daily", "weekly", "monthly", "cron")


class Dashboard(Base):
    """
    Tableau de bord personnalisable.

    Un dashboard contient des widgets configurables (graphiques, KPIs, tableaux)
    disposés dans une grille responsive. Chaque widget a sa propre source de données
    (requête SQL ou métrique prédéfinie de l'application).

    Supporte l'envoi planifié par email (schedule_*).
    """

    __tablename__ = "F_DASHBOARD"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True,
        comment="Nom du tableau de bord",
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Description du tableau de bord"
    )

    # Template — permet de sauvegarder un dashboard comme modèle réutilisable
    is_template: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True si ce dashboard est un modèle réutilisable",
    )
    template_description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        comment="Description du modèle (affichée dans la galerie de templates)",
    )

    # Ownership
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Utilisateur propriétaire du tableau de bord",
    )

    # ── Envoi planifié par email ──────────────────────────────────────────
    schedule_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="Envoi planifié actif",
    )
    schedule_type: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        comment="Type de planification: daily, weekly, monthly, cron",
    )
    schedule_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Config JSON: {hour, minute, day_of_week, day, cron}",
    )
    schedule_recipients: Mapped[Optional[list]] = mapped_column(
        JSON,
        nullable=True,
        comment="Liste d'emails destinataires",
    )
    schedule_period_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
        comment="Période de données à inclure (jours)",
    )
    schedule_last_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Dernière date d'envoi planifié",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        comment="Date de création",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
        comment="Date de dernière modification",
    )

    # Relations
    user: Mapped["User"] = relationship("User")
    widgets: Mapped[list["DashboardWidget"]] = relationship(
        "DashboardWidget",
        back_populates="dashboard",
        cascade="all, delete-orphan",
        order_by="DashboardWidget.position_order",
    )
    filters: Mapped[list["DashboardFilter"]] = relationship(
        "DashboardFilter",
        back_populates="dashboard",
        cascade="all, delete-orphan",
        order_by="DashboardFilter.position_order",
    )

    def __repr__(self):
        return f"<Dashboard(id={self.id}, name='{self.name}')>"

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API.

        N'accède PAS aux relations (widgets, user) pour éviter MissingGreenlet.
        Utiliser des requêtes séparées pour les widgets.
        """
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_template": self.is_template,
            "template_description": self.template_description,
            "user_id": self.user_id,
            "schedule_enabled": self.schedule_enabled,
            "schedule_type": self.schedule_type,
            "schedule_config": self.schedule_config,
            "schedule_recipients": self.schedule_recipients,
            "schedule_period_days": self.schedule_period_days,
            "schedule_last_sent_at": (
                ensure_utc(self.schedule_last_sent_at).isoformat()
                if self.schedule_last_sent_at
                else None
            ),
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
            "updated_at": ensure_utc(self.updated_at).isoformat() if self.updated_at else None,
        }


class DashboardWidget(Base):
    """
    Widget d'un tableau de bord.

    Chaque widget représente une visualisation (graphique, KPI, tableau)
    avec sa propre source de données et sa configuration d'affichage.

    Types de widgets :
    - chart : graphique interactif (line, bar, pie, donut, area, scatter)
    - kpi : indicateur clé (nombre avec variation)
    - table : tableau de données

    Sources de données :
    - sql : requête SQL personnalisée exécutée contre Sage
    - metric : métrique prédéfinie de l'application (recherches, exécutions, etc.)
    """

    __tablename__ = "F_DASHBOARD_WIDGET"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    dashboard_id: Mapped[int] = mapped_column(
        ForeignKey("F_DASHBOARD.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Dashboard parent",
    )
    title: Mapped[str] = mapped_column(
        String(200), nullable=False, comment="Titre affiché du widget"
    )

    # Type de widget
    widget_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="chart",
        comment="Type: 'chart', 'kpi', 'table', 'text', 'grid'",
    )
    chart_type: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        comment="Type de graphique: 'line', 'bar', 'pie', 'donut', 'area', 'scatter'",
    )

    # Source de données
    data_source_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="metric",
        comment="Source: 'sql' (requête custom) ou 'metric' (métrique prédéfinie)",
    )
    data_source_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment=(
            "Config JSON de la source. "
            "sql: {'query': 'SELECT ...'} | "
            "metric: {'metric_name': 'total_searches', 'period': '7d'}"
        ),
    )

    # Position dans la grille
    col_span: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=6,
        comment="Largeur en colonnes (sur 12). 3=quart, 4=tiers, 6=moitié, 12=pleine",
    )
    position_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Ordre d'affichage dans le dashboard (0 = premier)",
    )

    # Style
    style_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment=(
            "Config style JSON. "
            "Ex: {'colors': ['#4F46E5', '#10B981'], 'show_legend': true, "
            "'height': 300}"
        ),
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    # Relations
    dashboard: Mapped["Dashboard"] = relationship("Dashboard", back_populates="widgets")

    # Constantes de validation
    # "grid" : widget tableau interactif = copie conforme de la result area
    # /iris (composant GridTabManager + SqlResultGrid). Distinct de "table"
    # qui rend du HTML simple non interactif via renderTable(). data_source_
    # type imposé à "sql" (pas de version aggregée/IA — affichage brut).
    VALID_WIDGET_TYPES = ("chart", "kpi", "table", "text", "grid")
    VALID_CHART_TYPES = ("line", "bar", "pie", "donut", "area", "scatter")
    # "static" : widget sans source de données dynamique (texte structurant,
    # note, séparateur de section). data_source_config porte {title, content}.
    VALID_DATA_SOURCE_TYPES = ("sql", "metric", "static")
    VALID_COL_SPANS = (3, 4, 6, 8, 12)

    # Caps applicatifs pour widget_type="text" / data_source_type="static".
    # Single source of truth : referencer ces constantes côté frontend
    # (via injection template) et côté service (truncate défensif).
    MAX_TEXT_WIDGET_CONTENT_LEN = 5000
    MAX_TEXT_WIDGET_TITLE_LEN = 200

    # Feature "Requête SQL" (menu [+] de la grille) : un widget grid peut
    # porter, en plus de sa requête principale, N onglets SQL additionnels —
    # chacun une requête INDÉPENDANTE ré-exécutée à chaque affichage (même
    # pipeline que le tab principal). Stockés dans data_source_config sous
    # la clé "extra_tabs": [{"label": str, "query": str}, ...].
    # SSoT des caps — mirroir côté JS (iris-grid.js _sqlTabContext) et
    # défense-in-depth côté service (_execute_grid_extra_tabs).
    MAX_GRID_EXTRA_TABS = 10
    MAX_GRID_TAB_LABEL_LEN = 100
    MAX_GRID_TAB_QUERY_LEN = 10000
    # Mode classeur (sauvegarde du widget grille façon /datastore) : cap du
    # nombre TOTAL de feuilles (SQL + manuelles + drill-down) d'un classeur
    # de widget. Les feuilles SQL restent bornées par 1 + MAX_GRID_EXTRA_TABS.
    MAX_GRID_WORKBOOK_TABS = 30

    def __repr__(self):
        return (
            f"<DashboardWidget(id={self.id}, title='{self.title}', " f"type='{self.widget_type}')>"
        )

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API.

        N'accède PAS à la relation dashboard pour éviter MissingGreenlet.
        """
        return {
            "id": self.id,
            "dashboard_id": self.dashboard_id,
            "title": self.title,
            "widget_type": self.widget_type,
            "chart_type": self.chart_type,
            "data_source_type": self.data_source_type,
            "data_source_config": self.data_source_config,
            "col_span": self.col_span,
            "position_order": self.position_order,
            "style_config": self.style_config,
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
            "updated_at": ensure_utc(self.updated_at).isoformat() if self.updated_at else None,
        }

    def validate(self) -> list[str]:
        """Valide la configuration du widget. Retourne une liste d'erreurs."""
        errors = []

        if not self.title or not self.title.strip():
            errors.append("Le titre est obligatoire.")

        if self.widget_type not in self.VALID_WIDGET_TYPES:
            errors.append(
                f"Type de widget invalide: '{self.widget_type}'. "
                f"Valeurs acceptées: {', '.join(self.VALID_WIDGET_TYPES)}"
            )

        if self.widget_type == "chart":
            # chart_type est optionnel pour les widgets SQL (auto-détection depuis
            # la forme des données retournées). Reste obligatoire pour les metrics
            # préconfigurées dont la forme de donnée n'est pas standardisée.
            if not self.chart_type:
                if self.data_source_type != "sql":
                    errors.append("Le type de graphique est obligatoire pour un widget chart.")
            elif self.chart_type not in self.VALID_CHART_TYPES:
                errors.append(
                    f"Type de graphique invalide: '{self.chart_type}'. "
                    f"Valeurs acceptées: {', '.join(self.VALID_CHART_TYPES)}"
                )

        # "grid" : composant interactif SqlResultGrid (copie /iris). Impose
        # une source SQL — pas de version metric/static (le tableau brut n'a
        # de sens qu'avec une requête utilisateur explicite).
        if self.widget_type == "grid":
            if self.data_source_type != "sql":
                errors.append(
                    "Un widget grid doit avoir data_source_type='sql' "
                    "(le tableau interactif ne supporte que les requêtes SQL)."
                )
            # chart_type n'a aucun sens pour un grid — bloquer pour éviter
            # un état incohérent (le frontend ignorerait silencieusement).
            if self.chart_type:
                errors.append(
                    "Un widget grid ne doit pas avoir de chart_type "
                    "(le tableau interactif n'est pas un graphique)."
                )
            # Defense-in-depth : SELECT/WITH uniquement au SAVE (pas qu'au
            # runtime dans _fetch_sql_data). Sans ça, un POST direct via
            # curl persiste un INSERT/DROP en BDD, qui est ensuite cloné
            # par clone_dashboard, exporté, et peut être ré-exécuté par un
            # futur code path qui bypass _fetch_sql_data (debug tool admin,
            # script de migration). Adversarial review CRIT-4 — 2026-05-26.
            cfg = self.data_source_config or {}
            query = cfg.get("query", "") if isinstance(cfg, dict) else ""
            if isinstance(query, str) and query.strip():
                stripped = query.strip().upper()
                if not (stripped.startswith("SELECT") or stripped.startswith("WITH")):
                    errors.append(
                        "La requête doit commencer par SELECT ou WITH "
                        "(seules les requêtes en lecture sont autorisées)."
                    )
                # CWE-158 : NUL → troncature silencieuse driver ODBC. Rejet au
                # save (anti-curl) en parité avec le runtime (_fetch_sql_data)
                # et /api/datastore/sql/execute.
                if "\x00" in query:
                    errors.append("La requête ne doit pas contenir de caractère NUL.")
                # Cap longueur : parité avec les onglets additionnels (sinon une
                # requête principale géante — jusqu'au cap body ~256 KiB — serait
                # ré-exécutée contre Sage + cachée à chaque render/export/email).
                if len(query) > self.MAX_GRID_TAB_QUERY_LEN:
                    errors.append(
                        f"La requête est trop longue "
                        f"(maximum {self.MAX_GRID_TAB_QUERY_LEN} caractères)."
                    )

            # Onglets SQL additionnels (feature menu [+] « Requête SQL »).
            # Mêmes garanties que la requête principale, appliquées à CHAQUE
            # onglet : SELECT/WITH au save (defense-in-depth anti-curl —
            # cf. CRIT-4 ci-dessus, étendu aux extra_tabs car ils sont aussi
            # clonés/exportés/ré-exécutés). check_sql_dangerous reste appliqué
            # au runtime dans _fetch_sql_data (SSoT validateur Iris).
            extra_tabs = cfg.get("extra_tabs") if isinstance(cfg, dict) else None
            if extra_tabs is not None:
                if not isinstance(extra_tabs, list):
                    errors.append("Les onglets SQL (extra_tabs) doivent être une liste.")
                elif len(extra_tabs) > self.MAX_GRID_EXTRA_TABS:
                    errors.append(
                        f"Trop d'onglets SQL : {len(extra_tabs)} "
                        f"(maximum {self.MAX_GRID_EXTRA_TABS})."
                    )
                else:
                    for idx, tab in enumerate(extra_tabs):
                        pos = idx + 1
                        if not isinstance(tab, dict):
                            errors.append(f"Onglet SQL #{pos} : format invalide.")
                            continue
                        label = tab.get("label")
                        if not isinstance(label, str) or not label.strip():
                            errors.append(f"Onglet SQL #{pos} : le titre est obligatoire.")
                        elif len(label) > self.MAX_GRID_TAB_LABEL_LEN:
                            errors.append(
                                f"Onglet SQL #{pos} : titre trop long "
                                f"(maximum {self.MAX_GRID_TAB_LABEL_LEN} caractères)."
                            )
                        tab_query = tab.get("query")
                        if not isinstance(tab_query, str) or not tab_query.strip():
                            errors.append(f"Onglet SQL #{pos} : la requête est obligatoire.")
                        elif len(tab_query) > self.MAX_GRID_TAB_QUERY_LEN:
                            errors.append(
                                f"Onglet SQL #{pos} : requête trop longue "
                                f"(maximum {self.MAX_GRID_TAB_QUERY_LEN} caractères)."
                            )
                        elif "\x00" in tab_query:
                            # CWE-158 : certains drivers ODBC tronquent
                            # silencieusement la requête au 1er NUL → la requête
                            # réellement exécutée diffère de celle affichée
                            # (données fausses silencieuses). Parité avec la
                            # requête principale (ci-dessus) et
                            # ``/api/datastore/sql/execute``.
                            errors.append(
                                f"Onglet SQL #{pos} : caractère NUL interdit dans la requête."
                            )
                        elif not (
                            tab_query.strip().upper().startswith("SELECT")
                            or tab_query.strip().upper().startswith("WITH")
                        ):
                            errors.append(
                                f"Onglet SQL #{pos} : la requête doit commencer par "
                                f"SELECT ou WITH (lecture seule)."
                            )

        if self.data_source_type not in self.VALID_DATA_SOURCE_TYPES:
            errors.append(
                f"Source de données invalide: '{self.data_source_type}'. "
                f"Valeurs acceptées: {', '.join(self.VALID_DATA_SOURCE_TYPES)}"
            )

        if not self.data_source_config:
            errors.append("La configuration de la source de données est obligatoire.")
        elif self.data_source_type == "sql":
            if not isinstance(self.data_source_config, dict):
                errors.append("La configuration SQL doit être un dictionnaire.")
            elif not self.data_source_config.get("query"):
                errors.append("La requête SQL est obligatoire pour une source SQL.")
        elif self.data_source_type == "metric":
            if not isinstance(self.data_source_config, dict):
                errors.append("La configuration métrique doit être un dictionnaire.")
            elif not self.data_source_config.get("metric_name"):
                errors.append("Le nom de la métrique est obligatoire.")
        elif self.data_source_type == "static":
            if not isinstance(self.data_source_config, dict):
                errors.append("La configuration statique doit être un dictionnaire.")
            else:
                content = self.data_source_config.get("content")
                if not isinstance(content, str) or not content.strip():
                    errors.append("Le contenu texte est obligatoire pour un widget statique.")
                elif len(content) > self.MAX_TEXT_WIDGET_CONTENT_LEN:
                    errors.append(
                        f"Le contenu texte dépasse {self.MAX_TEXT_WIDGET_CONTENT_LEN} "
                        "caractères."
                    )
                # Caractères de contrôle (0x00-0x1F sauf \n \t) : rendus de
                # façon incohérente entre Chrome/Firefox/Safari (glyph .notdef
                # ou rien). Bypass possible via curl direct — le textarea
                # HTML les strippe partiellement, pas tous. Reject explicite
                # = render uniforme + sécurité supply chain (paste de payloads
                # malicieux dans un éditeur tiers).
                elif isinstance(content, str) and any(
                    ord(c) < 32 and c not in "\n\t" for c in content
                ):
                    errors.append("Le contenu contient des caractères de contrôle interdits.")
                # Cap title aussi, sinon la BDD JSONB peut stocker une string
                # géante (la column DB widget.title fait String(200) mais la
                # clé title dans data_source_config n'a aucune limite native).
                title = self.data_source_config.get("title")
                if title is not None and not isinstance(title, str):
                    errors.append("Le titre statique doit être une chaîne.")
                elif isinstance(title, str) and len(title) > self.MAX_TEXT_WIDGET_TITLE_LEN:
                    errors.append(
                        f"Le titre statique dépasse {self.MAX_TEXT_WIDGET_TITLE_LEN} " "caractères."
                    )

        if self.col_span not in self.VALID_COL_SPANS:
            errors.append(
                f"Largeur invalide: {self.col_span}. "
                f"Valeurs acceptées: {', '.join(str(s) for s in self.VALID_COL_SPANS)}"
            )

        return errors


class DashboardFilter(Base):
    """
    Filtre/slicer d'un tableau de bord — style Power BI.

    Chaque filtre représente un contrôle interactif (dropdown, date range, etc.)
    qui filtre les données de tous les widgets du dashboard simultanément.
    Le parameter_name est injecté dans les requêtes des widgets.

    Types de filtres :
    - dropdown_single : liste déroulante (une seule valeur)
    - dropdown_multi : liste déroulante (plusieurs valeurs)
    - date_range : plage de dates (début/fin)
    - numeric_range : plage numérique (min/max)
    - text_search : recherche textuelle libre

    Sources de valeurs (pour les dropdowns) :
    - static : liste de valeurs statiques définies par l'utilisateur
    - sql : requête SQL dont les résultats peuplent la liste
    """

    __tablename__ = "F_DASHBOARD_FILTER"

    # Identification
    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    dashboard_id: Mapped[int] = mapped_column(
        ForeignKey("F_DASHBOARD.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Dashboard parent",
    )

    # Définition du filtre
    parameter_name: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Identifiant du paramètre (doit matcher un nom de colonne pour SQL widgets)",
    )
    label: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Libellé affiché dans l'UI",
    )
    filter_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Type de contrôle: dropdown_single, dropdown_multi, date_range, "
        "numeric_range, text_search",
    )

    # Source des valeurs (pour les dropdowns)
    values_source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="static",
        comment="Source des options: static, sql",
    )
    values_config: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Config selon values_source. "
        "static: {'options': [{'value': 'x', 'label': 'X'}, ...]} | "
        "sql: {'query': 'SELECT DISTINCT col FROM ...'}",
    )

    # Valeur par défaut
    default_value: Mapped[Optional[dict]] = mapped_column(
        JSON,
        nullable=True,
        comment="Valeur par défaut (scalar ou liste selon filter_type)",
    )

    # Position
    position_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Ordre d'affichage dans la barre de filtres (0 = premier)",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    # Relations
    dashboard: Mapped["Dashboard"] = relationship("Dashboard", back_populates="filters")

    # Constantes de validation
    VALID_FILTER_TYPES = (
        "dropdown_single",
        "dropdown_multi",
        "date_range",
        "numeric_range",
        "text_search",
    )
    VALID_VALUES_SOURCES = ("static", "sql")
    VALID_PARAMETER_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,49}$")

    def __repr__(self):
        return (
            f"<DashboardFilter(id={self.id}, param='{self.parameter_name}', "
            f"type='{self.filter_type}')>"
        )

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API.

        N'accède PAS à la relation dashboard pour éviter MissingGreenlet.
        """
        return {
            "id": self.id,
            "dashboard_id": self.dashboard_id,
            "parameter_name": self.parameter_name,
            "label": self.label,
            "filter_type": self.filter_type,
            "values_source": self.values_source,
            "values_config": self.values_config,
            "default_value": self.default_value,
            "position_order": self.position_order,
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
            "updated_at": ensure_utc(self.updated_at).isoformat() if self.updated_at else None,
        }

    def validate(self) -> list[str]:
        """Valide la configuration du filtre. Retourne une liste d'erreurs."""
        errors = []

        if not self.parameter_name or not self.VALID_PARAMETER_NAME_RE.match(self.parameter_name):
            errors.append(
                "parameter_name doit être alphanumérique (lettres, chiffres, underscore), "
                "commencer par une lettre ou underscore, max 50 caractères."
            )

        if not self.label or not self.label.strip():
            errors.append("Le libellé est obligatoire.")

        if self.filter_type not in self.VALID_FILTER_TYPES:
            errors.append(
                f"Type de filtre invalide: '{self.filter_type}'. "
                f"Valeurs acceptées: {', '.join(self.VALID_FILTER_TYPES)}"
            )

        if self.values_source not in self.VALID_VALUES_SOURCES:
            errors.append(
                f"Source de valeurs invalide: '{self.values_source}'. "
                f"Valeurs acceptées: {', '.join(self.VALID_VALUES_SOURCES)}"
            )

        # Validate values_config based on source
        if self.values_source == "static":
            if self.filter_type in ("dropdown_single", "dropdown_multi"):
                cfg = self.values_config or {}
                options = cfg.get("options", [])
                if not isinstance(options, list) or not options:
                    errors.append(
                        "Les filtres dropdown statiques nécessitent une liste "
                        "'options' non vide dans values_config."
                    )
        elif self.values_source == "sql":
            cfg = self.values_config or {}
            query = cfg.get("query", "")
            if not query or not query.strip():
                errors.append(
                    "Les filtres avec source SQL nécessitent une 'query' " "dans values_config."
                )

        return errors


class DashboardSchedule(Base):
    """Planification d'envoi automatique d'un dashboard par email."""

    __tablename__ = "F_DASHBOARD_SCHEDULE"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    dashboard_id: Mapped[int] = mapped_column(
        ForeignKey("F_DASHBOARD.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    schedule_type: Mapped[str] = mapped_column(String(20), nullable=False)
    schedule_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    export_format: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="excel",
    )
    recipients: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    subject: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    last_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
    )
    last_status: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
    )
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=clock.now,
        onupdate=clock.now,
    )

    dashboard: Mapped["Dashboard"] = relationship("Dashboard")
    user: Mapped["User"] = relationship("User")

    VALID_SCHEDULE_TYPES = ("daily", "weekly", "monthly")
    VALID_EXPORT_FORMATS = ("csv", "excel")
    #: Cap métier sur la liste de destinataires d'un envoi (planifié OU
    #: ad-hoc via ``DashboardSendNowAPIHandler``). Source unique de vérité
    #: référencée par ``validate()`` ci-dessous ET par le handler send-now
    #: (cf. ``app/handlers/dashboard_builder.py::DashboardSendNowAPIHandler``).
    #: Au-delà : 400 côté handler, erreur métier côté validate. Toute
    #: modification ici doit faire grimper le cap des deux entrées.
    #:
    #: ``ClassVar[int]`` plutôt que ``Mapped[...]`` : c'est une constante
    #: de classe (single source of truth), pas une colonne SQL. Le linter
    #: bloque ainsi une mutation accidentelle externe (mypy lèvera l'erreur
    #: sur ``DashboardSchedule.MAX_RECIPIENTS = 99`` à l'extérieur de la classe).
    MAX_RECIPIENTS: ClassVar[int] = 50
    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    def __repr__(self):
        return (
            f"<DashboardSchedule(id={self.id}, "
            f"dashboard_id={self.dashboard_id}, "
            f"type='{self.schedule_type}', active={self.is_active})>"
        )

    def to_dict(self):
        """Convertit en dictionnaire pour JSON API."""
        return {
            "id": self.id,
            "dashboard_id": self.dashboard_id,
            "user_id": self.user_id,
            "schedule_type": self.schedule_type,
            "schedule_config": self.schedule_config,
            "export_format": self.export_format,
            "recipients": self.recipients,
            "subject": self.subject,
            "message": self.message,
            "is_active": self.is_active,
            "last_sent_at": (
                ensure_utc(self.last_sent_at).isoformat() if self.last_sent_at else None
            ),
            "last_status": self.last_status,
            "last_error": self.last_error,
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
        }

    def validate(self) -> list[str]:
        """Valide la configuration. Retourne une liste d'erreurs."""
        errors = []
        if self.schedule_type not in self.VALID_SCHEDULE_TYPES:
            errors.append(
                f"Type invalide: '{self.schedule_type}'. "
                f"Valeurs: {', '.join(self.VALID_SCHEDULE_TYPES)}"
            )
        if self.export_format not in self.VALID_EXPORT_FORMATS:
            errors.append(
                f"Format invalide: '{self.export_format}'. "
                f"Valeurs: {', '.join(self.VALID_EXPORT_FORMATS)}"
            )
        if not self.recipients or not isinstance(self.recipients, list):
            errors.append("Au moins un destinataire est requis.")
        else:
            valid = [r for r in self.recipients if isinstance(r, str) and self._EMAIL_RE.match(r)]
            if not valid:
                errors.append("Aucun email valide.")
            if len(self.recipients) > self.MAX_RECIPIENTS:
                errors.append(f"Maximum {self.MAX_RECIPIENTS} destinataires.")
        cfg = self.schedule_config or {}
        if not isinstance(cfg, dict):
            errors.append("schedule_config doit être un dictionnaire.")
        else:
            hour = cfg.get("hour")
            if hour is not None:
                try:
                    h = int(hour)
                    if not (0 <= h <= 23):
                        errors.append("Heure: 0-23.")
                except (ValueError, TypeError):
                    errors.append("Heure invalide.")
            minute = cfg.get("minute")
            if minute is not None:
                try:
                    m = int(minute)
                    if not (0 <= m <= 59):
                        errors.append("Minutes: 0-59.")
                except (ValueError, TypeError):
                    errors.append("Minutes invalides.")
            if self.schedule_type == "weekly":
                dow = cfg.get("day_of_week")
                valid_days = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
                if dow and dow not in valid_days:
                    errors.append(f"Jour invalide: '{dow}'.")
            elif self.schedule_type == "monthly":
                day = cfg.get("day")
                if day is not None:
                    try:
                        d = int(day)
                        if not (1 <= d <= 28):
                            errors.append("Jour du mois: 1-28.")
                    except (ValueError, TypeError):
                        errors.append("Jour du mois invalide.")
        return errors
