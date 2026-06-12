"""
Constructeur de graphiques pour rapports
Génère des graphiques avec matplotlib pour intégration dans les PDFs
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Literal
import math
import os
import tempfile
from datetime import datetime
import re
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

from app.utils.logger import get_logger

matplotlib.use("Agg")  # Backend sans affichage
# Désactive le parsing mathtext : sinon un ``$`` dans un libellé (fréquent en
# données comptables : montants USD, « Coût $ », « $100-$200 ») déclenche le
# mode maths LaTeX-like de matplotlib → libellé DÉFORMÉ dans le graphe du
# rapport (et crash possible de savefig sur du mathtext invalide). Les libellés
# proviennent des données (titres, noms de colonnes, catégories) — on veut
# TOUJOURS du texte littéral, jamais des maths.
matplotlib.rcParams["text.parse_math"] = False

logger = get_logger(__name__)


ChartType = Literal["bar", "line", "pie", "auto"]


def _safe_float(val, default=0.0):
    """
    Convertit une valeur en float fini de manière sûre.

    Args:
        val: Valeur à convertir (peut être None ou invalide)
        default: Valeur par défaut si la conversion échoue ou si la valeur n'est pas finie

    Returns:
        float: Valeur convertie finie, ou `default` si None / non convertible / NaN / +/-Inf

    Note:
        NaN et +/-Inf sont rejetés vers `default` car ils produisent des
        labels textuels « nan »/« inf » dans les PDFs côté callers (bar /
        line / multi-series). Le filtre `math.isfinite` reprend celui déjà
        appliqué dans `aggregated_chart_renderer._safe_float` (qui filtre en
        plus `bool` — hors scope ici car les callers n'envoient pas de bool).
    """
    try:
        f = float(val) if val is not None else default
    except (ValueError, TypeError):
        return default
    if not math.isfinite(f):
        return default
    return f


class ChartBuilder:
    """Constructeur de graphiques pour rapports"""

    def __init__(
        self,
        style: str = "seaborn-v0_8-darkgrid",
        dpi: int = 150,
        figsize: Tuple[float, float] = (10, 6),
    ):
        """
        Initialise le constructeur de graphiques

        Args:
            style: Style matplotlib ('seaborn-v0_8-darkgrid', 'ggplot', etc.)
            dpi: Résolution pour export PNG
            figsize: Taille de la figure (largeur, hauteur) en inches
        """
        self.dpi = dpi
        self.figsize = figsize

        # Définir style
        try:
            plt.style.use(style)
        except (ValueError, OSError):
            logger.warning("Style %s non disponible, utilisation du style par défaut", style)
            plt.style.use("default")

        # Couleurs professionnelles
        self.colors = [
            "#366092",  # Bleu principal
            "#2ecc71",  # Vert
            "#e74c3c",  # Rouge
            "#f39c12",  # Orange
            "#9b59b6",  # Violet
            "#1abc9c",  # Turquoise
            "#34495e",  # Gris foncé
            "#e67e22",  # Orange foncé
        ]

    def auto_detect_chart_type(
        self, data: List[Dict[str, Any]], x_column: str, y_column: str
    ) -> ChartType:
        """
        Détecte automatiquement le type de graphique le plus adapté

        Args:
            data: Données à visualiser
            x_column: Nom de la colonne X
            y_column: Nom de la colonne Y

        Returns:
            Type de graphique recommandé
        """
        if not data or len(data) == 0:
            return "bar"

        # Analyser les données
        num_points = len(data)
        x_values = [row.get(x_column) for row in data]

        # Vérifier si X contient des dates (datetime objects ou strings date-like)
        has_dates = any(isinstance(x, datetime) for x in x_values)

        # Si pas de datetime objects, vérifier les strings ressemblant à des dates
        if not has_dates and x_values:
            # Vérifier si colonne X ressemble à des dates (format ISO, contient -, /)
            sample = str(x_values[0]) if x_values[0] is not None else ""
            has_dates = bool(
                re.match(r"^\d{2,4}[-/]\d{1,2}[-/]\d{1,2}", sample)
                or re.match(r"^\d{1,2}[-/]\d{1,2}[-/]\d{2,4}", sample)
            )

        # Règles de détection (ordre important : dates en priorité)
        if has_dates:
            # Dates → ligne pour évolution temporelle
            return "line"

        elif num_points > 20:
            # Beaucoup de points → ligne pour lisibilité
            return "line"

        elif num_points <= 5:
            # Peu de points (non-temporels) → camembert pour répartition
            return "pie"

        else:
            # Cas général → barres pour comparaison
            return "bar"

    def create_bar_chart(
        self,
        data: List[Dict[str, Any]],
        x_column: str,
        y_column: str,
        title: str = "Graphique à barres",
        xlabel: Optional[str] = None,
        ylabel: Optional[str] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Crée un graphique à barres

        Args:
            data: Données à visualiser
            x_column: Nom de la colonne pour l'axe X (catégories)
            y_column: Nom de la colonne pour l'axe Y (valeurs)
            title: Titre du graphique
            xlabel: Label axe X (optionnel)
            ylabel: Label axe Y (optionnel)
            output_path: Chemin de sortie (temporaire si None)

        Returns:
            Chemin du fichier PNG généré
        """
        logger.info("📊 Création graphique barres: %s", title)

        # Vérifier si données vides
        if not data:
            fig, ax = plt.subplots(figsize=self.figsize)
            try:
                ax.text(
                    0.5,
                    0.5,
                    "Aucune donnée",
                    transform=ax.transAxes,
                    ha="center",
                    va="center",
                    fontsize=14,
                    color="gray",
                )
                ax.set_title(title, fontsize=14, fontweight="bold")
                ax.axis("off")
                plt.tight_layout()
                if output_path is None:
                    fd, tmp = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    output_path = Path(tmp)
                fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
            finally:
                plt.close(fig)
            return output_path

        # Extraire données
        x_values = [str(row.get(x_column, "")) for row in data]
        y_values = [_safe_float(row.get(y_column, 0)) for row in data]

        # Créer figure
        fig, ax = plt.subplots(figsize=self.figsize)
        try:
            # Graphique
            bars = ax.bar(
                range(len(x_values)),
                y_values,
                color=self.colors[0],
                alpha=0.8,
                edgecolor="white",
                linewidth=1.5,
            )

            # Personnalisation
            ax.set_title(title, fontsize=14, fontweight="bold", pad=20)
            ax.set_xlabel(xlabel or x_column, fontsize=11)
            ax.set_ylabel(ylabel or y_column, fontsize=11)
            ax.set_xticks(range(len(x_values)))
            ax.set_xticklabels(x_values, rotation=45, ha="right")

            # Ajouter valeurs sur les barres
            for bar in bars:
                height = bar.get_height()
                ax.text(
                    bar.get_x() + bar.get_width() / 2.0,
                    height,
                    f"{height:,.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                )

            # Grille
            ax.grid(axis="y", alpha=0.3, linestyle="--")

            # Layout serré
            plt.tight_layout()

            # Sauvegarder
            if output_path is None:
                fd, tmp = tempfile.mkstemp(suffix=".png")
                os.close(fd)
                output_path = Path(tmp)

            fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
        finally:
            plt.close(fig)

        logger.info("Graphique barres généré: %s", output_path)
        return output_path

    def create_line_chart(
        self,
        data: List[Dict[str, Any]],
        x_column: str,
        y_column: str,
        title: str = "Graphique en ligne",
        xlabel: Optional[str] = None,
        ylabel: Optional[str] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Crée un graphique en ligne (évolution)

        Args:
            data: Données à visualiser
            x_column: Nom de la colonne pour l'axe X
            y_column: Nom de la colonne pour l'axe Y
            title: Titre du graphique
            xlabel: Label axe X (optionnel)
            ylabel: Label axe Y (optionnel)
            output_path: Chemin de sortie (temporaire si None)

        Returns:
            Chemin du fichier PNG généré
        """
        logger.info("📈 Création graphique ligne: %s", title)

        # Vérifier si données vides
        if not data:
            fig, ax = plt.subplots(figsize=self.figsize)
            try:
                ax.text(
                    0.5,
                    0.5,
                    "Aucune donnée",
                    transform=ax.transAxes,
                    ha="center",
                    va="center",
                    fontsize=14,
                    color="gray",
                )
                ax.set_title(title, fontsize=14, fontweight="bold")
                ax.axis("off")
                plt.tight_layout()
                if output_path is None:
                    fd, tmp = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    output_path = Path(tmp)
                fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
            finally:
                plt.close(fig)
            return output_path

        # Extraire données
        x_values = [row.get(x_column) for row in data]
        y_values = [_safe_float(row.get(y_column, 0)) for row in data]

        # Gérer dates si présentes
        has_dates = any(isinstance(x, datetime) for x in x_values)
        x_plot = list(range(len(x_values))) if has_dates else x_values

        # Créer figure
        fig, ax = plt.subplots(figsize=self.figsize)
        try:
            # Graphique
            ax.plot(
                x_plot,
                y_values,
                color=self.colors[0],
                linewidth=2.5,
                marker="o",
                markersize=6,
                markerfacecolor="white",
                markeredgewidth=2,
                markeredgecolor=self.colors[0],
            )

            # Remplir zone sous la courbe
            ax.fill_between(
                x_plot,
                y_values,
                alpha=0.2,
                color=self.colors[0],
            )

            # Personnalisation
            ax.set_title(title, fontsize=14, fontweight="bold", pad=20)
            ax.set_xlabel(xlabel or x_column, fontsize=11)
            ax.set_ylabel(ylabel or y_column, fontsize=11)

            # Formatter dates si nécessaire
            if has_dates:
                ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m"))
                ax.xaxis.set_major_locator(mdates.AutoDateLocator())
                plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha="right")

            # Grille
            ax.grid(True, alpha=0.3, linestyle="--")

            # Layout
            plt.tight_layout()

            # Sauvegarder
            if output_path is None:
                fd, tmp = tempfile.mkstemp(suffix=".png")
                os.close(fd)
                output_path = Path(tmp)

            fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
        finally:
            plt.close(fig)

        logger.info("Graphique ligne généré: %s", output_path)
        return output_path

    def create_pie_chart(
        self,
        data: List[Dict[str, Any]],
        label_column: str,
        value_column: str,
        title: str = "Graphique camembert",
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Crée un graphique camembert (répartition)

        Args:
            data: Données à visualiser
            label_column: Nom de la colonne pour les labels
            value_column: Nom de la colonne pour les valeurs
            title: Titre du graphique
            output_path: Chemin de sortie (temporaire si None)

        Returns:
            Chemin du fichier PNG généré
        """
        logger.info("🥧 Création graphique camembert: %s", title)

        # Vérifier si données vides
        if not data:
            fig, ax = plt.subplots(figsize=self.figsize)
            try:
                ax.text(
                    0.5,
                    0.5,
                    "Aucune donnée",
                    transform=ax.transAxes,
                    ha="center",
                    va="center",
                    fontsize=14,
                    color="gray",
                )
                ax.set_title(title, fontsize=14, fontweight="bold")
                ax.axis("off")
                plt.tight_layout()
                if output_path is None:
                    fd, tmp = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    output_path = Path(tmp)
                fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
            finally:
                plt.close(fig)
            return output_path

        # Extraire données et filtrer : matplotlib.pie refuse les valeurs négatives,
        # nulles, NaN ou infinies. SSoT #143 : ``prepare_pie_slices`` filtre ces
        # valeurs ET compte celles ≤ 0 exclues (``excluded_nonpos``), surfacées en
        # légende (sinon le camembert prétend représenter 100 % des données). Pas
        # d'agrégation « Autres » ici (``max_slices=0`` → toutes les parts montrées).
        from app.services.reporting.pie_data import prepare_pie_slices

        labels, values, _others, excluded_nonpos = prepare_pie_slices(
            ((row.get(label_column, ""), row.get(value_column, 0)) for row in data),
            max_slices=0,
        )

        if not values:
            # Toutes les valeurs ont été filtrées — placeholder au lieu de crasher
            ax_empty = fig = plt.figure(figsize=self.figsize)
            try:
                ax_empty = fig.add_subplot(111)
                ax_empty.text(
                    0.5,
                    0.5,
                    "Aucune valeur positive",
                    ha="center",
                    va="center",
                    transform=ax_empty.transAxes,
                    color="gray",
                )
                ax_empty.axis("off")
                if output_path is None:
                    fd, tmp = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    output_path = Path(tmp)
                fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
            finally:
                plt.close(fig)
            return output_path

        # Créer figure
        fig, ax = plt.subplots(figsize=self.figsize)
        try:
            # Exploser la plus grande part
            max_val = max(values) if values else 0
            max_idx = values.index(max_val) if values and max_val > 0 else -1
            explode = [0.1 if i == max_idx else 0 for i in range(len(values))]

            # Graphique
            wedges, texts, autotexts = ax.pie(
                values,
                labels=labels,
                autopct="%1.1f%%",
                startangle=90,
                colors=self.colors[: len(values)],
                explode=explode,
                shadow=True,
                textprops={"fontsize": 10},
            )

            # Style des pourcentages
            for autotext in autotexts:
                autotext.set_color("white")
                autotext.set_fontweight("bold")

            # Titre
            ax.set_title(title, fontsize=14, fontweight="bold", pad=20)

            # Égaliser aspect ratio
            ax.axis("equal")

            # Transparence : signaler les parts non représentables exclues (≤ 0,
            # NaN ou valeur absente) sinon le camembert prétend représenter 100 %
            # des données alors qu'il en omet une partie.
            if excluded_nonpos:
                fig.text(
                    0.5,
                    0.01,
                    f"{excluded_nonpos} catégorie(s) sans valeur affichable exclue(s)",
                    ha="center",
                    fontsize=8,
                    color="gray",
                )

            # Layout
            plt.tight_layout()

            # Sauvegarder
            if output_path is None:
                fd, tmp = tempfile.mkstemp(suffix=".png")
                os.close(fd)
                output_path = Path(tmp)

            fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
        finally:
            plt.close(fig)

        logger.info("Graphique camembert généré: %s", output_path)
        return output_path

    def create_chart(
        self,
        data: List[Dict[str, Any]],
        x_column: str,
        y_column: str,
        chart_type: ChartType = "auto",
        title: str = "Graphique",
        xlabel: Optional[str] = None,
        ylabel: Optional[str] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Crée un graphique avec détection automatique du type

        Args:
            data: Données à visualiser
            x_column: Colonne X (ou labels pour pie)
            y_column: Colonne Y (ou values pour pie)
            chart_type: Type de graphique ('auto', 'bar', 'line', 'pie')
            title: Titre
            xlabel: Label X
            ylabel: Label Y
            output_path: Chemin de sortie

        Returns:
            Chemin du fichier PNG généré
        """
        # Auto-détection si demandé
        if chart_type == "auto":
            chart_type = self.auto_detect_chart_type(data, x_column, y_column)
            logger.info("🔍 Type détecté: %s", chart_type)

        # Créer le graphique selon le type
        if chart_type == "bar":
            return self.create_bar_chart(
                data, x_column, y_column, title, xlabel, ylabel, output_path
            )

        elif chart_type == "line":
            return self.create_line_chart(
                data, x_column, y_column, title, xlabel, ylabel, output_path
            )

        elif chart_type == "pie":
            return self.create_pie_chart(data, x_column, y_column, title, output_path)

        else:
            raise ValueError(f"Type de graphique non supporté: {chart_type}")

    def create_multi_series_chart(
        self,
        data: List[Dict[str, Any]],
        x_column: str,
        y_columns: List[str],
        title: str = "Graphique multi-séries",
        xlabel: Optional[str] = None,
        ylabel: Optional[str] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Crée un graphique avec plusieurs séries de données

        Args:
            data: Données à visualiser
            x_column: Colonne X partagée
            y_columns: Liste des colonnes Y à tracer
            title: Titre
            xlabel: Label X
            ylabel: Label Y
            output_path: Chemin de sortie

        Returns:
            Chemin du fichier PNG généré
        """
        logger.info("📊 Création graphique multi-séries: %s", title)

        # Vérifier si données vides
        if not data:
            fig, ax = plt.subplots(figsize=self.figsize)
            try:
                ax.text(
                    0.5,
                    0.5,
                    "Aucune donnée",
                    transform=ax.transAxes,
                    ha="center",
                    va="center",
                    fontsize=14,
                    color="gray",
                )
                ax.set_title(title, fontsize=14, fontweight="bold")
                ax.axis("off")
                plt.tight_layout()
                if output_path is None:
                    fd, tmp = tempfile.mkstemp(suffix=".png")
                    os.close(fd)
                    output_path = Path(tmp)
                fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
            finally:
                plt.close(fig)
            return output_path

        # Extraire données X
        x_values = [row.get(x_column) for row in data]

        # Créer figure
        fig, ax = plt.subplots(figsize=self.figsize)
        try:
            # Tracer chaque série
            for i, y_col in enumerate(y_columns):
                y_values = [_safe_float(row.get(y_col, 0)) for row in data]
                ax.plot(
                    x_values,
                    y_values,
                    label=y_col,
                    color=self.colors[i % len(self.colors)],
                    linewidth=2,
                    marker="o",
                    markersize=5,
                )

            # Personnalisation
            ax.set_title(title, fontsize=14, fontweight="bold", pad=20)
            ax.set_xlabel(xlabel or x_column, fontsize=11)
            ax.set_ylabel(ylabel or "Valeurs", fontsize=11)
            ax.legend(loc="best", framealpha=0.9)
            ax.grid(True, alpha=0.3, linestyle="--")

            # Layout
            plt.tight_layout()

            # Sauvegarder
            if output_path is None:
                fd, tmp = tempfile.mkstemp(suffix=".png")
                os.close(fd)
                output_path = Path(tmp)

            fig.savefig(output_path, dpi=self.dpi, bbox_inches="tight", facecolor="white")
        finally:
            plt.close(fig)

        logger.info("Graphique multi-séries généré: %s", output_path)
        return output_path
