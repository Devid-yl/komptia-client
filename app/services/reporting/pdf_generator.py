"""
Générateur de rapports PDF professionnels
Utilise ReportLab pour créer des PDFs formatés avec logo, tableaux et métadonnées
"""

from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer,
    PageBreak,
    Image,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from xml.sax.saxutils import escape as xml_escape

from app.core import clock
from app.services.reporting.number_format import format_number_preserving_nonzero
from app.utils.logger import get_logger

logger = get_logger(__name__)


class PDFGenerator:
    """Générateur de rapports PDF professionnels"""

    def __init__(
        self,
        logo_path: Optional[Path] = None,
        company_name: Optional[str] = None,
        pagesize=A4,
    ):
        """
        Initialise le générateur PDF

        Args:
            logo_path: Chemin vers le logo (optionnel)
            company_name: Nom de l'organisation. Si ``None``, lit la valeur
                configurée par l'admin via
                ``app.services.branding.get_company_name()`` (axe 6 :
                généricité, pas de hardcode d'un nom particulier).
            pagesize: Taille de page (A4 par défaut)
        """
        self.logo_path = logo_path
        if company_name is None:
            from app.services.branding import get_company_name

            company_name = get_company_name()
        self.company_name = company_name
        self.pagesize = pagesize
        self.styles = getSampleStyleSheet()

        # Styles personnalisés
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Crée des styles personnalisés pour le document"""
        # Titre principal
        self.styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=self.styles["Heading1"],
                fontSize=18,
                textColor=colors.HexColor("#2c3e50"),
                spaceAfter=20,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )
        )

        # Sous-titre
        self.styles.add(
            ParagraphStyle(
                name="CustomSubtitle",
                parent=self.styles["Heading2"],
                fontSize=12,
                textColor=colors.HexColor("#7f8c8d"),
                spaceAfter=10,
                alignment=TA_CENTER,
            )
        )

        # En-tête
        self.styles.add(
            ParagraphStyle(
                name="Header",
                parent=self.styles["Normal"],
                fontSize=10,
                textColor=colors.HexColor("#95a5a6"),
                alignment=TA_RIGHT,
            )
        )

        # Pied de page
        self.styles.add(
            ParagraphStyle(
                name="Footer",
                parent=self.styles["Normal"],
                fontSize=8,
                textColor=colors.HexColor("#95a5a6"),
                alignment=TA_CENTER,
            )
        )

    def generate_from_query_result(
        self,
        output_path: Path,
        title: str,
        results: List[Dict[str, Any]],
        metadata: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        include_chart: bool = False,
        chart_config: Optional[Dict[str, Any]] = None,
        include_analysis: bool = False,
        analysis_text: Optional[str] = None,
    ) -> Path:
        """
        Génère un PDF depuis des résultats de requête

        Args:
            output_path: Chemin du fichier PDF à créer
            title: Titre du rapport
            results: Liste de dictionnaires (résultats de requête)
            metadata: Métadonnées PDF (auteur, sujet, etc.)
            description: Description optionnelle du rapport
            include_chart: Inclure un graphique
            chart_config: Configuration du graphique (x_column, y_column, chart_type, etc.)
            include_analysis: Inclure une analyse IA
            analysis_text: Texte d'analyse (généré si None)

        Returns:
            Chemin du fichier généré
        """
        logger.info("📄 Génération PDF: %s", title)

        # Reset temp chart paths at start of generation
        self._temp_chart_paths = []

        # Créer le document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=self.pagesize,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=title,
            author=metadata.get("author", self.company_name) if metadata else self.company_name,
            subject=(
                metadata.get("subject", "Rapport automatisé") if metadata else "Rapport automatisé"
            ),
        )

        # Construire le contenu
        story = []

        # En-tête avec logo
        story.extend(self._build_header(title, description))

        # Analyse IA (avant le graphique si demandée)
        if include_analysis and analysis_text:
            self.add_analysis_section(story, analysis_text)

        # Graphique (si demandé)
        if include_chart and results and chart_config:
            story.append(Spacer(1, 0.5 * cm))
            chart_path = self._build_chart(results, chart_config)
            if chart_path:
                story.append(chart_path)
                story.append(Spacer(1, 0.5 * cm))

        # Tableau de données
        if results:
            story.append(Spacer(1, 0.5 * cm))
            story.extend(self._build_table(results))
        else:
            story.append(Paragraph("Aucun résultat", self.styles["Normal"]))

        # Pied de page
        story.append(Spacer(1, 1 * cm))
        story.extend(self._build_footer())

        # Générer le PDF
        try:
            doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        finally:
            # Nettoyer les PNG chart temporaires MÊME si ``build()`` lève
            # (erreur de layout ReportLab, image corrompue, OOM sur gros
            # tableau…) : sinon les PNG restent sur disque → fuite + croissance
            # non bornée sur échecs répétés. Même pattern try/finally que
            # report_storage.save_report (cleanup orphelin).
            for temp_path in getattr(self, "_temp_chart_paths", []):
                try:
                    Path(temp_path).unlink(missing_ok=True)
                except OSError:
                    pass

        logger.info("✅ PDF généré: %s", output_path)
        return output_path

    def _render_chart_image(
        self, chart_config: Dict[str, Any], fallback_data: List[Dict[str, Any]]
    ) -> Optional[Image]:
        """Route chart config to the appropriate renderer.

        Preferred format (LLM-generated, pre-aggregated):
            {type: "bar", bars: [...]} | {type: "line", series: [...]} | {type: "pie", slices: [...]}

        Legacy format (x/y columns, raw data):
            {chart_type, x_column, y_column, title}
        """
        # Detect pre-aggregated format by presence of bars/series/slices
        is_aggregated = any(k in chart_config for k in ("bars", "series", "slices"))

        if is_aggregated:
            try:
                from app.services.reporting.aggregated_chart_renderer import (
                    render_aggregated_chart,
                )
            except ImportError:
                return None
            chart_path = render_aggregated_chart(chart_config)
            if chart_path is None:
                return None
            img = Image(str(chart_path), width=15 * cm, height=9 * cm)
            if not hasattr(self, "_temp_chart_paths"):
                self._temp_chart_paths = []
            self._temp_chart_paths.append(chart_path)
            return img

        # Legacy path
        return self._build_chart(fallback_data, chart_config)

    def _build_chart(
        self, results: List[Dict[str, Any]], chart_config: Dict[str, Any]
    ) -> Optional[Image]:
        """
        Construit un graphique et retourne l'objet Image pour le PDF

        Args:
            results: Données pour le graphique
            chart_config: Configuration (x_column, y_column, chart_type, title, etc.)

        Returns:
            Objet Image ReportLab ou None si erreur
        """
        try:
            from app.services.reporting.chart_builder import ChartBuilder

            # Créer le constructeur
            chart_builder = ChartBuilder(dpi=150, figsize=(8, 5))

            # Extraire config
            x_column = chart_config.get("x_column")
            y_column = chart_config.get("y_column")
            chart_type = chart_config.get("chart_type", "auto")
            chart_title = chart_config.get("title", "Graphique")
            xlabel = chart_config.get("xlabel")
            ylabel = chart_config.get("ylabel")

            if not x_column or not y_column:
                logger.warning("Configuration graphique incomplète (x_column ou y_column manquant)")
                return None

            # Générer le graphique
            chart_path = chart_builder.create_chart(
                data=results,
                x_column=x_column,
                y_column=y_column,
                chart_type=chart_type,
                title=chart_title,
                xlabel=xlabel,
                ylabel=ylabel,
            )

            # Créer objet Image pour PDF
            img = Image(str(chart_path), width=15 * cm, height=9 * cm)

            # Stocker le chemin temp pour nettoyage après doc.build()
            if not hasattr(self, "_temp_chart_paths"):
                self._temp_chart_paths = []
            self._temp_chart_paths.append(chart_path)

            return img

        except (ValueError, OSError, RuntimeError) as e:
            logger.error("Erreur génération graphique: %s", e, exc_info=True)
            return None

    def _build_header(self, title: str, description: Optional[str] = None) -> List:
        """Construit l'en-tête du document"""
        elements = []

        # Logo (si disponible)
        if self.logo_path and self.logo_path.exists():
            try:
                logo = Image(str(self.logo_path), width=3 * cm, height=3 * cm)
                elements.append(logo)
                elements.append(Spacer(1, 0.3 * cm))
            except (OSError, ValueError) as e:
                logger.warning("Impossible de charger le logo: %s", e)

        # Nom de l'organisation
        elements.append(Paragraph(xml_escape(self.company_name), self.styles["CustomSubtitle"]))
        elements.append(Spacer(1, 0.2 * cm))

        # Titre principal
        elements.append(Paragraph(xml_escape(title), self.styles["CustomTitle"]))

        # Description (optionnelle)
        if description:
            elements.append(Spacer(1, 0.2 * cm))
            elements.append(Paragraph(xml_escape(description), self.styles["Normal"]))

        # Date de génération — heure SERVEUR (config.server.timezone) : un PDF est
        # une sortie backend (pas de navigateur pour convertir), cf. doctrine
        # d'affichage. clock.now_local() applique machine_tz (SSoT), au lieu de
        # clock.now() qui rendait l'UTC brut (+4h pour America/Guadeloupe).
        date_str = clock.now_local().strftime("%d/%m/%Y à %H:%M")
        elements.append(Spacer(1, 0.3 * cm))
        elements.append(Paragraph(f"<i>Généré le {date_str}</i>", self.styles["CustomSubtitle"]))

        return elements

    def _build_table(self, results: List[Dict[str, Any]]) -> List:
        """Construit un tableau formaté depuis les résultats"""
        if not results:
            return []

        elements = []

        # Extraire colonnes : union ordonnée (ordre de première apparition).
        # Préserve l'ordre SQL standard quand les lignes sont homogènes et
        # tolère l'hétérogénéité (CASE WHEN, UNION ALL, JSON_*, drivers qui
        # omettent les colonnes NULL sur la 1ère ligne) sans perdre de clés.
        seen: set = set()
        columns: List[str] = []
        for row in results:
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    columns.append(k)

        # Signaler le seul COMPTE de clés ajoutées après la 1ère ligne
        # (axe 5 CLAUDE.md : erreurs silencieuses doivent laisser une trace).
        # On NE LOGUE PAS les noms de colonnes : ils peuvent être PII-adjacent
        # (ex. `nom_client`, `dossier_<entite>`) et `komptia.log` a 30j de
        # rétention + handler console — confidentialité multi-niveaux.
        first_row_keys = set(results[0].keys())
        extra_count = sum(1 for k in columns if k not in first_row_keys)
        if extra_count:
            logger.warning(
                "_build_table : %d cle(s) absentes de la 1ere ligne mais "
                "presentes dans des lignes ulterieures (heterogeneite SQL)",
                extra_count,
            )

        # Préparer données pour le tableau
        data = [columns]  # En-tête

        for row in results:
            data.append([self._format_cell_value(row.get(col)) for col in columns])

        # Calculer largeurs colonnes
        num_cols = len(columns)
        available_width = self.pagesize[0] - 4 * cm  # Marges
        col_width = available_width / num_cols

        # Limiter hauteur des lignes
        max_rows_per_page = 35
        if len(data) > max_rows_per_page:
            # Diviser en plusieurs pages
            for i in range(0, len(data), max_rows_per_page):
                chunk = data[i : i + max_rows_per_page]
                if i > 0:
                    # Répéter l'en-tête
                    chunk = [data[0]] + chunk

                table = self._create_table(chunk, col_width, num_cols)
                elements.append(table)

                if i + max_rows_per_page < len(data):
                    elements.append(PageBreak())
        else:
            table = self._create_table(data, col_width, num_cols)
            elements.append(table)

        # Statistiques
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"<b>Total:</b> {len(results)} ligne(s)", self.styles["Normal"]))

        return elements

    def _create_table(self, data: List[List[str]], col_width: float, num_cols: int) -> Table:
        """Crée un tableau avec style"""
        table = Table(
            data, colWidths=[col_width] * num_cols, repeatRows=1  # Répéter en-tête sur chaque page
        )

        # Style du tableau
        table.setStyle(
            TableStyle(
                [
                    # En-tête
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#366092")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    # Corps
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.black),
                    ("ALIGN", (0, 1), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("TOPPADDING", (0, 1), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
                    # Alternance couleurs lignes
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8f9fa")],
                    ),
                    # Bordures
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
                    ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#366092")),
                ]
            )
        )

        return table

    def _format_cell_value(self, value: Any) -> str:
        """Formate une valeur de cellule pour affichage"""
        if value is None:
            return ""

        if isinstance(value, datetime):
            return value.strftime("%d/%m/%Y %H:%M")

        if isinstance(value, float):
            # Formatter avec 2 décimales si nombre décimal
            if value % 1 == 0:
                return str(int(value))
            # #142 — SSoT anti-zéro-trompeur : un non-zéro ne doit JAMAIS s'afficher
            # « 0.00 » (perte de donnée silencieuse pour le lecteur du PDF).
            return format_number_preserving_nonzero(value, 2)

        return str(value)

    def _build_footer(self) -> List:
        """Construit le pied de page"""
        elements = []

        # Ligne de séparation
        from reportlab.platypus import HRFlowable

        elements.append(
            HRFlowable(
                width="100%",
                thickness=1,
                color=colors.HexColor("#dee2e6"),
                spaceBefore=0.3 * cm,
                spaceAfter=0.3 * cm,
            )
        )

        # Texte pied de page
        elements.append(
            Paragraph(
                f"<i>Rapport généré automatiquement par {xml_escape(self.company_name)}</i>",
                self.styles["Footer"],
            )
        )

        return elements

    def _add_page_number(self, canvas, doc):
        """Ajoute numérotation des pages"""
        canvas.saveState()

        # Numéro de page
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"

        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.HexColor("#95a5a6"))
        canvas.drawRightString(doc.pagesize[0] - 2 * cm, 1.5 * cm, text)

        canvas.restoreState()

    def generate_multi_section_report(
        self,
        output_path: Path,
        title: str,
        sections: List[Dict[str, Any]],
        metadata: Optional[Dict[str, str]] = None,
        introduction: Optional[str] = None,
    ) -> Path:
        """
        Génère un PDF avec plusieurs sections.

        Chaque section peut contenir (tous optionnels sauf title) :
            - title: str
            - description: str (court paragraphe)
            - data: list[dict] (tableau)
            - charts: list[dict] (chaque dict: {x_column, y_column, chart_type?, title?})
            - commentary: str (analyse/narration après le tableau et les graphiques)

        Args:
            output_path: Chemin du fichier PDF
            title: Titre du rapport
            sections: Liste de sections (voir schéma ci-dessus)
            metadata: Métadonnées PDF
            introduction: Paragraphe d'introduction affiché après l'en-tête

        Returns:
            Chemin du fichier généré

        Rétro-compatibilité : les sections avec seulement {title, description, data}
        continuent de fonctionner sans modification.
        """
        logger.info("📄 Génération PDF multi-sections: %s", title)

        # Reset temp chart paths at start of generation
        self._temp_chart_paths = []

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=self.pagesize,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=title,
            author=metadata.get("author", self.company_name) if metadata else self.company_name,
        )

        story = []

        # En-tête principal
        story.extend(self._build_header(title))

        # Introduction globale (optionnel)
        if introduction:
            story.append(Spacer(1, 0.3 * cm))
            for para in introduction.split("\n\n"):
                if para.strip():
                    story.append(Paragraph(xml_escape(para.strip()), self.styles["Normal"]))
                    story.append(Spacer(1, 0.2 * cm))

        # Chaque section
        for i, section in enumerate(sections):
            if i > 0:
                story.append(PageBreak())

            story.append(Spacer(1, 0.5 * cm))
            story.append(
                Paragraph(
                    xml_escape(section.get("title", f"Section {i + 1}")),
                    self.styles["Heading2"],
                )
            )

            if section.get("description"):
                # Split sur \n\n (parité avec introduction/commentary) : sinon
                # une note ajoutée en fin de description (ex. marqueur #87
                # « N graphiques non affichés ») se collait inline au texte au
                # lieu d'apparaître sur sa propre ligne.
                for para in str(section["description"]).split("\n\n"):
                    if para.strip():
                        story.append(Paragraph(xml_escape(para.strip()), self.styles["Normal"]))
                        story.append(Spacer(1, 0.2 * cm))

            story.append(Spacer(1, 0.3 * cm))

            # Table de données (optionnel — `data` affiche un tableau brut)
            if section.get("data"):
                story.extend(self._build_table(section["data"]))

            # Graphiques (0, 1 ou plusieurs par section)
            # Deux formats acceptés pour chaque chart_cfg :
            #   - Pré-agrégé (nouveau — préféré) : {type, bars|series|slices}
            #     Le LLM fournit les données finales déjà groupées/sommées.
            #   - Data-driven (legacy) : {chart_type, x_column, y_column}
            #     Fallback vers ChartBuilder avec données brutes.
            charts = section.get("charts") or []
            chart_source = section.get("chart_data") or section.get("data") or []
            for chart_cfg in charts:
                if not isinstance(chart_cfg, dict):
                    continue
                img = self._render_chart_image(chart_cfg, chart_source)
                if img is not None:
                    story.append(Spacer(1, 0.4 * cm))
                    chart_title = chart_cfg.get("title")
                    if chart_title:
                        story.append(Paragraph(xml_escape(chart_title), self.styles["Heading3"]))
                    story.append(img)

            # Commentaire / analyse de la section
            commentary = section.get("commentary")
            if commentary:
                story.append(Spacer(1, 0.4 * cm))
                for para in commentary.split("\n\n"):
                    if para.strip():
                        story.append(Paragraph(xml_escape(para.strip()), self.styles["Normal"]))
                        story.append(Spacer(1, 0.2 * cm))

        # Pied de page
        story.append(Spacer(1, 1 * cm))
        story.extend(self._build_footer())

        try:
            doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        finally:
            # Cleanup temp chart PNG MÊME si ``build()`` lève (anti-fuite disque
            # / croissance non bornée). Cf. méthode chart-based ci-dessus +
            # report_storage.save_report pour le même pattern try/finally.
            for chart_path in self._temp_chart_paths:
                try:
                    Path(chart_path).unlink(missing_ok=True)
                except OSError:
                    pass
            self._temp_chart_paths = []

        logger.info("✅ PDF multi-sections généré: %s", output_path)
        return output_path

    def add_analysis_section(
        self, story: List, analysis_text: str, title: str = "Analyse des données"
    ) -> None:
        """
        Ajoute une section d'analyse IA au document

        Args:
            story: Liste d'éléments du document (modifiée en place)
            analysis_text: Texte d'analyse généré
            title: Titre de la section
        """
        logger.info("📝 Ajout section analyse: %s", title)

        # Style pour le cadre d'analyse
        if "AnalysisText" not in self.styles:
            self.styles.add(
                ParagraphStyle(
                    name="AnalysisText",
                    parent=self.styles["Normal"],
                    fontSize=10,
                    leading=14,
                    alignment=TA_LEFT,
                    spaceAfter=10,
                    leftIndent=0.5 * cm,
                    rightIndent=0.5 * cm,
                    textColor=colors.HexColor("#2c3e50"),
                )
            )
        analysis_style = self.styles["AnalysisText"]

        # Ajouter espacement
        story.append(Spacer(1, 0.8 * cm))

        # Titre de la section — échappé (ReportLab parse le markup ; un `&`/`<`
        # dans un titre customisé casserait le rendu, cf. xml_escape ailleurs).
        story.append(Paragraph(xml_escape(title), self.styles["Heading2"]))
        story.append(Spacer(1, 0.3 * cm))

        # Diviser le texte en paragraphes
        paragraphs = analysis_text.split("\n\n")

        for para in paragraphs:
            if para.strip():
                # Nettoyer et échapper le texte (ReportLab parse HTML dans Paragraph)
                clean_text = xml_escape(para.strip().replace("\n", " "))

                # Créer le paragraphe
                p = Paragraph(clean_text, analysis_style)
                story.append(p)
                story.append(Spacer(1, 0.2 * cm))

        logger.debug("✅ Section analyse ajoutée (%s paragraphes)", len(paragraphs))
