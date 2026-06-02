"""
Module de génération de rapports
Fournit des outils pour générer des rapports PDF professionnels avec graphiques
"""

from app.services.reporting.pdf_generator import PDFGenerator
from app.services.reporting.template_manager import TemplateManager
from app.services.reporting.report_analyzer import ReportAnalyzer, AnalysisFormatter

__all__ = ["PDFGenerator", "TemplateManager", "ReportAnalyzer", "AnalysisFormatter"]

# Import optionnel de ChartBuilder (nécessite matplotlib)
try:
    from app.services.reporting.chart_builder import ChartBuilder

    __all__.append("ChartBuilder")
except ImportError:
    ChartBuilder = None
