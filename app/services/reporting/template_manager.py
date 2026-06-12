"""
Gestionnaire de templates de rapports prédéfinis.
Charge et applique des templates JSON pour générer des rapports standardisés.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from app.core import clock
from app.services.reporting.number_format import format_number_preserving_nonzero
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Notation FR : "1 000 000" (espace milliers) → splits en 5 tokens au lieu de 3.
# Le pattern colle uniquement un espace situé entre un chiffre et un groupe
# d'EXACTEMENT 3 chiffres suivi d'un non-chiffre ou de la fin de chaîne
# (convention milliers FR stricte). Évite les faux positifs sur les
# identifiers terminés par un chiffre, ex: "col1 0 > 5" reste inchangé.
# `\s` matche aussi U+00A0 (no-break) et U+202F (narrow no-break).
_FR_NUMBER_RE = re.compile(r"(?<=\d)\s+(?=\d{3}(?:\D|$))")


class TemplateManager:
    """
    Gère les templates de rapports prédéfinis.

    Fonctionnalités:
    - Chargement templates depuis JSON
    - Validation structure template
    - Application template à génération PDF
    - Listing templates disponibles
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialise le gestionnaire de templates.

        Args:
            templates_dir: Répertoire contenant les templates JSON.
                          Par défaut: app/services/reporting/templates/
        """
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "templates"

        self.templates_dir = Path(templates_dir)
        self._templates_cache: Dict[str, Dict] = {}
        self._templates_mtime: Dict[str, float] = {}  # mtime du fichier au moment du cache

        logger.info("📂 TemplateManager initialisé: %s", self.templates_dir)

    def list_templates(self) -> List[Dict[str, Any]]:
        """
        Liste tous les templates disponibles avec métadonnées.

        Returns:
            Liste de dicts avec: id, name, description, category, icon
        """
        templates = []

        if not self.templates_dir.exists():
            logger.warning("Répertoire templates inexistant: %s", self.templates_dir)
            return templates

        for template_file in self.templates_dir.glob("*.json"):
            try:
                template = self.load_template(template_file.stem)
                templates.append(
                    {
                        "id": template["id"],
                        "name": template["name"],
                        "description": template["description"],
                        "category": template.get("category", "general"),
                        "icon": template.get("icon", "📄"),
                    }
                )
            except (OSError, json.JSONDecodeError, ValueError) as e:
                logger.error("Erreur chargement template %s: %s", template_file.name, e)

        # Tri par catégorie puis nom
        templates.sort(key=lambda t: (t["category"], t["name"]))

        logger.info("📋 %s templates chargés", len(templates))
        return templates

    def load_template(self, template_id: str) -> Dict[str, Any]:
        """
        Charge un template depuis le fichier JSON.

        Args:
            template_id: Identifiant du template (nom fichier sans .json)

        Returns:
            Dictionnaire avec la structure complète du template

        Raises:
            FileNotFoundError: Template introuvable
            json.JSONDecodeError: JSON invalide
            ValueError: Structure template invalide
        """
        # Valider template_id contre le path traversal
        if ".." in template_id or "/" in template_id or "\\" in template_id:
            raise ValueError("template_id invalide: caractères interdits")

        # Charger le fichier (besoin du path pour vérifier le mtime)
        template_path = self.templates_dir / f"{template_id}.json"

        # Double-check: le chemin résolu doit rester dans templates_dir
        if not template_path.resolve().is_relative_to(self.templates_dir.resolve()):
            raise ValueError("template_id invalide: chemin hors du répertoire autorisé")

        if not template_path.exists():
            raise FileNotFoundError(f"Template introuvable: {template_id}")

        # Vérifier le cache avec invalidation par mtime
        # (si le fichier a été modifié depuis la mise en cache, on recharge)
        current_mtime = template_path.stat().st_mtime
        if template_id in self._templates_cache:
            cached_mtime = self._templates_mtime.get(template_id, 0)
            if current_mtime <= cached_mtime:
                return self._templates_cache[template_id]
            logger.info("🔄 Template modifié, rechargement: %s", template_id)

        with open(template_path, "r", encoding="utf-8") as f:
            template = json.load(f)

        # Valider la structure
        self._validate_template(template)

        # Mettre en cache avec mtime
        self._templates_cache[template_id] = template
        self._templates_mtime[template_id] = current_mtime

        logger.info("✅ Template chargé: %s", template_id)
        return template

    def _validate_template(self, template: Dict[str, Any]) -> None:
        """
        Valide la structure d'un template.

        Args:
            template: Template à valider

        Raises:
            ValueError: Structure invalide
        """
        required_fields = ["id", "name", "description", "query", "columns", "metadata"]

        for field in required_fields:
            if field not in template:
                raise ValueError(f"Champ obligatoire manquant: {field}")

        # Valider query
        if "type" not in template["query"]:
            raise ValueError("query.type manquant")

        if template["query"]["type"] == "sql":
            if "sql" not in template["query"]:
                raise ValueError("query.sql manquant pour type=sql")

        # Valider columns (au moins 1)
        if not template["columns"]:
            raise ValueError("Au moins 1 colonne requise")

        for col in template["columns"]:
            if "name" not in col or "label" not in col:
                raise ValueError("Colonne invalide: name et label obligatoires")

    def get_template_query(self, template_id: str) -> str:
        """
        Récupère la requête SQL d'un template.

        Args:
            template_id: Identifiant du template

        Returns:
            Requête SQL
        """
        template = self.load_template(template_id)
        return template["query"]["sql"]

    def get_chart_config(self, template_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère la configuration graphique d'un template.

        Args:
            template_id: Identifiant du template

        Returns:
            Config graphique ou None si désactivé
        """
        template = self.load_template(template_id)
        chart = template.get("chart", {})

        if not chart.get("enabled", False):
            return None

        return chart

    def get_metadata(self, template_id: str) -> Dict[str, str]:
        """
        Récupère les métadonnées PDF d'un template.

        Args:
            template_id: Identifiant du template

        Returns:
            Dict avec title, description, author, subject
        """
        template = self.load_template(template_id)
        return template["metadata"]

    def get_column_labels(self, template_id: str) -> Dict[str, str]:
        """
        Récupère le mapping colonnes -> labels.

        Args:
            template_id: Identifiant du template

        Returns:
            Dict {column_name: label}
        """
        template = self.load_template(template_id)
        return {col["name"]: col["label"] for col in template["columns"]}

    def format_results(self, template_id: str, results: List[Dict]) -> List[Dict]:
        """
        Formate les résultats selon les specs du template.

        Args:
            template_id: Identifiant du template
            results: Résultats bruts de la requête

        Returns:
            Résultats formatés avec colonnes labellisées
        """
        template = self.load_template(template_id)
        formatted = []

        for row in results:
            formatted_row = {}

            for col in template["columns"]:
                col_name = col["name"]
                col_label = col["label"]
                value = row.get(col_name)

                # Appliquer formatage si spécifié
                if value is not None and "format" in col:
                    value = self._apply_format(value, col)

                formatted_row[col_label] = value

            formatted.append(formatted_row)

        return formatted

    def _apply_format(self, value: Any, col_config: Dict) -> str:
        """
        Applique le formatage d'une colonne.

        Args:
            value: Valeur brute
            col_config: Config colonne avec format

        Returns:
            Valeur formatée en string
        """
        format_type = col_config.get("format", "text")

        try:
            # #142 — SSoT anti-zéro-trompeur : un montant/pourcentage/décimal NON
            # NUL ne doit jamais s'afficher « 0.00 » (perte de donnée silencieuse
            # pour le lecteur). ``format_number_preserving_nonzero`` révèle le
            # premier chiffre significatif quand l'arrondi collapse en zéro.
            if format_type == "currency":
                suffix = col_config.get("suffix", " €")
                return f"{format_number_preserving_nonzero(float(value), 2, grouping=True)}{suffix}"

            elif format_type == "percentage":
                return f"{format_number_preserving_nonzero(float(value), 2)}%"

            elif format_type == "integer":
                return str(int(float(value)))

            elif format_type == "decimal":
                decimals = min(max(int(col_config.get("decimals", 2)), 0), 10)
                return format_number_preserving_nonzero(float(value), decimals)

            elif format_type == "date":
                if isinstance(value, str):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                # ``or`` (pas un simple défaut de .get) : un template qui met
                # explicitement format_string=null ou "" retombe sur le défaut
                # au lieu de propager None à strftime_fr (robustesse template).
                format_string = col_config.get("format_string") or "%d/%m/%Y"
                # strftime_fr : un format_string de template avec %B/%A (ex.
                # ca_mensuel.json : "%B %Y") doit rendre « juin 2026 », PAS
                # « June 2026 » — l'image prod (python:slim) n'a pas de locale
                # fr_FR. SSoT des noms FR : app.core.clock (zéro paquet locales).
                return clock.strftime_fr(value, format_string)

            else:  # text
                return str(value)
        except (ValueError, TypeError):
            logger.warning("Cannot format value %r as %s", value, format_type)
            return str(value)

    def get_aggregations(self, template_id: str) -> List[Dict[str, str]]:
        """
        Récupère les agrégations définies dans le template.

        Args:
            template_id: Identifiant du template

        Returns:
            Liste des agrégations avec column, operation, label
        """
        template = self.load_template(template_id)
        return template.get("aggregations", [])

    def get_alerts(self, template_id: str, results: List[Dict]) -> List[str]:
        """
        Évalue les conditions d'alerte et retourne les messages.

        Args:
            template_id: Identifiant du template
            results: Résultats de la requête

        Returns:
            Liste des messages d'alerte déclenchés
        """
        template = self.load_template(template_id)
        alerts_config = template.get("alerts", [])
        alerts = []

        for alert in alerts_config:
            condition = alert["condition"]

            # Parser une seule fois par condition (hors boucle row) pour éviter
            # un warning N fois par row sur condition mal formée, et pour signaler
            # même quand results est vide. Format attendu : "col OP value".
            parts = _FR_NUMBER_RE.sub("", condition).split()
            if len(parts) != 3:
                logger.warning(
                    "Condition d'alerte ignorée (format 'col OP value' attendu, "
                    "%d tokens trouvés): %r",
                    len(parts),
                    condition,
                )
                continue
            col_name, operator, threshold = parts

            # Évaluer la condition sur chaque ligne
            for row in results:
                try:
                    col_value = row.get(col_name)

                    if col_value is not None:
                        threshold_num = float(threshold)
                        col_num = float(col_value)

                        triggered = False
                        if operator == ">":
                            triggered = col_num > threshold_num
                        elif operator == ">=":
                            triggered = col_num >= threshold_num
                        elif operator == "<":
                            triggered = col_num < threshold_num
                        elif operator == "<=":
                            triggered = col_num <= threshold_num
                        elif operator == "==":
                            triggered = col_num == threshold_num

                        if triggered:
                            alerts.append(alert["message"])
                            break  # Une seule alerte par condition
                except (TypeError, ValueError):
                    logger.warning("Impossible d'évaluer condition: %s", condition)

        return list(set(alerts))  # Dédupliquer

    def clear_cache(self) -> None:
        """Vide le cache des templates."""
        self._templates_cache.clear()
        self._templates_mtime.clear()
        logger.info("🗑️ Cache templates vidé")

    async def generate_analysis(
        self,
        template_id: str,
        results: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> Optional[str]:
        """
        Génère une analyse IA pour les résultats d'un template

        Args:
            template_id: ID du template
            results: Résultats de la requête
            context: Contexte additionnel (période, etc.)
            user_id: identifiant utilisateur pour le proxy d'anonymisation
                (forwardé à ``ReportAnalyzer.analyze_data``). ``None`` pour
                appels système / batch — la couche PII regex s'applique
                quand même côté proxy.

        Returns:
            Texte d'analyse ou None si analyse désactivée
        """
        template = self.load_template(template_id)

        # Vérifier si l'analyse est activée pour ce template
        ai_config = template.get("ai_analysis", {})
        if not ai_config.get("enabled", False):
            logger.debug("Analyse IA désactivée pour template %s", template_id)
            return None

        # Importer ReportAnalyzer
        from app.services.reporting.report_analyzer import ReportAnalyzer

        # Créer l'analyseur
        analyzer = ReportAnalyzer()

        # Préparer le contexte
        analysis_context = context or {}
        analysis_context["template_name"] = template.get("name", template_id)

        # Générer l'analyse
        try:
            analysis = await analyzer.analyze_data(
                data=results,
                template_name=template.get("name", template_id),
                context=analysis_context,
                user_id=user_id,
            )
            logger.info("✅ Analyse générée pour %s", template_id)
            return analysis
        except (OSError, ValueError, KeyError) as e:
            logger.error("❌ Erreur génération analyse: %s", e, exc_info=True)
            return None
