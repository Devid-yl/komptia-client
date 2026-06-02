"""
Service de rendu de templates emails avec Jinja2.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional
from jinja2 import Environment, FileSystemLoader, TemplateNotFound

logger = logging.getLogger(__name__)


class EmailTemplateRenderer:
    """
    Gestionnaire de rendu de templates emails avec Jinja2.

    Supporte les templates HTML et texte, avec variables dynamiques.
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialise le renderer avec le répertoire des templates.

        Args:
            templates_dir: Chemin vers le dossier templates/email/
                          Par défaut: BASE_DIR/templates/email/
        """
        if templates_dir is None:
            from app.config import config

            self.templates_dir = config.templates_dir / "email"
        else:
            self.templates_dir = Path(templates_dir)

        # Créer l'environnement Jinja2
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True,  # Sécurité XSS
            trim_blocks=True,
            lstrip_blocks=True,
        )

        logger.info("EmailTemplateRenderer initialisé: %s", self.templates_dir)

    def _enrich_with_branding(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Injecte ``company_name`` depuis le helper branding si non fourni.

        L'appelant peut toujours surcharger ``company_name`` dans son context
        (ex: tests). Si non fourni, on lit la valeur configurée via
        ``/admin/settings`` ; si rien n'est configuré, le helper renvoie
        ``"[Entreprise à configurer]"`` (placeholder visible). **Pas de
        hardcode** d'un nom particulier ici.
        """
        if "company_name" not in context:
            from app.services.branding import get_company_name

            enriched = dict(context)
            enriched["company_name"] = get_company_name()
            return enriched
        return context

    def render_html(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Rend un template HTML.

        Args:
            template_name: Nom du template (ex: 'rapport', 'alerte', 'resume')
            context: Variables à injecter dans le template. ``company_name`` est
                injecté automatiquement depuis la config admin si absent.

        Returns:
            HTML rendu en tant que string

        Raises:
            TemplateNotFound: Si le template n'existe pas
        """
        template_file = f"{template_name}.html"

        try:
            template = self.env.get_template(template_file)
            html = template.render(**self._enrich_with_branding(context))

            logger.debug("Template HTML rendu: %s", template_file)
            return html

        except TemplateNotFound:
            logger.error("Template introuvable: %s", template_file)
            raise
        except (OSError, ValueError, KeyError):
            logger.error("Erreur rendu template %s", template_file, exc_info=True)
            raise

    def render_text(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        Rend un template texte.

        Args:
            template_name: Nom du template (ex: 'rapport', 'alerte', 'resume')
            context: Variables à injecter dans le template. ``company_name`` est
                injecté automatiquement depuis la config admin si absent.

        Returns:
            Texte rendu en tant que string

        Raises:
            TemplateNotFound: Si le template n'existe pas
        """
        template_file = f"{template_name}.txt"

        try:
            template = self.env.get_template(template_file)
            text = template.render(**self._enrich_with_branding(context))

            logger.debug("Template texte rendu: %s", template_file)
            return text

        except TemplateNotFound:
            logger.error("Template introuvable: %s", template_file)
            raise
        except (OSError, ValueError, KeyError):
            logger.error("Erreur rendu template %s", template_file, exc_info=True)
            raise

    def render_both(self, template_name: str, context: Dict[str, Any]) -> tuple[str, str]:
        """
        Rend les deux versions (HTML et texte) d'un template.

        Args:
            template_name: Nom du template
            context: Variables à injecter

        Returns:
            Tuple (html, text)
        """
        html = self.render_html(template_name, context)
        text = self.render_text(template_name, context)

        return html, text

    def list_templates(self) -> list[str]:
        """
        Liste tous les templates disponibles.

        Returns:
            Liste des noms de templates (sans extension)
        """
        templates = set()

        if not self.templates_dir.exists():
            logger.warning("Répertoire templates inexistant: %s", self.templates_dir)
            return []

        try:
            for file in self.templates_dir.glob("*.html"):
                if file.name != "base.html":
                    templates.add(file.stem)
        except OSError:
            logger.error(
                "Erreur lecture répertoire templates: %s", self.templates_dir, exc_info=True
            )

        return sorted(list(templates))

    def validate_template(self, template_name: str) -> Dict[str, bool]:
        """
        Vérifie l'existence des versions HTML et texte d'un template.

        Args:
            template_name: Nom du template à valider

        Returns:
            Dict avec clés 'html' et 'text' (bool)
        """
        html_path = self.templates_dir / f"{template_name}.html"
        text_path = self.templates_dir / f"{template_name}.txt"

        return {"html": html_path.exists(), "text": text_path.exists()}


# Instance globale pour réutilisation
_renderer: Optional[EmailTemplateRenderer] = None


def get_renderer() -> EmailTemplateRenderer:
    """
    Retourne l'instance singleton du renderer.
    """
    global _renderer
    if _renderer is None:
        _renderer = EmailTemplateRenderer()
    return _renderer
