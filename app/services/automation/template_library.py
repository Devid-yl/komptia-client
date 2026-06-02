"""
Bibliotheque de templates d'automatisation (Phase 3d).

Templates = des automatisations pre-faites livrees avec Komptia, que
l'utilisateur peut "instancier" (cloner) pour demarrer un nouveau workflow
sans partir de zero.

Pattern : filesystem-based (calque sur ``app/services/reporting/template_manager.py``).
Pas de table BDD — les templates vivent dans ``app/services/automation/templates/``
et sont versiones avec le code (donc identiques pour tous les utilisateurs, et
embarques automatiquement dans l'image client via ``COPY app/`` / rsync ``/app/***``).

Format : JSON v2 du systeme d'export Komptia (cf. ``AutomationExportHandler``)
enrichi d'un bloc ``template_meta`` pour la galerie (id, label, description,
category, icon, difficulty). Le bloc ``automation`` + ``steps`` + ``edges``
reste compatible avec ``AutomationImportHandler._validate_import``.

Securite :
* Path traversal : validation regex ``[a-zA-Z0-9_-]+`` + double-check
  ``Path.resolve().is_relative_to`` (defense-in-depth).
* Cache mtime : invalide auto si le fichier change sur disque (utile en
  developpement).
* Read-only : ce service ne fait QUE lire — aucune ecriture, aucune
  suppression. Pas de surface admin a securiser.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Identifiants de template : alphanumerique + tirets/underscores uniquement.
# Empeche path traversal (`..`, `/`, `\`) et caracteres NULL/ctrl.
_VALID_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


class TemplateNotFoundError(Exception):
    """Levee quand un template_id n'existe pas (ou path traversal detecte)."""


class TemplateInvalidError(Exception):
    """Levee quand un template JSON ne respecte pas le format attendu."""


class AutomationTemplateLibrary:
    """Lit les templates JSON d'automatisation depuis le filesystem.

    Cache en memoire avec invalidation par ``mtime`` du fichier.

    Usage::

        lib = AutomationTemplateLibrary()
        for tpl in lib.list_templates():
            print(tpl["id"], tpl["label"])
        full = lib.load_template("01_extract_email_simple")
        # full["automation"], full["steps"], full["edges"], full["template_meta"]
    """

    # Champs minimaux requis dans `template_meta`.
    _META_REQUIRED: tuple[str, ...] = ("id", "label", "description")
    _META_ALLOWED: frozenset[str] = frozenset(
        {"id", "label", "description", "category", "icon", "difficulty"}
    )

    def __init__(self, templates_dir: Optional[Path] = None) -> None:
        if templates_dir is None:
            # Default : `app/services/automation/templates/` — SOUS ``app/`` (et
            # non ``data/``) à dessein. ``data/`` est exclu de l'image Docker
            # ET masqué au runtime par le volume nommé ``komptia-data`` (vide
            # sur un client neuf) → des templates rangés là seraient invisibles
            # en prod (galerie vide silencieuse). Sous ``app/`` ils sont
            # embarqués automatiquement (``COPY app/`` + rsync ``/app/***``),
            # comme les templates de ``reporting/template_manager.py``.
            templates_dir = Path(__file__).resolve().parent / "templates"
        self.templates_dir = Path(templates_dir)
        # Cache : id → (parsed_dict, mtime_at_cache_time)
        self._cache: Dict[str, tuple[Dict[str, Any], float]] = {}
        logger.info(
            "AutomationTemplateLibrary initialise (dir=%s, exists=%s)",
            self.templates_dir,
            self.templates_dir.exists(),
        )

    # ─────────────────────────────────────────────────────────────
    # Lecture publique
    # ─────────────────────────────────────────────────────────────

    def list_templates(self) -> List[Dict[str, Any]]:
        """Liste tous les templates disponibles (metadonnees galerie).

        Renvoie une liste triee par ``category`` puis ``label``. Chaque entree
        contient le bloc ``template_meta`` du fichier (id, label, description,
        category, icon, difficulty), pas le payload complet.

        Phase 3d : un flag ``available`` indique si le template est
        instanciable (passe ``_validate_import`` complet). Les seeds qui
        echouent la validation reapparaissent en galerie avec ce flag a
        False et un ``unavailable_reason`` pour debug — le frontend peut
        les griser. Cette pre-validation evite qu'un user clique
        "Utiliser" puis recoive un 500 sans diagnostic.

        Les fichiers JSON invalides au niveau schema (template_meta
        manquant) sont eux logges et silencieusement skippes — pas de
        candidat dans la galerie.
        """
        results: List[Dict[str, Any]] = []
        if not self.templates_dir.exists():
            logger.warning("Repertoire templates inexistant : %s", self.templates_dir)
            return results

        for path in sorted(self.templates_dir.glob("*.json")):
            template_id = path.stem
            if not _VALID_ID_RE.match(template_id):
                logger.warning("Template ignore (id invalide) : %s", path.name)
                continue
            try:
                full = self.load_template(template_id)
            except (TemplateInvalidError, OSError, json.JSONDecodeError) as e:
                logger.warning("Template ignore (invalide) : %s — %s", path.name, e)
                continue

            # Pre-validation _validate_import : si un seed a un format
            # invalide qui n'est pas detecte par _validate_payload (ex:
            # type d'etape retire, cron expression cassee), on le marque
            # available=False plutot que de laisser un 500 a l'utilisateur.
            available = True
            unavailable_reason: Optional[str] = None
            try:
                self._dry_validate_import(full)
            except ValueError as e:
                available = False
                unavailable_reason = str(e)
                logger.warning(
                    "Template %s pre-validation echouee : %s",
                    template_id,
                    e,
                )
            except Exception as e:  # noqa: BLE001
                # Garde-fou : un import handler en travaux pourrait throw
                # autre chose. On ne casse pas la galerie pour autant.
                available = False
                unavailable_reason = "Pre-validation incomplete"
                logger.error(
                    "Template %s pre-validation crash : %s",
                    template_id,
                    e,
                    exc_info=True,
                )

            meta = full.get("template_meta", {})
            entry = {
                "id": meta.get("id", template_id),
                "label": meta.get("label", template_id),
                "description": meta.get("description", ""),
                "category": meta.get("category", "general"),
                "icon": meta.get("icon", "diagram-3"),
                "difficulty": meta.get("difficulty", "facile"),
                "step_count": len(full.get("steps") or []),
                "edge_count": len(full.get("edges") or []),
                "available": available,
            }
            if unavailable_reason:
                entry["unavailable_reason"] = unavailable_reason
            results.append(entry)

        results.sort(key=lambda t: (not t.get("available", True), t["category"], t["label"]))
        return results

    @staticmethod
    def _dry_validate_import(payload: Dict[str, Any]) -> None:
        """Lance la validation d'import (regles completes) sans muter la BDD.

        Importe tardivement pour eviter le cycle ``handlers → services``.
        Phase 3d : appelle directement la fonction module-level
        ``validate_automation_payload`` (extraite du handler pour ce
        usage exact).
        """
        from app.handlers.automations import validate_automation_payload

        validate_automation_payload(payload)

    def load_template(self, template_id: str) -> Dict[str, Any]:
        """Charge un template par son id (nom de fichier sans .json).

        Renvoie le payload complet (komptia_export, template_meta, automation,
        steps, edges) — pret a etre passe a ``AutomationImportHandler.
        _validate_import`` apres extraction de ``payload["automation"]``.

        Leve :
            * ``TemplateNotFoundError`` : id absent ou path traversal detecte.
            * ``TemplateInvalidError`` : JSON invalide ou structure non
              conforme au schema attendu.
        """
        if not isinstance(template_id, str) or not template_id:
            raise TemplateNotFoundError("template_id manquant")

        # Validation regex stricte. ".." et "/" deja exclus de [a-zA-Z0-9_-].
        if not _VALID_ID_RE.match(template_id):
            raise TemplateNotFoundError(f"template_id invalide : {template_id!r}")

        path = self.templates_dir / f"{template_id}.json"

        # Defense-in-depth : meme si la regex ci-dessus est correcte, on
        # verifie que le path resolu reste dans le repertoire autorise.
        # `Path.is_relative_to` (3.9+) leve ValueError si on est hors du
        # base — plus robuste que `str.startswith` qui matchait
        # faussement les dirs voisins (ex: `/data/templates/x.json` vs
        # `/data/templates_evil/x.json` partagent le prefix). On suit
        # aussi les symlinks via .resolve(strict=False).
        try:
            resolved = path.resolve()
            base = self.templates_dir.resolve()
        except (OSError, RuntimeError) as e:
            raise TemplateNotFoundError(f"path resolution echoue : {e}") from e
        try:
            resolved.relative_to(base)
        except ValueError as e:
            raise TemplateNotFoundError(
                f"template_id hors du repertoire autorise : {template_id!r}"
            ) from e

        if not path.exists():
            raise TemplateNotFoundError(f"template introuvable : {template_id}")

        # Cache check par mtime
        current_mtime = path.stat().st_mtime
        if template_id in self._cache:
            cached, cached_mtime = self._cache[template_id]
            if current_mtime <= cached_mtime:
                return cached

        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except json.JSONDecodeError as e:
            raise TemplateInvalidError(f"JSON invalide : {e}") from e

        self._validate_payload(payload, template_id)
        self._cache[template_id] = (payload, current_mtime)
        return payload

    # ─────────────────────────────────────────────────────────────
    # Validation
    # ─────────────────────────────────────────────────────────────

    def _validate_payload(self, payload: Any, template_id: str) -> None:
        """Verifie le schema minimal. Ne refait PAS la validation complete
        (deleguee a ``AutomationImportHandler._validate_import`` au moment de
        l'instanciation) — on ne fait que verifier que l'enveloppe est
        coherente pour eviter qu'un fichier corrompu casse la galerie.
        """
        if not isinstance(payload, dict):
            raise TemplateInvalidError("Le template doit etre un objet JSON")

        meta = payload.get("komptia_export")
        if not isinstance(meta, dict) or meta.get("type") != "automation":
            raise TemplateInvalidError("Bloc komptia_export manquant ou type != 'automation'")

        version = meta.get("version", 1)
        if version not in (1, 2):
            raise TemplateInvalidError(f"Version d'export non supportee : {version}")

        tpl_meta = payload.get("template_meta")
        if not isinstance(tpl_meta, dict):
            raise TemplateInvalidError("Bloc template_meta manquant")
        for required in self._META_REQUIRED:
            if not tpl_meta.get(required):
                raise TemplateInvalidError(f"template_meta.{required} manquant ou vide")
        # Coherence id template_meta vs nom de fichier.
        meta_id = tpl_meta.get("id")
        if meta_id != template_id:
            raise TemplateInvalidError(f"template_meta.id ({meta_id}) != filename ({template_id})")
        # Refuse les cles inconnues pour eviter les pollutions.
        unknown = set(tpl_meta.keys()) - self._META_ALLOWED
        if unknown:
            raise TemplateInvalidError(f"Cles template_meta inconnues : {sorted(unknown)}")

        if not isinstance(payload.get("automation"), dict):
            raise TemplateInvalidError("Bloc automation manquant")
        if not isinstance(payload.get("steps"), list):
            raise TemplateInvalidError("Bloc steps doit etre une liste")
        if not isinstance(payload.get("edges", []), list):
            raise TemplateInvalidError("Bloc edges doit etre une liste")


# Instance globale partagee. Lazy : creee au premier import par les handlers.
_default_library: Optional[AutomationTemplateLibrary] = None


def get_template_library() -> AutomationTemplateLibrary:
    """Renvoie la singleton globale (lazy-init au 1er appel)."""
    global _default_library
    if _default_library is None:
        _default_library = AutomationTemplateLibrary()
    return _default_library
