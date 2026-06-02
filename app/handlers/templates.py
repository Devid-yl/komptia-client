"""Handlers HTTP pour les templates de rapports prédéfinis.

Trois endpoints en lecture seule (pas de mutation — les templates sont
gérés côté filesystem, hors portée de l'API) :

* ``GET /api/templates``              — liste des templates avec métadonnées
* ``GET /api/templates/<id>``         — détail (``query.sql`` masquée)
* ``GET /api/templates/<id>/preview`` — prévisualisation avec N lignes bidon

Garanties senior (OWASP API Top 10 2023 + ASVS v5 + CLAUDE.md)
--------------------------------------------------------------
1. **Fail-closed authz** — :class:`AuthenticatedHandler` rejette en
   ``prepare`` (401 JSON pour ``/api/`` / redirect login HTML). Aucun
   check ``if not user: ...`` inline. Cohérent avec le pattern établi
   dans ``findings/GLOBAL_FINDINGS.md`` (pattern ``[DUP] Auth manuelle``).
2. **Anti-information-disclosure (CWE-200)** — :func:`_safe_template_view`
   ne renvoie **jamais** le champ ``query.sql`` qui exposerait la
   structure de la BDD source (Sage Coala ou autre) à un utilisateur non
   admin. Allowlist explicite de champs exposés (pas de ``{k:v for k,v
   in template.items() if k != 'query'}`` qui est fail-open sur un futur
   ajout de champ sensible).
3. **Path traversal** — triple défense :
   a) regex de route ``[a-z0-9_]+`` (whitelist stricte côté Tornado) ;
   b) rejet de ``..``/``/``/``\\`` dans :class:`TemplateManager` ;
   c) ``resolve().is_relative_to(templates_dir)`` côté service.
   Un ``ValueError`` côté service est remappé en **404** par ce handler
   (anti-oracle — pas de distinction publique entre « n'existe pas » et
   « nom interdit »).
4. **Rate-limiting (API4:2023 Unrestricted Resource Consumption)** —
   60 lectures/min/user via :class:`RateLimiter`. Les endpoints lisent
   des fichiers + parsent du JSON ; un script en boucle (bug UI,
   crawler) pourrait saturer l'I/O disque sans ce garde-fou. Le coût
   est trivial pour un usage humain normal (< 10/min).
5. **Erreurs déterministes (CWE-209)** — aucun ``str(exception)`` au
   client ; tous les messages sont des ``Final[str]`` centralisés dans
   :class:`_Messages`. Les erreurs lèvent ``HTTPError`` et transitent
   par :meth:`BaseHandler.write_error` pour un shape uniforme
   ``{error, status, message, request_id}`` — aligné sur
   ``saved_queries.py`` et ``reports.py``.
6. **Cache partagé, singleton module-level** — un unique
   :class:`TemplateManager` est instancié une fois à l'import et
   partagé entre les 3 handlers. Avant cette refonte, chaque requête
   créait une instance fraîche (cache vide → file read systématique).
   En Tornado single-thread event-loop, aucune race sur le dict cache
   (GIL garantit l'atomicité des opérations ``dict[k] = v`` ; pas de
   ``yield`` entre lecture et écriture de cache).
7. **Sample data déterministe** — :func:`_generate_sample_data` est
   pur et testable hors handler ; pas de bug de zero-padding pour
   ``i ≥ 9`` (``{month:02d}`` au lieu de ``"0{i+1}"``) ; valeurs
   choisies pour rendre visible le formatage du template (séparateurs
   milliers, décimales, suffixe devise).
8. **Réponse JSON UTF-8** — :meth:`BaseHandler.write_json` utilise
   ``ensure_ascii=False``, préservant les caractères accentués des
   descriptions FR sans les échapper en ``\\uXXXX``.
"""

from __future__ import annotations

from typing import Any, Final

import tornado.web

from app.handlers.base import AuthenticatedHandler
from app.services.reporting.template_manager import TemplateManager
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ════════════════════════════════════════════════════════════════════════
# Constantes (toutes ``Final`` + justification — pas de magic numbers)
# ════════════════════════════════════════════════════════════════════════

#: Nombre de lignes d'exemple générées pour ``/preview``. 5 suffit à
#: montrer le rendu sans alourdir la payload (5 × N colonnes reste petit
#: même pour N ≈ 30). Constante module-level : modifier cette valeur
#: change le rendu pour tous les templates et casse volontairement les
#: tests qui dépendent du comptage — signal fort de modification.
_SAMPLE_ROW_COUNT: Final[int] = 5

#: Année figée dans les dates d'exemple. Pinnée (plutôt que
#: ``date.today().year``) pour garantir des sample data stables entre
#: tests/snapshots et éviter une flakiness le 1er janvier. Sans impact
#: fonctionnel : ces dates ne sont jamais persistées ni validées contre
#: une BDD — strictement illustratives.
_SAMPLE_YEAR: Final[int] = 2026

#: Jour du mois utilisé (15 = milieu, neutre — évite les pièges de
#: calendrier genre 31 février).
_SAMPLE_DAY: Final[int] = 15

#: Base pour les valeurs ``currency`` d'exemple. 1 000 rend visible le
#: séparateur de milliers appliqué par ``_apply_format``.
_SAMPLE_CURRENCY_BASE: Final[float] = 1_000.0

#: Offset fractionnaire pour que la valeur ne soit pas ronde (``.25``
#: rend visibles les 2 décimales du format monétaire).
_SAMPLE_CURRENCY_OFFSET: Final[float] = 50.25

#: Base et pas pour les pourcentages (10, 15, 20, 25, 30).
_SAMPLE_PERCENTAGE_BASE: Final[float] = 10.0
_SAMPLE_PERCENTAGE_STEP: Final[float] = 5.0

#: Pas pour les entiers (10, 20, 30, 40, 50).
_SAMPLE_INTEGER_STEP: Final[int] = 10

#: Rate-limit sur les lectures. 60 req/min/user couvre largement un
#: usage humain (un utilisateur très actif dépasse rarement 10/min en
#: navigation) et laisse confortablement passer les intégrations batch
#: légitimes (cron horaire qui liste + détail). Au-delà, c'est un bug
#: UI (polling serré) ou un crawler — 429 explicite.
_READ_RATE_MAX: Final[int] = 60

#: Fenêtre (secondes) pour le sliding window du rate-limiter.
_READ_RATE_WINDOW: Final[int] = 60

#: Clé de rate-limit pour un user non-identifié. Ne devrait jamais être
#: atteinte (:class:`AuthenticatedHandler` rejette anonyme), mais
#: défense en profondeur : si un jour le handler est branché hors auth
#: par erreur, le rate-limit reste actif sous cette clé partagée.
_ANON_RATE_KEY: Final[str] = "templates:_anon_"


# ════════════════════════════════════════════════════════════════════════
# Singletons module-level (cache partagé, rate-limit partagé)
# ════════════════════════════════════════════════════════════════════════

#: Un seul :class:`TemplateManager` partagé entre les 3 handlers pour
#: que le cache ``_templates_cache`` / ``_templates_mtime`` survive
#: entre requêtes. Invalidation automatique sur modification fichier
#: (mtime check dans :meth:`TemplateManager.load_template`).
#:
#: Tornado est single-thread pour Python code (pas de GIL release entre
#: ``dict[k] = v`` consécutifs sans ``await``), donc pas de race
#: observable sur les écritures de cache. Si le projet passait à du
#: multi-thread un jour, il faudrait soit remplacer par un ``threading.
#: RLock`` autour des accès cache, soit instancier par thread.
_template_manager: Final[TemplateManager] = TemplateManager()

#: Rate-limiter partagé — :class:`RateLimiter` est thread-safe (lock
#: interne) donc sûr même si un futur refactor multi-thread débarque.
_rate_limiter: Final[RateLimiter] = RateLimiter()


# ════════════════════════════════════════════════════════════════════════
# Messages utilisateur centralisés (FR, ton cohérent avec le reste du projet)
# ════════════════════════════════════════════════════════════════════════


class _Messages:
    """Messages d'erreur client. ``Final[str]`` pour stabilité/testabilité.

    Centraliser ici : (1) facilite l'audit sécurité (aucun message n'est
    construit par concaténation d'input utilisateur — élimine la classe
    CWE-209), (2) prépare l'i18n future, (3) permet aux tests d'importer
    les constantes plutôt que dupliquer des littéraux fragiles.
    """

    NOT_FOUND: Final[str] = "Template introuvable."
    LOAD_ERROR: Final[str] = "Erreur de chargement des templates."
    LOAD_ITEM_ERROR: Final[str] = "Erreur de chargement du template."
    PREVIEW_ERROR: Final[str] = "Erreur de prévisualisation du template."
    RATE_LIMITED: Final[str] = "Trop de requêtes — patientez quelques secondes."


# ════════════════════════════════════════════════════════════════════════
# Helpers purs (pas de ``self``, testables hors handler)
# ════════════════════════════════════════════════════════════════════════


def _safe_template_view(template: dict[str, Any]) -> dict[str, Any]:
    """Vue publique d'un template avec whitelist stricte de champs.

    Exclut :

    * ``query`` — la requête SQL exposerait la structure de la BDD
      source à un user non-admin (CWE-200 Information Exposure). Aucun
      cas d'usage front pour le SQL brut (le front lance l'exécution
      via ``/api/reports/generate`` qui garde le SQL côté serveur).
    * ``aggregations``, ``alerts``, ``ai_analysis`` — computés côté
      serveur au moment de la génération, pas exposés pour inspection.

    Filtrage par allowlist explicite : un futur ajout de champ sensible
    ne fuitera pas par défaut. Fail-closed.

    Args:
        template: Template chargé par :meth:`TemplateManager.load_template`.
                  Garantie : contient ``id``, ``name``, ``description``,
                  ``columns``, ``metadata`` (validés à la charge).

    Returns:
        Dict prêt à sérialiser en JSON pour le client.
    """
    return {
        "id": template["id"],
        "name": template["name"],
        "description": template["description"],
        "category": template.get("category", "general"),
        "icon": template.get("icon", "📄"),
        "columns": template["columns"],
        "chart": template.get("chart", {}),
        "metadata": template["metadata"],
    }


def _sample_value_for(col_format: str, row_index: int) -> Any:
    """Retourne une valeur d'exemple pour ``col_format`` à l'indice ``row_index``.

    Format inconnu → fallback sur ``"Exemple N"`` (cohérent avec le
    comportement historique, pas de crash). ``row_index`` démarre à 0.

    La génération est déterministe : aucun appel à ``random`` ou à
    l'horloge — les snapshots de tests restent stables.
    """
    if col_format == "currency":
        return _SAMPLE_CURRENCY_BASE * (row_index + 1) + _SAMPLE_CURRENCY_OFFSET
    if col_format == "percentage":
        return _SAMPLE_PERCENTAGE_BASE + row_index * _SAMPLE_PERCENTAGE_STEP
    if col_format == "integer":
        return (row_index + 1) * _SAMPLE_INTEGER_STEP
    if col_format == "date":
        # Cycle sur 12 mois : supporte un ``_SAMPLE_ROW_COUNT`` futur
        # > 11 sans produire ``YYYY-13-15`` (bug du code original où
        # ``f"2026-0{i+1}-15"`` cassait dès ``i ≥ 9`` : ``2026-010-15``
        # puis ``2026-013-15`` etc.).
        month = (row_index % 12) + 1
        return f"{_SAMPLE_YEAR}-{month:02d}-{_SAMPLE_DAY:02d}"
    return f"Exemple {row_index + 1}"


def _generate_sample_data(
    columns: list[dict[str, Any]],
    *,
    row_count: int = _SAMPLE_ROW_COUNT,
) -> list[dict[str, Any]]:
    """Génère ``row_count`` lignes d'exemple selon les formats des colonnes.

    Pur — ne touche à rien hors de ses arguments. Les valeurs sont
    choisies pour rendre visible le formatage appliqué côté
    :meth:`TemplateManager._apply_format` (séparateurs, décimales,
    suffixes).

    Args:
        columns: Colonnes du template — chaque entrée doit contenir au
                 moins ``name`` (str) ; ``format`` est optionnel, défaut
                 ``"text"``.
        row_count: Nombre de lignes (défaut : ``_SAMPLE_ROW_COUNT``).
                   Accepte ``0`` (retourne une liste vide) ; n'accepte
                   pas de valeur négative (``range(negative)`` = vide,
                   comportement Python natif).

    Returns:
        Liste de dicts ``{col_name: valeur_brute}`` prête à être passée
        à :meth:`TemplateManager.format_results` pour le rendu final.
    """
    rows: list[dict[str, Any]] = []
    for i in range(row_count):
        row: dict[str, Any] = {}
        for col in columns:
            col_name = col["name"]
            col_format = col.get("format", "text")
            row[col_name] = _sample_value_for(col_format, i)
        rows.append(row)
    return rows


# ════════════════════════════════════════════════════════════════════════
# Handlers
# ════════════════════════════════════════════════════════════════════════


class _TemplatesAPIBase(AuthenticatedHandler):
    """Base commune — rate-limit par user avant chaque handler.

    Centralise le rate-limit pour éviter la duplication des 3 gardes
    (``_check_read_rate`` en tête de chaque handler). Hérite de
    :class:`AuthenticatedHandler` qui rejette anonyme en ``prepare``
    (401 JSON pour ``/api/``).
    """

    def _check_read_rate(self) -> None:
        """Applique un sliding-window rate-limit par user.

        Clé scopée par user_id (ou ``_ANON_RATE_KEY`` en défense en
        profondeur si le guard anonyme est cassé un jour). 429 +
        message FR si dépassement.
        """
        user = self.current_user
        user_id = getattr(user, "id", None) if user is not None else None
        key = f"templates:{user_id}" if user_id is not None else _ANON_RATE_KEY
        if not _rate_limiter.check(
            key,
            max_requests=_READ_RATE_MAX,
            window_seconds=_READ_RATE_WINDOW,
        ):
            raise tornado.web.HTTPError(429, _Messages.RATE_LIMITED)


class TemplatesListHandler(_TemplatesAPIBase):
    """Liste tous les templates disponibles avec métadonnées.

    Réponses :

    * ``200`` : ``{"success": True, "count": int, "templates": [...]}``
    * ``401`` : anonyme (via :class:`AuthenticatedHandler`)
    * ``429`` : rate-limit dépassé
    * ``500`` : I/O inattendu (permission, disque plein, …) — message
               générique côté client, trace complète loggée.
    """

    async def get(self) -> None:
        """GET /api/templates — liste des templates."""
        self._check_read_rate()
        try:
            templates = _template_manager.list_templates()
        except (OSError, ValueError) as exc:
            # ``list_templates`` attrape ses propres erreurs par-fichier
            # (log + skip) ; ce except attrape les pannes au niveau
            # répertoire (dir missing/perm). Remontée en 500 générique,
            # trace complète via ``logger.exception``.
            logger.exception(
                "Liste templates : échec I/O",
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            raise tornado.web.HTTPError(500, _Messages.LOAD_ERROR) from exc

        self.write_json({"success": True, "count": len(templates), "templates": templates})


class TemplateDetailHandler(_TemplatesAPIBase):
    """Détail d'un template donné — SQL masqué pour ne pas exposer la BDD.

    Réponses :

    * ``200`` : ``{"success": True, "template": {id, name, columns, ...}}``
    * ``401`` : anonyme
    * ``404`` : template introuvable OU id invalide (anti-oracle)
    * ``429`` : rate-limit
    * ``500`` : I/O inattendu
    """

    async def get(self, template_id: str) -> None:
        """GET /api/templates/{id} — détail d'un template."""
        self._check_read_rate()
        try:
            template = _template_manager.load_template(template_id)
        except FileNotFoundError as exc:
            # Template absent du FS — 404 explicite. Pas de log (cas
            # normal : UI teste l'existence d'un template inconnu).
            raise tornado.web.HTTPError(404, _Messages.NOT_FOUND) from exc
        except ValueError as exc:
            # Deux cas remontés via ``ValueError`` :
            # (a) ``template_id`` invalide (..``/``\\``) — attaque path
            #     traversal bloquée par le service. Log ``warning``
            #     pour audit sécu, 404 côté client (anti-oracle : ne
            #     pas distinguer de « n'existe pas »).
            # (b) structure JSON cassée (champ requis manquant) — cas
            #     ops qui a pushé un template malformé. Log ``warning``,
            #     404 (le user ne peut rien faire).
            logger.warning(
                "Template rejeté %r : %s",
                template_id,
                exc,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            raise tornado.web.HTTPError(404, _Messages.NOT_FOUND) from exc
        except OSError as exc:
            # PermissionError, disque plein, etc. — cas ops à remonter.
            logger.exception(
                "Détail template %r : I/O échec",
                template_id,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            raise tornado.web.HTTPError(500, _Messages.LOAD_ITEM_ERROR) from exc

        self.write_json({"success": True, "template": _safe_template_view(template)})


class TemplatePreviewHandler(_TemplatesAPIBase):
    """Prévisualisation d'un template avec lignes d'exemple formatées.

    Génère :data:`_SAMPLE_ROW_COUNT` lignes via
    :func:`_generate_sample_data` puis applique le formatage du template
    (devise, pourcentage, …) pour montrer le rendu final au client avant
    la vraie exécution SQL.

    Réponses :

    * ``200`` : ``{"success": True, "template_id": str, "template_name":
                   str, "sample_data": [{col_label: formatted_value}, ...],
                   "chart_config": {...}}``
    * ``401/404/429/500`` idem :class:`TemplateDetailHandler`.
    """

    async def get(self, template_id: str) -> None:
        """GET /api/templates/{id}/preview — prévisualisation."""
        self._check_read_rate()
        try:
            template = _template_manager.load_template(template_id)
            sample_data = _generate_sample_data(template["columns"])
            formatted = _template_manager.format_results(template_id, sample_data)
        except FileNotFoundError as exc:
            raise tornado.web.HTTPError(404, _Messages.NOT_FOUND) from exc
        except ValueError as exc:
            logger.warning(
                "Preview rejeté %r : %s",
                template_id,
                exc,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            raise tornado.web.HTTPError(404, _Messages.NOT_FOUND) from exc
        except OSError as exc:
            logger.exception(
                "Preview template %r : I/O échec",
                template_id,
                extra={"request_id": getattr(self, "request_id", "?")},
            )
            raise tornado.web.HTTPError(500, _Messages.PREVIEW_ERROR) from exc

        self.write_json(
            {
                "success": True,
                "template_id": template_id,
                "template_name": template["name"],
                "sample_data": formatted,
                "chart_config": template.get("chart", {}),
            }
        )
