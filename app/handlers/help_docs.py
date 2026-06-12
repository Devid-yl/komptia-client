"""Handlers de la section « Aide » — guides d'utilisation PDF servis par rôle.

Surface HTTP
------------
* ``GET /help/guides/<key>``  — téléchargement (ou affichage ``?inline=true``)
  authentifié d'un guide PDF. ``<key>`` ∈ {user, admin}. Hors ``/api/``
  volontairement : liens cliqués en navigation top-level → une erreur rend
  ``error.html`` / redirige vers ``/login`` plutôt qu'un JSON brut.

La page ``/settings`` (cf. :mod:`app.handlers.settings`) affiche une carte par
guide *visible* pour l'utilisateur courant ; le lien pointe vers cet endpoint.

Doctrine sécurité (équipe sénior — mêmes garanties que ``reports.py``)
----------------------------------------------------------------------
1. **Whitelist stricte** — la clé d'URL est résolue dans :data:`HELP_GUIDES`
   (registre figé). Aucun nom de fichier ne vient de l'utilisateur : pas de
   path traversal possible par construction. La revérification
   ``is_relative_to`` est une défense-in-depth au point d'émission.
2. **Fail-closed sur le rôle** — un guide ``admin_only`` n'est servi qu'aux
   admins (:func:`~app.handlers.base.is_admin`). Un non-admin reçoit **404**
   (pas 403) pour ne pas divulguer l'existence du guide admin (oracle
   d'énumération — même logique que ``reports.py::_fetch_owned_report``).
3. **Headers de téléchargement mutualisés** — :func:`set_download_security_headers`
   (SSoT ``app.utils.http_streaming``) : ``Referrer-Policy: no-referrer`` +
   ``X-Content-Type-Options: nosniff`` + ``Content-Disposition`` anti-CRLF.
4. **Streaming borné mémoire** — :func:`stream_file_to_handler` (chunks 64 KiB),
   identique aux rapports/datastore — pas de ``read()`` intégral du PDF.

Le contenu (``docs/guides/*.pdf``) est **livré en lecture seule avec l'app**
(généré par ``scripts/build_guides.py`` en dev, embarqué dans l'image Docker en
prod via ``.dockerignore``/``Dockerfile``) — il ne vit PAS dans le volume de
données runtime, donc reste disponible pour un nouveau client sans aucune
génération côté serveur.

Mapping rôle → guide (2026-06-05 : fusion user + expert)
--------------------------------------------------------
* ``user`` → tout utilisateur authentifié. Inclut désormais le contenu avancé
  (ex-« guide expert ») : « expert » était du *contenu*, pas un rôle d'accès —
  Komptia n'a que 2 rôles, ``admin`` et ``user`` (cf.
  :class:`app.models.user.UserRole`).
* ``admin`` → admins uniquement (appliqué côté serveur, pas seulement masqué
  dans l'UI).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

import tornado.web

from app.config import get_config
from app.handlers.base import BaseHandler, authenticated, is_admin
from app.utils.http_streaming import set_download_security_headers, stream_file_to_handler
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Type MIME des guides (tous des PDF auto-portants générés par weasyprint).
_PDF_MIME: Final[str] = "application/pdf"


@dataclass(frozen=True)
class HelpGuide:
    """Métadonnées d'un guide d'aide (entrée du registre whitelist).

    * ``key`` — identifiant stable utilisé dans l'URL (``[a-z0-9_-]+``).
    * ``filename`` — nom du PDF dans ``config.guides_dir`` (jamais issu de
      l'utilisateur — c'est ce qui rend le path traversal impossible).
    * ``download_name`` — nom de fichier lisible proposé au navigateur.
    * ``admin_only`` — ``True`` ⇒ réservé aux admins (fail-closed).
    """

    key: str
    filename: str
    title: str
    description: str
    admin_only: bool
    download_name: str


#: Registre SSoT des guides. Les ``filename`` correspondent exactement aux
#: sorties de ``scripts/build_guides.py``. Ajouter un guide ici suffit à le
#: rendre téléchargeable ET à le faire apparaître dans /settings (la page
#: filtre via :func:`available_guides_for_user`).
HELP_GUIDES: Final[tuple[HelpGuide, ...]] = (
    HelpGuide(
        key="user",
        filename="komptia_guide_user.pdf",
        title="Guide utilisateur",
        description=(
            "Prise en main pas-à-pas : interface, Iris, exploration des données, "
            "automatisations, tableaux de bord, paramètres — et usage avancé "
            "(grille experte, construction de données, DAG avancés, webhooks)."
        ),
        admin_only=False,
        download_name="Komptia - Guide utilisateur.pdf",
    ),
    HelpGuide(
        key="admin",
        filename="komptia_guide_admin.pdf",
        title="Guide administrateur",
        description=(
            "Configuration & exploitation : base de données, fournisseur IA, SMTP, "
            "utilisateurs, mode invisible, anonymisation, sécurité, audit."
        ),
        admin_only=True,
        download_name="Komptia - Guide administrateur.pdf",
    ),
)

#: Index clé → guide pour une résolution O(1) côté handler.
_GUIDES_BY_KEY: Final[dict[str, HelpGuide]] = {g.key: g for g in HELP_GUIDES}


def guides_for_user(user: Any) -> list[HelpGuide]:
    """Guides *autorisés* pour ``user`` selon son rôle (fail-closed).

    Ne touche PAS le disque — filtre purement sur ``admin_only``. Utilisé
    par le handler de download (autorisation) et indirectement par
    :func:`available_guides_for_user`.
    """
    admin = is_admin(user)
    return [g for g in HELP_GUIDES if (not g.admin_only) or admin]


def available_guides_for_user(user: Any) -> list[HelpGuide]:
    """Guides autorisés ET réellement présents sur le disque.

    Utilisé par :class:`app.handlers.settings.SettingsPageHandler` pour ne
    rendre que des cartes téléchargeables (pas de bouton « Voir » mort si un
    PDF n'a pas été généré/embarqué). Si la liste est vide, /settings affiche
    un empty-state « aucun guide disponible ».
    """
    guides_dir = get_config().guides_dir
    return [g for g in guides_for_user(user) if (guides_dir / g.filename).is_file()]


class HelpGuideDownloadHandler(BaseHandler):
    """``GET /help/guides/<key>`` — téléchargement authentifié d'un guide PDF."""

    @authenticated
    async def get(self, key: str) -> None:
        guide = _GUIDES_BY_KEY.get(key)
        # 404 d'abord : une clé inconnue ne révèle rien.
        if guide is None:
            raise tornado.web.HTTPError(404)
        # Fail-closed rôle. 404 (pas 403) : un user ne doit pas pouvoir déduire
        # l'existence du guide admin par le code de statut.
        if guide.admin_only and not is_admin(self.current_user):
            raise tornado.web.HTTPError(404)

        guides_dir = get_config().guides_dir.resolve()
        file_path = (guides_dir / guide.filename).resolve()
        # Défense-in-depth path traversal (le filename est déjà whitelisté).
        if not file_path.is_relative_to(guides_dir) or not file_path.is_file():
            logger.warning(
                "Guide '%s' demandé mais introuvable sur le disque (%s)",
                key,
                file_path,
            )
            raise tornado.web.HTTPError(404)

        inline = self.get_argument("inline", "false").lower() == "true"
        set_download_security_headers(
            self,
            content_type=_PDF_MIME,
            filename=guide.download_name,
            inline=inline,
            content_length=file_path.stat().st_size,
        )
        # F4 follow-up (review loop) : ces guides sont des PDF role-class STATIQUES
        # (mêmes octets pour tous les users d'un rôle, ~MB). Le ``no-store``
        # générique posé en ``prepare()`` par ``apply_authenticated_cache_control``
        # les re-téléchargerait INTÉGRALEMENT à chaque ouverture. On rétablit un
        # cache PRIVÉ : ``private`` (jamais de cache partagé) + ``Vary: Cookie``
        # (déjà posé par F4) → aucune fuite cross-session ; ``max-age=3600`` évite
        # le re-download pendant 1 h (les guides changent rarement — régénérés via
        # ``make guides``). Override APRÈS ``prepare()`` → l'emporte sur le no-store.
        self.set_header("Cache-Control", "private, max-age=3600")
        self.clear_header("Pragma")  # le ``no-cache`` de prepare() bloquerait le cache privé
        await stream_file_to_handler(self, file_path)
        self.finish()
