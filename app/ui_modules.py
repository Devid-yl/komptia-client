"""UIModules Tornado partagés.

Composants serveur réutilisables rendus via ``{% module X(...) %}`` dans les
templates. Source UNIQUE de vérité pour des fragments d'UI transverses, afin
d'éviter la duplication (standards Komptia : single source of truth, axes 7/13).

``Pagination`` : barre de pagination unifiée — Première ⏮ · Précédente ‹ ·
numéros fenêtrés (avec « … ») · Suivante › · Dernière ⏭ — pour TOUTES les pages
rendues côté serveur. Le pendant client (rendu en JS pour les listes chargées
en AJAX) vit dans ``static/js/pagination.js`` et partage le MÊME algorithme de
fenêtrage : ``build_pagination_window`` ci-dessous a une réplique JS
``buildWindow``. Un test de parité (``tests/js/test_pagination.mjs`` +
``tests/unit/test_pagination_window.py``) garde les deux strictement alignés.
"""

from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlencode

import tornado.web


def build_pagination_window(
    page: int,
    total_pages: int,
    sibling: int = 2,
    boundary: int = 1,
) -> List[Optional[int]]:
    """Calcule la liste fenêtrée des numéros de page à afficher.

    Retourne une liste d'entiers (numéros de page) où ``None`` représente une
    ellipse « … ». Sont toujours inclus : les ``boundary`` premières et
    dernières pages, plus ``page ± sibling``. Un trou d'UNE seule page est
    comblé par son numéro (on n'affiche pas « … » pour sauter une seule page —
    comportement état-de-l'art Material UI / Ant Design / GOV.UK).

    Exemples (sibling=2, boundary=1) :
        page=1,  total=24 → [1, 2, 3, None, 24]
        page=6,  total=24 → [1, None, 4, 5, 6, 7, 8, None, 24]
        page=24, total=24 → [1, None, 22, 23, 24]
        total<=1          → []  (la barre se masque entièrement)

    Le résultat est volontairement borné : au plus
    ``2*boundary + 2*sibling + 3`` entrées, quel que soit ``total_pages``
    (pas de croissance non bornée — axe Komptia 21).
    """
    try:
        total_pages = int(total_pages)
    except (TypeError, ValueError):
        return []
    if total_pages <= 1:
        return []

    # Clamp défensif : un appelant peut passer une page hors bornes
    # (deep-link forgé, off-by-one). On ne fait JAMAIS confiance à l'entrée.
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    page = max(1, min(page, total_pages))
    sibling = max(0, int(sibling))
    boundary = max(1, int(boundary))

    keep: set[int] = set()
    for i in range(1, boundary + 1):
        keep.add(i)
        keep.add(total_pages - i + 1)
    for p in range(page - sibling, page + sibling + 1):
        keep.add(p)

    ordered = sorted(p for p in keep if 1 <= p <= total_pages)

    result: List[Optional[int]] = []
    prev = 0
    for p in ordered:
        gap = p - prev
        if gap == 2:
            result.append(prev + 1)  # comble un trou d'une seule page
        elif gap > 2:
            result.append(None)  # ellipse « … »
        result.append(p)
        prev = p
    return result


class Pagination(tornado.web.UIModule):
    """Barre de pagination serveur unifiée (rendu plein-page / liens ``<a>``).

    Usage minimal dans un template :

        {% module Pagination(page=page, total_pages=total_pages) %}

    Le module :
      * se masque tout seul si ``total_pages <= 1`` (rien à paginer) ;
      * préserve AUTOMATIQUEMENT tous les filtres de l'URL courante
        (``?status=…&days=…&q=…&type=…``) en ne remplaçant que ``page`` — donc
        aucun handler n'a à lui passer la liste des params (zéro couplage) ;
      * dérive le chemin de base depuis ``request.path`` — fonctionne tel quel
        pour ``/executions``, ``/admin``, ``/automations/history/42``,
        ``/admin/ai-training``, ``/admin/ai-performance``, etc.

    Accessibilité : ``<nav aria-label>``, ``aria-current="page"`` sur la page
    active, ``aria-label`` FR sur chaque contrôle, bornes désactivées via
    ``<button disabled>`` (non focusable, non cliquable).
    """

    def render(  # type: ignore[override]
        self,
        page: int,
        total_pages: int,
        sibling: int = 2,
    ) -> bytes:
        try:
            total_pages = int(total_pages)
        except (TypeError, ValueError):
            return b""
        if total_pages <= 1:
            return b""
        try:
            page = int(page)
        except (TypeError, ValueError):
            page = 1
        page = max(1, min(page, total_pages))

        items = build_pagination_window(page, total_pages, sibling=sibling)

        base_path = self.handler.request.path
        # Préserve tous les query-params SAUF ``page`` (ré-encodé proprement).
        # ``query_arguments`` est un dict[str, list[bytes]] côté Tornado.
        preserved: List[tuple[str, str]] = []
        for key, values in self.handler.request.query_arguments.items():
            if key == "page":
                continue
            for raw in values:
                preserved.append((key, raw.decode("utf-8", "replace")))

        def href(target: int) -> str:
            return base_path + "?" + urlencode(preserved + [("page", str(target))])

        return self.render_string(
            "_partials/pagination_ssr.html",
            items=items,
            current=page,
            total_pages=total_pages,
            href=href,
        )
