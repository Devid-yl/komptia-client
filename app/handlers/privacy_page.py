"""Handler de la page ``/data/privacy`` — tableau de bord de confidentialité.

Surface unique (``@authenticated``) :

* :class:`PrivacyPageHandler` — page HTML ``/data/privacy``. Rend le
  template Jinja ``privacy.html``. La page est entièrement pilotée par
  AJAX vers les endpoints existants ``/api/anonymization/*`` (handlers
  dans :mod:`app.handlers.anonymization`).

Choix de design (équipe sénior) :

* **Aucune logique métier** — toute la logique (terms, audit, stats,
  export, wipe, scan, auto-classify) vit déjà dans
  :mod:`app.services.anonymization.api_service` et est exposée via
  :mod:`app.handlers.anonymization`. Ce handler ne fait que servir le
  template, exactement comme :class:`EmailHistoryPageHandler`.
* **Gating identique aux pages "Données"** — ``@authenticated`` suffit ;
  l'API en aval applique ``@require_role(USER, ADMIN)`` et un
  ownership-404 sur les ressources de détail. Pas de double-gating au
  niveau du rendu (cohérent avec ``EmailHistoryPageHandler``,
  ``DatastoreHandler``).
* **Aucun nom hardcodé** — ni organisation, ni nom de BDD source, ni
  collaborateur : cohérent avec la règle GÉNÉRICITÉ Komptia.

Sécurité (OWASP ASVS + Top 10 2025) :

* A01 Broken Access Control — ``@authenticated`` ; les API en aval ont
  leur propre ``@require_role`` + ownership.
* A05 Security Misconfiguration — pas de message d'erreur inline ; les
  erreurs proviennent des API (toasts + bouton « Signaler » via
  :mod:`feedback-reporter`).
* CSP — le template utilise ``handler.csp_nonce`` pour le bloc
  ``<script>`` (aucun ``onclick`` inline ; ``addEventListener``).

Ce module ne contient **aucun** nom de BDD source, d'organisation
ou de collaborateur — la page est universelle.
"""

from __future__ import annotations

from typing import Final

from app.handlers.base import BaseHandler, authenticated

#: Titre de la page (FR) — affiché en ``<h1>`` et dans ``<title>``.
_PAGE_TITLE: Final[str] = "Confidentialité"


class PrivacyPageHandler(BaseHandler):
    """Rend la page HTML ``/data/privacy``.

    L'UI charge ensuite ses données via les endpoints AJAX existants :

    * ``GET /api/anonymization/stats`` — agrégats (badge global).
    * ``GET /api/anonymization/terms`` — état dictionnaire utilisateur.
    * ``GET /api/anonymization/audit`` — historique paginé.
    * ``GET /api/anonymization/terms/<id>/coverage`` — détail par terme.
    * ``GET /api/anonymization/export`` — téléchargement utilisateur.
    * ``POST /api/anonymization/wipe`` — utilisateur (double-confirm).
    * ``POST /api/anonymization/scan`` — scan datastore (SSE).
    * ``POST /api/anonymization/auto-classify[/probe|/regex]`` —
      classification automatique (LLM local + fallback regex).

    Accessible à tous les utilisateurs connectés (admin + user) — la
    confidentialité est une donnée par utilisateur, pas une feature
    admin-only.
    """

    @authenticated
    async def get(self) -> None:
        self.render("privacy.html", page_title=_PAGE_TITLE)
