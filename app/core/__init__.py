"""Noyau fondamental de Komptia (primitives techniques partagées).

Ce package regroupe les briques bas-niveau indépendantes du domaine
métier et consommées par l'ensemble des services, handlers et modèles.

Sous-modules
============

``app.core.database``
    Connexion SQLAlchemy 2.0 asynchrone (``aiosqlite``) à la base SQLite
    locale chiffrée via SQLCipher : ``Base`` déclarative, cycle de vie
    du moteur (``init_database`` / ``close_database``), ``get_session``
    (context manager avec commit/rollback automatique) et factory de
    sessions. Charge l'extension ``sqlite-vec`` si disponible pour la
    recherche vectorielle, positionne les PRAGMA WAL/foreign_keys/
    busy_timeout et expose également ``get_db_url`` pour les
    composants synchrones (APScheduler).

``app.core.exceptions``
    Hiérarchie d'exceptions métier unifiée sous ``KomptiaError`` —
    authentification (``AuthenticationError`` et filles), base de
    données (``DatabaseError``, ``QueryError``, ``SageConnectionError``),
    IA (``AIError``, ``SQLGenerationError``, ``SQLValidationError``),
    automatisation, reporting, email, validation et configuration.
    Cet import est sans dépendance tierce, donc toujours bon marché.

Politique d'import (règle d'équipe)
===================================

Ce ``__init__`` n'expose **aucun réexport**. Les consommateurs
importent explicitement depuis le sous-module concerné
(``from app.core.database import get_session``,
``from app.core.exceptions import ValidationError``). Deux invariants
doivent être préservés par toute évolution :

1. *Pay for what you use* — importer une exception ne doit jamais
   charger SQLAlchemy ni ``aiosqlite``. Ajouter un réexport de
   ``database`` ici casserait cet invariant (chaîne d'import
   ``app.core → app.core.database → sqlalchemy``).
2. *One obvious way* — un symbole, un chemin d'import. Un alias
   au niveau package crée deux manières équivalentes d'importer la
   même chose et dérive inévitablement en incohérence.

Toute exception à cette règle (p. ex. façade publique versionnée)
doit être justifiée en docstring ici et conserver les deux invariants.
"""
