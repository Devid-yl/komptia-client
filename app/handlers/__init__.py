"""Handlers HTTP et WebSocket de Komptia (Tornado ``RequestHandler``).

Ce package regroupe l'ensemble des points d'entrée HTTP/WS exposés par
l'application. Chaque sous-module définit une ou plusieurs classes
``...Handler`` qui héritent de ``app.handlers.base.BaseHandler`` (cookies
sécurisés, charge de l'utilisateur courant, headers de sécurité, identifiant
de requête, journalisation). L'assemblage en routes se fait de manière
centralisée dans ``app.routes``.

Catégories de sous-modules
==========================

``base``
    Socle partagé : ``BaseHandler``, décorateurs d'autorisation
    (``admin_required``, ``require_role``), helpers JSON/erreurs,
    gestion de session SQLAlchemy.

``auth``
    Surface publique d'authentification (``LoginHandler``,
    ``LogoutHandler``) — seuls handlers accessibles sans session.

Applicatif (authentifié utilisateur)
    ``dashboard``, ``dashboard_builder``, ``workbooks``, ``reports``,
    ``contacts``, ``iris``, ``datastore``, ``saved_queries``,
    ``automations``, ``drilldown``, ``templates``, ``result_assistant``,
    ``webhooks``, ``email_history``.

Administration (rôle ``admin`` requis)
    ``admin``, ``admin_smtp``, ``ai_admin``, ``ai_config``, ``db_config``,
    ``settings``.

Infrastructure
    ``health`` (liveness/readiness + scheduler), ``performance``
    (métriques applicatives).

Politique d'import (règle d'équipe)
===================================

Ce ``__init__`` n'expose **aucun réexport**. Les consommateurs importent
toujours depuis le sous-module concerné
(``from app.handlers.health import HealthHandler``). Deux invariants
doivent être préservés par toute évolution :

1. *Pay for what you use* — importer ``app.handlers`` seul ne doit charger
   aucune dépendance lourde. Certains handlers ont un coût d'import
   massif (``reports`` ⇒ Matplotlib + Plotly + WeasyPrint,
   ``datastore`` ⇒ pyodbc + pilote SQL Server, ``iris`` ⇒ Anthropic SDK +
   orchestrateur). Un réexport au niveau package les tirerait tous en
   cascade sur chaque ``import app.handlers``, y compris dans les
   tests unitaires.
2. *One obvious way* — un symbole, un chemin d'import. Un alias au
   niveau package créerait deux manières équivalentes d'importer la
   même chose et dérive inévitablement en incohérence.

Le point d'assemblage des routes (``app.routes``) importe chaque handler
explicitement depuis son sous-module : c'est le seul endroit du code
qui doit connaître la topologie complète.

Toute exception à cette règle (p. ex. façade publique versionnée) doit
être justifiée dans cette docstring et garantir les deux invariants,
éventuellement via un mécanisme de chargement paresseux (PEP 562
``__getattr__``).
"""
