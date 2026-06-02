"""Middlewares transversaux de Komptia (Tornado).

Ce package regroupe les middlewares appliqués par ``BaseHandler.prepare()``
pour injecter des comportements communs sans polluer chaque handler. Chaque
sous-module expose une classe ou une fonction dont le nom suit le contrat
publié et qui est importée depuis ``app.handlers.base`` ou ``app.routes``.

Sous-modules
============

``security``
    ``SecurityHeadersMiddleware`` : injecte les headers de sécurité
    (CSP + nonce, HSTS, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, COOP/CORP, Cache-Control sensible).

    ``is_safe_redirect_url`` : valide une URL cible de redirection contre
    l'open-redirect (CWE-601), les caractères de contrôle, les bypass
    backslash (WHATWG URL spec) et le spoofing Unicode.

Politique d'import (règle d'équipe)
===================================

Aucun réexport n'est effectué depuis ce ``__init__``. Les consommateurs
importent toujours depuis le sous-module concerné
(``from app.middleware.security import SecurityHeadersMiddleware``).

Invariants :

1. *Pay for what you use* — importer ``app.middleware`` seul ne doit
   charger aucune dépendance lourde. Si un futur middleware tire des
   dépendances coûteuses, elles ne doivent pas polluer les autres.
2. *One obvious way* — un symbole, un chemin d'import. Un alias niveau
   package créerait deux chemins d'import équivalents et dérive en
   incohérence.

Toute exception (façade publique versionnée) doit être justifiée dans
cette docstring et garantir les deux invariants, éventuellement via
chargement paresseux (PEP 562 ``__getattr__``).
"""
