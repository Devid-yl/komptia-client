"""Source UNIQUE de l'IP client pour les clés de rate-limit.

Single source of truth pour les endpoints PUBLICS (sans auth) dont le seul
garde-fou anti-abus est le rate-limit par IP — actuellement l'approbation DBA
(``iris_sql_write_dba``) et la reprise d'attente (``wait_response``).

Doctrine : ne JAMAIS dériver l'IP de ``X-Real-IP``/``X-Forwarded-For`` lus à la
main. Ces headers sont contrôlés par le client : un attaquant les ferait tourner
pour tomber dans un bucket de rate-limit différent à chaque requête et ainsi le
contourner entièrement. La seule source fiable est ``request.remote_ip``, qui
respecte la config ``trust_proxy_headers`` (elle pilote ``xheaders`` de Tornado,
cf. ``app/main.py``) :

* ``trust_proxy_headers=False`` (défaut sûr, expo directe / dev) → ``remote_ip``
  est l'IP socket du pair, non-spoofable.
* ``trust_proxy_headers=True`` (derrière un reverse-proxy de confiance, ex.
  nginx) → Tornado a déjà réécrit ``remote_ip`` depuis les en-têtes posés par
  le proxy de confiance.

C'est aussi le pattern du reste de la codebase (``auth``, ``feedback``,
``csp_report`` lisent tous ``request.remote_ip``).
"""

from __future__ import annotations

import tornado.web

#: Longueur max d'une représentation textuelle d'IPv6 (cap défensif sur la clé).
_IP_KEY_MAX_LEN: int = 45


def client_ip_for_rate_limit(handler: tornado.web.RequestHandler) -> str:
    """IP du client à utiliser comme composante d'une clé de rate-limit.

    Retourne ``request.remote_ip`` (cf. doctrine du module) tronqué à
    :data:`_IP_KEY_MAX_LEN`, avec fallback ``"unknown"`` si absent — ce qui
    regroupe les requêtes sans IP dans un seul bucket (fail-closed strict).
    """
    return (handler.request.remote_ip or "unknown")[:_IP_KEY_MAX_LEN]
