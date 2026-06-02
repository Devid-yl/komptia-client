"""Défense SSRF (Server-Side Request Forgery) — primitives réseau.

Ce module fournit les helpers à appeler **avant** toute connexion réseau
sortante initiée à partir d'un input utilisateur (host SQL Server fourni
via le formulaire admin de configuration BDD, par exemple). L'objectif :
empêcher un admin malveillant — ou un compte compromis — d'utiliser le
serveur Komptia comme proxy pour scanner le réseau interne ou exfiltrer
des credentials cloud (metadata IMDSv1 sur AWS, GCE metadata, etc.).

Cf. OWASP A10:2021 — Server-Side Request Forgery, et la matrice de
mitigations OWASP SSRF Cheat Sheet (2025).

Principes appliqués :

* **Résolution explicite** via :func:`socket.getaddrinfo` — on ne se
  contente PAS d'inspecter la string du host. Un hostname tel que
  ``internal.corp.local`` peut résoudre vers une IP privée, et un
  hostname tel que ``rebind.attacker.tld`` peut faire du DNS rebinding
  (TTL = 0 → résolution différente entre la vérif et l'usage). Dans ce
  module on **résout une fois** et on retourne l'IP résolue, charge à
  l'appelant d'utiliser cette IP pour la connexion suivante (pin DNS).
* **Denylist > allowlist** pour les CIDR : la liste blanche serait
  ingérable (chaque admin a sa propre BDD interne). On bloque les plages
  IANA-réservées et les plages connues comme dangereuses (link-local,
  loopback, RFC1918, AWS metadata). C'est aligné avec la recommandation
  OWASP 2025 — pour un cas d'usage entreprise, l'allowlist serait plus
  sûre, mais elle imposerait une liste de hosts en dur, ce que la règle
  de généricité de la codebase interdit.
* **Validation du port** : refuse 0 et > 65535 (corruption de buffer
  côté driver), refuse les ports < 1024 SAUF la whitelist SQL/SQL
  Server (1433 default, 1434 SQL Browser, 4022 Service Broker) — un
  admin légitime ne pointe jamais vers le port 22 ou 25.
* **Pas d'I/O hors DNS** : aucun handshake TCP, aucun probe — on veut
  rester déterministe et rapide (la résolution DNS coûte déjà ~5-50 ms).
* **Messages FR neutres** : ne fuite pas l'IP résolue dans le message
  user-facing (un attaquant pourrait s'en servir pour scanner via
  oracle).

Politique d'erreur :

* :exc:`UnsafeHostError` (sous-classe de ``ValueError``) — le host est
  refusé pour raison de sécurité. Le message est court et neutre, prêt
  pour l'affichage UI.
* L'appelant doit catcher ``UnsafeHostError`` (ou ``ValueError``) et
  retourner un 400 — JAMAIS un 500. Une bonne config qui pointe vers
  une IP publique passe sans accroc.

Tests recommandés (tests/unit/test_network_safety.py) :

* ``assert_safe_host("8.8.8.8", 53)`` — IP publique, OK.
* ``assert_safe_host("169.254.169.254", 80)`` — AWS metadata → refus.
* ``assert_safe_host("127.0.0.1", 1433)`` → refus (loopback).
* ``assert_safe_host("10.0.0.1", 1433)`` → refus (RFC1918).
* ``assert_safe_host("evil\\r\\n.com", 1433)`` → refus (CRLF injection).
* ``assert_safe_host("server.local", 22)`` → refus (port non autorisé).
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Final

from app.utils.validators import assert_no_crlf

__all__ = [
    "DEFAULT_ALLOWED_PORTS",
    "PRIVATE_CIDRS",
    "UnsafeHostError",
    "assert_safe_host",
    "is_private_ip",
    "resolve_host_safely",
]


# Plages IP réservées qu'on REFUSE pour une connexion sortante depuis
# un input utilisateur. Liste tirée de IANA Special-Purpose Registry
# (RFC 6890) + AWS/GCP metadata service IPs + plages cloud-only.
PRIVATE_CIDRS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = (
    # IPv4 — RFC 1918 (entreprises) — usually attack target via SSRF
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 — RFC 6890 (loopback, link-local, multicast, broadcast, …)
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (AWS/GCP metadata)
    ipaddress.ip_network("0.0.0.0/8"),  # this network
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.ip_network("198.18.0.0/15"),  # benchmark (RFC 2544)
    ipaddress.ip_network("224.0.0.0/4"),  # multicast
    ipaddress.ip_network("240.0.0.0/4"),  # reserved (incl. broadcast)
    # IPv6 — équivalents
    ipaddress.ip_network("::1/128"),  # loopback
    ipaddress.ip_network("fc00::/7"),  # unique local (RFC 4193)
    ipaddress.ip_network("fe80::/10"),  # link-local
    ipaddress.ip_network("ff00::/8"),  # multicast
    ipaddress.ip_network("::/128"),  # unspecified
    # IPv4-mapped IPv6 (::ffff:0:0/96) ne couvre pas tout — ipaddress
    # détecte automatiquement les v4-mapped via IPv6Address.ipv4_mapped,
    # géré dans is_private_ip().
)


# Ports autorisés pour les connexions sortantes vers des SGBD. La règle :
# ne JAMAIS laisser un admin pointer vers 22 (SSH), 25 (SMTP),
# 6379 (Redis), 11211 (Memcached), 9200 (Elasticsearch) — qui sont des
# vecteurs SSRF classiques pour exfiltrer des données ou exécuter du code.
# On ouvre les ports SQL Server par défaut + une plage haute pour les
# admins qui ont configuré un port custom (sécurité par obscurité —
# rare mais pas interdit).
DEFAULT_ALLOWED_PORTS: Final[frozenset[int]] = frozenset(
    {
        1433,  # SQL Server default
        1434,  # SQL Server Browser (UDP, mais réservé par convention)
        4022,  # SQL Server Service Broker default
        5432,  # PostgreSQL (futur usage générique — cf. DatabaseType extensible)
        3306,  # MySQL/MariaDB (idem)
    }
)


# Plage haute = ports custom (sécurité par obscurité). Borne basse à
# 1024 pour interdire les ports privilégiés (où traînent SSH, SMTP, …).
_CUSTOM_PORT_MIN: Final[int] = 1024
_CUSTOM_PORT_MAX: Final[int] = 65535


class UnsafeHostError(ValueError):
    """Le host (ou le port) résolu/fourni est refusé pour raison de sécurité.

    Sous-classe de :class:`ValueError` pour rester compatible avec les
    handlers qui catchent déjà ``ValueError`` → 400. Le message est
    user-facing en français — neutre, pas d'IP résolue, pas de stack.
    """


def is_private_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Retourne ``True`` si l'IP appartient à une des plages refusées.

    Accepte une string (parsée via ``ipaddress.ip_address``) ou un objet
    déjà parsé. Les v4-mapped IPv6 (``::ffff:1.2.3.4``) sont normalisés
    en v4 avant la vérification — sans ça, un attaquant pourrait
    contourner la denylist en utilisant ``::ffff:127.0.0.1``.
    """
    if isinstance(ip, str):
        addr = ipaddress.ip_address(ip)
    else:
        addr = ip

    # Normalisation v4-mapped IPv6 → IPv4 pour ne pas trouer la denylist.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    for cidr in PRIVATE_CIDRS:
        # IPv4Network ne contient que IPv4Address ; éviter ValueError type-mismatch.
        if isinstance(addr, ipaddress.IPv4Address) and isinstance(cidr, ipaddress.IPv4Network):
            if addr in cidr:
                return True
        elif isinstance(addr, ipaddress.IPv6Address) and isinstance(cidr, ipaddress.IPv6Network):
            if addr in cidr:
                return True

    # Fallback ipaddress builtin pour couvrir les marqueurs is_private,
    # is_loopback, is_link_local, is_multicast — défense-in-depth si une
    # plage est oubliée.
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _is_port_allowed(
    port: int,
    extra_allowed: frozenset[int] | None = None,
) -> bool:
    """Logique de validation port — extrait pour testabilité unitaire."""
    if not isinstance(port, int) or isinstance(port, bool):
        return False
    if port in DEFAULT_ALLOWED_PORTS:
        return True
    if extra_allowed and port in extra_allowed:
        return True
    return _CUSTOM_PORT_MIN <= port <= _CUSTOM_PORT_MAX


def resolve_host_safely(host: str) -> str:
    """Résout ``host`` via DNS et retourne la première IP non-privée.

    Lève :exc:`UnsafeHostError` si :

    * le host contient des CR/LF (injection),
    * le host est vide ou > 255 caractères (limite DNS),
    * la résolution DNS échoue (gaierror),
    * **toutes** les IP résolues sont privées/réservées.

    Note importante : on retourne la **première** IP publique trouvée.
    L'appelant doit utiliser cette IP (et non le hostname original) pour
    la connexion suivante — sinon DNS rebinding (TTL=0 → résolution
    différente après le check).
    """
    # Validation purement syntaxique avant tout I/O réseau.
    if not isinstance(host, str) or not host:
        raise UnsafeHostError("L'adresse du serveur est requise.")

    cleaned = host.strip()
    if not cleaned:
        raise UnsafeHostError("L'adresse du serveur est requise.")

    # Limite DNS : RFC 1035 cap à 255 octets pour un FQDN. Borne large
    # pour tolérer punycode (xn--…) avant qu'on tape le résolveur.
    if len(cleaned) > 255:
        raise UnsafeHostError("L'adresse du serveur est trop longue.")

    # CRLF injection = sortie de protocole texte (SMTP, LDAP, …) — refus.
    try:
        assert_no_crlf(cleaned, "host")
    except ValueError as exc:
        raise UnsafeHostError("L'adresse du serveur contient des caractères interdits.") from exc

    # Cas litéral IP : pas besoin de DNS, on vérifie directement.
    try:
        literal = ipaddress.ip_address(cleaned)
    except ValueError:
        literal = None

    if literal is not None:
        if is_private_ip(literal):
            raise UnsafeHostError("Cette adresse de serveur n'est pas autorisée.")
        return str(literal)

    # Résolution DNS — on demande IPv4 + IPv6, pas seulement la 1ère.
    try:
        infos = socket.getaddrinfo(cleaned, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeHostError("Le serveur est introuvable. Vérifiez le nom de domaine.") from exc

    public_ips: list[str] = []
    for entry in infos:
        # entry = (family, type, proto, canonname, sockaddr)
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if not is_private_ip(addr):
            public_ips.append(str(addr))

    if not public_ips:
        raise UnsafeHostError("Cette adresse de serveur n'est pas autorisée.")

    # Pin une IP publique → l'appelant l'utilise au lieu du hostname (anti
    # rebinding). On PRÉFÈRE une IPv4 quand elle existe : certains drivers
    # consommateurs (ex. ODBC SQL Server, ``SERVER={ip,port}``) ne gèrent
    # pas une IPv6 littérale non-bracketée. Sécurité identique (IPv4 et IPv6
    # publiques sont toutes deux validées par ``is_private_ip`` ci-dessus) —
    # c'est un choix d'utilisabilité côté consommateur, pas un relâchement du
    # garde. Fallback IPv6 si le host est IPv6-only (pas de faux refus).
    for ip in public_ips:
        if ipaddress.ip_address(ip).version == 4:
            return ip
    return public_ips[0]


def assert_safe_host(
    host: str,
    port: int,
    extra_allowed_ports: frozenset[int] | None = None,
) -> str:
    """Garde-fou unique appelable depuis un handler ou un service.

    Combine :func:`resolve_host_safely` et :func:`_is_port_allowed`. Lève
    :exc:`UnsafeHostError` si l'un des deux échoue. Retourne l'IP
    résolue (à passer telle quelle au driver pour pin DNS).

    Exemple d'usage :

    .. code-block:: python

        try:
            safe_ip = assert_safe_host(form_host, form_port)
        except UnsafeHostError as exc:
            self.set_status(400)
            self.write_json({"success": False, "error": str(exc)})
            return
        # safe_ip est garantie publique — peut être passée au driver.
    """
    if not _is_port_allowed(port, extra_allowed_ports):
        raise UnsafeHostError("Le port spécifié n'est pas autorisé pour ce type de connexion.")
    return resolve_host_safely(host)
