#!/usr/bin/env python3
"""Génère la conf nginx déployée à partir du template versionné ``komptia.conf``.

But (todo consolidation déploiement, Bloc A — automatiser sans migrer) : remplace
le ``cp komptia.conf + sed`` manuel par une transformation reproductible et testée.
Substitue ``server_name`` + chemins du certificat, et — pour un cert auto-signé /
interne — retire l'OCSP stapling (sans objet, logue des erreurs), le
``ssl_trusted_certificate`` (inexistant) et le HSTS (dangereux tant que le cert
n'est pas de confiance : lockout navigateur).

SSoT : lit ``deployment/nginx/komptia.conf`` (source unique versionnée), produit
la conf rendue sur stdout (ou ``--out``). AUCUNE 2e conf en dur → pas de
duplication. Le site config produit vaut pour host-nginx OU nginx-in-compose.

Usage::

    python -m scripts.render_nginx_conf --server-name 192.168.1.123 \\
      --fullchain /etc/ssl/komptia/fullchain.pem \\
      --privkey   /etc/ssl/komptia/privkey.pem \\
      --self-signed > /etc/nginx/sites-available/komptia
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_DEFAULT_TEMPLATE = Path(__file__).resolve().parent.parent / "deployment" / "nginx" / "komptia.conf"

# Lignes retirées pour un cert auto-signé / interne (non public) :
# - OCSP stapling (ssl_stapling*, resolver*) : sans objet, logue des warnings ;
# - ssl_trusted_certificate : fichier chain.pem inexistant en auto-signé ;
# - HSTS : un navigateur qui voit HSTS sur un cert non fiable bloque DÉFINITIVEMENT
#   l'accès (pas de « continuer ») → lockout. On ne l'émet qu'avec un cert fiable.
_SELF_SIGNED_DROP = re.compile(
    r"^\s*(ssl_stapling\b|ssl_stapling_verify\b|resolver\b|resolver_timeout\b|"
    r"ssl_trusted_certificate\b|add_header\s+Strict-Transport-Security\b)"
)


def render(
    template_text: str,
    server_name: str,
    fullchain: str,
    privkey: str,
    self_signed: bool,
) -> str:
    """Rend la conf nginx déployée. Lève ``ValueError`` si une cible manque."""
    text = template_text

    text, n_sn = re.subn(
        r"server_name\s+komptia\.exemple\.fr;",
        f"server_name {server_name};",
        text,
    )
    text, n_fc = re.subn(
        r"ssl_certificate\s+\S+;",
        f"ssl_certificate {fullchain};",
        text,
    )
    text, n_pk = re.subn(
        r"ssl_certificate_key\s+\S+;",
        f"ssl_certificate_key {privkey};",
        text,
    )

    # Garde anti « sortie fausse silencieuse » (règle consequences.md) : si une
    # substitution requise n'a rien matché, le template a changé de forme → on
    # échoue fort plutôt que de produire une conf cassée ou non sécurisée.
    missing = []
    if n_sn < 1:
        missing.append("server_name komptia.exemple.fr")
    if n_fc < 1:
        missing.append("ssl_certificate")
    if n_pk < 1:
        missing.append("ssl_certificate_key")
    if missing:
        raise ValueError(
            "Template nginx inattendu — cibles introuvables : "
            + ", ".join(missing)
            + ". Vérifier deployment/nginx/komptia.conf."
        )

    if self_signed:
        text = "\n".join(line for line in text.splitlines() if not _SELF_SIGNED_DROP.match(line))
        if not text.endswith("\n"):
            text += "\n"

    return text


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rend la conf nginx déployée depuis le template komptia.conf."
    )
    parser.add_argument(
        "--server-name", required=True, help="IP ou domaine public (ex. 192.168.1.123)"
    )
    parser.add_argument("--fullchain", required=True, help="Chemin du certificat (fullchain.pem)")
    parser.add_argument("--privkey", required=True, help="Chemin de la clé privée (privkey.pem)")
    parser.add_argument(
        "--self-signed",
        action="store_true",
        help="Cert auto-signé/interne : retire OCSP stapling + HSTS + trusted_certificate",
    )
    parser.add_argument(
        "--template", default=str(_DEFAULT_TEMPLATE), help="Template source (défaut: komptia.conf)"
    )
    parser.add_argument("--out", default="-", help="Fichier de sortie (défaut: stdout)")
    args = parser.parse_args()

    template_text = Path(args.template).read_text(encoding="utf-8")
    rendered = render(
        template_text, args.server_name, args.fullchain, args.privkey, args.self_signed
    )

    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.out).write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
