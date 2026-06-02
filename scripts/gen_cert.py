#!/usr/bin/env python3
"""Génère un certificat TLS auto-signé pour un déploiement LAN/VPN (Bloc A no-regret).

But (todo consolidation déploiement) : automate le ``openssl req`` qu'on lançait
à la main pour le reverse-proxy HTTPS. Le SAN (subjectAltName) est OBLIGATOIRE
côté navigateurs modernes (le CN seul est ignoré) — on l'auto-détecte : une IP
donne ``IP:x``, un nom d'hôte donne ``DNS:x``. Requis quelle que soit la topologie
(host-nginx OU nginx-in-compose) → brique neutre.

Pour un cert de CONFIANCE (sans avertissement navigateur), voir Phase 2 / mkcert
(todo #16). Ici = auto-signé : l'utilisateur clique « continuer » une fois.

Usage::

    python -m scripts.gen_cert --server-name 192.168.1.123 --alt komptia.lan \\
      --out-dir /etc/ssl/komptia
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys
from pathlib import Path


def san_entry(name: str) -> str:
    """``IP:x`` si ``name`` est une IP (v4/v6), sinon ``DNS:x``.

    Le SAN doit distinguer IP et DNS : un navigateur qui accède par IP exige une
    entrée ``IP:`` (une entrée ``DNS:`` ne matche pas une IP).
    """
    try:
        ipaddress.ip_address(name)
        return f"IP:{name}"
    except ValueError:
        return f"DNS:{name}"


def build_openssl_args(
    server_name: str, fullchain: str, privkey: str, days: int, alt_names: list[str]
) -> list[str]:
    """Construit la commande ``openssl req`` (fonction pure → testable sans I/O)."""
    sans = [san_entry(server_name)] + [san_entry(a) for a in alt_names if a]
    return [
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-days",
        str(days),
        "-newkey",
        "rsa:2048",
        "-keyout",
        privkey,
        "-out",
        fullchain,
        "-subj",
        f"/CN={server_name}",
        "-addext",
        f"subjectAltName={','.join(sans)}",
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère un cert TLS auto-signé (SAN auto).")
    parser.add_argument("--server-name", required=True, help="IP ou nom d'hôte principal")
    parser.add_argument(
        "--alt", action="append", default=[], help="SAN additionnel (répétable : --alt komptia.lan)"
    )
    parser.add_argument("--out-dir", default="/etc/ssl/komptia", help="Dossier de sortie")
    parser.add_argument("--days", type=int, default=825, help="Validité (jours, défaut 825)")
    parser.add_argument(
        "--force", action="store_true", help="Écraser un certificat existant (sinon skip sûr)"
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    fullchain = out_dir / "fullchain.pem"
    privkey = out_dir / "privkey.pem"

    # Garde anti-footgun : ne PAS régénérer un cert existant sans --force (un
    # nouveau cert invaliderait celui que des clients/navigateurs ont accepté).
    if (fullchain.exists() or privkey.exists()) and not args.force:
        sys.stderr.write(
            f"Certificat déjà présent dans {out_dir} — utiliser --force pour régénérer "
            f"(attention : invalide les clients qui ont accepté l'ancien).\n"
        )
        sys.exit(0)

    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = build_openssl_args(args.server_name, str(fullchain), str(privkey), args.days, args.alt)
    subprocess.run(cmd, check=True)
    sys.stderr.write(f"Certificat auto-signé généré : {fullchain} (SAN auto IP/DNS).\n")


if __name__ == "__main__":
    main()
