#!/usr/bin/env python3
"""Installe/recharge le reverse-proxy host-nginx pour Komptia (Bloc A — SANS migration).

Orchestre les briques EXISTANTES (aucune duplication) — exactement le runbook
qu'on faisait à la main, scripté et idempotent :

  1. cert auto-signé           → scripts.gen_cert        (#3)
  2. zones limit_req (http{})  → ensure_limit_req_zones  (#11, idempotent)
  3. site config nginx         → scripts.render_nginx_conf (#4)
  4. enable + nginx -t + reload

Approche « host-nginx » (le déploiement qui marche) — NE touche PAS docker-compose.
À lancer sur le serveur, en root. ``--dry-run`` affiche les actions sans rien changer.

Usage::

    python3 -m scripts.setup_host_nginx --server-name 192.168.1.123 --alt komptia.lan
    python3 -m scripts.setup_host_nginx --server-name 192.168.1.123 --dry-run
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

_ZONE_DEFS = {
    "komptia_limit": "limit_req_zone $binary_remote_addr zone=komptia_limit:10m rate=10r/s;",
    "login_limit": "limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;",
}


def ensure_limit_req_zones(conf_text: str) -> str:
    """Insère les zones ``limit_req`` dans le bloc ``http {`` si absentes (idempotent).

    Idempotence PAR NOM de zone (``zone=komptia_limit`` / ``zone=login_limit``) :
    robuste si l'admin a déjà une zone du même nom avec un autre rate — on ne
    réinsère JAMAIS un nom existant (sinon nginx refuse : zone dupliquée). On
    n'insère que les noms manquants, juste après ``http {``. Pas de bloc ``http {``
    → ``ValueError`` (refuse de produire un nginx.conf cassé).
    """
    missing = {name: line for name, line in _ZONE_DEFS.items() if f"zone={name}" not in conf_text}
    if not missing:
        return conf_text

    out: list[str] = []
    inserted = False
    for line in conf_text.splitlines(keepends=True):
        out.append(line)
        if not inserted and line.lstrip().startswith("http {"):
            for zone_line in missing.values():
                out.append(f"    {zone_line}\n")
            inserted = True
    if not inserted:
        raise ValueError("Bloc 'http {' introuvable dans nginx.conf — insertion zones impossible.")
    return "".join(out)


def _run(cmd: list[str], dry_run: bool) -> None:
    if dry_run:
        print("  [dry-run] " + " ".join(cmd))
        return
    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Installe host-nginx pour Komptia (sans migration)."
    )
    parser.add_argument("--server-name", required=True, help="IP ou domaine public")
    parser.add_argument("--alt", action="append", default=[], help="SAN additionnel (répétable)")
    parser.add_argument("--cert-dir", default="/etc/ssl/komptia")
    parser.add_argument("--nginx-conf", default="/etc/nginx/nginx.conf")
    parser.add_argument("--site", default="/etc/nginx/sites-available/komptia")
    parser.add_argument("--enabled", default="/etc/nginx/sites-enabled/komptia")
    parser.add_argument(
        "--dry-run", action="store_true", help="Affiche les actions sans rien modifier"
    )
    args = parser.parse_args()

    py = sys.executable
    cert_dir = Path(args.cert_dir)
    fullchain = cert_dir / "fullchain.pem"
    privkey = cert_dir / "privkey.pem"

    # 1. Certificat auto-signé (gen_cert garde anti-écrasement intégrée).
    print("-> Certificat auto-signé...")
    cert_cmd = [
        py,
        "-m",
        "scripts.gen_cert",
        "--server-name",
        args.server_name,
        "--out-dir",
        str(cert_dir),
    ]
    for alt in args.alt:
        cert_cmd += ["--alt", alt]
    _run(cert_cmd, args.dry_run)

    # 2. Zones limit_req dans http{} (idempotent, avec backup avant écriture).
    print("-> Zones limit_req dans nginx.conf...")
    nginx_conf = Path(args.nginx_conf)
    conf_text = nginx_conf.read_text(encoding="utf-8")
    new_conf = ensure_limit_req_zones(conf_text)
    if new_conf != conf_text:
        if args.dry_run:
            print(f"  [dry-run] ajouterait les zones limit_req dans {nginx_conf}")
        else:
            shutil.copy2(nginx_conf, nginx_conf.with_suffix(nginx_conf.suffix + ".komptia.bak"))
            nginx_conf.write_text(new_conf, encoding="utf-8")
    else:
        print("  (zones déjà présentes)")

    # 3. Site config rendu depuis le template komptia.conf (cert auto-signé).
    print("-> Génération du site nginx...")
    render_cmd = [
        py,
        "-m",
        "scripts.render_nginx_conf",
        "--server-name",
        args.server_name,
        "--fullchain",
        str(fullchain),
        "--privkey",
        str(privkey),
        "--self-signed",
        "--out",
        args.site,
    ]
    _run(render_cmd, args.dry_run)

    # 4. Enable + test + reload. On retire d'abord le site `default` Debian
    # (page d'accueil) qui écoute sur :80 et masquerait sinon notre vhost.
    print("-> Activation + reload nginx...")
    _run(["rm", "-f", "/etc/nginx/sites-enabled/default"], args.dry_run)
    _run(["ln", "-sf", args.site, args.enabled], args.dry_run)
    _run(["nginx", "-t"], args.dry_run)
    _run(["systemctl", "reload", "nginx"], args.dry_run)

    print(f"+ host-nginx configuré pour {args.server_name} (cert auto-signé).")
    print(
        "  Accès : https://%s  (avertissement cert auto-signé attendu en Phase 1)."
        % args.server_name
    )


if __name__ == "__main__":
    main()
