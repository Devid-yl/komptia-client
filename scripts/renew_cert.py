#!/usr/bin/env python3
"""Renouvellement AUTOMATIQUE du certificat TLS auto-signé (timer trimestriel).

Conçu pour être lancé périodiquement (systemd timer trimestriel, cf.
``scripts/install_cert_timer.py``). « Tous les 3 mois » est la cadence de
VÉRIFICATION, **pas** de régénération : régénérer un cert auto-signé à chaque
passage forcerait TOUS les postes à ré-accepter l'exception navigateur. On ne
régénère donc QUE si le certificat approche de son expiration (seuil
``--renew-before-days``, 180 j par défaut — > 2× l'intervalle de check
trimestriel (~91 j), donc une vérification manquée (Persistent=true) ne laisse
pas passer l'expiration ; le timer ajoute un ``OnBootSec`` pour couvrir un
serveur éteint plusieurs trimestres : rallumage = contrôle immédiat).

Réutilise les briques EXISTANTES (zéro duplication) :
  - ``scripts.gen_cert --force``           → régénère le cert (SAN auto IP/DNS)
  - ``nginx -t && systemctl reload nginx`` → recharge à chaud (sans coupure)

Le SAN (server-name + alt) est RE-DÉRIVÉ du certificat existant (CN + SAN) : le
cert est sa propre source de vérité, aucun fichier d'état à maintenir/synchroniser
(qui pourrait diverger). Un ``--server-name``/``--alt`` explicite permet de forcer
si le SAN du cert est malformé.

Usage::

    python3 -m scripts.renew_cert                  # check + renew si proche expiration
    python3 -m scripts.renew_cert --force          # régénère MAINTENANT (re-accept !)
    python3 -m scripts.renew_cert --dry-run        # montre la décision, n'agit pas
    python3 -m scripts.renew_cert --renew-before-days 120
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Mois anglais -> numéro. openssl émet TOUJOURS des abréviations anglaises
# (« Jun », « Jul »…) quelle que soit la locale ; ``datetime.strptime("%b")`` est
# au contraire DÉPENDANT de la locale → sur un serveur en locale FR/autre, parser
# « Jun » avec %b lèverait ValueError. On mappe donc à la main (locale-indépendant).
_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass
class CertInfo:
    """Infos extraites d'un certificat (CN, SAN, date d'expiration UTC)."""

    cn: str
    sans: list[str] = field(default_factory=list)
    not_after: datetime | None = None


# ── Fonctions PURES (testables sans I/O) ──────────────────────────────────────


def parse_cn(subject_line: str) -> str:
    """Extrait le CN d'une ligne ``subject=`` openssl (3.x « CN = x » ou 1.0 « /CN=x »)."""
    m = re.search(r"CN\s*=\s*([^,/\n]+)", subject_line)
    return m.group(1).strip() if m else ""


def parse_san_values(text: str) -> list[str]:
    """Extrait les valeurs SAN (``IP Address:x`` / ``DNS:x``) → ``["x", ...]``.

    Robuste au bloc multi-ligne d'openssl. On ne garde que les valeurs (gen_cert
    re-détecte IP vs DNS via ``san_entry``), dédupliquées en préservant l'ordre.
    """
    vals = re.findall(r"(?:IP Address|DNS):\s*([^\s,]+)", text)
    return list(dict.fromkeys(vals))


def derive_server_and_alts(cn: str, sans: list[str]) -> tuple[str, list[str]]:
    """Re-dérive ``(server_name, alts)`` pour ``gen_cert`` depuis CN + SAN existants.

    Le CN devient le nom principal ; les autres SAN deviennent les ``--alt``.
    Sans CN, on retombe sur le 1er SAN. Sans ni CN ni SAN → ``ValueError`` (on
    refuse de régénérer un cert « à l'aveugle » avec un nom inventé).
    """
    sans = list(dict.fromkeys(sans))
    if cn:
        server = cn
    elif sans:
        server = sans[0]
    else:
        raise ValueError(
            "Certificat sans CN ni SAN exploitable — impossible de re-dériver le nom. "
            "Régénérer explicitement via 'make production-setup SERVER_NAME=...'."
        )
    alts = [s for s in sans if s != server]
    return server, alts


def parse_not_after(enddate_line: str) -> datetime:
    """Parse ``notAfter=Jun  4 12:00:00 2028 GMT`` → datetime UTC (locale-indépendant)."""
    m = re.search(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", enddate_line)
    if not m:
        raise ValueError(f"Date d'expiration illisible dans : {enddate_line!r}")
    mon = _MONTHS.get(m.group(1))
    if mon is None:
        raise ValueError(f"Mois inconnu dans la date openssl : {m.group(1)!r}")
    day, hh, mm, ss, year = (int(m.group(i)) for i in (2, 3, 4, 5, 6))
    return datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc)


def days_until(not_after: datetime, now: datetime) -> int:
    """Jours (entiers, plancher) restant avant ``not_after``. Négatif si déjà expiré."""
    return (not_after - now).days


def should_renew(days_left: int, threshold_days: int, force: bool) -> bool:
    """Renouveler si forcé, ou si on est dans la fenêtre de seuil (ou déjà expiré)."""
    return bool(force) or days_left <= threshold_days


# ── I/O (openssl / gen_cert / nginx) ──────────────────────────────────────────


def _ensure_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise FileNotFoundError(
            f"'{name}' introuvable dans le PATH — requis pour le renouvellement."
        )


def read_cert_info(fullchain: Path) -> CertInfo:
    """Lit CN + SAN + date d'expiration d'un cert via openssl.

    Le SAN est lu via ``-ext subjectAltName`` (compact, OpenSSL >= 1.1.1) ; si ce
    flag n'est pas supporté (OpenSSL 1.0.x → exit non-zero), on retombe sur
    ``-text`` (présent partout). ``parse_san_values`` lit le SAN dans les 2 sorties.
    Sans ce fallback, un serveur à vieux openssl échouerait à CHAQUE passage et le
    cert ne serait JAMAIS renouvelé (panne silencieuse).
    """
    _ensure_tool("openssl")
    base = ["openssl", "x509", "-in", str(fullchain), "-noout", "-subject", "-enddate"]
    res = subprocess.run(base + ["-ext", "subjectAltName"], capture_output=True, text=True)
    if res.returncode != 0:
        res = subprocess.run(base + ["-text"], capture_output=True, text=True)
        res.check_returncode()
    blob = res.stdout
    subject_line = next((ln for ln in blob.splitlines() if ln.startswith("subject=")), "")
    enddate_line = next((ln for ln in blob.splitlines() if ln.startswith("notAfter=")), "")
    return CertInfo(
        cn=parse_cn(subject_line),
        sans=parse_san_values(blob),
        not_after=parse_not_after(enddate_line) if enddate_line else None,
    )


def regenerate_cert(server_name: str, alts: list[str], cert_dir: Path) -> None:
    """Régénère le cert via la brique existante ``scripts.gen_cert --force``."""
    cmd = [
        sys.executable,
        "-m",
        "scripts.gen_cert",
        "--server-name",
        server_name,
        "--out-dir",
        str(cert_dir),
        "--force",
    ]
    for alt in alts:
        cmd += ["--alt", alt]
    subprocess.run(cmd, check=True)


def reload_nginx() -> None:
    """``nginx -t`` puis ``systemctl reload nginx`` (reload à chaud, sans coupure)."""
    _ensure_tool("nginx")
    subprocess.run(["nginx", "-t"], check=True)
    subprocess.run(["systemctl", "reload", "nginx"], check=True)


def attempt_reload(sentinel: Path) -> bool:
    """Recharge nginx ; gère la SENTINELLE de convergence.

    Si le reload réussit → efface la sentinelle (le cert neuf est servi).
    Si le reload échoue après une régénération réussie → pose la sentinelle pour
    REJOUER le reload au prochain passage. Sans ça, le cert neuf serait sur disque
    mais nginx servirait l'ancien INDÉFINIMENT (le passage suivant verrait un cert
    « frais » et ne retenterait jamais le reload = donnée fausse silencieuse).
    """
    try:
        reload_nginx()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        sentinel.write_text("reload nginx en attente (échec précédent)\n", encoding="utf-8")
        sys.stderr.write(
            f"[renew_cert] Reload nginx échoué : {exc} — sentinelle posée ({sentinel}).\n"
        )
        return False
    if sentinel.exists():
        sentinel.unlink()
    return True


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Renouvelle le cert TLS auto-signé si proche expiration."
    )
    parser.add_argument(
        "--cert-dir", default="/etc/ssl/komptia", help="Dossier du cert (def /etc/ssl/komptia)"
    )
    parser.add_argument(
        "--renew-before-days",
        type=int,
        default=180,
        help="Renouveler si <= N jours avant expiration (def 180)",
    )
    parser.add_argument(
        "--server-name", default=None, help="Forcer le nom principal (sinon re-dérivé du cert)"
    )
    parser.add_argument("--alt", action="append", default=[], help="Forcer un SAN (répétable)")
    parser.add_argument(
        "--force", action="store_true", help="Régénérer même si pas proche de l'expiration"
    )
    parser.add_argument(
        "--skip-reload", action="store_true", help="Ne pas recharger nginx (debug/non-systemd)"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Affiche la décision, n'écrit/reload rien"
    )
    args = parser.parse_args()

    cert_dir = Path(args.cert_dir)
    fullchain = cert_dir / "fullchain.pem"

    # Cert absent : le timer a pu se déclencher AVANT l'install initiale. Ce n'est
    # pas une erreur — gen_cert (via setup_host_nginx) est l'outil d'installation.
    if not fullchain.exists():
        sys.stderr.write(
            f"[renew_cert] Aucun certificat dans {cert_dir} — rien à renouveler "
            f"(installation initiale : 'make production-setup SERVER_NAME=...').\n"
        )
        return 0

    try:
        info = read_cert_info(fullchain)
    except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"[renew_cert] Lecture du certificat impossible : {exc}\n")
        return 1

    if info.not_after is None:
        sys.stderr.write("[renew_cert] Date d'expiration absente du certificat — abandon.\n")
        return 1

    sentinel = cert_dir / ".reload_pending"
    days_left = days_until(info.not_after, now_utc())
    renew = should_renew(days_left, args.renew_before_days, args.force)
    sys.stderr.write(
        f"[renew_cert] Expiration le {info.not_after:%Y-%m-%d} (J-{days_left}), "
        f"seuil {args.renew_before_days} j, force={args.force} -> "
        f"{'RENOUVELLEMENT' if renew else 'rien à faire'}.\n"
    )

    if not renew:
        # Convergence : si un reload restait en attente (régénération précédente OK
        # mais reload KO), le rejouer même sans régénérer — sinon nginx servirait
        # l'ancien cert indéfiniment alors que le neuf est déjà sur disque.
        if sentinel.exists() and not args.skip_reload and not args.dry_run:
            sys.stderr.write(
                "[renew_cert] Reload nginx en attente (échec précédent) — nouvelle tentative.\n"
            )
            return 0 if attempt_reload(sentinel) else 1
        return 0

    # Nom/alt : override explicite sinon re-dérivé du cert existant.
    if args.server_name:
        server_name, alts = args.server_name, list(args.alt)
    else:
        try:
            server_name, alts = derive_server_and_alts(info.cn, info.sans)
        except ValueError as exc:
            sys.stderr.write(f"[renew_cert] {exc}\n")
            return 1

    if args.dry_run:
        sys.stderr.write(
            f"[renew_cert] [dry-run] régénérerait gen_cert --server-name {server_name} "
            f"{' '.join('--alt ' + a for a in alts)} --out-dir {cert_dir} --force, "
            f"puis {'(reload skip)' if args.skip_reload else 'nginx -t && systemctl reload nginx'}.\n"
        )
        return 0

    try:
        regenerate_cert(server_name, alts, cert_dir)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        sys.stderr.write(f"[renew_cert] Échec de la régénération du certificat : {exc}\n")
        return 1

    if not args.skip_reload and not attempt_reload(sentinel):
        sys.stderr.write(
            f"[renew_cert] Certificat régénéré pour {server_name} mais nginx PAS rechargé "
            f"— reload rejoué au prochain passage (sentinelle).\n"
        )
        return 1

    sys.stderr.write(
        f"[renew_cert] Certificat renouvelé pour {server_name} "
        f"(SAN: {', '.join([server_name] + alts)})"
        f"{'' if args.skip_reload else ' — nginx rechargé'}.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
