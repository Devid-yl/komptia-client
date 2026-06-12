#!/usr/bin/env python3
"""Installe le timer systemd de renouvellement automatique du certificat TLS.

Rend les units depuis les templates VERSIONNÉS (``deployment/systemd/``, SSoT),
les pose dans ``/etc/systemd/system`` et active le timer. Le service appelle
``scripts.renew_cert`` (qui ne régénère QUE si le cert approche l'expiration).

À lancer en root sur le serveur Linux. Câblé dans ``make production-setup`` (donc
installé à chaque déploiement) et disponible seul via ``make cert-renew-timer``
(pour un serveur déjà déployé). Idempotent. ``--dry-run`` montre les units rendues
+ les actions, sans rien écrire.

Usage::

    python3 -m scripts.install_cert_timer
    python3 -m scripts.install_cert_timer --dry-run
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_TEMPLATE_DIR = _REPO / "deployment" / "systemd"
_SERVICE_NAME = "komptia-cert-renew.service"
_TIMER_NAME = "komptia-cert-renew.timer"


def render_service(template_text: str, working_dir: str, python_path: str) -> str:
    """Substitue ``@WORKING_DIR@`` / ``@PYTHON@`` dans le template service.

    Garde anti « sortie fausse silencieuse » (consequences.md) : si un placeholder
    reste non substitué (template modifié), on échoue FORT plutôt que d'installer
    une unit cassée (ExecStart invalide → renouvellement qui ne tournerait jamais).
    """
    text = template_text.replace("@WORKING_DIR@", working_dir).replace("@PYTHON@", python_path)
    leftover = re.findall(r"@[A-Z_]+@", text)
    if leftover:
        raise ValueError(f"Placeholders non substitués dans l'unit service : {leftover}")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Installe le timer systemd de renouvellement du cert."
    )
    parser.add_argument(
        "--repo-dir",
        default=str(_REPO),
        help="Racine du repo (WorkingDirectory de l'unit ; def = ce repo)",
    )
    parser.add_argument(
        "--python",
        default=None,
        help="Python pour l'ExecStart (def = python3 du PATH ; renew_cert n'utilise que la stdlib)",
    )
    parser.add_argument(
        "--unit-dir", default="/etc/systemd/system", help="Dossier des units systemd"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Affiche les units rendues, n'écrit rien"
    )
    args = parser.parse_args()

    python_path = args.python or shutil.which("python3") or "/usr/bin/python3"

    service_tpl = (_TEMPLATE_DIR / _SERVICE_NAME).read_text(encoding="utf-8")
    timer_tpl = (_TEMPLATE_DIR / _TIMER_NAME).read_text(encoding="utf-8")

    try:
        service_rendered = render_service(service_tpl, args.repo_dir, python_path)
    except ValueError as exc:
        sys.stderr.write(f"[install_cert_timer] {exc}\n")
        return 1

    unit_dir = Path(args.unit_dir)
    service_path = unit_dir / _SERVICE_NAME
    timer_path = unit_dir / _TIMER_NAME

    if args.dry_run:
        sys.stderr.write(
            f"[install_cert_timer] [dry-run] WorkingDirectory={args.repo_dir} ExecStart python={python_path}\n"
        )
        sys.stderr.write(
            f"--- {service_path} ---\n{service_rendered}\n--- {timer_path} ---\n{timer_tpl}\n"
        )
        sys.stderr.write(
            "[dry-run] puis : systemctl daemon-reload ; systemctl enable --now komptia-cert-renew.timer\n"
        )
        return 0

    service_path.write_text(service_rendered, encoding="utf-8")
    timer_path.write_text(timer_tpl, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    # Efface un éventuel état `failed` d'un run précédent (sinon il persiste et
    # masque le prochain succès dans les dashboards). check=False : pas grave si
    # l'unité n'a jamais échoué.
    subprocess.run(["systemctl", "reset-failed", _SERVICE_NAME], check=False)
    subprocess.run(["systemctl", "enable", "--now", _TIMER_NAME], check=True)
    sys.stderr.write(
        f"[install_cert_timer] Timer installé et activé. "
        f"Vérifier : systemctl list-timers {_TIMER_NAME}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
