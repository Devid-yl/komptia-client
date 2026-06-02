#!/usr/bin/env python3
"""Auto-configure l'environnement de déploiement (.env + config.yaml) — #6b / #10b.

Depuis le ``--server-name``, renseigne automatiquement les 2 réglages « derrière
proxy » qu'on devait poser à la main :
  - ``KOMPTIA_ALLOWED_ORIGINS=https://<server-name>`` dans ``.env`` (#6b) — sinon
    le WebSocket d'aperçu d'automatisation est refusé en prod (fail-closed) ;
  - ``server.trust_proxy_headers: true`` dans ``config.yaml`` (#10b) — vraie IP
    client (rate-limiter), HSTS, URLs https.

À lancer côté serveur AVANT ``docker compose up`` (les valeurs sont lues au boot
du conteneur). Fonctions pures testables + idempotentes ; ``--dry-run`` n'écrit
rien.

Optionnel ``--timezone`` (#7) : pose ``TZ`` (.env, niveau OS) + ``server.timezone``
(config.yaml, niveau app), après validation IANA via ``zoneinfo`` (un fuseau
erroné = rapports/scheduler à la mauvaise heure silencieusement → refus fail-loud).

Usage::

    python3 -m scripts.setup_deploy_env --server-name 192.168.1.123
    python3 -m scripts.setup_deploy_env --server-name 192.168.1.123 --timezone America/Guadeloupe
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import zoneinfo
from pathlib import Path


def ensure_env_var(env_text: str, key: str, value: str, *, overwrite: bool = False) -> str:
    """Pose ``KEY=value`` dans un texte ``.env`` (idempotent).

    - Ligne ``KEY=`` vide → renseignée ; ``KEY=déjà_rempli`` → laissée (sauf
      ``overwrite``) pour respecter une valeur posée manuellement ; absente → ajoutée.
    - Ignore les lignes commentées (``# KEY=...``).
    """
    out: list[str] = []
    found = False
    for line in env_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"{key}=") and not stripped.startswith("#"):
            found = True
            current = stripped.split("=", 1)[1]
            out.append(line if (current and not overwrite) else f"{key}={value}")
        else:
            out.append(line)
    if not found:
        out.append(f"{key}={value}")
    result = "\n".join(out)
    if env_text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def enable_trust_proxy(config_yaml_text: str) -> str:
    """Passe ``trust_proxy_headers`` à ``true`` dans config.yaml (idempotent).

    Déjà ``true`` → inchangé ; ``false`` → flippé ; absent → ``ValueError`` (le
    champ doit exister sous ``server:`` — refuse de produire une config trompeuse).
    """
    if re.search(r"trust_proxy_headers:\s*true", config_yaml_text):
        return config_yaml_text
    new, n = re.subn(r"trust_proxy_headers:\s*false", "trust_proxy_headers: true", config_yaml_text)
    if n == 0:
        raise ValueError("trust_proxy_headers introuvable dans config.yaml (attendu sous server:).")
    return new


def set_server_timezone(config_yaml_text: str, tz: str) -> str:
    """Pose ``timezone: "<tz>"`` sous ``server:`` dans config.yaml (idempotent).

    - Clé ``timezone:`` déjà présente → sa valeur est remplacée.
    - Absente → insérée juste après la ligne ``server:`` (indentation 2 espaces).
    - Section ``server:`` introuvable → ``ValueError`` (refuse une config trompeuse).

    Le ``tz`` est supposé déjà validé IANA par l'appelant (cf. ``main``).
    """
    if re.search(r"^[ \t]*timezone:[ \t]*.*$", config_yaml_text, re.MULTILINE):
        return re.sub(
            r"(^[ \t]*timezone:[ \t]*).*$",
            rf'\g<1>"{tz}"',
            config_yaml_text,
            count=1,
            flags=re.MULTILINE,
        )
    m = re.search(r"^server:[ \t]*$", config_yaml_text, re.MULTILINE)
    if m is None:
        raise ValueError("section 'server:' introuvable dans config.yaml")
    insert_at = m.end()
    return config_yaml_text[:insert_at] + f'\n  timezone: "{tz}"' + config_yaml_text[insert_at:]


def _write(path: Path, new_text: str, old_text: str, dry_run: bool, label: str) -> None:
    if new_text == old_text:
        print(f"  ({label} déjà à jour)")
        return
    if dry_run:
        print(f"  [dry-run] mettrait à jour {path}")
        return
    shutil.copy2(path, path.with_suffix(path.suffix + ".komptia.bak"))
    path.write_text(new_text, encoding="utf-8")
    print(f"  + {path} mis à jour (backup .komptia.bak)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-config .env + config.yaml pour le déploiement."
    )
    parser.add_argument("--server-name", required=True, help="IP ou domaine public d'accès")
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--config-yaml", default="config.yaml")
    parser.add_argument(
        "--scheme", default="https", help="Schéma de l'origine (défaut https — derrière TLS)"
    )
    parser.add_argument(
        "--timezone",
        default="",
        help="Fuseau IANA (ex: Europe/Paris, America/Guadeloupe) — pose TZ (.env) "
        "+ server.timezone (config.yaml). Vide = fuseau inchangé.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Validation fail-loud du fuseau AVANT toute écriture : un TZ erroné =
    # rapports/scheduler à la mauvaise heure SILENCIEUSEMENT (cf. dates décalées
    # serveur Guadeloupe). On refuse tout de suite plutôt qu'écrire une valeur fausse.
    if args.timezone:
        try:
            zoneinfo.ZoneInfo(args.timezone)
        except Exception:  # noqa: BLE001 — fail-loud, message actionnable
            parser.error(
                f"--timezone invalide ({args.timezone!r}) : pas un fuseau IANA reconnu "
                "(ex: Europe/Paris, America/Guadeloupe, UTC)"
            )

    origin = f"{args.scheme}://{args.server_name}"

    # .env : KOMPTIA_ALLOWED_ORIGINS (+ TZ si --timezone) — un seul write.
    env_path = Path(args.env_file)
    env_text = env_path.read_text(encoding="utf-8")
    new_env = ensure_env_var(env_text, "KOMPTIA_ALLOWED_ORIGINS", origin)
    print(f"-> KOMPTIA_ALLOWED_ORIGINS={origin} dans {args.env_file}...")
    if args.timezone:
        new_env = ensure_env_var(new_env, "TZ", args.timezone, overwrite=True)
        print(f"-> TZ={args.timezone} dans {args.env_file}...")
    _write(env_path, new_env, env_text, args.dry_run, ".env")

    # config.yaml : trust_proxy_headers (+ server.timezone si --timezone) — un seul write.
    cfg_path = Path(args.config_yaml)
    cfg_text = cfg_path.read_text(encoding="utf-8")
    new_cfg = enable_trust_proxy(cfg_text)
    print(f"-> trust_proxy_headers: true dans {args.config_yaml}...")
    if args.timezone:
        new_cfg = set_server_timezone(new_cfg, args.timezone)
        print(f"-> server.timezone: {args.timezone} dans {args.config_yaml}...")
    _write(cfg_path, new_cfg, cfg_text, args.dry_run, "config.yaml")

    print(
        "+ Config déploiement prête. Appliquer avec : docker compose up -d (recrée le conteneur)."
    )
    if not args.dry_run and not args.timezone:
        sys.stderr.write(
            "NB: fuseau horaire non modifié — passez --timezone (ex: America/Guadeloupe) "
            "pour le poser et éviter des dates/rapports décalés.\n"
        )


if __name__ == "__main__":
    main()
