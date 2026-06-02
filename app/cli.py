"""CLI sync unifié — single entry point pour toutes les opérations sync.

Encapsule les 3 scripts standalone (`scripts/*.py`) dans une commande unique
pour éviter à l'admin de mémoriser 3 chemins différents et 3 syntaxes
légèrement divergentes.

Usage :
    python -m app.cli sync rebuild-fts        # FTS5 trigram + triggers
    python -m app.cli sync rebuild-fts --no-triggers
    python -m app.cli sync seed               # value_mapping depuis sage_copy.db
    python -m app.cli sync seed --max-per-col 50000
    python -m app.cli sync seed --table Dossiers
    python -m app.cli sync recovery           # full sync via SchemaSyncService
    python -m app.cli sync recovery --dry-run

Note 2026-05-22 : la colonne ``value_mapping.anonymized_value`` a été
supprimée — ``/data-privacy`` (``anonymization_terms``) est la seule source
des pseudos runtime. Les scripts ``rebuild-fts`` et ``seed`` continuent à
peupler ``value_mapping`` (vraies valeurs uniquement) ; ils n'écrivent plus
dans ``anonymized_value``.

Implémentation : subprocess vers les scripts existants. Pas d'import direct
côté app/ (les scripts ont leurs propres deps et entry points). Avantage :
si un script change de signature, l'app code n'est pas affecté.

Si vous voulez exécuter un script avec arguments custom non listés ici,
utilisez directement `python scripts/<name>.py --help`.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"

# Mapping commande → script. Single source of truth — un changement de nom
# de script se fait ici uniquement.
_SUBCOMMANDS = {
    "rebuild-fts": SCRIPTS / "setup_fts5_value_mapping.py",
    "seed": SCRIPTS / "seed_value_mapping_from_sage.py",
    "recovery": SCRIPTS / "recovery_sync_sqlite.py",
}


def _run_subscript(script_path: Path, forwarded_args: Sequence[str]) -> int:
    """Exécute le script avec ses args, propage le returncode."""
    if not script_path.exists():
        print(
            f"ERREUR: script introuvable : {script_path}",
            file=sys.stderr,
        )
        return 1
    cmd = [sys.executable, str(script_path), *forwarded_args]
    try:
        # Pas de capture_output : laisser stdout/stderr couler en temps réel
        # pour que l'admin voie la progression du script.
        return subprocess.call(cmd, cwd=str(ROOT))
    except KeyboardInterrupt:
        return 130


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="komptia-cli",
        description=(
            "CLI unifié pour les opérations de sync Komptia. Toutes les "
            "options après le nom de sous-commande sont passées au script "
            "sous-jacent. Voir `python -m app.cli sync <cmd> --help`."
        ),
    )
    sub = ap.add_subparsers(dest="domain", required=True)
    sync = sub.add_parser("sync", help="Opérations de synchronisation BDD source ↔ locale")
    sync_sub = sync.add_subparsers(dest="cmd", required=True)
    for name, path in _SUBCOMMANDS.items():
        sync_sub.add_parser(
            name,
            help=f"Délègue à {path.name}",
            add_help=False,  # le script destinataire gère --help
        )
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # On ne parse QUE 2 niveaux ("sync" + sous-commande) pour identifier
    # la cible. Le reste passe brut au script (--help, --table, etc.).
    if len(argv) >= 2 and argv[0] == "sync" and argv[1] in _SUBCOMMANDS:
        script = _SUBCOMMANDS[argv[1]]
        forwarded = argv[2:]
        return _run_subscript(script, forwarded)
    # Sinon : afficher l'aide standard via argparse (validation stricte)
    parser = _build_parser()
    parser.parse_args(argv)
    # parse_args lève SystemExit si invalide ; ne devrait pas arriver ici.
    return 0


if __name__ == "__main__":
    sys.exit(main())
