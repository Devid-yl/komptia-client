"""scripts/vacuum_db.py — reclaim OPT-IN de l'espace disque de la BDD locale.

SQLite ne rend jamais l'espace à l'OS après ``DELETE`` (high-water mark) : les
pages libérées par le cleanup TTL (``db_retention``) restent dans le fichier. Un
``VACUUM`` reconstruit le fichier compacté → l'espace est réellement rendu.

⚠️ ``VACUUM`` est **coûteux** (réécrit tout le fichier) et prend un **lock
exclusif** → JAMAIS automatique en prod. C'est une opération **OPÉRATEUR**, à
lancer **hors-ligne** (cf. cible ``make vacuum`` qui arrête le container d'abord).
Choisi à dessein : full ``VACUUM`` in-place (marche sur BDD neuves ET existantes,
contrairement à ``auto_vacuum=INCREMENTAL`` qui ne sert que les BDD créées avec).

Garde-fou : ``VACUUM`` écrit un fichier temporaire ≈ taille de la BDD avant de
remplacer → on **refuse fail-closed** si l'espace disque libre est insuffisant
(sinon le VACUUM échoue en milieu de course et peut laisser un temp orphelin).

Usage :
    python -m scripts.vacuum_db [--dry-run] [--min-free-ratio 1.2]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass

from sqlalchemy import create_engine, event, text

from app.config import config
from app.core.database import setup_encryption

#: Marge d'espace libre requise (multiple de la taille BDD). ``VACUUM`` écrit une
#: copie ≈ 1× la taille avant de basculer → 1.2 = 1× + 20% de marge prudente.
_DEFAULT_MIN_FREE_RATIO = 1.2


class VacuumError(RuntimeError):
    """Échec d'un VACUUM (BDD introuvable, espace insuffisant, erreur SQLite)."""


class InsufficientDiskSpaceError(VacuumError):
    """Espace disque libre < ``min_free_ratio × taille BDD`` → VACUUM refusé."""


@dataclass(frozen=True)
class VacuumResult:
    db_path: str
    before_bytes: int
    after_bytes: int
    free_before_bytes: int
    dry_run: bool

    @property
    def reclaimed_bytes(self) -> int:
        return max(self.before_bytes - self.after_bytes, 0)


def _resolve_db_path() -> str:
    return config.database.path


def vacuum_database(
    *,
    db_path: str | None = None,
    keyed: bool = True,
    dry_run: bool = False,
    min_free_ratio: float = _DEFAULT_MIN_FREE_RATIO,
) -> VacuumResult:
    """Compacte la BDD SQLite via ``VACUUM`` in-place. Retourne un :class:`VacuumResult`.

    Args:
        db_path: chemin du fichier BDD. Défaut = ``config.database.path``.
        keyed: enregistre ``setup_encryption`` (clé SQLCipher) sur la connexion —
            indispensable sur un déploiement chiffré (la clé n'est PAS posée
            automatiquement sur un engine ad-hoc). ``False`` pour une BDD en clair
            (tests).
        dry_run: mesure l'espace récupérable potentiel SANS exécuter le VACUUM
            (ne lock pas) — en pratique on rapporte juste la taille courante.
        min_free_ratio: garde-fou espace disque (cf. constante).

    Raises:
        VacuumError: BDD introuvable.
        InsufficientDiskSpaceError: espace libre insuffisant (fail-closed).
    """
    db_path = db_path or _resolve_db_path()
    if not os.path.isfile(db_path):
        raise VacuumError(f"BDD introuvable : {db_path}")

    before_bytes = os.path.getsize(db_path)
    free_bytes = shutil.disk_usage(os.path.dirname(os.path.abspath(db_path))).free

    required = int(before_bytes * min_free_ratio)
    if free_bytes < required:
        raise InsufficientDiskSpaceError(
            f"Espace libre insuffisant pour VACUUM : {free_bytes} octets libres < "
            f"{required} requis ({min_free_ratio}× la BDD de {before_bytes} octets). "
            "Libérez de l'espace ou utilisez un disque temporaire (SQLITE_TMPDIR)."
        )

    if dry_run:
        return VacuumResult(db_path, before_bytes, before_bytes, free_bytes, dry_run=True)

    engine = create_engine(f"sqlite:///{db_path}")
    if keyed:
        # La clé SQLCipher n'est posée que par les hooks de l'engine principal
        # (``_register_connection_hooks``) ; un engine ad-hoc ne l'hérite pas →
        # on réutilise ``setup_encryption`` (SSoT) sinon VACUUM échouerait sur
        # un déploiement chiffré ("file is not a database").
        event.listen(engine, "connect", setup_encryption)
    try:
        # VACUUM interdit dans une transaction → AUTOCOMMIT.
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("VACUUM"))
    except Exception as exc:  # noqa: BLE001 — on enveloppe pour un message actionnable
        raise VacuumError(f"VACUUM a échoué sur {db_path} : {exc}") from exc
    finally:
        engine.dispose()

    after_bytes = os.path.getsize(db_path)
    return VacuumResult(db_path, before_bytes, after_bytes, free_bytes, dry_run=False)


def _human(n: int) -> str:
    units = ["o", "Kio", "Mio", "Gio", "Tio"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.1f} {u}"
        size /= 1024
    return f"{n} o"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VACUUM opt-in de la BDD locale Komptia.")
    parser.add_argument(
        "--dry-run", action="store_true", help="Ne lance pas le VACUUM, rapporte la taille."
    )
    parser.add_argument(
        "--min-free-ratio",
        type=float,
        default=_DEFAULT_MIN_FREE_RATIO,
        help=f"Marge d'espace libre requise (défaut {_DEFAULT_MIN_FREE_RATIO}× la BDD).",
    )
    args = parser.parse_args(argv)

    try:
        result = vacuum_database(dry_run=args.dry_run, min_free_ratio=args.min_free_ratio)
    except InsufficientDiskSpaceError as exc:
        print(f"REFUSÉ (fail-closed) : {exc}", file=sys.stderr)
        return 2
    except VacuumError as exc:
        print(f"ERREUR : {exc}", file=sys.stderr)
        return 1

    if result.dry_run:
        print(
            f"[dry-run] BDD {result.db_path} : {_human(result.before_bytes)} (aucun VACUUM lancé)."
        )
    else:
        print(
            f"VACUUM terminé : {result.db_path}\n"
            f"  avant   : {_human(result.before_bytes)}\n"
            f"  après   : {_human(result.after_bytes)}\n"
            f"  rendu   : {_human(result.reclaimed_bytes)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
