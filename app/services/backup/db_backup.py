"""Snapshot cohérent + sûr de la BDD locale (SQLite/SQLCipher) — sous-étape 1b.

**Mécanisme** : ``VACUUM INTO`` sur une connexion DBAPI fournie par l'appelant.
``VACUUM INTO`` produit en UNE instruction une copie cohérente et défragmentée
de la base, sur une vue transactionnelle stable (WAL-safe) — pas de lock manuel,
pas de risque de torn-read comme une copie-fichier à chaud.

**Garde fail-closed (anti-fuite)** : si la base source est chiffrée (clé
SQLCipher configurée) mais que le snapshot produit est EN CLAIR — ce qui peut
arriver selon la build/version de SQLCipher (``VACUUM INTO`` n'hérite de la clé
qu'à partir de SQLCipher 4.3) — on **refuse et supprime** le fichier. On ne livre
JAMAIS un backup en clair de données confidentielles silencieusement.

**Découplage** : la connexion est INJECTÉE (pas créée ici). En prod le job
scheduler (sous-étape 1c) passe une connexion ouverte via le moteur de l'app
(donc déjà clé par le driver SQLCipher) ; en test on passe une connexion
``sqlite3`` standard. Cela rend le mécanisme testable headless ET vérifie
directement le mode d'échec prod (clé attendue mais sortie en clair → garde).

⚠️ ``VACUUM INTO`` ne tolère pas de transaction ouverte : la connexion doit être
en autocommit (``isolation_level=None`` pour ``sqlite3``).
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any, Optional, Protocol

#: 16 premiers octets d'un fichier SQLite EN CLAIR. Une base SQLCipher chiffrée
#: ne commence JAMAIS par cette signature (son header est lui-même chiffré).
#: Réf. : https://www.sqlite.org/fileformat.html#the_database_header
_SQLITE_PLAINTEXT_MAGIC = b"SQLite format 3\x00"

#: Secondes par jour (rotation par âge).
_SECONDS_PER_DAY = 86_400


class BackupError(Exception):
    """Erreur de sauvegarde (base de la hiérarchie)."""


class BackupEncryptionError(BackupError):
    """Le snapshot d'une BDD chiffrée est sorti EN CLAIR — refusé (fail-closed)."""


class _DBAPIConnection(Protocol):
    """Sous-ensemble DBAPI utilisé (``sqlite3.Connection`` / driver SQLCipher)."""

    def execute(self, sql: str, *args: Any) -> Any: ...  # pragma: no cover - typing


def is_plaintext_sqlite(path: Path | str) -> bool:
    """True si ``path`` commence par la signature SQLite EN CLAIR.

    Fail-safe : un fichier illisible/absent → ``False`` (on ne PRÉTEND pas
    qu'il est en clair ; la décision « refuser » est portée par l'appelant qui
    sait si le chiffrement était attendu).
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(len(_SQLITE_PLAINTEXT_MAGIC)) == _SQLITE_PLAINTEXT_MAGIC
    except OSError:
        return False


def snapshot_via_vacuum(
    connection: _DBAPIConnection,
    dest_path: Path | str,
    *,
    expect_encrypted: bool,
) -> Path:
    """Écrit un snapshot cohérent de ``connection`` vers ``dest_path``.

    Args:
        connection: connexion DBAPI déjà ouverte (et clé en prod), en autocommit.
        dest_path: fichier de destination — NE doit PAS exister (VACUUM INTO
            refuse d'écraser ; on lève une erreur claire en amont).
        expect_encrypted: ``True`` si la source est chiffrée (clé configurée).
            Si le snapshot produit est alors en clair → refus + suppression.

    Returns:
        Le ``Path`` du snapshot créé.

    Raises:
        BackupError: destination préexistante, ou aucun fichier produit.
        BackupEncryptionError: chiffrement attendu mais snapshot en clair.
    """
    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        # VACUUM INTO échouerait de toute façon ; message clair en amont.
        raise BackupError(f"destination de backup déjà existante : {dest}")

    # VACUUM INTO n'accepte pas de bind-param pour le chemin → littéral SQL
    # quoté (apostrophes doublées). Le chemin est dérivé de la config app
    # (backups_dir + timestamp), pas d'input utilisateur, mais on quote par
    # défense en profondeur.
    quoted = "'" + str(dest).replace("'", "''") + "'"
    connection.execute(f"VACUUM INTO {quoted}")

    if not dest.exists():
        raise BackupError("VACUUM INTO n'a produit aucun fichier de sortie")

    if expect_encrypted and is_plaintext_sqlite(dest):
        # Footgun SQLCipher : base chiffrée mais snapshot en clair = fuite de
        # données confidentielles. On refuse ET on supprime (fail-closed) —
        # jamais de backup en clair livré silencieusement.
        try:
            dest.unlink()
        except OSError:
            pass
        raise BackupEncryptionError(
            "Snapshot produit EN CLAIR alors que la BDD est chiffrée — refusé "
            "et supprimé (fail-closed). La build SQLCipher doit supporter "
            "VACUUM INTO keyé (>=4.3) ; sinon basculer sur l'API backup keyée."
        )

    return dest


def prune_snapshots(
    directory: Path | str,
    *,
    prefix: str,
    keep_count: int,
    keep_days: int,
    now: Optional[float] = None,
) -> list[Path]:
    """Rotation des snapshots : ``keep_count`` ET ``keep_days`` composables.

    Un fichier ``{prefix}*`` survit **seulement s'il est parmi les
    ``keep_count`` plus récents ET plus jeune que ``keep_days``** — le critère
    le plus strict gagne (même logique composable que :class:`LLMLogConfig`).

    Args:
        now: epoch de référence (injectable pour les tests). Défaut ``time.time()``.

    Returns:
        La liste des fichiers supprimés.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []
    ref_now = time.time() if now is None else now
    cutoff = ref_now - keep_days * _SECONDS_PER_DAY

    snaps = sorted(
        (p for p in directory.glob(f"{prefix}*") if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,  # plus récent d'abord
    )

    deleted: list[Path] = []
    for idx, path in enumerate(snaps):
        too_many = idx >= keep_count
        too_old = path.stat().st_mtime < cutoff
        if too_many or too_old:
            try:
                path.unlink()
                deleted.append(path)
            except OSError:
                # Best-effort : un fichier non supprimable ne casse pas la rotation.
                pass
    return deleted


def copy_to_offsite(snapshot_path: Path | str, offsite_dir: Path | str) -> Path:
    """Copie ATOMIQUE d'un snapshot vers un répertoire off-site **EXISTANT** (3-2-1).

    L'off-site (montage NFS/SMB/rclone, USB…) doit déjà exister : on **ne le crée
    PAS**. Un ``mkdir`` sur un montage non monté créerait un faux off-site local
    silencieux (données « sauvegardées » sur le même disque que la source) →
    fail-loud à la place (l'appelant logue et passe, le snapshot local reste valide).

    Copie via fichier ``.tmp`` puis ``os.replace`` (rename atomique sur le même
    FS) → jamais de fichier off-site partiel/corrompu visible.

    Raises:
        BackupError: répertoire off-site absent (montage indisponible), ou snapshot source absent.
    """
    src = Path(snapshot_path)
    offsite = Path(offsite_dir)
    if not src.is_file():
        raise BackupError(f"snapshot source introuvable : {src}")
    if not offsite.is_dir():
        raise BackupError(
            f"répertoire off-site absent : {offsite} — montage indisponible ? "
            "copie off-site ignorée (aucun faux off-site local créé)"
        )
    dest = offsite / src.name
    tmp = offsite / (src.name + ".tmp")
    shutil.copy2(src, tmp)
    os.replace(tmp, dest)  # rename atomique (même FS)
    return dest
