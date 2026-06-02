"""Sauvegarde automatique de la BDD locale (SQLite/SQLCipher).

Sous-package introduit par le loop d'implémentation déploiement (TODO #1).
- ``db_backup`` : mécanisme de snapshot cohérent + sûr (fail-closed anti-clair)
  et rotation. La connexion est injectée (découplé du moteur async, testable).

Le câblage scheduler + engine + config vit dans la sous-étape 1c.
"""

from app.services.backup.backup_job import run_backup_job
from app.services.backup.db_backup import (
    BackupEncryptionError,
    BackupError,
    copy_to_offsite,
    is_plaintext_sqlite,
    prune_snapshots,
    snapshot_via_vacuum,
)

__all__ = (
    "BackupError",
    "BackupEncryptionError",
    "is_plaintext_sqlite",
    "snapshot_via_vacuum",
    "prune_snapshots",
    "copy_to_offsite",
    "run_backup_job",
)
