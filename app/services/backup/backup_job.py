"""Job scheduler de sauvegarde auto de la BDD locale — sous-étape 1c.

Orchestre : (opt-in `config.backup`) → snapshot cohérent (`VACUUM INTO`,
garde fail-closed anti-clair de `db_backup`) → rotation bornée.

**SSoT réutilisées** (zéro duplication) : `get_db_url` + `setup_encryption`
(MÊME hook clé SQLCipher que l'app → la connexion de backup est keyée en prod,
donc `VACUUM INTO` hérite de la clé ; en clair, no-op), `config.backup` /
`config.backups_dir`, `clock.now`. Fonction **sync** (APScheduler
BackgroundScheduler), **fail-soft** comme `cleanup_db_retention_job` : aucune
exception ré-émise vers le scheduler (le job de demain retentera).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, event

from app.core import clock
from app.core.database import get_db_url, setup_encryption
from app.services.backup.db_backup import (
    BackupEncryptionError,
    copy_to_offsite,
    prune_snapshots,
    snapshot_via_vacuum,
)

logger = logging.getLogger(__name__)

#: Format timestamp du nom de snapshot — tri lexicographique == chronologique.
_TS_FORMAT = "%Y%m%dT%H%M%S"


def _snapshot_prefix(db_path: Path) -> str:
    """Préfixe de nommage dérivé du nom de fichier BDD (générique, pas de hardcode)."""
    return f"{db_path.stem}-backup-"


def run_backup_job() -> Optional[Path]:
    """Snapshot quotidien de la BDD locale + rotation. **No-op si désactivé.**

    Returns:
        Le ``Path`` du snapshot créé, ou ``None`` (désactivé / échec fail-soft).

    Un échec de chiffrement (snapshot en clair alors que la BDD est chiffrée)
    est loggé en **CRITICAL** — jamais silencieux — et le fichier en clair a
    déjà été supprimé par la garde de :func:`snapshot_via_vacuum`.
    """
    from app.config import config

    if not config.backup.enabled:
        return None

    db_path = Path(config.database.path)
    backups_dir = Path(config.backups_dir)
    prefix = _snapshot_prefix(db_path)
    dest = backups_dir / f"{prefix}{clock.now().strftime(_TS_FORMAT)}.db"
    # Chiffrement attendu ssi une clé est configurée (même critère que l'app).
    expect_encrypted = bool(config.database.encryption_key)

    engine = create_engine(get_db_url())
    # Réutilise le hook clé canonique : 1er hook sur connexion neuve. En prod
    # SQLCipher → PRAGMA key posé → VACUUM INTO hérite de la clé. Sans clé → no-op.
    event.listen(engine, "connect", setup_encryption)
    try:
        raw = engine.raw_connection()
        try:
            dbapi = raw.driver_connection
            # VACUUM INTO interdit en transaction → autocommit (sqlite3).
            dbapi.isolation_level = None
            snapshot_via_vacuum(dbapi, dest, expect_encrypted=expect_encrypted)
        finally:
            raw.close()
    except BackupEncryptionError:
        logger.critical(
            "Backup BDD REFUSÉ : snapshot produit EN CLAIR alors que la BDD est "
            "chiffrée (fichier supprimé). Vérifier la build SQLCipher (VACUUM INTO "
            "keyé >= 4.3) — AUCUN backup n'a été conservé ce cycle.",
            exc_info=True,
        )
        return None
    except Exception:  # noqa: BLE001 — fail-soft scheduler (cf. cleanup_db_retention_job)
        logger.error("Backup BDD : échec du snapshot, skip ce cycle", exc_info=True)
        return None
    finally:
        engine.dispose()

    # Rotation best-effort : ne doit JAMAIS invalider un snapshot réussi.
    try:
        removed = prune_snapshots(
            backups_dir,
            prefix=prefix,
            keep_count=config.backup.retention_count,
            keep_days=config.backup.retention_days,
        )
        if removed:
            logger.info("Backup rotation : %d ancien(s) snapshot(s) supprimé(s)", len(removed))
    except Exception:  # noqa: BLE001 — rotation best-effort
        logger.warning("Backup rotation : échec, snapshot conservé", exc_info=True)

    # Off-site (règle 3-2-1) : copie best-effort vers config.backup.offsite_dir
    # si configuré. Un échec (montage down) est loggé en ERROR — perte de la
    # protection off-site ce cycle — mais le snapshot LOCAL reste valide, donc
    # on ne fait pas échouer le job.
    offsite_dir = config.backup.offsite_dir
    if offsite_dir:
        try:
            offsite_copy = copy_to_offsite(dest, offsite_dir)
            prune_snapshots(
                Path(offsite_dir),
                prefix=prefix,
                keep_count=config.backup.retention_count,
                keep_days=config.backup.retention_days,
            )
            logger.info("Backup off-site copié : %s", offsite_copy)
        except Exception:  # noqa: BLE001 — best-effort, snapshot local conservé
            logger.error(
                "Backup off-site ÉCHOUÉ (snapshot local conservé) — protection "
                "off-site absente ce cycle, vérifier le montage %r.",
                offsite_dir,
                exc_info=True,
            )

    logger.info("Backup BDD créé : %s", dest)
    return dest
