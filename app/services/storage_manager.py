"""
Service pour gérer le stockage utilisateur et les quotas.
Synchronise le filesystem avec la base de données.
"""

import hashlib
import mimetypes
from pathlib import Path
from typing import Final, List, Optional, Tuple

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core import clock
from app.models.user_storage import UserStorage, FileMetadata
from app.utils.logger import get_logger

logger = get_logger(__name__)

#: Quota par défaut utilisé UNIQUEMENT si AIConfig pas encore initialisé
#: (boot strap initial ou base BDD fraîche). En runtime normal, la valeur
#: vient toujours de AIConfig clé STORAGE_QUOTA_PER_USER_BYTES qui est la
#: SOURCE UNIQUE de vérité (modifiable via /admin/performance).
_DEFAULT_QUOTA_BYTES: Final[int] = 500 * 1024 * 1024  # 500 MiB


async def _get_global_quota(db: Optional[AsyncSession] = None) -> int:
    """Récupère le quota global utilisateur depuis AIConfig.

    Source UNIQUE de vérité : valeur saisie par l'admin via
    /admin/performance section "Stockage local (SQLite)". Identique
    pour TOUS les users — ignore le rôle (admin/user/reader). Fallback
    sur ``_DEFAULT_QUOTA_BYTES`` si la clé n'est pas encore en BDD
    (premier boot, avant que l'admin ait sauvé sa valeur).

    Le paramètre ``db`` est conservé pour rétro-compat d'appel mais n'est PAS
    utilisé (la valeur est lue via le cache du service AIConfig, qui gère sa
    propre session).
    """
    # Import local pour éviter les cycles : storage_manager est appelé
    # avant que ai_config soit complètement chargé dans certains tests.
    from app.services.ai.config_service import get_ai_config_service
    from app.models.ai_config import AIConfigKey

    try:
        svc = get_ai_config_service()
        value = await svc.get(AIConfigKey.STORAGE_QUOTA_PER_USER_BYTES)
        if value is not None and isinstance(value, int) and value > 0:
            return value
    except Exception as exc:
        logger.warning("Lecture quota depuis AIConfig échouée (fallback default) : %s", exc)
    return _DEFAULT_QUOTA_BYTES


async def get_storage_quota_bytes() -> int:
    """SSoT runtime du quota de stockage par utilisateur (octets).

    Valeur admin (/admin/performance → ``STORAGE_QUOTA_PER_USER_BYTES``),
    identique pour tous les users. **SOURCE UNIQUE de toutes les limites de
    classeur** : borne le stockage disque ET — depuis la suppression des caps
    de décompression hardcodés — la taille DÉCOMPRESSÉE maximale d'un
    ``.afz.json`` (sauvegarde / lecture / export anonymisé / téléchargement).

    ⚠️ Conséquence mémoire : comme la décompression d'un ``.afz.json`` se fait
    en RAM, ce quota borne aussi le pic mémoire d'une requête. L'admin doit
    donc le dimensionner en connaissant la RAM du conteneur (le défaut 500 Mio
    est sûr ; au-delà de ~800 Mio sur un conteneur ~3 Gio, surveiller l'OOM,
    surtout sous concurrence ou sur le chemin export anonymisé ≈ 3× la taille).
    """
    return await _get_global_quota()


def get_storage_quota_bytes_sync() -> int:
    """Version SYNCHRONE de :func:`get_storage_quota_bytes` (lit le cache
    AIConfig en mémoire) — pour les chemins de décompression exécutés dans un
    thread (``asyncio.to_thread``) qui ne peuvent pas ``await``.

    Fail-safe : si le cache AIConfig n'est pas encore chargé (boot à froid),
    retombe sur ``_DEFAULT_QUOTA_BYTES`` (500 Mio) — JAMAIS une valeur trop
    petite qui bloquerait à tort un classeur légitime.
    """
    from app.services.ai.config_service import get_ai_config_service
    from app.models.ai_config import AIConfigKey

    try:
        svc = get_ai_config_service()
        value = svc.get_cached_sync(AIConfigKey.STORAGE_QUOTA_PER_USER_BYTES, _DEFAULT_QUOTA_BYTES)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    except Exception as exc:
        logger.warning("Lecture quota (sync) échouée (fallback default) : %s", exc)
    return _DEFAULT_QUOTA_BYTES


class StorageManager:
    """Gestionnaire centralisé du stockage utilisateur."""

    def __init__(self, db: AsyncSession, datastore_root: Path):
        self.db = db
        self.datastore_root = datastore_root

    async def get_or_create_user_storage(self, user_id: int, role: str = "user") -> UserStorage:
        """Récupère ou crée l'enregistrement de stockage utilisateur.

        Le ``quota_limit`` du UserStorage est synchronisé à chaque appel
        avec la valeur globale lue depuis AIConfig (clé
        ``STORAGE_QUOTA_PER_USER_BYTES``). Permet à un changement admin
        via /admin/performance de s'appliquer immédiatement à tous les
        users, sans batch script. Le paramètre ``role`` est conservé
        pour rétro-compat de signature mais N'EST PLUS consulté — le
        quota est identique pour TOUS les rôles (intent user 2026-05-14).
        """
        result = await self.db.execute(select(UserStorage).where(UserStorage.user_id == user_id))
        storage = result.scalar_one_or_none()

        global_quota = await _get_global_quota(self.db)

        if storage is None:
            storage = UserStorage(
                user_id=user_id, quota_limit=global_quota, quota_used=0, file_count=0
            )
            self.db.add(storage)
            # Savepoint anti-TOCTOU : deux 1ers uploads concurrents du MÊME user
            # ont chacun lu ``scalar_one_or_none() is None`` ci-dessus avant que
            # l'autre n'ait flushé → le 2e INSERT viole l'unique ``user_id`` →
            # IntegrityError. Sans garde, ça remonte en 500 (le wrapper de retry
            # upload ne rattrape que ``OperationalError`` locked). On isole
            # l'INSERT dans un savepoint : sur collision, on rollback CE savepoint
            # (PAS la session, qui peut porter le ``FileMetadata`` pending de
            # ``register_upload``), on retire l'instance en double, puis on relit
            # la row gagnante. Pattern aligné sur ``contact_service.batch_add_members``.
            savepoint = await self.db.begin_nested()
            try:
                await self.db.flush()
                await savepoint.commit()
            except IntegrityError:
                await savepoint.rollback()
                self.db.expunge(storage)
                storage = (
                    await self.db.execute(select(UserStorage).where(UserStorage.user_id == user_id))
                ).scalar_one()
                logger.info(
                    "Stockage user_id=%s résolu après race concurrente (1er upload)", user_id
                )
            else:
                await self.db.refresh(storage)
                logger.info(
                    "Stockage créé pour user_id=%s, quota=%s", user_id, _human_size(global_quota)
                )
        else:
            # Sync : si l'admin a changé la valeur globale via /admin/performance,
            # le ``quota_limit`` individuel doit refléter cette valeur pour que
            # ``can_upload`` retourne la bonne décision. Try/except défensif pour
            # tolérer les Mocks de tests (Mock != int → comparaison non-déterministe).
            try:
                if isinstance(storage.quota_limit, int) and storage.quota_limit != global_quota:
                    old = storage.quota_limit
                    storage.quota_limit = global_quota
                    await self.db.flush()
                    logger.info(
                        "Quota user_id=%s resynced %s → %s (config admin)",
                        user_id,
                        _human_size(old),
                        _human_size(global_quota),
                    )
            except (TypeError, AttributeError):
                pass  # storage est probablement un Mock en test ; on n'écrase pas

        return storage

    async def check_quota(self, user_id: int, file_size: int) -> Tuple[bool, Optional[str]]:
        """
        Vérifie si l'utilisateur peut uploader un fichier.

        Returns:
            (can_upload: bool, error_message: Optional[str])
        """
        storage = await self.get_or_create_user_storage(user_id)
        return storage.can_upload(file_size)

    async def register_upload(
        self,
        user_id: int,
        file_path: Path,
        relative_path: str,
        description: Optional[str] = None,
        file_size: Optional[int] = None,
        file_hash: Optional[str] = None,
    ) -> FileMetadata:
        """
        Enregistre un nouveau fichier uploadé dans la DB.
        Met à jour les quotas utilisateur.

        Utilise flush() au lieu de commit() pour permettre au handler appelant
        de gérer la transaction atomiquement (commit/rollback via get_session).

        Args:
            file_size: Si fourni, évite de lire le fichier sur disque (utile pour DB-first).
            file_hash: Si fourni, évite de calculer le hash depuis le disque.
        """
        actual_size = file_size if file_size is not None else file_path.stat().st_size
        actual_hash = file_hash or _calculate_file_hash(file_path)
        mime_type = mimetypes.guess_type(str(file_path))[0]

        metadata = FileMetadata(
            user_id=user_id,
            file_path=relative_path,
            file_hash=actual_hash,
            filename=file_path.name,
            extension=file_path.suffix.lower(),
            mime_type=mime_type or "application/octet-stream",
            size_bytes=actual_size,
            description=description,
        )
        self.db.add(metadata)

        # Assure l'existence de la row (création au 1er upload) AVANT l'UPDATE.
        await self.get_or_create_user_storage(user_id)
        # Incrément ATOMIQUE (UPDATE ... SET col = col + N) plutôt qu'un
        # read-modify-write Python : sous uploads concurrents du même user
        # (multi-onglets / double-clic), un RMW perdrait un incrément →
        # quota_used SOUS-compté = quota contournable + usage faux sur /dashboard.
        await self.db.execute(
            update(UserStorage)
            .where(UserStorage.user_id == user_id)
            .values(
                quota_used=UserStorage.quota_used + actual_size,
                file_count=UserStorage.file_count + 1,
                last_upload=int(clock.timestamp()),
            )
        )

        await self.db.flush()
        logger.info(
            "Upload enregistré : %s (%s) pour user_id=%s",
            relative_path,
            _human_size(actual_size),
            user_id,
        )
        return metadata

    async def register_deletion(self, user_id: int, relative_path: str) -> bool:
        """
        Enregistre la suppression d'un fichier.
        Met à jour les quotas utilisateur.

        Returns:
            True si supprimé, False si fichier non trouvé en DB
        """
        result = await self.db.execute(
            select(FileMetadata)
            .where(FileMetadata.user_id == user_id)
            .where(FileMetadata.file_path == relative_path)
        )
        metadata = result.scalar_one_or_none()

        if metadata is None:
            logger.warning("Fichier non trouvé en DB : %s", relative_path)
            return False

        # Mettre à jour les quotas. NB : décrément VOLONTAIREMENT en SET absolu
        # (max(0, used - size)) et NON en UPDATE relatif (used = used - size).
        # Sous deux suppressions concurrentes du MÊME fichier, un relatif
        # double-décrémenterait (→ quota sous-compté = bypass) ; le SET absolu
        # collapse les deux en un seul décrément. La dérive inverse (sur-compte
        # sous suppressions de fichiers DIFFÉRENTS en concurrence) est bénigne
        # (quota plus strict) et réconciliée par sync_user_storage. L'upload, lui,
        # est en incrément atomique car son cas non-atomique sous-compte (bypass).
        storage = await self.get_or_create_user_storage(user_id)
        storage.quota_used = max(0, storage.quota_used - metadata.size_bytes)
        storage.file_count = max(0, storage.file_count - 1)

        await self.db.delete(metadata)
        await self.db.flush()

        logger.info(
            "Suppression enregistrée : %s (%s) pour user_id=%s",
            relative_path,
            _human_size(metadata.size_bytes),
            user_id,
        )
        return True

    async def sync_user_storage(self, user_id: int) -> dict:
        """
        Synchronise le stockage utilisateur entre filesystem et DB.
        Utile après migration ou correction d'incohérences.

        Returns:
            dict avec statistiques de synchronisation
        """
        user_dir = self.datastore_root / str(user_id)
        if not user_dir.exists():
            return {"synced": 0, "errors": [], "status": "no_directory"}

        # Scanner le filesystem
        files_on_disk = {}
        for file_path in user_dir.rglob("*"):
            if file_path.is_file():
                rel_path = str(file_path.relative_to(user_dir))
                files_on_disk[rel_path] = file_path

        # Récupérer fichiers en DB
        result = await self.db.execute(select(FileMetadata).where(FileMetadata.user_id == user_id))
        files_in_db = {m.file_path: m for m in result.scalars().all()}

        synced = 0
        errors = []

        # Ajouter fichiers manquants en DB
        for rel_path, file_path in files_on_disk.items():
            if rel_path not in files_in_db:
                try:
                    await self.register_upload(user_id, file_path, rel_path)
                    synced += 1
                except (OSError, SQLAlchemyError):
                    logger.warning("Erreur sync fichier %s", rel_path, exc_info=True)
                    errors.append(f"{rel_path}: erreur synchronisation")

        # Supprimer métadonnées orphelines (fichiers supprimés du disque)
        for rel_path, metadata in files_in_db.items():
            if rel_path not in files_on_disk:
                try:
                    await self.db.delete(metadata)
                    synced += 1
                except SQLAlchemyError:
                    logger.warning("Erreur suppression métadonnée %s", rel_path, exc_info=True)
                    errors.append(f"{rel_path}: erreur suppression")

        # Recalculer les quotas
        storage = await self.get_or_create_user_storage(user_id)
        storage.quota_used = sum(f.stat().st_size for f in files_on_disk.values())
        storage.file_count = len(files_on_disk)

        await self.db.commit()

        logger.info(
            "Sync terminé pour user_id=%s: %d fichiers, %d erreurs",
            user_id,
            synced,
            len(errors),
        )

        return {
            "synced": synced,
            "errors": errors,
            "total_files": len(files_on_disk),
            "quota_used": storage.quota_used,
            "status": "success" if not errors else "partial",
        }

    async def get_storage_stats(self, user_id: int) -> dict:
        """Récupère les statistiques de stockage d'un utilisateur.

        **Phase 2 (2026-04-27)** : refresh on-demand de ``db_bytes_used``
        avant d'agréger. L'utilisateur voit toujours un quota à jour quand
        il ouvre la page (sinon il reste avec la valeur du dernier job
        quotidien à 02:00, jusqu'à 24h de retard). Coût ~10-100ms — invisible.
        Le job quotidien reste utile pour pré-calculer hors interaction
        et pour les dashboards admin (vue agrégée multi-users).
        """
        from app.services.db_usage import (
            compute_db_bytes_breakdown,
            update_user_db_usage,
        )

        # Refresh on-demand : recalcule ``db_bytes_used`` AVANT de lire
        # le UserStorage. Best-effort : si fail, on garde la valeur cached
        # plutôt que de bloquer l'affichage du quota.
        try:
            await update_user_db_usage(self.db, user_id, commit=False)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "get_storage_stats: refresh db_bytes_used user=%s fail (%s) — "
                "valeur cached utilisée",
                user_id,
                exc,
            )

        storage = await self.get_or_create_user_storage(user_id)

        # Distribution par type de fichier
        result = await self.db.execute(
            select(FileMetadata.extension, FileMetadata.size_bytes).where(
                FileMetadata.user_id == user_id
            )
        )

        by_extension = {}
        for ext, size in result.all():
            ext = ext or "(sans ext)"
            if ext not in by_extension:
                by_extension[ext] = {"count": 0, "size": 0}
            by_extension[ext]["count"] += 1
            by_extension[ext]["size"] += size

        # Breakdown par table BDD (Phase 2) — pour tooltip / vue détaillée.
        try:
            db_breakdown = await compute_db_bytes_breakdown(self.db, user_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_storage_stats: db_breakdown user=%s fail (%s)", user_id, exc)
            db_breakdown = {}

        file_bytes = storage.quota_used or 0
        db_bytes = storage.db_bytes_used or 0
        total = file_bytes + db_bytes

        return {
            "quota_limit": storage.quota_limit,
            # Champs historiques préservés pour compat templates existants.
            # ``quota_used`` reste le BYTES FICHIERS (pas le total), pour
            # ne pas casser les rendus qui affichent "fichiers".
            "quota_used": file_bytes,
            "quota_percent": storage.quota_percent,  # déjà sur total via property
            "quota_remaining": storage.quota_remaining,  # déjà sur total
            "file_count": storage.file_count,
            "total_files": storage.file_count,
            "total_size_human": _human_size(file_bytes),
            "by_extension": dict(sorted(by_extension.items(), key=lambda x: -x[1]["size"])[:10]),
            "last_upload": storage.last_upload,
            # Phase 2 — breakdown BDD ajouté
            "file_bytes": file_bytes,
            "file_bytes_human": _human_size(file_bytes),
            "db_bytes": db_bytes,
            "db_bytes_human": _human_size(db_bytes),
            "db_breakdown": {
                table: {"bytes": b, "human": _human_size(b)} for table, b in db_breakdown.items()
            },
            "total_used": total,
            "total_used_human": _human_size(total),
        }

    async def search_files(
        self,
        user_id: int,
        query: Optional[str] = None,
        extension: Optional[str] = None,
        limit: int = 50,
    ) -> List[FileMetadata]:
        """
        Recherche rapide dans les métadonnées (indexées).
        Plus performant que scanner le filesystem.
        """
        stmt = select(FileMetadata).where(FileMetadata.user_id == user_id)

        if query:
            # Escape LIKE wildcards in user input to prevent pattern injection
            safe_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(FileMetadata.filename.ilike(f"%{safe_query}%", escape="\\"))

        if extension:
            stmt = stmt.where(FileMetadata.extension == extension.lower())

        stmt = stmt.order_by(FileMetadata.created_at.desc()).limit(limit)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())


def _calculate_file_hash(file_path: Path) -> str:
    """Calcule le SHA-256 d'un fichier sur disque."""
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_hash_from_bytes(data: bytes) -> str:
    """Calcule le SHA-256 depuis des bytes en mémoire (évite l'accès disque)."""
    return hashlib.sha256(data).hexdigest()


def sanitize_csv_value(value) -> str:
    """
    Neutralise les formules CSV potentiellement dangereuses (CSV Injection / DDE attack).
    Préfixe avec une apostrophe les valeurs commençant par des caractères dangereux.
    Excel ignore l'apostrophe de tête lors de l'affichage.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "|", "\t", "\r"):
        return f"'{s}"
    return s


def _human_size(size: int) -> str:
    """Conversion octets → format lisible."""
    for unit in ("o", "Ko", "Mo", "Go"):
        if abs(size) < 1024:
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"
