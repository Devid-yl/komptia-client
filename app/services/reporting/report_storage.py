"""
Service de stockage et archivage des rapports.
US-4.5 : Stockage & Archivage Rapports

Gère le cycle de vie complet des fichiers de rapports :
- Sauvegarde avec métadonnées en BDD
- Téléchargement sécurisé
- Partage via token temporaire
- Nettoyage automatique (rétention configurable)
"""

import secrets
from pathlib import Path
from typing import Any, Optional, Tuple, List

from sqlalchemy import and_, case, func, or_, select, update

from app.core import clock
from app.core.database import get_session
from app.models.report import Report
from app.utils.logger import get_logger
from app.constants import DEFAULT_RETENTION_DAYS, SHARE_LINK_EXPIRY_HOURS, MAX_UPLOAD_BYTES
from app.config import REPORTS_DIR

logger = get_logger(__name__)

# Formats autorisés
ALLOWED_FORMATS = {"pdf", "csv", "xlsx"}
# Garde-fou de taille pour les rapports STOCKÉS. ``MAX_UPLOAD_BYTES`` vaut ~1 TiB
# (« pratiquement infini ») : pour un rapport GÉNÉRÉ en interne (PDF/xlsx d'une
# automation), il n'y a pas de cap métier — un rapport légitime peut être
# volumineux. Pour l'UPLOAD d'un rapport par l'utilisateur, la vraie limite est
# le SSoT admin ``get_max_upload_size_bytes()`` (/admin/performance), appliquée
# en amont dans ``ReportsAPIHandler.post``.
MAX_FILE_SIZE = MAX_UPLOAD_BYTES

# Taille max EN OCTETS du fragment "nom original sanitisé" intégré au nom de
# fichier de stockage. Le nom complet (timestamp + token + safe_name + extension)
# doit rester sous NAME_MAX (255 octets sur ext4/APFS) — sinon ``write_bytes``
# lève ``OSError`` et l'upload remonte en 500 au lieu d'aboutir. 200 octets laisse
# une marge confortable (préfixe horodaté + token + extension ≈ 40 octets → total
# ≤ ~238). Aligné sur l'esprit du cap de la génération (``_MAX_REPORT_FILE_NAME_BASE``).
_MAX_STORED_FILE_NAME_LEN: int = 200


def _build_stored_filename(file_name: str, file_format: str) -> str:
    """Construit le nom de fichier de stockage : unique, borné, extension sûre.

    * **Sanitize** : tout caractère hors ``[alnum]`` / ``-_.`` → ``_`` — neutralise
      les séparateurs de chemin (``/``, ``\\``) donc pas de path traversal.
    * **Tronque** ``safe_name`` à :data:`_MAX_STORED_FILE_NAME_LEN` pour que le nom
      complet reste sous NAME_MAX (255). Sans ce cap, un filename client de 230+
      caractères fait lever ``OSError`` à ``write_bytes`` → 500.
    * **Unicité** : préfixe ``timestamp + token_hex`` garantie même après troncature.
    * **Extension** : ré-assurée (la troncature a pu la rogner).
    """
    timestamp = clock.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in file_name)
    # Tronque par OCTETS, pas par caractères : NAME_MAX est en octets, et
    # ``str.isalnum()`` conserve les lettres unicode (``é``, ``中``…). Un nom de
    # 200 caractères accentués = ~400 octets → dépasserait quand même NAME_MAX.
    # ``decode(errors="ignore")`` jette un caractère multi-octets coupé au bord.
    safe_name = safe_name.encode("utf-8")[:_MAX_STORED_FILE_NAME_LEN].decode("utf-8", "ignore")
    # token_hex(8) = 64 bits : le timestamp est à la seconde, donc deux uploads
    # la même seconde ne se distinguent QUE par le token. À 32 bits, une collision
    # (improbable mais non nulle) écraserait SILENCIEUSEMENT le fichier du 1er
    # rapport par le 2e (data corruption silencieuse — pire qu'un crash). 64 bits
    # rend ça astronomique pour un coût d'un caractère (nom complet ≤ ~238 octets).
    unique_name = f"{timestamp}_{secrets.token_hex(8)}_{safe_name}"
    if not unique_name.endswith(f".{file_format}"):
        unique_name = f"{unique_name}.{file_format}"
    return unique_name


class ReportStorage:
    """
    Gère le stockage physique (filesystem) et logique (BDD) des rapports.
    """

    def __init__(self):
        # Créer le répertoire de stockage s'il n'existe pas
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("📁 ReportStorage initialisé – dossier : %s", REPORTS_DIR)

    # ------------------------------------------------------------------
    # CRUD opérations
    # ------------------------------------------------------------------

    async def save_report(
        self,
        file_content: bytes,
        file_name: str,
        title: str,
        file_format: str = "pdf",
        description: Optional[str] = None,
        report_type: str = "custom",
        user_id: Optional[int] = None,
        automation_id: Optional[int] = None,
        execution_id: Optional[int] = None,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> Report:
        """
        Sauvegarde un rapport (fichier + métadonnées).

        Args:
            file_content: Contenu binaire du fichier.
            file_name: Nom original du fichier.
            title: Titre affiché dans l'UI.
            file_format: Extension (pdf, csv, xlsx).
            description: Résumé optionnel.
            report_type: Catégorie du rapport.
            user_id: Propriétaire.
            automation_id: Automatisation source (optionnel).
            execution_id: Exécution source (optionnel).
            retention_days: Durée de rétention en jours.

        Returns:
            Instance Report persistée.
        """
        if file_format not in ALLOWED_FORMATS:
            raise ValueError(f"Format non autorisé : {file_format}. Autorisés : {ALLOWED_FORMATS}")

        if len(file_content) > MAX_FILE_SIZE:
            raise ValueError(
                f"Fichier trop volumineux ({len(file_content)} octets). Max : {MAX_FILE_SIZE}"
            )

        # Nom de stockage unique + borné (sanitize + cap NAME_MAX + extension).
        # Cf. _build_stored_filename : sans le cap, un filename de 230+ caractères
        # ferait lever OSError à write_bytes → 500 au lieu d'un upload propre.
        unique_name = _build_stored_filename(file_name, file_format)

        # Préparer le chemin AVANT le try pour qu'il soit accessible dans
        # le finally (cleanup orphelin si la persistance BDD échoue).
        file_path = REPORTS_DIR / unique_name

        # Prod-loop task #17 (axe 21 — growth bounded) : sans ce try/finally,
        # si ``write_bytes`` réussit puis la persistance BDD échoue
        # (FK violation, BDD locked, ``session.flush`` raise, commit auto
        # du ``async with`` raise…), le fichier reste sur disque sans
        # ``Report`` correspondant → orphelin invisible par
        # ``cleanup_expired`` (qui itère uniquement sur ``Report.file_path``).
        # Pattern miroir de la task #11 (``delivery_service.py`` cleanup
        # tempfile quand SMTP raise).
        #
        # try/finally (PLUTÔT que try/except + raise) pour couvrir aussi
        # ``BaseException`` — notamment ``asyncio.CancelledError`` qui peut
        # remonter pendant le shutdown APScheduler ou le recycle Tornado.
        # Le flag ``persisted`` est mis à True UNIQUEMENT après que le
        # ``async with get_session()`` ait exited proprement (= commit auto
        # réussi). Si une exception (Exception OU BaseException) remonte
        # à n'importe quel point avant ce moment, ``persisted`` reste False
        # et le finally supprime l'orphelin.
        persisted = False
        try:
            # Écrire sur le filesystem
            file_path.write_bytes(file_content)
            file_size = len(file_content)

            logger.info("💾 Fichier rapport écrit : %s (%s octets)", file_path, file_size)

            # Persister les métadonnées en BDD
            async with get_session() as session:
                report = Report(
                    title=title,
                    description=description,
                    report_type=report_type,
                    file_path=str(unique_name),  # chemin relatif à REPORTS_DIR
                    file_name=file_name,
                    file_format=file_format,
                    file_size=file_size,
                    created_by_user_id=user_id,
                    automation_id=automation_id,
                    execution_id=execution_id,
                    retention_days=retention_days,
                )
                session.add(report)
                await session.flush()
                await session.refresh(report)

                logger.info("✅ Rapport #%s '%s' sauvegardé", report.id, title)

                # Tracking T3.1 — incrémente ``total_reports_generated`` +
                # maj ``last_report_generated_at`` côté ``UserActivitySummary``.
                # Wrapped dans ``begin_nested()`` (savepoint) : sans isolation,
                # un échec du tracker (BDD locked, FK violation théorique...)
                # mettrait la session en ``pending_rollback`` → le commit auto
                # de ``get_session()`` à la sortie crasherait → l'INSERT du
                # rapport serait annulé. Or le fichier est déjà sur disque
                # → orphelin filesystem. Le savepoint cantonne tout échec
                # du tracker à lui-même, le rapport reste persisté.
                try:
                    from app.services.onboarding import track_report_generated

                    async with session.begin_nested():
                        await track_report_generated(session, user_id)
                except Exception:  # noqa: BLE001 — fail-soft télémétrie
                    logger.debug("track_report_generated non écrit", exc_info=True)

            # ⚠️ Si on arrive ICI, ``__aexit__`` du ``async with`` (commit
            # auto) a réussi → le ``Report`` est durablement persisté en
            # BDD. C'est SEULEMENT à ce moment qu'on peut désactiver le
            # cleanup orphelin (``expire_on_commit=False`` rend les
            # attributs de ``report`` accessibles après session.close()).
            persisted = True
            return report
        finally:
            if not persisted:
                # Cleanup orphelin filesystem. ``missing_ok=True`` gère
                # deux cas : (a) ``write_bytes`` lui-même raise → fichier
                # non créé → unlink silencieux ; (b) write OK puis BDD
                # raise → fichier supprimé.
                try:
                    file_path.unlink(missing_ok=True)
                except OSError as cleanup_err:
                    # Le cleanup ne doit pas masquer l'exception métier
                    # (qui propage naturellement après le finally). On
                    # log uniquement (sinon orphelin invisible côté admin).
                    logger.warning(
                        "⚠️ Cleanup orphelin %s impossible : %s",
                        file_path,
                        cleanup_err,
                    )

    async def get_report(self, report_id: int) -> Optional[Report]:
        """Récupère un rapport par son ID."""
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            return result.scalar_one_or_none()

    async def get_report_by_share_token(self, token: str) -> Optional[Report]:
        """Récupère un rapport via son token de partage."""
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.share_token == token))
            return result.scalar_one_or_none()

    async def list_reports(
        self,
        user_id: Optional[int] = None,
        report_type: Optional[str] = None,
        file_format: Optional[str] = None,
        search: Optional[str] = None,
        is_archived: Optional[bool] = None,
        page: int = 1,
        per_page: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> Tuple[List[Report], int]:
        """
        Liste les rapports avec filtres et pagination.

        Returns:
            Tuple (list[Report], total_count)
        """
        async with get_session() as session:
            query = select(Report)

            if user_id is not None:
                query = query.where(Report.created_by_user_id == user_id)
            if report_type:
                query = query.where(Report.report_type == report_type)
            if file_format:
                query = query.where(Report.file_format == file_format)
            if is_archived is not None:
                query = query.where(Report.is_archived == is_archived)
            if search:
                safe_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                pattern = f"%{safe_search}%"
                query = query.where(
                    Report.title.ilike(pattern, escape="\\")
                    | Report.description.ilike(pattern, escape="\\")
                )

            # Total
            count_q = select(func.count()).select_from(query.subquery())
            total = (await session.execute(count_q)).scalar() or 0

            # Tri
            allowed_sorts = {"title", "file_format", "file_size", "created_at", "is_archived"}
            col_name = sort_by if sort_by in allowed_sorts else "created_at"
            sort_col = getattr(Report, col_name)
            order = sort_col.asc() if sort_order == "asc" else sort_col.desc()
            # Tie-breaker déterministe sur ``id`` (clé unique) : sans lui, un tri
            # sur une colonne à FAIBLE cardinalité (``file_format`` = 3 valeurs,
            # ``is_archived`` = 2) laisse l'ordre des ex-æquo NON spécifié par
            # SQL → en pagination OFFSET, un rapport peut être sauté ou dupliqué
            # entre deux pages (skip/doublon silencieux). Même garantie « tri
            # stable, paginer sans doublon ni saut » que
            # ``email_history_service`` (ORDER BY ..., id). Direction alignée
            # sur le tri primaire pour un tie-break cohérent.
            id_order = Report.id.asc() if sort_order == "asc" else Report.id.desc()
            query = query.order_by(order, id_order)
            query = query.offset((page - 1) * per_page).limit(per_page)

            rows = (await session.execute(query)).scalars().all()
            return rows, total

    async def delete_report(self, report_id: int) -> bool:
        """
        Supprime un rapport (fichier + métadonnées).
        Returns True si supprimé.
        """
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return False

            # Supprimer le fichier physique (avec protection path traversal).
            # ``is_relative_to`` (≠ ``str.startswith``) : évite que
            # "data/reports_evil" matche le préfixe "data/reports". Cohérent
            # avec ``datastore._safe_path``.
            file_path = (REPORTS_DIR / report.file_path).resolve()
            if not file_path.is_relative_to(REPORTS_DIR.resolve()):
                # Branche normalement inatteignable (``file_path`` est généré
                # serveur + sanitizé). On loggue plutôt que de skip en silence
                # pour ne jamais laisser un orphelin invisible (parité avec
                # ``get_file_path``).
                logger.warning(
                    "Path traversal au delete (report_id=%s) — fichier ignoré : %s",
                    report_id,
                    report.file_path,
                )
            elif file_path.exists():
                file_path.unlink()
                logger.info("Fichier supprimé : %s", file_path)

            await session.delete(report)
            logger.info("✅ Rapport #%s supprimé", report_id)
            return True

    # ------------------------------------------------------------------
    # Partage sécurisé
    # ------------------------------------------------------------------

    async def create_share_link(
        self, report_id: int, expires_hours: int = SHARE_LINK_EXPIRY_HOURS
    ) -> Optional[str]:
        """
        Génère un lien de partage temporaire pour un rapport.

        Returns:
            Token de partage ou None si rapport introuvable.
        """
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return None

            token = report.generate_share_token(expires_hours=expires_hours)
            logger.info(
                "🔗 Lien de partage créé pour rapport #%s (expire dans %sh)",
                report_id,
                expires_hours,
            )
            return token

    async def revoke_share_link(self, report_id: int) -> bool:
        """Révoque le lien de partage d'un rapport."""
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return False

            report.share_token = None
            report.share_expires_at = None
            logger.info("🔒 Lien de partage révoqué pour rapport #%s", report_id)
            return True

    async def increment_download_count(self, report_id: int) -> None:
        """Incrémente le compteur de téléchargements partagés — **atomiquement**.

        ``UPDATE ... SET col = col + 1`` (incrément côté BDD) plutôt qu'un
        read-modify-write Python : sous téléchargements concurrents du même
        lien de partage public, deux requêtes liraient N et écriraient toutes
        deux N+1 → incrément perdu (sous-comptage, donnée fausse silencieuse).
        ``share_download_count`` est NOT NULL (défaut 0) → pas de COALESCE.
        """
        async with get_session() as session:
            await session.execute(
                update(Report)
                .where(Report.id == report_id)
                .values(share_download_count=Report.share_download_count + 1)
            )

    # ------------------------------------------------------------------
    # Archivage & Rétention
    # ------------------------------------------------------------------

    async def toggle_archive(self, report_id: int) -> Optional[bool]:
        """
        Bascule l'état archivé d'un rapport.
        Returns le nouvel état ou None.
        """
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return None

            report.is_archived = not report.is_archived
            state = "archivé" if report.is_archived else "désarchivé"
            logger.info("Rapport #%s %s", report_id, state)
            return report.is_archived

    async def set_archive(self, report_id: int, archived: bool) -> Optional[bool]:
        """
        Force l'état archivé d'un rapport à la valeur demandée.
        Returns le nouvel état ou None si le rapport n'existe pas.
        """
        async with get_session() as session:
            result = await session.execute(select(Report).where(Report.id == report_id))
            report = result.scalar_one_or_none()
            if not report:
                return None

            report.is_archived = archived
            state = "archivé" if archived else "désarchivé"
            logger.info("Rapport #%s %s (forcé)", report_id, state)
            return report.is_archived

    async def cleanup_expired(self) -> int:
        """
        Supprime les rapports ayant dépassé leur période de rétention.
        Les rapports archivés sont épargnés.

        Returns:
            Nombre de rapports supprimés.
        """
        deleted_count = 0
        file_paths_to_delete = []

        async with get_session() as session:
            # Récupérer les rapports non-archivés
            result = await session.execute(
                select(Report).where(Report.is_archived == False)  # noqa: E712
            )
            reports = result.scalars().all()

            for report in reports:
                if report.is_expired:
                    # Collecter le chemin pour suppression ultérieure
                    file_path = (REPORTS_DIR / report.file_path).resolve()
                    if not file_path.is_relative_to(REPORTS_DIR.resolve()):
                        logger.warning(
                            "Path traversal au cleanup (report_id=%s) — fichier ignoré : %s",
                            report.id,
                            report.file_path,
                        )
                    elif file_path.exists():
                        file_paths_to_delete.append(file_path)

                    await session.delete(report)
                    deleted_count += 1

            # Commit avant suppression des fichiers
            await session.commit()

        # Supprimer les fichiers physiques après commit
        for file_path in file_paths_to_delete:
            try:
                file_path.unlink()
            except OSError as e:
                logger.warning("⚠️ Erreur suppression fichier %s: %s", file_path, e)

        if deleted_count:
            logger.info(
                "🧹 Nettoyage automatique : %s rapport(s) expiré(s) supprimé(s)", deleted_count
            )

        return deleted_count

    async def get_storage_stats(self, user_id: Optional[int] = None) -> dict:
        """Statistiques de stockage des rapports.

        Si ``user_id`` est fourni, restreint le calcul aux rapports du user
        (mêmes filtres que ``list_reports`` → cohérence garantie entre le
        bandeau "Total / Taille totale" et la liste affichée). Si ``user_id``
        est ``None`` (admin), agrège sur l'ensemble.

        **Sécurité (cross-user leak)** : sans ce filtre, la page ``/reports``
        d'un user fraîchement créé affichait le total ``count(*)`` et
        ``sum(file_size)`` de tous les rapports tous comptes confondus,
        révélant le volume d'activité des autres utilisateurs (issue 2026-05-22).
        """
        async with get_session() as session:
            base_where: Optional[Any] = None
            if user_id is not None:
                base_where = Report.created_by_user_id == user_id

            # A3-F6 : ne compter que les partages ENCORE VALIDES (même critère que
            # ``Report.is_share_valid`` : token présent ET non expiré). Avant, un
            # lien simplement expiré (token non purgé) gonflait « Partagés » alors
            # que /share/report renvoie 404 et que le badge ligne le dit non-partagé.
            _now = clock.now()
            _share_valid = and_(
                Report.share_token.isnot(None),
                or_(
                    Report.share_expires_at.is_(None),
                    Report.share_expires_at > _now,
                ),
            )
            stats_q = select(
                func.count(Report.id).label("total_reports"),
                func.sum(Report.file_size).label("total_size"),
                func.count(case((_share_valid, Report.id))).label("shared_reports"),
            )
            if base_where is not None:
                stats_q = stats_q.where(base_where)
            result = await session.execute(stats_q)
            stats = result.one()

            archived_q = select(func.count(Report.id)).where(
                Report.is_archived == True  # noqa: E712
            )
            if base_where is not None:
                archived_q = archived_q.where(base_where)
            archived_count = (await session.execute(archived_q)).scalar() or 0

            return {
                "total_reports": stats.total_reports or 0,
                "total_size": stats.total_size or 0,
                "total_size_human": self._human_size(stats.total_size or 0),
                "shared_reports": stats.shared_reports or 0,
                "archived_reports": archived_count,
            }

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convertit des octets en format lisible."""
        for unit in ("o", "Ko", "Mo", "Go"):
            if size_bytes < 1024:
                return f"{size_bytes:.0f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} To"

    def get_file_path(self, report: Report) -> Optional[Path]:
        """Retourne le chemin absolu du fichier, ou None si inexistant."""
        full_path = (REPORTS_DIR / report.file_path).resolve()
        # Path traversal protection : ``is_relative_to`` (≠ ``str.startswith``)
        # pour que "data/reports_evil" ne matche pas le préfixe "data/reports".
        if not full_path.is_relative_to(REPORTS_DIR.resolve()):
            logger.warning("Path traversal détecté dans report file_path: %s", report.file_path)
            return None
        return full_path if full_path.exists() else None


# Singleton
_storage: Optional[ReportStorage] = None


def get_report_storage() -> ReportStorage:
    """Retourne l'instance singleton du service de stockage."""
    global _storage
    if _storage is None:
        _storage = ReportStorage()
    return _storage
