"""Per-user BDD storage accounting (Phase 2).

Le quota :class:`UserStorage.quota_used` ne couvrait historiquement que les
fichiers (datastore filesystem). Plusieurs tables BDD scopées ``user_id``
(anonymization_terms, conversations, search_history, audit, dashboard, …)
peuvent croître sans borne pour un user actif et accumulent des dizaines
de Mo invisibles au quota.

Ce module ajoute l'accounting BDD complémentaire :

- :func:`compute_db_bytes_breakdown` retourne un mapping ``{table: bytes}``
  par user en sommant ``LENGTH`` des colonnes texte significatives + un
  overhead constant par row (id, FKs, timestamps).
- :func:`compute_total_db_bytes_for_user` agrège.
- :func:`update_user_db_usage` recalcule et persiste dans
  :class:`UserStorage.db_bytes_used` (cache, rafraîchi par job quotidien
  ou à la demande quand l'UI affiche la barre de quota).

**Source unique** : la BDD reste source unique. Le static
:data:`_USER_SCOPED_TABLES` est uniquement un schéma déclaratif (quelle
table, quelles colonnes) — pas une duplication d'état.

**Sécurité** : noms de tables et colonnes proviennent exclusivement du
whitelist :data:`_USER_SCOPED_TABLES` (jamais d'input user). Pas
d'injection SQL possible. ``user_id`` est paramétrisé via bind.

**Performance** : ``SELECT SUM(LENGTH(c1) + LENGTH(c2) + …)`` est
extrêmement rapide en SQLite (full table scan mais indexé sur ``user_id``,
~10ms par table même pour 50K rows). Total ≤ 100ms par user, 1s pour
10 users en run-séquentiel — daily job tient la milliseconde.
"""

from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.logger import get_logger

logger = get_logger(__name__)


#: Surcharge constante par row pour estimer les bytes non textuels :
#: id (8) + user_id FK (8) + timestamps (16) + index entries (~30) +
#: row header SQLite (~10). 80 bytes est une approximation conservatrice
#: alignée avec la doc SQLite (avg row overhead 50-100 bytes).
_ROW_OVERHEAD_BYTES = 80


#: Whitelist déclarative des tables user-scoped. Chaque entrée :
#:
#: - ``table`` : nom de la table (DDL)
#: - ``user_id_col`` : nom de la colonne FK vers ``users.id``
#: - ``text_cols`` : liste des colonnes TEXT/JSON/VARCHAR significatives
#:   à mesurer (LENGTH SUM). Les colonnes courtes (booléens, ids, FK,
#:   timestamps) sont ignorées — couvertes par ``_ROW_OVERHEAD_BYTES``.
#:
#: Pour ajouter une nouvelle table à l'accounting : ajouter une entrée
#: ici. Pas besoin de modifier le code de calcul. Pas de migration BDD
#: nécessaire (le SUM tournera dès le prochain recompute).
#:
#: **Note couverture** : seules les tables avec FK directe ``user_id``
#: sont incluses. Les tables jointes indirectement (ex: dashboard_widget
#: → dashboard.user_id) sont volontairement omises pour V1 — elles
#: peuvent être ajoutées plus tard via un JOIN dans la query.
_USER_SCOPED_TABLES: List[Dict[str, Any]] = [
    # --- Anonymisation : token cross-classeur ---
    {
        "table": "anonymization_terms",
        "user_id_col": "user_id",
        "text_cols": ["term", "pseudo_middle"],
    },
    # --- Conversations Iris (titre + découvertes) ---
    {
        "table": "conversations",
        "user_id_col": "user_id",
        "text_cols": ["title", "discoveries"],
    },
    # --- Historique requêtes SQL ---
    {
        "table": "search_history",
        "user_id_col": "user_id",
        "text_cols": ["question", "sql_generated", "sql_validated", "feedback_comment"],
    },
    # --- Dashboards utilisateurs ---
    {
        "table": "F_DASHBOARD",
        "user_id_col": "user_id",
        "text_cols": ["description"],
    },
    # F_DASHBOARD_SCHEDULE : schedules de dashboards privés du user.
    {
        "table": "F_DASHBOARD_SCHEDULE",
        "user_id_col": "user_id",
        "text_cols": ["schedule_config", "recipients"],
    },
    # --- Préférences user (clé/valeur) ---
    {
        "table": "user_preferences",
        "user_id_col": "user_id",
        "text_cols": ["value"],
    },
    # --- Contacts (carnet d'adresses privé du user) ---
    {
        "table": "contacts",
        "user_id_col": "user_id",
        "text_cols": ["full_name", "email", "phone", "notes", "tags"],
    },
    # --- Distribution lists (listes diffusion privées du user) ---
    {
        "table": "distribution_lists",
        "user_id_col": "user_id",
        "text_cols": ["name", "description"],
    },
    # --- Query diff history (historique privé de modifications SQL) ---
    {
        "table": "query_diff_history",
        "user_id_col": "user_id",
        "text_cols": ["sql_before", "sql_after", "diff_summary"],
    },
    # --- File metadata (méta des fichiers du datastore — fichiers eux-mêmes
    # comptés dans quota_used, ici on ajoute juste la surcharge méta) ---
    {
        "table": "file_metadata",
        "user_id_col": "user_id",
        "text_cols": ["file_path", "filename", "description", "mime_type"],
    },
    # --- Pipeline runs (runs déclenchés par le user) ---
    {
        "table": "pipeline_runs",
        "user_id_col": "user_id",
        "text_cols": ["pipeline_name", "status", "config_json", "error_message"],
    },
    # --- SMTP settings (config SMTP perso du user, mots de passe chiffrés) ---
    {
        "table": "smtp_settings",
        "user_id_col": "user_id",
        "text_cols": ["smtp_host", "smtp_username", "sender_email", "sender_name"],
    },
    # NOTE : ``audit_logs`` et ``training_data`` ont été RETIRÉS du
    # tracking quota le 2026-05-14. Justification :
    #   * audit_logs = logs forensic admin (user n'a aucun contrôle sur ce
    #     qui s'y écrit, pas son "stockage" sémantiquement parlant).
    #   * training_data = RAG partagé entre TOUS les users (DDL, doc métier,
    #     paires Q/SQL validées). Le ``created_by`` indique juste l'auteur
    #     d'une contribution, la donnée bénéficie à toute l'équipe.
    # --- Automatisations (workflow engine) — F_AUTOMATION direct ---
    {
        "table": "F_AUTOMATION",
        "user_id_col": "user_id",
        "text_cols": [
            "name",
            "description",
            "query_text",
            "schedule_config",
            "recipients",
            "notification_emails",
        ],
    },
    # F_AUTOMATION_STEP : pas de user_id direct → JOIN via F_AUTOMATION
    # (cf. décision David 2026-05-08 : le quota stockage doit couvrir TOUTES
    # les données utilisateur, pas seulement celles avec user_id direct).
    # `join_via` est lu par compute_db_bytes_breakdown pour produire un
    # JOIN au lieu d'un WHERE direct.
    {
        "table": "F_AUTOMATION_STEP",
        "join_via": {
            "parent_table": "F_AUTOMATION",
            "fk_col": "automation_id",
            "parent_user_col": "user_id",
        },
        "text_cols": ["name", "step_type", "config", "input_policy"],
    },
    {
        "table": "F_AUTOMATION_EDGE",
        "join_via": {
            "parent_table": "F_AUTOMATION",
            "fk_col": "automation_id",
            "parent_user_col": "user_id",
        },
        "text_cols": ["data_type", "metadata_json"],
    },
    # F_EXECUTION : `triggered_by_user_id` peut être NULL pour scheduled
    # runs ; on rattache plutôt à `automation_id → F_AUTOMATION.user_id`
    # (le propriétaire de l'auto, qui est responsable de toutes ses
    # exécutions, y compris programmées).
    {
        "table": "F_EXECUTION",
        "join_via": {
            "parent_table": "F_AUTOMATION",
            "fk_col": "automation_id",
            "parent_user_col": "user_id",
        },
        "text_cols": [
            "status",
            "output_file_path",
            "error_message",
            "error_traceback",
            "trigger_payload",
        ],
    },
    {
        "table": "F_STEP_EXECUTION",
        "join_via": {
            "parent_table": "F_EXECUTION",
            "fk_col": "execution_id",
            "parent_user_col": None,
            # F_STEP_EXECUTION → F_EXECUTION → F_AUTOMATION (deux JOINs).
            # parent_user_col=None signale le double-hop ; le code construit
            # alors un JOIN imbriqué (cf. compute_db_bytes_breakdown).
            "grandparent": {
                "table": "F_AUTOMATION",
                "fk_in_parent": "automation_id",
                "user_col": "user_id",
            },
        },
        "text_cols": [
            "step_name",
            "step_type",
            "status",
            "warnings",
            "error_message",
            "step_input",
            "step_output",
        ],
    },
    # NB : email_log, ai_performance, contacts, sessions etc. peuvent
    # être ajoutés ici si l'usage le justifie. Démarrer minimal pour
    # éviter d'agréger des tables sans consultation des DBA.
]


async def compute_db_bytes_breakdown(session: AsyncSession, user_id: int) -> Dict[str, int]:
    """Calcule la taille BDD par table pour un user.

    Returns mapping ``{table_name: bytes_used}``. Une table absente du
    résultat = 0 row pour ce user. Les tables manquantes (schéma sans
    cette table) sont silencieusement skippées avec un debug log.
    """
    breakdown: Dict[str, int] = {}
    for cfg in _USER_SCOPED_TABLES:
        table = cfg["table"]
        text_cols = cfg["text_cols"]

        # Construit `COALESCE(LENGTH(c1), 0) + COALESCE(LENGTH(c2), 0) + …`
        # COALESCE pour gérer les colonnes NULL (sinon LENGTH(NULL) = NULL,
        # SUM(NULL) collapse en NULL pour toute la row).
        sum_expr = " + ".join(f"COALESCE(LENGTH(t.{c}), 0)" for c in text_cols)
        if not sum_expr:
            sum_expr = "0"

        # Construction de la query selon le mode :
        # - `user_id_col` direct (table contient user_id) → WHERE simple
        # - `join_via` parent direct → INNER JOIN F_AUTOMATION ON …
        # - `join_via` avec `grandparent` → double JOIN (ex: F_STEP_EXECUTION
        #   → F_EXECUTION → F_AUTOMATION). Cf. décision quota global 2026-05-08.
        if "user_id_col" in cfg:
            user_col = cfg["user_id_col"]
            sql = (
                f"SELECT COALESCE(SUM(({sum_expr}) + {_ROW_OVERHEAD_BYTES}), 0) "
                f"FROM {table} t WHERE t.{user_col} = :user_id"
            )
        elif "join_via" in cfg:
            jv = cfg["join_via"]
            parent_table = jv["parent_table"]
            fk_col = jv["fk_col"]
            grandparent = jv.get("grandparent")
            if grandparent is None:
                # Single JOIN: t → parent (parent.user_id_col = :user_id)
                parent_user_col = jv["parent_user_col"]
                sql = (
                    f"SELECT COALESCE(SUM(({sum_expr}) + {_ROW_OVERHEAD_BYTES}), 0) "
                    f"FROM {table} t "
                    f"INNER JOIN {parent_table} p ON p.id = t.{fk_col} "
                    f"WHERE p.{parent_user_col} = :user_id"
                )
            else:
                # Double JOIN: t → parent → grandparent (gp.user_col = :user_id)
                gp_table = grandparent["table"]
                gp_fk_in_parent = grandparent["fk_in_parent"]
                gp_user_col = grandparent["user_col"]
                sql = (
                    f"SELECT COALESCE(SUM(({sum_expr}) + {_ROW_OVERHEAD_BYTES}), 0) "
                    f"FROM {table} t "
                    f"INNER JOIN {parent_table} p ON p.id = t.{fk_col} "
                    f"INNER JOIN {gp_table} gp ON gp.id = p.{gp_fk_in_parent} "
                    f"WHERE gp.{gp_user_col} = :user_id"
                )
        else:
            logger.warning(
                "_USER_SCOPED_TABLES entry without user_id_col or join_via: %s",
                cfg,
            )
            continue

        try:
            result = await session.execute(text(sql), {"user_id": user_id})
            bytes_used = int(result.scalar() or 0)
            if bytes_used > 0:
                breakdown[table] = bytes_used
        except Exception as exc:  # noqa: BLE001
            # Table absente du schéma actuel (ex: feature non encore
            # déployée), ou schéma divergent. On loggue debug et on
            # continue — pas de raise (l'accounting reste partiel mais
            # cohérent).
            logger.debug(
                "compute_db_bytes_breakdown: skip table %s (user=%s) — %s",
                table,
                user_id,
                exc,
            )
    return breakdown


async def compute_total_db_bytes_for_user(session: AsyncSession, user_id: int) -> int:
    """Total bytes BDD pour un user (somme de tout le breakdown)."""
    breakdown = await compute_db_bytes_breakdown(session, user_id)
    return sum(breakdown.values())


async def update_user_db_usage(session: AsyncSession, user_id: int, *, commit: bool = True) -> int:
    """Recalcule + persiste ``UserStorage.db_bytes_used`` pour un user.

    Retourne le total bytes après update. **Ne crée PAS** le row
    ``UserStorage`` si absent — c'est le rôle exclusif de
    :class:`StorageManager.get_or_create_user_storage` qui connaît le
    rôle de l'user pour appliquer le bon ``quota_limit``. Si on créait
    ici avec un rôle par défaut "user", on race avec le flow file-op
    qui créerait avec le bon rôle, et l'unique-constraint ferait fail
    le 2ème insert (ou pire : on écrase le quota d'un admin).

    Donc : si UserStorage n'existe pas → on retourne le total calculé
    sans persister. Le row sera créé au prochain file-op via
    StorageManager, et la valeur recalculée au prochain run du job
    quotidien (ou au prochain on-demand via ``get_storage_stats``).

    Si ``commit=False``, le caller doit gérer le commit (utile dans une
    transaction plus large, ex: handler qui groupe plusieurs writes).
    """
    from sqlalchemy import select
    from app.models.user_storage import UserStorage

    total = await compute_total_db_bytes_for_user(session, user_id)

    stmt = select(UserStorage).where(UserStorage.user_id == user_id)
    result = await session.execute(stmt)
    storage = result.scalar_one_or_none()
    if storage is None:
        # Pas de UserStorage row → l'user n'a jamais touché au datastore.
        # On ne crée pas (cf. docstring). Le total reste cohérent côté
        # caller (qui peut décider d'afficher 0 ou de skip).
        logger.debug(
            "update_user_db_usage: user_id=%s sans UserStorage row, skip persist "
            "(total calculé=%d, sera persisté au prochain file-op)",
            user_id,
            total,
        )
        return total

    storage.db_bytes_used = total
    if commit:
        await session.commit()
    else:
        await session.flush()

    return total


async def update_all_users_db_usage(session_factory, *, batch_size: int = 50) -> Dict[str, Any]:
    """Recompute ``db_bytes_used`` pour TOUS les users (job quotidien).

    Itère par batch pour ne pas tenir une transaction longue. Retourne
    un compteur ``{updated, errors, total_bytes}`` pour les logs ops.
    Best-effort : si un user fail, on continue les autres.

    ``session_factory`` : callable qui retourne un AsyncSession (typiquement
    ``app.core.database.get_session_factory()``).
    """
    from sqlalchemy import select
    from app.models.user import User

    updated = 0
    errors = 0
    total_bytes = 0

    async with session_factory() as session:
        # Fetch user ids only (lightweight)
        result = await session.execute(select(User.id))
        user_ids = [row[0] for row in result.fetchall()]

    logger.info("update_all_users_db_usage: %d users à recalculer", len(user_ids))

    for i in range(0, len(user_ids), batch_size):
        batch = user_ids[i : i + batch_size]
        async with session_factory() as session:
            for uid in batch:
                try:
                    bytes_used = await update_user_db_usage(session, uid, commit=False)
                    total_bytes += bytes_used
                    updated += 1
                except Exception as exc:  # noqa: BLE001
                    errors += 1
                    logger.warning(
                        "update_all_users_db_usage: user_id=%s a fail : %s",
                        uid,
                        exc,
                    )
            try:
                await session.commit()
            except Exception as exc:  # noqa: BLE001
                # Si le commit fail (rare), on logge mais on continue
                # le batch suivant. Les rows non commited sont rollback.
                logger.error(
                    "update_all_users_db_usage: commit batch [%d:%d] fail : %s",
                    i,
                    i + batch_size,
                    exc,
                )
                errors += len(batch)
                updated -= len(batch)
                await session.rollback()

    summary = {
        "updated": updated,
        "errors": errors,
        "total_bytes": total_bytes,
        "users_count": len(user_ids),
    }
    logger.info("update_all_users_db_usage: %s", summary)
    return summary


def get_tracked_tables() -> List[str]:
    """Liste les noms de tables suivies (pour diagnostics admin)."""
    return [cfg["table"] for cfg in _USER_SCOPED_TABLES]


# ── Job APScheduler ───────────────────────────────────────────────────
# Doit être MODULE-LEVEL (pas une closure imbriquée) pour qu'APScheduler
# puisse stocker une référence textuelle ``app.services.db_usage:db_usage_recompute_job``
# et reconstruire le job au redémarrage / hot-reload. Une fonction nichée
# dans ``start_scheduler`` produit l'erreur :
#     "This Job cannot be serialized since the reference to its callable
#      could not be determined."


async def db_usage_recompute_job() -> None:
    """Wrapper async pour APScheduler — fournit la ``session_factory``.

    Appelé quotidiennement à 02:00 par ``app.services.automation.scheduler``.
    Itère tous les users, recalcule ``UserStorage.db_bytes_used`` pour
    chacun. Best-effort : exceptions individuelles loggées, n'interrompt
    pas le batch.
    """
    from app.core.database import get_session_factory

    session_factory = get_session_factory()
    await update_all_users_db_usage(session_factory)
