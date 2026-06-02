"""Cleanup TTL des tables-logs qui croissent sans borne.

Cinq tables identifiées au 2026-04-30 comme ayant une croissance non bornée
(axe Komptia 21) — toutes traitées ici depuis 2026-05-15 où
``conversation_messages`` a rejoint le pool via ``cleanup_conversation_messages``
(purge couplée à ``Conversation.summary`` / ``is_active``, cf. ci-dessous) :

* ``audit_logs`` — audit légal des actions admin (user CRUD, settings, etc.)
* ``search_history`` — historique des requêtes Iris
* ``ai_performance_logs`` — métriques d'inférence LLM (tokens, latence)
* ``email_logs`` — historique des envois SMTP
* ``anonymization_audit`` — journal des modifications de termes
  d'anonymisation (lifecycle utilisateur, cleanup auto, etc.)
* ``conversation_messages`` — messages des chats Iris ; purgé via la
  conv parente (inactive OU active avec summary posé + stale).

TTL par défaut conservatif (audit légal pour les deux ``*_log`` tables, plus
court pour les métriques) — configurable via variables d'environnement, cf.
``_get_retention_days``. Aucun TTL hardcodé en dur dans le code métier.

Pattern : DELETE par chunks de 1000 IDs (évite la limite SQLite des bind
variables et n'écrit pas un ROLLBACK gigantesque en cas d'erreur). Engine
``create_engine(get_db_url())`` et ``Session()`` sync — APScheduler tourne
dans un BackgroundScheduler synchrone (cf. ``automation/scheduler.py``).

**Anti-fallback silencieux** : chaque erreur est loggée explicitement (niveau
``error`` avec ``exc_info=True``), jamais avalée. Mais ne raise PAS au
scheduler — un échec sur ``audit_logs`` ne doit pas empêcher le cleanup de
``email_logs``.
"""

from __future__ import annotations

import datetime
import logging
import os
from typing import Optional

from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core import clock
from app.core.database import get_db_url


def _create_cleanup_engine() -> Engine:
    """Crée un engine sync avec ``PRAGMA foreign_keys=ON`` actif (SQLite).

    Indispensable pour ``cleanup_executions`` car la cascade FK
    ``StepExecution.execution_id → Execution.id ondelete='CASCADE'`` ne
    s'applique que si les FK sont activées. SQLite les désactive par défaut
    sur chaque nouvelle connexion. Sans ce PRAGMA, le DELETE Execution
    laisse des orphelins en BDD ET peut lever une IntegrityError selon le
    schéma.

    Pour PostgreSQL/MySQL ce PRAGMA n'a aucun effet (les FK sont toujours
    actives) — l'event listener s'exécute mais le PRAGMA est ignoré.
    """
    engine = create_engine(get_db_url())

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fk(dbapi_conn, _conn_record):  # type: ignore[no-untyped-def]
        try:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.close()
        except Exception:  # noqa: BLE001 — non-SQLite drivers : silently ignore
            pass

    return engine


logger = logging.getLogger(__name__)

#: Taille de chunk pour ``DELETE WHERE id IN (...)``. SQLite a une limite de
#: 999 paramètres par défaut — 1000 marche sur PostgreSQL/MySQL et reste OK
#: sur SQLite tant qu'on évite les paramètres additionnels dans la même
#: requête (ce qui est notre cas : juste ``id IN (...)``).
_DELETE_CHUNK_SIZE = 500

#: Valeurs par défaut conservatrices.
#:
#: * ``AUDIT_LOGS`` : **5 ans** (1825 jours) par défaut. La conformité légale
#:   française (cabinets comptables, RGPD audit trail) exige typiquement
#:   3-10 ans selon le type d'événement audité. 5 ans couvre la plupart
#:   des cas (durée de prescription civile + 1 an). Ajustable via env
#:   ``AUDIT_LOGS_RETENTION_DAYS`` (ex: 3650 pour 10 ans).
#: * ``EMAIL_LOGS`` : 1 an — historique d'envois SMTP, utile pour debug
#:   livraison + traçabilité des notifications, rarement nécessaire au-delà.
#: * ``SEARCH_HISTORY`` / ``AI_PERFORMANCE_LOGS`` : 90 jours — métriques
#:   techniques pour analyser des tendances trimestrielles sans gonfler.
_RETENTION_DEFAULTS = {
    "AUDIT_LOGS_RETENTION_DAYS": 1825,
    # sql_write_audit_log : audit des écritures SQL privilégiées proposées via
    # Iris (texte SQL + metadata JSON + erreurs). Legal-grade 1825j (≈ 5 ans)
    # comme AUDIT_LOGS — c'est une piste d'audit d'opérations sensibles (RGPD /
    # durée de prescription). Seules les lignes en statut TERMINAL sont purgées
    # (cf. cleanup_sql_write_audit) ; les AWAITING_DBA en attente du DBA sont
    # préservées quel que soit leur âge.
    "SQL_WRITE_AUDIT_RETENTION_DAYS": 1825,
    "SEARCH_HISTORY_RETENTION_DAYS": 90,
    "AI_PERFORMANCE_LOGS_RETENTION_DAYS": 90,
    # ``schema_syncs`` (D1-F8 #77) — journal d'audit des syncs schéma BDD
    # (1 row APPEND par sync auto/manuelle/scheduled : counts de changements,
    # changes_detail JSON, stats). Sans cleanup, croissance non bornée
    # (axe 21 Komptia : ex 1 sync auto/h × 365j = ~8760 rows/an + JSON).
    # TTL 90 jours = convention "log opérationnel" (comme search_history /
    # ai_performance_logs). SAFE : TOUS les consommateurs lisent la sync la
    # PLUS RÉCENTE (``order_by(created_at.desc()).limit(N)`` —
    # get_sync_history, schema_freshness.get_last_sync_time, system_health,
    # pipeline_runner) ; AUCUN ne compte le total ni n'agrège l'historique.
    # La décision ``is_fresh`` se calcule par comparaison schéma-stocké-vs-live
    # (schema_freshness), indépendante de cette table — purger les vieilles
    # lignes n'altère aucune donnée exploitée. Configurable via env
    # ``SCHEMA_SYNCS_RETENTION_DAYS``.
    "SCHEMA_SYNCS_RETENTION_DAYS": 90,
    "EMAIL_LOGS_RETENTION_DAYS": 365,
    # Task #9 sous-tâche A — Fichiers uploadés via le bouton trombone
    # Iris. Stockés dans ``config.data_dir/uploads/{user_id}/``. Sans
    # cleanup, croissance disque non bornée (F2 brainstorm). 30 jours
    # = couvre les conversations actives + 1 semaine de marge pour
    # retours utilisateur sur fichiers anciens. Ajustable via env
    # ``IRIS_UPLOADS_RETENTION_DAYS``.
    "IRIS_UPLOADS_RETENTION_DAYS": 30,
    # G1 — Executions + step_executions : 1 an par défaut.
    # Cabinet comptable : la clôture annuelle (bilan N-1) demande de pouvoir
    # consulter les runs de l'exercice complet. 365 jours couvre l'exercice
    # comptable + une marge pour clôtures en retard. Une auto cron horaire
    # avec 5 steps = 43k step_executions/an. Sans purge, BDD grossit sans
    # bornes. Variable env ``EXECUTIONS_RETENTION_DAYS`` (ex: 540 = 18 mois,
    # 90 = trimestre, etc.). Cascade FK CASCADE purge step_executions.
    "EXECUTIONS_RETENTION_DAYS": 365,
    # ``anonymization_audit`` — journal append-only des actions sur les termes
    # d'anonymisation. 90 jours par défaut : aligné sur ``search_history`` /
    # ``ai_performance_logs`` (métriques techniques). Le terme courant reste
    # en BDD (table ``anonymization_terms``) ; seul l'historique des
    # modifications est purgé. Configurable via
    # ``ANONYMIZATION_AUDIT_RETENTION_DAYS`` pour les déploiements qui
    # exigent une rétention plus longue (compliance interne).
    "ANONYMIZATION_AUDIT_RETENTION_DAYS": 90,
    # ``conversation_events`` — journal append-only des events WS Iris pour
    # le replay DOM-IDENTIQUE au refresh. 30 jours par défaut : suffisant
    # pour qu'un user reprenne sa conv après quelques jours / 1 semaine
    # sans recharger une UX dégradée. Volume estimé : 100 events/tour × 5
    # tours/conv × 1 conv/jour/user × 50 users = 25k rows/jour. Avec TTL
    # 30j → ~750k rows en steady-state, ~50KB par row → 37GB max. Configurable
    # via ``CONVERSATION_EVENTS_RETENTION_DAYS`` pour ajuster selon BDD
    # disponible. Cf. APEX 2026-05-09 (Solution B).
    "CONVERSATION_EVENTS_RETENTION_DAYS": 30,
    # ``query_diff_history`` — diff temporel des résultats de requêtes
    # répétées (T30). Contient des données client (rows added/removed/
    # modified) → confidentialité. 30 jours par défaut, plus court que
    # ``ai_performance_logs`` (90j) car le diff perd vite son utilité
    # pratique. Cascade FK supprime auto les rows quand l'AIPerformanceLog
    # référencé expire. Configurable via
    # ``QUERY_DIFF_HISTORY_RETENTION_DAYS``.
    "QUERY_DIFF_HISTORY_RETENTION_DAYS": 30,
    # ``conversation_messages`` — messages des chats Iris/Copilot. TTL 180
    # jours par défaut (≈ 6 mois). Plus long que ``search_history`` /
    # ``ai_performance_logs`` (90j) parce que c'est de l'historique
    # user-facing : un utilisateur fidèle qui revient consulter un chat
    # de 4-5 mois doit retrouver son contexte. NB : la purge est
    # conditionnelle à l'état de la Conversation parente (cf.
    # ``cleanup_conversation_messages``) — on ne purge JAMAIS les messages
    # d'une conv active sans summary (l'user peut avoir un long historique
    # en attente du résumé auto). Configurable via
    # ``CONVERSATION_MESSAGES_RETENTION_DAYS``.
    "CONVERSATION_MESSAGES_RETENTION_DAYS": 180,
    # ``login_attempts`` — journal des tentatives de connexion (réussites +
    # échecs) servant au rate-limiting persistant. TTL 30 jours par défaut.
    # Justification :
    #   * Le ``LoginRateLimiter`` ne lit que la fenêtre courante
    #     (``rate_limit_login_window_seconds``, default 900 s = 15 min).
    #     Au-delà, les rows ne participent plus à une décision de blocage —
    #     30 jours = ~2 880× la fenêtre par défaut. Si un admin pousse la
    #     fenêtre à 24 h, le ratio tombe à 30× (encore confortable) ; à
    #     5 jours il tombe à 6× ; au-delà, le guard runtime émet un
    #     warning (cf. ``cleanup_login_attempts``).
    #   * Le dashboard admin (``AdminMonitoringService._count_failed_logins``)
    #     affiche un horizon ``since`` de 24 h par défaut — 30 jours couvre.
    #   * RGPD : l'IP normalisée est une donnée personnelle ; minimisation
    #     conseille une rétention courte. 30 j respecte ce principe ; les
    #     déploiements qui exigent davantage pour leur compliance interne
    #     ajustent via ``LOGIN_ATTEMPTS_RETENTION_DAYS``.
    # L'audit légal des authentifications réussies vit dans ``audit_logs``
    # (5 ans par défaut) — pas dans cette table, qui est opérationnelle.
    "LOGIN_ATTEMPTS_RETENTION_DAYS": 30,
    # ``training_data`` (todo #27) — mémoire long-terme de l'agent Iris :
    # DDL, QUESTION_SQL validés, DOCUMENTATION, insights métier appris.
    # Le job purge UNIQUEMENT les entrées explicitement désactivées
    # (``is_active=False``) plus âgées que ce TTL. Les entrées actives
    # ne sont JAMAIS touchées — c'est la connaissance vivante de Iris.
    #
    # Pourquoi 180 jours : une entrée désactivée par un admin peut être
    # réactivée pendant ce délai (ex: revue de décisions trimestrielle,
    # rollback d'une suppression accidentelle). Au-delà, on assume la
    # désactivation définitive et on libère le stockage.
    #
    # Volume estimé : une BDD de 200 tables × 1 sync/jour × 10% de churn
    # (entrées désactivées) × 180 jours = ~3600 rows soft-deleted en
    # steady-state. Sans cleanup, croissance non bornée — axe 21 Komptia.
    #
    # Configurable via env ``TRAINING_DATA_RETENTION_DAYS``.
    "TRAINING_DATA_RETENTION_DAYS": 180,
    # ``conversations`` ``source='automation'`` (Tasks #7/#46, 2026-05-27) —
    # chaque run d'auto avec step iris crée une Conversation transient
    # (``is_active=False``, source=AUTOMATION) pour audit/traçabilité. Sans
    # cleanup, 1 auto */1min × 365j = 525 600 conv/an (violation axe 21
    # Komptia "pas de croissance non bornée"). Configurable via env
    # ``AUTOMATION_CONV_RETENTION_DAYS``. 30 jours = forensics court-terme
    # OK pour debug + compliance cabinet comptable (audit_log dédié garde
    # un résumé 90 jours dans AuditLog.details cf. Task #33).
    "AUTOMATION_CONV_RETENTION_DAYS": 30,
}


def _get_retention_days(env_var: str) -> int:
    """Lit la rétention depuis l'env, fallback sur la valeur par défaut.

    Anti-fallback silencieux : si l'env est mal formé, on log un warning
    visible et on tombe sur la valeur par défaut (jamais 0 ou négatif —
    ce qui supprimerait TOUT).
    """
    raw = os.environ.get(env_var, "")
    if not raw:
        return _RETENTION_DEFAULTS[env_var]
    try:
        value = int(raw)
        if value <= 0:
            logger.warning(
                "%s = %r interprété comme négatif/zéro, fallback %d jours",
                env_var,
                raw,
                _RETENTION_DEFAULTS[env_var],
            )
            return _RETENTION_DEFAULTS[env_var]
        return value
    except (TypeError, ValueError):
        logger.warning(
            "%s = %r non-int, fallback %d jours",
            env_var,
            raw,
            _RETENTION_DEFAULTS[env_var],
        )
        return _RETENTION_DEFAULTS[env_var]


#: Plafond du nombre de lignes supprimées par table ET par run de cleanup.
#: Borne la durée d'UN run (anti-boucle si une table reçoit des inserts plus vite
#: que le cleanup). **Configurable** via ``DB_RETENTION_MAX_ROWS_PER_RUN`` : un
#: déploiement à fort débit dont une table-log expire > 1M lignes/jour DOIT
#: pouvoir relever ce plafond, sinon la cadence quotidienne (04:00) ne rattrape
#: jamais le backlog → croissance non bornée (zone 10). Les commits par chunk
#: gardent la fenêtre de lock à ~ms quel que soit le plafond → l'augmenter est sûr.
_DEFAULT_MAX_ROWS_PER_RUN = 1_000_000
_MAX_ROWS_PER_RUN_ENV = "DB_RETENTION_MAX_ROWS_PER_RUN"


def _get_max_iterations() -> int:
    """Nombre max de chunks par table/run = ``ceil(max_rows / _DELETE_CHUNK_SIZE)``.

    Lit ``DB_RETENTION_MAX_ROWS_PER_RUN`` (défaut 1 000 000). Anti-fallback
    silencieux (même doctrine que :func:`_get_retention_days`) : env mal formé ou
    inférieur à un chunk → warning visible + défaut. Plancher = au moins un chunk
    (un cap < ``_DELETE_CHUNK_SIZE`` purgerait 0 ligne → backlog garanti).
    """
    raw = os.environ.get(_MAX_ROWS_PER_RUN_ENV, "")
    max_rows = _DEFAULT_MAX_ROWS_PER_RUN
    if raw:
        try:
            parsed = int(raw)
            if parsed < _DELETE_CHUNK_SIZE:
                logger.warning(
                    "%s = %r < taille de chunk (%d) — fallback %d (au moins un chunk).",
                    _MAX_ROWS_PER_RUN_ENV,
                    raw,
                    _DELETE_CHUNK_SIZE,
                    _DEFAULT_MAX_ROWS_PER_RUN,
                )
            else:
                max_rows = parsed
        except (TypeError, ValueError):
            logger.warning(
                "%s = %r non-int — fallback %d.",
                _MAX_ROWS_PER_RUN_ENV,
                raw,
                _DEFAULT_MAX_ROWS_PER_RUN,
            )
    # Division entière plafonnée (ceil) sans importer math.
    return -(-max_rows // _DELETE_CHUNK_SIZE)


def _cleanup_table_by_age(
    session: Session,
    model: type,
    date_col,
    retention_days: int,
    label: str,
    extra_filter=None,
) -> int:
    """Supprime les lignes de ``model`` plus anciennes que ``retention_days``.

    Procède par chunks de ``_DELETE_CHUNK_SIZE`` IDs pour rester compatible
    avec la limite de bind variables de SQLite.

    Args:
        session: session SQLAlchemy ouverte. Le caller commit/rollback.
        model: classe de modèle (ex ``AuditLog``).
        date_col: ``InstrumentedAttribute`` de la colonne timestamp à comparer.
        retention_days: âge max en jours.
        label: libellé pour le log (ex "audit_logs").
        extra_filter: condition SQLAlchemy supplémentaire AND-ée à la sélection
            des IDs (ex ``Model.status.in_([...])``). ``None`` = purge par âge
            seul (comportement historique, rétrocompatible). Permet de ne purger
            qu'un sous-ensemble (ex lignes en statut terminal) SANS dupliquer la
            boucle chunk/cap/commit battle-testée.

    Returns:
        Nombre total de lignes supprimées (toutes chunks confondues).

    Raises:
        ValueError: si ``retention_days <= 0``. ``_get_retention_days``
            normalise les env vars négatives/zéro vers le default, mais un
            caller qui passe explicitement une valeur incorrecte
            (``cleanup_xxx(retention_days=0)``) supprimerait TOUTES les
            rows — silent data loss critique. Fail-fast obligatoire ici.
    """
    if retention_days <= 0:
        raise ValueError(
            f"{label}: retention_days doit être > 0 (reçu {retention_days}); "
            "supprimer 100% d'une table-log ne peut pas être un comportement par défaut."
        )

    cutoff = clock.now() - datetime.timedelta(days=retention_days)

    # FIX M3 (review adversariale) : cap sur le nombre d'itérations pour borner
    # la durée d'UN run si la table reçoit des inserts plus vite que le cleanup.
    # Plafond CONFIGURABLE (``DB_RETENTION_MAX_ROWS_PER_RUN``, défaut 1M lignes/run)
    # pour les déploiements à fort débit (zone 10) — SSoT : :func:`_get_max_iterations`.
    _MAX_ITERATIONS = _get_max_iterations()

    # Sélectionne les IDs en lot pour éviter ``DELETE WHERE col < x`` direct
    # qui peut tenir un long lock sur SQLite. Avec une LIMIT par chunk on
    # rend la fenêtre de lock prédictible (~ms).
    deleted_total = 0
    iterations = 0
    while iterations < _MAX_ITERATIONS:
        iterations += 1
        id_stmt = select(model.id).where(date_col < cutoff)
        if extra_filter is not None:
            id_stmt = id_stmt.where(extra_filter)
        ids = session.execute(id_stmt.limit(_DELETE_CHUNK_SIZE)).scalars().all()
        if not ids:
            break
        result = session.execute(delete(model).where(model.id.in_(ids)))
        chunk_deleted = result.rowcount or 0
        deleted_total += chunk_deleted
        # Commit par chunk — si le serveur crash mid-cleanup, on a au moins
        # libéré ce qui a déjà été supprimé. Le prochain run reprendra.
        session.commit()
        if chunk_deleted < len(ids):
            # rowcount peut être 0 si la ligne a déjà été supprimée par un
            # autre process — anormal mais pas bloquant. On stop pour éviter
            # une boucle infinie potentielle.
            logger.warning(
                "%s: chunk_deleted=%d < len(ids)=%d, stop early",
                label,
                chunk_deleted,
                len(ids),
            )
            break
        if len(ids) < _DELETE_CHUNK_SIZE:
            # Dernier chunk plein-vide : pas la peine de re-query.
            break
    else:
        # Le ``while`` a sorti via la condition ``iterations < MAX``
        # (sans break) — log warning explicite pour qu'un ops voie qu'on
        # a touché le cap (pathologique).
        logger.warning(
            "cleanup %s: cap %d itérations atteint (deleted=%d). "
            "Probable cas pathologique : insertion plus rapide que cleanup.",
            label,
            _MAX_ITERATIONS,
            deleted_total,
        )

    if deleted_total:
        logger.info(
            "cleanup %s: deleted=%d (older than %d days, cutoff=%s)",
            label,
            deleted_total,
            retention_days,
            cutoff.isoformat(),
        )
    return deleted_total


def cleanup_audit_logs(retention_days: Optional[int] = None) -> int:
    """Supprime les ``AuditLog`` plus âgés que ``retention_days`` (défaut 1825)."""
    from app.models.audit import AuditLog

    if retention_days is None:
        retention_days = _get_retention_days("AUDIT_LOGS_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session, AuditLog, AuditLog.created_at, retention_days, "audit_logs"
            )
    finally:
        engine.dispose()


def cleanup_sql_write_audit(retention_days: Optional[int] = None) -> int:
    """Purge les ``SqlWriteAuditLog`` en statut TERMINAL plus âgés que
    ``retention_days`` (défaut 1825j ≈ 5 ans, legal-grade comme ``audit_logs``).

    ``sql_write_audit_log`` trace chaque écriture SQL privilégiée proposée via
    Iris (texte SQL + metadata JSON + erreurs). Une ligne est créée à CHAQUE
    proposition et n'était jamais supprimée → croissance non bornée (axe 21).
    ``iris_write_session.cleanup_expired_and_zombie`` ne fait que des UPDATE de
    statut (pas de DELETE). On purge ici uniquement les lignes TERMINALES ; les
    ``AWAITING_DBA`` (en attente du DBA) sont préservées quel que soit leur âge
    — perdre une demande en cours serait pire que la croissance.

    Allow-list explicite des statuts terminaux = fail-safe : un statut
    inconnu/futur n'est PAS purgé (sous-suppression plutôt que sur-suppression
    pour une opération destructive).
    """
    from app.models.sql_write_audit import SqlWriteAuditLog, SqlWriteStatus

    if retention_days is None:
        retention_days = _get_retention_days("SQL_WRITE_AUDIT_RETENTION_DAYS")

    terminal_statuses = [
        SqlWriteStatus.EXECUTED.value,
        SqlWriteStatus.FAILED.value,
        SqlWriteStatus.ABORTED.value,
        SqlWriteStatus.EXPIRED.value,
        SqlWriteStatus.REJECTED_BY_VALIDATOR.value,
    ]

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                SqlWriteAuditLog,
                SqlWriteAuditLog.created_at,
                retention_days,
                "sql_write_audit",
                extra_filter=SqlWriteAuditLog.status.in_(terminal_statuses),
            )
    finally:
        engine.dispose()


def cleanup_search_history(retention_days: Optional[int] = None) -> int:
    """Supprime les ``SearchHistory`` plus âgés que ``retention_days`` (défaut 90)."""
    from app.models.search_history import SearchHistory

    if retention_days is None:
        retention_days = _get_retention_days("SEARCH_HISTORY_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                SearchHistory,
                SearchHistory.created_at,
                retention_days,
                "search_history",
            )
    finally:
        engine.dispose()


def cleanup_query_diff_history(retention_days: Optional[int] = None) -> int:
    """Supprime les ``QueryDiffHistory`` plus âgés que ``retention_days`` (défaut 30).

    Confidentialité : ``diff_json`` contient des données client (rows
    cellules added/removed/modified). TTL agressif (30j vs 90j pour les
    autres logs) car le diff perd vite son intérêt pratique.

    Cascade FK ``ai_performance_logs.id ON DELETE CASCADE`` supprime
    déjà automatiquement les rows quand l'``AIPerformanceLog`` référencé
    expire — ce job nettoie les rows orphelines en plus.
    """
    from app.models.query_diff_history import QueryDiffHistory

    if retention_days is None:
        retention_days = _get_retention_days("QUERY_DIFF_HISTORY_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                QueryDiffHistory,
                QueryDiffHistory.created_at,
                retention_days,
                "query_diff_history",
            )
    finally:
        engine.dispose()


def cleanup_ai_performance_logs(retention_days: Optional[int] = None) -> int:
    """Supprime les ``AIPerformanceLog`` plus âgés que ``retention_days`` (défaut 90)."""
    from app.models.ai_performance import AIPerformanceLog

    if retention_days is None:
        retention_days = _get_retention_days("AI_PERFORMANCE_LOGS_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                AIPerformanceLog,
                AIPerformanceLog.created_at,
                retention_days,
                "ai_performance_logs",
            )
    finally:
        engine.dispose()


def cleanup_schema_syncs(retention_days: Optional[int] = None) -> int:
    """Supprime les ``SchemaSync`` plus âgés que ``retention_days`` (défaut 90).

    Journal d'audit APPEND des syncs schéma (1 row/sync). Tous les lecteurs
    ne consultent que la/les plus récente(s) (``created_at.desc()`` + limit) et
    la fraîcheur du schéma se décide par comparaison stocké-vs-live (indépendante
    de cette table) — purger les vieilles lignes ne perd aucune donnée exploitée.
    Sans cleanup : croissance non bornée (axe 21). Cf. ``SCHEMA_SYNCS_RETENTION_DAYS``.
    """
    from app.models.ai_performance import SchemaSync

    if retention_days is None:
        retention_days = _get_retention_days("SCHEMA_SYNCS_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                SchemaSync,
                SchemaSync.created_at,
                retention_days,
                "schema_syncs",
            )
    finally:
        engine.dispose()


def cleanup_email_logs(retention_days: Optional[int] = None) -> int:
    """Supprime les ``EmailLog`` plus âgés que ``retention_days`` (défaut 365)."""
    from app.models.email_log import EmailLog

    if retention_days is None:
        retention_days = _get_retention_days("EMAIL_LOGS_RETENTION_DAYS")

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session, EmailLog, EmailLog.sent_at, retention_days, "email_logs"
            )
    finally:
        engine.dispose()


def cleanup_executions(retention_days: Optional[int] = None) -> int:
    """Supprime les ``Execution`` plus âgées que ``retention_days`` (défaut 365).

    G1 — La cascade ``ondelete='CASCADE'`` sur ``StepExecution.execution_id``
    purge automatiquement les step_executions associés **uniquement si
    PRAGMA foreign_keys=ON** sur SQLite. ``_create_cleanup_engine()`` active
    le PRAGMA via event listener "connect" — sans ça, SQLite ignore la
    cascade et laisse des orphelins (croissance non bornée silencieuse).

    On filtre sur ``started_at`` (toujours non-null, cf. Execution model).
    ``ended_at`` peut être null pour runs en cours ou crashés.
    """
    from app.models.execution import Execution

    if retention_days is None:
        retention_days = _get_retention_days("EXECUTIONS_RETENTION_DAYS")

    # G1 — engine avec PRAGMA foreign_keys=ON (sinon cascade FK silencieusement
    # désactivée sur SQLite, step_executions deviennent orphelins).
    engine = _create_cleanup_engine()
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                Execution,
                Execution.started_at,
                retention_days,
                "executions",
            )
    finally:
        engine.dispose()


def cleanup_anonymization_audit(retention_days: Optional[int] = None) -> int:
    """Supprime les ``AnonymizationAudit`` plus âgés que ``retention_days`` (défaut 90).

    Le journal d'audit des termes d'anonymisation est append-only : chaque
    insert/update/delete sur ``anonymization_terms`` produit une row ici via
    ``app.services.anonymization.audit.log_audit_action``. Sans purge, une
    activité utilisateur normale (~1500-3000 rows/mois sur 500 termes)
    saturerait la BDD à terme.

    Filtre sur ``AnonymizationAudit.created_at`` (hérité de ``BaseModel`` —
    timestamp posé à l'insertion, jamais modifié ensuite). Le cutoff est
    glissant (``now - retention_days``).

    **Conservation** : seul l'historique des modifications est purgé. La
    table ``anonymization_terms`` (état courant) n'est PAS touchée — elle
    a son propre cleanup (``cleanup_unused_anonymization_terms_job``) basé
    sur la présence dans les classeurs.
    """
    from app.models.anonymization_audit import AnonymizationAudit

    if retention_days is None:
        retention_days = _get_retention_days("ANONYMIZATION_AUDIT_RETENTION_DAYS")

    # PRAGMA foreign_keys=ON via _create_cleanup_engine — la FK
    # ``anonymization_term_id ondelete='SET NULL'`` ne nécessite pas le
    # PRAGMA pour le delete d'une row audit (c'est une FK sortante), mais
    # on aligne le pattern sur ``cleanup_executions`` pour cohérence et
    # pour anticiper toute évolution future de la cascade.
    engine = _create_cleanup_engine()
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                AnonymizationAudit,
                AnonymizationAudit.created_at,
                retention_days,
                "anonymization_audit",
            )
    finally:
        engine.dispose()


def cleanup_conversation_events(retention_days: Optional[int] = None) -> int:
    """Supprime les ``ConversationEvent`` selon une logique TTL conditionnelle.

    **Pourquoi conditionnelle (et non simple age-based)** :
    Solution B (cf. APEX 2026-05-09) garantit un refresh DOM-IDENTIQUE en
    rejouant les events stockés. Si ce job purge les events d'une conversation
    encore ACTIVE et utilisée par un user, le prochain refresh affichera un
    DOM tronqué silencieusement → casse exactement la promesse qui justifie
    cette table (review BLOCKING #5).

    **Règle appliquée** : purge un event SSI la Conversation parente est :
        (a) ``is_active = False`` (clear par l'user) — quel que soit l'age, ou
        (b) ``is_active = True`` ET ``updated_at < (now - retention_days)``
            (active mais inutilisée depuis ``retention_days`` jours).

    Cascade FK ``ondelete='CASCADE'`` gère déjà le cas (a) si la Conversation
    elle-même est supprimée. Ce job complète pour les conv juste désactivées
    (soft-delete) et les conv abandonnées par l'user (cas b).
    """
    import sqlalchemy as sa
    from app.models.conversation import Conversation, ConversationEvent

    if retention_days is None:
        retention_days = _get_retention_days("CONVERSATION_EVENTS_RETENTION_DAYS")
    if retention_days <= 0:
        raise ValueError(
            f"conversation_events: retention_days doit être > 0 (reçu {retention_days})"
        )

    cutoff = clock.now() - datetime.timedelta(days=retention_days)
    engine = _create_cleanup_engine()
    deleted_total = 0
    # Même plafond configurable que `_cleanup_table_by_age` (SSoT).
    _MAX_ITERATIONS = _get_max_iterations()
    try:
        with Session(engine) as session:
            # IDs des conv "purgables" : inactives OU actives-mais-stale.
            # Sous-requête recalculée à chaque chunk (les conv peuvent passer
            # is_active=False entre 2 chunks, on veut prendre les nouvelles).
            iterations = 0
            while iterations < _MAX_ITERATIONS:
                iterations += 1
                purgable_conv_ids = sa.select(Conversation.id).where(
                    sa.or_(
                        Conversation.is_active.is_(False),
                        sa.and_(
                            Conversation.is_active.is_(True),
                            Conversation.updated_at < cutoff,
                        ),
                    )
                )
                ids = (
                    session.execute(
                        sa.select(ConversationEvent.id)
                        .where(ConversationEvent.conversation_id.in_(purgable_conv_ids))
                        .limit(_DELETE_CHUNK_SIZE)
                    )
                    .scalars()
                    .all()
                )
                if not ids:
                    break
                result = session.execute(
                    sa.delete(ConversationEvent).where(ConversationEvent.id.in_(ids))
                )
                chunk_deleted = result.rowcount or 0
                deleted_total += chunk_deleted
                session.commit()
                if chunk_deleted < len(ids):
                    logger.warning(
                        "conversation_events: chunk_deleted=%d < ids=%d, stop early",
                        chunk_deleted,
                        len(ids),
                    )
                    break
                if len(ids) < _DELETE_CHUNK_SIZE:
                    break
            logger.info(
                "conversation_events: purged %d rows (inactive convs + active stale >%dj)",
                deleted_total,
                retention_days,
            )
            return deleted_total
    finally:
        engine.dispose()


def cleanup_conversation_messages(retention_days: Optional[int] = None) -> int:
    """Supprime les ``ConversationMessage`` via une logique TTL conditionnelle
    couplée à l'état de la ``Conversation`` parente.

    **Pourquoi conditionnelle (pas simple age-based)** :
    Les messages d'une conversation active SANS summary représentent un
    contexte que l'user peut encore consulter ou réutiliser. Les purger
    sec à >180j romprait silencieusement la continuité de l'historique
    Iris d'un utilisateur fidèle qui revient sur des chats anciens.
    Default 180 jours (≈ 6 mois) = plus long que les autres tables-logs
    techniques (90j search_history) car c'est de l'historique user-facing.

    **Règle appliquée** : purge un message SSI la Conversation parente est :
        (a) ``is_active = False`` (clear soft historique, antérieur au passage
            en hard-delete du 2026-05-15) — quel que soit l'âge, ou
        (b) ``summary`` non-vide (``length(trim(summary)) > 0``) ET
            ``COALESCE(updated_at, created_at) < (now - retention_days)``
            (résumé P2.1 posé : le contexte est sauvegardé dans
            ``Conversation.summary``, l'historique brut peut dégager).

    Les conv actives SANS summary ne sont JAMAIS purgées par ce job, peu
    importe leur âge. Si le summary auto-généré tarde (run abandonné,
    LLM down, etc.), l'historique reste intact.

    NB : depuis 2026-05-15, le bouton "Effacer" côté UI fait un hard-delete
    de la Conversation (cascade FK vire les messages). La branche (a) est
    donc essentiellement un filet pour les données héritées soft-delete.

    Défense en profondeur — pourquoi ``COALESCE`` et ``length(trim)`` :
    ``BaseModel.updated_at`` est ``nullable=True`` avec ``onupdate=func.now()``
    seulement (pas de ``default=``, cf. ``app/models/base.py:43-45``). Une
    conv qui reçoit ``summary`` au même flush que sa création (ou via raw
    SQL) garde ``updated_at = NULL`` ; sans COALESCE, ``NULL < cutoff``
    retourne NULL (falsy) et la conv fuiterait indéfiniment. Idem
    ``length(trim(summary)) > 0`` : ``IS NOT NULL`` accepterait ``""`` ou
    whitespace-only, ce qui purgerait à tort si un futur appelant écrit un
    placeholder vide. Aujourd'hui ``agent_service`` filtre via
    ``if not cleaned: return`` (cf. ``agent_service.py:6880``), mais ce job
    ne doit pas dépendre de la convention côté caller.
    """
    import sqlalchemy as sa
    from app.models.conversation import Conversation, ConversationMessage

    if retention_days is None:
        retention_days = _get_retention_days("CONVERSATION_MESSAGES_RETENTION_DAYS")
    if retention_days <= 0:
        raise ValueError(
            f"conversation_messages: retention_days doit être > 0 (reçu {retention_days})"
        )

    cutoff = clock.now() - datetime.timedelta(days=retention_days)
    engine = _create_cleanup_engine()
    deleted_total = 0
    # Même plafond configurable que `_cleanup_table_by_age` (SSoT).
    _MAX_ITERATIONS = _get_max_iterations()
    try:
        with Session(engine) as session:
            iterations = 0
            while iterations < _MAX_ITERATIONS:
                iterations += 1
                # Sous-requête recalculée à chaque chunk (les conv peuvent
                # gagner un summary entre 2 chunks, on veut prendre les
                # nouvelles éligibles).
                #
                # ``COALESCE(updated_at, created_at)`` — voir docstring
                # "Défense en profondeur" : updated_at peut être NULL pour
                # les conv jamais updatées (BaseModel.updated_at nullable
                # sans default), et ``NULL < cutoff`` = NULL (falsy) en SQL,
                # ce qui ferait fuiter ces conv indéfiniment.
                # ``length(trim(summary)) > 0`` — protège contre un futur
                # caller qui écrirait summary="" ou whitespace-only (ce
                # qui passerait IS NOT NULL et purgerait à tort).
                effective_updated_at = sa.func.coalesce(
                    Conversation.updated_at, Conversation.created_at
                )
                summary_non_empty = sa.func.length(sa.func.trim(Conversation.summary)) > 0
                purgable_conv_ids = sa.select(Conversation.id).where(
                    sa.or_(
                        Conversation.is_active.is_(False),
                        sa.and_(
                            Conversation.summary.is_not(None),
                            summary_non_empty,
                            effective_updated_at < cutoff,
                        ),
                    )
                )
                ids = (
                    session.execute(
                        sa.select(ConversationMessage.id)
                        .where(ConversationMessage.conversation_id.in_(purgable_conv_ids))
                        .limit(_DELETE_CHUNK_SIZE)
                    )
                    .scalars()
                    .all()
                )
                if not ids:
                    break
                result = session.execute(
                    sa.delete(ConversationMessage).where(ConversationMessage.id.in_(ids))
                )
                chunk_deleted = result.rowcount or 0
                deleted_total += chunk_deleted
                session.commit()
                if chunk_deleted < len(ids):
                    logger.warning(
                        "conversation_messages: chunk_deleted=%d < ids=%d, stop early",
                        chunk_deleted,
                        len(ids),
                    )
                    break
                if len(ids) < _DELETE_CHUNK_SIZE:
                    break
            else:
                logger.warning(
                    "cleanup conversation_messages: cap %d itérations atteint " "(deleted=%d).",
                    _MAX_ITERATIONS,
                    deleted_total,
                )
            if deleted_total:
                logger.info(
                    "conversation_messages: purged %d rows "
                    "(inactive convs + convs with summary stale >%dj)",
                    deleted_total,
                    retention_days,
                )
            return deleted_total
    finally:
        engine.dispose()


def cleanup_login_attempts(retention_days: Optional[int] = None) -> int:
    """Supprime les ``LoginAttempt`` plus âgés que ``retention_days`` (défaut 30).

    La table ``login_attempts`` enregistre chaque appel à ``record_attempt``
    du ``LoginRateLimiter`` (``app/services/auth/login_rate_limiter.py``).
    Elle croît à raison de N rows par tentative — sous bruteforce, plusieurs
    k/h. Sans cleanup, croissance non bornée (axe Komptia 21).

    Filtre sur ``LoginAttempt.attempted_at`` (NOT NULL, default ``now(UTC)``
    posé par le model). La purge est par âge **global** : success=True et
    success=False sont traités identiquement, indépendamment de l'IP ou
    du username.

    Pourquoi 30 jours par défaut (vs 90 j search_history / 1825 j audit_logs) :
        * usage opérationnel uniquement (rate-limit + dashboard 24 h) ;
        * RGPD — IP = donnée personnelle, minimisation ;
        * audit légal des connexions = ``audit_logs`` (table séparée).
    30× la fenêtre par défaut (15 min). Si un admin pousse
    ``rate_limit_login_window_seconds`` au-delà de la moitié du TTL
    (par exemple > 15 jours pour TTL=30j), un warning est loggé au start
    du cleanup pour signaler qu'il faudrait ajuster ``LOGIN_ATTEMPTS_RETENTION_DAYS``.
    Configurable via env ``LOGIN_ATTEMPTS_RETENTION_DAYS`` pour les
    déploiements qui exigent une rétention plus longue.
    """
    from app.models.login_attempt import LoginAttempt

    if retention_days is None:
        retention_days = _get_retention_days("LOGIN_ATTEMPTS_RETENTION_DAYS")

    # Adversarial guard : si le TTL est plus court que 2× la fenêtre du
    # rate-limiter, on peut purger des rows que le rate-limiter a encore
    # besoin de lire → affaiblissement silencieux du bruteforce-defense.
    # On log un warning visible (pas raise — il ne faut pas bloquer le
    # cleanup en prod) pour qu'un ops s'en aperçoive via les logs
    # quotidiens. Le facteur 2× est arbitrairement conservateur : 1×
    # serait limite (cutoff pile au début de la fenêtre), 2× donne une
    # marge raisonnable. Cf. review adversariale 2026-05-20 finding #3.
    #
    # Lecture de config en lazy import pour éviter le cycle module au
    # démarrage (db_retention est appelé via scheduler, qui boot après
    # config). Si la lecture échoue (config non initialisée, env de
    # test, etc.), on skip le guard sans casser le cleanup principal.
    try:
        from app.config import config as _cfg

        window_seconds = _cfg.security.rate_limit_login_window_seconds
        ttl_seconds = retention_days * 86400
        if ttl_seconds < 2 * window_seconds:
            logger.warning(
                "login_attempts: TTL=%dj (%ds) < 2× rate_limit window (%ds). "
                "Le rate-limiter peut perdre des décisions de blocage. "
                "Ajuster LOGIN_ATTEMPTS_RETENTION_DAYS ou réduire "
                "rate_limit_login_window_seconds.",
                retention_days,
                ttl_seconds,
                window_seconds,
            )
    except Exception:  # noqa: BLE001 — guard non-bloquant
        pass

    # ``_create_cleanup_engine`` active PRAGMA foreign_keys=ON même si
    # ``login_attempts`` n'a pas (encore) de FK entrante. Aligné sur
    # ``cleanup_anonymization_audit`` (même justification verbatim :
    # cohérence + anticipation d'une cascade future). Cf. review
    # adversariale 2026-05-20 finding #1.
    engine = _create_cleanup_engine()
    try:
        with Session(engine) as session:
            return _cleanup_table_by_age(
                session,
                LoginAttempt,
                LoginAttempt.attempted_at,
                retention_days,
                "login_attempts",
            )
    finally:
        engine.dispose()


def cleanup_training_data(retention_days: Optional[int] = None) -> int:
    """Purge les ``TrainingData`` soft-deleted (``is_active=False``) plus
    âgés que ``retention_days`` (défaut 180 jours, todo #27).

    **Doctrine stricte** : on ne touche JAMAIS aux entrées ``is_active=True``
    — c'est la mémoire vivante de l'agent Iris (DDL connue, Q/SQL validés,
    insights métier). Seules les entrées explicitement désactivées par un
    admin ou le système (drift schéma, doublon résolu, etc.) sont éligibles
    à la purge physique après le TTL.

    Critère de purge : ``is_active = False AND updated_at < cutoff``.
    Le champ ``updated_at`` reflète la date de désactivation (l'admin a
    explicitement modifié la row). Si une entrée est désactivée puis
    réactivée puis re-désactivée, c'est la dernière désactivation qui
    compte — comportement attendu.

    Generic : aucun nom métier hardcodé, opère sur toutes les
    ``TrainingDataType`` (DDL, QUESTION_SQL, DOCUMENTATION, etc.) sans
    distinction. Si on voulait des TTL différents par type, un futur
    chantier pourrait spécialiser via plusieurs env vars.
    """
    from app.models.training_data import TrainingData

    if retention_days is None:
        retention_days = _get_retention_days("TRAINING_DATA_RETENTION_DAYS")

    cutoff = clock.now() - datetime.timedelta(days=retention_days)

    engine = create_engine(get_db_url())
    try:
        with Session(engine) as session:
            stmt = delete(TrainingData).where(
                TrainingData.is_active.is_(False),
                TrainingData.updated_at < cutoff,
            )
            result = session.execute(stmt)
            session.commit()
            deleted = result.rowcount or 0
            logger.info(
                "cleanup_training_data: deleted=%d soft-deleted rows older than %d days",
                deleted,
                retention_days,
            )
            return deleted
    finally:
        engine.dispose()


def cleanup_iris_uploads(retention_days: Optional[int] = None) -> int:
    """**Task #9 sous-tâche A — TTL cleanup des uploads Iris.**

    Supprime les fichiers ``config.data_dir/uploads/{user_id}/*`` plus
    vieux que ``retention_days`` (défaut 30 jours, ajustable via env
    ``IRIS_UPLOADS_RETENTION_DAYS``).

    **Pourquoi** : F2 du brainstorm initial (2026-05-25) — avant ce
    job, ``/uploads/`` croissait indéfiniment, aucun cleanup. Pour un
    cabinet avec uploads quotidiens (états mensuels, déclarations TVA),
    cumulés à 5-10 Mo/fichier sur 6 mois = 1-2 Go gâché. Le job de
    dédup SHA256 (Task #17) réduit la duplication mais ne résout PAS
    la croissance par accumulation de fichiers différents au fil du
    temps.

    **Met aussi à jour le ``.dedup.json``** de chaque user_dir pour
    retirer les entries dont les fichiers physiques ont été supprimés
    (sinon l'index conserverait des pointeurs morts qui forceraient
    une réécriture inutile au prochain upload).

    **Robustesse** : chaque user_dir est traité indépendamment dans un
    try/except — un fichier verrouillé (Windows par anti-virus) ou
    une permission denied isolée n'arrête pas le job pour les autres
    users.

    Returns:
        Nombre total de fichiers supprimés.
    """
    if retention_days is None:
        retention_days = _get_retention_days("IRIS_UPLOADS_RETENTION_DAYS")

    # Import lazy pour éviter un cycle (iris.py est un handler, il
    # n'importe normalement pas les services cleanup).
    try:
        from app.handlers.iris import _UPLOAD_DIR, _dedup_index_path
    except Exception as exc:
        logger.warning("cleanup_iris_uploads: import iris.py échoué: %s", exc)
        return 0

    if not _UPLOAD_DIR.is_dir():
        return 0

    cutoff_ts = clock.timestamp() - (retention_days * 86400)
    deleted_count = 0

    for user_dir in _UPLOAD_DIR.iterdir():
        if not user_dir.is_dir():
            continue
        try:
            deleted_file_ids: set[str] = set()
            for entry in user_dir.iterdir():
                if not entry.is_file():
                    continue
                # Skip les fichiers sidecar (commencent par .)
                if entry.name.startswith("."):
                    continue
                try:
                    mtime = entry.stat().st_mtime
                    if mtime < cutoff_ts:
                        file_id = entry.stem  # nom sans extension = UUID
                        entry.unlink()
                        deleted_file_ids.add(file_id)
                        deleted_count += 1
                except OSError as os_exc:
                    logger.warning(
                        "cleanup_iris_uploads: échec suppression %s: %s",
                        entry,
                        os_exc,
                    )

            # Met à jour .dedup.json pour retirer les entries des
            # fichiers supprimés. Sinon l'index garde des pointeurs
            # morts qui forceraient un nouveau write au prochain upload
            # du même contenu (dédup cassée silencieusement).
            if deleted_file_ids:
                _prune_dedup_index(
                    _dedup_index_path(user_dir),
                    deleted_file_ids,
                )

            # MED-9 — nettoyer les orphelins .dedup.json.tmp (crash
            # entre write et rename atomique). Sans ça : accumulation
            # lente de fichiers .tmp jamais nettoyés (le cleanup
            # principal skip tous les fichiers préfixés `.`).
            # On supprime UNIQUEMENT les .tmp plus vieux qu'1 heure
            # pour ne pas tuer une écriture concurrente légitime.
            try:
                tmp_cutoff = clock.timestamp() - 3600  # 1 h
                for tmp_entry in user_dir.glob("*.tmp"):
                    if not tmp_entry.is_file():
                        continue
                    try:
                        if tmp_entry.stat().st_mtime < tmp_cutoff:
                            tmp_entry.unlink()
                            logger.debug(
                                "cleanup_iris_uploads: orphelin .tmp supprimé %s",
                                tmp_entry,
                            )
                    except OSError:
                        # Race avec écriture concurrente — ignorer
                        pass
            except OSError as glob_exc:
                logger.warning(
                    "cleanup_iris_uploads: glob .tmp échoué dans %s: %s",
                    user_dir,
                    glob_exc,
                )
        except Exception:  # noqa: BLE001 — fail-soft par user
            logger.error(
                "cleanup_iris_uploads: échec user_dir %s, skip",
                user_dir,
                exc_info=True,
            )

    if deleted_count > 0:
        logger.info(
            "cleanup_iris_uploads: %d fichier(s) supprimé(s) (retention=%d j)",
            deleted_count,
            retention_days,
        )
    return deleted_count


def _prune_dedup_index(idx_path, deleted_file_ids: set) -> None:
    """Retire de ``.dedup.json`` les entries dont le ``file_id`` est
    dans ``deleted_file_ids``. Écriture atomique via tmp + rename
    (cohérent avec ``_dedup_record`` côté iris.py).

    Robuste aux corruptions : si JSON invalide, on ne fait rien (le
    prochain ``_dedup_record`` reconstruira l'index propre).

    CRIT-2 adversarial fix 2026-05-26 — la séquence read-modify-write
    est protégée par ``_dedup_locked`` (lock ``fcntl`` Unix), même
    lock que ``_dedup_record``. Avant ce fix, le cleanup TTL pouvait
    écraser une entry ajoutée concurremment.
    """
    import json as _json
    import os as _os

    if not idx_path.is_file():
        return

    # Import lazy pour éviter le cycle (db_retention chargé tôt par
    # main.py, iris.py est chargé après). user_dir = parent de l'index.
    try:
        from app.handlers.iris import _dedup_locked
    except ImportError:
        # En tests qui mockent iris, on continue sans lock (pas safe
        # mais pas crash — comportement antérieur préservé).
        from contextlib import nullcontext as _dedup_locked  # type: ignore

    user_dir = idx_path.parent

    with _dedup_locked(user_dir):
        # Re-lire dans le lock (la lecture pré-lock plus haut est
        # invalidée — un upload concurrent a pu modifier l'index entre
        # is_file() et l'acquisition du lock).
        if not idx_path.is_file():
            return
        try:
            with idx_path.open("r", encoding="utf-8") as f:
                data = _json.load(f)
        except (OSError, _json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return

        new_data = {
            sha: entry
            for sha, entry in data.items()
            if not (isinstance(entry, dict) and entry.get("file_id") in deleted_file_ids)
        }
        if len(new_data) == len(data):
            return  # rien à pruner

        tmp_path = idx_path.with_suffix(".json.tmp")
        with tmp_path.open("w", encoding="utf-8") as f:
            _json.dump(new_data, f)
        _os.replace(str(tmp_path), str(idx_path))


def cleanup_db_retention_job() -> None:
    """Job scheduler — appelle tous les cleanup tables.

    Chaque table a son propre try/except : un échec sur l'une (ex SQL lock
    transitoire) ne bloque pas les autres. Aucune exception n'est ré-émise
    vers le scheduler — le job suivant tourne quand même demain.
    """
    total = 0
    for fn, label in (
        (cleanup_audit_logs, "audit_logs"),
        (cleanup_sql_write_audit, "sql_write_audit"),
        (cleanup_search_history, "search_history"),
        (cleanup_ai_performance_logs, "ai_performance_logs"),
        (cleanup_schema_syncs, "schema_syncs"),
        (cleanup_email_logs, "email_logs"),
        (cleanup_executions, "executions"),
        (cleanup_anonymization_audit, "anonymization_audit"),
        (cleanup_conversation_events, "conversation_events"),
        (cleanup_conversation_messages, "conversation_messages"),
        (cleanup_query_diff_history, "query_diff_history"),
        (cleanup_login_attempts, "login_attempts"),
        (cleanup_training_data, "training_data"),
        # Task #9 sous-tâche A — F2 brainstorm initial : croissance
        # disque non bornée /uploads/. Cleanup TTL par défaut 30 jours.
        (cleanup_iris_uploads, "iris_uploads"),
    ):
        try:
            total += fn()
        except Exception:  # noqa: BLE001 — fail-soft per table
            logger.error("cleanup %s: échec, skip", label, exc_info=True)

    logger.info("cleanup_db_retention_job done: total_deleted=%d", total)
