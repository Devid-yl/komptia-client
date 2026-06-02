"""Admin monitoring service — security KPIs and per-user overview.

Ce service complete ``AdminStatsService`` avec deux jeux de donnees orientes
"supervision multi-users" :

* ``get_security_stats`` : sessions actives, logins echoues 24h, quotas
  depasses, alertes systeme (chaines pretes a afficher). Tout est agrege
  globalement, pas de PII individuelle.
* ``get_users_overview`` : tableau de TOUS les utilisateurs avec leurs
  metriques operationnelles (recherches 7j, stockage, sessions). Permet
  a l'admin de monitorer chaque user individuellement sans devoir
  enchainer N requetes.

Choix de design :

* **Une seule ``AsyncSession`` par appel public** — le pattern ``gather``
  du handler ouvre deja une session par sous-tache, on respecte la meme
  convention (pas de partage de session cross-task qui cassait avec
  SQLAlchemy 2.0 async).
* **Pas de PII fine** : on ne renvoie pas les IP, les session tokens, les
  user-agents bruts. Juste des comptes et des stats agreges. Si l'admin
  veut le detail individuel, il va sur ``/admin/users``.
* **Fail-soft REEL par sous-load** : chaque sous-load (sessions, logins,
  quotas, stuck) est wrappee dans SON PROPRE try/except. Une erreur sur
  un seul KPI ne fait PAS perdre les 3 autres -- les autres affichent
  leur vraie valeur, l'erronne reste a 0 et son nom va dans ``_errors``
  pour que le bandeau d'erreur le mentionne.
* **Imports lazy de modeles optionnels** : ``Execution`` via
  ``_get_model`` (idem ``admin_stats``) pour eviter une boucle d'import
  au boot.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.core import clock
from app.models.base import ensure_utc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.login_attempt import LoginAttempt
from app.models.ai_performance import AIPerformanceLog
from app.models.session import Session as UserSession
from app.models.user import User, UserRole
from app.models.user_storage import UserStorage
from app.services.dashboard.helpers import _get_model
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int = 1,
    maximum: int = 1_000_000,
) -> int:
    """Lit un seuil entier depuis l'environnement avec validation min/max.

    Garde-fous (review R2-A3) :
    - Variable absente ou vide → ``default``.
    - Non parseable (``=abc``) → ``default`` + warning.
    - Hors bornes ``[minimum, maximum]`` → ``default`` + warning. On NE
      clamp PAS à la borne : un admin qui passe ``=999999999`` veut
      probablement désactiver l'alerte, mais on préfère revenir au défaut
      pour éviter un comportement silencieusement absurde (alerte qui ne
      se déclenche jamais).

    ⚠️ Les valeurs sont lues **à l'import** du module — modifier ``.env``
    exige un redémarrage complet. Idem pour ``_SUBLOAD_TIMEOUT_S`` dans
    ``app/handlers/dashboard.py``.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        logger.warning("Env %s=%r invalide (entier attendu), fallback %d", name, raw, default)
        return default
    if value < minimum or value > maximum:
        logger.warning(
            "Env %s=%d hors bornes [%d, %d], fallback %d",
            name,
            value,
            minimum,
            maximum,
            default,
        )
        return default
    return value


# Seuils configurables via env (cf. review #9 — ne plus hardcoder).
# Le dict de retour expose ``failed_logins_threshold`` pour que le template
# puisse colorier de façon cohérente sans dupliquer la valeur côté Jinja.

# Logins échoués 24h. 20 = signal faible mais visible ; bot bruteforce
# > 50/24h. Plafond 10000 (au-delà = valeur absurde, retombe au défaut).
_FAILED_LOGINS_ALERT_THRESHOLD: int = _env_int(
    "KOMPTIA_FAILED_LOGINS_ALERT_THRESHOLD",
    default=20,
    minimum=1,
    maximum=10_000,
)

# Exécutions ``running`` depuis > N heures = bloquées (timeout par défaut
# bien plus court). Plafond 168h (1 semaine) — au-delà, l'alerte devient
# inutile (on ne saurait jamais qu'un job est bloqué).
_STUCK_EXECUTION_AGE_HOURS: int = _env_int(
    "KOMPTIA_STUCK_EXECUTION_AGE_HOURS",
    default=1,
    minimum=1,
    maximum=168,
)

# Limite par défaut pour le tableau monitoring users. Plafond 500 cohérent
# avec le hard cap ci-dessous.
_USERS_OVERVIEW_DEFAULT_LIMIT: int = _env_int(
    "KOMPTIA_USERS_OVERVIEW_DEFAULT_LIMIT",
    default=50,
    minimum=10,
    maximum=500,
)

# Cap dur pour éviter qu'un appelant passe ``limit=10000`` et charge
# des Mo dans le navigateur. Plafond 5000 (au-delà, l'admin doit
# paginer via ``/admin``).
_USERS_OVERVIEW_HARD_CAP: int = _env_int(
    "KOMPTIA_USERS_OVERVIEW_HARD_CAP",
    default=500,
    minimum=50,
    maximum=5_000,
)


class AdminMonitoringService:
    """Stats securite + monitoring users pour le dashboard admin.

    Toutes les methodes publiques sont async et retournent des dicts
    serialisables JSON (string/int/float/bool, listes, dicts plats). A
    appeler depuis le handler ``DashboardHandler`` via le facade
    ``DashboardStatsService``.
    """

    # ── Securite ──────────────────────────────────────────────

    async def get_security_stats(self) -> Dict[str, Any]:
        """Retourne les KPIs securite + alertes systeme.

        Structure de retour :

        .. code-block:: python

            {
                "active_sessions_count": int,
                "failed_logins_24h": int,
                "users_quota_exceeded": int,
                "stuck_executions": int,
                "failed_logins_threshold": int,  # seuil utilise -> coloriage UI
                "stuck_executions_threshold": int,  # seuil heures -> libelle UI
                "sage_connected": bool,
                "sage_status": str,              # "unconfigured"|"connected"|"disconnected"|"untested"
                "system_alerts": list[str],
                "_errors": list[str],            # nom des sous-loads en erreur
            }

        Fail-soft REEL : chaque KPI a son propre try/except. Si l'un
        d'eux plante, les 3 autres restent valides et l'erreur est
        nommee dans ``_errors`` pour que l'UI puisse l'afficher.
        """
        now = clock.now()
        day_ago = now - timedelta(hours=24)
        stuck_cutoff = now - timedelta(hours=_STUCK_EXECUTION_AGE_HOURS)

        stats: Dict[str, Any] = {
            "active_sessions_count": 0,
            "failed_logins_24h": 0,
            "users_quota_exceeded": 0,
            "stuck_executions": 0,
            "failed_logins_threshold": _FAILED_LOGINS_ALERT_THRESHOLD,
            # Seuil "exécution bloquée" exposé pour que le template n'écrive
            # PAS "1h" en dur (env ``KOMPTIA_STUCK_EXECUTION_AGE_HOURS``) —
            # même SSoT que ``failed_logins_threshold``. Cf. review loop F3.
            "stuck_executions_threshold": _STUCK_EXECUTION_AGE_HOURS,
            "system_alerts": [],
            "_errors": [],
        }

        async with get_session() as session:
            # Chaque sous-load isolé : un fail n'impacte pas les autres.
            # Lambdas = création LAZY de la coroutine (cf. admin_stats #62) : une
            # exception non-SQLAlchemyError qui se propage ne laisse pas de
            # coroutines non-awaited → pas de RuntimeWarning « never awaited ».
            for label, make_coro in (
                ("sessions actives", lambda: self._count_active_sessions(session, now)),
                ("logins echoues", lambda: self._count_failed_logins(session, day_ago)),
                ("quotas depasses", lambda: self._count_quotas_exceeded(session)),
                (
                    "executions bloquees",
                    lambda: self._count_stuck_executions(session, stuck_cutoff),
                ),
            ):
                try:
                    value = await make_coro()
                except SQLAlchemyError:
                    logger.warning("stats securite: sous-load %r en erreur", label, exc_info=True)
                    stats["_errors"].append(label)
                    # Sans rollback, la transaction autobegin reste en échec
                    # après une SQLAlchemyError (ex: « database is locked ») et
                    # les sous-loads suivants cascade-failent (PendingRollbackError)
                    # → l'isolation serait illusoire (cf. admin_stats #62).
                    try:
                        await session.rollback()
                    except SQLAlchemyError:
                        logger.warning(
                            "stats securite: rollback post-erreur a échoué", exc_info=True
                        )
                    continue
                # Mapping label -> clef dict (ordre + nommage stable).
                if label == "sessions actives":
                    stats["active_sessions_count"] = value
                elif label == "logins echoues":
                    stats["failed_logins_24h"] = value
                elif label == "quotas depasses":
                    stats["users_quota_exceeded"] = value
                elif label == "executions bloquees":
                    stats["stuck_executions"] = value

        # Sage / providers : check synchrone, pas de session DB. On
        # distingue trois etats pour eviter le faux positif "deconnectee"
        # au boot (le connector est lazy : ``_connected=False`` tant que
        # personne n'a fait une requete, mais ce n'est pas une erreur).
        sage_status = (
            self._check_sage_status()
        )  # "unconfigured" | "untested" | "connected" | "disconnected"
        stats["sage_connected"] = sage_status == "connected"
        stats["sage_status"] = sage_status

        # Construction des alertes — uniquement les conditions VRAIMENT
        # actionables (pas d'alerte "untested" qui se declencherait
        # chaque matin avant le premier user et tuerait la confiance
        # dans les autres alertes -- cf. consequences.md).
        alerts: List[str] = []
        if sage_status == "unconfigured":
            alerts.append(
                "Aucune connexion BDD activee -- l'execution SQL est desactivee. "
                "Allez sur /admin/database pour creer/activer une connexion."
            )
        elif sage_status == "disconnected":
            alerts.append("Base Sage deconnectee -- les requetes echoueront jusqu'a reconnexion")
        if stats["users_quota_exceeded"] > 0:
            n = stats["users_quota_exceeded"]
            alerts.append(f"{n} utilisateur{'s' if n > 1 else ''} a depasse son quota de stockage")
        if stats["failed_logins_24h"] >= _FAILED_LOGINS_ALERT_THRESHOLD:
            alerts.append(f"{stats['failed_logins_24h']} tentatives de connexion echouees sur 24h")
        if stats["stuck_executions"] > 0:
            n = stats["stuck_executions"]
            alerts.append(
                f"{n} execution{'s' if n > 1 else ''} bloquee{'s' if n > 1 else ''}"
                f" depuis plus de {_STUCK_EXECUTION_AGE_HOURS}h (worker bloque ?)"
            )
        stats["system_alerts"] = alerts
        return stats

    @staticmethod
    async def _count_active_sessions(session: AsyncSession, now: datetime) -> int:
        """Sessions ``is_active=true`` ET ``expires_at`` dans le futur."""
        result = await session.execute(
            select(func.count(UserSession.id)).where(
                UserSession.is_active.is_(True),
                UserSession.expires_at > now,
            )
        )
        return int(result.scalar() or 0)

    @staticmethod
    async def _count_failed_logins(session: AsyncSession, since: datetime) -> int:
        """Tentatives de connexion echouees depuis ``since``."""
        result = await session.execute(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.success.is_(False),
                LoginAttempt.attempted_at >= since,
            )
        )
        return int(result.scalar() or 0)

    @staticmethod
    async def _count_quotas_exceeded(session: AsyncSession) -> int:
        """Utilisateurs dont le total (fichiers + bdd) depasse le quota.

        Calcul en SQL pour eviter de hydrater toutes les rows juste pour
        comparer. ``coalesce`` defensif : ``db_bytes_used`` peut etre
        ``NULL`` sur d'anciennes rows (pre-migration phase 2).
        """
        # SSoT : on compare au quota GLOBAL live (AIConfig admin), comme le
        # dashboard de l'user — PAS au ``UserStorage.quota_limit`` figé (re-sync
        # seulement au prochain upload). Sinon, après un changement de quota
        # admin, on compterait de faux dépassements (divergence + fausse alerte).
        from app.services.storage_manager import _get_global_quota

        global_quota = int(await _get_global_quota(session) or 0)
        if global_quota <= 0:
            return 0  # pas de quota configuré → personne en dépassement
        result = await session.execute(
            select(func.count(UserStorage.id)).where(
                (UserStorage.quota_used + func.coalesce(UserStorage.db_bytes_used, 0))
                >= global_quota
            )
        )
        return int(result.scalar() or 0)

    @staticmethod
    async def _count_stuck_executions(session: AsyncSession, cutoff: datetime) -> int:
        """Executions ``running`` qui n'ont pas avance depuis ``cutoff``.

        Important : on filtre sur ``started_at`` plutot qu'un eventuel
        ``updated_at`` (pas garanti present sur tous les modeles
        Execution). Si ``Execution`` n'existe pas (boot partiel, tests),
        on retourne 0 plutot que de planter le dashboard entier.
        """
        try:
            Execution = _get_model("Execution")
        except Exception:  # noqa: BLE001 — modele optionnel
            return 0
        result = await session.execute(
            select(func.count(Execution.id)).where(
                Execution.status == "running",
                Execution.started_at < cutoff,
            )
        )
        return int(result.scalar() or 0)

    @staticmethod
    def _check_sage_status() -> str:
        """Renvoie ``"unconfigured"``, ``"connected"``, ``"disconnected"`` ou ``"untested"``.

        Délègue à la **source unique** :func:`app.services.database.sage_health.
        get_sage_health_snapshot` — la review adversariale finding #39 a
        identifié 3 implémentations divergentes ; cette méthode est
        désormais un mince mapping vers le snapshot brut.

        Les 4 états restent identiques (cf. ``SageHealthSnapshot.state``) :

        * ``"unconfigured"`` : aucune connexion activée via /admin/database.
        * ``"connected"`` : au moins 1 query récente OK.
        * ``"disconnected"`` : circuit breaker a enregistré ≥ 1 échec.
        * ``"untested"`` : config présente mais aucune tentative encore.

        Sync (pas d'I/O réseau).
        """
        from app.services.database.sage_health import get_sage_health_snapshot

        return get_sage_health_snapshot().state

    # ── Monitoring utilisateurs ───────────────────────────────

    async def get_users_overview(
        self,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Liste de TOUS les utilisateurs avec leurs metriques operationnelles.

        Retourne un dict :

        .. code-block:: python

            {
                "users": list[dict],   # voir structure ci-dessous
                "total": int,          # count total dans la BDD (pas borne)
                "truncated": bool,     # True si total > limit applique
                "limit": int,          # limit reellement appliquee
            }

        Chaque dict ``users[i]`` :

        .. code-block:: python

            {
                "id": int,
                "username": str,
                "role": str,                     # "admin" | "user"
                "is_admin": bool,
                "is_active": bool,
                "created_at": str | None,        # ISO 8601 UTC
                "last_login": str | None,        # ISO 8601 UTC ou None
                "active_sessions": int,
                "searches_7d": int,
                "storage_used_bytes": int,
                "storage_quota_bytes": int,      # quota GLOBAL live (AIConfig), pas le quota_limit figé par-user (SSoT)
                "quota_percent": float | None,   # None si quota=0 (non configure)
            }

        L'objectif est qu'un admin puisse trier/filtrer/cliquer
        n'importe quelle ligne sans avoir a ouvrir une fiche user
        individuelle pour chaque info.

        Performance : on charge les users d'abord (1 query), puis on
        agrege en BATCH les sessions / searches / quotas via 3 queries
        groupees (3 + 1 = 4 queries totales, pas N+1). Tri par
        ``last_login`` decroissant (NULLs en bas) avec ``id`` ascendant
        comme tie-breaker pour un ordre deterministe entre deux loads.
        """
        if limit is None or limit <= 0:
            limit = _USERS_OVERVIEW_DEFAULT_LIMIT
        # Cap defensif -- un limit explicite trop large pourrait charger
        # des Mo de payload dans le navigateur. Le ``truncated`` flag
        # alerte l'admin qu'il doit aller sur ``/admin`` pour voir la
        # suite (cf. consequences.md : ne jamais afficher un sous-
        # ensemble silencieux qui pourrait masquer des comptes critiques).
        limit = min(limit, _USERS_OVERVIEW_HARD_CAP)

        now = clock.now()
        week_ago = now - timedelta(days=7)

        empty_response: Dict[str, Any] = {
            "users": [],
            "total": 0,
            "truncated": False,
            "limit": limit,
        }

        try:
            async with get_session() as session:
                # 0. Total reel (avant cap) -- pour le flag truncated.
                total_result = await session.execute(select(func.count(User.id)))
                total_users = int(total_result.scalar() or 0)

                # 1. Users de base — derniers connectes en haut, jamais-connectes en bas,
                #    tie-breaker par id pour un ordre deterministe stable.
                users_result = await session.execute(
                    select(
                        User.id,
                        User.username,
                        User.role,
                        User.is_active,
                        User.created_at,
                        User.last_login,
                    )
                    .order_by(User.last_login.desc().nullslast(), User.id.asc())
                    .limit(limit)
                )
                user_rows = users_result.all()
                if not user_rows:
                    empty_response["total"] = total_users
                    return empty_response
                user_ids = [row.id for row in user_rows]

                # 2. Sessions actives par user (groupby) — 1 query.
                sessions_result = await session.execute(
                    select(
                        UserSession.user_id,
                        func.count(UserSession.id).label("n"),
                    )
                    .where(
                        UserSession.user_id.in_(user_ids),
                        UserSession.is_active.is_(True),
                        UserSession.expires_at > now,
                    )
                    .group_by(UserSession.user_id)
                )
                sessions_by_user = {row.user_id: int(row.n) for row in sessions_result.all()}

                # 3. Recherches 7j par user (groupby) — 1 query.
                # Source : ``AIPerformanceLog`` (vraie table alimentée par
                # Iris), pas ``SearchHistory`` legacy. Cf. admin_stats.py.
                searches_result = await session.execute(
                    select(
                        AIPerformanceLog.user_id,
                        func.count(AIPerformanceLog.id).label("n"),
                    )
                    .where(
                        AIPerformanceLog.user_id.in_(user_ids),
                        AIPerformanceLog.created_at >= week_ago,
                    )
                    .group_by(AIPerformanceLog.user_id)
                )
                searches_by_user = {row.user_id: int(row.n) for row in searches_result.all()}

                # 4. Stockage (UserStorage) par user — 1 query. On lit
                # ``quota_used`` + ``db_bytes_used`` bruts (le dénominateur n'est
                # PAS ``UserStorage.quota_limit`` — cf. ``global_quota`` ci-dessous).
                storage_result = await session.execute(
                    select(
                        UserStorage.user_id,
                        UserStorage.quota_used,
                        UserStorage.db_bytes_used,
                    ).where(UserStorage.user_id.in_(user_ids))
                )
                storage_by_user = {
                    row.user_id: {
                        "used": int((row.quota_used or 0) + (row.db_bytes_used or 0)),
                    }
                    for row in storage_result.all()
                }
                # SSoT du dénominateur quota : quota GLOBAL live (AIConfig
                # admin), comme le dashboard user — PAS le ``quota_limit`` figé
                # (re-sync seulement au prochain upload → divergence + fausse
                # alerte « quota dépassé » après un changement admin).
                from app.services.storage_manager import _get_global_quota

                global_quota = int(await _get_global_quota(session) or 0)
        except SQLAlchemyError:
            logger.error("Erreur monitoring users", exc_info=True)
            # On distingue "vraiment vide" (pas de ``_errors``) d'une erreur
            # BDD : sans ce signal, l'admin verrait "Aucun utilisateur" sans
            # savoir qu'un KPI ment (cf. taxonomie erreurs, axe 5).
            return {**empty_response, "_errors": ["users_overview"]}

        # 5. Assemblage final (Python pur -- pas de SQL ici).
        users: List[Dict[str, Any]] = []
        for row in user_rows:
            storage = storage_by_user.get(row.id, {"used": 0})
            used = storage["used"]
            limit_bytes = global_quota  # quota GLOBAL live (SSoT), pas le figé par-user
            # Quota pct : None si quota non configure (limit=0). Permet
            # au template de differencier "pas de quota" (gris/N/A) de
            # "quota OK mais vide" (vert 0%). Sinon les deux apparaissent
            # comme une barre verte 0% trompeuse.
            quota_pct: Optional[float] = (
                round(used / limit_bytes * 100.0, 1) if limit_bytes > 0 else None
            )
            # Normalisation role : SQLAlchemy peut renvoyer enum OU str
            # selon dialect/driver. On force la string pour stabilite.
            role_raw = row.role
            role_str = role_raw.value if hasattr(role_raw, "value") else str(role_raw)
            # Forcer ``+00:00`` dans l'ISO pour que JS interprète comme UTC
            # (le datetime stocké en SQLite est naïf — ``isoformat()`` seul
            # produirait une chaîne sans tz que JS prend pour heure locale).
            created_at_utc = ensure_utc(row.created_at)
            last_login_utc = ensure_utc(row.last_login)
            users.append(
                {
                    "id": row.id,
                    "username": row.username or "",
                    "role": role_str,
                    "is_admin": role_str == UserRole.ADMIN.value,
                    "is_active": bool(row.is_active),
                    "created_at": created_at_utc.isoformat() if created_at_utc else None,
                    "last_login": last_login_utc.isoformat() if last_login_utc else None,
                    "active_sessions": sessions_by_user.get(row.id, 0),
                    "searches_7d": searches_by_user.get(row.id, 0),
                    "storage_used_bytes": used,
                    "storage_quota_bytes": limit_bytes,
                    "quota_percent": quota_pct,
                }
            )
        return {
            "users": users,
            "total": total_users,
            "truncated": total_users > len(users),
            "limit": limit,
        }
