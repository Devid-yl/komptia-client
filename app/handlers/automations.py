"""Handlers HTTP pour le module d'automatisations.

Ce module expose 21 handlers couvrant : CRUD automatisations, wizard, preview
SQL, execution manuelle, historique, telechargement de resultats, et API CRUD
pour les etapes workflow.

Principes de securite appliques
-------------------------------

* **404 plutot que 403 pour l'ownership** : une ressource qui n'appartient pas
  a l'utilisateur courant est indistinguable d'une ressource inexistante.
  Retourner 403 sur les IDs valides mais appartenant a autrui permettrait
  d'enumerer les ressources (CWE-284 / CWE-203 information exposure via
  different responses). Voir EPIC:HANDLERS-404-SYMMETRY.
* **Mass-assignment bloque** : les booleens (is_active, notify_on_*) sont
  passes par ``strict_bool`` — un JSON body avec ``"is_active": "false"`` ou
  ``42`` leve 400 au lieu de se retrouver en True via ``bool(str)``.
* **Rate-limit endpoint-par-endpoint** : les routes couteuses ou abusables
  (preview, execute, import, duplicate) ont chacune leur quota utilisateur
  pour limiter l'epuisement des credits LLM et les floods. Voir
  EPIC:RATE-LIMIT-SENSITIVE-ENDPOINTS.
* **CRLF header injection** : tout nom de fichier ecrit dans
  ``Content-Disposition`` est passe par ``assert_no_crlf`` (defense-in-depth
  contre CWE-113). Le regex sur ``automation.name`` + le nom du fichier
  ``execution.output_file_path`` ne preservent pas les ``\\r`` / ``\\n``.
* **Symlink TOCTOU** : resolution du chemin + verification symlink en une
  seule lecture, avant tout acces disque (CWE-367).
* **Validation config d'etape** : le config_schema dans STEP_TYPE_META est
  consulte a la creation/import pour refuser les cles inconnues — evite que
  l'UI pousse des payloads arbitraires dans la BDD.
"""

from __future__ import annotations

import asyncio  # noqa: F401 — exposé pour streaming downloads (test_handlers_deep_review.test_asyncio_imported)
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional, Tuple

import tornado.web
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from app.constants import (
    AUTOMATIONS_PER_PAGE,
    DEFAULT_PER_PAGE,
    EXECUTIONS_PER_PAGE,
)
from app.core import clock
from app.handlers.base import AuthenticatedHandler, require_role
from app.models.audit import AuditAction
from app.models.automation import Automation
from app.models.automation_edge import EDGE_DATA_TYPES, AutomationEdge
from app.models.automation_step import (
    STEP_CATEGORIES,
    STEP_TYPE_META,
    AutomationStep,
    StepType,
)
from app.models.base import ensure_utc
from app.models.execution import Execution
from app.models.step_execution import StepExecution
from app.models.webhook_trigger import WebhookTrigger
from app.services.audit import audit_event
from app.services.automation import (
    execute_automation,
    schedule_automation,
    unschedule_automation,
)
from app.services.automation.scheduler import get_scheduler, validate_cron_expression
from app.utils.http_streaming import stream_file_to_handler
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.validators import (
    assert_no_crlf,
    is_valid_email,
    strict_bool,
)

logger = get_logger(__name__)


# AUTO-1 — exécutions manuelles en fire-and-forget : strong-refs sur les tasks
# de fond (asyncio ne garde qu'une weak-ref → GC possible avant la fin sans ça).
_MANUAL_EXEC_TASKS: "set[asyncio.Task]" = set()


async def _run_manual_automation_bg(automation_id: int, user_id: int, name: str) -> None:
    """Lance le run manuel via la SSoT ``execute_automation`` (sérialisée par le
    lock per-automation) SANS bloquer la requête HTTP. Le panneau « En cours »
    (poller /api/executions/running) suit la progression ; l'issue est tracée
    via le modèle ``Execution``. Best-effort : on logge, on ne propage jamais."""
    try:
        result = await execute_automation(
            automation_id,
            manual=True,
            trigger_source="manual",
            triggered_by_user_id=user_id,
        )
        if not result.get("success"):
            logger.warning(
                "Exécution manuelle « %s » terminée en échec : %s",
                name,
                result.get("error"),
                extra={"automation_id": automation_id},
            )
    except Exception:  # noqa: BLE001 — tâche détachée : ne jamais propager
        logger.exception("Exécution manuelle « %s » : crash inattendu", name)


# ── Constantes locales ────────────────────────────────────────
# Valeurs techniques proprement typees et partagees entre handlers. Elles ne
# dependent ni du client ni de l'environnement (les seuils business pilotes
# par l'admin vivraient dans ``app/config.py``).

_VALID_OUTPUT_FORMATS: frozenset[str] = frozenset({"csv", "excel", "pdf"})
_VALID_SCHEDULE_TYPES: frozenset[str] = frozenset({"once", "daily", "weekly", "monthly", "cron"})
_VALID_QUERY_TYPES: frozenset[str] = frozenset({"nl", "sql"})
_FILENAME_SAFE_RE: re.Pattern[str] = re.compile(r"[^a-zA-Z0-9_-]")

MAX_NAME_LENGTH: int = 200
MAX_DESCRIPTION_LENGTH: int = 2000
MAX_RECIPIENTS: int = 200
MAX_STEPS_PER_IMPORT: int = 50
# Phase 1 DAG : borne le nombre d'aretes a l'import pour eviter un DoS
# via un JSON avec des milliers d'edges (DFS recursif cycle detection,
# boucle DB pour inserer les edges). 50 steps = theorique 2500 edges
# en graphe complet, en pratique <= 200 suffit largement.
MAX_EDGES_PER_IMPORT: int = 200
MAX_REORDER_STEPS: int = 100
MAX_RUNNING_DISPLAY: int = 10

#: AUTO-3 — fenêtre (s) pendant laquelle une exécution TERMINÉE reste remontée au
#: moniteur frontend avec son VRAI statut (success/failed/partial/cancelled),
#: pour qu'un run disparu de la liste « running » n'apparaisse pas faussement
#: « terminé » en vert. Doit couvrir l'intervalle de poll (3–15 s) + du slack.
_RECENT_FINISHED_WINDOW_SECONDS: int = 60
MAX_HISTORY_DAYS: int = 365
DEFAULT_HISTORY_DAYS: int = 7
MAX_IMPORT_FILE_BYTES: int = 512 * 1024

STEP_MAX_RETRIES_CAP: int = 5
STEP_RETRY_DELAY_MIN_SEC: int = 1
STEP_RETRY_DELAY_MAX_SEC: int = 60
STEP_RETRY_DELAY_DEFAULT_SEC: int = 5

DOWNLOAD_CHUNK_BYTES: int = 64 * 1024

# Rate-limit quotas (par utilisateur, fenetre glissante en secondes).
# Les endpoints IA/DB lourds sont isoles pour ne pas bloquer les lectures.
RATE_LIMIT_PREVIEW: tuple[int, int] = (10, 60)
RATE_LIMIT_EXECUTE: tuple[int, int] = (20, 60)
RATE_LIMIT_IMPORT: tuple[int, int] = (5, 60)
# Phase 1 DAG : limite les POST/DELETE sur les aretes. Chaque POST
# charge tous les steps + tous les edges + lance validate_structural,
# sans borne la surface DoS est reelle.
RATE_LIMIT_EDGES_WRITE: tuple[int, int] = (60, 60)
RATE_LIMIT_DUPLICATE: tuple[int, int] = (20, 60)
# Phase 3b : creation canvas. 10/min suffit pour un usage humain, bloque le
# spam d'un compte compromis ou d'un script buggy.
RATE_LIMIT_NEW_AUTOMATION: tuple[int, int] = (10, 60)

# Phase 3b-2 : autosave metadata (name, description, fail_policy, ...).
# Dedie pour ne pas starver le quota edges-write ; l'autosave du nom
# debounce a 800 ms cote canvas donc ~30/min suffit largement.
RATE_LIMIT_METADATA: tuple[int, int] = (30, 60)

# Phase 3c : replay execution. Bouton a un clic = spam accidentel possible,
# et chaque replay declenche un workflow complet (CPU + IO + LLM).
# Plus restrictif que /execute manuel (qui est typiquement un clic
# explicite avec saisie params).
RATE_LIMIT_REPLAY: tuple[int, int] = (5, 60)

# Cycle 5 fix — Toggle activation : limiter dedie pour eviter la starvation
# par `_edges_write_limiter` (60/min partage avec steps/edges/validate).
# Un user power-actif sur le canvas (drag-drop frequent = saturation
# edges_write) ne doit pas etre bloque pour activer/desactiver son auto.
# 30/min largement suffit (toggle est rarissime cote user reel).
RATE_LIMIT_TOGGLE: tuple[int, int] = (30, 60)

# Schedule API : preview + GET/PUT. Le preview est appele en debounce
# 300 ms au fil de la saisie utilisateur, donc un quota plus genereux
# que toggle (mais pas illimite — defense anti-DoS via spam validation
# cron). 60/min couvre une session d'edition active.
RATE_LIMIT_SCHEDULE: tuple[int, int] = (60, 60)

# Post-adversarial cluster-B 2026-05-26 — l'export GET produit maintenant un
# audit row + commit ; sans rate-limit, un user peut spammer
# ``/automations/:id/export`` pour gonfler ``audit_logs`` (DoS disk).
# 10/min/user couvre largement l'usage humain (export rare) + bot CI.
RATE_LIMIT_EXPORT: tuple[int, int] = (10, 60)

# Plafond hard par utilisateur. Defense en profondeur contre un compte
# compromis qui pourrait creer des milliers d'automations en contournant le
# rate-limit glissant. 500 = largement au-dela d'un usage humain realiste.
MAX_AUTOMATIONS_PER_USER: int = 500

# Limiters au module-scope : une instance par endpoint sensible. Thread-safe.
_preview_limiter = RateLimiter()
_execute_limiter = RateLimiter()
_import_limiter = RateLimiter()
_edges_write_limiter = RateLimiter()
_duplicate_limiter = RateLimiter()
_new_automation_limiter = RateLimiter()
_metadata_limiter = RateLimiter()
_replay_limiter = RateLimiter()
_toggle_limiter = RateLimiter()
_schedule_limiter = RateLimiter()
_export_limiter = RateLimiter()


# ── Helpers reutilisables ─────────────────────────────────────


def _check_rate_limit(
    limiter: RateLimiter, user_id: int, max_requests: int, window_seconds: int
) -> None:
    """Leve HTTPError(429) si le rate-limit utilisateur est depasse.

    Centraliser le lookup + l'erreur evite que chaque handler reimplemente
    le meme pattern avec des status codes et messages inconsistants.
    """
    key = f"user:{user_id}"
    if not limiter.check(key, max_requests=max_requests, window_seconds=window_seconds):
        raise tornado.web.HTTPError(
            429,
            "Trop de requetes. Veuillez patienter quelques secondes.",
        )


async def _get_owned_automation_or_404(
    session: AsyncSession,
    automation_id: int,
    user_id: int,
    *,
    options: Optional[list] = None,
) -> Automation:
    """Recupere une automation ou leve 404 (soit absente, soit non-ownee).

    **Securite** : on retourne 404 pour les deux cas (absent / pas owner).
    Un 403 sur ID valide+non-owner permettrait d'enumerer les IDs existants
    (information disclosure CWE-284/203).
    """
    if options:
        automation = await session.get(Automation, automation_id, options=options)
    else:
        automation = await session.get(Automation, automation_id)
    if not automation or automation.user_id != user_id:
        raise tornado.web.HTTPError(404, "Automatisation non trouvee")
    return automation


async def _get_owned_then_rate_limit(
    session: AsyncSession,
    automation_id: int,
    user_id: int,
    limiter: RateLimiter,
    max_requests: int,
    window_seconds: int,
    *,
    options: Optional[list] = None,
) -> Automation:
    """S4 — Helper combo : ownership 404 D'ABORD, rate-limit APRES.

    Sans cet ordre, un attaquant qui spam ``/automations/<random_id>/toggle``
    distingue 429 (sa propre limite de spam, donc l'ID existe + il est
    rate-limite par sa propre activite) vs 404 (ID absent ou non-owne).
    Cela permet d'enumerer les IDs valides (oracle CWE-204).

    L'ordre correct est :
    1. ``_get_owned_automation_or_404`` (404 si pas owne) → l'attaquant
       voit toujours 404 sans aucun signal sur l'existence.
    2. ``_check_rate_limit`` (429 si quota depasse) → uniquement applique
       sur les ressources legitimement owned, donc pas d'oracle.

    Ce helper centralise pour empecher la regression : tout handler qui
    veut faire les deux DOIT passer par ici, pas reimplementer en local.

    Args:
        session: Session async ouverte.
        automation_id: ID a verifier.
        user_id: ID de l'utilisateur courant (pour ownership check).
        limiter: ``RateLimiter`` de la categorie d'action.
        max_requests, window_seconds: parametres du quota.
        options: Optional ``selectinload`` chargements pour eviter les
            lazy-load post-session (ex: ``[selectinload(Automation.steps)]``).

    Returns:
        L'``Automation`` chargee si owned ET sous quota.

    Raises:
        HTTPError(404) si l'automation est absente ou non-ownee.
        HTTPError(429) si le quota est depasse (apres validation ownership).
    """
    automation = await _get_owned_automation_or_404(
        session, automation_id, user_id, options=options
    )
    _check_rate_limit(limiter, user_id, max_requests, window_seconds)
    return automation


def _utc_naive_now() -> datetime:
    """Retourne un datetime UTC naive (pour comparaisons SQLite).

    SQLAlchemy DateTime sur SQLite stocke sans tzinfo. Le code ecrit
    un instant tz-aware, mais au read-back il redevient naive. Pour
    comparer (``column >= cutoff``), le cutoff doit etre naive UTC aussi
    — sinon TypeError ou 8h de decalage.
    """
    return clock.naive_utc()


# =============================================================================
# Cluster-N 2026-05-26 — Optimistic concurrency multi-onglets
# =============================================================================
#
# 2 onglets ouverts sur la même automation → silent overwrite si rien ne
# protège. Le contrat : chaque ressource a un champ `version` monotone
# incrémenté à chaque mutation. Le client envoie `If-Match: <version>`
# sur PUT ; serveur compare-and-swap atomique → 200 ou 409 Conflict.
#
# Strict mode désactivé par défaut (rétrocompat clients legacy sans
# header). Quand le header est présent, on l'enforce → 409.


def _parse_if_match_version(handler: Any) -> Optional[int]:
    """Lit `If-Match: <int>` du request. Retourne None si absent/invalide.

    Tolère les guillemets ETag standard (`"42"`) car certaines libs
    HTTP les rajoutent automatiquement. Le préfixe W/ (weak ETag) est
    refusé car la sémantique d'égalité diffère.
    """
    raw = handler.request.headers.get("If-Match")
    if not raw:
        return None
    cleaned = raw.strip()
    if cleaned.startswith("W/"):
        # Weak ETag — sémantique différente, on refuse pour éviter
        # ambiguïté plutôt qu'accepter avec un cap caché.
        return None
    cleaned = cleaned.strip('"').strip("'")
    if not cleaned or cleaned == "*":
        # `*` signifie "n'importe quelle version" → équivaut à pas de
        # header pour notre besoin (pas de protection demandée).
        return None
    try:
        version = int(cleaned)
    except (TypeError, ValueError):
        return None
    if version < 0:
        return None
    return version


def _set_etag_header(handler: Any, version: int) -> None:
    """Pose l'en-tête `ETag: "<version>"` sur la réponse.

    Format quoted-string conforme RFC 7232. Le client lit ce header
    pour mettre à jour son state local sans re-fetch.
    """
    handler.set_header("ETag", f'"{int(version)}"')


def _emit_version_conflict(
    handler: Any,
    current_version: Optional[int],
    *,
    resource: str = "automation",
) -> None:
    """409 Conflict standardisé pour cluster-N.

    Le client reçoit la version BDD courante pour pouvoir re-merger
    intelligemment (ou simplement re-fetch et ré-essayer).
    """
    handler.set_status(409)
    payload: Dict[str, Any] = {
        "success": False,
        "error": (
            "Cette ressource a été modifiée par un autre onglet ou "
            "session. Rafraîchissez la page et réessayez."
        ),
        "code": "version_conflict",
        "resource": resource,
    }
    if current_version is not None:
        payload["current_version"] = int(current_version)
        _set_etag_header(handler, current_version)
    handler.write(payload)


async def _cas_bump_automation_version(
    session: AsyncSession,
    automation_id: int,
    expected_version: int,
) -> Optional[int]:
    """Atomic compare-and-swap sur Automation.version.

    Émet `UPDATE ... WHERE id = ? AND version = ?` ; retourne la nouvelle
    version si rowcount=1, sinon None (= race ou mismatch).

    Safe en multi-instance car la WHERE-clause sert de lock optimiste :
    deux UPDATE concurrents avec la même expected_version → un seul
    rowcount=1, l'autre rowcount=0.
    """
    from sqlalchemy import update as sa_update

    new_version = int(expected_version) + 1
    result = await session.execute(
        sa_update(Automation)
        .where(
            Automation.id == automation_id,
            Automation.version == int(expected_version),
        )
        .values(version=new_version)
    )
    if (result.rowcount or 0) != 1:
        return None
    return new_version


def _check_if_match_or_409(
    handler: Any,
    automation: Automation,
) -> bool:
    """Vérifie le header If-Match en début de handler — fail-fast.

    Retourne True si la version client matche (ou si If-Match absent
    = rétro-compat opt-in). Retourne False + 409 écrit sur réponse
    si mismatch. NE BUMP PAS — le bump est l'acte LAST-WRITE avant
    commit (cf. ``_bump_version_and_set_etag``).

    Cette séparation évite les ETag fantômes : si le handler return
    early (404, validation 400, no-op) APRÈS un bump, le SQL UPDATE
    est rollback mais le client a stocké un ETag inexistant en BDD
    → boucle 409 perma. Pattern correct = check first, work, bump last.
    """
    expected = _parse_if_match_version(handler)
    if expected is None:
        # Rétro-compat opt-in : pas de header = pas de protection.
        # Logger WARN pour mesurer le bypass en prod (cf. cluster-N
        # adversarial CRIT-2 : sans ce log, on ignore combien de
        # clients legacy contournent la protection).
        logger.warning(
            "[cluster-N] PUT sans If-Match (rétro-compat) auto=%s — "
            "client legacy ou bypass intentionnel",
            getattr(automation, "id", "?"),
            extra={"automation_id": getattr(automation, "id", None)},
        )
        return True
    current_db_version = int(automation.version or 1)
    if expected != current_db_version:
        _emit_version_conflict(handler, current_db_version)
        return False
    return True


async def _bump_version_and_set_etag(
    handler: Any,
    session: AsyncSession,
    automation: Automation,
) -> Optional[int]:
    """LAST-WRITE atomic bump avant commit. Pose ETag header en succès.

    Doit être appelé APRÈS toutes les validations qui peuvent rollback
    (404, 400 schéma, validate_structural, etc.). Si le caller fait
    rollback APRÈS cet appel, le UPDATE CAS est aussi rollback (même
    transaction) — ETag header reste posté mais le client le verra
    DANS UN 5xx (pas un 200), donc il n'override pas son state local.

    Retourne la nouvelle version ou None (= 409 émis, caller return).
    """
    current = int(automation.version or 1)
    new_version = await _cas_bump_automation_version(session, automation.id, current)
    if new_version is None:
        # Race avec un autre commit (multi-instance ou autre handler) : la
        # version BDD a bougé → la CAS a matché 0 ligne.
        #
        # ⚠️ ROLLBACK OBLIGATOIRE avant d'émettre le 409 (fix consolidé
        # 2026-06-10). ``db_session()`` (base.py) COMMIT sur sortie NORMALE du
        # bloc ``async with`` (``yield`` puis ``session.commit()``), et tous les
        # callers font ``return`` sur ce ``None``. Sans rollback ici, la
        # mutation déjà ``flush``ée (step/edge ajouté) serait PERSISTÉE alors
        # qu'on répond 409 « rejeté » → changement commité sans bump de version
        # + réponse d'échec = incohérence (donnée fausse silencieuse cross-tab).
        # Le rollback garantit la sémantique « conflit → rien n'est persisté →
        # le client retry sur l'état à jour ». Corrige les 8 call-sites d'un
        # coup (SSoT du bump optimiste).
        await session.rollback()
        # Relire APRÈS rollback pour donner au client la version exacte (le
        # rollback a expiré l'identity-map → ``get`` re-SELECT la vraie valeur).
        refreshed = await session.get(Automation, automation.id)
        current_db = int(refreshed.version) if refreshed else current
        _emit_version_conflict(handler, current_db)
        return None
    automation.version = new_version
    _set_etag_header(handler, new_version)
    return new_version


async def _check_and_bump_or_409(
    handler: Any,
    session: AsyncSession,
    automation: Automation,
) -> Optional[int]:
    """[DEPRECATED — utiliser _check_if_match_or_409 + _bump_version_and_set_etag]

    Conservé pour rétro-compat tests. Combine check + bump en un seul
    acte → expose au bug ETag fantôme si caller return early après.
    Préférer le split en deux helpers pour pattern correct.
    """
    if not _check_if_match_or_409(handler, automation):
        return None
    return await _bump_version_and_set_etag(handler, session, automation)


def _validated_execution_status(raw: Optional[str]) -> Optional[str]:
    """Retourne ``raw`` si c'est un statut Execution valide (SSoT
    ``Execution.all_statuses()``), sinon ``None`` (A7-F6).

    Sans cette validation, un filtre statut inconnu (typo, URL trafiquée)
    produisait ``WHERE status='xxx'`` → 0 ligne, et l'utilisateur croyait
    qu'il n'avait AUCUNE exécution (faux vide trompeur — données fausses
    silencieuses). Un statut invalide est ignoré (on montre tout), jamais
    transformé en résultat vide. Même philosophie graceful que
    ``_apply_days_filter`` (filtre facultatif → pas de 400).
    """
    if raw and raw in Execution.all_statuses():
        return raw
    return None


def _apply_days_filter(
    query,
    days_arg: Optional[str],
    column,
    *,
    default_days: int = DEFAULT_HISTORY_DAYS,
    max_days: int = MAX_HISTORY_DAYS,
):
    """Applique un filtre ``column >= now - days`` si ``days_arg`` fourni.

    Extrait du pattern duplique 3x (history, executions API, all executions).
    Un input non-convertible retombe sur ``default_days`` plutot que 400 pour
    preserver l'UX (l'utilisateur voit ses donnees, pas un ecran d'erreur
    sur un argument facultatif).
    """
    if not days_arg:
        return query
    try:
        days_int = min(max(int(days_arg), 1), max_days)
    except (ValueError, TypeError):
        days_int = default_days
    cutoff = _utc_naive_now() - timedelta(days=days_int)
    return query.where(column >= cutoff)


def _extract_email_list(raw: Any) -> list[str]:
    """Normalise une liste d'emails (accepte CSV, liste, ou autre).

    Les inputs non-string ou invalides sont ecartes silencieusement — un
    email mal forme dans une liste ne doit pas bloquer l'enregistrement de
    l'automatisation, c'est juste un destinataire de moins.
    """
    if isinstance(raw, str):
        raw = [e.strip() for e in raw.split(",") if e.strip()]
    if not isinstance(raw, list):
        return []
    emails = [r.strip() for r in raw if isinstance(r, str) and is_valid_email(r)]
    return emails[:MAX_RECIPIENTS]


def _coerce_strict_bool_or_400(
    data: dict, key: str, default: bool = False, *, required: bool = False
) -> bool:
    """Extrait ``data[key]`` en strict_bool — leve HTTPError(400) sinon.

    Empeche le mass-assignment via strings truandees (``"false"`` ->
    ``True``). Si la cle est absente et ``required=False``, on utilise
    ``default``.
    """
    if key not in data:
        if required:
            raise tornado.web.HTTPError(400, f"Champ obligatoire manquant : {key}")
        return default
    try:
        return strict_bool(data[key], field=key)
    except (ValueError, TypeError) as e:
        raise tornado.web.HTTPError(400, str(e)) from e


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    """Borne un entier dans [lo, hi] ; retombe sur ``default`` si non-int."""
    try:
        return min(max(int(value), lo), hi)
    except (ValueError, TypeError):
        return default


def _sanitize_error_message(raw: Optional[str], *, max_length: int = 500) -> Optional[str]:
    """Filtre une stack-trace / exception avant exposition a l'utilisateur.

    Phase 3c : ``StepExecution.error_message`` peut contenir le retour brut
    de ``traceback.format_exc()`` ou un ``repr(exc)`` issu de pyodbc/httpx
    qui inclut paths absolus, mots de passe encodes dans une connection
    string, tokens API (CWE-209 Information Exposure Through an Error
    Message). On supprime :

    * les lignes ``  File "/abs/path/...", line N, in func`` (stack frames)
    * les lignes ``    <code>`` qui suivent (les indents 4-spaces de la
      stack)
    * les motifs ``password=...`` / ``pwd=...`` / ``token=...``

    Puis on tronque a ``max_length`` caracteres pour eviter les messages
    multi-lignes verbeux qui cassent le layout. Le suffixe ``…`` indique
    la troncature.

    None reste None.
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        raw = str(raw)

    lines = raw.splitlines()
    cleaned: list[str] = []
    skip_next_indent = False
    for line in lines:
        stripped = line.strip()
        # Stack frame : "  File "...", line N, in ..."
        if stripped.startswith('File "') and ", line " in stripped:
            skip_next_indent = True
            continue
        # Ligne suivante = code source du frame (indent 4+ spaces).
        if skip_next_indent and (line.startswith("    ") or stripped == ""):
            skip_next_indent = False
            continue
        skip_next_indent = False
        # Filtrer les credentials connus dans les connection strings.
        masked = re.sub(
            r"(password|pwd|token|secret|api[-_]key)\s*=\s*[^;\s'\"]+",
            r"\1=***",
            line,
            flags=re.IGNORECASE,
        )
        cleaned.append(masked)

    result = "\n".join(cleaned).strip()
    if len(result) > max_length:
        result = result[:max_length].rstrip() + "…"
    return result or None


async def _safe_error_for_user(
    raw: Optional[str],
    user: Any,
    *,
    max_length: int = 500,
) -> Optional[str]:
    """**Mode invisible rétroactif sur les erreurs d'automation** —
    Sanitize (stack/credentials/troncate) PUIS scrub data_access (noms
    de tables denied → ``[…]``).

    Sans ce wrapper, ``error_message`` raw exposé dans
    ``automations/history.html`` ou les API JSON pouvait contenir
    ``"Invalid object name 'F_SALAIRES'. (208)"`` — leak du nom de
    table interdite à l'utilisateur qui consulte son historique
    d'automations, en violation du mode invisible.

    Ordre des opérations :

    1. :func:`_sanitize_error_message` : strip stack frames, masque
       les credentials, tronque à ``max_length``. Comportement
       inchangé pour les call-sites qui appelaient déjà ce sanitize.
    2. :func:`scrub_text_for_user` : remplace les noms denied par
       ``[…]`` (no-op pour admin / sans restrictions).

    Args :
        raw : message d'erreur brut (Optional pour préserver le
            comportement legacy ``None → None``).
        user : utilisateur qui consultera l'erreur. ``None`` accepté
            pour les callers admin / scheduled jobs (skip scrub).
        max_length : longueur max après sanitize (cohérent avec
            ``_sanitize_error_message``).

    Fail-safe : si le scrub crash, on retourne la version sanitizée
    (mieux qu'aucun message d'erreur).
    """
    sanitized = _sanitize_error_message(raw, max_length=max_length)
    if not sanitized or user is None:
        return sanitized
    from app.services.data_access.error_messages import scrub_text_for_user

    try:
        return await scrub_text_for_user(sanitized, user, context_label="automation_error")
    except Exception as exc:  # noqa: BLE001 — fail-safe explicite + alertable
        # Cluster-C 2026-05-26 — Logger explicitement l'exception du scrub :
        # avant, le ``return sanitized`` silencieux masquait les bugs de
        # ``scrub_text_for_user`` (regex mal formé, exception sur pattern)
        # → le user voyait potentiellement des noms de tables denied sans
        # qu'on le sache. Le fail-safe reste pour ne pas casser l'UI, mais
        # l'incident est désormais visible dans les logs ERROR (alertable
        # via watchdog).
        logger.error(
            "_safe_error_for_user: scrub_text_for_user a échoué — "
            "fallback sur la version sanitizée. Mode invisible peut être "
            "compromis sur cette réponse (user_id=%s, exception=%r)",
            getattr(user, "id", "?"),
            exc,
            exc_info=True,
        )
        return sanitized


# Cap des champs config libres de type "text" (body email, instructions
# copilot/iris, prompt rapport). Aligne sur la convention email pro
# ``contact_mailer_service.MAX_EMAIL_BODY_LENGTH = 10_000`` (constante non
# importee : ce cap couvre TOUS les champs texte de step, pas que les emails).
# Donnees reelles : la plus grosse config persistee fait < 400 caracteres —
# le cap protege la colonne JSON et les emails sortants (croissance non
# bornee, axe 21) sans jamais toucher un usage legitime.
_TEXT_CONFIG_MAX_CHARS = 10_000


def _validate_step_config(step_type: str, config: dict) -> Optional[str]:
    """Valide la config d'un step contre ``STEP_TYPE_META[step_type]``.

    - Cles inconnues : rejetees a la source (evite qu'un client malicieux
      pousse des champs arbitraires dans la JSON BDD, exploitables en aval).
    - Champs de type ``text`` (textarea libre) : doivent etre des str
      (ou None/absents) et tenir sous ``_TEXT_CONFIG_MAX_CHARS`` — un body
      multi-Mo pousse via l'API gonflerait la colonne JSON et chaque email
      envoye (self-DoS stockage/deliverabilite).
    Retourne un message d'erreur en cas de probleme, None sinon.
    """
    try:
        step_type_enum = StepType(step_type)
    except ValueError:
        return f"Type d'etape invalide : {step_type}"
    meta = STEP_TYPE_META.get(step_type_enum)
    if not meta:
        return f"Meta de type manquante : {step_type}"
    schema = meta.get("config_schema", {})
    allowed_keys = set(schema.keys())
    extra = set(config.keys()) - allowed_keys
    if extra:
        return f"Cles de config inconnues pour {step_type}: {', '.join(sorted(extra))}"
    for key, spec in schema.items():
        if spec.get("type") != "text" or key not in config:
            continue
        val = config[key]
        if val is None:
            continue
        if not isinstance(val, str):
            return f"Le champ « {key} » doit etre du texte."
        if len(val) > _TEXT_CONFIG_MAX_CHARS:
            return f"Le champ « {key} » depasse {_TEXT_CONFIG_MAX_CHARS} caracteres ({len(val)})."
    return None


def _sanitize_filename(name: str, *, max_len: int = 50) -> str:
    """Produit un nom de fichier ASCII-safe pour Content-Disposition.

    Strip les caracteres non ``[a-zA-Z0-9_-]``, coupe a ``max_len``, et
    passe par ``assert_no_crlf`` comme defense-in-depth contre CRLF header
    injection. Retourne ``"export"`` si le resultat est vide (fallback
    stable plutot qu'un filename vide qui casse certains clients).
    """
    if not isinstance(name, str):
        name = "export"
    cleaned = _FILENAME_SAFE_RE.sub("_", name).strip("_")[:max_len] or "export"
    return assert_no_crlf(cleaned, field="filename")


async def _audit_automation_event(
    handler: AuthenticatedHandler,
    session: AsyncSession,
    *,
    action: str,
    entity_type: str = "automation",
    entity_id: Optional[int] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Cluster-B 2026-05-26 — helper local DRY pour ``audit_event``.

    Extrait automatiquement ``user_id`` / ``ip`` / ``user_agent`` /
    ``request_id`` depuis le handler — élimine ~6 lignes de boilerplate
    sur chaque call-site CRUD/lifecycle de ce fichier (~17 sites).

    Doctrine compliance : l'audit est ajouté à la session MAIS le
    commit reste la responsabilité du caller (atomic avec sa
    mutation). Cf. ``app/services/audit/audit_log.py`` pour le détail.
    """
    merged = dict(details or {})
    # Post-adversarial 2026-05-26 — `setdefault` ne replace pas None par
    # le request_id du handler ; on veut "inherit si absent OU None".
    if not merged.get("request_id"):
        merged["request_id"] = getattr(handler, "request_id", None)
    user_id = handler.current_user.id if handler.current_user else None
    # Defensive : certains tests construisent un handler sans request réel.
    # En prod, BaseHandler.prepare garantit que self.request est présent.
    request = getattr(handler, "request", None)
    ip_address = getattr(request, "remote_ip", None) if request is not None else None
    ua: Optional[str] = None
    if request is not None:
        try:
            ua = request.headers.get("User-Agent", "") or None
        except (AttributeError, TypeError):
            ua = None
    # Tronquer UA à une borne raisonnable — le schéma audit_logs.user_agent
    # est Text mais des UA monstres (custom clients) pollueraient la table.
    if ua and len(ua) > 500:
        ua = ua[:500]
    await audit_event(
        session,
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=merged,
        ip_address=ip_address,
        user_agent=ua,
    )


class AutomationsListHandler(AuthenticatedHandler):
    """Liste des automatisations de l'utilisateur"""

    @require_role("admin", "user")
    async def get(self) -> None:
        """Affiche la liste des automatisations avec filtres et pagination"""
        # Paramètres de filtrage
        status = self.get_argument("status", None)
        page = self._parse_int_or_400(self.get_argument("page", "1"), "page")
        # A7-F5 — clamp page >= 1 : un page <= 0 produisait un OFFSET négatif
        # ((page-1)*per_page) silencieusement traité comme page 1 par certains
        # backends, ou une erreur SQL selon le moteur. On ramène gentiment à 1
        # (cohérent avec le clamp pagination de email_history).
        if page < 1:
            page = 1
        per_page = AUTOMATIONS_PER_PAGE

        # Recuperer les automatisations de l'utilisateur
        async with self.db_session() as session:
            # Base query — eager-load steps to detect workflow mode
            query = (
                select(Automation)
                .options(selectinload(Automation.steps))
                .where(Automation.user_id == self.current_user.id)
            )

            # Appliquer filtres
            if status == "active":
                query = query.where(Automation.is_active == True)  # noqa: E712
            elif status == "inactive":
                query = query.where(Automation.is_active == False)  # noqa: E712

            # Compter total (avant pagination)
            count_result = await session.execute(select(func.count()).select_from(query.subquery()))
            total_count = count_result.scalar()
            total_pages = (total_count + per_page - 1) // per_page

            # Appliquer pagination et tri
            query = query.order_by(Automation.created_at.desc())
            query = query.offset((page - 1) * per_page).limit(per_page)

            result = await session.execute(query)
            automations = result.scalars().all()

            # Statistiques pour toutes les automatisations en un seul query
            auto_ids = [auto.id for auto in automations]
            if auto_ids:
                stats_result = await session.execute(
                    select(
                        Execution.automation_id,
                        func.count(Execution.id).label("total"),
                        func.sum(case((Execution.status == "success", 1), else_=0)).label(
                            "success"
                        ),
                    )
                    .where(Execution.automation_id.in_(auto_ids))
                    .group_by(Execution.automation_id)
                )
                stats_map = {row.automation_id: row for row in stats_result}
            else:
                stats_map = {}

            # Batch-load des jobs scheduler (evite N+1 queries)
            scheduler = get_scheduler()
            all_jobs = {job.id: job for job in scheduler.get_jobs()}

            # Batch-load webhook counts (avoid N+1)
            webhook_counts_map = {}
            if auto_ids:
                wh_result = await session.execute(
                    select(
                        WebhookTrigger.automation_id,
                        func.count(WebhookTrigger.id).label("wh_count"),
                    )
                    .where(WebhookTrigger.automation_id.in_(auto_ids))
                    .group_by(WebhookTrigger.automation_id)
                )
                webhook_counts_map = {row.automation_id: row.wh_count for row in wh_result}

            # Construire les résultats avec les stats
            # Capture ORM data inside session (avoid MissingGreenlet in template)
            automation_stats = []
            for auto in automations:
                stats_row = stats_map.get(auto.id)
                total = stats_row.total if stats_row else 0
                success = stats_row.success if stats_row else 0

                # Lookup direct dans le batch (O(1) par automation)
                next_run = None
                if auto.is_active:
                    job = all_jobs.get(f"automation_{auto.id}")
                    if job:
                        next_run = job.next_run_time

                # Output summary : derive du DAG (sinks reels) plutot que
                # de l'ancien `output_format` (legacy mono-step). Affiche
                # ce que l'automation PRODUIT vraiment (PDF + Excel/CSV +
                # Email + sauvegarde datastore). Vide si aucun sink — le
                # template masque la pastille dans ce cas.
                _sink_types = {
                    (s.step_type.value if hasattr(s.step_type, "value") else s.step_type)
                    for s in (auto.steps or [])
                }
                _summary_parts: list[str] = []
                if "report" in _sink_types:
                    _summary_parts.append("PDF")
                if "export_workbook" in _sink_types:
                    # Distinguer Excel vs CSV depuis la config quand possible
                    # (utile : 2 automations avec mêmes step_types mais
                    # exports différents auront des badges différents).
                    _fmts = set()
                    for _s in auto.steps or []:
                        _st = _s.step_type.value if hasattr(_s.step_type, "value") else _s.step_type
                        if _st != "export_workbook":
                            continue
                        _f = (_s.config or {}).get("format") or "excel"
                        _fmts.add(str(_f).lower())
                    if "excel" in _fmts and "csv" in _fmts:
                        _summary_parts.append("Excel+CSV")
                    elif "csv" in _fmts:
                        _summary_parts.append("CSV")
                    else:
                        _summary_parts.append("Excel")
                if "save_to_datastore" in _sink_types:
                    _summary_parts.append("Datastore")
                if "email" in _sink_types:
                    _summary_parts.append("Email")
                output_summary = " · ".join(_summary_parts)

                automation_stats.append(
                    {
                        "automation": SimpleNamespace(
                            id=auto.id,
                            name=auto.name,
                            description=auto.description,
                            is_active=auto.is_active,
                            schedule_type=auto.schedule_type,
                            output_format=auto.output_format,
                            output_summary=output_summary,
                            created_at=auto.created_at,
                            is_workflow=bool(auto.steps),
                            step_count=len(auto.steps),
                            has_webhooks=webhook_counts_map.get(auto.id, 0) > 0,
                            has_notifications=(auto.notify_on_failure or auto.notify_on_success),
                        ),
                        "total_executions": total,
                        "successful_executions": success,
                        "success_rate": (success / total * 100) if total else 0,
                        "next_run_time": next_run,
                    }
                )

        self.render(
            "automations/list.html",
            automations=automation_stats,
            page=page,
            total_pages=total_pages,
            status_filter=status,
            page_title="Mes Automatisations",
        )


class AutomationCreateHandler(AuthenticatedHandler):
    """Creation / mise a jour d'une automatisation (simple ou workflow)."""

    @require_role("admin", "user")
    async def post(self) -> None:
        """Cree ou met a jour une automatisation."""
        try:
            data = self.get_json_body()
        except tornado.web.HTTPError:
            raise

        try:
            payload = self._validate_create_payload(data)
        except tornado.web.HTTPError:
            raise
        except ValueError as e:
            self.set_status(400)
            self.write({"success": False, "error": str(e)})
            return

        try:
            async with self.db_session() as session:
                if payload["automation_id"] is not None:
                    automation = await _get_owned_automation_or_404(
                        session, payload["automation_id"], self.current_user.id
                    )
                    was_active = automation.is_active
                    if was_active:
                        await unschedule_automation(automation.id)
                else:
                    automation = Automation(user_id=self.current_user.id)
                    session.add(automation)

                for field, value in payload["fields"].items():
                    setattr(automation, field, value)

                # Real-review #2 cycle 23 : si on active via cette route
                # legacy, valider le DAG d'abord — sinon BUG-D bypass.
                # On charge les steps+edges pour valider. Cohérent avec
                # AutomationToggleHandler.
                if automation.is_active:
                    from app.services.automation.dag_validator import (
                        errors_to_json,
                        validate_all,
                    )

                    # Eager-load (en cas de auto existante avec déjà des steps)
                    if payload["automation_id"] is not None:
                        await session.refresh(automation, attribute_names=["steps", "edges"])

                    pre_nodes = [
                        {
                            "id": s.id,
                            "step_type": (
                                s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                            ),
                            "name": s.name,
                            "config": s.config or {},
                            "is_enabled": s.is_enabled,
                        }
                        for s in (automation.steps or [])
                    ]
                    pre_edges = [
                        {
                            "id": e.id,
                            "from_step_id": e.from_step_id,
                            "to_step_id": e.to_step_id,
                            "data_type": e.data_type,
                        }
                        for e in (automation.edges or [])
                    ]
                    pre_errors = list(validate_all(pre_nodes, pre_edges, for_activation=True))
                    if pre_errors:
                        await session.rollback()
                        self.set_status(400)
                        self.write(
                            {
                                "success": False,
                                "error": "Activation refusee : le workflow est incomplet.",
                                "errors": errors_to_json(pre_errors),
                            }
                        )
                        return

                # Cluster-B 2026-05-26 — audit avant commit (atomic).
                # Cette route legacy gère CREATE et UPDATE en un seul endpoint
                # selon ``payload["automation_id"]``. On flush d'abord pour
                # garantir un ID assigné côté CREATE, puis audit.
                if payload["automation_id"] is None:
                    await session.flush()
                    audit_action = AuditAction.AUTOMATION_CREATE
                else:
                    audit_action = AuditAction.AUTOMATION_UPDATE
                await _audit_automation_event(
                    self,
                    session,
                    action=audit_action,
                    entity_id=automation.id,
                    details={
                        "name": automation.name,
                        "source": "legacy_create_handler",
                        "fields_changed": sorted(payload["fields"].keys()),
                    },
                )
                await session.commit()
                await session.refresh(automation)

                # Capturer les attributs tant que la session est ouverte pour
                # eviter MissingGreenlet lors du log/schedule apres commit.
                new_is_active = automation.is_active
                auto_id = automation.id
                auto_name = automation.name
                detached_copy = automation

                # Tracking T3.1 — uniquement à la CRÉATION (pas update). Le
                # payload ``automation_id is None`` discrimine. Best-effort
                # via ``begin_nested()`` (savepoint) pour ISOLER tout échec
                # du tracker : sans savepoint, une UniqueConstraintViolation
                # ou autre erreur SQL dans le tracker mettrait la session
                # en ``pending_rollback`` et casserait le commit final
                # → automation perdue. Le savepoint cantonne le rollback
                # au tracker lui-même.
                if payload.get("automation_id") is None:
                    try:
                        from app.services.onboarding import track_automation_created

                        async with session.begin_nested():
                            await track_automation_created(session, self.current_user.id)
                    except Exception:  # noqa: BLE001 — fail-soft télémétrie
                        logger.debug("track_automation_created non écrit", exc_info=True)

                if new_is_active:
                    await schedule_automation(detached_copy)

                # Hook auto-scan anonymization (fire-and-forget) — alimente
                # /data/privacy sans attendre "Scanner mes données".
                from app.services.anonymization.auto_scan import (
                    schedule_target_rescan,
                )

                schedule_target_rescan(self.current_user.id, "automation", int(auto_id))

            action = "creee" if payload["automation_id"] is None else "mise a jour"
            logger.info(
                "Automatisation %s: %s",
                action,
                auto_name,
                extra={"automation_id": auto_id, "user_id": self.current_user.id},
            )
            self.write(
                {
                    "success": True,
                    "automation_id": auto_id,
                    "message": "Automatisation enregistree avec succes",
                }
            )
        except SQLAlchemyError as e:
            logger.error("Erreur creation automatisation: %s", e, exc_info=True)
            raise tornado.web.HTTPError(
                500,
                "Une erreur est survenue lors de la creation de l'automatisation.",
            )

    def _validate_create_payload(self, data: Any) -> dict:
        """Retourne un dict valide ou leve ValueError / HTTPError.

        Centralise la validation pour que le handler reste focalise sur
        l'orchestration BDD. Tout cas d'echec est traduit explicitement
        (pas de silent-coerce) — evite les bugs de type mass-assignment.
        """
        if not isinstance(data, dict):
            raise ValueError("Body JSON doit etre un objet.")

        name = (data.get("name") or "").strip() if isinstance(data.get("name"), str) else ""
        if not name:
            raise ValueError(f"Le nom est requis (max {MAX_NAME_LENGTH} caracteres).")
        if len(name) > MAX_NAME_LENGTH:
            raise ValueError(f"Le nom est trop long (max {MAX_NAME_LENGTH} caracteres).")

        query_text = (
            data.get("query_text", "").strip() if isinstance(data.get("query_text"), str) else ""
        )
        if not query_text:
            raise ValueError("La requete est requise.")

        description = (
            data.get("description", "").strip() if isinstance(data.get("description"), str) else ""
        )
        if len(description) > MAX_DESCRIPTION_LENGTH:
            raise ValueError(f"Description trop longue (max {MAX_DESCRIPTION_LENGTH} caracteres).")

        query_type = data.get("query_type", "nl")
        if query_type not in _VALID_QUERY_TYPES:
            raise ValueError("Type de requete invalide.")

        output_format = data.get("output_format", "csv")
        if output_format not in _VALID_OUTPUT_FORMATS:
            # A7-F1 — cohérence + anti-format-faux-silencieux : avant, un
            # output_format invalide était coercé EN SILENCE vers "csv" (l'user
            # demandait pdf → recevait csv sans le savoir), alors que query_type
            # et schedule_type lèvent 400. On lève aussi ici.
            raise ValueError("Format de sortie invalide.")

        schedule_type = data.get("schedule_type", "daily")
        if schedule_type not in _VALID_SCHEDULE_TYPES:
            raise ValueError("Type de planification invalide.")

        schedule_config = data.get("schedule_config", {})
        if not isinstance(schedule_config, dict):
            schedule_config = {}

        if schedule_type == "cron":
            cron_expr = schedule_config.get("cron", "")
            if not cron_expr:
                raise ValueError("Expression cron requise pour ce type de planification.")
            try:
                validate_cron_expression(cron_expr)
            except ValueError as e:
                raise ValueError(f"Expression cron invalide : {e}") from e

        recipients = _extract_email_list(data.get("recipients", []))
        notification_emails = _extract_email_list(data.get("notification_emails", []))

        notify_on_failure = _coerce_strict_bool_or_400(data, "notify_on_failure", default=True)
        notify_on_success = _coerce_strict_bool_or_400(data, "notify_on_success", default=False)
        is_active = _coerce_strict_bool_or_400(data, "is_active", default=True)

        raw_automation_id = data.get("id")
        automation_id: Optional[int] = None
        if raw_automation_id is not None:
            try:
                automation_id = int(raw_automation_id)
            except (ValueError, TypeError) as e:
                raise ValueError("ID d'automatisation invalide.") from e

        return {
            "automation_id": automation_id,
            "fields": {
                "name": name,
                "description": description,
                "query_type": query_type,
                "query_text": query_text,
                "schedule_type": schedule_type,
                "schedule_config": schedule_config,
                "output_format": output_format,
                "recipients": recipients,
                "notify_on_failure": notify_on_failure,
                "notify_on_success": notify_on_success,
                "notification_emails": notification_emails or None,
                "is_active": is_active,
            },
        }


class AutomationToggleHandler(AuthenticatedHandler):
    """Activer / desactiver une automatisation.

    Activation : applique ``validate_all(for_activation=True)`` pour
    refuser une activation si le DAG est incomplet (sans source / sans
    sink / node orphelin / double delivery email). La desactivation est
    toujours autorisee — on ne veut pas bloquer un utilisateur qui
    essaie de couper un workflow cassé.
    """

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Toggle le statut actif d'une automatisation.

        **Securite** : 404 sur ID invalide OU non-owner (pas de 403, pour
        eviter l'enumeration d'IDs — voir EPIC:HANDLERS-404-SYMMETRY).
        **Integrite** : refuse l'activation si le DAG ne passe pas
        ``validate_all(for_activation=True)`` — defense en profondeur
        en plus du bouton "Valider" du canvas editor.
        """
        from app.services.automation.dag_validator import validate_all

        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")

        # Real-review #4 cycle 23 : accepter un body `{"target": true|false}`
        # explicite pour éviter les races multi-tab. Si target est fourni
        # ET correspond à l'état actuel → 409 Conflict (l'auto est déjà
        # dans cet état). Sinon (body vide / target absent), on flippe
        # comme avant pour rétro-compat avec les clients legacy.
        body = {}
        try:
            raw = self.get_json_body()
            if isinstance(raw, dict):
                body = raw
        except Exception:  # noqa: BLE001 — JSON body optionnel
            body = {}
        target_intent = body.get("target") if isinstance(body.get("target"), bool) else None

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 D'ABORD, rate-limit APRES (helper combo).
                # Avant : rate-limit 429 leakait l'existence des IDs valides
                # (oracle CWE-204). Ici l'attaquant voit toujours 404 sur
                # un ID non-owne, sans signal sur le quota.
                # Cycle 5 fix : limiter DEDIE _toggle_limiter (pas
                # _edges_write_limiter partage avec canvas drag-drop)
                # pour eviter qu'un user power-actif self-DoS son toggle.
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id_int,
                    self.current_user.id,
                    _toggle_limiter,
                    *RATE_LIMIT_TOGGLE,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )
                # Real-review #4 cycle 23 : si le client a précisé son intent,
                # on l'utilise (sécurité multi-tab). Sinon flip classique.
                if target_intent is not None:
                    if target_intent == automation.is_active:
                        # No-op explicite : l'auto est déjà dans l'état demandé
                        self.set_status(409)
                        self.write(
                            {
                                "success": False,
                                "error": (
                                    "L'automatisation est déjà "
                                    + ("activée" if target_intent else "désactivée")
                                    + ". Rafraîchissez la page si vous voyez l'état contraire."
                                ),
                                "is_active": automation.is_active,
                            }
                        )
                        return
                    would_activate = target_intent
                else:
                    would_activate = not automation.is_active

                # Enforce completude AVANT de flipper la valeur. Si invalide,
                # on retourne 400 avec la liste structuree, sans muter l'etat.
                if would_activate:
                    # BUG-D bis cycle 23 : avant, le payload nodes ne
                    # contenait que {id, step_type} → validate_all voyait
                    # cfg={} pour tous les steps → faux positifs
                    # STEP_CONFIG_INCOMPLETE / EMAIL_NO_RECIPIENT bloquant
                    # toute activation. Cohérent avec le fix BUG-D dans
                    # AutomationValidateAPIHandler.
                    # Real-review #6 : `is_enabled` aussi — sinon les steps
                    # désactivés (ignorés au runtime) bloquent l'activation
                    # pour leurs configs incomplètes.
                    nodes = [
                        {
                            "id": s.id,
                            "step_type": (
                                s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                            ),
                            "name": s.name,
                            "config": s.config or {},
                            "is_enabled": s.is_enabled,
                        }
                        for s in automation.steps
                    ]
                    edges_list = [
                        {
                            "id": e.id,
                            "from_step_id": e.from_step_id,
                            "to_step_id": e.to_step_id,
                            "data_type": e.data_type,
                        }
                        for e in automation.edges
                    ]
                    errors = validate_all(nodes, edges_list, for_activation=True)
                    if errors:
                        self.set_status(400)
                        self.write(
                            {
                                "success": False,
                                "error": "Activation refusee : le workflow est incomplet.",
                                "errors": [
                                    {
                                        "code": err.code,
                                        "message": err.message,
                                        "context": err.context or {},
                                    }
                                    for err in errors
                                ],
                            }
                        )
                        return

                    # #21 fix 2026-06-11 — refs mortes (fail-fast à l'activation).
                    # validate_all (structurel) ne peut PAS vérifier l'existence des
                    # fichiers /datastore référencés (aucun accès FS). Un step
                    # load_workbook (config 'path') ou load_saved_query (config
                    # 'sql_path') pointant un fichier SUPPRIMÉ passait l'activation
                    # puis ÉCHOUAIT au run (souvent planifié → découvert tard). On
                    # vérifie ici (accès session + user_id) que les refs des steps
                    # ENABLED existent (les disabled sont ignorés au runtime, comme
                    # validate_all). Limite connue : un fichier supprimé APRÈS
                    # activation → le run échouera proprement (ValueError claire) ;
                    # ce check ne couvre que l'état au moment du toggle.
                    from app.handlers.datastore import _safe_path, _user_dir

                    _ref_fields = {"load_workbook": "path", "load_saved_query": "sql_path"}
                    _user_dir_path = _user_dir(automation.user_id)
                    _dead_refs = []
                    for _s in automation.steps:
                        if not getattr(_s, "is_enabled", True):
                            continue
                        _stype = (
                            _s.step_type.value if hasattr(_s.step_type, "value") else _s.step_type
                        )
                        _field = _ref_fields.get(_stype)
                        if not _field:
                            continue
                        _rel = ((_s.config or {}).get(_field) or "").strip()
                        if not _rel:
                            # Config incomplète : déjà du ressort de validate_all.
                            continue
                        _target = _safe_path(_user_dir_path, _rel)
                        if _target is None or not _target.exists() or not _target.is_file():
                            _dead_refs.append({"step": _s.name, "path": _rel})
                    if _dead_refs:
                        self.set_status(400)
                        self.write(
                            {
                                "success": False,
                                "error": (
                                    "Activation refusee : une ou plusieurs etapes "
                                    "referencent un fichier /datastore introuvable "
                                    "(supprime ou deplace). Corrigez-les avant d'activer."
                                ),
                                "dead_refs": _dead_refs,
                            }
                        )
                        return

                automation.is_active = would_activate
                new_is_active = automation.is_active
                auto_id = automation.id
                auto_name = automation.name

                # Cluster-U 2026-05-26 — Reset compteurs auto-pause sur
                # toggle ON manuel. Sans ça, une auto auto-pausée à 5
                # échecs reste à 5 → réactiver = 1 échec déclenche un
                # nouveau auto-pause immédiat (UX : "j'ai fix le bug,
                # pourquoi ça se re-pause direct ?"). Le toggle ON manuel
                # est un signal explicite "le user a vérifié, c'est OK".
                # Coercion defensive : Mock dans tests legacy ou valeur
                # corrompue (str) ne crash pas, fallback safe.
                if new_is_active:
                    _cfc = getattr(automation, "consecutive_failure_count", 0)
                    try:
                        _cfc_int = int(_cfc) if _cfc is not None else 0
                    except (TypeError, ValueError):
                        _cfc_int = 0
                    if _cfc_int > 0:
                        automation.consecutive_failure_count = 0
                    if getattr(automation, "paused_reason", None) is not None:
                        automation.paused_reason = None
                    # paused_at gardé pour traçabilité historique
                    # (admin peut voir "auto-pausée le X, réactivée le Y").
                # Capture scalaires AVANT commit pour eviter expire_on_commit +
                # lazy-load dans schedule_automation (loader.py:182-186). Pattern
                # SimpleNamespace identique a AutomationScheduleAPIHandler.put
                # (l.1316-1322) pour la coherence + safety post-commit.
                detached = SimpleNamespace(
                    id=auto_id,
                    name=auto_name,
                    is_active=new_is_active,
                    schedule_type=automation.schedule_type,
                    schedule_config=automation.schedule_config,
                )
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_TOGGLE,
                    entity_id=auto_id,
                    details={
                        "name": auto_name,
                        "new_is_active": new_is_active,
                        "target_intent_was_provided": target_intent is not None,
                    },
                )
                await session.commit()

                # Cluster-S 2026-05-26 — Toggle vers inactif = cancel les
                # waits pending (reminders inutiles, destinataires reçoivent
                # 410 sur leurs liens). notify_owner=True car le toggle off
                # peut affecter le user qui ne pensait pas avoir des waits.
                if not new_is_active:
                    try:
                        from app.services.automation.wait_resume import (
                            cancel_pending_waits_for_automation,
                        )

                        await cancel_pending_waits_for_automation(
                            auto_id,
                            reason="Automatisation desactivee",
                            notify_owner=True,
                        )
                    except Exception:  # noqa: BLE001 — best-effort
                        logger.warning(
                            "Cluster-S : cancel_pending_waits after toggle OFF echec",
                            exc_info=True,
                            extra={"automation_id": auto_id},
                        )

                # schedule_automation / unschedule_automation swallow leurs exceptions
                # et retournent False (loader.py:189-191, :240). Si APScheduler echoue
                # apres le commit BDD sur l'activation, l'auto reste en is_active=True
                # mais le job n'existe pas → l'auto ne se declenchera jamais.
                # Cote desactivation : unschedule_automation retourne False de facon
                # legitime (job deja absent : auto jamais activee, MemoryJobStore
                # restart, etc.) — on ne traite que le cas raise comme un vrai
                # echec. Le champ ``scheduled`` + log serveur ameliorent
                # l'observabilite (axe 21 CLAUDE.md). Frontend wire-up du champ
                # ``warning`` non inclus (out-of-scope run-3 ; tracker post-loop).
                scheduled_ok = True
                warning_msg: Optional[str] = None
                try:
                    if new_is_active:
                        scheduled_ok = bool(await schedule_automation(detached))
                    else:
                        scheduled_ok = bool(await unschedule_automation(auto_id))
                except Exception as e:  # noqa: BLE001 — defense-in-depth
                    logger.error(
                        "schedule/unschedule a leve apres toggle: %s",
                        e,
                        exc_info=True,
                        extra={"automation_id": auto_id, "new_is_active": new_is_active},
                    )
                    scheduled_ok = False
                    if new_is_active:
                        warning_msg = (
                            "Automatisation activee en BDD mais le job n'a pas pu "
                            "etre inscrit dans le scheduler (probablement temporaire). "
                            "Desactivez puis reactivez pour reessayer."
                        )
                    else:
                        warning_msg = (
                            "Automatisation desactivee en BDD mais le scheduler "
                            "a leve une exception. Etat probablement coherent "
                            "(rien a faire), verifier les logs si doute."
                        )
                else:
                    if new_is_active and not scheduled_ok:
                        warning_msg = (
                            "Automatisation activee en BDD mais le job n'a pas pu "
                            "etre inscrit dans le scheduler (probablement temporaire). "
                            "Desactivez puis reactivez pour reessayer."
                        )
                    # NOTE: pas de warning sur unschedule=False — c'est le cas
                    # NORMAL (job deja absent : auto jamais activee, scheduler
                    # restart MemoryJobStore, double-clic deactivate).

            logger.info(
                "Automatisation %s: %s scheduled=%s",
                "activee" if new_is_active else "desactivee",
                auto_name,
                scheduled_ok,
                extra={"automation_id": auto_id},
            )
            response: Dict[str, Any] = {
                "success": True,
                "is_active": new_is_active,
                "scheduled": scheduled_ok,
            }
            if warning_msg:
                response["warning"] = warning_msg
            self.write(response)

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError as e:
            logger.error("Erreur toggle automatisation: %s", e, exc_info=True)
            raise tornado.web.HTTPError(
                500,
                "Une erreur est survenue lors de la modification de l'automatisation.",
            )


# ── Helpers Schedule API ──────────────────────────────────────
#
# Schedule API : trois endpoints (GET, PUT, preview) qui partagent la
# meme normalisation/validation. Centralise ici pour eviter la duplication
# et garantir un comportement coherent entre lecture et ecriture.


_VALID_DAYS_OF_WEEK: frozenset[str] = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})


def _coerce_int_in_range(value: Any, field: str, lo: int, hi: int) -> int:
    """Coerce ``value`` en int et verifie l'inclusion dans ``[lo, hi]``.

    Retourne l'int normalise. Leve ``ValueError`` avec un message FR clair
    pour l'utilisateur (le message remonte tel quel dans la reponse 400).
    """
    try:
        n = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Champ '{field}' doit etre un entier.") from e
    if not (lo <= n <= hi):
        raise ValueError(f"Champ '{field}' hors limites ({lo}-{hi}).")
    return n


def _parse_iso_datetime(value: Any) -> datetime:
    """Parse une chaine ISO 8601 (ex: input HTML ``datetime-local``).

    Le navigateur envoie ``YYYY-MM-DDTHH:MM`` sans timezone — on l'accepte
    tel quel (datetime naive) ; APScheduler interprete via la TZ du
    scheduler (TZ serveur dynamique) au moment du fire. Une string aware est
    egalement acceptee si le client la fournit.
    """
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ValueError("Date/heure invalide (format ISO 8601 attendu).")
    s = value.strip()
    if not s:
        raise ValueError("Date/heure requise.")
    # TZ-2 (#48) — le frontend envoie désormais l'heure en UTC via
    # ``Date.toISOString()`` (suffixe 'Z'). ``datetime.fromisoformat`` n'accepte
    # 'Z' qu'à partir de Python 3.11 → on normalise en '+00:00' pour rester
    # compatible 3.10. Une string UTC aware ainsi parsée ne sera PAS re-localisée
    # en TZ serveur par l'appelant (tzinfo non-None) → l'instant absolu voulu par
    # l'utilisateur est préservé, indépendamment du fuseau serveur.
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"Date/heure invalide : {e}") from e


def _validate_schedule_payload(
    schedule_type: Any,
    schedule_config: Any,
) -> Tuple[str, dict]:
    """Valide un payload de planification et retourne ``(type, config)``
    normalises et persistables tels quels dans ``Automation.schedule_*``.

    Source de verite unique pour la validation cote API : reutilise par
    ``AutomationScheduleAPIHandler`` (PUT) et
    ``AutomationSchedulePreviewAPIHandler``. Tout champ inconnu dans le
    config est volontairement ignore — on ne stocke que ce qui correspond
    au mode (anti mass-assignment).

    Raises:
        ValueError: avec message FR exploitable par l'UI (remonte en 400).
    """
    if not isinstance(schedule_type, str) or schedule_type not in _VALID_SCHEDULE_TYPES:
        valid = " / ".join(sorted(_VALID_SCHEDULE_TYPES))
        raise ValueError(f"Type de planification invalide. Valeurs acceptees : {valid}.")

    if schedule_config is None:
        schedule_config = {}
    if not isinstance(schedule_config, dict):
        raise ValueError("Configuration de planification invalide (objet attendu).")

    if schedule_type == "cron":
        cron_expr = schedule_config.get("cron", "")
        if not isinstance(cron_expr, str) or not cron_expr.strip():
            raise ValueError("Expression cron requise pour le mode 'Avance'.")
        cron_expr = cron_expr.strip()
        try:
            validate_cron_expression(cron_expr)
        except ValueError as e:
            raise ValueError(f"Expression cron invalide : {e}") from e
        return schedule_type, {"cron": cron_expr}

    if schedule_type == "once":
        run_date_dt = _parse_iso_datetime(schedule_config.get("run_date"))
        # TZ-2 (#48, revue adversariale) — DEFENSE-IN-DEPTH : le frontend envoie
        # désormais TOUJOURS l'heure en UTC (Date.toISOString → 'Z'). Un client
        # buggé/malveillant qui fournirait un offset NON-UTC (ex. '+05:00')
        # programmerait le run à un instant FAUX SILENCIEUX (APScheduler honore
        # l'offset). On fail-closed : une valeur AWARE doit être en UTC. Le naïf
        # legacy reste localisé en TZ serveur ci-dessous (rétro-compat).
        if (
            run_date_dt.tzinfo is not None
            and run_date_dt.utcoffset() is not None
            and run_date_dt.utcoffset().total_seconds() != 0  # type: ignore[union-attr]
        ):
            raise ValueError(
                "L'heure doit être en UTC (le navigateur la convertit "
                "automatiquement). Offset non-UTC refusé."
            )
        # Si l'utilisateur n'a pas specifie de TZ (datetime naif), on assume
        # la TZ machine (config.timezone). Sans ca, le datetime serait
        # interprete par APScheduler comme UTC ou comme une autre TZ
        # arbitraire selon le path d'execution → confusion silencieuse
        # entre ce que l'utilisateur a vu dans la modal et ce qui est
        # vraiment programme. Cf. incident David 2026-05-08 : run_date
        # "14:43:00" sans tz interprete en heure locale serveur, mais
        # depuis une autre TZ → 6h de decalage et drop misfire silencieux.
        if run_date_dt.tzinfo is None:
            from app.services.automation.scheduler import _resolve_scheduler_tz

            run_date_dt = run_date_dt.replace(tzinfo=_resolve_scheduler_tz())
        # Validation past : rejeter immediatement les run_date dans le passe
        # ou dans la grace_period (60s). Sans ce check, APScheduler accepte
        # le add_job puis le drop silencieusement via misfire — l'utilisateur
        # voit "scheduled=True" mais aucune execution n'aura lieu (fail
        # silent, cf. incident David 2026-05-08).
        from datetime import timedelta as _td

        now_utc = clock.now()
        grace = _td(seconds=60)
        if run_date_dt <= now_utc + grace:
            raise ValueError(
                f"La date d'execution doit etre au moins 1 minute dans le futur. "
                f"Recue : {run_date_dt.isoformat()} ; maintenant : {now_utc.isoformat()}."
            )
        # Persist en ISO pour pouvoir relire par fromisoformat. APScheduler
        # accepte aussi datetime direct, mais on prefere une serialisation
        # stable JSON (le schedule_config est stocke en JSON cote SQLite).
        return schedule_type, {"run_date": run_date_dt.isoformat()}

    if schedule_type == "daily":
        h = _coerce_int_in_range(schedule_config.get("hour", 9), "hour", 0, 23)
        m = _coerce_int_in_range(schedule_config.get("minute", 0), "minute", 0, 59)
        return schedule_type, {"hour": h, "minute": m}

    if schedule_type == "weekly":
        dow_raw = schedule_config.get("day_of_week", "mon")
        if not isinstance(dow_raw, str) or not dow_raw.strip():
            raise ValueError("Jour de la semaine requis pour 'Hebdomadaire'.")
        days = [d.strip().lower() for d in dow_raw.split(",") if d.strip()]
        if not days or any(d not in _VALID_DAYS_OF_WEEK for d in days):
            raise ValueError(
                "Jour(s) de la semaine invalide(s). "
                "Valeurs acceptees : mon, tue, wed, thu, fri, sat, sun."
            )
        h = _coerce_int_in_range(schedule_config.get("hour", 9), "hour", 0, 23)
        m = _coerce_int_in_range(schedule_config.get("minute", 0), "minute", 0, 59)
        return schedule_type, {"day_of_week": ",".join(days), "hour": h, "minute": m}

    if schedule_type == "monthly":
        day = _coerce_int_in_range(schedule_config.get("day", 1), "day", 1, 31)
        h = _coerce_int_in_range(schedule_config.get("hour", 9), "hour", 0, 23)
        m = _coerce_int_in_range(schedule_config.get("minute", 0), "minute", 0, 59)
        return schedule_type, {"day": day, "hour": h, "minute": m}

    # Defensive — _VALID_SCHEDULE_TYPES garde-fou en amont.
    raise ValueError(f"Type de planification non supporte : {schedule_type}")


class AutomationScheduleAPIHandler(AuthenticatedHandler):
    """Lecture et mise a jour de la planification d'UNE automation.

    Endpoints :
    - ``GET  /api/automations/:id/schedule`` : retourne ``{schedule_type,
      schedule_config, is_active, next_run_time, next_runs}``.
    - ``PUT  /api/automations/:id/schedule`` : valide ``{schedule_type,
      schedule_config}``, persiste, et **re-inscrit le job** APScheduler
      via ``schedule_automation`` si ``is_active=True`` (sinon juste
      persistence — le job sera cree au prochain toggle ON).

    Securite :
    - Ownership 404 (pas 403) — symetrie anti-enumeration CWE-204.
    - Rate-limit dedie ``_schedule_limiter`` pour ne pas starver les autres
      endpoints d'edition canvas (metadata, edges-write).
    - Validation centralisee dans ``_validate_schedule_payload`` (anti
      mass-assignment : seules les cles attendues par mode sont conservees).
    - Validation cron via ``validate_cron_expression`` (reutilise du
      pipeline legacy ``AutomationCreateHandler``).
    """

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        from app.services.automation.scheduler import (
            build_trigger,
            compute_next_runs,
            get_next_run_for_automation,
        )

        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                # S-04 fix : ownership 404 D'ABORD, rate-limit APRES (helper combo).
                # Avant le fix, le GET n'avait pas de rate-limit du tout, ce qui
                # cassait le contrat de defense-in-depth annonce dans la
                # docstring du module (lignes 18-20).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id_int,
                    self.current_user.id,
                    _schedule_limiter,
                    *RATE_LIMIT_SCHEDULE,
                )
                schedule_type = automation.schedule_type
                schedule_config = automation.schedule_config or {}
                is_active = automation.is_active
                # A7-M6 — expose la version pour que la modal Planif renvoie
                # If-Match au PUT (sinon le PUT tombe en rétro-compat sans
                # protection → overwrite silencieux multi-onglets). Capturé DANS
                # la session (automation est détaché après le `async with`).
                schedule_version = int(automation.version or 1)

            # Source de verite "prochain run reel" : APScheduler quand
            # l'auto est active et inscrite. Sinon : dry-run sur le payload
            # courant (le job n'est pas encore inscrit, le scheduler
            # n'aurait rien a dire).
            next_run_time: Optional[str] = None
            if is_active:
                nrt = get_next_run_for_automation(auto_id_int)
                if nrt is not None:
                    next_run_time = nrt.isoformat()

            next_runs: list[str] = []
            try:
                trigger = build_trigger(schedule_type, schedule_config)
                runs = compute_next_runs(trigger, n=5)
                next_runs = [r.isoformat() for r in runs]
                if next_run_time is None and runs:
                    next_run_time = runs[0].isoformat()
            except (ValueError, TypeError, AttributeError):
                # Config corrompue (schedule_config tombe en panne, ex:
                # cron malforme stocke en BDD). On retourne quand meme les
                # autres champs pour que la modal puisse au moins s'afficher
                # et permettre a l'utilisateur de corriger.
                logger.warning(
                    "Schedule config invalide pour automation %d (type=%s)",
                    auto_id_int,
                    schedule_type,
                )

            # A7-M6 — ETag = version (optimistic concurrency), aligné sur le
            # pattern canvas (steps/edges). La modal Planif lit le champ
            # `version` du body et le renvoie en If-Match au PUT.
            # ⚠️ ``no-store`` OBLIGATOIRE : c'est de la donnée LIVE user-spécifique
            # ET la base de l'optimistic-lock. Sans ça, un cache navigateur
            # heuristique (ETag présent, pas de Cache-Control) pourrait servir une
            # version PÉRIMÉE → If-Match stale → boucle 409.
            self.set_header("Cache-Control", "no-store, max-age=0")
            _set_etag_header(self, schedule_version)
            self.write(
                {
                    "schedule_type": schedule_type,
                    "schedule_config": schedule_config,
                    "is_active": is_active,
                    "next_run_time": next_run_time,
                    "next_runs": next_runs,
                    "version": schedule_version,
                }
            )
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError as e:
            logger.error("Erreur GET schedule: %s", e, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Une erreur est survenue."})

    @require_role("admin", "user")
    async def put(self, automation_id: str) -> None:
        from app.services.automation.scheduler import (
            build_trigger,
            compute_next_runs,
        )

        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            data = self.get_json_body()
        except Exception:  # noqa: BLE001 — body parsing fail = 400
            self.set_status(400)
            self.write({"success": False, "error": "Body JSON invalide."})
            return
        if not isinstance(data, dict):
            self.set_status(400)
            self.write({"success": False, "error": "Body JSON invalide."})
            return

        try:
            normalized_type, normalized_config = _validate_schedule_payload(
                data.get("schedule_type"),
                data.get("schedule_config", {}),
            )
        except ValueError as e:
            self.set_status(400)
            self.write({"success": False, "error": str(e)})
            return

        try:
            async with self.db_session() as session:
                # Ownership 404 D'ABORD, rate-limit APRES (cf.
                # ``_get_owned_then_rate_limit`` docstring : eviter l'oracle
                # CWE-204 via le 429 sur les IDs valides non-ownes).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id_int,
                    self.current_user.id,
                    _schedule_limiter,
                    *RATE_LIMIT_SCHEDULE,
                )
                # Cluster-N 2026-05-26 — Step 1/2 : fail-fast If-Match
                # AVANT toute mutation (pas de bump tant que validation OK).
                if not _check_if_match_or_409(self, automation):
                    return
                # Cluster-B 2026-05-26 — capture ancien schedule AVANT mutation
                # pour compliance (compare before/after dans details).
                old_schedule_type = automation.schedule_type
                old_schedule_config = automation.schedule_config
                automation.schedule_type = normalized_type
                automation.schedule_config = normalized_config
                # Capture pour rescheduling apres commit (expire_on_commit
                # pourrait fail des lazy-loads sinon).
                is_active = automation.is_active
                auto_name = automation.name
                detached = SimpleNamespace(
                    id=auto_id_int,
                    name=auto_name,
                    is_active=is_active,
                    schedule_type=normalized_type,
                    schedule_config=normalized_config,
                )
                # Post-adversarial 2026-05-26 — compliance demande old + new
                # config (cron string, daily heure, etc.) pour pouvoir
                # reconstruire "qui a changé quoi". Le cap JSON dans
                # ``audit_event`` (4KB) protège contre les configs énormes.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_SCHEDULE_CHANGE,
                    entity_id=auto_id_int,
                    details={
                        "name": auto_name,
                        "old_type": old_schedule_type,
                        "new_type": normalized_type,
                        "old_config": old_schedule_config,
                        "new_config": normalized_config,
                        "was_active": is_active,
                    },
                )
                # Cluster-N — Step 2/2 : bump APRÈS validations métier,
                # juste avant commit. Pas de risque d'ETag fantôme.
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return
                await session.commit()

            # Re-inscrire le job APScheduler avec le nouveau trigger UNIQUEMENT
            # si l'auto est active. Si elle est en pause, le job n'existe pas
            # dans le scheduler et sera cree au prochain toggle ON via
            # ``schedule_automation`` (loader.py:145).
            #
            # S-02 fix : ``schedule_automation`` swallow ses exceptions et
            # retourne ``False`` (loader.py:189). Si l'add_job APScheduler
            # echoue (jobstore SQLite locked, scheduler shutdown, etc.), la
            # BDD a deja ete commitee mais aucun job n'est inscrit → l'auto
            # ne se declenchera pas. On lit le retour et on signale dans la
            # reponse via ``scheduled`` + ``warning`` pour que le JS affiche
            # un toast warning au lieu d'un faux "succes".
            scheduled_ok = True
            warning_msg: Optional[str] = None
            if is_active:
                try:
                    scheduled_ok = bool(await schedule_automation(detached))
                except Exception as e:  # noqa: BLE001 — defense-in-depth
                    logger.error(
                        "schedule_automation a leve apres PUT schedule: %s",
                        e,
                        exc_info=True,
                        extra={"automation_id": auto_id_int},
                    )
                    scheduled_ok = False
                if not scheduled_ok:
                    warning_msg = (
                        "Configuration enregistree mais le job n'a pas pu etre "
                        "inscrit dans le scheduler (probablement temporaire). "
                        "Desactivez puis reactivez l'automatisation pour reessayer."
                    )

            # Retour : prochaines executions calculees a partir du payload
            # tout juste persiste (source = config, pas BDD relue, pour
            # tests deterministes).
            next_runs: list[str] = []
            try:
                trigger = build_trigger(normalized_type, normalized_config)
                runs = compute_next_runs(trigger, n=5)
                next_runs = [r.isoformat() for r in runs]
            except (ValueError, TypeError, AttributeError):
                logger.warning(
                    "compute_next_runs failed apres PUT schedule (type=%s)",
                    normalized_type,
                )

            logger.info(
                "Schedule mis a jour: type=%s scheduled=%s",
                normalized_type,
                scheduled_ok,
                extra={"automation_id": auto_id_int},
            )

            response = {
                "success": True,
                "schedule_type": normalized_type,
                "schedule_config": normalized_config,
                "is_active": is_active,
                "scheduled": scheduled_ok,
                "next_runs": next_runs,
                # Cluster-N — version retournée pour MAJ état client.
                "version": int(new_version),
            }
            if warning_msg:
                response["warning"] = warning_msg
            self.write(response)
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError as e:
            logger.error("Erreur PUT schedule: %s", e, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Une erreur est survenue."})


class AutomationSchedulePreviewAPIHandler(AuthenticatedHandler):
    """Calcul dry-run des prochaines executions pour un payload donne.

    POST ``/api/automations/schedule/preview`` avec ``{schedule_type,
    schedule_config}``. Pas d'effet de bord (pas de touche BDD ni
    APScheduler) : valide le payload, construit un Trigger, itere
    ``get_next_fire_time`` jusqu'a 5 fois.

    Sert au front pour afficher les "5 prochaines executions" en debounce
    pendant que l'utilisateur edite. Sans cet endpoint, il faudrait soit
    sauvegarder pour voir le resultat (UX douloureuse), soit reimplementer
    la logique APScheduler en JS (duplication source de bugs).

    Securite :
    - Auth requise (``@require_role("admin", "user")``).
    - Rate-limit ``_schedule_limiter`` (60/min) — un debounce 300 ms cote
      front genere ~3 req/sec en saisie active, le quota est large.
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        from app.services.automation.scheduler import (
            build_trigger,
            compute_next_runs,
        )

        _check_rate_limit(
            _schedule_limiter,
            self.current_user.id,
            *RATE_LIMIT_SCHEDULE,
        )

        try:
            data = self.get_json_body()
        except Exception:  # noqa: BLE001
            self.set_status(400)
            self.write({"success": False, "error": "Body JSON invalide."})
            return
        if not isinstance(data, dict):
            self.set_status(400)
            self.write({"success": False, "error": "Body JSON invalide."})
            return

        try:
            normalized_type, normalized_config = _validate_schedule_payload(
                data.get("schedule_type"),
                data.get("schedule_config", {}),
            )
        except ValueError as e:
            self.set_status(400)
            self.write({"success": False, "error": str(e)})
            return

        try:
            trigger = build_trigger(normalized_type, normalized_config)
            runs = compute_next_runs(trigger, n=5)
        except (ValueError, TypeError, AttributeError) as e:
            self.set_status(400)
            self.write({"success": False, "error": f"Trigger invalide : {e}"})
            return

        self.write(
            {
                "success": True,
                "schedule_type": normalized_type,
                "schedule_config": normalized_config,
                "next_runs": [r.isoformat() for r in runs],
            }
        )


class AutomationDeleteHandler(AuthenticatedHandler):
    """CRUD individuel d'une automatisation : DELETE + PUT (edit metadonnees).

    Le nom historique est conserve (le handler gerait seulement DELETE avant
    Phase 3b-2) — la responsabilite reste "operations sur une automation par
    id" et rester generique evite de renommer la route.
    """

    # Champs metadonnees editables via PUT. Tout autre champ est rejete
    # silencieusement pour eviter un mass-assignment (CWE-915).
    _EDITABLE_FIELDS: frozenset[str] = frozenset(
        {
            "name",
            "description",
            "fail_policy",
            "notify_on_failure",
            "notify_on_success",
            "max_llm_cost_eur",
            "max_total_rows",
            "max_duration_seconds",
        }
    )

    @require_role("admin", "user")
    async def delete(self, automation_id: str) -> None:
        """Supprime une automatisation. 404 sur invalide OU non-owner."""
        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session, auto_id_int, self.current_user.id
                )

                was_active = automation.is_active
                name = automation.name
                auto_id = automation.id
                # #32 fix 2026-06-11 — déprogrammer INCONDITIONNELLEMENT (avant :
                # seulement `if was_active`). Un job APScheduler orphelin peut
                # survivre sur une auto ``is_active=False`` (toggle-off dont
                # l'unschedule a échoué en silence, job stale persisté par le
                # SQLAlchemyJobStore, race) → sans ce retrait au delete, le job
                # re-fire après ``misfire_grace_time`` sur une auto SUPPRIMÉE.
                # ``unschedule_automation`` est idempotent (job absent → False,
                # exception catchée → False, jamais de raise) donc sûr ici.
                await unschedule_automation(auto_id)

                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_DELETE,
                    entity_id=auto_id,
                    details={"name": name, "was_active": was_active},
                )

                # Cluster-S 2026-05-26 — Cancel les waits AVANT delete pour
                # notifier les destinataires externes (sinon cascade FK des
                # WaitToken les supprime sans signal). Le helper ouvre sa
                # propre session et commit en interne — l'auto reste pending
                # delete dans CETTE session. notify_owner=False car le user
                # a triggered le delete lui-même.
                try:
                    from app.services.automation.wait_resume import (
                        cancel_pending_waits_for_automation,
                    )

                    await cancel_pending_waits_for_automation(
                        auto_id,
                        reason="Automatisation supprimee",
                        notify_owner=False,
                    )
                except Exception:  # noqa: BLE001 — best-effort
                    logger.warning(
                        "Cluster-S : cancel_pending_waits before DELETE auto echec",
                        exc_info=True,
                        extra={"automation_id": auto_id},
                    )

                await session.delete(automation)
                await session.commit()

            # Cluster-F #7 — purge le lock per-automation en mémoire : l'auto
            # est définitivement supprimée, son lock ne resservira jamais.
            # Évite la croissance non bornée de _automation_run_locks (axe 21).
            from app.services.automation.executor import _drop_automation_run_lock

            _drop_automation_run_lock(auto_id)

            logger.info(
                "Automatisation supprimee: %s",
                name,
                extra={"automation_id": auto_id},
            )
            self.write({"success": True, "message": "Automatisation supprimee"})

        except SQLAlchemyError as e:
            logger.error("Erreur suppression automatisation: %s", e, exc_info=True)
            raise tornado.web.HTTPError(
                500,
                "Une erreur est survenue lors de la suppression de l'automatisation.",
            )

    @require_role("admin", "user")
    async def put(self, automation_id: str) -> None:
        """Met a jour les metadonnees de l'automation (name, description, etc.).

        Ne touche pas aux steps/edges/schedule — seulement les champs
        listes dans ``_EDITABLE_FIELDS``. Les booleens sont passes par
        ``strict_bool`` pour eviter un mass-assignment "false" → True.
        Rate-limite via ``_metadata_limiter`` dedie (evite la starvation
        du quota edges-write en cas d'edition intensive combinant autosave
        metadata + autosave structure canvas).
        """
        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")
        try:
            body = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            raise tornado.web.HTTPError(400, "JSON invalide")
        if not isinstance(body, dict):
            raise tornado.web.HTTPError(400, "Corps doit etre un objet JSON")

        # Filtrage : ignorer silencieusement les cles inconnues plutot que
        # 400, pour rester tolerant aux futurs champs. Mais conserver le log
        # pour tracer les tentatives de mass-assignment.
        filtered: Dict[str, Any] = {}
        for key, value in body.items():
            if key in self._EDITABLE_FIELDS:
                filtered[key] = value

        if not filtered:
            raise tornado.web.HTTPError(
                400,
                "Aucun champ editable fourni. "
                "Champs acceptes : " + ", ".join(sorted(self._EDITABLE_FIELDS)),
            )

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id_int,
                    self.current_user.id,
                    _metadata_limiter,
                    *RATE_LIMIT_METADATA,
                )
                # Cluster-N 2026-05-26 — Step 1/2 : fail-fast If-Match.
                if not _check_if_match_or_409(self, automation):
                    return

                if "name" in filtered:
                    name = filtered["name"]
                    if not isinstance(name, str):
                        raise tornado.web.HTTPError(400, "name doit etre une chaine")
                    name = name.strip()
                    if not name:
                        raise tornado.web.HTTPError(400, "name ne peut pas etre vide")
                    if len(name) > MAX_NAME_LENGTH:
                        raise tornado.web.HTTPError(
                            400, f"name depasse {MAX_NAME_LENGTH} caracteres"
                        )
                    assert_no_crlf(name, field="name")
                    automation.name = name

                if "description" in filtered:
                    desc = filtered["description"]
                    if desc is not None and not isinstance(desc, str):
                        raise tornado.web.HTTPError(400, "description doit etre une chaine ou null")
                    if desc is not None and len(desc) > MAX_DESCRIPTION_LENGTH:
                        raise tornado.web.HTTPError(
                            400, f"description depasse {MAX_DESCRIPTION_LENGTH}"
                        )
                    automation.description = desc or None

                if "fail_policy" in filtered:
                    fp = filtered["fail_policy"]
                    if fp not in ("abort", "continue"):
                        raise tornado.web.HTTPError(
                            400, "fail_policy doit etre 'abort' ou 'continue'"
                        )
                    automation.fail_policy = fp

                if "notify_on_failure" in filtered:
                    automation.notify_on_failure = _coerce_strict_bool_or_400(
                        filtered, "notify_on_failure", required=True
                    )
                if "notify_on_success" in filtered:
                    automation.notify_on_success = _coerce_strict_bool_or_400(
                        filtered, "notify_on_success", required=True
                    )

                for num_field in (
                    "max_llm_cost_eur",
                    "max_total_rows",
                    "max_duration_seconds",
                ):
                    if num_field in filtered:
                        raw = filtered[num_field]
                        if raw is None:
                            setattr(automation, num_field, None)
                        else:
                            try:
                                parsed = float(raw) if num_field == "max_llm_cost_eur" else int(raw)
                            except (TypeError, ValueError):
                                raise tornado.web.HTTPError(400, f"{num_field} doit etre un nombre")
                            if parsed < 0:
                                raise tornado.web.HTTPError(400, f"{num_field} doit etre positif")
                            setattr(automation, num_field, parsed)

                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_UPDATE,
                    entity_id=automation.id,
                    details={"fields_changed": sorted(filtered.keys())},
                )
                # Cluster-N — Step 2/2 : bump avant commit.
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return
                await session.commit()
                await session.refresh(automation)
                auto_dict = {
                    "id": automation.id,
                    "name": automation.name,
                    "description": automation.description,
                    "is_active": automation.is_active,
                    "fail_policy": automation.fail_policy,
                    "notify_on_failure": automation.notify_on_failure,
                    "notify_on_success": automation.notify_on_success,
                    "max_llm_cost_eur": automation.max_llm_cost_eur,
                    "max_total_rows": automation.max_total_rows,
                    "max_duration_seconds": automation.max_duration_seconds,
                    # Cluster-N — version client-facing.
                    "version": int(automation.version or 1),
                }
            self.write({"success": True, "automation": auto_dict})
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur update automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur mise a jour"})


class AutomationDuplicateHandler(AuthenticatedHandler):
    """Duplication d'une automatisation (y compris les etapes workflow)."""

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Duplique une automatisation.

        **Rate-limit** : duplicata de masse casse la cote (ecriture BDD +
        replication d'etapes). Quota par utilisateur applique.
        """
        auto_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                original = await _get_owned_then_rate_limit(
                    session,
                    auto_id_int,
                    self.current_user.id,
                    _duplicate_limiter,
                    *RATE_LIMIT_DUPLICATE,
                    options=[
                        selectinload(Automation.steps),
                        # Real-review #1 : eager-load edges pour les copier
                        # aussi. Sans ça, le duplicate produit un graphe sans
                        # arêtes (que des nodes orphelins) → activation
                        # impossible.
                        selectinload(Automation.edges),
                    ],
                )

                # Real-review #9 cycle 23 : deepcopy des configs/policies pour
                # éviter le partage par référence entre original et duplicate.
                # Sans ça, modifier la config sur la copie mutait l'original
                # tant que SQLAlchemy n'avait pas flushed.
                import copy as _copy

                step_configs = [
                    {
                        "id": s.id,  # gardé en local pour mapping edges
                        "name": s.name,
                        "step_type": s.step_type,
                        "step_order": s.step_order,
                        "config": (
                            _copy.deepcopy(s.config) if isinstance(s.config, dict) else None
                        ),
                        "is_enabled": s.is_enabled,
                        "max_retries": s.max_retries,
                        "retry_delay_seconds": s.retry_delay_seconds,
                        "input_policy": (
                            _copy.deepcopy(s.input_policy)
                            if isinstance(s.input_policy, dict)
                            else None
                        ),
                        "layout_x": s.layout_x,
                        "layout_y": s.layout_y,
                    }
                    for s in sorted(original.steps, key=lambda x: x.step_order)
                ]

                # Real-review #28 : ne PAS hériter recipients/notification_emails
                # /webhook_triggers — sécurité défense. Cohérent avec
                # AutomationTemplateInstantiateHandler.
                duplicate = Automation(
                    user_id=self.current_user.id,
                    name=f"{original.name} (Copie)",
                    description=original.description,
                    query_type=original.query_type,
                    query_text=original.query_text,
                    schedule_type=original.schedule_type,
                    schedule_config=original.schedule_config,
                    output_format=original.output_format,
                    recipients=[],
                    notify_on_failure=original.notify_on_failure,
                    notify_on_success=original.notify_on_success,
                    notification_emails=[],
                    is_active=False,
                )

                session.add(duplicate)
                await session.flush()

                # Mapping ancien step.id → nouveau step.id pour copier les edges
                old_to_new_step_id: Dict[int, int] = {}
                for sc in step_configs:
                    step = AutomationStep(
                        automation_id=duplicate.id,
                        name=sc["name"],
                        step_type=sc["step_type"],
                        step_order=sc["step_order"],
                        config=sc["config"],
                        is_enabled=sc["is_enabled"],
                        max_retries=sc["max_retries"],
                        retry_delay_seconds=sc["retry_delay_seconds"],
                        input_policy=sc["input_policy"],
                        layout_x=sc["layout_x"],
                        layout_y=sc["layout_y"],
                    )
                    session.add(step)
                    await session.flush()  # pour avoir step.id
                    old_to_new_step_id[sc["id"]] = step.id

                # Real-review #1 cycle 23 : copier les edges DAG. Sans ça,
                # un workflow valide dupliqué devient inactivable (orphan nodes).
                for edge in original.edges:
                    new_from = old_to_new_step_id.get(edge.from_step_id)
                    new_to = old_to_new_step_id.get(edge.to_step_id)
                    if new_from is None or new_to is None:
                        # Edge référençant un step non copié (incohérence
                        # original → on skip silencieusement plutôt que crasher)
                        continue
                    session.add(
                        AutomationEdge(
                            automation_id=duplicate.id,
                            from_step_id=new_from,
                            to_step_id=new_to,
                            data_type=edge.data_type,
                            metadata_json=(
                                _copy.deepcopy(edge.metadata_json)
                                if isinstance(edge.metadata_json, dict)
                                else None
                            ),
                        )
                    )

                dup_id = duplicate.id
                orig_id = original.id
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_DUPLICATE,
                    entity_id=dup_id,
                    details={
                        "source_id": orig_id,
                        "name": duplicate.name,
                        "step_count": len(step_configs),
                    },
                )
                await session.commit()

            logger.info(
                "Automatisation %d dupliquee -> %d (%d etapes) par %s",
                orig_id,
                dup_id,
                len(step_configs),
                self.current_user.email,
            )
            self.write({"success": True, "id": dup_id})

        except SQLAlchemyError as e:
            logger.error(
                "Erreur duplication automatisation %s: %s", automation_id, e, exc_info=True
            )
            self.set_status(500)
            self.write(
                {
                    "success": False,
                    "error": "Une erreur est survenue lors de la duplication de l'automatisation.",
                }
            )


class AutomationExportHandler(AuthenticatedHandler):
    """Export d'une automatisation au format JSON."""

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Exporte une automatisation + etapes + aretes DAG au format JSON (v2)."""
        aid = self._parse_int_or_400(automation_id, "automation_id")
        try:
            async with self.db_session() as session:
                # Post-adversarial cluster-B 2026-05-26 — l'export GET produit
                # maintenant un audit row + commit (compliance trail). Sans
                # rate-limit, un user pourrait spammer cet endpoint pour
                # gonfler audit_logs. Pattern ``_get_owned_then_rate_limit``
                # garantit ownership 404 AVANT 429 (anti-oracle CWE-204).
                automation = await _get_owned_then_rate_limit(
                    session,
                    aid,
                    self.current_user.id,
                    _export_limiter,
                    *RATE_LIMIT_EXPORT,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )

                # Instant UTC aware via clock ; on emet un ISO avec suffixe Z
                # (UTC sans offset) pour compat clients.
                exported_at = clock.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

                sorted_steps = sorted(automation.steps, key=lambda x: x.step_order)

                # Si aucune arete n'est definie (workflow pre-DAG), on genere
                # les aretes lineaires depuis step_order pour que l'import cote
                # Komptia >= Phase 1 obtienne un DAG fonctionnel sans etape
                # manuelle. Chaque arete emet "workbook" par defaut — type de
                # donnee par defaut entre transforms Phase 1 DAG.
                edges_payload: list[dict] = []
                if automation.edges:
                    # Mapper step_id -> step.name pour referencer par nom
                    # (l'id est local a la base, nom est portable).
                    id_to_name = {s.id: s.name for s in sorted_steps}
                    for e in automation.edges:
                        edges_payload.append(
                            {
                                "from_step_name": id_to_name.get(e.from_step_id),
                                "to_step_name": id_to_name.get(e.to_step_id),
                                "data_type": e.data_type,
                                "metadata": e.metadata_json or {},
                            }
                        )
                else:
                    # Generation lineaire step[i] -> step[i+1]
                    enabled = [s for s in sorted_steps if s.is_enabled]
                    for i in range(len(enabled) - 1):
                        edges_payload.append(
                            {
                                "from_step_name": enabled[i].name,
                                "to_step_name": enabled[i + 1].name,
                                "data_type": "workbook",
                                "metadata": {},
                            }
                        )

                export_data = {
                    "komptia_export": {
                        "version": 2,
                        "type": "automation",
                        "exported_at": exported_at,
                    },
                    "automation": {
                        "name": automation.name,
                        "description": automation.description,
                        "query_type": automation.query_type,
                        "query_text": automation.query_text,
                        "schedule_type": automation.schedule_type,
                        "schedule_config": automation.schedule_config,
                        "output_format": automation.output_format,
                        "recipients": automation.recipients,
                        "notify_on_failure": automation.notify_on_failure,
                        "notify_on_success": automation.notify_on_success,
                        "notification_emails": automation.notification_emails,
                    },
                    "steps": [
                        {
                            "name": s.name,
                            "step_type": s.step_type,
                            "step_order": s.step_order,
                            "config": s.config or {},
                            "is_enabled": s.is_enabled,
                            "max_retries": s.max_retries,
                            "retry_delay_seconds": s.retry_delay_seconds,
                            "layout_x": s.layout_x,
                            "layout_y": s.layout_y,
                            "input_policy": s.input_policy or {},
                        }
                        for s in sorted_steps
                    ],
                    "edges": edges_payload,
                }
                safe_name = _sanitize_filename(automation.name)
                from app.services.branding import get_company_name

                safe_company = _sanitize_filename(get_company_name())
                filename = f"{safe_company}_{safe_name}.json"

                # Cluster-B 2026-05-26 — audit GET export : pas de mutation
                # BDD mais compliance exige la trace de qui a exporté quoi
                # (les exports contiennent toute la config de l'auto, y compris
                # recipients/schedule — exfiltration possible).
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_EXPORT,
                    entity_id=automation.id,
                    details={
                        "name": automation.name,
                        "step_count": len(export_data.get("steps", [])),
                        "edge_count": len(export_data.get("edges", [])),
                    },
                )
                await session.commit()

            self.set_header("Content-Type", "application/json; charset=utf-8")
            self.set_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.write(json.dumps(export_data, ensure_ascii=False, indent=2))

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur export automatisation %s", automation_id, exc_info=True)
            raise tornado.web.HTTPError(500, "Erreur lors de l'export")


def validate_automation_payload(
    payload: dict,
) -> tuple[dict, list[dict], list[dict]]:
    """Valide le payload d'import (v1 ou v2). Leve ValueError sur faute.

    Phase 3d : extrait de ``AutomationImportHandler._validate_import``
    pour pouvoir etre reutilise par ``AutomationTemplateInstantiateHandler``
    sans le hack ``__new__``. Pas d'etat (fonction pure), aucun side-effect.

    Retourne ``(auto_fields, steps, edges)`` :
      - ``auto_fields`` s'injecte directement dans ``Automation(**auto_fields)``
      - ``steps`` est une liste de dicts prets pour ``AutomationStep``
      - ``edges`` est une liste de dicts {from_step_name, to_step_name,
        data_type, metadata} prets pour ``AutomationEdge`` (le caller
        resout les noms en step_id apres flush).

    v1 : pas de section ``edges``, generation automatique lineaire.
    v2 : section ``edges`` explicite avec from_step_name/to_step_name.
    """
    if not isinstance(payload, dict):
        raise ValueError("Format invalide. Objet JSON attendu.")

    meta = payload.get("komptia_export")
    if not isinstance(meta, dict) or meta.get("type") != "automation":
        raise ValueError("Format invalide. Fichier Komptia attendu.")

    version = meta.get("version", 1)
    if version not in (1, 2):
        raise ValueError(f"Version d'export non supportee: {version}. Versions reconnues: 1, 2.")

    auto_data = payload.get("automation")
    if not isinstance(auto_data, dict):
        raise ValueError("Donnees d'automatisation manquantes.")

    name = (auto_data.get("name") or "").strip()
    if not name:
        raise ValueError("Le nom est obligatoire.")
    name = name[:MAX_NAME_LENGTH]

    query_text = (auto_data.get("query_text") or "").strip()
    if not query_text:
        raise ValueError("Le texte de la requete est obligatoire.")

    # A7-F1 (étendu, suite review adversariale) — cohérence avec
    # AutomationCreateHandler._validate_create_payload : on LÈVE sur une valeur
    # hors-set au lieu de coercer EN SILENCE vers le défaut. Sans ça, un export
    # hand-édité (ou version-drifté) avec query_type/schedule_type/output_format
    # invalide était importé avec une valeur différente sans avertir l'user
    # (livrable/sémantique faux silencieux). Les call-sites import + template
    # traduisent ce ValueError en 400. Les 3 templates galerie ont des valeurs
    # valides (vérifié) → zéro régression d'instanciation.
    query_type = auto_data.get("query_type", "nl")
    if query_type not in _VALID_QUERY_TYPES:
        raise ValueError("Type de requete invalide.")

    schedule_type = auto_data.get("schedule_type", "daily")
    if schedule_type not in _VALID_SCHEDULE_TYPES:
        raise ValueError("Type de planification invalide.")

    # Validation cron stricte — un import avec cron invalide echoue ici
    # plutot qu'a la prochaine activation (fail-early).
    schedule_config = auto_data.get("schedule_config") or {}
    if not isinstance(schedule_config, dict):
        schedule_config = {}
    if schedule_type == "cron":
        cron_expr = schedule_config.get("cron", "")
        if not cron_expr:
            raise ValueError("Expression cron manquante dans schedule_config.")
        try:
            validate_cron_expression(cron_expr)
        except ValueError as e:
            raise ValueError(f"Expression cron invalide : {e}") from e

    output_format = auto_data.get("output_format", "csv")
    if output_format not in _VALID_OUTPUT_FORMATS:
        raise ValueError("Format de sortie invalide.")

    recipients = _extract_email_list(auto_data.get("recipients") or [])
    notification_emails = _extract_email_list(auto_data.get("notification_emails") or [])

    # S5 — strict_bool sur l'import JSON (axe sécu 7, mass-assignment).
    # Avant : bool() brut accepte "false" (string truthy) → notify_on_failure=True
    # silencieusement. Maintenant : on rejette les strings truandées MAIS on
    # tolère int 0/1 (anciennes versions de Komptia ou JS qui sérialise
    # `+true` en `1`). strict_bool() est intentionnellement strict (refuse int)
    # pour les POST handlers ; à l'import, on coerce int 0/1 en amont.
    def _import_bool(key: str, default: bool) -> bool:
        v = auto_data.get(key, default)
        if isinstance(v, bool):
            return v
        if isinstance(v, int) and v in (0, 1):
            return bool(v)
        # Tout autre type (string, None, etc.) → 400 via strict_bool.
        return _coerce_strict_bool_or_400(auto_data, key, default=default)

    notify_on_failure = _import_bool("notify_on_failure", True)
    notify_on_success = _import_bool("notify_on_success", False)

    raw_steps = payload.get("steps") or []
    if not isinstance(raw_steps, list):
        raw_steps = []

    # Types retires en Phase 1 DAG : on les detecte explicitement pour un
    # message d'erreur clair, plutot que "Type inconnu" generique qui
    # laisse l'utilisateur perplexe sur pourquoi son ancien export casse.
    legacy_removed_types = {
        "delay",
        "loop",
        "for_each",
        "parallel",
        "sub_workflow",
        "try_catch",
    }

    valid_step_types = {t.value for t in StepType}
    validated_steps: list[dict] = []
    for i, s in enumerate(raw_steps[:MAX_STEPS_PER_IMPORT]):
        if not isinstance(s, dict):
            continue
        stype = s.get("step_type", "")
        if stype in legacy_removed_types:
            raise ValueError(
                f"Etape {i + 1}: le type '{stype}' a ete retire en Phase 1 DAG "
                f"(docs/design_automations_dag.md §7 D18). "
                f"Recree l'etape avec un type supporte : "
                f"{sorted(valid_step_types)}"
            )
        if stype not in valid_step_types:
            raise ValueError(f"Type d'etape inconnu a l'etape {i + 1}: {stype}")

        sconfig = s.get("config") if isinstance(s.get("config"), dict) else {}
        schema_err = _validate_step_config(stype, sconfig)
        if schema_err:
            raise ValueError(f"Etape {i + 1}: {schema_err}")

        sname = (s.get("name") or f"Etape {i + 1}").strip()[:MAX_NAME_LENGTH]
        # Detection des noms dupliques : cles de reference des edges.
        # Deux steps avec le meme nom casseraient la resolution name->id.
        if any(vs["name"] == sname for vs in validated_steps):
            raise ValueError(
                f"Etape {i + 1}: le nom '{sname}' est en double (un autre step "
                f"porte deja ce nom). Les noms de steps doivent etre uniques "
                f"au sein d'un workflow (cles des aretes DAG)."
            )
        max_retries = _clamp_int(s.get("max_retries", 0), 0, STEP_MAX_RETRIES_CAP, 0)
        retry_delay = _clamp_int(
            s.get("retry_delay_seconds", STEP_RETRY_DELAY_DEFAULT_SEC),
            STEP_RETRY_DELAY_MIN_SEC,
            STEP_RETRY_DELAY_MAX_SEC,
            STEP_RETRY_DELAY_DEFAULT_SEC,
        )

        # Champs Phase 1 DAG (v2 uniquement, sinon None)
        layout_x = s.get("layout_x") if isinstance(s.get("layout_x"), int) else None
        layout_y = s.get("layout_y") if isinstance(s.get("layout_y"), int) else None
        input_policy = s.get("input_policy") if isinstance(s.get("input_policy"), dict) else None

        validated_steps.append(
            {
                "name": sname,
                "step_type": stype,
                "step_order": i + 1,
                "config": sconfig,
                "is_enabled": bool(s.get("is_enabled", True)),
                "max_retries": max_retries,
                "retry_delay_seconds": retry_delay,
                "layout_x": layout_x,
                "layout_y": layout_y,
                "input_policy": input_policy,
            }
        )

    # --- Aretes DAG ---
    validated_edges: list[dict] = []
    if version == 2:
        raw_edges = payload.get("edges") or []
        if not isinstance(raw_edges, list):
            raw_edges = []
        if len(raw_edges) > MAX_EDGES_PER_IMPORT:
            raise ValueError(
                f"Trop d'aretes: {len(raw_edges)}. Max autorise a l'import: "
                f"{MAX_EDGES_PER_IMPORT}."
            )
        valid_data_types = set(EDGE_DATA_TYPES)
        step_names = {vs["name"] for vs in validated_steps}
        for j, e in enumerate(raw_edges):
            if not isinstance(e, dict):
                continue
            frm_name = (e.get("from_step_name") or "").strip()
            to_name = (e.get("to_step_name") or "").strip()
            dtype = (e.get("data_type") or "").strip()
            if not frm_name or not to_name:
                raise ValueError(f"Arete {j + 1}: from_step_name et to_step_name requis.")
            if frm_name not in step_names or to_name not in step_names:
                raise ValueError(
                    f"Arete {j + 1}: nom d'etape inconnu " f"(from='{frm_name}', to='{to_name}')."
                )
            if frm_name == to_name:
                raise ValueError(f"Arete {j + 1}: self-loop interdit.")
            if dtype not in valid_data_types:
                raise ValueError(
                    f"Arete {j + 1}: data_type invalide '{dtype}'. "
                    f"Valeurs: {sorted(valid_data_types)}"
                )
            emeta = e.get("metadata") if isinstance(e.get("metadata"), dict) else None
            validated_edges.append(
                {
                    "from_step_name": frm_name,
                    "to_step_name": to_name,
                    "data_type": dtype,
                    "metadata": emeta,
                }
            )
    else:
        # v1 : generation lineaire step[i] -> step[i+1] sur TOUS les steps
        # (pas uniquement les `is_enabled`). L'executor saute deja les
        # disabled au runtime — detacher du graphe creerait des orphelins
        # structurels a la reactivation.
        for k in range(len(validated_steps) - 1):
            validated_edges.append(
                {
                    "from_step_name": validated_steps[k]["name"],
                    "to_step_name": validated_steps[k + 1]["name"],
                    "data_type": "workbook",
                    "metadata": None,
                }
            )

    auto_fields = {
        "name": f"{name} (Import)",
        "description": auto_data.get("description") or None,
        "query_type": query_type,
        "query_text": query_text,
        "schedule_type": schedule_type,
        "schedule_config": schedule_config or None,
        "output_format": output_format,
        "recipients": recipients or None,
        "notify_on_failure": notify_on_failure,
        "notify_on_success": notify_on_success,
        "notification_emails": notification_emails or None,
    }
    return auto_fields, validated_steps, validated_edges


class AutomationImportHandler(AuthenticatedHandler):
    """Import d'une automatisation depuis un fichier JSON.

    **Securite** :

    * Taille max du payload : ``MAX_IMPORT_FILE_BYTES`` (512 KB). Un JSON plus
      gros leve 400 avant tout parsing.
    * Plafond d'etapes : ``MAX_STEPS_PER_IMPORT`` (50). Evite qu'un fichier
      forge ne cree 10000 AutomationStep.
    * Validation stricte du type et de la config de chaque etape contre
      ``STEP_TYPE_META.config_schema``.
    * Import cree TOUJOURS ``is_active=False`` (l'utilisateur doit activer
      manuellement, ce qui passe par la planification + verif cron).
    * Rate-limite par utilisateur (fichier volumineux + ecriture BDD).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        """Importe une automatisation depuis un JSON (body ou file upload)."""
        _check_rate_limit(_import_limiter, self.current_user.id, *RATE_LIMIT_IMPORT)

        try:
            payload = self._parse_import_payload()
        except tornado.web.HTTPError:
            raise
        except json.JSONDecodeError:
            self.set_status(400)
            self.write({"success": False, "error": "JSON invalide."})
            return
        except RecursionError:
            # A7-F7 — un JSON trop profondément imbriqué fait lever
            # RecursionError par json.loads (PAS JSONDecodeError) → sans ce
            # catch, propagation en 5xx. C'est un input malformé (taxonomie
            # 4-cas : erreur métier prévue), donc 400.
            self.set_status(400)
            self.write({"success": False, "error": "JSON trop imbriqué (structure invalide)."})
            return

        try:
            auto_fields, validated_steps, validated_edges = self._validate_import(payload)
        except ValueError as e:
            self.set_status(400)
            self.write({"success": False, "error": str(e)})
            return

        try:
            async with self.db_session() as session:
                automation = Automation(
                    user_id=self.current_user.id,
                    is_active=False,
                    **auto_fields,
                )
                session.add(automation)
                await session.flush()

                # Map name -> step_id pour resoudre les edges par nom
                name_to_step_id: dict[str, int] = {}
                for sc in validated_steps:
                    step = AutomationStep(
                        automation_id=automation.id,
                        name=sc["name"],
                        step_type=sc["step_type"],
                        step_order=sc["step_order"],
                        config=sc["config"],
                        is_enabled=sc["is_enabled"],
                        max_retries=sc["max_retries"],
                        retry_delay_seconds=sc["retry_delay_seconds"],
                        layout_x=sc.get("layout_x"),
                        layout_y=sc.get("layout_y"),
                        input_policy=sc.get("input_policy"),
                    )
                    session.add(step)
                    await session.flush()  # pour obtenir step.id
                    name_to_step_id[sc["name"]] = step.id

                # Creation des aretes DAG (v2) ou generation lineaire (v1).
                # On collecte d'abord pour pouvoir valider AVANT commit.
                from app.services.automation.dag_validator import (
                    errors_to_json,
                    validate_structural,
                )

                new_edges_for_validation: list[dict] = []
                edges_to_create: list[AutomationEdge] = []
                for ec in validated_edges:
                    frm_id = name_to_step_id.get(ec["from_step_name"])
                    to_id = name_to_step_id.get(ec["to_step_name"])
                    if frm_id is None or to_id is None:
                        continue  # nom introuvable, ignore silencieusement
                    edges_to_create.append(
                        AutomationEdge(
                            automation_id=automation.id,
                            from_step_id=frm_id,
                            to_step_id=to_id,
                            data_type=ec["data_type"],
                            metadata_json=ec.get("metadata") or None,
                        )
                    )
                    new_edges_for_validation.append(
                        {
                            "id": None,
                            "from_step_id": frm_id,
                            "to_step_id": to_id,
                            "data_type": ec["data_type"],
                        }
                    )

                # Validation DAG AVANT commit : bloque cycles, types
                # incompatibles, fan-in heterogene. Sans ca, un JSON v2
                # crafte peut creer un graphe inexecutable.
                dag_errors = validate_structural(
                    nodes=[
                        {
                            "id": name_to_step_id[vs["name"]],
                            "step_type": vs["step_type"],
                            "name": vs["name"],
                            "config": vs["config"],
                        }
                        for vs in validated_steps
                    ],
                    edges=new_edges_for_validation,
                )
                if dag_errors:
                    await session.rollback()
                    self.set_status(400)
                    self.write(
                        {
                            "success": False,
                            "error": "Validation DAG de l'import echouee",
                            "errors": errors_to_json(dag_errors),
                        }
                    )
                    return

                for e in edges_to_create:
                    session.add(e)

                auto_id = automation.id
                step_count = len(validated_steps)
                edge_count = len(edges_to_create)
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_IMPORT,
                    entity_id=auto_id,
                    details={
                        "name": automation.name,
                        "step_count": step_count,
                        "edge_count": edge_count,
                    },
                )
                await session.commit()

            logger.info(
                "Automatisation importee id=%d (%d etapes, %d aretes) par %s",
                auto_id,
                step_count,
                edge_count,
                self.current_user.email,
            )
            self.write(
                {
                    "success": True,
                    "id": auto_id,
                    "step_count": step_count,
                    "edge_count": edge_count,
                }
            )

        except SQLAlchemyError:
            logger.error("Erreur import automatisation", exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "success": False,
                    "error": "Erreur lors de la creation de l'automatisation.",
                }
            )

    def _parse_import_payload(self) -> dict:
        """Parse le payload d'import (body JSON ou file upload).

        Le plafond de taille est verifie **avant** le decodage JSON pour
        eviter un DoS par payload geant qui epuiserait la memoire du parser.
        """
        files = self.request.files.get("file")
        if files and len(files) > 0:
            file_body = files[0]["body"]
            if len(file_body) > MAX_IMPORT_FILE_BYTES:
                raise tornado.web.HTTPError(
                    400,
                    f"Fichier trop volumineux (max {MAX_IMPORT_FILE_BYTES // 1024} KB)",
                )
            return json.loads(file_body.decode("utf-8"))

        body = self.request.body
        if not body:
            raise tornado.web.HTTPError(400, "Aucune donnee recue")
        if len(body) > MAX_IMPORT_FILE_BYTES:
            raise tornado.web.HTTPError(
                400,
                f"Payload trop volumineux (max {MAX_IMPORT_FILE_BYTES // 1024} KB)",
            )
        return json.loads(body.decode("utf-8"))

    def _validate_import(self, payload: dict) -> tuple[dict, list[dict], list[dict]]:
        """Wrapper sur ``validate_automation_payload`` (Phase 3d : extrait
        en module-level pour reutilisation dans
        ``AutomationTemplateInstantiateHandler`` sans hack ``__new__``).
        Backward-compat : on garde la methode pour les tests existants.
        """
        return validate_automation_payload(payload)


class AutomationExecuteHandler(AuthenticatedHandler):
    """Execution manuelle d'une automatisation."""

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Lance l'execution manuelle.

        **Rate-limit** : execution = tache lourde (SQL + IA + I/O fichier +
        mail). Quota strict par utilisateur.

        **MissingGreenlet** : on capture ``automation.name`` dans la session
        AVANT le commit pour le log en aval — SQLAlchemy async leve
        ``MissingGreenlet`` sur un lazy-load hors session.
        """
        from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
        from app.services.automation.feature_flag_service import is_truthy

        automation_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                # Kill-switch admin : refuse nouvelles executions si flag actif.
                # Les runs deja en cours ne sont pas interrompus (hors scope).
                if await is_truthy(session, FLAG_AUTOMATIONS_DISABLED, default=False):
                    self.set_status(503)
                    self.write(
                        {
                            "success": False,
                            "error": (
                                "Les executions d'automatisations sont temporairement "
                                "desactivees par l'administrateur."
                            ),
                        }
                    )
                    return

                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                # Real-review #3 : eager-load steps+edges pour valider le DAG
                # AVANT de lancer l'exécution. Sans ça, un workflow incomplet
                # crash en plein run avec une trace cryptique côté user.
                automation = await _get_owned_then_rate_limit(
                    session,
                    automation_id_int,
                    self.current_user.id,
                    _execute_limiter,
                    *RATE_LIMIT_EXECUTE,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )
                auto_name = automation.name

                # Real-review #3 cycle 23 : validation DAG AVANT exécution.
                # Évite des runs voués à l'échec (config incomplète, source
                # manquante, cycle, types incompatibles). Cohérent avec le
                # check d'activation du toggle handler.
                from app.services.automation.dag_validator import (
                    errors_to_json,
                    validate_all,
                )

                pre_nodes = [
                    {
                        "id": s.id,
                        "step_type": (
                            s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                        ),
                        "name": s.name,
                        "config": s.config or {},
                        "is_enabled": s.is_enabled,
                    }
                    for s in automation.steps
                ]
                pre_edges = [
                    {
                        "id": e.id,
                        "from_step_id": e.from_step_id,
                        "to_step_id": e.to_step_id,
                        "data_type": e.data_type,
                    }
                    for e in automation.edges
                ]
                pre_errors = list(validate_all(pre_nodes, pre_edges, for_activation=True))
                if pre_errors:
                    logger.info(
                        "Execution refusee : DAG invalide",
                        extra={
                            "automation_id": automation_id_int,
                            "errors": [e.code for e in pre_errors],
                        },
                    )
                    self.set_status(400)
                    self.write(
                        {
                            "success": False,
                            "error": "Execution refusee : le workflow est incomplet.",
                            "errors": errors_to_json(pre_errors),
                        }
                    )
                    return

                # Cluster-B 2026-05-26 — audit de l'INTENTION (manual trigger).
                # Le résultat asynchrone du run lui-même est tracé séparément
                # via le modèle ``Execution`` (started_at/finished_at/status).
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_EXECUTE,
                    entity_id=automation_id_int,
                    details={"trigger_source": "manual", "name": auto_name},
                )
                await session.commit()

            # AUTO-1 — fire-and-forget : on dispatche le run en tâche de fond
            # (même SSoT ``execute_automation``, sérialisée par le lock
            # per-automation) et on rend la main IMMÉDIATEMENT. Avant, on
            # awaitait tout le run (extract+LLM+PDF+email, parfois plusieurs
            # minutes) en tenant la requête HTTP → bouton figé, message
            # « lancée » mensonger, et un 504 proxy → retry nginx → DOUBLE envoi
            # mail. Le panneau « En cours » (poller /api/executions/running)
            # suit la progression ; « Exécution lancée » devient donc VRAI.
            _task = asyncio.create_task(
                _run_manual_automation_bg(
                    automation_id_int, self.current_user.id, auto_name
                ),
                name=f"manual-exec-{automation_id_int}",
            )
            _MANUAL_EXEC_TASKS.add(_task)
            _task.add_done_callback(_MANUAL_EXEC_TASKS.discard)
            logger.info(
                "Execution manuelle dispatchée pour %s",
                auto_name,
                extra={"automation_id": automation_id_int},
            )
            self.write({"success": True, "message": "Exécution lancée"})

        except tornado.web.HTTPError:
            raise
        except (SQLAlchemyError, OSError, ValueError) as e:
            logger.error("Erreur execution manuelle: %s", e, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "success": False,
                    "error": "Une erreur est survenue lors de l'execution de l'automatisation.",
                }
            )


class AutomationHistoryHandler(AuthenticatedHandler):
    """Historique d'executions d'une automatisation."""

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Affiche l'historique des executions avec filtres et pagination."""
        status = _validated_execution_status(self.get_argument("status", None))
        days = self.get_argument("days", None)
        page = self._parse_int_or_400(self.get_argument("page", "1"), "page")
        per_page = DEFAULT_PER_PAGE
        automation_id_int = self._parse_int_or_400(automation_id, "automation_id")

        async with self.db_session() as session:
            automation = await _get_owned_automation_or_404(
                session,
                automation_id_int,
                self.current_user.id,
                options=[selectinload(Automation.steps)],
            )

            auto_name = automation.name
            is_workflow = bool(automation.steps)

            query = select(Execution).where(Execution.automation_id == automation_id_int)
            if status:
                query = query.where(Execution.status == status)
            query = _apply_days_filter(query, days, Execution.started_at)

            # Total count
            count_result = await session.execute(select(func.count()).select_from(query.subquery()))
            total_count = count_result.scalar()
            total_pages = (total_count + per_page - 1) // per_page

            # Pagination
            query = query.order_by(Execution.started_at.desc())
            query = query.offset((page - 1) * per_page).limit(per_page)

            result = await session.execute(query)
            executions = result.scalars().all()

            # Capture execution data inside session (avoid MissingGreenlet in template).
            # **Mode invisible** — ``error_message`` passe par sanitize + scrub data_access
            # AVANT exposition au template HTML (peut contenir un nom de table denied).
            executions_data = [
                SimpleNamespace(
                    id=ex.id,
                    status=ex.status,
                    started_at=ex.started_at,
                    finished_at=ex.finished_at,
                    duration_seconds=ex.duration_seconds,
                    result_rows=ex.result_rows,
                    output_file_path=ex.output_file_path,
                    error_message=await _safe_error_for_user(ex.error_message, self.current_user),
                    has_steps=is_workflow,
                )
                for ex in executions
            ]

        self.render(
            "automations/history.html",
            automation=SimpleNamespace(name=auto_name, id=automation_id_int),
            executions=executions_data,
            page=page,
            total_pages=total_pages,
            status_filter=status,
            days_filter=days,
            page_title=f"Historique: {auto_name}",
        )


class AutomationExecutionsAPIHandler(AuthenticatedHandler):
    """API pour recuperer les executions d'une automation en JSON."""

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Retourne les executions en JSON avec filtres et pagination."""
        status = _validated_execution_status(self.get_argument("status", None))
        days = self.get_argument("days", None)
        page = self._parse_int_or_400(self.get_argument("page", "1"), "page")
        per_page = DEFAULT_PER_PAGE
        automation_id_int = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                await _get_owned_automation_or_404(session, automation_id_int, self.current_user.id)

                query = select(Execution).where(Execution.automation_id == automation_id_int)
                if status:
                    query = query.where(Execution.status == status)
                query = _apply_days_filter(query, days, Execution.started_at)

                count_result = await session.execute(
                    select(func.count()).select_from(query.subquery())
                )
                total_count = count_result.scalar() or 0
                total_pages = (total_count + per_page - 1) // per_page

                query = query.order_by(Execution.started_at.desc())
                query = query.offset((page - 1) * per_page).limit(per_page)

                result = await session.execute(query)
                executions = result.scalars().all()

                # `exec` est le builtin Python — on utilise ``ex`` pour ne pas
                # le shadower localement (clean-code + evite les pieges dans
                # les tests qui injecteraient un fake ``exec``).
                # Cluster-C 2026-05-26 — scrub data_access mode invisible sur
                # ``error_message`` (avant : leak des noms de tables denied
                # via l'API JSON ; asymétrie avec AutomationHistoryHandler
                # qui scrub déjà côté HTML).
                executions_data = []
                for ex in executions:
                    executions_data.append(
                        {
                            "id": ex.id,
                            "status": ex.status,
                            "started_at": clock.iso_utc(ex.started_at),
                            "finished_at": clock.iso_utc(ex.finished_at),
                            "duration_seconds": ex.duration_seconds,
                            "result_rows": ex.result_rows,
                            "output_filename": (
                                Path(ex.output_file_path).name if ex.output_file_path else None
                            ),
                            "error_message": await _safe_error_for_user(
                                ex.error_message, self.current_user
                            ),
                        }
                    )

                self.write(
                    {
                        "success": True,
                        "executions": executions_data,
                        "page": page,
                        "total_pages": total_pages,
                        "total_count": total_count,
                    }
                )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError as e:
            logger.error("Erreur API executions: %s", e, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "success": False,
                    "error": "Erreur lors de la recuperation des executions.",
                }
            )


class AutomationDownloadHandler(AuthenticatedHandler):
    """Telechargement securise des fichiers de resultat d'execution.

    **Defenses** :

    * 404 uniformement (fichier absent, pas-owner, hors repertoire autorise,
      symlink) — aucun message different ne doit permettre d'inferer l'etat
      filesystem (CWE-203).
    * Symlink check post-resolve : on resoud UNE FOIS avec `os.path.realpath`
      via ``Path.resolve()``, puis on compare le prefixe a ``allowed_dir``
      ET on refuse si le lien symbolique existe. TOCTOU minimise (on passe
      la meme Path a l'ouverture).
    * Content-Disposition : filename assaini ASCII + anti-CRLF. Le suffixe
      ``Path.suffix`` vient du resolved, pas du nom stocke en BDD.
    * Whitelisting MIME : extensions non listees retombent sur
      ``application/octet-stream`` (navigateur ne lancera pas un viewer).
    """

    _CONTENT_TYPES: dict[str, str] = {
        ".csv": "text/csv",
        ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ".pdf": "application/pdf",
    }

    @require_role("admin", "user")
    async def get(self, execution_id: str) -> None:
        """Telecharge le fichier de resultat d'une execution."""
        execution_id_int = self._parse_int_or_400(execution_id, "execution_id")

        async with self.db_session() as session:
            result = await session.execute(
                select(Execution)
                .where(Execution.id == execution_id_int)
                .options(selectinload(Execution.automation))
            )
            execution = result.scalar_one_or_none()

            if not execution or not execution.automation:
                raise tornado.web.HTTPError(404, "Execution non trouvee")

            # 404 (et pas 403) sur non-owner — voir EPIC:HANDLERS-404-SYMMETRY.
            if execution.automation.user_id != self.current_user.id:
                raise tornado.web.HTTPError(404, "Execution non trouvee")

            if not execution.output_file_path:
                raise tornado.web.HTTPError(404, "Aucun fichier disponible")

            file_path = Path(execution.output_file_path)

        from app.config import config

        allowed_dir = (config.data_dir / "automation_reports").resolve()

        # CWE-367 (TOCTOU) : on resoud d'abord, puis on verifie sur
        # `resolved` UNIQUEMENT — sinon un attaquant peut swap entre
        # `is_symlink(file_path)` et `file_path.resolve()`. `resolve()`
        # suit deja la chaine de symlinks ; si la cible finale est elle-meme
        # un symlink (cas extreme, possible avec `lchmod` + race), on la
        # bloque. Et `is_relative_to` verifie le containment sur la meme
        # Path resolue, fermant le TOCTOU sur le containment aussi.
        try:
            resolved = file_path.resolve()
        except (OSError, RuntimeError):
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        if resolved.is_symlink():
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        try:
            resolved.relative_to(allowed_dir)
        except ValueError:
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        if not resolved.exists() or not resolved.is_file():
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        content_type = self._CONTENT_TYPES.get(resolved.suffix.lower(), "application/octet-stream")
        self.set_header("Content-Type", content_type)

        # Filename safe : ASCII + anti-CRLF. On tronque a 200 caracteres pour
        # rester sous les limites de certains user-agents.
        safe_name = _sanitize_filename(resolved.name, max_len=200)
        suffix = resolved.suffix.lower()
        if suffix and not safe_name.endswith(suffix):
            safe_name = f"{safe_name}{suffix}"
        self.set_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.set_header("Content-Length", resolved.stat().st_size)

        await stream_file_to_handler(self, resolved, DOWNLOAD_CHUNK_BYTES)


class AutomationPreviewOutputHandler(AuthenticatedHandler):
    """B5 — Sert les fichiers preview tmp generes par le step preview live.

    ``GET /automations/<auto_id>/preview/output/<step_id>/<filename>?token=<hmac>``

    Le preview WebSocket (cf. ``preview_service.py``) genere des fichiers
    tmp pour les steps `report` (PDF) et `export_workbook` (xlsx/csv) et
    emet un token HMAC time-limite via ``StepPreviewResult.output_file_token``.
    Ce handler consomme ce token : il valide l'ownership, la signature, le
    path (anti-traversal), puis stream le fichier.

    **Defenses** (alignees sur ``AutomationDownloadHandler``):

    * Ownership 404 sur automation_id (anti-oracle).
    * Token HMAC : ``verify_output_token`` rejette signature invalide,
      expire passee, ou parametres tampered (CWE-345).
    * ``resolve_preview_output_path`` refuse les filenames avec ``/``,
      ``\\``, ``.`` initial, et verifie le containment dans le tmp dir
      du user (anti-traversal CWE-22).
    * 404 uniformement sur tous les echecs (token, ownership, path).
    * Symlink check post-resolve (deja dans ``resolve_preview_output_path``).
    """

    _CONTENT_TYPES: dict[str, str] = {
        ".csv": "text/csv",
        ".xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ".pdf": "application/pdf",
        ".zip": "application/zip",
    }

    @require_role("admin", "user")
    async def get(self, automation_id: str, step_id: str, filename: str) -> None:
        from app.services.automation.preview_service import (
            resolve_preview_output_path,
            verify_output_token,
        )

        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        step_id_int = self._parse_int_or_400(step_id, "step_id")

        # Ownership 404 sur l'automation. Le step_id sera valide via le
        # path tmp (qui inclut user_id + automation_id + step_id).
        async with self.db_session() as session:
            await _get_owned_automation_or_404(session, auto_id, self.current_user.id)

        # Token HMAC : query param ``?token=...``. Sans token = 404 (pas
        # 401, pour aligner avec les autres path-traversal defenses qui
        # 404 partout).
        token = self.get_argument("token", default="")
        if not token or not verify_output_token(
            token,
            user_id=self.current_user.id,
            automation_id=auto_id,
            step_id=step_id_int,
            filename=filename,
        ):
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        # Resoud le path tmp (refuse filename avec / \\ . initial,
        # verifie containment dans le repertoire du user).
        resolved = resolve_preview_output_path(
            user_id=self.current_user.id,
            automation_id=auto_id,
            step_id=step_id_int,
            filename=filename,
        )
        if resolved is None:
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        if not resolved.exists() or not resolved.is_file():
            raise tornado.web.HTTPError(404, "Fichier non trouve")

        content_type = self._CONTENT_TYPES.get(resolved.suffix.lower(), "application/octet-stream")
        self.set_header("Content-Type", content_type)
        # B5 cycle 6 — Defense-in-depth headers : nosniff bloque le MIME
        # sniffing (Edge legacy peut sniffer un xlsx en HTML si content
        # commence par <html>). CSP default-src 'none' empeche tout
        # contexte d'execution si le navigateur essayait de rendre le
        # fichier comme une page (ne devrait pas, mais defense en profondeur).
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Content-Security-Policy", "default-src 'none'")

        safe_name = _sanitize_filename(resolved.name, max_len=200)
        suffix = resolved.suffix.lower()
        if suffix and not safe_name.endswith(suffix):
            safe_name = f"{safe_name}{suffix}"
        self.set_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.set_header("Content-Length", resolved.stat().st_size)

        await stream_file_to_handler(self, resolved, DOWNLOAD_CHUNK_BYTES)


class AllExecutionsHandler(AuthenticatedHandler):
    """Vue globale de toutes les executions de l'utilisateur."""

    @require_role("admin", "user")
    async def get(self) -> None:
        """Affiche toutes les executions avec filtres et pagination."""
        status = _validated_execution_status(self.get_argument("status", None))
        days = self.get_argument("days", None)
        page = self._parse_int_or_400(self.get_argument("page", "1"), "page")
        per_page = EXECUTIONS_PER_PAGE

        async with self.db_session() as session:
            query = (
                select(Execution)
                .join(Automation, Automation.id == Execution.automation_id)
                .where(Automation.user_id == self.current_user.id)
                .options(joinedload(Execution.automation).selectinload(Automation.steps))
            )

            if status:
                query = query.where(Execution.status == status)
            query = _apply_days_filter(query, days, Execution.started_at)

            # Total count
            count_result = await session.execute(select(func.count()).select_from(query.subquery()))
            total_count = count_result.scalar()
            total_pages = (total_count + per_page - 1) // per_page

            # Pagination
            query = query.order_by(Execution.started_at.desc())
            query = query.offset((page - 1) * per_page).limit(per_page)

            result = await session.execute(query)
            executions = result.scalars().all()

            # Capture all data inside session (avoid MissingGreenlet in template).
            # Cluster-C 2026-05-26 — scrub data_access mode invisible sur
            # ``error_message`` (avant : leak noms tables denied + paths
            # absolus dans le template ``automations/all_executions.html``).
            executions_data = []
            for ex in executions:
                executions_data.append(
                    SimpleNamespace(
                        id=ex.id,
                        status=ex.status,
                        started_at=ex.started_at,
                        finished_at=ex.finished_at,
                        duration_seconds=ex.duration_seconds,
                        result_rows=ex.result_rows,
                        output_file_path=ex.output_file_path,
                        error_message=await _safe_error_for_user(
                            ex.error_message, self.current_user
                        ),
                        _automation_name=ex.automation.name if ex.automation else "?",
                        automation_id=ex.automation_id,
                        has_steps=(
                            bool(ex.automation and ex.automation.steps) if ex.automation else False
                        ),
                    )
                )

        self.render(
            "automations/all_executions.html",
            executions=executions_data,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
            status_filter=status,
            days_filter=days,
            page_title="Historique des exécutions",
        )


class ExecutionDetailHandler(AuthenticatedHandler):
    """Vue detail d'une execution individuelle avec timeline step-by-step."""

    @require_role("admin", "user")
    async def get(self, execution_id: str) -> None:
        """Affiche le detail complet d'une execution avec ses etapes."""
        execution_id_int = self._parse_int_or_400(execution_id, "execution_id")

        async with self.db_session() as session:
            # Charger l'execution avec automation et steps
            result = await session.execute(
                select(Execution)
                .where(Execution.id == execution_id_int)
                .options(
                    joinedload(Execution.automation),
                    selectinload(Execution.step_executions),
                )
            )
            execution = result.scalars().unique().first()

            if not execution or not execution.automation:
                raise tornado.web.HTTPError(404, "Execution non trouvee")

            # Ownership check
            if execution.automation.user_id != self.current_user.id:
                raise tornado.web.HTTPError(404, "Execution non trouvee")

            # Capture automation data
            auto_data = SimpleNamespace(
                id=execution.automation.id,
                name=execution.automation.name,
            )

            # Capture step data inside session (avoid MissingGreenlet).
            # Phase 3c : `error_message` sanitize (stacktraces/credentials)
            # avant insertion dans le contexte template (CWE-209).
            steps_data = []
            success_count = 0
            failed_count = 0
            skipped_count = 0
            retried_count = 0
            for s in execution.step_executions:
                steps_data.append(
                    SimpleNamespace(
                        id=s.id,
                        step_order=s.step_order,
                        step_name=s.step_name,
                        step_type=s.step_type,
                        attempt_number=s.attempt_number,
                        status=s.status,
                        started_at=s.started_at,
                        finished_at=s.finished_at,
                        duration_ms=s.duration_ms,
                        rows_in=s.rows_in,
                        rows_out=s.rows_out,
                        warnings=s.warnings or [],
                        error_message=await _safe_error_for_user(
                            s.error_message, self.current_user
                        ),
                    )
                )
                if s.status == "success":
                    success_count += 1
                elif s.status == "failed":
                    failed_count += 1
                elif s.status == "skipped":
                    skipped_count += 1
                elif s.status == "retried":
                    retried_count += 1

            # Capture execution data (sanitize + scrub data_access du banner d'erreur global).
            exec_data = SimpleNamespace(
                id=execution.id,
                automation_id=execution.automation_id,
                status=execution.status,
                started_at=execution.started_at,
                finished_at=execution.finished_at,
                duration_seconds=execution.duration_seconds,
                result_rows=execution.result_rows,
                output_file_path=execution.output_file_path,
                error_message=await _safe_error_for_user(
                    execution.error_message, self.current_user
                ),
            )

            # Task #17 (2026-05-27) — Panneau Décisions Iris : lecture des
            # AuditLog avec action=IRIS_AUTOMATION_DECISION pour les step_ids
            # iris de cette execution. Permet à l'user de voir POURQUOI Iris
            # a pris chaque décision (instruction, summary, variables, abort).
            iris_step_ids = [s.id for s in execution.step_executions if s.step_type == "iris"]
            iris_decisions = []
            if iris_step_ids:
                from app.models.audit import AuditAction, AuditLog
                import json as _json

                audit_result = await session.execute(
                    select(AuditLog)
                    .where(
                        AuditLog.action == AuditAction.IRIS_AUTOMATION_DECISION,
                        AuditLog.entity_type == "automation_step",
                        AuditLog.entity_id.in_(iris_step_ids),
                    )
                    .order_by(AuditLog.created_at.asc())
                )
                for log_row in audit_result.scalars().all():
                    try:
                        details = (
                            _json.loads(log_row.details)
                            if isinstance(log_row.details, str)
                            else (log_row.details or {})
                        )
                    except (TypeError, ValueError):
                        details = {}
                    iris_decisions.append(
                        SimpleNamespace(
                            step_id=log_row.entity_id,
                            created_at=log_row.created_at,
                            instruction=details.get("instruction", ""),
                            decision_summary=details.get("decision_summary", ""),
                            aborted=bool(details.get("aborted")),
                            abort_reason=details.get("abort_reason"),
                            variables_written=details.get("variables_written", []),
                            turns_used=int(details.get("turns_used", 0) or 0),
                            trace_length=int(details.get("trace_length", 0) or 0),
                            llm_cost_usd=float(details.get("llm_cost_usd", 0.0) or 0.0),
                        )
                    )

        self.render(
            "automations/execution_detail.html",
            execution=exec_data,
            automation=auto_data,
            steps=steps_data,
            iris_decisions=iris_decisions,
            stats=SimpleNamespace(
                total=len(steps_data),
                success=success_count,
                failed=failed_count,
                skipped=skipped_count,
                retried=retried_count,
            ),
            page_title=f"Execution #{execution_id_int}",
        )


# ── Workflow Steps API ──


class AutomationStepTypesAPIHandler(AuthenticatedHandler):
    """API retournant les types d'etapes disponibles pour le workflow builder.

    Fusionne STEP_TYPE_META (config_schema, icone, description) et
    NODE_TYPE_SIGNATURES (inputs/outputs DAG typés, is_source, is_sink).
    Le frontend canvas utilise cette source unique pour : afficher la
    palette, valider les branchements visuellement (types d'edges),
    generer les formulaires de config (via config_schema).
    """

    @require_role("admin", "user")
    async def get(self) -> None:
        """Retourne la liste des types d'etapes groupes par categorie + signatures DAG."""
        from app.services.automation.dag_validator import NODE_TYPE_SIGNATURES

        categories: dict = {}
        for step_type, meta in STEP_TYPE_META.items():
            # Phase 3d : un type marque `available=False` est expose au
            # frontend mais avec un flag `available=False` qui doit
            # bloquer le drag-drop dans la palette. Cote backend, on le
            # retourne quand meme pour que le viewer (DAG d'une execution
            # passee) puisse afficher correctement le label/icone si le
            # type est apparu dans une exec historique.
            available = meta.get("available", True)

            cat = meta.get("category", "autre")
            if cat not in categories:
                cat_meta = STEP_CATEGORIES.get(cat, {"label": cat, "icon": "gear", "order": 99})
                categories[cat] = {
                    "label": cat_meta["label"],
                    "icon": cat_meta["icon"],
                    "order": cat_meta["order"],
                    "steps": [],
                }
            # Signature DAG (peut ne pas exister pour les types non-DAG like
            # `aggregate` legacy ; fallback sur un schema generique workbook).
            sig = NODE_TYPE_SIGNATURES.get(step_type.value, {})
            categories[cat]["steps"].append(
                {
                    "type": step_type.value,
                    "label": meta["label"],
                    "icon": meta["icon"],
                    "description": meta["description"],
                    "category": cat,
                    "config_schema": meta.get("config_schema", {}),
                    # Phase 3a DAG : signature pour validation visuelle canvas
                    "inputs": sig.get("inputs", []),
                    "outputs": sig.get("outputs", []),
                    "is_source": sig.get("is_source", False),
                    "is_sink": sig.get("is_sink", False),
                    # Phase 3d : flag de disponibilite. Le frontend palette
                    # lit ce flag pour griser/desactiver le drag.
                    "available": available,
                }
            )

        # Trier les categories par ordre
        sorted_cats = sorted(categories.values(), key=lambda c: c["order"])
        self.write(
            {
                "success": True,
                "categories": sorted_cats,
                # Types de donnees qui circulent sur les edges — expose pour
                # que le renderer puisse colorer/valider visuellement.
                "edge_data_types": list(EDGE_DATA_TYPES),
            }
        )


class AutomationStepsAPIHandler(AuthenticatedHandler):
    """API CRUD pour les etapes d'un workflow."""

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Liste les etapes d'une automatisation."""
        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                await _get_owned_automation_or_404(session, auto_id, self.current_user.id)

                result = await session.execute(
                    select(AutomationStep)
                    .where(AutomationStep.automation_id == auto_id)
                    .order_by(AutomationStep.step_order)
                )
                steps = result.scalars().all()

                self.write(
                    {
                        "success": True,
                        "steps": [s.to_dict() for s in steps],
                    }
                )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur lecture etapes automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de lecture des etapes."})

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Ajoute une etape au workflow.

        Phase 3b-2 : accepte `layout_x` / `layout_y` dans le body pour
        persister la position directement au drop (evite un round-trip
        supplementaire + perte si refresh rapide).
        Rate-limite via `_edges_write_limiter` (endpoint de mutation
        canvas frequent).
        """
        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        body = self.get_json_body()
        if not isinstance(body, dict) or not body:
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        name = (body.get("name", "") or "").strip()[:MAX_NAME_LENGTH]
        step_type = (body.get("step_type", "") or "").strip()
        step_config = body.get("config", {})

        if not name:
            self.set_status(400)
            self.write({"success": False, "error": "Le nom de l'etape est requis."})
            return

        valid_types = {t.value for t in StepType}
        if step_type not in valid_types:
            self.set_status(400)
            self.write({"success": False, "error": "Type d'etape invalide."})
            return

        if not isinstance(step_config, dict):
            step_config = {}

        schema_err = _validate_step_config(step_type, step_config)
        if schema_err:
            self.set_status(400)
            self.write({"success": False, "error": schema_err})
            return

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id,
                    self.current_user.id,
                    _edges_write_limiter,
                    *RATE_LIMIT_EDGES_WRITE,
                )

                max_order_result = await session.execute(
                    select(func.max(AutomationStep.step_order)).where(
                        AutomationStep.automation_id == auto_id
                    )
                )
                max_order = max_order_result.scalar()
                if max_order is None:
                    max_order = -1

                max_retries = _clamp_int(body.get("max_retries", 0), 0, STEP_MAX_RETRIES_CAP, 0)
                retry_delay = _clamp_int(
                    body.get("retry_delay_seconds", STEP_RETRY_DELAY_DEFAULT_SEC),
                    STEP_RETRY_DELAY_MIN_SEC,
                    STEP_RETRY_DELAY_MAX_SEC,
                    STEP_RETRY_DELAY_DEFAULT_SEC,
                )

                try:
                    is_enabled = (
                        strict_bool(body["is_enabled"], field="is_enabled")
                        if "is_enabled" in body
                        else True
                    )
                except (ValueError, TypeError) as e:
                    self.set_status(400)
                    self.write({"success": False, "error": str(e)})
                    return

                # Positions layout (optionnelles) : clamped aux bornes
                # definies pour PUT /layout pour rester coherent.
                layout_x: Optional[int] = None
                layout_y: Optional[int] = None
                if "layout_x" in body and body["layout_x"] is not None:
                    layout_x = _clamp_int(
                        body["layout_x"],
                        _LAYOUT_MIN_COORD,
                        _LAYOUT_MAX_COORD,
                        0,
                    )
                if "layout_y" in body and body["layout_y"] is not None:
                    layout_y = _clamp_int(
                        body["layout_y"],
                        _LAYOUT_MIN_COORD,
                        _LAYOUT_MAX_COORD,
                        0,
                    )

                step = AutomationStep(
                    automation_id=auto_id,
                    name=name,
                    step_type=step_type,
                    step_order=max_order + 1,
                    config=step_config,
                    is_enabled=is_enabled,
                    max_retries=max_retries,
                    retry_delay_seconds=retry_delay,
                    layout_x=layout_x,
                    layout_y=layout_y,
                )

                # `partial=True` : a la creation/edition canvas, un step est
                # drag-droppe avec config vide (l'utilisateur configure ensuite
                # via le panel). On ne bloque PAS sur les champs `required`
                # manquants ici — ce sera verifie a l'activation par
                # `validate_completeness` (qui rappelle validate(partial=False)
                # sur chaque node). Sans `partial=True`, drag-and-drop d'un
                # extract_sql, filter_rows, etc. (la majorite des types)
                # crashe immediatement avec un 400 "Champ requis manquant".
                errors = step.validate(partial=True)
                if errors:
                    self.set_status(400)
                    self.write({"success": False, "error": "; ".join(errors)})
                    return

                session.add(step)
                await session.flush()
                # Cluster-B-FOLLOWUP 2026-05-26 — Audit STEP_CREATE.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.STEP_CREATE,
                    entity_id=auto_id,
                    details={
                        "step_id": step.id,
                        "step_name": name,
                        "step_type": step_type,
                    },
                )
                # T4 2026-06-10 — bumper la version (cohérence optimistic-lock).
                # Créer un nœud change la structure → les autres onglets doivent
                # être invalidés (avant ce fix, POST /steps ne bumpait PAS la
                # version, donc un autre onglet ignorait l'ajout = trou cross-tab).
                # Pas de `_check_if_match_or_409` ici : la création reste
                # PERMISSIVE (un client à version périmée peut quand même créer un
                # nœud) ; le CAS depuis la version chargée n'échoue que sur une
                # vraie race serveur concurrente → 409 émis, on rollback (le
                # client re-synchronise via le handler de conflit côté canvas).
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return  # 409 version_conflict émis ; le context rollback
                await session.commit()
                await session.refresh(step)
                step_dict = step.to_dict()

            logger.info(
                "Etape ajoutee: %s (type=%s) pour automation %d",
                name,
                step_type,
                auto_id,
            )
            from app.services.anonymization.auto_scan import schedule_target_rescan

            schedule_target_rescan(self.current_user.id, "automation", auto_id)
            self.write({"success": True, "step": step_dict, "version": new_version})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur ajout etape automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de l'ajout de l'etape."})


class AutomationStepDetailAPIHandler(AuthenticatedHandler):
    """API pour modifier/supprimer une etape."""

    @require_role("admin", "user")
    async def put(self, automation_id: str, step_id: str) -> None:
        """Met a jour une etape."""
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        s_id = self._parse_int_or_400(step_id, "step_id")

        body = self.get_json_body()
        if not isinstance(body, dict) or not body:
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session, auto_id, self.current_user.id
                )
                # Cluster-N 2026-05-26 — Step 1/2 : fail-fast If-Match.
                if not _check_if_match_or_409(self, automation):
                    return

                step = await session.get(AutomationStep, s_id)
                if not step or step.automation_id != auto_id:
                    raise tornado.web.HTTPError(404, "Etape non trouvee")

                # #25 — état AVANT modif, pour détecter une VRAIE réactivation
                # (False→True) distincte d'un autosave no-op (True→True).
                _was_enabled = step.is_enabled

                if "name" in body:
                    name = (body["name"] or "").strip()[:MAX_NAME_LENGTH]
                    if name:
                        step.name = name
                if "step_type" in body:
                    valid_types = {t.value for t in StepType}
                    if body["step_type"] in valid_types:
                        step.step_type = body["step_type"]
                if "config" in body and isinstance(body["config"], dict):
                    # Valider la config contre le schema du type (courant ou
                    # nouveau). Une config invalide pour le type final
                    # retourne 400.
                    target_type = step.step_type
                    schema_err = _validate_step_config(target_type, body["config"])
                    if schema_err:
                        self.set_status(400)
                        self.write({"success": False, "error": schema_err})
                        return
                    step.config = body["config"]
                if "is_enabled" in body:
                    try:
                        step.is_enabled = strict_bool(body["is_enabled"], field="is_enabled")
                    except (ValueError, TypeError) as e:
                        self.set_status(400)
                        self.write({"success": False, "error": str(e)})
                        return
                if "step_order" in body:
                    try:
                        step.step_order = int(body["step_order"])
                    except (ValueError, TypeError):
                        logger.warning(
                            "step_order invalide ignore: %r (etape %s)",
                            body["step_order"],
                            step_id,
                        )
                if "max_retries" in body:
                    step.max_retries = _clamp_int(
                        body["max_retries"], 0, STEP_MAX_RETRIES_CAP, step.max_retries
                    )
                if "retry_delay_seconds" in body:
                    step.retry_delay_seconds = _clamp_int(
                        body["retry_delay_seconds"],
                        STEP_RETRY_DELAY_MIN_SEC,
                        STEP_RETRY_DELAY_MAX_SEC,
                        step.retry_delay_seconds,
                    )

                # `partial=True` : a la creation/edition canvas, un step est
                # drag-droppe avec config vide (l'utilisateur configure ensuite
                # via le panel). On ne bloque PAS sur les champs `required`
                # manquants ici — ce sera verifie a l'activation par
                # `validate_completeness` (qui rappelle validate(partial=False)
                # sur chaque node). Sans `partial=True`, drag-and-drop d'un
                # extract_sql, filter_rows, etc. (la majorite des types)
                # crashe immediatement avec un 400 "Champ requis manquant".
                errors = step.validate(partial=True)
                if errors:
                    self.set_status(400)
                    self.write({"success": False, "error": "; ".join(errors)})
                    return

                # #25 fix 2026-06-11 — réactiver un step (is_enabled False→True)
                # sur une auto ACTIVE doit garder le DAG valide. Avant, le PUT ne
                # validait QUE le step seul en ``partial=True`` (configs incomplètes
                # tolérées) → un step réactivé avec config incomplète (ou créant un
                # double-envoi / orphelin) rendait l'auto active invalide → ÉCHEC
                # silencieux au prochain run planifié. On re-valide le DAG complet
                # (symétrie avec l'activation, AutomationToggleHandler) UNIQUEMENT
                # sur une vraie transition False→True — PAS un autosave no-op
                # True→True qui spammerait des 400 en plein édition canvas. Les
                # ``select`` ci-dessous renvoient — via l'IDENTITY MAP — la MÊME
                # instance ``step`` déjà chargée par ``session.get`` et mutée en
                # mémoire (``is_enabled=True``/config), donc la re-validation voit
                # bien l'état post-édition. (NB : la session est ``autoflush=False``,
                # ce n'est PAS un flush qui assure la fraîcheur mais l'identity map ;
                # ne pas s'appuyer sur un autoflush inexistant.) Un rollback annule
                # ensuite la mutation en attente si la validation échoue.
                if automation.is_active and _was_enabled is False and step.is_enabled is True:
                    from app.services.automation.dag_validator import (
                        errors_to_json,
                        validate_all,
                    )

                    _re_nodes_q = await session.execute(
                        select(AutomationStep).where(AutomationStep.automation_id == auto_id)
                    )
                    _re_edges_q = await session.execute(
                        select(AutomationEdge).where(AutomationEdge.automation_id == auto_id)
                    )
                    _re_nodes = [
                        {
                            "id": s.id,
                            "step_type": (
                                s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                            ),
                            "name": s.name,
                            "config": s.config or {},
                            "is_enabled": s.is_enabled,
                        }
                        for s in _re_nodes_q.scalars().all()
                    ]
                    _re_edges = [
                        {
                            "id": e.id,
                            "from_step_id": e.from_step_id,
                            "to_step_id": e.to_step_id,
                            "data_type": e.data_type,
                        }
                        for e in _re_edges_q.scalars().all()
                    ]
                    _re_errors = list(validate_all(_re_nodes, _re_edges, for_activation=True))
                    if _re_errors:
                        await session.rollback()
                        self.set_status(400)
                        self.write(
                            {
                                "success": False,
                                "error": (
                                    "Reactivation refusee : reactiver cette etape rendrait "
                                    "l'automatisation active invalide. Desactivez "
                                    "l'automatisation pour l'editer, ou completez l'etape d'abord."
                                ),
                                "errors": errors_to_json(_re_errors),
                            }
                        )
                        return

                # Cluster-N — Step 2/2 : bump APRÈS validate(partial=True)
                # (le 400 ci-dessus n'a alors pas créé d'ETag fantôme).
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return

                # Cluster-B-FOLLOWUP 2026-05-26 — Audit STEP_UPDATE.
                # `body.keys()` capture les champs modifiés (compliance
                # RGPD/ISO 27001 : qui a changé quoi sur le DAG).
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.STEP_UPDATE,
                    entity_id=auto_id,
                    details={
                        "step_id": s_id,
                        "fields_changed": sorted(body.keys()),
                    },
                )
                await session.commit()
                await session.refresh(step)
                step_dict = step.to_dict()
                parent_version = int(new_version)

            from app.services.anonymization.auto_scan import schedule_target_rescan

            schedule_target_rescan(self.current_user.id, "automation", auto_id)
            # Cluster-N — expose parent version pour MAJ état canvas client.
            self.write({"success": True, "step": step_dict, "version": parent_version})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error(
                "Erreur mise a jour etape %s (automation %s)",
                step_id,
                automation_id,
                exc_info=True,
            )
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de la mise a jour de l'etape."})

    @require_role("admin", "user")
    async def delete(self, automation_id: str, step_id: str) -> None:
        """Supprime une etape."""
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        s_id = self._parse_int_or_400(step_id, "step_id")

        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session, auto_id, self.current_user.id
                )
                # Cluster-N — DELETE step = mutation DAG. Check If-Match
                # pour empêcher tab B (stale) de supprimer un step déjà
                # modifié par tab A (asymétrie CRITICAL adversarial).
                if not _check_if_match_or_409(self, automation):
                    return

                step = await session.get(AutomationStep, s_id)
                if not step or step.automation_id != auto_id:
                    raise tornado.web.HTTPError(404, "Etape non trouvee")

                step_name = step.name
                step_type_audit = step.step_type
                await session.delete(step)
                # Cluster-N — bump LAST avant commit (404 ci-dessus
                # rollback sans ETag fantôme).
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return

                # Cluster-B-FOLLOWUP 2026-05-26 — Audit STEP_DELETE.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.STEP_DELETE,
                    entity_id=auto_id,
                    details={
                        "step_id": s_id,
                        "step_name": step_name,
                        "step_type": step_type_audit,
                    },
                )

                # Cluster-S 2026-05-26 — Cancel les waits pendants liés
                # à CE step AVANT commit (FK cascade va supprimer les
                # tokens sinon — perte des destinataires à notifier).
                # step_id filter = ne touche pas aux autres step waits.
                try:
                    from app.services.automation.wait_resume import (
                        cancel_pending_waits_for_automation,
                    )

                    await cancel_pending_waits_for_automation(
                        auto_id,
                        reason="Etape supprimee : tache annulee",
                        step_id=s_id,
                        notify_owner=True,
                    )
                except Exception:  # noqa: BLE001 — best-effort
                    logger.warning(
                        "Cluster-S : cancel_pending_waits before DELETE step echec",
                        exc_info=True,
                        extra={"automation_id": auto_id, "step_id": s_id},
                    )

                await session.commit()

            logger.info(
                "Etape supprimee: %s (automation %d)",
                step_name,
                auto_id,
            )
            self.write(
                {
                    "success": True,
                    "message": "Etape supprimee",
                    "version": int(new_version),
                }
            )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error(
                "Erreur suppression etape %s (automation %s)",
                step_id,
                automation_id,
                exc_info=True,
            )
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de la suppression de l'etape."})


class AutomationStepsReorderAPIHandler(AuthenticatedHandler):
    """API pour reordonner les etapes d'un workflow."""

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Reordonne les etapes selon l'ordre fourni.

        Plafond ``MAX_REORDER_STEPS`` sur la taille de la liste — un payload
        qui viserait a creer 10000 updates consecutifs est refuse a la source.
        """
        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        body = self.get_json_body()
        if not isinstance(body, dict) or not body:
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        step_ids = body.get("step_ids", [])
        if not isinstance(step_ids, list):
            self.set_status(400)
            self.write({"success": False, "error": "step_ids doit etre une liste."})
            return

        if len(step_ids) > MAX_REORDER_STEPS:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": f"Trop d'etapes ({len(step_ids)} > {MAX_REORDER_STEPS}).",
                }
            )
            return

        try:
            async with self.db_session() as session:
                await _get_owned_automation_or_404(session, auto_id, self.current_user.id)

                applied = []
                for order, raw_step_id in enumerate(step_ids):
                    try:
                        sid = int(raw_step_id)
                    except (ValueError, TypeError):
                        continue
                    step = await session.get(AutomationStep, sid)
                    if step and step.automation_id == auto_id:
                        step.step_order = order
                        applied.append(sid)

                # V11 (2026-06-10) — Audit STEP_REORDER. Toute mutation de la
                # structure du DAG doit être traçable (compliance, comme
                # STEP_CREATE/UPDATE/DELETE). La constante AuditAction.STEP_REORDER
                # existait mais n'était jamais appelée ici (seul handler de
                # mutation non audité). Auditer SEULEMENT si des étapes ont
                # réellement bougé (pas de spam audit_logs sur un payload no-op),
                # même pattern que AutomationLayoutAPIHandler.
                if applied:
                    await _audit_automation_event(
                        self,
                        session,
                        action=AuditAction.STEP_REORDER,
                        entity_id=auto_id,
                        details={"step_ids": applied, "count": len(applied)},
                    )

                await session.commit()

            self.write({"success": True, "message": "Etapes reordonnees"})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error(
                "Erreur reordonnement etapes automation %s",
                automation_id,
                exc_info=True,
            )
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors du reordonnement."})


class RunningExecutionsAPIHandler(AuthenticatedHandler):
    """API pour recuperer les executions en cours avec progression des etapes."""

    @require_role("admin", "user")
    async def get(self) -> None:
        """Retourne les executions running/pending de l'utilisateur courant.

        Inclut le nombre total d'etapes et le nombre d'etapes terminees
        pour afficher une barre de progression en temps reel.
        """
        try:
            async with self.db_session() as session:
                # Charger les executions en cours avec leur automation et steps
                result = await session.execute(
                    select(Execution)
                    .join(Automation, Automation.id == Execution.automation_id)
                    .where(
                        Automation.user_id == self.current_user.id,
                        # ENGINE-3-ux (#49) — inclure 'waiting' : un run suspendu sur
                        # un step email_wait_response ne doit PAS disparaître du
                        # moniteur (sinon l'user croit qu'il a fini/planté). Le
                        # frontend le rend avec un badge « en attente d'une réponse
                        # par email ». Le champ ``status`` est déjà exposé ci-dessous.
                        Execution.status.in_(["pending", "running", "waiting"]),
                    )
                    .options(joinedload(Execution.automation).selectinload(Automation.steps))
                    .order_by(Execution.started_at.desc())
                    .limit(MAX_RUNNING_DISPLAY)
                )
                executions = result.scalars().unique().all()

                running_data = []
                for ex in executions:
                    # Compter les step executions pour cette execution
                    step_counts = await session.execute(
                        select(
                            func.count(StepExecution.id).label("total"),
                            func.sum(
                                case(
                                    (StepExecution.status.in_(["success", "failed", "skipped"]), 1),
                                    else_=0,
                                )
                            ).label("completed"),
                            func.sum(
                                case(
                                    (StepExecution.status == "running", 1),
                                    else_=0,
                                )
                            ).label("active"),
                        ).where(
                            StepExecution.execution_id == ex.id,
                            # Exclure les retried (ne compter que la derniere tentative)
                            StepExecution.status != "retried",
                        )
                    )
                    counts = step_counts.one()
                    completed = counts.completed or 0
                    active = counts.active or 0

                    # Le nombre total d'etapes est dans l'automation
                    total_steps = len(ex.automation.steps) if ex.automation else 0

                    # Nom de l'etape en cours (la derniere avec status "running")
                    current_step_result = await session.execute(
                        select(StepExecution.step_name, StepExecution.step_type)
                        .where(
                            StepExecution.execution_id == ex.id,
                            StepExecution.status == "running",
                        )
                        .order_by(StepExecution.step_order.desc())
                        .limit(1)
                    )
                    current_step = current_step_result.one_or_none()

                    # Duree ecoulee (avec ensure_utc pour les started_at naive
                    # venant de SQLite — comparaison tz-consistante).
                    elapsed_seconds = None
                    if ex.started_at:
                        now = clock.now()
                        started = ex.started_at
                        if started.tzinfo is None:
                            started = ensure_utc(started)
                        elapsed_seconds = round((now - started).total_seconds(), 1)

                    running_data.append(
                        {
                            "execution_id": ex.id,
                            "automation_id": ex.automation_id,
                            "automation_name": ex.automation.name if ex.automation else "?",
                            "status": ex.status,
                            "started_at": clock.iso_utc(ex.started_at),
                            "elapsed_seconds": elapsed_seconds,
                            "total_steps": total_steps,
                            "completed_steps": completed,
                            "active_steps": active,
                            "current_step_name": current_step.step_name if current_step else None,
                            "current_step_type": current_step.step_type if current_step else None,
                            "is_workflow": total_steps > 0,
                        }
                    )

                # AUTO-3 — exécutions TERMINÉES récemment (fenêtre courte) avec
                # leur VRAI statut. Le moniteur frontend les utilise pour
                # afficher « terminée » / « ÉCHOUÉE » / « annulée » correctement
                # quand un run disparaît de la liste running, au lieu d'un
                # « terminée » vert systématique (un échec passait pour un succès).
                _recent_cutoff = clock.now() - timedelta(
                    seconds=_RECENT_FINISHED_WINDOW_SECONDS
                )
                recent_result = await session.execute(
                    select(Execution)
                    .join(Automation, Automation.id == Execution.automation_id)
                    .where(
                        Automation.user_id == self.current_user.id,
                        Execution.status.in_(["success", "failed", "partial", "cancelled"]),
                        Execution.finished_at.is_not(None),
                        Execution.finished_at >= _recent_cutoff,
                    )
                    .options(joinedload(Execution.automation))
                    .order_by(Execution.finished_at.desc())
                    .limit(MAX_RUNNING_DISPLAY)
                )
                recently_finished = [
                    {
                        "execution_id": ex.id,
                        "automation_name": ex.automation.name if ex.automation else "?",
                        "status": ex.status,
                    }
                    for ex in recent_result.scalars().unique().all()
                ]

            self.write(
                {
                    "success": True,
                    "running": running_data,
                    "count": len(running_data),
                    "recently_finished": recently_finished,
                }
            )

        except SQLAlchemyError:
            logger.error("Erreur chargement executions en cours", exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de chargement."})


class ExecutionStepsAPIHandler(AuthenticatedHandler):
    """API pour recuperer les resultats par etape d'une execution workflow.

    Phase 3c : enrichi avec ``trace_id``, ``attempt_number``, ``llm_*``,
    et ``automation_id`` au top-level pour que le viewer DAG puisse
    appeler ``GET /api/automations/:id/dag`` ensuite. Les champs sensibles
    (``step_input/output/sql_executed``) restent sur l'endpoint dedie
    ``ExecutionStepDetailAPIHandler`` afin de ne pas inonder le payload
    pour 50 steps a chaque rafraichissement du viewer.
    """

    @require_role("admin", "user")
    async def get(self, execution_id: str) -> None:
        execution_id_int = self._parse_int_or_400(execution_id, "execution_id")

        try:
            async with self.db_session() as session:
                execution = await session.get(Execution, execution_id_int)
                if not execution:
                    # Anti-oracle 404 : meme reponse pour absent vs non-owner.
                    raise tornado.web.HTTPError(404, "Execution non trouvee")

                await _get_owned_automation_or_404(
                    session, execution.automation_id, self.current_user.id
                )

                # Capture des champs scalaires AVANT detach (MissingGreenlet).
                automation_id = execution.automation_id
                exec_status = execution.status

                result = await session.execute(
                    select(StepExecution)
                    .where(StepExecution.execution_id == execution_id_int)
                    .order_by(StepExecution.step_order, StepExecution.attempt_number)
                )
                steps = result.scalars().all()

                # **Mode invisible** : ``error_message`` passe par sanitize +
                # scrub data_access. Boucle explicite plutôt que list-comp
                # car ``await`` dans une dict-comp n'est pas autorisé.
                steps_data: list[dict] = []
                for s in steps:
                    steps_data.append(
                        {
                            "id": s.id,
                            "step_id": s.step_id,
                            "step_order": s.step_order,
                            "step_name": s.step_name,
                            "step_type": s.step_type,
                            "attempt_number": s.attempt_number,
                            "status": s.status,
                            "trace_id": s.trace_id,
                            "started_at": clock.iso_utc(s.started_at),
                            "finished_at": clock.iso_utc(s.finished_at),
                            "duration_ms": s.duration_ms,
                            "rows_in": s.rows_in,
                            "rows_out": s.rows_out,
                            "warnings": s.warnings or [],
                            # Sanitize stacktraces/credentials (CWE-209) + scrub data_access.
                            "error_message": await _safe_error_for_user(
                                s.error_message, self.current_user
                            ),
                            "llm_tokens_in": s.llm_tokens_in,
                            "llm_tokens_out": s.llm_tokens_out,
                            "llm_cost_eur": s.llm_cost_eur,
                        }
                    )

            self.write(
                {
                    "success": True,
                    "execution_id": execution_id_int,
                    "automation_id": automation_id,
                    "execution_status": exec_status,
                    "steps": steps_data,
                    "total": len(steps_data),
                }
            )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error(
                "Erreur chargement step executions %s",
                execution_id,
                exc_info=True,
            )
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de chargement."})


class ExecutionStepDetailAPIHandler(AuthenticatedHandler):
    """Detail complet d'une step_execution (champs sensibles inclus).

    GET /api/executions/:execution_id/steps/:step_exec_id

    Phase 3c : separate de ``ExecutionStepsAPIHandler`` pour deux raisons :
    1) eviter de transferer les blobs (step_input/output, sql_executed,
       config_snapshot) pour TOUS les steps a chaque hydratation viewer ;
    2) permettre une autorisation specifique : ici l'utilisateur voit
       SES propres donnees (ownership 404 suffit, pas besoin de
       ``require_role("admin")`` qui serait pour exposer a un tiers).

    Anti-oracle : 404 sur execution inconnue OU non-owned, ET sur
    step_exec inconnu. Les blobs peuvent contenir des donnees client
    (workbook tronque a 100 rows/tab par ``workbook_snapshot_for_db`` —
    cf. ``app/services/automation/workbook_service.py``).
    """

    @require_role("admin", "user")
    async def get(self, execution_id: str, step_exec_id: str) -> None:
        execution_id_int = self._parse_int_or_400(execution_id, "execution_id")
        step_exec_id_int = self._parse_int_or_400(step_exec_id, "step_exec_id")

        try:
            async with self.db_session() as session:
                # Defense en profondeur (CWE-639 IDOR) : on JOIN explicitement
                # StepExecution → Execution → Automation et on filtre sur
                # current_user.id en SQL. Une seule requete au lieu de 2 fetchs
                # separes (pas de TOCTOU), et impossible de toucher un
                # step_exec d'une autre execution OU d'une automation non-owned.
                stmt = (
                    select(StepExecution)
                    .join(Execution, StepExecution.execution_id == Execution.id)
                    .join(Automation, Execution.automation_id == Automation.id)
                    .where(
                        StepExecution.id == step_exec_id_int,
                        StepExecution.execution_id == execution_id_int,
                        Automation.user_id == self.current_user.id,
                    )
                )
                result = await session.execute(stmt)
                step_exec = result.scalars().first()
                if step_exec is None:
                    # Anti-oracle 404 : meme reponse pour exec inconnue,
                    # exec non-owned, step inconnu, step cross-execution.
                    raise tornado.web.HTTPError(404, "Etape non trouvee")

                detail = step_exec.to_dict(include_sensitive=True)
                # Sanitize stacktrace/credentials (CWE-209) + scrub data_access (mode invisible).
                if detail.get("error_message"):
                    detail["error_message"] = await _safe_error_for_user(
                        detail["error_message"], self.current_user
                    )

            self.write({"success": True, "step": detail})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error(
                "Erreur chargement step detail %s/%s",
                execution_id,
                step_exec_id,
                exc_info=True,
            )
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de chargement."})


# =============================================================================
# Phase 3b DAG — Canvas editor HTML pages
# =============================================================================


class AutomationEditHandler(AuthenticatedHandler):
    """Page d'edition d'une automation (canvas DAG).

    GET /automations/:id/edit — render le template edit.html.
    Ownership check 404 anti-oracle. Capture name/id AVANT sortie de session
    (MissingGreenlet async).
    """

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session, auto_id, self.current_user.id
                )
                # Capturer en session pour eviter MissingGreenlet
                name = automation.name
                auto_id_val = automation.id
        except tornado.web.HTTPError:
            raise

        self.render(
            "automations/edit.html",
            automation_id=auto_id_val,
            automation_name=name,
            page_title=f"Edition — {name}",
            # TZ-1 — nom de la TZ serveur DYNAMIQUE (SSoT clock.machine_tz_name,
            # honore l'override admin config.server.timezone). Remplace le
            # hardcode « Europe/Paris » qui était faux hors de Paris.
            server_timezone=clock.machine_tz_name(),
        )


class AutomationNewHandler(AuthenticatedHandler):
    """Cree une automation vide + redirige vers /automations/:id/edit.

    POST /automations/new (XSRF protege). La creation est un effet de bord,
    donc uniquement POST — un GET ici violerait la safety/idempotence HTTP
    (prefetch Chrome/Safari, crawlers, liens `<a href="/automations/new">`
    creeraient des automations a chaque visite). Le formulaire du listing
    (list.html) cible ce POST avec xsrf_form_html().

    Defenses contre le spam :
    * rate-limit glissant 10/min/utilisateur ;
    * plafond dur MAX_AUTOMATIONS_PER_USER (defense en profondeur) ;
    * nom unique par utilisateur via suffixe numerique automatique (sinon
      les brouillons deviennent indistinguables dans le listing).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        _check_rate_limit(
            _new_automation_limiter,
            self.current_user.id,
            *RATE_LIMIT_NEW_AUTOMATION,
        )
        try:
            auto_id_val = await self._create_automation()
        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur creation nouvelle automation", exc_info=True)
            # Route HTML : rediriger avec un flash plutot que du JSON brut.
            # Le user arrive via formulaire, il doit revoir une page.
            self.redirect("/automations?error=creation_failed")
            return

        logger.info(
            "Nouvelle automation creee id=%d par %s",
            auto_id_val,
            self.current_user.email,
        )
        self.redirect(f"/automations/{auto_id_val}/edit")

    async def _create_automation(self) -> int:
        """Cree une automation vide avec nom unique par utilisateur.

        Renvoie l'id. Leve HTTPError(429) si plafond atteint.
        """
        async with self.db_session() as session:
            count_stmt = (
                select(func.count())
                .select_from(Automation)
                .where(Automation.user_id == self.current_user.id)
            )
            current_count = (await session.execute(count_stmt)).scalar_one()
            if current_count >= MAX_AUTOMATIONS_PER_USER:
                raise tornado.web.HTTPError(
                    429,
                    f"Plafond atteint ({MAX_AUTOMATIONS_PER_USER} automatisations). "
                    "Supprimez-en avant d'en creer une nouvelle.",
                )

            name = await self._generate_unique_name(session)
            automation = Automation(
                user_id=self.current_user.id,
                name=name,
                description=None,
                query_type="nl",
                query_text="",
                schedule_type="daily",
                schedule_config=None,
                output_format="csv",
                recipients=None,
                is_active=False,
                notify_on_failure=True,
                notify_on_success=False,
            )
            session.add(automation)
            await session.flush()
            await _audit_automation_event(
                self,
                session,
                action=AuditAction.AUTOMATION_CREATE,
                entity_id=automation.id,
                details={"name": automation.name, "source": "new_handler"},
            )
            await session.commit()
            await session.refresh(automation)
            return automation.id

    async def _generate_unique_name(self, session: AsyncSession) -> str:
        """Renvoie `Nouvelle automatisation` si libre, sinon `(N)` incremental.

        Scope = user courant uniquement (pas besoin d'unicite globale).
        On charge seulement les noms qui matchent le prefixe, pas toute la
        table, pour rester borne meme avec beaucoup d'utilisateurs.
        """
        base = "Nouvelle automatisation"
        stmt = select(Automation.name).where(
            Automation.user_id == self.current_user.id,
            Automation.name.like(f"{base}%"),
        )
        existing = {row[0] for row in (await session.execute(stmt)).all()}
        if base not in existing:
            return base
        # Chercher le plus petit N libre. Plafonne a MAX_AUTOMATIONS_PER_USER
        # pour eviter une boucle infinie pathologique.
        for n in range(2, MAX_AUTOMATIONS_PER_USER + 2):
            candidate = f"{base} ({n})"
            if candidate not in existing:
                return candidate
        # Cas theorique : plafond plein. Le plafond au-dessus aurait deja
        # bloque, mais on tombe sur un nom horodate par defense.
        return f"{base} {clock.now().strftime('%Y-%m-%d %H%M%S')}"


# =============================================================================
# Phase 3a DAG — API d'hydratation du canvas frontend
# =============================================================================


class AutomationDAGAPIHandler(AuthenticatedHandler):
    """Hydratation du canvas : renvoie nodes + edges en un seul appel.

    GET /api/automations/:id/dag
    Structure : {
        "steps":     [...],  # chaque step.to_dict() — inclut layout_x/y
        "edges":     [...],  # chaque edge.to_dict() — inclut data_type
        "layout_auto": bool, # True si aucun layout persiste (le frontend
                             # doit generer une grille par defaut)
        "automation": {
            "id", "name", "is_active", "fail_policy",
            "max_llm_cost_eur", "max_total_rows", "max_duration_seconds",
        },
    }
    """

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        # Rate-limit lecture (evite DoS memoire par spam GET /dag).
        _check_rate_limit(
            _dag_read_limiter,
            f"{self.current_user.id}:dag:{auto_id}",
            *RATE_LIMIT_DAG_READ,
        )

        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session,
                    auto_id,
                    self.current_user.id,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )

                steps_sorted = sorted(automation.steps, key=lambda s: s.step_order)
                # Steps sans position : le frontend applique une grille par
                # defaut UNIQUEMENT sur ces ids (pas tout-ou-rien, ce qui
                # empilait les nodes a (0,0) sur un workflow partiellement
                # positionne).
                unpositioned_step_ids = [
                    s.id for s in steps_sorted if s.layout_x is None or s.layout_y is None
                ]

                response = {
                    "success": True,
                    "automation": {
                        "id": automation.id,
                        "name": automation.name,
                        "description": automation.description,
                        "is_active": automation.is_active,
                        "fail_policy": automation.fail_policy,
                        "max_llm_cost_eur": automation.max_llm_cost_eur,
                        "max_total_rows": automation.max_total_rows,
                        "max_duration_seconds": automation.max_duration_seconds,
                        # Cluster-N — version exposée à l'hydratation client
                        # (sans ça : 1er PUT envoie If-Match=1 par défaut →
                        # 409 immédiat si BDD est à v>1).
                        "version": int(automation.version or 1),
                    },
                    "steps": [s.to_dict() for s in steps_sorted],
                    "edges": [e.to_dict() for e in automation.edges],
                    # Phase 3a : liste des ids a positionner automatiquement.
                    # Le frontend applique la grille par defaut UNIQUEMENT
                    # sur ces nodes (pas un flag global tout-ou-rien qui
                    # empilait des nodes a (0,0) sur des workflows
                    # partiellement positionnes).
                    "unpositioned_step_ids": unpositioned_step_ids,
                }
            # Cluster-N — pose aussi ETag pour les clients HTTP standard.
            # A7-M6b (#61) — ``no-store`` OBLIGATOIRE avec l'ETag d'optimistic-lock
            # (parité avec le GET schedule) : sans ça, un cache/proxy pourrait
            # resservir un canvas périmé + son ETag → l'user éditerait une version
            # stale (données obsolètes) et le save partirait avec un If-Match
            # périmé. La donnée est LIVE user-spécifique : jamais cacheable.
            self.set_header("Cache-Control", "no-store, max-age=0")
            _set_etag_header(self, int(automation.version or 1))
            self.write(response)

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur hydratation DAG automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de chargement du DAG."})


# Bornes de position sur le canvas (pixels). Defensif : evite qu'un user
# malveillant ou un bug frontend ne persiste des coordonnees absurdes.
_LAYOUT_MIN_COORD = -10_000
_LAYOUT_MAX_COORD = 10_000
_LAYOUT_MAX_STEPS = 500  # plafond du nombre de positions par PUT

# Rate-limit specifique au layout : l'autosave peut appeler ce endpoint
# frequemment (drag-drop = nombreuses mises a jour). Quota tres permissif.
# Cle composite `user:{id}:layout:{auto_id}` → pas de collision entre tabs.
RATE_LIMIT_LAYOUT: tuple[int, int] = (120, 60)
_layout_limiter = RateLimiter()

# Rate-limit GET /dag — lecture frequente potentiellement lourde.
RATE_LIMIT_DAG_READ: tuple[int, int] = (60, 60)
_dag_read_limiter = RateLimiter()


def _parse_layout_positions(positions: Any) -> Dict[int, Tuple[int, int]]:
    """Parse defensif d'un dict {step_id: {x, y}} → {id_int: (x, y)}.

    Ignore silencieusement les entrees invalides (id non-numerique, x/y hors
    bornes, pos non-dict). Retourne un dict eventuellement vide. Fonction
    pure pour testabilite (cf. tests/unit/test_dag_api_hydration.py).

    Bornes : _LAYOUT_MIN_COORD .. _LAYOUT_MAX_COORD sur chaque coordonnee.
    """
    if not isinstance(positions, dict):
        return {}
    parsed: Dict[int, Tuple[int, int]] = {}
    for raw_id, raw_pos in positions.items():
        try:
            step_id_int = int(raw_id)
        except (ValueError, TypeError):
            continue
        if not isinstance(raw_pos, dict):
            continue
        try:
            x = int(raw_pos.get("x", 0))
            y = int(raw_pos.get("y", 0))
        except (ValueError, TypeError):
            continue
        if not (_LAYOUT_MIN_COORD <= x <= _LAYOUT_MAX_COORD):
            continue
        if not (_LAYOUT_MIN_COORD <= y <= _LAYOUT_MAX_COORD):
            continue
        parsed[step_id_int] = (x, y)
    return parsed


class AutomationLayoutAPIHandler(AuthenticatedHandler):
    """Persistance des positions des nodes sur le canvas.

    PUT /api/automations/:id/layout
    Body : {"positions": {"<step_id>": {"x": int, "y": int}, ...}}

    - Ownership check (404 anti-oracle).
    - Rate-limit permissif (autosave frequent).
    - Bornes defensives sur les coordonnees.
    - Un step_id inconnu dans le body = ignore silencieusement (pas d'erreur
      blocante — un frontend peut envoyer des positions obsoletes apres
      suppression d'un step).
    """

    @require_role("admin", "user")
    async def put(self, automation_id: str) -> None:
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        # Rate-limit par (user, automation) — evite la collision entre
        # deux tabs ouvertes sur deux workflows differents.
        _check_rate_limit(
            _layout_limiter,
            f"{self.current_user.id}:layout:{auto_id}",
            *RATE_LIMIT_LAYOUT,
        )

        body = self.get_json_body()
        if not isinstance(body, dict):
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        positions = body.get("positions")
        if not isinstance(positions, dict):
            self.set_status(400)
            self.write({"success": False, "error": "Champ 'positions' manquant ou invalide."})
            return
        if len(positions) > _LAYOUT_MAX_STEPS:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": f"Trop de positions (max {_LAYOUT_MAX_STEPS}).",
                }
            )
            return

        # Parser defensif AVANT la transaction DB (fonction pure testable).
        parsed_positions = _parse_layout_positions(positions)

        if not parsed_positions:
            self.write({"success": True, "updated": 0})
            return

        try:
            async with self.db_session() as session:
                automation = await _get_owned_automation_or_404(
                    session, auto_id, self.current_user.id
                )
                # Cluster-N 2026-05-26 — Layout (positions x/y canvas)
                # est cosmétique : autosave drag-drop = N updates/sec.
                # Volontairement PAS de bump de `automation.version` ici
                # pour éviter une cascade de 409 lors d'un déplacement
                # actif. Le serveur retourne la version courante pour
                # info, mais If-Match n'est pas vérifié non plus.
                current_version = int(getattr(automation, "version", 1) or 1)

                # Bulk UPDATE via executemany — 1 round-trip par step mais
                # dans une seule transaction. Mieux que 500 appels `session.add`
                # qui generent 500 UPDATE avec flush + commit final.
                from sqlalchemy import update as sa_update

                updated = 0
                for step_id_int, (x, y) in parsed_positions.items():
                    result = await session.execute(
                        sa_update(AutomationStep)
                        .where(
                            AutomationStep.id == step_id_int,
                            AutomationStep.automation_id == auto_id,
                        )
                        .values(layout_x=x, layout_y=y)
                    )
                    updated += result.rowcount or 0

                # Cluster-B-FOLLOWUP 2026-05-26 — Audit LAYOUT_UPDATE.
                # Pas d'audit si updated=0 (no-op autosave bénin). Details
                # minimaliste pour ne pas exploser audit_logs avec des
                # coordonnées x/y (autosave drag-drop = N updates/sec).
                if updated > 0:
                    await _audit_automation_event(
                        self,
                        session,
                        action=AuditAction.AUTOMATION_LAYOUT_UPDATE,
                        entity_id=auto_id,
                        details={"steps_moved": updated},
                    )
                await session.commit()

            _set_etag_header(self, current_version)
            self.write({"success": True, "updated": updated, "version": current_version})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur sauvegarde layout automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de la sauvegarde du layout."})


# =============================================================================
# Phase 1 DAG — API REST des aretes (edges) du graphe d'automatisation
# =============================================================================


class AutomationEdgesAPIHandler(AuthenticatedHandler):
    """CRUD des aretes du DAG d'une automatisation.

    GET  /api/automations/:id/edges        -> liste les aretes
    POST /api/automations/:id/edges        -> cree une arete (validation structurale)
    """

    @require_role("admin", "user")
    async def get(self, automation_id: str) -> None:
        """Liste les aretes de l'automatisation."""
        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                await _get_owned_automation_or_404(session, auto_id, self.current_user.id)

                result = await session.execute(
                    select(AutomationEdge)
                    .where(AutomationEdge.automation_id == auto_id)
                    .order_by(AutomationEdge.id)
                )
                edges = result.scalars().all()

                self.write(
                    {
                        "success": True,
                        "edges": [e.to_dict() for e in edges],
                    }
                )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur lecture aretes automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de lecture des aretes."})

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        """Cree une arete. Valide la structure DAG AVANT le commit."""
        from app.services.automation.dag_validator import (
            errors_to_json,
            validate_structural,
        )

        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        body = self.get_json_body()
        if not isinstance(body, dict) or not body:
            self.set_status(400)
            self.write({"success": False, "error": "Corps JSON requis."})
            return

        from_step_id = body.get("from_step_id")
        to_step_id = body.get("to_step_id")
        data_type = (body.get("data_type", "") or "").strip()

        if from_step_id is None or to_step_id is None:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": "from_step_id et to_step_id sont requis.",
                }
            )
            return

        try:
            from_step_id = int(from_step_id)
            to_step_id = int(to_step_id)
        except (ValueError, TypeError):
            self.set_status(400)
            self.write({"success": False, "error": "from_step_id / to_step_id invalides."})
            return

        if data_type not in EDGE_DATA_TYPES:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": f"data_type invalide. Valeurs: {list(EDGE_DATA_TYPES)}",
                }
            )
            return

        if from_step_id == to_step_id:
            self.set_status(400)
            self.write({"success": False, "error": "Self-loop interdit."})
            return

        metadata = body.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            self.set_status(400)
            self.write({"success": False, "error": "metadata doit etre un objet."})
            return

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id,
                    self.current_user.id,
                    _edges_write_limiter,
                    *RATE_LIMIT_EDGES_WRITE,
                )
                # EDGE-1 — fail-fast If-Match AVANT mutation (cohérent avec
                # PUT /steps). Sans ça, un autre onglet ayant modifié le DAG
                # entre-temps verrait sa connexion créée sur une version périmée
                # → désync silencieuse multi-onglets. Read-only : check tôt OK.
                if not _check_if_match_or_409(self, automation):
                    return

                # Verifier que les deux steps appartiennent bien a cette automation
                steps_result = await session.execute(
                    select(AutomationStep).where(
                        AutomationStep.automation_id == auto_id,
                        AutomationStep.id.in_([from_step_id, to_step_id]),
                    )
                )
                steps_in_auto = {s.id: s for s in steps_result.scalars().all()}
                if from_step_id not in steps_in_auto or to_step_id not in steps_in_auto:
                    self.set_status(404)
                    self.write(
                        {
                            "success": False,
                            "error": "Un des steps n'appartient pas a cette automatisation.",
                        }
                    )
                    return

                # Charger toutes les aretes actuelles pour la validation structurale
                existing_edges_result = await session.execute(
                    select(AutomationEdge).where(AutomationEdge.automation_id == auto_id)
                )
                existing_edges = list(existing_edges_result.scalars().all())

                # Charger tous les steps pour la validation
                all_steps_result = await session.execute(
                    select(AutomationStep).where(AutomationStep.automation_id == auto_id)
                )
                all_steps = list(all_steps_result.scalars().all())

                # Simuler l'ajout de la nouvelle arete pour la validation
                candidate_edge = {
                    "id": None,
                    "from_step_id": from_step_id,
                    "to_step_id": to_step_id,
                    "data_type": data_type,
                }
                all_edges_plus_candidate = [
                    {
                        "id": e.id,
                        "from_step_id": e.from_step_id,
                        "to_step_id": e.to_step_id,
                        "data_type": e.data_type,
                    }
                    for e in existing_edges
                ] + [candidate_edge]

                validation_errors = validate_structural(
                    nodes=[
                        {
                            "id": s.id,
                            "step_type": s.step_type,
                            "name": s.name,
                            "config": s.config or {},
                        }
                        for s in all_steps
                    ],
                    edges=all_edges_plus_candidate,
                )
                if validation_errors:
                    self.set_status(400)
                    self.write(
                        {
                            "success": False,
                            "error": "Validation DAG echouee",
                            "errors": errors_to_json(validation_errors),
                        }
                    )
                    return

                # Creation effective
                edge = AutomationEdge(
                    automation_id=auto_id,
                    from_step_id=from_step_id,
                    to_step_id=to_step_id,
                    data_type=data_type,
                    metadata_json=metadata,
                )
                session.add(edge)
                await session.flush()
                # Cluster-B-FOLLOWUP 2026-05-26 — Audit EDGE_CREATE.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.EDGE_CREATE,
                    entity_id=auto_id,
                    details={
                        "edge_id": edge.id,
                        "from_step_id": from_step_id,
                        "to_step_id": to_step_id,
                        "data_type": data_type,
                    },
                )
                # EDGE-1 — bump version (optimistic concurrency) en DERNIER acte
                # avant commit : pose l'ETag que le client ré-hydrate, et fait
                # 409 les prochaines mutations des autres onglets (qui n'ont pas
                # cette arête) → ils savent qu'ils doivent resynchroniser.
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return  # 409 émis (race CAS multi-instance)
                await session.commit()
                await session.refresh(edge)
                edge_dict = edge.to_dict()

            logger.info(
                "Arete DAG creee: %d -> %d (%s) pour automation %d",
                from_step_id,
                to_step_id,
                data_type,
                auto_id,
            )
            # ``version`` dans le JSON comme les autres mutations (PUT/DELETE
            # steps & edges) : POST /edges était la SEULE mutation dont le 200
            # ne portait la nouvelle version que via le header ETag — un proxy
            # qui réécrit l'ETag rendait le client stale (revue 2026-06-12).
            self.write({"success": True, "edge": edge_dict, "version": new_version})

        except tornado.web.HTTPError:
            raise
        except IntegrityError:
            # EDGE-2 — un edge dupliqué (même from_step_id/to_step_id) viole la
            # contrainte unique ``uq_automation_edge_from_to``. C'est une erreur
            # MÉTIER prévisible (la connexion existe déjà), pas une panne serveur :
            # on répond 409 Conflict actionnable au lieu d'un 500 opaque. Couvre
            # aussi la course multi-onglets (deux ajouts concurrents du même edge,
            # le 2ᵉ flush lève IntegrityError après le pré-check structural).
            logger.info(
                "Arete DAG dupliquee refusee (%s -> %s) pour automation %s",
                from_step_id,
                to_step_id,
                automation_id,
            )
            self.set_status(409)
            self.write({"success": False, "error": "Cette connexion existe déjà."})
        except SQLAlchemyError:
            logger.error("Erreur creation arete automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de la creation de l'arete."})


class AutomationEdgeDetailAPIHandler(AuthenticatedHandler):
    """Modification + suppression d'une arete.

    PUT    /api/automations/:id/edges/:edge_id  -> change data_type
    DELETE /api/automations/:id/edges/:edge_id  -> supprime l'arete
    """

    @require_role("admin", "user")
    async def put(self, automation_id: str, edge_id: str) -> None:
        """Change le ``data_type`` d'une arete existante.

        Body : ``{"data_type": "workbook" | "report_file" | "trigger"}``

        Use case : permettre a l'utilisateur de basculer une edge entre
        « data » (transmission du workbook/file) et « trigger » (juste
        sequencement, sans transmission). Pratique pour les step ``email``
        ou ``email_wait_response`` ou l'user ne veut pas joindre les
        donnees mais veut qu'une autre etape declenche l'envoi.

        Revalide la coherence du DAG (signatures + fan-in) avant commit ;
        rollback si invalide.
        """
        from app.models.automation_edge import EDGE_DATA_TYPES
        from app.services.automation.dag_validator import validate_structural

        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        edge_id_int = self._parse_int_or_400(edge_id, "edge_id")

        try:
            payload = json.loads(self.request.body or b"{}")
        except json.JSONDecodeError:
            self.set_status(400)
            self.write({"success": False, "error": "JSON invalide."})
            return
        new_type = (payload or {}).get("data_type")
        if not isinstance(new_type, str) or new_type not in EDGE_DATA_TYPES:
            self.set_status(400)
            self.write(
                {
                    "success": False,
                    "error": f"data_type doit etre un de {list(EDGE_DATA_TYPES)}",
                }
            )
            return

        try:
            async with self.db_session() as session:
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id,
                    self.current_user.id,
                    _edges_write_limiter,
                    *RATE_LIMIT_EDGES_WRITE,
                )
                # Cluster-N 2026-05-26 — Step 1/2 : fail-fast If-Match
                # AVANT toute lecture/mutation. Le bump arrive après
                # validate_structural (peut rollback → pas d'ETag fantôme).
                if not _check_if_match_or_409(self, automation):
                    return

                edge_result = await session.execute(
                    select(AutomationEdge).where(
                        AutomationEdge.id == edge_id_int,
                        AutomationEdge.automation_id == auto_id,
                    )
                )
                edge = edge_result.scalars().first()
                if edge is None:
                    self.set_status(404)
                    self.write({"success": False, "error": "Arete introuvable."})
                    return

                if edge.data_type == new_type:
                    # No-op explicite — pas de write inutile, retour cohérent.
                    # Cluster-N — sur no-op, on ne bump PAS (rien à
                    # protéger : la BDD est identique avant/après).
                    # ETag courant pour info client.
                    # A7-M6b (#61) — no-store cohérent avec les autres réponses
                    # porteuses d'ETag d'optimistic-lock (défense-in-depth :
                    # un ETag d'optimistic-lock ne doit jamais être resservi
                    # périmé depuis un cache intermédiaire).
                    self.set_header("Cache-Control", "no-store, max-age=0")
                    _set_etag_header(self, int(automation.version or 1))
                    self.write(
                        {
                            "success": True,
                            "edge": edge.to_dict(),
                            "version": int(automation.version or 1),
                        }
                    )
                    return

                old_type = edge.data_type
                edge.data_type = new_type

                # Revalider tout le DAG : la nouvelle data_type peut casser
                # la coherence (mismatch source.outputs / target.inputs ou
                # fan-in mixed). On revalide AVANT commit pour pouvoir
                # rollback via la session pending.
                steps_q = await session.execute(
                    select(AutomationStep).where(AutomationStep.automation_id == auto_id)
                )
                steps_list = list(steps_q.scalars().all())
                edges_q = await session.execute(
                    select(AutomationEdge).where(AutomationEdge.automation_id == auto_id)
                )
                edges_list = list(edges_q.scalars().all())
                errors = validate_structural(steps_list, edges_list)
                if errors:
                    # Rollback in-memory + reponse 409
                    edge.data_type = old_type
                    await session.rollback()
                    self.set_status(409)
                    self.write(
                        {
                            "success": False,
                            "error": "La modification casse la coherence du DAG.",
                            "validation_errors": [
                                {"code": e.code, "message": e.message, "context": e.context}
                                for e in errors
                            ],
                        }
                    )
                    return

                # Cluster-N — Step 2/2 : bump APRÈS validate_structural
                # (peut rollback en cas d'erreur DAG — pas d'ETag fantôme).
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return

                # Cluster-B-FOLLOWUP 2026-05-26 — Audit EDGE_UPDATE.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.EDGE_UPDATE,
                    entity_id=auto_id,
                    details={
                        "edge_id": edge_id_int,
                        "old_data_type": old_type,
                        "new_data_type": new_type,
                    },
                )
                await session.commit()
                await session.refresh(edge)

            logger.info(
                "Arete %d (auto %d) data_type %s -> %s",
                edge_id_int,
                auto_id,
                old_type,
                new_type,
            )
            # Cluster-N — expose parent version pour MAJ état canvas client.
            self.write({"success": True, "edge": edge.to_dict(), "version": int(new_version)})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur PUT arete %s", edge_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur serveur."})

    @require_role("admin", "user")
    async def delete(self, automation_id: str, edge_id: str) -> None:
        auto_id = self._parse_int_or_400(automation_id, "automation_id")
        edge_id_int = self._parse_int_or_400(edge_id, "edge_id")

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id,
                    self.current_user.id,
                    _edges_write_limiter,
                    *RATE_LIMIT_EDGES_WRITE,
                )
                # Cluster-N — DELETE edge = mutation DAG ; check If-Match
                # (cf. asymétrie CRITICAL adversarial).
                if not _check_if_match_or_409(self, automation):
                    return

                result = await session.execute(
                    select(AutomationEdge).where(
                        AutomationEdge.id == edge_id_int,
                        AutomationEdge.automation_id == auto_id,
                    )
                )
                edge = result.scalars().first()
                if edge is None:
                    self.set_status(404)
                    self.write({"success": False, "error": "Arete introuvable."})
                    return

                edge_from_audit = edge.from_step_id
                edge_to_audit = edge.to_step_id
                await session.delete(edge)
                # Cluster-N — bump LAST avant commit.
                new_version = await _bump_version_and_set_etag(self, session, automation)
                if new_version is None:
                    return

                # Cluster-B-FOLLOWUP 2026-05-26 — Audit EDGE_DELETE.
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.EDGE_DELETE,
                    entity_id=auto_id,
                    details={
                        "edge_id": edge_id_int,
                        "from_step_id": edge_from_audit,
                        "to_step_id": edge_to_audit,
                    },
                )
                await session.commit()

            logger.info("Arete DAG supprimee: %d (automation %d)", edge_id_int, auto_id)
            self.write({"success": True, "version": int(new_version)})

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur suppression arete %s", edge_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de la suppression."})


class AutomationValidateAPIHandler(AuthenticatedHandler):
    """Validation non-mutante du DAG (structure + completude).

    POST /api/automations/:id/validate

    Reponse :
    - 200 toujours (on ne mute rien, l'invalide est une info, pas une erreur).
    - ``{"success": true, "valid": bool, "errors": [...]}`` ou chaque
      erreur contient ``code``, ``message``, et eventuellement ``context``.

    Utilise dans Phase 3b-2 par le bouton "Valider" du canvas editor.
    Permet a l'utilisateur de verifier la sante de son DAG avant
    d'activer (POST /toggle). La validation structurelle est deja faite
    a chaque mutation ; la validation de completude ne l'est qu'a
    l'activation — cet endpoint l'expose en lecture seule.
    """

    @require_role("admin", "user")
    async def post(self, automation_id: str) -> None:
        # Import tardif pour eviter un cycle de dependances.
        from app.services.automation.dag_validator import (
            validate_completeness,
            validate_structural,
        )

        auto_id = self._parse_int_or_400(automation_id, "automation_id")

        try:
            async with self.db_session() as session:
                # S4 — Ownership 404 d'abord, rate-limit apres (helper combo).
                # Validate est O(V+E) (DFS cycle + signatures) → sans rate-limit
                # un client peut spammer et pomper CPU + BDD. Mais l'oracle 429
                # vs 404 doit etre evite : ownership en premier.
                automation = await _get_owned_then_rate_limit(
                    session,
                    auto_id,
                    self.current_user.id,
                    _edges_write_limiter,
                    *RATE_LIMIT_EDGES_WRITE,
                    options=[
                        selectinload(Automation.steps),
                        selectinload(Automation.edges),
                    ],
                )
                # BUG-D cycle 23 : avant, on ne passait que {id, step_type}.
                # Le validator voyait alors `cfg = {}` pour tous les nodes
                # → faux positifs STEP_CONFIG_INCOMPLETE / EMAIL_NO_RECIPIENT
                # même quand toutes les configs étaient remplies. L'utilisateur
                # ne pouvait JAMAIS valider ses autos.
                # Real-review #6 : `is_enabled` aussi pour skip les disabled.
                nodes = [
                    {
                        "id": s.id,
                        "step_type": (
                            s.step_type.value if hasattr(s.step_type, "value") else s.step_type
                        ),
                        "name": s.name,
                        "config": s.config or {},
                        "is_enabled": s.is_enabled,
                    }
                    for s in automation.steps
                ]
                edges_list = [
                    {
                        "id": e.id,
                        "from_step_id": e.from_step_id,
                        "to_step_id": e.to_step_id,
                        "data_type": e.data_type,
                    }
                    for e in automation.edges
                ]

            structural_errors = list(validate_structural(nodes, edges_list))
            # Pas de completude si la structure est cassee (messages
            # trompeurs) — aligne sur validate_all(for_activation=True).
            if structural_errors:
                completeness_errors: list = []
            else:
                completeness_errors = list(validate_completeness(nodes, edges_list))

            serialized = [
                {
                    "code": err.code,
                    "message": err.message,
                    "context": err.context or {},
                    "kind": "structural",
                }
                for err in structural_errors
            ] + [
                {
                    "code": err.code,
                    "message": err.message,
                    "context": err.context or {},
                    "kind": "completeness",
                }
                for err in completeness_errors
            ]
            self.write(
                {
                    "success": True,
                    "valid": len(serialized) == 0,
                    "errors": serialized,
                }
            )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur validation automation %s", automation_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur de validation."})


# =============================================================================
# Phase 2b DAG — Replay d'une execution + Export logs CSV
# =============================================================================


class ExecutionReplayHandler(AuthenticatedHandler):
    """Re-execute une automation avec le trigger_payload d'origine (RE-RUN).

    ⚠️ B6 — Semantique clarifiee : ceci est un **RE-RUN**, PAS un
    "replay reproductible". Le workflow est ré-éxécuté **à neuf** :
    SQL Server est requeté en live (les donnees ont peut-etre change),
    le LLM est rappele (la sortie peut differer), les SavedQuery sont
    relues (drift possible si edited entre temps). Seul le
    ``trigger_payload`` (webhook body, etc.) est preserve.

    Pour un **replay vraiment reproductible** (lecture des snapshots
    ``StepExecution.config_snapshot`` / ``sql_executed`` / ``step_input``),
    il faudrait un mode ``replay_from_snapshot`` qui n'est pas implemente
    (cf. backlog B6 / design_automations_dag.md §9). Le champ
    ``trigger_source="replay"`` du model Execution accepte cette valeur
    par avance, mais le handler actuel ne fait que re-run.

    POST /api/executions/:id/replay
    - 404 si execution inconnue ou non-autorisee (anti-oracle)
    - Rate-limit applique APRES le 404 ownership : sinon un attaquant
      observe que sa propre instance est rate-limitee differement de la
      reponse 404 d'une execution non-existante (oracle de rate-limit).
    - Limiter dedie ``_replay_limiter`` (5/min/user) plus restrictif que
      l'execution manuelle car le bouton est a un clic et l'utilisateur
      peut spammer accidentellement.
    - Le trigger_source devient "replay", triggered_by_user_id = current user

    Response inclut ``warning: "rerun"`` pour que le frontend puisse
    afficher un message clair "Re-execution avec donnees actuelles, pas
    reproduction du run d'origine".
    """

    @require_role("admin", "user")
    async def post(self, execution_id: str) -> None:
        ex_id = self._parse_int_or_400(execution_id, "execution_id")

        try:
            async with self.db_session() as session:
                # Charger l'execution source avec ownership check via join automation
                result = await session.execute(
                    select(Execution)
                    .where(Execution.id == ex_id)
                    .options(joinedload(Execution.automation))
                )
                source_exec = result.scalars().first()
                if source_exec is None or source_exec.automation is None:
                    raise tornado.web.HTTPError(404, "Execution non trouvee")
                if source_exec.automation.user_id != self.current_user.id:
                    # Anti-oracle : meme message que not-found
                    raise tornado.web.HTTPError(404, "Execution non trouvee")

                # Capturer les valeurs necessaires AVANT sortie de session
                # (MissingGreenlet sinon sur un lazy-load hors session).
                automation_id = source_exec.automation_id
                saved_payload = source_exec.trigger_payload
                source_trigger_source = source_exec.trigger_source
                auto_name = source_exec.automation.name

                # Rate-limit APRES ownership check : evite l'oracle 429 vs 404.
                # Post-adversarial 2026-05-26 — DOIT être AVANT le commit audit,
                # sinon 429 spam crée des audit rows non-désirées.
                _check_rate_limit(_replay_limiter, self.current_user.id, *RATE_LIMIT_REPLAY)

                # Cluster-B 2026-05-26 — audit intent replay (run lui-même
                # tracé via Execution model).
                await _audit_automation_event(
                    self,
                    session,
                    action=AuditAction.AUTOMATION_REPLAY,
                    entity_id=automation_id,
                    details={
                        "source_execution_id": ex_id,
                        "source_trigger_source": source_trigger_source,
                        "name": auto_name,
                    },
                )
                await session.commit()

            # Relance hors-session (execute_automation gere sa propre session)
            result = await execute_automation(
                automation_id,
                manual=True,
                trigger_data=saved_payload,
                trigger_source="replay",
                triggered_by_user_id=self.current_user.id,
            )

            if result.get("success"):
                logger.info(
                    "Replay execution %d (src trigger=%s) pour automation '%s'",
                    ex_id,
                    source_trigger_source,
                    auto_name,
                    extra={
                        "source_execution_id": ex_id,
                        "new_execution_id": result.get("execution_id"),
                    },
                )
                self.write(
                    {
                        "success": True,
                        "execution_id": result.get("execution_id"),
                        "source_execution_id": ex_id,
                        "message": "Re-execution lancee avec succes",
                        # B6 — flag explicit : le client doit afficher "Re-execute
                        # avec donnees actuelles" (pas "Reproduit l'ancien run").
                        "warning": "rerun",
                        "warning_message": (
                            "Re-execution avec les donnees actuelles. "
                            "Le SQL est requete en live et le LLM est rappele. "
                            "Pour reproduire exactement l'ancien run, un mode "
                            "replay_from_snapshot serait necessaire (non implemente)."
                        ),
                    }
                )
            else:
                self.write({"success": False, "error": result.get("error", "Erreur inconnue")})

        except tornado.web.HTTPError:
            raise
        except (SQLAlchemyError, OSError, ValueError) as e:
            logger.error("Erreur replay execution %s: %s", ex_id, e, exc_info=True)
            self.set_status(500)
            self.write(
                {
                    "success": False,
                    "error": "Erreur lors du replay de l'execution.",
                }
            )


class ExecutionLogsCSVHandler(AuthenticatedHandler):
    """Telecharge les step executions d'un run en CSV.

    GET /api/executions/:id/logs.csv
    - Ownership check 404 anti-oracle
    - Ne contient PAS les champs sensibles (sql_executed, step_input/output,
      config_snapshot). UI admin separee si besoin.
    - Stream CSV avec en-tetes UTF-8 BOM pour Excel.
    """

    @require_role("admin", "user")
    async def get(self, execution_id: str) -> None:
        from app.services.export.csv_export import to_csv_bytes

        ex_id = self._parse_int_or_400(execution_id, "execution_id")

        try:
            async with self.db_session() as session:
                # Verifier ownership + charger les step executions
                exec_result = await session.execute(
                    select(Execution)
                    .where(Execution.id == ex_id)
                    .options(
                        joinedload(Execution.automation),
                        selectinload(Execution.step_executions),
                    )
                )
                execution = exec_result.scalars().unique().first()
                if execution is None or execution.automation is None:
                    raise tornado.web.HTTPError(404, "Execution non trouvee")
                if execution.automation.user_id != self.current_user.id:
                    raise tornado.web.HTTPError(404, "Execution non trouvee")

                # Capture en session avant sortie (MissingGreenlet)
                auto_name = execution.automation.name
                trace_id = None
                rows_data = []
                for se in sorted(execution.step_executions, key=lambda s: s.step_order or 0):
                    if se.trace_id:
                        trace_id = se.trace_id
                    # Cluster-C 2026-05-26 — scrub data_access mode invisible
                    # AVANT le replace newlines (CSV safety). Avant ce fix,
                    # l'export CSV hors-ligne contenait les noms de tables
                    # denied en clair (bypass mode invisible via téléchargement,
                    # plus dangereux qu'une fuite UI car persistant sur disque).
                    scrubbed_err = await _safe_error_for_user(
                        se.error_message, self.current_user, max_length=500
                    )
                    rows_data.append(
                        {
                            "step_order": se.step_order,
                            "step_name": se.step_name,
                            "step_type": se.step_type,
                            "status": se.status,
                            "attempt_number": se.attempt_number,
                            # Export CSV (fichier hors-ligne, AUCUNE couche JS
                            # pour reconvertir) → heure SERVEUR (doctrine
                            # « exports → heure serveur »), pas l'ISO UTC brut
                            # (l'utilisateur ouvre dans Excel et verrait l'UTC).
                            "started_at": (
                                clock.format_local_fr(se.started_at, with_time=True)
                                if se.started_at
                                else ""
                            ),
                            "finished_at": (
                                clock.format_local_fr(se.finished_at, with_time=True)
                                if se.finished_at
                                else ""
                            ),
                            "duration_ms": se.duration_ms or 0,
                            "rows_in": se.rows_in or 0,
                            "rows_out": se.rows_out or 0,
                            "warnings_count": len(se.warnings or []),
                            "error_message": (scrubbed_err or "").replace("\n", " "),
                            "llm_tokens_in": se.llm_tokens_in or 0,
                            "llm_tokens_out": se.llm_tokens_out or 0,
                            "llm_cost_eur": se.llm_cost_eur or 0.0,
                        }
                    )

            # D\u00e9l\u00e8gue au service unifi\u00e9 ``csv_export.to_csv_bytes`` :
            # bytes UTF-8 BOM (Excel friendly) + sanitisation
            # OWASP-CSV-Injection (CWE-1236) sur headers ET valeurs.
            csv_bytes = to_csv_bytes(
                rows_data,
                columns=[
                    "step_order",
                    "step_name",
                    "step_type",
                    "status",
                    "attempt_number",
                    "started_at",
                    "finished_at",
                    "duration_ms",
                    "rows_in",
                    "rows_out",
                    "warnings_count",
                    "error_message",
                    "llm_tokens_in",
                    "llm_tokens_out",
                    "llm_cost_eur",
                ],
            )

            safe_name = _sanitize_filename(auto_name)
            from app.services.branding import get_company_name

            safe_company = _sanitize_filename(get_company_name())
            filename = f"{safe_company}_execution_{ex_id}_{safe_name}.csv"
            # Protection CRLF injection
            filename = assert_no_crlf(filename, "filename")

            self.set_header("Content-Type", "text/csv; charset=utf-8")
            self.set_header("Content-Disposition", f'attachment; filename="{filename}"')
            if trace_id:
                self.set_header("X-Trace-Id", trace_id)
            self.write(csv_bytes)

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur export logs execution %s", execution_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de l'export."})


# =============================================================================
# Phase 3d — Galerie de templates d'automatisation (filesystem-based)
# =============================================================================

# Rate-limit instanciation : chaque clone cree une Automation + ses steps +
# edges. Sans borne, un user pourrait spammer la BDD via l'endpoint public.
RATE_LIMIT_TEMPLATE_INSTANTIATE: tuple[int, int] = (10, 60)
_template_instantiate_limiter = RateLimiter()


class AutomationTemplatesListHandler(AuthenticatedHandler):
    """Liste les templates d'automatisation disponibles.

    GET /api/automation-templates

    Lecture only — aucun side-effect serveur. Pas de rate-limit dedie : la
    galerie est consultee a la demande, charge BDD nulle (filesystem +
    cache mtime), pas une cible DoS interessante.
    """

    @require_role("admin", "user")
    async def get(self) -> None:
        from app.services.automation.template_library import get_template_library

        library = get_template_library()
        templates = library.list_templates()
        self.write({"success": True, "templates": templates, "total": len(templates)})


class AutomationTemplateDetailHandler(AuthenticatedHandler):
    """Detail d'un template (preview avant instanciation).

    GET /api/automation-templates/:template_id

    Renvoie le payload complet (template_meta + automation + steps + edges)
    avec `automation.query_text` masque pour eviter de leaker des requetes
    SQL exemples qui pourraient evoluer en signatures de patterns metier.
    L'utilisateur voit le SQL apres instanciation (c'est sa propre copie).
    """

    @require_role("admin", "user")
    async def get(self, template_id: str) -> None:
        from app.services.automation.template_library import (
            TemplateInvalidError,
            TemplateNotFoundError,
            get_template_library,
        )

        library = get_template_library()
        try:
            payload = library.load_template(template_id)
        except TemplateNotFoundError:
            # Anti-oracle 404 — meme reponse pour absent vs invalide.
            raise tornado.web.HTTPError(404, "Template introuvable")
        except TemplateInvalidError as e:
            logger.error("Template %s invalide : %s", template_id, e)
            raise tornado.web.HTTPError(404, "Template introuvable")

        # Preview en clair : on retourne tout sauf le SQL des extracts qui
        # est masque (il sera lisible dans la copie utilisateur apres
        # instanciation). Cette politique est calque sur le pattern templates
        # de rapport (templates.py:_safe_template_view).
        sanitized_steps = []
        for step in payload.get("steps", []):
            step_copy = dict(step)
            cfg = step_copy.get("config", {})
            if isinstance(cfg, dict) and step_copy.get("step_type") == "extract_sql":
                cfg_copy = dict(cfg)
                if "sql" in cfg_copy:
                    cfg_copy["sql"] = "/* requete masquee — visible apres instanciation */"
                step_copy["config"] = cfg_copy
            sanitized_steps.append(step_copy)

        self.write(
            {
                "success": True,
                "template_meta": payload.get("template_meta", {}),
                "automation": {
                    "name": payload.get("automation", {}).get("name", ""),
                    "description": payload.get("automation", {}).get("description", ""),
                    "schedule_type": payload.get("automation", {}).get("schedule_type", "daily"),
                    "output_format": payload.get("automation", {}).get("output_format", "csv"),
                    # query_type expose pour aider l'utilisateur a juger,
                    # mais query_text masque ci-dessus dans les steps.
                    "query_type": payload.get("automation", {}).get("query_type", "nl"),
                },
                "steps": sanitized_steps,
                "edges": payload.get("edges", []),
            }
        )


class AutomationTemplateInstantiateHandler(AuthenticatedHandler):
    """Instancie un template — cree une nouvelle automation pour le user.

    POST /api/automation-templates/:template_id/instantiate

    Reutilise la logique de validation/creation de
    ``AutomationImportHandler`` pour beneficier des memes garanties (DAG
    valide, types reconnus, plafonds). Le ``user_id`` est force au current
    user — pas de moyen pour un attaquant de creer des automations chez
    un autre utilisateur via cet endpoint.

    Anti-spam : rate-limit dedie 10/min/user + plafond global
    ``MAX_AUTOMATIONS_PER_USER`` (defense-in-depth) verifie avant insertion.
    """

    @require_role("admin", "user")
    async def post(self, template_id: str) -> None:
        from app.services.automation.dag_validator import (
            errors_to_json,
            validate_structural,
        )
        from app.services.automation.template_library import (
            TemplateInvalidError,
            TemplateNotFoundError,
            get_template_library,
        )

        _check_rate_limit(
            _template_instantiate_limiter,
            self.current_user.id,
            *RATE_LIMIT_TEMPLATE_INSTANTIATE,
        )

        library = get_template_library()
        try:
            payload = library.load_template(template_id)
        except (TemplateNotFoundError, TemplateInvalidError) as e:
            logger.warning("Instanciation template echouee : %s", e)
            raise tornado.web.HTTPError(404, "Template introuvable")

        # On reutilise la validation de l'import handler : meme format JSON
        # (komptia_export v2). Phase 3d : extraite en fonction module-level
        # pour eliminer le hack `__new__` historique. Pas de duplication.
        try:
            auto_fields, validated_steps, validated_edges = validate_automation_payload(payload)
        except ValueError as e:
            logger.error("Template %s invalide a l'instanciation : %s", template_id, e)
            self.set_status(500)
            self.write({"success": False, "error": "Template invalide cote serveur"})
            return

        # Politique securite/UX : un template ne pre-remplit JAMAIS de
        # destinataires. L'utilisateur doit explicitement saisir les emails
        # dans son clone (evite qu'un seed avec des recipients de demo
        # envoie a des inconnus si l'utilisateur active sans editer).
        auto_fields["recipients"] = []
        # Idem pour les notifications — le destinataire admin doit etre
        # configure intentionnellement.
        auto_fields["notification_emails"] = []
        # `_validate_import` suffixe le nom avec " (Import)". Pour un
        # template instancie, on prefere preserver le nom du template
        # ou bien le suffixer "(modele)" — l'utilisateur le renommera
        # de toute facon dans le canvas editor.
        original_name = auto_fields["name"]
        if original_name.endswith(" (Import)"):
            auto_fields["name"] = original_name[: -len(" (Import)")]
        # Idem cleanup config steps : retirer les emails dans les
        # configs `email.recipients` qui pourraient venir des seeds.
        for step_cfg in validated_steps:
            cfg = step_cfg.get("config")
            if isinstance(cfg, dict) and step_cfg.get("step_type") == "email":
                cfg["recipients"] = []

        try:
            async with self.db_session() as session:
                # Plafond hard par user — defense-in-depth contre
                # un compte compromis qui contournerait le rate-limit.
                count_result = await session.execute(
                    select(func.count())
                    .select_from(Automation)
                    .where(Automation.user_id == self.current_user.id)
                )
                if count_result.scalar_one() >= MAX_AUTOMATIONS_PER_USER:
                    raise tornado.web.HTTPError(
                        429,
                        f"Plafond atteint ({MAX_AUTOMATIONS_PER_USER} automatisations).",
                    )

                automation = Automation(
                    user_id=self.current_user.id,
                    is_active=False,
                    **auto_fields,
                )
                session.add(automation)
                await session.flush()

                name_to_step_id: Dict[str, int] = {}
                for sc in validated_steps:
                    step = AutomationStep(
                        automation_id=automation.id,
                        name=sc["name"],
                        step_type=sc["step_type"],
                        step_order=sc["step_order"],
                        config=sc["config"],
                        is_enabled=sc["is_enabled"],
                        max_retries=sc["max_retries"],
                        retry_delay_seconds=sc["retry_delay_seconds"],
                        layout_x=sc.get("layout_x"),
                        layout_y=sc.get("layout_y"),
                        input_policy=sc.get("input_policy"),
                    )
                    session.add(step)
                    await session.flush()
                    name_to_step_id[sc["name"]] = step.id

                edges_to_create: list[AutomationEdge] = []
                edges_for_validation: list[dict] = []
                for ec in validated_edges:
                    frm_id = name_to_step_id.get(ec["from_step_name"])
                    to_id = name_to_step_id.get(ec["to_step_name"])
                    if frm_id is None or to_id is None:
                        continue
                    edges_to_create.append(
                        AutomationEdge(
                            automation_id=automation.id,
                            from_step_id=frm_id,
                            to_step_id=to_id,
                            data_type=ec["data_type"],
                            metadata_json=ec.get("metadata") or None,
                        )
                    )
                    edges_for_validation.append(
                        {
                            "id": None,
                            "from_step_id": frm_id,
                            "to_step_id": to_id,
                            "data_type": ec["data_type"],
                        }
                    )

                # Re-validation DAG : un template versionne pourrait
                # contenir un cycle si quelqu'un edite mal le JSON.
                # On bloque AVANT commit pour ne pas creer un workflow
                # inexecutable.
                dag_errors = validate_structural(
                    nodes=[
                        {
                            "id": name_to_step_id[s["name"]],
                            "step_type": s["step_type"],
                        }
                        for s in validated_steps
                    ],
                    edges=edges_for_validation,
                )
                if dag_errors:
                    await session.rollback()
                    logger.error(
                        "Template %s : DAG invalide a l'instanciation: %s",
                        template_id,
                        dag_errors,
                    )
                    self.set_status(500)
                    self.write(
                        {
                            "success": False,
                            "error": "Template DAG invalide cote serveur",
                            "errors": errors_to_json(dag_errors),
                        }
                    )
                    return

                for edge in edges_to_create:
                    session.add(edge)
                await session.commit()
                auto_id = automation.id
                step_count = len(validated_steps)
                edge_count = len(edges_to_create)

            logger.info(
                "Template %s instancie pour user %s → automation id=%d (%d etapes)",
                template_id,
                self.current_user.email,
                auto_id,
                step_count,
            )
            self.write(
                {
                    "success": True,
                    "id": auto_id,
                    "automation_id": auto_id,
                    "step_count": step_count,
                    "edge_count": edge_count,
                    "redirect_url": f"/automations/{auto_id}/edit",
                }
            )

        except tornado.web.HTTPError:
            raise
        except SQLAlchemyError:
            logger.error("Erreur instanciation template %s", template_id, exc_info=True)
            self.set_status(500)
            self.write({"success": False, "error": "Erreur lors de l'instanciation."})


class AutomationTemplatesPageHandler(AuthenticatedHandler):
    """Page HTML galerie de templates : /automations/templates"""

    @require_role("admin", "user")
    async def get(self) -> None:
        self.render(
            "automations/templates_gallery.html",
            page_title="Galerie de templates",
        )
