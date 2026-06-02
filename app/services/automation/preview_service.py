"""Service de preview d'étapes pour `/automations/N/edit`.

Permet à l'utilisateur de cliquer "▶ Preview" sur un noeud du DAG pour
voir ce qu'il produit pendant qu'il configure son automatisation. Le
preview est *non-mutant* : email = dry-run, report/export = fichier
tmp avec TTL court (pas de persistance `Execution`).

Garanties
---------

* **Single source of truth** : les helpers d'exécution (`_execute_query`,
  `_generate_nl_sql`, `_generate_llm_report`, `_generate_workbook_export`,
  `_load_workbook_from_datastore`) sont ceux de `AutomationExecutor`.
  On dispatche par `step_type` mais on n'écrit pas une nouvelle logique
  d'extraction/génération.
* **Cascade parents** : si un noeud a des parents, le service les
  exécute d'abord (séquentiel pour MVP). Les outputs des parents sont
  cachés en mémoire (TTL 15 min, LRU 50/user) avec invalidation par
  hash de config — un changement de config invalide tout le sous-graphe.
* **Confidentialité** : aucune persistance disque pour les workbooks
  (les fichiers tmp report/export sont des artefacts demandés par
  l'utilisateur, qui les ouvre puis ils expirent). Le cache mémoire
  n'est jamais sérialisé.
* **format_copilot** : appelle `format_workbook_for_automation`
  (anonymisation déjà gérée par le bridge).
* **email** : DRY-RUN — résolution destinataires + tickets sans
  appel SMTPClient.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core import clock
from app.constants import (
    MAX_STEP_PREVIEW_ROWS,
    STEP_PREVIEW_CACHE_MAX_PER_USER,
    STEP_PREVIEW_CACHE_TTL_SECONDS,
    STEP_PREVIEW_OUTPUT_TOKEN_TTL_SECONDS,
    STEP_PREVIEW_TMP_TTL_SECONDS,
)

# Plafond du nombre de steps cascadés par clic ▶. Au-delà, on demande à
# l'utilisateur d'exécuter le workflow réel (pour ne pas tenir Sage 25 min
# avec 50 SQL en cascade pour un seul clic, cf. finding M3 de la review).
MAX_PREVIEW_CASCADE_STEPS: int = 10

# Plafond global de previews simultanés tous-users (defense Sage côté
# pyodbc qui ne peut pas annuler une query en cours — un user qui ferme
# sa WS laisse la query tourner). Cohérent avec ``_SAGE_MAX_CONCURRENT=5``
# du sage_connector : on alloue un peu moins pour ne pas saturer la
# pool quand le run réel d'une autre automation tourne en parallèle.
# 2026-05-27 (Task #41) : ENV-configurable car lié à la capacité machine
# (pool Sage / RAM). Default 3 = valeur historique.
# Override via ``KOMPTIA_PREVIEW_MAX_GLOBAL_CONCURRENT`` (instance-spécifique).
import os as _os_for_env  # noqa: E402

try:
    MAX_GLOBAL_CONCURRENT_PREVIEWS: int = int(
        _os_for_env.environ.get("KOMPTIA_PREVIEW_MAX_GLOBAL_CONCURRENT", "3")
    )
    if MAX_GLOBAL_CONCURRENT_PREVIEWS < 1:
        MAX_GLOBAL_CONCURRENT_PREVIEWS = 3
except (TypeError, ValueError):
    MAX_GLOBAL_CONCURRENT_PREVIEWS = 3

# A7-M16 — Cap de previews CONCURRENTS PAR USER (isolation cross-user, axe 18).
# Le cap global protège Sage mais ne garantit PAS la fairness : un seul user
# ouvrant N aperçus monopolisait tous les slots globaux. On borne par user
# (< cap global, sinon l'isolation ne sert à rien). Configurable par instance.
try:
    MAX_PREVIEWS_PER_USER: int = int(_os_for_env.environ.get("KOMPTIA_PREVIEW_MAX_PER_USER", "2"))
    if MAX_PREVIEWS_PER_USER < 1:
        MAX_PREVIEWS_PER_USER = 2
except (TypeError, ValueError):
    MAX_PREVIEWS_PER_USER = 2
if MAX_PREVIEWS_PER_USER >= MAX_GLOBAL_CONCURRENT_PREVIEWS:
    MAX_PREVIEWS_PER_USER = max(1, MAX_GLOBAL_CONCURRENT_PREVIEWS - 1)

# #10 (2026-05-28) — Budget de scan pour ``cleanup_expired_preview_files`` :
# ``root.rglob("*")`` visite TOUT l'arbre tmp à chaque run (*/30min). rglob est
# lazy (pas un OOM mémoire), mais sur un tmpfs pathologique (millions d'inodes
# legacy/burst) un run scannerait tout en O(n) syscalls et bloquerait le worker.
# On borne le nombre d'entrées examinées par run (axe 21 : travail borné). Le
# backlog se résorbe sur plusieurs runs (TTL court → convergence). Override via
# ``KOMPTIA_PREVIEW_CLEANUP_MAX_SCAN``. Défaut 100k = très large (un arbre
# normal Komptia est intégralement scanné ; ne borne que le cas extrême).
try:
    PREVIEW_CLEANUP_MAX_SCAN_PER_RUN: int = int(
        _os_for_env.environ.get("KOMPTIA_PREVIEW_CLEANUP_MAX_SCAN", "100000")
    )
    if PREVIEW_CLEANUP_MAX_SCAN_PER_RUN < 1:
        PREVIEW_CLEANUP_MAX_SCAN_PER_RUN = 100000
except (TypeError, ValueError):
    PREVIEW_CLEANUP_MAX_SCAN_PER_RUN = 100000
from app.core.database import get_session_factory
from app.models.automation import Automation
from app.models.automation_edge import AutomationEdge
from app.models.automation_step import AutomationStep
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Erreurs typées (mappées en catégories côté WS handler) ────────────


class PreviewError(Exception):
    """Erreur de preview avec catégorie pour mapping client."""

    category: str = "internal"

    def __init__(self, message: str, *, category: Optional[str] = None) -> None:
        super().__init__(message)
        if category is not None:
            self.category = category


class PreviewValidationError(PreviewError):
    category = "validation"


class PreviewSageError(PreviewError):
    category = "sage_unavailable"


class PreviewLLMError(PreviewError):
    category = "llm_error"


class PreviewAnonPendingError(PreviewError):
    category = "anon_pending_review"


class PreviewTimeoutError(PreviewError):
    category = "timeout"


class PreviewNotFoundError(PreviewError):
    category = "not_found"


# ── Types ────────────────────────────────────────────────────────────


@dataclass
class StepPreviewResult:
    """Résultat d'un preview d'étape, sérialisable pour le client WS."""

    step_id: int
    step_type: str
    workbook: Optional[Dict[str, Any]]
    rows_in: int
    rows_out: int
    duration_ms: float
    truncated: bool
    from_cache: bool
    extras: Dict[str, Any] = field(default_factory=dict)
    output_file_token: Optional[str] = None
    output_filename: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_type": self.step_type,
            "workbook": self.workbook,
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "duration_ms": round(self.duration_ms, 1),
            "truncated": self.truncated,
            "from_cache": self.from_cache,
            "extras": self.extras,
            "output_file_token": self.output_file_token,
            "output_filename": self.output_filename,
        }


@dataclass
class _CachedOutput:
    """Entrée du cache mémoire des outputs de step preview.

    Couvre TOUS les types de step (sources, format, sinks). Pour les sinks
    file-based (report, export_workbook), ``output_path`` pointe sur le tmp
    file généré et ``output_filename`` permet de régénérer un token HMAC
    frais au cache hit (l'ancien token a un TTL court). Pour les sinks
    dry-run (email, save_to_datastore), ``extras`` reproduit le payload
    « ce qui serait envoyé/sauvegardé ».
    """

    workbook: Optional[Dict[str, Any]]
    rows_out: int
    config_hash: str
    parent_inputs_hash: str
    cached_at: float
    extras: Dict[str, Any] = field(default_factory=dict)
    output_path: Optional[str] = None  # Path absolu du tmp file (sinks file-based)
    output_filename: Optional[str] = None  # Filename pour token regen
    truncated: bool = False


# ── Cache mémoire LRU des outputs de parents ─────────────────────────


class StepPreviewCache:
    """Cache LRU thread-safe des outputs de parents pour cascade.

    Clé : (user_id, automation_id, step_id). Chaque entrée stocke le
    hash de config + le hash des inputs parents au moment du calcul ;
    si l'un des deux change → cache miss et re-run. Le TTL court
    couvre les variations BDD source qui ne sont pas dans le hash.

    Borné à `STEP_PREVIEW_CACHE_MAX_PER_USER` entrées par utilisateur
    (LRU eviction) — empêche un user qui édite 200 noeuds de garder
    50 Mo de workbooks par user en RAM.
    """

    def __init__(
        self,
        *,
        max_per_user: int = STEP_PREVIEW_CACHE_MAX_PER_USER,
        ttl_seconds: int = STEP_PREVIEW_CACHE_TTL_SECONDS,
    ) -> None:
        self._max_per_user = max_per_user
        self._ttl_seconds = ttl_seconds
        # user_id → OrderedDict[(automation_id, step_id) → _CachedOutput]
        self._by_user: Dict[int, "OrderedDict[Tuple[int, int], _CachedOutput]"] = {}
        self._lock = asyncio.Lock()

    async def get(
        self,
        *,
        user_id: int,
        automation_id: int,
        step_id: int,
        config_hash: str,
        parent_inputs_hash: str,
    ) -> Optional[_CachedOutput]:
        async with self._lock:
            user_cache = self._by_user.get(user_id)
            if user_cache is None:
                return None
            entry = user_cache.get((automation_id, step_id))
            if entry is None:
                return None
            now = time.monotonic()
            if now - entry.cached_at > self._ttl_seconds:
                user_cache.pop((automation_id, step_id), None)
                return None
            if entry.config_hash != config_hash:
                user_cache.pop((automation_id, step_id), None)
                return None
            if entry.parent_inputs_hash != parent_inputs_hash:
                user_cache.pop((automation_id, step_id), None)
                return None
            user_cache.move_to_end((automation_id, step_id))
            return entry

    async def put(
        self,
        *,
        user_id: int,
        automation_id: int,
        step_id: int,
        workbook: Optional[Dict[str, Any]],
        rows_out: int,
        config_hash: str,
        parent_inputs_hash: str,
        extras: Optional[Dict[str, Any]] = None,
        output_path: Optional[str] = None,
        output_filename: Optional[str] = None,
        truncated: bool = False,
    ) -> None:
        async with self._lock:
            user_cache = self._by_user.setdefault(user_id, OrderedDict())
            user_cache[(automation_id, step_id)] = _CachedOutput(
                workbook=workbook,
                rows_out=rows_out,
                config_hash=config_hash,
                parent_inputs_hash=parent_inputs_hash,
                cached_at=time.monotonic(),
                extras=dict(extras or {}),
                output_path=output_path,
                output_filename=output_filename,
                truncated=truncated,
            )
            user_cache.move_to_end((automation_id, step_id))
            while len(user_cache) > self._max_per_user:
                user_cache.popitem(last=False)

    async def invalidate_step(self, *, user_id: int, automation_id: int, step_id: int) -> None:
        async with self._lock:
            user_cache = self._by_user.get(user_id)
            if user_cache is not None:
                user_cache.pop((automation_id, step_id), None)

    async def invalidate_automation(self, *, user_id: int, automation_id: int) -> None:
        async with self._lock:
            user_cache = self._by_user.get(user_id)
            if user_cache is None:
                return
            keys = [k for k in user_cache if k[0] == automation_id]
            for k in keys:
                user_cache.pop(k, None)


_cache_singleton: Optional[StepPreviewCache] = None


def get_preview_cache() -> StepPreviewCache:
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = StepPreviewCache()
    return _cache_singleton


# Sémaphore global tous-users pour borner la charge concurrente sur Sage
# (cf. ``MAX_GLOBAL_CONCURRENT_PREVIEWS``). Initialisé lazy-au premier
# usage parce que le module se charge avant que l'event-loop soit prêt.
_global_preview_semaphore: Optional[asyncio.Semaphore] = None

# A7-M16 — Compteur de previews ACTIFS par user (fairness cross-user). Borné :
# la clé est retirée dès que le compteur retombe à 0 → ne contient que les users
# AYANT un preview en cours (pas de croissance non bornée). Mono-thread asyncio :
# le check-and-increment est atomique (aucun await entre get et set).
_user_preview_counts: Dict[int, int] = {}


def _get_global_semaphore() -> asyncio.Semaphore:
    global _global_preview_semaphore
    if _global_preview_semaphore is None:
        _global_preview_semaphore = asyncio.Semaphore(MAX_GLOBAL_CONCURRENT_PREVIEWS)
    return _global_preview_semaphore


# ── Stockage tmp + tokens HMAC pour fichiers preview ─────────────────


# Secret de fallback initialisé AU CHARGEMENT du module (pas en lazy-init
# qui aurait une race condition au boot Tornado). Si ``SECRET_KEY`` est
# défini en env, ce fallback n'est jamais utilisé. Si on tombe dessus,
# tous les tokens en cours sont invalidés au prochain reboot — c'est
# le prix à payer pour l'absence de config.
_EPHEMERAL_SECRET: bytes = secrets.token_bytes(32)


def _preview_hmac_secret() -> bytes:
    """Secret HMAC dérivé de l'env. Évite de réutiliser SECRET_KEY brut.

    Stratégie : on dérive depuis ``SECRET_KEY`` (env, ou ``app.config``
    qui le charge depuis ``.env``) avec un préfixe distinct du reste des
    usages crypto pour éviter les collisions. Fallback ``_EPHEMERAL_SECRET``
    initialisé au load du module (pas de race condition).
    """
    raw = os.environ.get("SECRET_KEY") or ""
    if not raw:
        return _EPHEMERAL_SECRET
    return hashlib.sha256(("step-preview:" + raw).encode("utf-8")).digest()


def _preview_tmp_root() -> Path:
    """Racine des fichiers tmp preview. Créée si absente."""
    root = Path(tempfile.gettempdir()) / "komptia-step-preview"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _preview_tmp_path(user_id: int, automation_id: int, step_id: int) -> Path:
    return _preview_tmp_root() / f"u{user_id}" / f"a{automation_id}" / f"s{step_id}"


def issue_output_token(*, user_id: int, automation_id: int, step_id: int, filename: str) -> str:
    """Émet un token HMAC time-limited pour servir le fichier tmp.

    Format : ``v1.<exp_unix>.<sig_hex>`` où sig = HMAC-SHA256 sur
    ``f"{user_id}:{automation_id}:{step_id}:{filename}:{exp_unix}"``.
    Pas de chiffrement (pas de secret côté client) — juste signature.
    """
    exp = int(clock.timestamp()) + STEP_PREVIEW_OUTPUT_TOKEN_TTL_SECONDS
    payload = f"{user_id}:{automation_id}:{step_id}:{filename}:{exp}".encode("utf-8")
    sig = hmac.new(_preview_hmac_secret(), payload, hashlib.sha256).hexdigest()
    return f"v1.{exp}.{sig}"


def verify_output_token(
    token: str,
    *,
    user_id: int,
    automation_id: int,
    step_id: int,
    filename: str,
) -> bool:
    """Vérifie un token HMAC. Retourne ``False`` à la moindre anomalie.

    Bornes de l'exp pour éviter (a) les tokens forgés avec un exp énorme
    (utilisable indéfiniment si la signature fuite) et (b) le DoS du
    parser ``int()`` sur un nombre de 1000 chiffres.
    """
    if not isinstance(token, str) or not token.startswith("v1."):
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    # Cap longueur du segment exp avant int() pour éviter le DoS
    if len(parts[1]) > 12:  # ts unix tient sur ≤10 chiffres pendant 200 ans
        return False
    try:
        exp = int(parts[1])
    except ValueError:
        return False
    now = int(clock.timestamp())
    # +60s de marge pour tolérer une dérive d'horloge raisonnable.
    if exp < now or exp > now + STEP_PREVIEW_OUTPUT_TOKEN_TTL_SECONDS + 60:
        return False
    payload = f"{user_id}:{automation_id}:{step_id}:{filename}:{exp}".encode("utf-8")
    expected = hmac.new(_preview_hmac_secret(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts[2])


def cleanup_expired_preview_files() -> int:
    """Supprime les fichiers tmp plus vieux que ``STEP_PREVIEW_TMP_TTL_SECONDS``.

    Renvoie le nombre de fichiers supprimés. Wiré via
    ``scheduler.py`` cron ``minute="*/30"`` (cf. ``system_cleanup_step_preview_tmp``).

    Cluster-G (G2) 2026-05-26 — Après ``unlink``, on tente aussi de
    ``rmdir`` les répertoires parents devenus vides (arbo
    ``u<user_id>/a<auto_id>/s<step_id>/`` → 3 niveaux). Sans ça, après
    plusieurs mois d'usage tmpfs accumule des dizaines de milliers
    d'inodes vides (axe 21 du contrat : ``pas de croissance non bornée``).
    Les rmdir sont best-effort (catch OSError pour les races et les
    dirs non-vides).
    """
    root = _preview_tmp_root()
    if not root.exists():
        return 0
    now = clock.timestamp()
    cutoff = now - STEP_PREVIEW_TMP_TTL_SECONDS
    deleted = 0
    # Collecte les parents à tenter de rmdir après suppression
    candidate_dirs: set[Path] = set()
    # #10 (2026-05-28) — borne le scan par run (axe 21). rglob est lazy donc
    # pas un OOM, mais sur un arbre pathologique un run bloquerait le worker.
    # On examine au plus PREVIEW_CLEANUP_MAX_SCAN_PER_RUN entrées ; le reste
    # est traité aux runs suivants (TTL court → convergence en quelques cycles).
    examined = 0
    scan_capped = False
    for p in root.rglob("*"):
        examined += 1
        if examined > PREVIEW_CLEANUP_MAX_SCAN_PER_RUN:
            scan_capped = True
            break
        if not p.is_file():
            continue
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                deleted += 1
                # Marquer les ancêtres jusqu'à root (exclu) pour rmdir tentative
                parent = p.parent
                while parent != root and parent.is_relative_to(root):
                    candidate_dirs.add(parent)
                    parent = parent.parent
        except OSError:
            logger.warning("preview cleanup: échec sur %s", p, exc_info=True)

    # Cluster-G (G2) 2026-05-26 — rmdir les empty dirs (les plus
    # profondes d'abord pour permettre la cascade vers les parents).
    rmdir_count = 0
    for d in sorted(candidate_dirs, key=lambda p: len(p.parts), reverse=True):
        try:
            d.rmdir()  # OSError si non-vide ; on ignore (best-effort).
            rmdir_count += 1
        except OSError:
            pass
    if rmdir_count:
        logger.info("preview cleanup: %d dirs vides supprimés", rmdir_count)
    if scan_capped:
        logger.warning(
            "preview cleanup: budget de scan atteint (%d entrées) — arbre tmp "
            "volumineux, le reste sera traité au prochain run. Augmenter "
            "KOMPTIA_PREVIEW_CLEANUP_MAX_SCAN si récurrent.",
            PREVIEW_CLEANUP_MAX_SCAN_PER_RUN,
        )
    return deleted


# ── Hashing config + inputs (pour invalidation cache) ────────────────


def _config_hash(step: AutomationStep) -> str:
    """Hash stable du contenu fonctionnel du step (config + flags)."""
    payload = {
        "step_type": step.step_type,
        "config": step.config or {},
        "is_enabled": bool(step.is_enabled),
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _workbook_input_hash(workbook: Optional[Dict[str, Any]]) -> str:
    """Hash stable d'un workbook pour clé de cache du noeud aval."""
    if workbook is None:
        return "none"
    from app.services.automation.workbook_service import workbook_stable_hash

    return workbook_stable_hash(workbook)


# ── Service principal ────────────────────────────────────────────────


ProgressCallback = Callable[[int, str, str], Awaitable[None]]
"""Signature : ``(step_id, phase, message) -> awaitable``."""


async def _noop_progress(step_id: int, phase: str, message: str) -> None:
    return None


class StepPreviewService:
    """Orchestrateur des previews d'étapes (cascade + cache + adapters)."""

    def __init__(self, *, cache: Optional[StepPreviewCache] = None) -> None:
        self._cache = cache or get_preview_cache()

    async def preview_step(
        self,
        *,
        user_id: int,
        automation_id: int,
        step_id: int,
        max_rows: Optional[int] = None,
        on_progress: ProgressCallback = _noop_progress,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> StepPreviewResult:
        """Exécute le preview d'un step (et cascade ses parents au besoin).

        Args:
            user_id: Propriétaire (vérifié contre ``automation.user_id``).
            automation_id: Automation cible.
            step_id: Step à preview.
            max_rows: Plafond lignes mode preview (défaut
                ``MAX_STEP_PREVIEW_ROWS``).
            on_progress: Callback async appelé à chaque phase pour pousser
                des événements WS au client.
            cancel_event: Event positionné par le client (close WS,
                "cancel" message). Vérifié entre les phases.

        Raises:
            PreviewNotFoundError: automation absente ou non-ownée.
            PreviewValidationError: config invalide / step absent.
            PreviewSageError: BDD source indisponible.
            PreviewLLMError: LLM en erreur (rate-limit, 5xx).
            PreviewAnonPendingError: termes non confirmés (format_copilot).
            PreviewTimeoutError: timeout step.
        """
        max_rows_eff = max_rows or MAX_STEP_PREVIEW_ROWS

        # A7-M15 — Kill-switch global admin. Le preview déclenche de VRAIES
        # requêtes Sage + des appels LLM (format_copilot) : il DOIT être couvert
        # par ``FLAG_AUTOMATIONS_DISABLED`` au même titre que les runs réels
        # (UI / scheduler / webhook, cf. executor + WebhookInboundHandler).
        # Sinon, couper toutes les automations laisse une porte ouverte sur les
        # ressources (Sage/LLM) via le bouton « Aperçu ». Vérifié AVANT toute
        # acquisition de sémaphore / query.
        from app.core.database import get_session_factory
        from app.models.feature_flag import FLAG_AUTOMATIONS_DISABLED
        from app.services.automation.feature_flag_service import is_truthy

        async with get_session_factory()() as _flag_sess:
            if await is_truthy(_flag_sess, FLAG_AUTOMATIONS_DISABLED, default=False):
                raise PreviewError(
                    "Aperçu indisponible : les automatisations sont temporairement "
                    "désactivées par l'administrateur.",
                    category="kill_switch",
                )

        # A7-M16 — Cap PAR USER avant le sémaphore global. Le cap global protège
        # Sage (slots partagés), mais un seul user ouvrant trop d'aperçus
        # monopolisait tous les slots → les autres users attendaient jusqu'au
        # timeout query (STEP_TIMEOUT_SQL_EXEC). On refuse IMMÉDIATEMENT les
        # aperçus excédentaires d'un même user AVANT qu'il n'occupe un slot
        # partagé (fairness).
        # Adversarial R2 — fail-closed : ``user_id`` est requis (le seul caller,
        # le WS handler authentifié, le fournit toujours). Un appelant interne
        # sans user_id contournerait le cap → on refuse explicitement.
        if user_id is None:
            raise PreviewError("Aperçu indisponible : utilisateur requis.", category="validation")
        # ⚠️ Check-and-increment ATOMIQUE (mono-thread asyncio) : NE JAMAIS
        # insérer d'``await`` entre le get et le set ci-dessous, sinon 2
        # coroutines du même user passent le check ensemble et dépassent le cap.
        _active = _user_preview_counts.get(user_id, 0)
        if _active >= MAX_PREVIEWS_PER_USER:
            raise PreviewError(
                f"Vous avez déjà {_active} aperçu(s) en cours. Attendez "
                "qu'ils se terminent avant d'en lancer un autre.",
                category="rate_limited",
            )
        _user_preview_counts[user_id] = _active + 1
        try:
            # Sémaphore global : borne la charge concurrente sur Sage. Acquis
            # AVANT toute query SQL, libéré après tout le pipeline (cascade
            # incluse). Si saturé, on attend (l'event de progression rassure
            # l'utilisateur). Pas de timeout d'acquisition pour ne pas casser
            # l'UX en cas de pic temporaire.
            async with _get_global_semaphore():
                res = await self._preview_step_inner(
                    user_id=user_id,
                    automation_id=automation_id,
                    step_id=step_id,
                    max_rows_eff=max_rows_eff,
                    on_progress=on_progress,
                    cancel_event=cancel_event,
                )
        finally:
            # Décrément + retrait de la clé à 0 (borne le dict). Dans le finally
            # → décrémente sur TOUT chemin (succès, PreviewError, Sage down,
            # timeout, CancelledError sur close WS) — pas de leak du compteur.
            _left = _user_preview_counts.get(user_id, 1) - 1
            if _left <= 0:
                _user_preview_counts.pop(user_id, None)
            else:
                _user_preview_counts[user_id] = _left

        # === HOOK task #8 POINT 3 : scan PII du preview output ===
        # Background task non-bloquant — ne ralentit pas le retour au client.
        # Les rows du preview workbook alimentent anonymization_terms avec
        # auto-catégorisation PII (commit 00ab3c8 #11). Note : les previews
        # sont éphémères en /tmp ; les termes ajoutés ici seront purgés
        # 2026-05-19 — Retrait du hook scan PII des previews automation.
        # Cohérence avec la décision sur ``agent_tools.execute_sql`` : le
        # scan d'anonymisation tire UNIQUEMENT depuis les cellules
        # VISIBLES affichées à l'user dans un iris-grid (trigger frontend
        # via ``GridTabManager.addTab``). Quand l'user ouvre la preview
        # automation dans l'UI, iris-grid charge les tabs et tire le scan
        # — pas besoin de le déclencher ici en backend.

        return res

    async def _preview_step_inner(
        self,
        *,
        user_id: int,
        automation_id: int,
        step_id: int,
        max_rows_eff: int,
        on_progress: ProgressCallback,
        cancel_event: Optional[asyncio.Event],
    ) -> StepPreviewResult:
        session_factory = get_session_factory()
        async with session_factory() as session:
            automation = await self._load_automation(session, automation_id, user_id)
            target_step = self._find_step(automation, step_id)
            self._validate_partial_complete(target_step)

            # Construction du chemin de cascade : parents directs récursivement.
            chain = self._build_cascade_chain(automation, target_step)
            if len(chain) > MAX_PREVIEW_CASCADE_STEPS:
                raise PreviewValidationError(
                    f"Trop d'étapes en cascade pour un aperçu "
                    f"({len(chain)} > {MAX_PREVIEW_CASCADE_STEPS}). "
                    "Exécutez le workflow réel pour voir le résultat final."
                )

            # Charge l'objet User pour appliquer RLS sur les queries SQL
            # (cf. finding C4). On le charge UNE fois pour toute la cascade.
            from app.services.automation.executor import get_executor

            runtime_user = await get_executor()._load_runtime_user(user_id)

            # Exécute chaque step dans l'ordre topologique. Les outputs sont
            # accumulés pour fan-in du noeud final.
            results_by_step: Dict[int, StepPreviewResult] = {}
            outputs_by_step: Dict[int, Optional[Dict[str, Any]]] = {}

            for step in chain:
                if cancel_event is not None and cancel_event.is_set():
                    raise PreviewError("Preview annulé.", category="cancelled")

                # Inputs du step depuis ses parents directs (déjà calculés).
                input_workbook = self._compute_input(automation, step, outputs_by_step)
                config_h = _config_hash(step)
                input_h = _workbook_input_hash(input_workbook)

                cached = await self._cache.get(
                    user_id=user_id,
                    automation_id=automation_id,
                    step_id=step.id,
                    config_hash=config_h,
                    parent_inputs_hash=input_h,
                )
                if cached is not None:
                    # Pour les sinks file-based (report/export_workbook) :
                    # vérifier que le tmp file existe encore (nettoyage cron
                    # 30min + TTL 1h peuvent l'avoir supprimé entre temps).
                    # Si fichier absent → cache invalide, force re-exec.
                    cached_file_ok = True
                    if cached.output_path:
                        from pathlib import Path as _P

                        if not _P(cached.output_path).exists():
                            cached_file_ok = False
                            await self._cache.invalidate_step(
                                user_id=user_id,
                                automation_id=automation_id,
                                step_id=step.id,
                            )
                    if cached_file_ok:
                        # Régénérer un token HMAC frais (l'ancien a expiré
                        # ou est sur le point de l'être — TTL court).
                        cached_token: Optional[str] = None
                        if cached.output_filename:
                            cached_token = issue_output_token(
                                user_id=user_id,
                                automation_id=automation_id,
                                step_id=step.id,
                                filename=cached.output_filename,
                            )
                        res = StepPreviewResult(
                            step_id=step.id,
                            step_type=step.step_type,
                            workbook=cached.workbook,
                            rows_in=_workbook_total_rows(input_workbook),
                            rows_out=cached.rows_out,
                            duration_ms=0.0,
                            truncated=cached.truncated,
                            from_cache=True,
                            extras=dict(cached.extras),
                            output_file_token=cached_token,
                            output_filename=cached.output_filename,
                        )
                        results_by_step[step.id] = res
                        outputs_by_step[step.id] = cached.workbook
                        await on_progress(
                            step.id, "cache_hit", f"Étape « {step.name} » (depuis le cache)"
                        )
                        continue

                await on_progress(step.id, "starting", f"Étape « {step.name} »…")
                started = time.monotonic()
                try:
                    output_wb, extras, output_path, output_filename = await self._execute_step(
                        session=session,
                        automation=automation,
                        step=step,
                        input_workbook=input_workbook,
                        max_rows=max_rows_eff,
                        on_progress=on_progress,
                        runtime_user=runtime_user,
                    )
                except PreviewError:
                    raise
                except asyncio.TimeoutError as exc:
                    raise PreviewTimeoutError(
                        f"Étape « {step.name} » : délai dépassé. Réduisez la portée ou réessayez."
                    ) from exc
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "preview_step crash sur step %s (type=%s)",
                        step.id,
                        step.step_type,
                        exc_info=True,
                    )
                    raise PreviewError(
                        f"Étape « {step.name} » : erreur inattendue. Voir les logs serveur."
                    ) from exc

                duration_ms = (time.monotonic() - started) * 1000.0
                rows_in = _workbook_total_rows(input_workbook)
                rows_out = _workbook_total_rows(output_wb)

                output_token: Optional[str] = None
                if output_path is not None and output_filename is not None:
                    output_token = issue_output_token(
                        user_id=user_id,
                        automation_id=automation_id,
                        step_id=step.id,
                        filename=output_filename,
                    )

                res = StepPreviewResult(
                    step_id=step.id,
                    step_type=step.step_type,
                    workbook=output_wb,
                    rows_in=rows_in,
                    rows_out=rows_out,
                    duration_ms=duration_ms,
                    truncated=bool(extras.get("truncated")),
                    from_cache=False,
                    extras=extras,
                    output_file_token=output_token,
                    output_filename=output_filename,
                )
                results_by_step[step.id] = res
                outputs_by_step[step.id] = output_wb

                # Cache TOUS les types (sources, format, sinks). Idempotent
                # pour la cascade : 2e preview du même step (config + inputs
                # identiques) → cache hit, 0 re-exec, 0 appel LLM/SMTP/SQL.
                # Sinks file-based : on stocke output_path pour vérifier la
                # présence du tmp file au cache hit (cleanup peut l'avoir
                # supprimé). Sinks dry-run : extras stocké pour reproduire
                # le payload « ce qui serait envoyé/sauvegardé ».
                #
                # Safety preview (re-vérifié dans le code) :
                # - email preview = DRY-RUN, jamais d'envoi SMTP
                # - save_to_datastore preview = DRY-RUN, jamais d'écriture
                # - report/export = écriture tmp, pas d'effet de bord persistant
                # → cacher ces sinks ne crée aucun risque d'action externe
                # silencieuse.
                await self._cache.put(
                    user_id=user_id,
                    automation_id=automation_id,
                    step_id=step.id,
                    workbook=output_wb,
                    rows_out=rows_out,
                    config_hash=config_h,
                    parent_inputs_hash=input_h,
                    extras=extras,
                    output_path=str(output_path) if output_path else None,
                    output_filename=output_filename,
                    truncated=bool(extras.get("truncated")),
                )

                await on_progress(step.id, "step_done", f"Étape « {step.name} » terminée.")

            return results_by_step[target_step.id]

    # ── Loading + chaîne de cascade ──────────────────────────────────

    async def _load_automation(
        self, session: AsyncSession, automation_id: int, user_id: int
    ) -> Automation:
        """Charge l'automation avec ses steps + edges, ownership 404."""
        automation = await session.get(
            Automation,
            automation_id,
            options=[
                selectinload(Automation.steps),
                selectinload(Automation.edges),
            ],
        )
        if automation is None or automation.user_id != user_id:
            raise PreviewNotFoundError("Automatisation non trouvée.")
        return automation

    def _find_step(self, automation: Automation, step_id: int) -> AutomationStep:
        for s in automation.steps or []:
            if s.id == step_id:
                return s
        raise PreviewNotFoundError("Étape non trouvée.")

    def _validate_partial_complete(self, step: AutomationStep) -> None:
        """Refuse de preview une config incomplète (preview != run, mais
        un step sans config minimale ne peut produire qu'une erreur
        cryptique de l'helper sous-jacent).

        On catch ``ValueError`` uniquement (contrat documenté de
        ``AutomationStep.validate``). Les autres exceptions (bugs ORM,
        attribut disparu post-migration) remontent et sont traitées par
        le caller comme erreur ``internal`` — pas masquées en
        "Configuration incomplète" qui tromperait l'utilisateur.
        """
        try:
            step.validate(partial=False)
        except ValueError as exc:
            raise PreviewValidationError(f"Configuration incomplète : {exc}") from exc

    def _build_cascade_chain(
        self, automation: Automation, target: AutomationStep
    ) -> List[AutomationStep]:
        """Liste topologique des steps à exécuter pour preview ``target``.

        Inclut tous les ancêtres + ``target``. Détecte les cycles
        (défense en profondeur — le validator DAG les bloque déjà).
        """
        edges: List[AutomationEdge] = list(automation.edges or [])
        steps_by_id: Dict[int, AutomationStep] = {s.id: s for s in (automation.steps or [])}

        # BFS inverse : ancestors de target
        parents_of: Dict[int, List[int]] = {sid: [] for sid in steps_by_id}
        children_of: Dict[int, List[int]] = {sid: [] for sid in steps_by_id}
        for e in edges:
            if e.from_step_id in parents_of and e.to_step_id in parents_of:
                parents_of[e.to_step_id].append(e.from_step_id)
                children_of[e.from_step_id].append(e.to_step_id)

        # Collecte ancêtres
        in_chain: set[int] = set()
        stack: List[int] = [target.id]
        while stack:
            sid = stack.pop()
            if sid in in_chain:
                continue
            in_chain.add(sid)
            for p in parents_of.get(sid, []):
                stack.append(p)

        # Tri topologique via Kahn restreint à in_chain
        indegree: Dict[int, int] = {
            sid: sum(1 for p in parents_of.get(sid, []) if p in in_chain) for sid in in_chain
        }
        order: List[int] = []
        queue: List[int] = [sid for sid, d in indegree.items() if d == 0]
        while queue:
            sid = queue.pop(0)
            order.append(sid)
            for c in children_of.get(sid, []):
                if c not in in_chain:
                    continue
                indegree[c] -= 1
                if indegree[c] == 0:
                    queue.append(c)

        if len(order) != len(in_chain):
            raise PreviewValidationError(
                "Cycle détecté dans le DAG. Corrigez-le avant de prévisualiser."
            )

        return [steps_by_id[sid] for sid in order]

    def _compute_input(
        self,
        automation: Automation,
        step: AutomationStep,
        outputs_by_step: Dict[int, Optional[Dict[str, Any]]],
    ) -> Optional[Dict[str, Any]]:
        """Reconstruit l'input du step à partir des sorties parents (fan-in)."""
        from app.services.automation.workbook_service import merge_workbooks

        edges = list(automation.edges or [])
        parent_ids = [e.from_step_id for e in edges if e.to_step_id == step.id]
        if not parent_ids:
            return None
        parent_outputs = [
            outputs_by_step[pid] for pid in parent_ids if outputs_by_step.get(pid) is not None
        ]
        if not parent_outputs:
            return None
        if len(parent_outputs) == 1:
            return parent_outputs[0]
        return merge_workbooks(parent_outputs)

    # ── Dispatch step_type → helpers AutomationExecutor (mode preview) ───

    async def _execute_step(
        self,
        *,
        session: AsyncSession,
        automation: Automation,
        step: AutomationStep,
        input_workbook: Optional[Dict[str, Any]],
        max_rows: int,
        on_progress: ProgressCallback,
        runtime_user: Optional[Any] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], Optional[Path], Optional[str]]:
        """Renvoie ``(output_workbook, extras, output_tmp_path, output_filename)``.

        ``output_tmp_path`` est non-None pour les sinks ``report`` et
        ``export_workbook`` (fichier servi via token HMAC).
        """
        from app.services.automation.executor import get_executor
        from app.services.automation.workbook_service import rows_to_workbook

        executor = get_executor()
        cfg = dict(step.config or {})
        st = step.step_type
        extras: Dict[str, Any] = {"warnings": []}

        # ── Sources ───────────────────────────────────────────────
        if st == "extract_sql":
            sql = (cfg.get("sql") or "").strip()
            if not sql:
                raise PreviewValidationError(f"Étape « {step.name} » : SQL manquant.")
            await on_progress(step.id, "running_sql", "Exécution SQL…")
            try:
                rows, truncated = await asyncio.wait_for(
                    self._execute_query_with_limit(
                        executor, session, sql, max_rows, user=runtime_user
                    ),
                    timeout=executor.STEP_TIMEOUT_SQL_EXEC,
                )
            except _SageUnavailable as exc:
                raise PreviewSageError(str(exc)) from exc
            tab_label = (cfg.get("tab_label") or step.name).strip() or step.name
            wb = rows_to_workbook(rows, tab_label=tab_label, sql=sql)
            extras["sql_executed"] = sql
            extras["truncated"] = truncated
            return wb, extras, None, None

        if st == "load_workbook":
            await on_progress(step.id, "loading_workbook", "Chargement du classeur…")
            wb = await executor._load_workbook_from_datastore(
                user_id=automation.user_id,
                relative_path=(cfg.get("path") or "").strip(),
                step_name=step.name,
            )
            # 2026-05-27 : suppression _truncate_workbook (double cap silencieux
            # cf. feedback_no_double_cap). Le workbook est servi tel quel ; la
            # SSoT pour le cap mémoire est gérée en amont (DatabaseConnection
            # ou ENV vars de chargement workbook).
            extras["loaded_path"] = cfg.get("path") or ""
            return wb, extras, None, None

        if st == "load_saved_query":
            from app.handlers.datastore import _safe_path, _user_dir

            sql_path = (cfg.get("sql_path") or "").strip()
            if not sql_path:
                raise PreviewValidationError(f"Étape « {step.name} » : fichier .sql manquant.")
            if not sql_path.lower().endswith(".sql"):
                raise PreviewValidationError(
                    f"Étape « {step.name} » : fichier doit avoir l'extension .sql"
                )
            user_dir = _user_dir(automation.user_id)
            target = _safe_path(user_dir, sql_path)
            if target is None or not target.exists() or not target.is_file():
                raise PreviewValidationError(
                    f"Étape « {step.name} » : fichier « {sql_path} » introuvable."
                )
            try:
                sql = await asyncio.to_thread(target.read_text, "utf-8")
            except OSError:
                raise PreviewValidationError(
                    f"Étape « {step.name} » : impossible de lire « {sql_path} »."
                )
            sql = sql.strip()
            if not sql:
                raise PreviewValidationError(
                    f"Étape « {step.name} » : fichier « {sql_path} » est vide."
                )
            await on_progress(step.id, "running_sql", "Exécution SQL…")
            try:
                rows, truncated = await asyncio.wait_for(
                    self._execute_query_with_limit(
                        executor, session, sql, max_rows, user=runtime_user
                    ),
                    timeout=executor.STEP_TIMEOUT_SQL_EXEC,
                )
            except _SageUnavailable as exc:
                raise PreviewSageError(str(exc)) from exc
            tab_label = (
                cfg.get("tab_label") or sql_path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or step.name
            ).strip() or step.name
            wb = rows_to_workbook(rows, tab_label=tab_label, sql=sql)
            extras["sql_executed"] = sql
            extras["truncated"] = truncated
            return wb, extras, None, None

        # ── Format ────────────────────────────────────────────────
        if st == "format_copilot":
            from app.services.ai.copilot_automation_bridge import (
                CopilotAutomationError,
                format_workbook_for_automation,
            )

            if input_workbook is None:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (format_copilot) : connectez d'abord une étape source."
                )
            # Simplifié 2026-05-27 (P0 Q9 doctrine SSoT) :
            # - tab_index / max_rows / max_rows_to_llm supprimés du config_schema UI
            # - Bridge utilise defaults None → pas de cap arbitraire
            # - Le LLM cape lui-même via son context_window (SSoT LlmModel)
            instruction = (cfg.get("instruction") or "").strip()

            await on_progress(step.id, "calling_llm", "Appel LLM (copilot)…")
            try:
                wb = await format_workbook_for_automation(
                    input_workbook,
                    instruction,
                    user_id=automation.user_id,
                )
            except CopilotAutomationError as exc:
                # Match par ``code`` (typed) — robuste face à une
                # reformulation du message français du bridge.
                if getattr(exc, "code", None) == "ANON_PENDING_REVIEW":
                    raise PreviewAnonPendingError(str(exc)) from exc
                raise PreviewLLMError(str(exc)) from exc
            extras["warnings"].extend(wb.get("warnings") or [])
            return wb, extras, None, None

        # ── Sinks (fichier tmp + token HMAC) ───────────────────────
        if st == "report":
            if input_workbook is None:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (report) : pas d'input. Connectez une étape source."
                )
            await on_progress(step.id, "generating_pdf", "Génération du PDF…")
            tabs = input_workbook.get("tabs", [])
            try:
                # ``execution_id`` n'est utilisé que dans le filename du PDF
                # (cf. ``_generate_llm_report`` : pas d'écriture BDD avec
                # cet id). Sentinel négatif → on remplace le nom du
                # fichier produit par un nom "preview_..." après coup
                # (move_to_preview_tmp).
                out_path_str = await executor._generate_llm_report(
                    automation,
                    -1,
                    tabs=tabs,
                    user_prompt=(cfg.get("prompt") or "").strip() or None,
                    user_title_hint=(cfg.get("title") or "").strip() or None,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # noqa: BLE001
                raise PreviewLLMError(f"Génération du rapport impossible : {_short(exc)}") from exc
            tmp_path = _move_to_preview_tmp(
                Path(out_path_str),
                automation.user_id,
                automation.id,
                step.id,
                rename_to=_preview_filename(automation.id, step.id, ".pdf"),
            )
            extras["output_kind"] = "report"
            return input_workbook, extras, tmp_path, tmp_path.name

        if st == "export_workbook":
            if input_workbook is None:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (export_workbook) : pas d'input."
                )
            all_tabs = input_workbook.get("tabs", [])
            try:
                selected_tabs = executor._parse_tabs_selector(cfg.get("tabs", "all"), all_tabs)
            except ValueError as exc:
                raise PreviewValidationError(f"Étape « {step.name} » : {exc}") from exc
            output_format = (cfg.get("format") or "excel").lower()
            if output_format not in {"excel", "csv"}:
                raise PreviewValidationError(
                    f"Étape « {step.name} » : format « {output_format} » invalide."
                )
            await on_progress(step.id, "exporting", f"Export {output_format.upper()}…")
            preview_hint = (cfg.get("filename") or "").strip() or f"preview_step{step.id}"
            out_path_str = await executor._generate_workbook_export(
                automation,
                -1,
                tabs=selected_tabs,
                output_format=output_format,
                filename_hint=preview_hint,
            )
            ext_map = {".xlsx": ".xlsx", ".csv": ".csv", ".zip": ".zip"}
            src_path = Path(out_path_str)
            ext = ext_map.get(src_path.suffix.lower(), src_path.suffix or ".bin")
            tmp_path = _move_to_preview_tmp(
                src_path,
                automation.user_id,
                automation.id,
                step.id,
                rename_to=_preview_filename(automation.id, step.id, ext),
            )
            extras["output_kind"] = "export"
            extras["exported_tabs"] = len(selected_tabs)
            return input_workbook, extras, tmp_path, tmp_path.name

        if st == "email":
            # DRY-RUN : on résout les destinataires + on construit les
            # tickets avec ``apply_delivery_strategy``, mais on n'appelle
            # JAMAIS ``smtp_client.send_email``. Le payload retourné en
            # extras permet à l'UI de montrer "voici ce qui serait envoyé".
            from app.services.automation.email_delivery_service import (
                VALID_DELIVERY_STRATEGIES,
                apply_delivery_strategy,
                resolve_recipients,
            )

            to_list = cfg.get("to") or cfg.get("recipients") or []
            if isinstance(to_list, str):
                to_list = [to_list]
            cc_list = cfg.get("cc") or []
            if isinstance(cc_list, str):
                cc_list = [cc_list]
            bcc_list = cfg.get("bcc") or []
            if isinstance(bcc_list, str):
                bcc_list = [bcc_list]
            try:
                resolved = await resolve_recipients(
                    session,
                    to=to_list,
                    cc=cc_list,
                    bcc=bcc_list,
                    from_distribution_list_id=cfg.get("from_distribution_list_id"),
                    owner_user_id=automation.user_id,
                )
            except ValueError as exc:
                raise PreviewValidationError(f"Étape « {step.name} » : {exc}") from exc
            no_explicit = (
                not to_list
                and not cc_list
                and not bcc_list
                and cfg.get("from_distribution_list_id") is None
            )
            if no_explicit and not any(resolved.values()):
                resolved["to"] = list(automation.recipients or [])
            subject = cfg.get("subject") or f"Rapport — {automation.name}"
            body = cfg.get("body") or ""
            strategy = cfg.get("delivery_strategy") or "single_email_all_recipients"
            if strategy not in VALID_DELIVERY_STRATEGIES:
                raise PreviewValidationError(
                    f"Étape « {step.name} » : delivery_strategy « {strategy} » invalide."
                )
            tickets = apply_delivery_strategy(
                strategy=strategy,
                recipients=resolved,
                attachments=[],  # fan-in fichiers non simulé en preview
                subject=subject,
                body=body,
            )
            # Confidentialité (finding M10) : masquer les emails dans
            # le payload WS pour ne pas exposer la liste complète à un
            # MITM Wi-Fi public. L'utilisateur voit le pattern (combien
            # d'emails, exemples masqués) — pas la liste exhaustive.
            # Conversion implicite workbook → xlsx : on annonce dans le
            # dry-run les ancetres directs qui produisent un workbook
            # (sources/format). Le runtime les convertira en xlsx tmp et
            # les attachera. Pour la preview, pas de conversion reelle —
            # juste un compteur informatif pour que l'utilisateur
            # comprenne quelles pj seront generees.
            #
            # Critere : ancetres directs (pas remontee transitive) dont
            # le step_type produit un workbook par contrat NODE_TYPE_SIGNATURES.
            # On reste statique, pas besoin de step_outputs runtime.
            _workbook_step_types = {
                "extract_sql",
                "load_workbook",
                "load_saved_query",
                "format_copilot",
            }
            _direct_parent_ids = [
                e.from_step_id for e in (automation.edges or []) if e.to_step_id == step.id
            ]
            _steps_by_id = {s.id: s for s in (automation.steps or [])}
            _implicit_steps: List[str] = []
            for pid in _direct_parent_ids:
                parent = _steps_by_id.get(pid)
                if parent is None:
                    continue
                if parent.step_type in _workbook_step_types:
                    _implicit_steps.append(parent.name or f"etape_{pid}")

            extras["output_kind"] = "email_dry_run"
            extras["dry_run"] = {
                "recipients": _mask_recipients(resolved),
                "subject": subject,
                "body": body,
                "strategy": strategy,
                "ticket_count": len(tickets),
                "total_recipients": (
                    len(resolved.get("to") or [])
                    + len(resolved.get("cc") or [])
                    + len(resolved.get("bcc") or [])
                ),
                "implicit_workbook_xlsx_count": len(_implicit_steps),
                "implicit_workbook_xlsx_steps": _implicit_steps,
            }
            return None, extras, None, None

        if st == "save_to_datastore":
            # DRY-RUN : on ne touche PAS au filesystem (eviter de polluer
            # le datastore a chaque clic preview). On calcule juste le
            # path resolu et les metadonnees, le frontend affiche un
            # recap "Voici ce qui serait sauvegarde".
            from app.handlers.datastore import (
                _safe_path,
                _sanitize_user_filename,
                _user_dir,
            )

            # Detection du mode (statique depuis les step_types des parents).
            # Si au moins un parent direct est un sink fichier (report,
            # export_workbook) → mode "copy" (archive du fichier genere).
            # Sinon → mode "serialize" (workbook → .afz.json natif Komptia).
            _direct_parent_ids = {
                e.from_step_id for e in (automation.edges or []) if e.to_step_id == step.id
            }
            _parent_types = {
                s.step_type for s in (automation.steps or []) if s.id in _direct_parent_ids
            }
            _file_producing = {"report", "export_workbook"}
            save_mode = "copy" if _parent_types & _file_producing else "serialize"

            if save_mode == "serialize" and input_workbook is None:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (save_to_datastore) : "
                    "connectez d'abord une étape source/format."
                )
            folder_path = (cfg.get("folder_path") or "").strip().strip("/")
            filename_raw = (cfg.get("filename") or "").strip()
            overwrite = bool(cfg.get("overwrite", False))
            if not filename_raw:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (save_to_datastore) : " "nom de fichier requis."
                )
            # Templating filename : naïf voulu (les strftime %Y-%m-%d /
            # %H-%M-%S n'affichent pas de TZ). clock.naive_utc() = horloge
            # machine en UTC sans tzinfo, via la source unique du temps.
            now = clock.naive_utc()
            filename_subst = filename_raw.replace("{date}", now.strftime("%Y-%m-%d")).replace(
                "{datetime}", now.strftime("%Y-%m-%d_%H-%M-%S")
            )
            base_name = _sanitize_user_filename(filename_subst)
            if not base_name:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (save_to_datastore) : nom "
                    f"« {filename_raw} » invalide après sanitization."
                )
            base_stem = base_name
            for suf in (".afz.json", ".json", ".pdf", ".xlsx", ".csv", ".zip"):
                if base_stem.lower().endswith(suf):
                    base_stem = base_stem[: -len(suf)]
                    break

            user_dir = _user_dir(automation.user_id)
            target_dir = _safe_path(user_dir, folder_path) if folder_path else user_dir
            if target_dir is None:
                raise PreviewValidationError(
                    f"Étape « {step.name} » (save_to_datastore) : "
                    f"dossier « {folder_path} » invalide (path-traversal)."
                )
            # Extension cible selon le mode :
            # - serialize : toujours .afz.json (format natif Komptia)
            # - copy      : statiquement on ne peut pas savoir l'extension
            #               sans executer l'amont — on annonce une extension
            #               "selon l'amont" dans la preview.
            if save_mode == "serialize":
                _target_ext_for_preview = ".afz.json"
            else:
                # Heuristique : report → .pdf, export_workbook → .xlsx ou .csv.
                # On prend l'extension qui correspond au 1er parent file-producing.
                _ext_map = {"report": ".pdf", "export_workbook": ".xlsx"}
                _target_ext_for_preview = next(
                    (_ext_map[pt] for pt in _parent_types if pt in _ext_map), ".bin"
                )
            target_path = target_dir / f"{base_stem}{_target_ext_for_preview}"
            collision = target_path.exists() and not overwrite
            if collision:
                # On affiche le path qui serait reellement utilise (suffixe
                # numerique) pour eviter une surprise post-execution.
                idx = 2
                while True:
                    candidate = target_dir / f"{base_stem}_{idx}{_target_ext_for_preview}"
                    if not candidate.exists():
                        target_path = candidate
                        break
                    idx += 1
                    if idx > 999:
                        break

            try:
                rel_path = target_path.relative_to(user_dir).as_posix()
            except ValueError:
                rel_path = target_path.name

            # Metadonnees selon le mode
            if save_mode == "serialize":
                tabs = (input_workbook or {}).get("tabs") or []
                total_rows = sum(len(t.get("rows") or []) for t in tabs)
                # Estimation taille (approximation rapide — pas de json.dumps
                # complet a chaque preview, c'est cher pour de gros workbooks).
                estimated_bytes = total_rows * 200 + len(tabs) * 1024
                content_descr = f"{len(tabs)} onglet(s) — {total_rows} ligne(s)"
            else:
                # Mode copy : on ne connait pas la taille statiquement (depend
                # de l'execution amont). On reporte juste l'origine.
                tabs = []
                total_rows = 0
                estimated_bytes = 0
                content_descr = (
                    f"Copie du fichier produit par l'etape amont "
                    f"({', '.join(sorted(_parent_types & _file_producing))})"
                )

            extras["output_kind"] = "datastore_dry_run"
            extras["dry_run"] = {
                "target_path": rel_path,
                "folder_path": folder_path or "(racine)",
                "filename": target_path.name,
                "save_mode": save_mode,
                "content_descr": content_descr,
                "tab_count": len(tabs),
                "total_rows": total_rows,
                "estimated_bytes": estimated_bytes,
                "overwrite": overwrite,
                "collision_resolved": collision,
            }
            return None, extras, None, None

        raise PreviewValidationError(
            f"Étape « {step.name} » : type « {st } » non supporté en preview."
        )

    async def _execute_query_with_limit(
        self,
        executor: Any,
        session: AsyncSession,
        sql: str,
        max_rows: int,
        *,
        user: Optional[Any] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Exécute le SQL via le QueryExecutor (TOP N injecté côté SQL).

        Retourne ``(rows, truncated)`` où ``truncated`` est le flag
        AUTORITATIF du connector (``QueryResult.truncated``), positionné
        quand le cap EFFECTIF (``min(caller, DatabaseConnection.max_rows)``)
        a été atteint. A6/A7-C6 : ne JAMAIS recalculer ``len(rows) >= max_rows``
        côté preview — ``max_rows`` y vaut la sentinelle ``MAX_STEP_PREVIEW_ROWS``
        (1e9), donc le recalcul était toujours False → troncature silencieuse
        (l'utilisateur croyait voir le résultat complet). SSoT = le connector.

        On passe ``user`` pour que les Row-Level Security rules
        (configurables par l'admin via ``/admin/data-access``)
        s'appliquent IDENTIQUEMENT en preview et en runtime — sinon
        un user verrait plus de données en preview qu'à l'exécution
        réelle (faille de confidentialité, finding C4).

        On wrap l'``OSError`` / ``SQLAlchemyError`` en ``_SageUnavailable``
        pour que le caller mappe sur la bonne catégorie d'erreur sans
        leak de détails internes au client.
        """
        from app.services.database.query_executor import QueryExecutor
        from sqlalchemy.exc import SQLAlchemyError

        qe = QueryExecutor()
        try:
            qr = await qe.execute(
                sql,
                max_rows=max_rows,
                user=user,
                rls_source="step_preview",
            )
        except (SQLAlchemyError, OSError) as exc:
            raise _SageUnavailable("BDD source indisponible. Réessayez dans un instant.") from exc
        return [dict(zip(qr.columns, row)) for row in qr.rows], bool(qr.truncated)


class _SageUnavailable(Exception):
    """Marqueur interne pour mapper l'erreur Sage en PreviewSageError."""


# ── Helpers utilitaires ──────────────────────────────────────────────


def _workbook_total_rows(wb: Optional[Dict[str, Any]]) -> int:
    if wb is None:
        return 0
    from app.services.automation.workbook_service import workbook_row_count

    return workbook_row_count(wb)


# _truncate_workbook supprimé 2026-05-27 (doctrine user P0 Q9 + cf.
# feedback_no_double_cap). C'était un cap "défense en profondeur" appelé
# avec max_rows=MAX_STEP_PREVIEW_ROWS=1e9 (sentinelle no-cap), donc en
# pratique sans effet. La SSoT pour le cap est gérée en amont.


def _preview_filename(automation_id: int, step_id: int, ext: str) -> str:
    """Nom de fichier preview lisible avec nonce.

    Le nonce 8-byte URL-safe garantit qu'un nouveau preview produit un
    fichier au nom différent — donc un token issu d'un run précédent ne
    peut pas servir un nouveau fichier après écrasement (cf. finding C8
    de l'adversarial review). Le token HMAC bind ce nom complet.
    """
    safe_ext = ext if ext.startswith(".") else f".{ext}"
    nonce = secrets.token_urlsafe(8)
    return f"preview_a{automation_id}_s{step_id}_{nonce}{safe_ext}"


def _move_to_preview_tmp(
    src: Path,
    user_id: int,
    automation_id: int,
    step_id: int,
    *,
    rename_to: Optional[str] = None,
) -> Path:
    """Déplace le fichier généré dans la zone tmp preview (gérée par le
    cleanup TTL). Si l'helper executor a déjà écrit dans /datastore ou
    similaire, on copie pour garder le tmp isolé.

    Si ``rename_to`` est fourni, le fichier final porte ce nom (sinon
    on garde le nom source).

    En cas d'échec de copie/move, on supprime le fichier source pour
    éviter les orphelins dans la zone réelle (``automation_reports/``)
    qui pollueraient l'historique des exécutions et la zone partagée
    user (cf. finding M8 de la review).
    """
    dest_dir = _preview_tmp_path(user_id, automation_id, step_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    final_name = rename_to or src.name
    dest = dest_dir / final_name
    try:
        # Move dans la mesure du possible (évite la double-occurrence
        # disque d'un PDF). Fallback copy si cross-device.
        os.replace(str(src), str(dest))
    except OSError:
        import shutil

        try:
            shutil.copy2(str(src), str(dest))
            try:
                src.unlink()
            except OSError:
                logger.warning(
                    "preview move: source non supprimée après copy %s",
                    src,
                    exc_info=True,
                )
        except OSError:
            # Move ET copy ont échoué. On nettoie le fichier source
            # restant dans la zone réelle pour éviter les orphelins.
            try:
                src.unlink()
            except OSError:
                pass
            raise
    return dest


def resolve_preview_output_path(
    *, user_id: int, automation_id: int, step_id: int, filename: str
) -> Optional[Path]:
    """Reconstruit le chemin tmp pour servir le fichier (handler output).

    Refuse path traversal — ``filename`` doit être un nom plat, pas
    un chemin relatif.

    B5 cycle 6 — defense-in-depth alignee sur ``AutomationDownloadHandler``:
    refuse aussi explicitement les symlinks post-resolve, meme si la
    resolution + ``relative_to`` les detecte deja indirectement (le lien
    serait suivi vers sa cible et le containment-check echouerait si la
    cible sort du root). Symetrie avec le pattern existant.
    """
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return None
    dest = _preview_tmp_path(user_id, automation_id, step_id) / filename
    try:
        resolved = dest.resolve(strict=True)
    except OSError:
        return None
    # B5 — Defense-in-depth : refuser explicitement les symlinks (CWE-59).
    # Meme si resolve() les suit, on bloque les liens dans le tmp dir pour
    # rester aligne avec AutomationDownloadHandler.
    if resolved.is_symlink():
        return None
    expected_root = _preview_tmp_path(user_id, automation_id, step_id).resolve(strict=False)
    try:
        resolved.relative_to(expected_root)
    except ValueError:
        return None
    return resolved


def _mask_email(addr: str) -> str:
    """Masque un email pour preview : ``dupont@example.fr`` → ``d***@e***.fr``."""
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    masked_local = (local[:1] or "*") + "***"
    if "." in domain:
        first, _, tld = domain.rpartition(".")
        masked_domain = (first[:1] or "*") + "***." + tld
    else:
        masked_domain = (domain[:1] or "*") + "***"
    return f"{masked_local}@{masked_domain}"


def _mask_recipients(resolved: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Masque chaque email + tronque à 5 entrées par bucket pour limiter
    l'exposition. Le compte total reste disponible séparément."""
    out: Dict[str, List[str]] = {}
    for bucket in ("to", "cc", "bcc"):
        emails = list(resolved.get(bucket) or [])
        masked = [_mask_email(e) for e in emails[:5]]
        if len(emails) > 5:
            masked.append(f"+{len(emails) - 5} autres")
        out[bucket] = masked
    return out


def _short(exc: Exception) -> str:
    """Message d'erreur court et safe (pas de path/credential)."""
    msg = str(exc) or type(exc).__name__
    if len(msg) > 200:
        msg = msg[:200] + "…"
    return msg


# ── Singleton ────────────────────────────────────────────────────────


_service_singleton: Optional[StepPreviewService] = None


def get_preview_service() -> StepPreviewService:
    global _service_singleton
    if _service_singleton is None:
        _service_singleton = StepPreviewService()
    return _service_singleton
