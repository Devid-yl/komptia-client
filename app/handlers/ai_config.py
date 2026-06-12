"""
Handlers pour la configuration IA via GUI.

Endpoints:
- GET  /admin/ai-config             Page HTML de configuration
- GET  /api/ai/config                Lire la configuration (clés sensibles masquées)
- POST /api/ai/config                Mettre à jour la configuration
- POST /api/ai/config/reset          Réinitialiser aux valeurs par défaut
- GET  /api/ai/config/export         Exporter la configuration (JSON téléchargeable)
- POST /api/ai/config/import         Importer une configuration exportée
- POST /api/ai/schema/sync           Synchroniser le schéma (mode bloquant, JSON)
- GET  /api/ai/schema/sync/stream    Synchroniser le schéma (SSE avec progression)
- GET  /api/ai/health                Health check du pipeline IA
- POST /api/ai/doc/reset             Effacer toute la documentation d'entraînement
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Iterable, Optional

from sqlalchemy.exc import SQLAlchemyError
from tornado.iostream import StreamClosedError

from app.core import clock
from app.handlers.base import BaseHandler, admin_required
from app.config import config as app_config
from app.models.ai_config import AIConfigKey
from app.services.ai.config_service import get_ai_config_service
from app.services.ai.llm_providers import (
    ensure_providers_from_db,
    get_llm_manager,
    reinit_providers_from_config,
)
from app.services.ai.schema_sync import get_sync_service
from app.services.ai.training_store import get_training_store
from app.services.ai.vanna_enhanced_generator import (
    get_enhanced_generator,
    reset_generator,
)

logger = logging.getLogger(__name__)


_INTERNAL_ONLY_KEYS: frozenset[str] = frozenset({AIConfigKey.SCHEMA_SYNC_LAST_RUN.value})

_ADMIN_WRITABLE_KEYS: frozenset[str] = frozenset(
    k.value for k in AIConfigKey if k.value not in _INTERNAL_ONLY_KEYS
)

_PROVIDER_RESET_KEYS: frozenset[str] = frozenset(
    {
        AIConfigKey.API_KEY.value,
        AIConfigKey.API_BASE_URL.value,
        AIConfigKey.PRIMARY_PROVIDER.value,
        AIConfigKey.PRIMARY_MODEL.value,
        AIConfigKey.FALLBACK_PROVIDER.value,
        AIConfigKey.FALLBACK_MODEL.value,
        # LLM local : un changement (toggle, URL, modèle, params) DOIT
        # déclencher un reinit, sinon le `LLMManager._local_fallback` garde
        # l'ancien client httpx avec l'ancien timeout/retries.
        AIConfigKey.LOCAL_LLM_ENABLED.value,
        AIConfigKey.LOCAL_LLM_BASE_URL.value,
        AIConfigKey.LOCAL_LLM_MODEL.value,
        AIConfigKey.LOCAL_LLM_TEMPERATURE.value,
        AIConfigKey.LOCAL_LLM_MAX_RETRIES.value,
        AIConfigKey.LOCAL_LLM_TIMEOUT_SECONDS.value,
    }
)

_SENSITIVE_INBOUND_KEYS: frozenset[str] = frozenset({AIConfigKey.API_KEY.value})

# Sérialise les POST /api/ai/config et /api/ai/config/reset pour éviter une
# race condition quand 2 admins concurrents switchent le provider en même
# temps : sans lock, A lit ``old_model``, B commit son set_many, A finit son
# set_many → l'audit log de A ment (compare son old à un new qui n'est plus
# le bon), et ``_reinit_after_config_change`` exécuté en chevauchement peut
# laisser ``_local_fallback`` référencer un httpx client fermé. Cf. review
# brainstorm 2026-05-14 CRIT3. Lock module-level (instance Tornado unique
# par process worker) — suffisant car Komptia n'a pas de cluster multi-process.
#
# **Lazy-init** (review adversariale 2026-05-14 CRIT4) : ``asyncio.Lock()``
# instancié à l'import-time tente de récupérer l'event loop courant
# (DeprecationWarning Python 3.10+, RuntimeError sur certains ordres
# d'import si l'IOLoop Tornado n'existe pas encore). On crée le lock au
# 1er appel async et on le cache module-level.
_CONFIG_WRITE_LOCK: Optional[asyncio.Lock] = None


def _get_config_write_lock() -> asyncio.Lock:
    """Retourne le lock module-level, créé au 1er appel (lazy-init).

    Doit être appelé depuis un contexte async (event loop actif), sinon
    Python 3.10+ lève ``DeprecationWarning`` sur ``asyncio.Lock()``
    sans loop. En pratique, tous les call sites sont des handlers
    Tornado async, donc OK.
    """
    global _CONFIG_WRITE_LOCK
    if _CONFIG_WRITE_LOCK is None:
        _CONFIG_WRITE_LOCK = asyncio.Lock()
    return _CONFIG_WRITE_LOCK


_TRUTHY_ARG_VALUES: frozenset[str] = frozenset({"1", "true", "yes", "on", "y", "t"})

SSE_HEARTBEAT_SECONDS: float = 15.0


def _parse_truthy(raw: str | None) -> bool:
    """Interprète une valeur d'argument HTTP comme booléen (voir `_TRUTHY_ARG_VALUES`)."""
    if raw is None:
        return False
    return raw.strip().lower() in _TRUTHY_ARG_VALUES


def _check_sync_cooldown(sync_service) -> tuple[bool, int]:
    """B11 — Vérifie le cooldown anti-spam-clic. Source unique de vérité
    pour les 2 handlers (POST `/api/ai/schema/sync` et SSE GET stream).

    Retourne ``(allowed, retry_after_seconds)``. Si ``allowed`` est False,
    le caller doit refuser la sync avec 429. Le SSE refuse en émettant un
    event `error` avec `retry_after_seconds`.
    """
    from app.constants_ai import get_schema_sync_cooldown_seconds

    last_completed = sync_service.get_last_completed_at()
    if last_completed is None:
        return True, 0
    elapsed = (clock.now() - last_completed).total_seconds()
    cooldown = get_schema_sync_cooldown_seconds()
    if elapsed >= cooldown:
        return True, 0
    return False, int(cooldown - elapsed)


class AIConfigPageHandler(BaseHandler):
    """Page de configuration IA complète. `GET /admin/ai-config`."""

    @admin_required
    async def get(self) -> None:
        user = self.current_user
        config_service = get_ai_config_service()
        config = await config_service.get_all_for_display()

        primary_provider = config.get(AIConfigKey.PRIMARY_PROVIDER.value)
        config.get(AIConfigKey.PRIMARY_MODEL.value) or ""
        # Provider précis (marque) pour le badge : dérivé du base_url stocké via
        # la SSoT host→provider du backend (PAS de mapping dupliqué en JS). Pour
        # un OpenAI-compat (Groq/Mistral/…) on nomme la marque au lieu du
        # libellé générique "OpenAI-compatible". Anthropic : le format suffit.
        detected_provider = ""
        if (primary_provider or "").lower() != "anthropic":
            from app.services.ai.llm_providers import _detect_openai_compat_provider_from_url

            detected_provider = (
                _detect_openai_compat_provider_from_url(
                    config.get(AIConfigKey.API_BASE_URL.value) or ""
                )
                or ""
            )
        available_models = self._collect_available_models_sync_fallback()
        try:
            await ensure_providers_from_db()
            available_models = await self._collect_available_models(primary_provider)
        except Exception:
            logger.error("Erreur récupération modèles disponibles", exc_info=True)

        self.render(
            "admin/ai_config.html",
            user=user,
            config=config,
            available_models=available_models,
            detected_provider=detected_provider,
            page_title="Configuration IA",
        )

    @staticmethod
    def _collect_available_models_sync_fallback() -> list[str]:
        """Fallback vide si l'initialisation des providers lève."""
        return []

    @staticmethod
    async def _collect_available_models(primary_provider: str | None) -> list[str]:
        llm_manager = get_llm_manager()
        all_models = await llm_manager.list_all_models()

        if primary_provider and primary_provider in all_models:
            return list(all_models[primary_provider])

        # Pas de provider fixé → liste agrégée dédupliquée (ordre stable)
        seen: set[str] = set()
        merged: list[str] = []
        for provider_models in all_models.values():
            for model in provider_models:
                if model not in seen:
                    seen.add(model)
                    merged.append(model)
        return merged


class AIConfigAPIHandler(BaseHandler):
    """API lecture/écriture de la configuration IA. `GET|POST /api/ai/config`."""

    @admin_required
    async def get(self) -> None:
        """Retourne la configuration complète avec les clés sensibles masquées."""
        config_service = get_ai_config_service()
        config = await config_service.get_all_for_display()
        self.write_json({"success": True, "config": config})

    @admin_required
    async def post(self) -> None:
        """Met à jour la configuration."""
        body = _parse_json_object_or_write_error(self)
        if body is None:
            return

        if not _enforce_https_for_sensitive_keys(self, body):
            return

        unknown_keys = [k for k in body.keys() if k not in _ADMIN_WRITABLE_KEYS]
        writable_updates = {k: v for k, v in body.items() if k in _ADMIN_WRITABLE_KEYS}

        if unknown_keys:
            # Fail-closed feedback : l'admin sait immédiatement que certaines clés
            # sont ignorées (typo, tentative d'écriture d'une clé interne, etc.).
            logger.warning(
                "POST /api/ai/config : clés rejetées (non admin-writable) : %s",
                unknown_keys,
            )
            self.write_json(
                {
                    "success": False,
                    "error": "Clés inconnues ou non modifiables",
                    "unknown_keys": unknown_keys,
                },
                status=400,
            )
            return

        # Section critique sérialisée — voir ``_CONFIG_WRITE_LOCK`` plus haut.
        # Empêche : (a) un 2e admin de lire ``old_model_pre_save`` pendant
        # qu'un 1er admin a commit son set_many mais pas encore appelé
        # _reinit, ce qui produirait un audit log mensonger ; (b) deux
        # _reinit_after_config_change chevauchants qui pourraient laisser
        # _local_fallback référencer un httpx client fermé. Le lock est
        # acquis AVANT la lecture ``old_model_pre_save`` ET libéré APRÈS
        # ``_reinit_after_config_change``. Coût : sérialisation des POST
        # admin config (acceptable, fréquence faible).
        async with _get_config_write_lock():
            try:
                config_service = get_ai_config_service()
                # Capture l'ANCIEN ``primary_model`` avant le set_many, pour
                # pouvoir logger le DIFF des capabilities ancien→nouveau plus
                # bas (review L3-L6 MAJ 4, 2026-05-14). Lecture best-effort :
                # si la BDD lève ou le champ n'existe pas, ``None`` → l'audit
                # log dégradera proprement à "ancien inconnu".
                old_model_pre_save: Optional[str] = None
                if isinstance(writable_updates.get(AIConfigKey.PRIMARY_MODEL.value), str):
                    try:
                        old_val = await config_service.get(AIConfigKey.PRIMARY_MODEL)
                        if isinstance(old_val, str):
                            old_model_pre_save = old_val
                    except Exception:  # noqa: BLE001
                        old_model_pre_save = None
                count = await config_service.set_many(
                    writable_updates, user_id=self.current_user.id
                )
            except ValueError as e:
                self.write_json({"success": False, "error": str(e)}, status=400)
                return
            except SQLAlchemyError:
                logger.error("Erreur mise à jour config IA", exc_info=True)
                self.write_json(
                    {"success": False, "error": "Erreur interne du serveur"},
                    status=500,
                )
                return

            # `set_many` ignore silencieusement les valeurs invalides (log warning).
            # On remonte un signal côté handler pour que l'UI puisse prévenir l'admin.
            rejected_count = len(writable_updates) - count
            if rejected_count > 0:
                logger.warning(
                    "POST /api/ai/config : %d valeur(s) invalide(s) ignorée(s) sur %d",
                    rejected_count,
                    len(writable_updates),
                )

            # Audit log dédié pour l'action "Effacer la connexion provider" (les 4
            # clés ``api_key`` / ``api_base_url`` / ``primary_provider`` /
            # ``primary_model`` envoyées vides en même temps). Sans ce log
            # explicite, l'opérateur ne voit qu'une rafale de 4 lignes
            # ``[AUDIT] Config IA modifiée: <clé>`` indissociable d'une rafale de
            # changements normaux. Le clear est l'action la plus destructrice de
            # cette page (Iris devient indispo) — elle mérite sa propre trace.
            _CLEAR_CONNECTION_KEYS = {
                AIConfigKey.API_KEY.value,
                AIConfigKey.API_BASE_URL.value,
                AIConfigKey.PRIMARY_PROVIDER.value,
                AIConfigKey.PRIMARY_MODEL.value,
            }
            cleared_keys = {
                k for k, v in writable_updates.items() if k in _CLEAR_CONNECTION_KEYS and v == ""
            }
            if cleared_keys == _CLEAR_CONNECTION_KEYS:
                logger.warning(
                    "[AUDIT] Connexion provider effacée par user=%s "
                    "(api_key, api_base_url, primary_provider, primary_model vidés). "
                    "Iris est indisponible jusqu'à reconfiguration d'une clé.",
                    self.current_user.id,
                )
            else:
                # Audit log enrichi : si l'admin change le modèle (sans clear
                # complet), tracer le DIFF de capabilities ancien→nouveau. Permet
                # de comprendre une régression observée après switch ("pourquoi
                # le caching n'est plus utilisé ?" → audit dit "+nouveau perd
                # supports_prompt_caching").
                new_model = writable_updates.get(AIConfigKey.PRIMARY_MODEL.value)
                new_provider = writable_updates.get(AIConfigKey.PRIMARY_PROVIDER.value)
                if isinstance(new_model, str) and new_model:
                    self._log_capability_diff_on_switch(
                        old_model=old_model_pre_save,
                        new_model=new_model,
                        new_provider=new_provider if isinstance(new_provider, str) else None,
                    )

            await _reinit_after_config_change(writable_updates.keys())

            self.write_json(
                {
                    "success": True,
                    "updated_count": count,
                    "rejected_count": rejected_count,
                }
            )

    def _log_capability_diff_on_switch(
        self,
        *,
        old_model: Optional[str],
        new_model: str,
        new_provider: Optional[str] = None,
    ) -> None:
        """Audit log enrichi quand l'admin change le modèle primary.

        Trace le DIFF des capabilities ancien→nouveau (review L3-L6 MAJ 4,
        2026-05-14) : ce qui est PERDU et ce qui est GAGNÉ par le switch.
        Permet à l'opérateur de comprendre immédiatement une régression
        post-switch ("pourquoi le caching n'est plus utilisé ?" → l'audit
        dit "+nouveau perd supports_prompt_caching").

        ``old_model=None`` → première configuration (pas de diff possible) ;
        on log juste les capabilities du nouveau modèle.

        ``new_provider`` inclus dans le log pour distinguer Sonnet→Haiku
        (intra-provider) de Sonnet→Groq Llama (cross-provider) — sans
        cross-référencer 3 logs.
        """
        try:
            from app.constants_ai import supports_capability_for_model

            tracked = (
                "extended_thinking",
                "prompt_caching",
                "reasoning_effort",
                "parallel_tool_calls",
                "streaming",
                "vision",
                "strict_json",
            )

            def _caps_of(model: Optional[str]) -> set[str]:
                if not model:
                    return set()
                return {c for c in tracked if supports_capability_for_model(model, c) is True}

            new_caps = _caps_of(new_model)
            old_caps = _caps_of(old_model)
            gained = new_caps - old_caps
            lost = old_caps - new_caps
            kept = new_caps & old_caps

            provider_suffix = f" (provider={new_provider})" if new_provider else ""
            if old_model is None:
                logger.warning(
                    "[AUDIT] Switch modèle %r → %r%s par user=%s — "
                    "première configuration, capabilities actives: [%s]",
                    old_model,
                    new_model,
                    provider_suffix,
                    self.current_user.id,
                    ", ".join(sorted(new_caps)) if new_caps else "aucune",
                )
            else:
                logger.warning(
                    "[AUDIT] Switch modèle %r → %r%s par user=%s — "
                    "gagné: [%s] | perdu: [%s] | conservé: [%s]",
                    old_model,
                    new_model,
                    provider_suffix,
                    self.current_user.id,
                    ", ".join(sorted(gained)) if gained else "aucune",
                    ", ".join(sorted(lost)) if lost else "aucune",
                    ", ".join(sorted(kept)) if kept else "aucune",
                )
        except Exception:  # noqa: BLE001 — l'audit log ne doit pas bloquer
            logger.warning(
                "Audit log capabilities post-switch échoué pour %r",
                new_model,
                exc_info=True,
            )


def _enforce_https_for_sensitive_keys(handler: BaseHandler, body: dict[str, Any]) -> bool:
    """Retourne False et écrit une réponse 400 si HTTPS manque en production.

    Fonction module-level (SSoT, B4-F1) : partagée par ``AIConfigAPIHandler.post``
    ET ``AIConfigImportHandler.post`` — les deux chemins d'écriture de config IA
    doivent appliquer la MÊME garde HTTPS sur les clés sensibles (api_key).
    """
    has_sensitive = any(k in body for k in _SENSITIVE_INBOUND_KEYS)
    if not (has_sensitive and app_config.is_production()):
        return True
    if _is_request_https(handler):
        return True
    logger.warning(
        "Tentative d'envoi de clé API sans HTTPS en production (user=%s, ip=%s)",
        getattr(handler.current_user, "id", None),
        handler.request.remote_ip,
    )
    handler.write_json(
        {
            "success": False,
            "error": "HTTPS requis pour configurer les clés API en production",
        },
        status=400,
    )
    return False


class AIModelsRefreshHandler(BaseHandler):
    """``POST /api/ai/models/refresh`` — découverte + enrichissement en 1 passe.

    Relie les deux mondes jusqu'ici déconnectés :

    1. ``sync_from_provider(provider)`` — upsert dans ``llm_models`` les modèles
       que l'API du provider expose (fenêtre provisoire 200K, ``verified=False``).
    2. ``enrich_from_litellm(force_refresh=True)`` — corrige ``context_window`` +
       pricing depuis le registre public LiteLLM et marque ``verified=True`` les
       fenêtres confirmées.

    Déclenché par le bouton « Tester » de ``/admin/ai-config`` après la
    sauvegarde de la clé. Avant cet endpoint, un modèle choisi dans la dropdown
    (peuplée en direct par l'API du provider via ``/api/ai/models``)
    n'atterrissait jamais dans ``llm_models`` → ``get_context_window_for_model``
    tombait sur le fallback 200K et « Mettre à jour fenêtres & tarifs » était
    impuissant (``skipped_unknown``). Cf. bug « 200K peu importe le modèle ».

    **Concurrence** : réutilise ``_CONFIG_WRITE_LOCK`` — deux « Tester »
    simultanés (ou un save config concurrent) sont sérialisés, évitant des
    inserts dupliqués. **Lock DB** : chaque commit passe par ``retry_on_locked``
    (la base SQLite locale peut être occupée par un run Iris).

    **Dégradé** : si l'enrich LiteLLM échoue (réseau / GitHub down), les modèles
    découverts gardent une fenêtre provisoire ``verified=False`` → l'indicateur
    affiche « à confirmer », jamais un chiffre faux. ``enrich_failed=True`` est
    remonté pour que l'UI prévienne l'admin.

    Retour : ``{success, provider, discovered, updated, enriched, enrich_failed,
    unverified, models}``.
    """

    @admin_required
    async def post(self) -> None:
        from app.core.db_retry import retry_on_locked
        from app.models.llm_model import LlmModel
        from app.services.ai.llm_model_registry import get_llm_model_registry
        from sqlalchemy import select

        # Body toléré vide (``{}``) : le provider peut venir de la config.
        body_raw = self.request.body
        try:
            body = json.loads(body_raw) if body_raw else {}
        except (json.JSONDecodeError, ValueError, TypeError):
            self.write_json({"success": False, "error": "JSON invalide"}, status=400)
            return
        if not isinstance(body, dict):
            self.write_json(
                {"success": False, "error": "Le corps JSON doit être un objet"}, status=400
            )
            return

        # Provider : body explicite > ``primary_provider`` configuré. Le JS
        # « Tester » sauvegarde la clé+provider AVANT d'appeler ce refresh, donc
        # ``primary_provider`` est à jour ; on accepte aussi un override explicite.
        provider = body.get("provider")
        if not isinstance(provider, str) or not provider.strip():
            try:
                cfg = await get_ai_config_service().get_all()
                provider = cfg.get(AIConfigKey.PRIMARY_PROVIDER.value) or ""
            except SQLAlchemyError:
                provider = ""
        provider = (provider or "").strip()
        if not provider:
            self.write_json(
                {
                    "success": False,
                    "error": (
                        "Aucun provider à rafraîchir : renseignez une clé API "
                        "(le provider est auto-détecté) ou passez 'provider'."
                    ),
                },
                status=400,
            )
            return

        await ensure_providers_from_db()
        registry = get_llm_model_registry()

        # Sessions fraîches PAR tentative (retry_on_locked rejoue le factory) —
        # une session post-rollback ne doit pas être réutilisée.
        async def _do_sync() -> dict[str, Any]:
            async with self.db_session() as session:
                return await registry.sync_from_provider(provider, session)

        async def _do_enrich() -> dict[str, Any]:
            async with self.db_session() as session:
                return await registry.enrich_from_litellm(session, force_refresh=True)

        # Section critique sérialisée (même lock que le save config).
        async with _get_config_write_lock():
            # 1. Découverte. sync_from_provider gère en interne l'échec
            # ``list_models`` (retourne stats avec 'error') ; ici on ne traite
            # que l'échec de commit (lock épuisé après retries / BDD).
            sync_stats: dict[str, Any] = {}
            try:
                sync_stats = await retry_on_locked(_do_sync, operation_name="models-refresh-sync")
            except SQLAlchemyError:
                logger.error(
                    "Refresh modèles : sync_from_provider (commit) a échoué", exc_info=True
                )
                self.write_json(
                    {
                        "success": False,
                        "error": (
                            "Découverte des modèles impossible (base de données "
                            "occupée). Réessayez dans un instant."
                        ),
                    },
                    status=503,
                )
                return

            # sync_from_provider avale l'échec de ``list_models`` (provider down,
            # clé invalide) et le renvoie dans ``stats['error']`` sans lever. On
            # le remonte explicitement : sinon l'admin verrait « discovered: 0 »
            # avec success:True, indistinguable d'un provider qui n'a simplement
            # aucun nouveau modèle (revue adversariale 2026-06-03, finding F1).
            discovery_failed = bool(sync_stats.get("error"))
            if discovery_failed:
                logger.warning(
                    "Refresh modèles : découverte provider '%s' a signalé une "
                    "erreur (list_models) : %s",
                    provider,
                    sync_stats.get("error"),
                )

            # 2. Enrichissement (best-effort, ne bloque jamais la découverte).
            # Échec fetch LiteLLM = ``stats['error']`` ; échec commit = exception.
            # Dans les deux cas les modèles restent ``verified=False`` → « à
            # confirmer » côté UI, jamais un faux chiffre.
            enrich_stats: dict[str, Any] = {}
            enrich_failed = False
            try:
                enrich_stats = await retry_on_locked(
                    _do_enrich, operation_name="models-refresh-enrich"
                )
                if enrich_stats.get("error"):
                    enrich_failed = True
                    logger.warning(
                        "Refresh modèles : enrich LiteLLM a signalé une erreur : %s",
                        enrich_stats.get("error"),
                    )
            except Exception as exc:  # noqa: BLE001 — enrich best-effort
                enrich_failed = True
                logger.warning("Refresh modèles : enrich LiteLLM a échoué (non bloquant) : %s", exc)

        # Liste à jour pour la dropdown (reflète la table après refresh).
        models: list[dict[str, Any]] = []
        unverified = 0
        try:
            async with self.db_session() as session:
                rows = (
                    (
                        await session.execute(
                            select(LlmModel).where(
                                LlmModel.provider == provider,
                                LlmModel.deprecated_at.is_(None),
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for r in rows:
                    models.append(
                        {
                            "name": r.name,
                            "display_name": r.display_name or r.name,
                            "context_window": r.context_window,
                            "context_window_verified": r.context_window_verified,
                        }
                    )
                    if not r.context_window_verified:
                        unverified += 1
        except SQLAlchemyError:
            logger.warning("Refresh modèles : lecture liste post-refresh échouée", exc_info=True)

        self.write_json(
            {
                "success": True,
                "provider": provider,
                "discovered": int(sync_stats.get("inserted", 0) or 0),
                "updated": int(sync_stats.get("updated", 0) or 0),
                "enriched": int(enrich_stats.get("updated", 0) or 0),
                "discovery_failed": discovery_failed,
                "discovery_error": sync_stats.get("error") if discovery_failed else None,
                "enrich_failed": enrich_failed,
                "unverified": unverified,
                "models": models,
            }
        )


class AIConfigResetHandler(BaseHandler):
    """Remet la configuration aux valeurs par défaut + vide l'historique de
    consommation API. `POST /api/ai/config/reset`.

    Effet complet :
    - Toutes les clés ``DEFAULT_AI_CONFIG`` sont remises à leurs valeurs
      d'usine (sauf ``api_key`` et ``primary_model`` — choix admin sensibles
      qui survivent au reset).
    - Toutes les rows ``ai_performance_logs`` sont supprimées (la section
      "Consommation API" repart à zéro). Justification : un reset config est
      un repart-à-zéro logique, l'historique de tokens/coûts ne fait plus
      sens si les paramètres de génération changent.
    - Providers LLM rehydratés (nouvelles temperature/max_retries/timeout
      defaults appliqués au runtime).
    """

    @admin_required
    async def post(self) -> None:
        user = self.current_user
        usage_deleted = 0
        try:
            config_service = get_ai_config_service()
            count = await config_service.reset_to_defaults(user_id=user.id)
            # Vider l'historique de consommation API en même temps que le reset
            # config (sémantique cohérente : "repartir de zéro"). Best-effort —
            # si la table est verrouillée, on log mais on ne bloque pas le reset.
            try:
                from sqlalchemy import delete
                from app.core.database import get_session
                from app.models.ai_performance import AIPerformanceLog

                async with get_session() as session:
                    res = await session.execute(delete(AIPerformanceLog))
                    await session.commit()
                    usage_deleted = res.rowcount or 0
            except Exception:  # noqa: BLE001 — défensif, ne bloque pas le reset
                logger.warning("Reset config: vidage ai_performance_logs échoué", exc_info=True)
        except SQLAlchemyError:
            logger.error("Erreur reset config IA", exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur interne du serveur"},
                status=500,
            )
            return

        logger.info(
            "[AUDIT] Config IA réinitialisée aux défauts par user=%s — %d clé(s) reset, "
            "%d ligne(s) ai_performance_logs supprimée(s)",
            user.id,
            count,
            usage_deleted,
        )
        # Reset = tous les providers peuvent avoir changé → reinit inconditionnel.
        await _reinit_after_config_change(_PROVIDER_RESET_KEYS)
        self.write_json(
            {
                "success": True,
                "reset_count": count,
                "usage_logs_deleted": usage_deleted,
            }
        )


class AIConfigExportHandler(BaseHandler):
    """Exporte la configuration complète. `GET /api/ai/config/export`."""

    @admin_required
    async def get(self) -> None:
        config_service = get_ai_config_service()
        export_data = await config_service.export_config()

        self.set_status(200)
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.set_header("Content-Disposition", 'attachment; filename="ai_config_export.json"')
        # Défense en profondeur : empêche un navigateur de "deviner" un type MIME
        # plus permissif (HTML/JS) si le contenu exporté contenait un jour du texte
        # interprétable. Cohérent avec la classe d'export en fichier.
        self.set_header("X-Content-Type-Options", "nosniff")
        self.write(json.dumps(export_data, ensure_ascii=False, indent=2, default=str))


class AIConfigImportHandler(BaseHandler):
    """Importe une configuration précédemment exportée. `POST /api/ai/config/import`."""

    @admin_required
    async def post(self) -> None:
        body = _parse_json_object_or_write_error(self)
        if body is None:
            return

        user = self.current_user

        raw_items = body.get("config")
        if not isinstance(raw_items, list):
            self.write_json(
                {
                    "success": False,
                    "error": "Format d'import invalide (clé 'config' = liste attendue).",
                },
                status=400,
            )
            return

        # B4-F1 (defense-in-depth) : l'import est un chemin d'écriture de config —
        # il ne doit PAS être plus permissif que POST /api/ai/config. On applique
        # ici les MÊMES gardes que le POST direct (SSoT des règles d'écriture
        # côté handler) :
        #   (a) HTTPS exigé en prod si une clé sensible (api_key) est présente —
        #       un export légitime n'en contient jamais (SECRET_CONFIG_KEYS exclues)
        #       mais un import forgé à la main pourrait ;
        #   (b) allowlist _ADMIN_WRITABLE_KEYS : on ne RESTAURE jamais une clé
        #       interne (ex. ``schema_sync_last_run`` = marqueur de sync qui doit
        #       refléter l'état LIVE, pas celui d'un backup périmé). Le POST les
        #       rejette en 400 ; ici on les filtre et on le signale.
        submitted_flat = {
            it.get("key"): it.get("value")
            for it in raw_items
            if isinstance(it, dict) and it.get("key")
        }
        if not _enforce_https_for_sensitive_keys(self, submitted_flat):
            return

        writable_items = [
            it for it in raw_items if isinstance(it, dict) and it.get("key") in _ADMIN_WRITABLE_KEYS
        ]
        skipped_internal = sorted(
            {
                it.get("key")
                for it in raw_items
                if isinstance(it, dict)
                and it.get("key")
                and it.get("key") not in _ADMIN_WRITABLE_KEYS
            }
        )
        if skipped_internal:
            logger.warning(
                "Import config IA : %d clé(s) interne/inconnue ignorée(s) : %s",
                len(skipped_internal),
                skipped_internal,
            )

        config_service = get_ai_config_service()
        try:
            count = await config_service.import_config({"config": writable_items}, user_id=user.id)
        except ValueError as e:
            self.write_json({"success": False, "error": str(e)}, status=400)
            return
        except SQLAlchemyError:
            logger.error("Erreur import config IA", exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur interne du serveur"},
                status=500,
            )
            return

        # Audit : on ne connaît pas précisément les clés rejetées par set_many
        # (il loggue juste un warning par valeur refusée) mais on loggue au moins
        # le résumé côté handler pour que l'opérateur voie l'action.
        submitted = sum(
            1
            for item in raw_items
            if isinstance(item, dict) and item.get("key") and item.get("value") is not None
        )
        logger.info(
            "[AUDIT] Import config IA par user=%s : %d/%d clé(s) appliquée(s) "
            "(%d clé(s) interne(s) ignorée(s))",
            user.id,
            count,
            submitted,
            len(skipped_internal),
        )

        # Import = config globale remplacée → reinit inconditionnel des providers.
        await _reinit_after_config_change(_PROVIDER_RESET_KEYS)
        self.write_json(
            {
                "success": True,
                "imported_count": count,
                "submitted_count": submitted,
                "skipped_internal_keys": skipped_internal,
            }
        )


class AISchemaSyncHandler(BaseHandler):
    """Synchronise le schéma de la base source.

    - `POST /api/ai/schema/sync` : déclenche la sync (avec cooldown)
    - `GET /api/ai/schema/sync` : retourne l'état courant (status JSON)
    - `DELETE /api/ai/schema/sync` : annule la sync en cours
    """

    @admin_required
    async def get(self) -> None:
        """B11 — Status JSON non-SSE pour polling UI léger.

        Retourne `{step, percent, message, started_at, elapsed_seconds,
        table_in_progress}` si une sync tourne, ou `{active: False, ...}`.
        """
        sync_service = get_sync_service()
        progress = sync_service.get_current_progress()
        last_completed = sync_service.get_last_completed_at()
        if progress is not None:
            self.write_json({"active": True, **progress})
            return
        self.write_json(
            {
                "active": False,
                "last_completed_at": (last_completed.isoformat() if last_completed else None),
            }
        )

    @admin_required
    async def delete(self) -> None:
        """B11 — Annule la sync en cours (set le cancel_event partagé).

        Retourne 204 si annulation envoyée, 404 si aucune sync active.
        L'annulation est asynchrone : le sync vérifie cancel à chaque
        étape et stoppe au prochain check.
        """
        sync_service = get_sync_service()
        sent = sync_service.cancel_active_sync()
        if sent:
            user = self.current_user
            logger.info("Annulation sync schéma demandée par user=%s", user.id)
            self.set_status(204)
            self.finish()
            return
        self.write_json(
            {"success": False, "error": "Aucune synchronisation en cours."},
            status=404,
        )

    @admin_required
    async def post(self) -> None:
        user = self.current_user
        sync_service = get_sync_service()

        # B11 — Cooldown anti-spam-clic. Le lock asyncio bloque déjà les
        # syncs concurrentes mais le cooldown évite qu'un admin clique
        # 10× et reçoive 10 erreurs successives. Source unique : helper
        # `_check_sync_cooldown` partagé avec le SSE handler (cf. fix
        # adversarial #1 — sinon bypass via SSE).
        allowed, remaining = _check_sync_cooldown(sync_service)
        if not allowed:
            self.write_json(
                {
                    "success": False,
                    "error": (f"Sync déjà effectué récemment. Réessayer dans " f"{remaining}s."),
                    "retry_after_seconds": remaining,
                },
                status=429,
            )
            self.set_header("Retry-After", str(remaining))
            return

        logger.info("Synchronisation du schéma déclenchée par user=%s", user.id)
        try:
            result = await sync_service.sync_from_sage(user_id=user.id)
        except RuntimeError as e:
            # Sync déjà en cours (lock) → 409 Conflict, message sûr pour l'UI.
            self.write_json({"success": False, "error": str(e)}, status=409)
            return
        except (ConnectionError, OSError):
            logger.error("Erreur connexion sync schéma", exc_info=True)
            self.write_json(
                {"success": False, "error": "Échec de connexion à la base source"},
                status=500,
            )
            return
        except SQLAlchemyError:
            logger.error("Erreur DB sync schéma", exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur interne du serveur"},
                status=500,
            )
            return

        if not result.get("success", True):
            # Le service signale explicitement un échec fonctionnel (ex: pyodbc manquant).
            self.write_json(result, status=400)
            return

        await _record_schema_sync_timestamp(user.id)

        self.write_json(
            {
                "success": True,
                "tables_synced": result.get("tables_count", 0),
                "views_synced": result.get("views_count", 0),
                "ddl_count": result.get("ddl_added", 0),
                "doc_count": result.get("doc_added", 0),
                "duration": result.get("duration", 0),
                # #76 — propager l'indicateur de complétude au client : même
                # avec success:True, des sections (functions/fk/inferred/…) ont
                # pu échouer → connaissance Iris partielle. Le client peut
                # alerter l'admin au lieu de croire la sync intégrale.
                "complete": result.get("complete", True),
                "incomplete_sections": result.get("incomplete_sections", []),
            }
        )


class AISchemaSyncStreamHandler(BaseHandler):
    """SSE : sync du schéma avec progression temps-réel.

    `GET /api/ai/schema/sync/stream?force_full=<truthy>`

    Émet une ligne `data: {...}\\n\\n` par étape. Un heartbeat (`event: ping`)
    est envoyé toutes les `SSE_HEARTBEAT_SECONDS` secondes pour empêcher les
    proxys / load balancers de fermer la connexion pendant les longues syncs.
    Fermer la connexion côté client annule la sync via `_cancel_event`.
    """

    @admin_required
    async def get(self) -> None:
        self._configure_sse_headers()
        force_full = _parse_truthy(self.get_argument("force_full", None))

        self._cancel_event = asyncio.Event()
        self._connection_closed = False
        cancel_event = self._cancel_event

        # B11 — Directive SSE retry: 5000ms (évite martèlement après coupure)
        await self._emit_retry_directive()

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            user = self.current_user
            sync_service = get_sync_service()

            # B11 — Même cooldown anti-spam que le POST, via le helper SSoT
            # `_check_sync_cooldown`. Sans ça le SSE bypassait l'anti-spam :
            # la directive `retry: 5000ms` fait reconnecter l'EventSource
            # automatiquement si la connexion saute → re-déclenchait
            # `sync_from_sage` (lecture LOURDE du schéma source de prod)
            # toutes les 5s, sans garde. Le client ferme l'EventSource sur
            # un event `step:error` (cf. iris.js `finish()`), donc émettre
            # l'erreur stoppe aussi la boucle de reconnexion.
            allowed, remaining = _check_sync_cooldown(sync_service)
            if not allowed:
                await self._emit_error_event(
                    f"Sync déjà effectué récemment. Réessayer dans {remaining}s."
                )
                return

            async def progress_callback(step: str, percent: int, message: str) -> None:
                if self._connection_closed:
                    cancel_event.set()
                    return
                payload = json.dumps(
                    {"step": step, "percent": percent, "message": message},
                    ensure_ascii=False,
                )
                await self._safe_sse_write(f"data: {payload}\n\n")

            try:
                result = await sync_service.sync_from_sage(
                    user_id=user.id,
                    progress_callback=progress_callback,
                    cancel_event=cancel_event,
                    force_full=force_full,
                )
            except RuntimeError as e:
                await self._emit_error_event(str(e))
                return
            except Exception:
                logger.error("Erreur sync stream", exc_info=True)
                await self._emit_error_event("Erreur interne")
                return

            if result.get("success"):
                await _record_schema_sync_timestamp(user.id)

            final_payload = json.dumps(
                {"step": "complete", "percent": 100, "result": result},
                ensure_ascii=False,
            )
            await self._safe_sse_write(f"data: {final_payload}\n\n")
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass

    def _configure_sse_headers(self) -> None:
        self.set_header("Content-Type", "text/event-stream; charset=UTF-8")
        self.set_header("Cache-Control", "no-cache")
        self.set_header("Connection", "keep-alive")
        self.set_header("X-Accel-Buffering", "no")

    async def _emit_retry_directive(self) -> None:
        """B11 — Émet une directive `retry:` SSE en début de stream.

        Indique au client EventSource d'attendre 5s avant retry après une
        coupure réseau (au lieu du défaut navigateur ~3s). Évite le
        martèlement de la sync si le LB drop la connexion.
        """
        await self._safe_sse_write("retry: 5000\n\n")

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._connection_closed:
                await asyncio.sleep(SSE_HEARTBEAT_SECONDS)
                if self._connection_closed:
                    return
                # Commentaire SSE : ignoré par EventSource, mais garde la
                # connexion en vie côté proxy/navigateur.
                await self._safe_sse_write(": heartbeat\n\n")
        except asyncio.CancelledError:
            raise

    async def _emit_error_event(self, message: str) -> None:
        payload = json.dumps(
            {"step": "error", "percent": 0, "message": message},
            ensure_ascii=False,
        )
        await self._safe_sse_write(f"data: {payload}\n\n")

    async def _safe_sse_write(self, data: str) -> None:
        """Write + flush. Marque la connexion fermée si le client est parti."""
        if self._connection_closed:
            return
        try:
            self.write(data)
            await self.flush()
        except StreamClosedError:
            self._connection_closed = True
            self._cancel_event.set()
        except Exception:
            logger.debug("SSE write inattendu", exc_info=True)
            self._connection_closed = True
            self._cancel_event.set()

    def on_connection_close(self) -> None:
        """Annule la sync dès que le client déconnecte."""
        self._connection_closed = True
        if hasattr(self, "_cancel_event"):
            self._cancel_event.set()


class AIHealthCheckHandler(BaseHandler):
    """Health check du pipeline IA. `GET /api/ai/health`."""

    @admin_required
    async def get(self) -> None:
        try:
            generator = get_enhanced_generator()
            health = await generator.health_check()
        except Exception:
            logger.error("Erreur health check IA", exc_info=True)
            self.write_json(
                {
                    "success": False,
                    "error": "Erreur lors du diagnostic IA",
                    "healthy": False,
                    "health": {"status": "error"},
                }
            )
            return

        # « Dernière sync » : SOURCE UNIQUE = la table schema_syncs (la même que
        # /admin/ai-training), via le checker de fraîcheur. Auparavant le front
        # lisait `data.last_sync` que cet endpoint n'émettait JAMAIS (champ sans
        # backend) → toujours affiché « - ». Émis en ISO HORODATÉ (offset +00:00)
        # via clock.iso_utc ; le front (KomptiaFormat, heure NAVIGATEUR) le formate
        # — un ISO naïf serait mal-parsé par new Date() (+Nh). clock.iso_utc gère
        # None→None (champ absent → front affiche « - »).
        last_sync_iso: Optional[str] = None
        try:
            from app.services.ai.schema_freshness import get_freshness_checker

            last_sync_dt = await get_freshness_checker().get_last_sync_time()
            last_sync_iso = clock.iso_utc(last_sync_dt)
        except Exception:
            logger.warning("Health check IA : échec récupération dernière sync", exc_info=True)

        self.write_json(
            {
                "success": True,
                "healthy": health.get("status") == "ok",
                "tables_count": health.get("tables_count", 0),
                "views_count": health.get("views_count", 0),
                "last_sync": last_sync_iso,
                "health": health,
            }
        )


class AIDocResetHandler(BaseHandler):
    """Efface toute la documentation d'entraînement IA. `POST /api/ai/doc/reset`."""

    @admin_required
    async def post(self) -> None:
        user = self.current_user
        try:
            store = get_training_store()
            counts = await store.reset_all()
        except SQLAlchemyError:
            logger.error("Erreur reset doc IA", exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur interne du serveur"},
                status=500,
            )
            return
        except Exception:
            logger.error("Erreur inattendue reset doc IA", exc_info=True)
            self.write_json(
                {"success": False, "error": "Erreur lors de la réinitialisation"},
                status=500,
            )
            return

        # ``counts`` peut être un int (rétrocompat ancien retour) ou un dict.
        if isinstance(counts, dict):
            total_deleted = sum(int(v or 0) for v in counts.values())
            breakdown = counts
        else:
            total_deleted = int(counts or 0)
            breakdown = {"training_data": total_deleted}
        logger.info(
            "[AUDIT] Documentation IA réinitialisée par user=%s : %d ligne(s) au total — %s",
            user.id,
            total_deleted,
            breakdown,
        )
        self.write_json({"success": True, "deleted_count": total_deleted, "breakdown": breakdown})


def _parse_json_object_or_write_error(handler: BaseHandler) -> dict[str, Any] | None:
    """Parse le body JSON comme un dict. Écrit une 400 et retourne None sinon."""
    try:
        body = json.loads(handler.request.body)
    except (json.JSONDecodeError, TypeError, ValueError):
        handler.write_json({"success": False, "error": "JSON invalide"}, status=400)
        return None
    if not isinstance(body, dict):
        handler.write_json(
            {"success": False, "error": "Le corps JSON doit être un objet"},
            status=400,
        )
        return None
    return body


def _is_request_https(handler: BaseHandler) -> bool:
    """True si la requête est HTTPS (directe ou via reverse proxy de confiance)."""
    if handler.request.protocol == "https":
        return True
    forwarded = handler.request.headers.get("X-Forwarded-Proto", "")
    # Un proxy peut chaîner "https,http" : on prend le premier segment.
    first_hop = forwarded.split(",", 1)[0].strip().lower()
    return first_hop == "https"


async def _reinit_after_config_change(changed_keys: Iterable[str]) -> None:
    """Invalide le cache du générateur et recharge les providers si nécessaire.

    La réinitialisation des providers est conditionnelle : elle ne se fait que si
    au moins une clé de `_PROVIDER_RESET_KEYS` a changé. Les erreurs de reinit
    sont loggées mais ne sont PAS remontées à l'appelant : la config a déjà été
    persistée en base, le failure mode "providers pas à jour en RAM" est moins
    grave qu'un 500 qui ferait penser à l'admin que rien n'a été sauvegardé.
    """
    try:
        await reset_generator()
    except Exception:
        logger.error(
            "reset_generator() a échoué — config sauvegardée mais cache stale",
            exc_info=True,
        )

    changed = set(changed_keys)
    if changed & _PROVIDER_RESET_KEYS:
        try:
            await reinit_providers_from_config()
        except Exception:
            logger.error(
                "reinit_providers_from_config() a échoué — config sauvegardée "
                "mais providers en RAM non rechargés",
                exc_info=True,
            )
        # Purge le cache "pricing warned" : un reinit peut signifier que
        # l'admin a réparé le pricing d'un modèle (sync depuis provider
        # ou saisie manuelle). Sans cette purge, le warning [BILLING]
        # resterait silencieux à vie même après que le pricing soit
        # correct → CRIT3 review adversariale 2026-05-14.
        try:
            from app.services.ai.llm_call_tracker import clear_pricing_warning_cache

            clear_pricing_warning_cache()  # purge complète, simple et safe
        except Exception:  # noqa: BLE001 — best-effort
            logger.debug("clear_pricing_warning_cache échoué (non-bloquant)", exc_info=True)
    # Invalider le cache RAG si l'admin a changé un param qui le concerne.
    # Cf. ``_get_rag_runtime_config`` dans training_store : tous les paramètres
    # RAG SSoT BDD passent par ce cache 60s. Doctrine ``feedback_no_double_cap`` :
    # un seul cap admin, pas de hard-cap applicatif caché en aval.
    _RAG_CONFIG_KEYS = {
        "rag_example_count",
        "confidence_threshold",
        "rag_ddl_count",
        "rag_doc_count",
        "rag_ddl_doc_min_score",
        "rag_min_examples",
        "rag_max_scan",
        "rag_reusable_score",
    }
    if changed & _RAG_CONFIG_KEYS:
        try:
            from app.services.ai.training_store import invalidate_rag_runtime_cache

            invalidate_rag_runtime_cache()
        except Exception:  # noqa: BLE001 — défensif
            logger.debug("invalidate_rag_runtime_cache failed (non-critical)")

    # Invalider le cache use_cache (prompt caching LLM global) si touché.
    if "use_cache" in changed:
        try:
            from app.services.ai.llm_providers import invalidate_use_cache_runtime

            invalidate_use_cache_runtime()
        except Exception:  # noqa: BLE001 — défensif
            logger.debug("invalidate_use_cache_runtime failed (non-critical)")


async def _record_schema_sync_timestamp(user_id: int | None) -> None:
    """Enregistre l'horodatage ISO-8601 UTC de la dernière synchronisation."""
    config_service = get_ai_config_service()
    now_iso = clock.now().isoformat()
    try:
        await config_service.set(AIConfigKey.SCHEMA_SYNC_LAST_RUN.value, now_iso, user_id=user_id)
    except (ValueError, SQLAlchemyError):
        logger.warning(
            "Impossible d'enregistrer schema_sync_last_run — sync elle-même OK",
            exc_info=True,
        )
