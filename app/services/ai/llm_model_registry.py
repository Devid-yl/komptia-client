"""``LlmModelRegistry`` — registre dynamique des modèles LLM (BDD-backed).

**Pourquoi ce service existe**

Avant, l'app dépendait d'une liste statique ``app.constants_ai._MODELS`` qui
exigeait une mise à jour du code à chaque release Anthropic / OpenAI / autre.
Ce registre rend ces métadonnées **dynamiques** :

* sync depuis les APIs provider (``provider.list_models()``) ;
* override admin pour les caractéristiques non exposées par les APIs
  (``context_window``, ``pricing``, ``capabilities``) ;
* cache mémoire avec TTL court pour ne pas frapper la BDD à chaque appel.

**Stratégie de fallback**

Le registre est **always-on**, jamais bloquant :
- Lecture : tente la BDD ; si la BDD est down → fallback sur les valeurs
  hardcoded dans ``constants_ai._MODELS`` (seed initial) ; si ce fallback
  ne connaît pas le modèle → valeur par défaut conservatrice.
- Écriture (sync) : best-effort. Une erreur réseau provider laisse les
  données BDD intactes — on ne supprime jamais un modèle qui ne répond pas.

**Provider-agnostic**

Aucune référence à un provider spécifique dans ce module. Ajouter un
nouveau provider (Mistral, Gemini) ne demande qu'une chose : implémenter
``LLMProvider.list_models()`` côté ``llm_providers.py``. Le registre
ingère automatiquement la nouvelle source.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import clock
from app.models.llm_model import LlmModel
from app.utils.logger import get_logger

logger = get_logger(__name__)


# TTL du cache mémoire — court, le registre est essentiellement read-only
# côté runtime (la sync est faite manuellement par l'admin). 60s = compromis
# entre fraîcheur et fréquence des requêtes BDD.
_CACHE_TTL_SECONDS = 60.0

# Longueur minimum d'un préfixe candidat pour la résolution alias.
# 5 = ``gpt-4o`` (6) accepté, ``gpt`` (3) refusé. Évite qu'un candidat
# trop générique capture tous les modèles d'un provider.
_MIN_PREFIX_MATCH_LEN = 5


class LlmModelRegistry:
    """Cache mémoire + accès BDD + sync provider pour le registre des
    modèles LLM. Singleton (une instance partagée pour le process)."""

    _instance: Optional["LlmModelRegistry"] = None

    def __init__(self) -> None:
        self._cache_by_name: Dict[str, Dict[str, Any]] = {}
        self._cache_loaded_at: float = 0.0
        self._seeded: bool = False

    # ── Cache management ────────────────────────────────────────────────

    def _is_cache_fresh(self) -> bool:
        return (time.monotonic() - self._cache_loaded_at) < _CACHE_TTL_SECONDS

    def invalidate(self) -> None:
        """Marque le cache mémoire comme périmé — appelé après une sync ou un
        override admin pour que la prochaine lecture **async** (``_ensure_loaded``)
        relise la BDD.

        ⚠️ **Ne vide PLUS ``_cache_by_name``** (régression 2026-06-02). Les
        lecteurs **synchrones** (``get_field_sync`` → ``constants_ai.get_*_for_model``,
        utilisés par l'indicateur context-window de ``/iris``, le clamp
        ``max_tokens``, le pricing) ne peuvent pas ``await`` un reload : s'ils
        tombaient sur un cache vidé, ``constants_ai`` retombait sur les maps
        statiques **VIDES** (``_MODELS=()`` depuis 2026-05-14) puis sur les
        défauts conservateurs (``_DEFAULT_CONTEXT_WINDOW=200_000`` /
        ``_DEFAULT_MAX_OUTPUT_TOKENS=8192``) — donc **tous** les modèles
        s'effondraient silencieusement sur 200k « peu importe le modèle » après
        chaque ``invalidate()`` (ex: ``sync_from_provider`` au save
        ``/admin/ai-config``). On conserve donc la **dernière valeur connue**
        (au pire légèrement périmée, jamais un faux défaut) ; le timestamp remis
        à 0 force le rechargement au prochain ``_ensure_loaded`` (lecteurs async)
        ou via le ``reload_from_db`` explicite des call-sites de sync.

        Pour un vidage réel (tests d'isolation), instancier un registre neuf
        plutôt que d'appeler ``invalidate()``."""
        self._cache_loaded_at = 0.0

    async def _load_cache(self, session: AsyncSession) -> None:
        """Recharge le cache depuis la BDD. Aussi appelée pour forcer un
        refresh (``invalidate()`` puis appel de cette méthode)."""
        try:
            result = await session.execute(select(LlmModel).where(LlmModel.deprecated_at.is_(None)))
            rows = result.scalars().all()
            self._cache_by_name = {row.name: row.to_dict() for row in rows}
            self._cache_loaded_at = time.monotonic()
        except Exception as exc:
            logger.warning("LlmModelRegistry: chargement BDD échoué : %s", exc)
            # On garde le cache existant — fail-soft.

    async def _ensure_loaded(self, session: AsyncSession) -> None:
        if not self._cache_loaded_at or not self._is_cache_fresh():
            await self._load_cache(session)

    # ── Lectures publiques ──────────────────────────────────────────────

    async def get(self, name: str, session: AsyncSession) -> Optional[Dict[str, Any]]:
        """Retourne les métadonnées d'un modèle par son nom (ID API).
        Résout les alias datés vers le modèle de base : ``claude-opus-4-7-20260101``
        → cherche d'abord exact, puis longest-prefix-match. Retourne ``None``
        si introuvable.
        """
        await self._ensure_loaded(session)
        # Snapshot via list() pour éviter une mutation pendant iteration si
        # un autre coroutine reload le cache (rebind atomique mais Python
        # rend explicite la défense ici).
        snapshot = dict(self._cache_by_name)
        if name in snapshot:
            return snapshot[name]
        return self._lookup_by_prefix(name, snapshot)

    @staticmethod
    def _lookup_by_prefix(
        name: str, cache_snapshot: Dict[str, Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Longest-prefix-match déterministe sur un snapshot du cache.

        **Pourquoi longest-prefix** : si le cache contient à la fois
        ``claude-opus-4`` et ``claude-opus-4-7``, alors ``claude-opus-4-7-20260101``
        doit résoudre vers ``claude-opus-4-7`` (le plus spécifique), pas vers
        le premier match d'itération (non-déterministe avant Python 3.7+).

        Garde-fou minimum 5 chars (``gpt-4o`` = 6 chars) pour éviter qu'un
        candidat trop court (``gpt``, ``llm``, etc.) capture tous les modèles.
        """
        best_key: Optional[str] = None
        for candidate_name in cache_snapshot:
            if len(candidate_name) < _MIN_PREFIX_MATCH_LEN:
                continue
            if name.startswith(candidate_name) and (
                best_key is None or len(candidate_name) > len(best_key)
            ):
                best_key = candidate_name
        return cache_snapshot[best_key] if best_key else None

    def get_field_sync(self, name: str, field: str) -> Optional[Any]:
        """API publique : lookup synchrone d'un champ pour un modèle.

        Encapsule le pattern « cache → exact → longest-prefix → None » pour
        que les callers (notamment ``constants_ai``) ne pokent pas
        ``_cache_by_name`` directement. Single source of truth.
        """
        if not name:
            return None
        snapshot = dict(self._cache_by_name)
        cached = snapshot.get(name)
        if cached is None:
            cached = self._lookup_by_prefix(name, snapshot)
        if cached is None:
            return None
        return cached.get(field)

    async def reload_from_db(self, session: AsyncSession) -> None:
        """API publique : recharge le cache mémoire depuis la BDD.

        Appelée par les call-sites externes (handler admin patch, boot
        warm-up) qui veulent garantir un cache frais après une écriture.
        Délégue à ``_load_cache`` qui est fail-soft.
        """
        await self._load_cache(session)

    async def list_all(
        self, session: AsyncSession, *, provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        await self._ensure_loaded(session)
        models = list(self._cache_by_name.values())
        if provider:
            models = [m for m in models if m.get("provider") == provider]
        # Tri stable : provider puis name
        models.sort(key=lambda m: (m.get("provider", ""), m.get("name", "")))
        return models

    # ── Lectures synchrones via fallback hardcoded ──────────────────────
    # Ces helpers sont appelés depuis du code synchrone qui ne peut pas
    # ouvrir une session BDD (ex: validation d'un payload, calcul d'un
    # cap dans un util). On retombe sur ``constants_ai._MODELS`` qui est
    # chargé en mémoire au démarrage. Si l'admin a override la BDD, le
    # fallback peut être stale — la décision pragmatique est : préférer
    # une valeur stable connue plutôt qu'un crash si la BDD n'est pas
    # accessible depuis ce contexte.

    def get_context_window_sync(self, name: str) -> int:
        from app.constants_ai import get_context_window_for_model as _fallback

        cached = self._cache_by_name.get(name)
        if cached:
            return int(cached["context_window"])
        return _fallback(name)

    def get_max_output_tokens_sync(self, name: str) -> int:
        from app.constants_ai import get_max_tokens_for_model as _fallback

        cached = self._cache_by_name.get(name)
        if cached:
            return int(cached["max_output_tokens"])
        return _fallback(name)

    def get_pricing_sync(self, name: str) -> Optional[Dict[str, float]]:
        """Retourne les 4 prix par modèle (USD/Mtok) :
        ``{input, output, cache_read, cache_creation}``. Les 2 derniers
        valent 0.0 si le modèle ne fait pas de prompt caching distinct,
        auquel cas le caller (``_compute_cost_snapshot``) tombe en fallback
        sur le prix input pour cache_read et 0 pour cache_creation.

        Single source of truth = registre BDD (plan dynamicité 2026-05-14).
        ``_MODELS=()`` donc le fallback static ``MODEL_PRICING`` était mort
        code (review adversariale BLOCKING #2). Retourne ``None`` si
        inconnu, caller logue [BILLING] warning throttle."""
        cached = self._cache_by_name.get(name)
        if cached:
            return {
                "input": float(cached.get("input_price_per_mtok_usd") or 0.0),
                "output": float(cached.get("output_price_per_mtok_usd") or 0.0),
                "cache_read": float(cached.get("cache_read_price_per_mtok_usd") or 0.0),
                "cache_creation": float(cached.get("cache_creation_price_per_mtok_usd") or 0.0),
            }
        return None

    # ── Sync depuis les providers ───────────────────────────────────────

    async def sync_from_provider(self, provider_name: str, session: AsyncSession) -> Dict[str, int]:
        """Synchronise les modèles d'un provider depuis son API.

        Stratégie : on appelle ``provider.list_models()`` (qui parle à
        l'API officielle), on insère les nouveaux modèles, on met à jour
        ``last_synced_at`` + ``display_name`` + ``created_at_provider``
        sur les existants. **Les caractéristiques admin-editables
        (``context_window``, ``pricing``, ``capabilities``) ne sont pas
        écrasées** sur les modèles dont ``manually_overridden=True``.

        Retourne un compteur ``{"inserted": N, "updated": M, "skipped": K}``.
        """
        from app.services.ai.llm_providers import get_llm_manager

        manager = get_llm_manager()
        try:
            models_from_api = await manager.list_models_for_provider(provider_name)
        except Exception as exc:
            logger.warning(
                "LlmModelRegistry.sync_from_provider(%s) : list_models a levé : %s",
                provider_name,
                exc,
            )
            return {"inserted": 0, "updated": 0, "skipped": 0, "error": str(exc)}

        inserted = 0
        updated = 0
        skipped_overridden = 0
        now = clock.now()

        for api_model in models_from_api:
            api_name = api_model.get("name") or ""
            if not api_name:
                continue
            # Lookup existant
            stmt = select(LlmModel).where(
                LlmModel.provider == provider_name, LlmModel.name == api_name
            )
            existing = (await session.execute(stmt)).scalar_one_or_none()

            if existing is None:
                # Nouveau modèle — on insère AVEC LES VALEURS DE L'API
                # provider uniquement. **Plus AUCUN fallback static** sur
                # ``MODEL_PRICING``/``MODEL_CONTEXT_WINDOW``/``MODEL_MAX_OUTPUT_TOKENS``
                # (qui sont VIDES depuis 2026-05-14, plan dynamicité radicale).
                # Si l'API du provider n'expose pas une valeur, on met le
                # default SQL (200_000 / 4_096 / 0.0) — la sync LiteLLM
                # ultérieure enrichit avec les vraies valeurs.
                api_ctx_window = api_model.get("context_window")
                api_max_output = api_model.get("max_output_tokens")
                api_in_price = api_model.get("input_price_per_mtok_usd")
                api_out_price = api_model.get("output_price_per_mtok_usd")

                row = LlmModel(
                    name=api_name,
                    provider=provider_name,
                    display_name=api_model.get("display_name"),
                    last_synced_at=now,
                    created_at_provider=_parse_datetime(api_model.get("created_at")),
                    # Defaults SQL si l'API n'expose pas — la sync LiteLLM
                    # complétera avec les vraies valeurs.
                    context_window=int(api_ctx_window) if api_ctx_window else 200_000,
                    max_output_tokens=int(api_max_output) if api_max_output else 4_096,
                    input_price_per_mtok_usd=(
                        float(api_in_price) if api_in_price is not None else 0.0
                    ),
                    output_price_per_mtok_usd=(
                        float(api_out_price) if api_out_price is not None else 0.0
                    ),
                )
                session.add(row)
                # Déduction des 5 flags Komptia-spécifiques (extended_thinking,
                # reasoning_effort, tool_call_format, system_prompt_format,
                # cache_ttl_options, supports_streaming) — délégué à la couche
                # litellm_registry_sync._deduce_komptia_flags qui connaît la
                # logique (provider, name) → flags. Sans cet appel, un modèle
                # ajouté par sync provider native garderait les defaults SQL
                # (``tool_call_format="openai"`` faux pour Anthropic).
                # Cf. plan dynamicité 2026-05-14.
                from app.services.ai.litellm_registry_sync import _deduce_komptia_flags

                _deduce_komptia_flags(row, diff={})
                inserted += 1
            else:
                # MAJ des champs sync ; respecte ``manually_overridden`` pour
                # les caractéristiques admin-editées.
                existing.last_synced_at = now
                if api_model.get("display_name"):
                    existing.display_name = api_model["display_name"]
                created = _parse_datetime(api_model.get("created_at"))
                if created and not existing.created_at_provider:
                    existing.created_at_provider = created
                if existing.manually_overridden:
                    skipped_overridden += 1
                updated += 1

        await session.commit()
        # Invalide + recharge immédiatement (symétrie avec ``enrich_from_litellm``
        # l.352-353). Sans le ``reload`` ici, les modèles fraîchement insérés/MAJ
        # ne sont visibles des lecteurs synchrones qu'au prochain ``_ensure_loaded``
        # async — fenêtre pendant laquelle ``/admin/ai-config`` venait d'être
        # sauvegardé (ce qui déclenche cette sync) et l'indicateur context-window
        # de ``/iris`` lisait un cache périmé. Cf. bug « toujours 200k » 2026-06-02.
        self.invalidate()
        await self.reload_from_db(session)
        return {
            "provider": provider_name,
            "inserted": inserted,
            "updated": updated,
            "skipped_overridden": skipped_overridden,
            "total_from_api": len(models_from_api),
        }

    async def enrich_from_litellm(
        self,
        session: AsyncSession,
        *,
        force_refresh: bool = False,
        allow_regression: bool = False,
    ) -> Dict[str, Any]:
        """Enrichit les ``context_window`` / ``max_output_tokens`` des modèles
        BDD non-overridés depuis le registre public LiteLLM.

        Source de vérité externe pour les fenêtres de contexte que ni
        Anthropic ni OpenAI n'exposent via leur ``GET /v1/models``. Délègue
        à :func:`app.services.ai.litellm_registry_sync.enrich_models_from_litellm`.
        Invalide le cache après update pour propagation immédiate.
        """
        from app.services.ai.litellm_registry_sync import enrich_models_from_litellm

        stats = await enrich_models_from_litellm(
            session, force_refresh=force_refresh, allow_regression=allow_regression
        )
        # Toujours invalider/reload après une tentative de sync, même si
        # ``updated == 0`` : le clic ``force_refresh`` est en soi une demande
        # de fraîcheur du cache mémoire (cas où l'admin a édité une row via
        # SQL direct, ou après un restore BDD). Cf. review adversariale.
        self.invalidate()
        await self.reload_from_db(session)
        # Le pricing BD vient potentiellement d'être renseigné (0/0 → > 0).
        # Purger le throttle de warning [BILLING] pour qu'un modèle qui warnait
        # "pricing inconnu" soit ré-évalué (sinon le warning reste muet à vie
        # après réparation — CRIT3 2026-05-14, étendu au path enrich LiteLLM).
        try:
            from app.services.ai.llm_call_tracker import clear_pricing_warning_cache

            clear_pricing_warning_cache(None)
        except Exception:  # noqa: BLE001 — best-effort, ne pas casser la sync
            pass
        return stats

    # ── Seed initial depuis _MODELS hardcoded ───────────────────────────

    async def seed_from_constants(self, session: AsyncSession) -> int:
        """Au premier démarrage (BDD vide), populate la table depuis le
        registre statique ``constants_ai._MODELS`` pour ne pas démarrer
        avec une BDD vide. Idempotent : ne ré-insère pas un modèle déjà
        présent.

        Retourne le nombre de modèles ajoutés.
        """
        if self._seeded:
            return 0
        from app.constants_ai import _MODELS

        # Capabilities du seed à back-filler sur BDD existante post-migration.
        # Sans ce back-fill, après une migration ``ADD COLUMN`` (cf. 2026-05-14
        # qui ajoute 8 capability flags), les rows existantes héritent des
        # ``DEFAULT`` SQL (0/1/NULL) au lieu des vraies valeurs de
        # ``_MODELS``. Résultat sans fix : tous les modèles déjà en BDD
        # perdent leurs capabilities → thinking et caching cassés
        # silencieusement après upgrade. Le back-fill ne touche QUE les rows
        # ``manually_overridden=False`` (l'admin gagne).
        _CAPABILITY_FIELDS_TO_BACKFILL = (
            "supports_extended_thinking",
            "supports_prompt_caching",
            "supports_tool_use",
            "supports_reasoning_effort",
            "supports_parallel_tool_calls",
            "supports_streaming",
            "supports_vision",
            "supports_strict_json",
            "tool_call_format",
            "system_prompt_format",
        )

        added = 0
        backfilled = 0
        for m in _MODELS:
            stmt = select(LlmModel).where(LlmModel.provider == m.provider, LlmModel.name == m.name)
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if existing is not None:
                # Row déjà présente : back-fill UNIQUEMENT si l'admin n'a
                # pas overridé manuellement. Aligne les capabilities sur
                # ``_MODELS`` après une migration ADD COLUMN qui aurait
                # laissé les nouvelles colonnes aux defaults SQL.
                if not existing.manually_overridden:
                    changed = False
                    for field in _CAPABILITY_FIELDS_TO_BACKFILL:
                        new_val = getattr(m, field)
                        if getattr(existing, field) != new_val:
                            setattr(existing, field, new_val)
                            changed = True
                    # cache_ttl_options : conversion tuple → list (JSON)
                    new_ttl = list(m.cache_ttl_options) if m.cache_ttl_options else None
                    if existing.cache_ttl_options != new_ttl:
                        existing.cache_ttl_options = new_ttl
                        changed = True
                    if changed:
                        backfilled += 1
                continue

            row = LlmModel(
                name=m.name,
                provider=m.provider,
                display_name=m.name,
                context_window=m.context_window,
                max_output_tokens=m.max_output_tokens,
                input_price_per_mtok_usd=m.input_price_per_mtok_usd,
                output_price_per_mtok_usd=m.output_price_per_mtok_usd,
                # Capabilities — copiées depuis ``ModelInfo`` (constants_ai)
                # qui est la source unique de vérité pour le seed initial.
                # Les déductions ``m.provider == "anthropic"`` ont été
                # remplacées par des valeurs explicites par modèle dans
                # ``_MODELS`` (plan dynamicité 2026-05-14) — chaque modèle
                # déclare ce qu'il supporte, le seed ne devine plus.
                supports_extended_thinking=m.supports_extended_thinking,
                supports_prompt_caching=m.supports_prompt_caching,
                supports_tool_use=m.supports_tool_use,
                supports_reasoning_effort=m.supports_reasoning_effort,
                supports_parallel_tool_calls=m.supports_parallel_tool_calls,
                supports_streaming=m.supports_streaming,
                supports_vision=m.supports_vision,
                supports_strict_json=m.supports_strict_json,
                tool_call_format=m.tool_call_format,
                system_prompt_format=m.system_prompt_format,
                # ``cache_ttl_options`` est ``tuple[str, ...]`` côté
                # dataclass (frozen+slots) → ``list`` pour la colonne JSON
                # (SQLAlchemy serialize les listes en JSON array).
                cache_ttl_options=list(m.cache_ttl_options) if m.cache_ttl_options else None,
                manually_overridden=False,
            )
            session.add(row)
            added += 1

        if added or backfilled:
            await session.commit()
            if backfilled:
                logger.info(
                    "seed_from_constants: %d row(s) back-fillées (capabilities post-migration "
                    "alignées sur _MODELS, manually_overridden préservé)",
                    backfilled,
                )
        # Warm-up : remplit ``_cache_by_name`` immédiatement après le seed.
        # Sans ça, les helpers sync (``get_max_tokens_sync``,
        # ``get_pricing_sync``, ``constants_ai.get_*_for_model``) retombent
        # sur le fallback static jusqu'au premier appel async — c.-à-d.
        # potentiellement TOUTE LA SESSION si aucun caller async ne déclenche
        # ``_ensure_loaded``. Le warm-up garantit que la BDD est la source
        # de vérité dès le premier call sync post-boot.
        await self.reload_from_db(session)
        self._seeded = True
        return added


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Tolère les formats date renvoyés par les APIs LLM (ISO 8601, epoch).
    Retourne ``None`` si non-parsable plutôt que de lever."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OSError):
            return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


# ── Singleton ────────────────────────────────────────────────────────────


def get_llm_model_registry() -> LlmModelRegistry:
    """Retourne le singleton du registre. Lazy-init au premier appel."""
    if LlmModelRegistry._instance is None:
        LlmModelRegistry._instance = LlmModelRegistry()
    return LlmModelRegistry._instance
