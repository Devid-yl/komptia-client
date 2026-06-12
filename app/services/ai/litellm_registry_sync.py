"""Sync du context_window/max_output_tokens depuis le registre public LiteLLM.

Pourquoi ?
- Anthropic et OpenAI n'exposent pas la fenêtre de contexte via leur API
  ``GET /v1/models``. Les valeurs deviennent vite obsolètes (Opus 4.7 listé
  à 200K alors qu'il supporte 1M).
- LiteLLM maintient un registre public (~2700 modèles) à jour quasi-quotidien
  qui couvre Anthropic, OpenAI, Mistral, Bedrock, etc.
- On enrichit nos modèles BDD avec ces valeurs, en respectant le flag
  ``manually_overridden`` (l'admin garde toujours la main).

Source : https://github.com/BerriAI/litellm/blob/main/model_prices_and_context_window.json
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, Final, List, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import config
from app.models.llm_model import LlmModel

logger = logging.getLogger(__name__)


_LITELLM_REGISTRY_URL = (
    "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
)
# Garde-fou : on n'accepte que HTTPS — pas de fallback HTTP même si la
# constante est modifiée plus tard.
assert _LITELLM_REGISTRY_URL.startswith("https://"), "LiteLLM registry URL doit être HTTPS"
_HTTP_TIMEOUT_SECONDS = 10.0
_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB — protège contre un registre devenu absurde
_CACHE_TTL_SECONDS = 24 * 3600
_USER_AGENT = "Komptia/litellm-registry-sync"

# Bornes anti-aberration sur les valeurs renvoyées par LiteLLM. Si une entrée
# tombe en dehors, on log un warning et on skip (mieux que d'écrire 0 ou 10^9
# en BDD parce qu'un commit foireux du registre amont a échappé à leur revue).
_MIN_CONTEXT_WINDOW = 1_000
_MAX_CONTEXT_WINDOW = 10_000_000
_MIN_MAX_OUTPUT = 256
_MAX_MAX_OUTPUT = 1_000_000
# Bornes pricing (USD per million tokens). Plancher > 0 pour exclure le 0.0
# silencieux ; plafond généreux pour absorber un futur modèle premium sans
# bloquer (mais rejeter une typo type 1e9).
_MIN_PRICE_PER_MTOK = 0.0
_MAX_PRICE_PER_MTOK = 1_000.0
_TOKENS_PER_MTOK = 1_000_000.0

# Lock module-level : un seul sync à la fois, peu importe combien d'admins
# cliquent. Sans ça : 2 fetch parallèles vers GitHub, double commit BDD,
# stats non-déterministes (admin A voit "5 updated", admin B voit "0").
_SYNC_LOCK: asyncio.Lock = asyncio.Lock()


def _cache_dir() -> Path:
    return config.data_dir / "cache"


def _cache_path() -> Path:
    """Chemin unique du cache (registry + fetched_at combinés).

    Un seul fichier → un seul ``replace()`` atomique → pas de désync
    possible entre la valeur et son timestamp. La version précédente
    avait deux fichiers et un kill entre les deux renames pouvait
    faire croire le système qu'un registry obsolète est frais (et
    inversement). Cf. review adversariale 2026-05-05.
    """
    return _cache_dir() / "litellm_registry.json"


def _read_cache() -> tuple[Optional[Dict[str, Any]], Optional[float]]:
    """Lit le cache disque. Retourne (registry, fetched_at_unix) ou (None, None).

    Fail-soft : toute erreur de lecture (corruption, permissions) → (None, None).
    """
    try:
        raw = _cache_path().read_text(encoding="utf-8")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return None, None
        registry = payload.get("registry")
        if not isinstance(registry, dict):
            return None, None
        fetched_at = float(payload.get("fetched_at", 0))
        return registry, fetched_at
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None, None


def _write_cache(registry: Dict[str, Any]) -> None:
    """Écrit le cache disque atomiquement (write tmp + rename, **un seul**
    fichier). Fail-soft."""
    try:
        _cache_dir().mkdir(parents=True, exist_ok=True)
        tmp = _cache_path().with_suffix(".json.tmp")
        payload = {"fetched_at": time.time(), "registry": registry}
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(_cache_path())
    except OSError as exc:  # noqa: BLE001 — fail-soft, on log seulement
        logger.warning("LiteLLM registry: échec écriture cache: %s", exc)


def _baseline_path() -> Path:
    """Snapshot read-only du registre, EMBARQUÉ avec le code sous ``app/``.

    SOUS ``app/`` (et non ``data/cache/``) à dessein : le cache mutable vit
    sous ``data/`` qui est exclu de l'image Docker ET masqué par le volume
    ``komptia-data`` (vide sur un client neuf). Sur un client qui ne peut pas
    joindre GitHub (réseau filtré/isolé), le fetch live échoue et il n'y a
    aucun cache disque → sans cette baseline, le pricing resterait à 0 et
    ``/admin/usage`` afficherait 0 $ indéfiniment (denial-of-wallet masqué).
    La baseline est embarquée auto (``COPY app/`` + rsync ``/app/***``) et
    rafraîchie par ``scripts/refresh_litellm_cache.py`` (maintenance/CI).
    """
    return Path(__file__).resolve().parent / "data" / "litellm_registry.json"


def _read_baseline() -> Optional[Dict[str, Any]]:
    """Lit la baseline embarquée (registre LiteLLM brut). Fail-soft → None.

    Format : le registre brut ``{model_name: meta}`` directement (pas
    l'enveloppe ``{fetched_at, registry}`` du cache mutable) — il n'a pas de
    notion de fraîcheur, c'est un fallback de dernier recours.
    """
    try:
        raw = _baseline_path().read_text(encoding="utf-8")
        data = json.loads(raw)
        if isinstance(data, dict) and data:
            return data
        return None
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        return None


async def refresh_baseline_from_live() -> int:
    """Fetch le registre live et l'écrit dans la baseline embarquée.

    Utilisé par ``scripts/refresh_litellm_cache.py`` (maintenance/CI, réseau
    requis). Réutilise ``_http_fetch_registry`` (même validation/sécurité que
    le runtime — source unique). Lève ``RuntimeError`` si le fetch échoue
    (signal honnête : ne pas écraser une baseline valide par du vide).
    Retourne le nombre de modèles écrits.
    """
    fresh = await _http_fetch_registry()
    if not fresh:
        raise RuntimeError("fetch LiteLLM live échoué — réseau requis pour rafraîchir la baseline")
    path = _baseline_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    # ``sort_keys`` : diff git lisible et déterministe d'un refresh à l'autre.
    tmp.write_text(json.dumps(fresh, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    _reset_public_pricing_cache()  # la baseline a changé → re-évaluer les verdicts
    return len(fresh)


# ──────────────────────────────────────────────────────────────────────────
# Oracle « ce modèle DEVRAIT-il coûter de l'argent ? » (consommé par
# ``llm_call_tracker`` pour ne pas masquer un modèle payant non-enrichi en 0 $).
# ──────────────────────────────────────────────────────────────────────────

# Caches module : le registre chargé (lazy, ~2 Mo parsé UNE fois) + le verdict
# par modèle. Le prix catalogue d'un modèle est un fait stable en cours de
# process → pas d'invalidation runtime nécessaire pour la correction du coût ;
# ``_reset_public_pricing_cache`` existe pour le refresh baseline et les tests.
_public_pricing_registry: Optional[Dict[str, Any]] = None
_public_pricing_verdict: Dict[str, bool] = {}


def _reset_public_pricing_cache() -> None:
    """Vide les caches de ``public_model_is_priced`` (tests / refresh baseline)."""
    global _public_pricing_registry
    _public_pricing_registry = None
    _public_pricing_verdict.clear()


def public_model_is_priced(model_name: str) -> bool:
    """``True`` si le registre public LiteLLM tarife ``model_name`` (input OU
    output cost > 0). Oracle générique, SOURCE DE VÉRITÉ pricing du projet
    (pas de ``provider == "ollama"`` hardcodé).

    Source : cache mutable (``_read_cache``) puis baseline embarquée
    (``_read_baseline``). Mémoïse le registre chargé ET le verdict par modèle
    (O(1) après le 1er lookup d'un modèle donné — protège le hot-path quand
    beaucoup d'appels portent sur des modèles à pricing 0/0).

    Robuste : toute erreur → ``False`` (ne jamais PRÉTENDRE qu'un modèle est
    tarifé si on n'en est pas certain).

    LIMITE ASSUMÉE : un modèle ABSENT du registre public (Ollama/local, ou
    modèle trop récent pas encore dans la baseline) → ``False``. On ne peut pas
    inventer un prix inexistant ; mitigé par ``make refresh-litellm``.
    """
    if not model_name:
        return False
    cached = _public_pricing_verdict.get(model_name)
    if cached is not None:
        return cached
    verdict = False
    try:
        global _public_pricing_registry
        if _public_pricing_registry is None:
            reg, _ = _read_cache()
            if not reg:
                reg = _read_baseline()
            _public_pricing_registry = reg or {}
        registry = _public_pricing_registry
        if registry:
            entry = _lookup_registry_entry(registry, model_name)
            if entry:
                verdict = (entry.get("input_cost_per_token") or 0) > 0 or (
                    entry.get("output_cost_per_token") or 0
                ) > 0
    except Exception:  # noqa: BLE001 — oracle best-effort, jamais bloquant
        verdict = False
    _public_pricing_verdict[model_name] = verdict
    return verdict


def _sanitize_log_snippet(s: str, max_len: int = 200) -> str:
    """Neutralise les caractères de contrôle (CR/LF/CTRL) avant d'interpoler
    dans un log — anti CWE-117 (log forging) si la réponse upstream est
    compromise (DNS hijack, registry corrompu)."""
    cleaned = "".join("?" if (ord(c) < 32 or ord(c) == 127) else c for c in s)
    return cleaned[:max_len]


async def _http_fetch_registry() -> Optional[Dict[str, Any]]:
    """HTTP GET du JSON public, retourne dict parsé ou None sur échec.

    Defense-in-depth :
    - ``follow_redirects=False`` : un attaquant qui contrôle le DNS ne peut
      pas rediriger vers son endpoint (httpx default est False mais on est
      explicite — ne dépend pas de la version).
    - ``trust_env=False`` : ignore HTTPS_PROXY/HTTP_PROXY env (un proxy
      attaquant ne peut pas intercepter).
    - Cap taille à _MAX_BODY_BYTES, timeout 10s, User-Agent explicite.
    - Logs sanitize les snippets venant de la réponse (anti log-forging).
    """
    try:
        async with httpx.AsyncClient(
            timeout=_HTTP_TIMEOUT_SECONDS,
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=False,
            trust_env=False,
        ) as client:
            resp = await client.get(_LITELLM_REGISTRY_URL)
        if resp.status_code != 200:
            logger.warning(
                "LiteLLM registry HTTP %d: %s",
                resp.status_code,
                _sanitize_log_snippet(resp.text),
            )
            return None
        if len(resp.content) > _MAX_BODY_BYTES:
            logger.warning(
                "LiteLLM registry payload trop gros (%d bytes > %d), skip.",
                len(resp.content),
                _MAX_BODY_BYTES,
            )
            return None
        data = resp.json()
        if not isinstance(data, dict):
            logger.warning("LiteLLM registry: JSON racine n'est pas un dict, skip.")
            return None
        return data
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        logger.warning("LiteLLM registry: fetch échoué (%s).", _sanitize_log_snippet(str(exc)))
        return None


async def fetch_litellm_registry(*, force_refresh: bool = False) -> Dict[str, Any]:
    """Retourne le registre LiteLLM (dict ``{model_name: meta}``).

    Stratégie :
    1. Si cache disque < 24h ET pas ``force_refresh`` → utilise cache (0 HTTP).
    2. Sinon HTTP GET, écrit le cache, retourne le résultat.
    3. Si HTTP échoue ET cache disque présent (même périmé) → utilise cache.
    4. Si HTTP échoue ET pas de cache → retourne ``{}`` (caller fail-soft).
    """
    cached, fetched_at = _read_cache()
    age = (time.time() - fetched_at) if fetched_at else float("inf")
    if cached is not None and age < _CACHE_TTL_SECONDS and not force_refresh:
        return cached
    fresh = await _http_fetch_registry()
    if fresh is not None:
        _write_cache(fresh)
        return fresh
    if cached is not None:
        logger.warning(
            "LiteLLM registry: utilisation cache stale (%.0fh) — fetch a échoué.",
            age / 3600,
        )
        return cached
    # Dernier recours : la baseline embarquée (client offline, jamais de cache
    # mutable). Évite le 0 $ silencieux sur /admin/usage (l'enrichissement
    # pricing au boot retombe dessus). Pricing potentiellement périmé →
    # rafraîchir via `python -m scripts.refresh_litellm_cache`.
    baseline = _read_baseline()
    if baseline is not None:
        logger.warning(
            "LiteLLM registry: fetch HTTP échoué et aucun cache disque — "
            "fallback sur la baseline embarquée (%d modèles, pricing "
            "potentiellement périmé).",
            len(baseline),
        )
        return baseline
    return {}


_PREFIX_BOUNDARY_CHARS = frozenset("-._/@:")


def _is_prefix_with_boundary(name: str, key: str) -> bool:
    """Vérifie ``name.startswith(key)`` AVEC garde-fou : le caractère qui suit
    le préfixe doit être un séparateur ou la fin de la chaîne. Sans ça,
    ``gpt-4o`` matcherait ``gpt-4`` à tort si jamais ``gpt-4`` était dans le
    registre — l'admin verrait alors les valeurs de gpt-4 (8K) appliquées
    à gpt-4o (128K). Cf. review adversariale (DRY/safety).
    """
    if not name.startswith(key):
        return False
    if len(name) == len(key):
        return True
    return name[len(key)] in _PREFIX_BOUNDARY_CHARS


def _lookup_registry_entry(registry: Dict[str, Any], model_name: str) -> Optional[Dict[str, Any]]:
    """Cherche un modèle : exact match, sinon longest-prefix-with-boundary
    match (≥5 chars). Le boundary check évite qu'un modèle dont le nom est
    strict-prefix d'un autre vole ses valeurs.
    """
    entry = registry.get(model_name)
    if isinstance(entry, dict):
        return entry
    best_key: Optional[str] = None
    for key in registry:
        if not isinstance(key, str) or len(key) < 5:
            continue
        if _is_prefix_with_boundary(model_name, key) and (
            best_key is None or len(key) > len(best_key)
        ):
            best_key = key
    if best_key is None:
        return None
    candidate = registry.get(best_key)
    return candidate if isinstance(candidate, dict) else None


def _validate_int_in_range(value: Any, lo: int, hi: int) -> Optional[int]:
    """Coerce et borne ; retourne ``None`` si hors plage ou non-numérique."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n < lo or n > hi:
        return None
    return n


def _validate_float_in_range(value: Any, lo: float, hi: float) -> Optional[float]:
    """Coerce float et borne ; retourne ``None`` si hors plage."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f < lo or f > hi:
        return None
    return f


def _convert_per_token_to_per_mtok(value: Any) -> Optional[float]:
    """LiteLLM expose ``input_cost_per_token`` / ``output_cost_per_token`` en
    USD/token. Komptia stocke en USD/Mtok. Conversion + bornes.
    """
    f = _validate_float_in_range(value, 0.0, _MAX_PRICE_PER_MTOK / _TOKENS_PER_MTOK)
    if f is None:
        return None
    return f * _TOKENS_PER_MTOK


async def enrich_models_from_litellm(
    session: AsyncSession,
    *,
    force_refresh: bool = False,
    allow_regression: bool = False,
) -> Dict[str, Any]:
    """Enrichit ``context_window``, ``max_output_tokens`` et le pricing
    (input/output USD/Mtok) des LlmModel non-deprecated et non
    manually_overridden depuis le registre LiteLLM. Logue chaque diff,
    retourne stats détaillées.

    Sécurités :
    - Bornes anti-aberration : valeurs hors [_MIN_*, _MAX_*] → skip + log.
    - **Fail-closed sur régression amont** : si la valeur du registre est
      PLUS PETITE que celle en BDD, on SKIP par défaut (compteur
      ``skipped_regression``). L'admin peut forcer via
      ``allow_regression=True`` après inspection. Doctrine : un commit
      foireux upstream ne doit pas dégrader silencieusement les capacités
      en prod.
    - Concurrence : protégée par un lock module-level (un seul sync à la
      fois, peu importe combien d'admins cliquent).
    """
    async with _SYNC_LOCK:
        return await _enrich_locked(
            session, force_refresh=force_refresh, allow_regression=allow_regression
        )


async def _enrich_locked(
    session: AsyncSession,
    *,
    force_refresh: bool,
    allow_regression: bool,
) -> Dict[str, Any]:
    registry = await fetch_litellm_registry(force_refresh=force_refresh)
    stats: Dict[str, Any] = {
        "fetched_entries": len(registry),
        "scanned": 0,
        "updated": 0,
        "skipped_overridden": 0,
        "skipped_unknown": 0,
        "skipped_invalid": 0,
        "skipped_regression": 0,
        "diffs": [],
    }
    if not registry:
        stats["error"] = "registry vide (fetch + cache indisponibles)"
        return stats

    rows = (
        (await session.execute(select(LlmModel).where(LlmModel.deprecated_at.is_(None))))
        .scalars()
        .all()
    )

    for row in rows:
        stats["scanned"] += 1
        if row.manually_overridden:
            stats["skipped_overridden"] += 1
            continue
        entry = _lookup_registry_entry(registry, row.name)
        if entry is None:
            stats["skipped_unknown"] += 1
            continue
        # Match EXACT (clé présente telle quelle) vs PRÉFIXE (modèle voisin).
        # Seul l'exact autorise la confirmation de fenêtre — cf. _compute_diff.
        is_exact = row.name in registry
        diff = _compute_diff(
            row,
            entry,
            allow_regression=allow_regression,
            stats=stats,
            is_exact_match=is_exact,
        )
        if diff is None:
            continue
        stats["updated"] += 1
        stats["diffs"].append(diff)
        logger.info("LiteLLM enrich: %s → %s", row.name, diff)

    if stats["updated"]:
        await session.commit()

    # Sync Ollama : LiteLLM ne connaît qu'une partie des modèles locaux
    # (29 sur ~3500 disponibles via Ollama). Pour les modèles que l'admin
    # a téléchargés (``ollama pull phi3:mini`` etc.), on enrichit le registre
    # via ``/api/show`` qui expose ``<arch>.context_length``. Ainsi le bouton
    # « Mettre à jour fenêtres & tarifs » couvre cloud + local en 1 clic.
    try:
        ollama_stats = await _enrich_from_ollama(session, allow_regression=allow_regression)
        stats["ollama"] = ollama_stats
    except Exception as exc:  # noqa: BLE001
        # Non-bloquant : si Ollama down ou non configuré, on a déjà fait
        # le sync LiteLLM, c'est mieux que rien.
        logger.warning("Sync Ollama échec (non bloquant) : %s", exc)
        stats["ollama"] = {"error": str(exc)}

    return stats


async def _enrich_from_ollama(
    session: AsyncSession,
    *,
    allow_regression: bool,
) -> Dict[str, Any]:
    """Sync les modèles Ollama configurés en BDD via ``/api/tags`` + ``/api/show``.

    Algorithme :

    1. Lit ``local_llm_enabled`` + ``local_llm_base_url`` (config admin).
       Si désactivé → skip propre.
    2. ``GET <base>/api/tags`` pour lister les modèles installés.
    3. Pour chaque modèle : ``POST <base>/api/show {"name": "<m>"}`` qui
       retourne le ``model_info`` (clés ``<arch>.context_length``, ex:
       ``phi3.context_length: 131072``, ``llama.context_length: 8192``).
    4. Upsert dans ``LlmModel`` :
       - ``context_window`` = ``<arch>.context_length`` (extrait via suffix match)
       - ``max_output_tokens`` = ``min(ctx_window, 8192)`` (Ollama ne distingue
         pas input/output ; on cap à 8k pour éviter une génération sans fin)
       - ``provider = "ollama"``, prices = 0 (local = gratuit)
       - ``manually_overridden`` préservé (jamais écrasé si admin l'a coché)
    5. Best-effort par modèle : un /api/show qui rate (modèle corrompu)
       skip le modèle, log warning, continue avec les autres.

    Returns:
        Dict stats ``{enabled, scanned, upserted, skipped_overridden,
        skipped_missing_caps, errors}``.
    """
    from app.services.ai.config_service import default_local_llm_base_url, get_ai_config_service

    cs = get_ai_config_service()
    enabled = bool(await cs.get("local_llm_enabled"))
    if not enabled:
        return {"enabled": False, "skipped": "local_llm_disabled"}

    base_url = (await cs.get("local_llm_base_url")) or default_local_llm_base_url()
    # Ollama natif tourne sur /api/* (pas /v1/*). Strip le suffixe /v1 si
    # présent (l'admin configure l'URL OpenAI-compat dans /admin/ai-config).
    ollama_base = base_url.rstrip("/")
    if ollama_base.endswith("/v1"):
        ollama_base = ollama_base[:-3]

    stats: Dict[str, Any] = {
        "enabled": True,
        "base_url": ollama_base,
        "scanned": 0,
        "upserted": 0,
        "skipped_overridden": 0,
        "skipped_missing_caps": 0,
        "errors": [],
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            tags_resp = await client.get(f"{ollama_base}/api/tags")
            tags_resp.raise_for_status()
            tags_data = tags_resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            stats["errors"].append(f"/api/tags: {exc}")
            return stats

        models_list = tags_data.get("models") or []
        for m in models_list:
            if not isinstance(m, dict):
                continue
            model_name = m.get("name") or m.get("model")
            if not isinstance(model_name, str) or not model_name.strip():
                continue
            stats["scanned"] += 1

            try:
                show_resp = await client.post(
                    f"{ollama_base}/api/show",
                    json={"name": model_name},
                )
                show_resp.raise_for_status()
                show_data = show_resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                stats["errors"].append(f"/api/show {model_name}: {exc}")
                continue

            # Extrait ``<arch>.context_length`` du model_info. Les architectures
            # connues : phi3, llama, gemma, mistral, qwen, deepseek… On scanne
            # toutes les clés qui finissent par ``.context_length`` (sans
            # hardcoder l'arch) et on prend la plus grande (au cas où il y en
            # ait plusieurs — défensif).
            model_info = show_data.get("model_info") or {}
            ctx_candidates: List[int] = []
            if isinstance(model_info, dict):
                for k, v in model_info.items():
                    if (
                        isinstance(k, str)
                        and k.endswith(".context_length")
                        and isinstance(v, int)
                        and v > 0
                    ):
                        ctx_candidates.append(v)
            if not ctx_candidates:
                stats["skipped_missing_caps"] += 1
                continue
            ctx = max(ctx_candidates)
            # ``max_output`` : Ollama ne distingue pas. On prend min(ctx, 8192)
            # pour éviter qu'un caller demande 128k de génération qui prendrait
            # des heures sur CPU. L'admin peut override via
            # ``manually_overridden=True`` dans /admin/ai-models s'il a un GPU.
            max_out = min(ctx, 8192)

            # Upsert dans LlmModel
            existing = (
                await session.scalars(select(LlmModel).where(LlmModel.name == model_name))
            ).first()
            if existing is not None:
                if existing.manually_overridden:
                    stats["skipped_overridden"] += 1
                    continue
                # Régression check : ne pas dégrader la BDD sauf si demandé.
                old_ctx = int(existing.context_window or 0)
                if old_ctx > ctx and not allow_regression:
                    continue
                existing.context_window = ctx
                existing.max_output_tokens = max_out
                # Fenêtre lue depuis ``/api/show`` (``<arch>.context_length``) =
                # source fiable → vérifiée (pas de « à confirmer » sur un modèle
                # Ollama dont la fenêtre est connue).
                existing.context_window_verified = True
                if not existing.provider:
                    existing.provider = "ollama"
                stats["upserted"] += 1
            else:
                session.add(
                    LlmModel(
                        name=model_name,
                        provider="ollama",
                        context_window=ctx,
                        max_output_tokens=max_out,
                        input_price_per_mtok_usd=0.0,
                        output_price_per_mtok_usd=0.0,
                        context_window_verified=True,
                    )
                )
                stats["upserted"] += 1

    if stats["upserted"]:
        await session.commit()
        # Invalide + reload le cache mémoire du registre. Sans ça, les
        # rows fraîchement upsertées (pricing=0 pour les modèles Ollama
        # gratuits, context_window découvert via /api/show) ne sont PAS
        # visibles depuis ``_registry_cache_lookup`` — la dashboard
        # /api/ai/usage continue de warner "Pricing inconnu" alors que
        # la BDD contient bien ``input_price_per_mtok_usd=0.0``. Pattern
        # cohérent avec ``LlmModelRegistry.enrich_from_litellm`` (qui
        # invalide+reload après son propre upsert).
        try:
            from app.services.ai.llm_model_registry import LlmModelRegistry

            instance = LlmModelRegistry._instance
            if instance is not None:
                instance.invalidate()
                await instance.reload_from_db(session)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "_enrich_from_ollama: invalidation cache registre échec "
                "(non-bloquant) — pricing/context_window des modèles Ollama "
                "ne sera visible qu'après reboot. Erreur: %s",
                exc,
            )
    return stats


def _compute_diff(
    row: LlmModel,
    entry: Dict[str, Any],
    *,
    allow_regression: bool,
    stats: Dict[str, Any],
    is_exact_match: bool = False,
) -> Optional[Dict[str, Any]]:
    """Calcule + applique les changements pour une ligne. ``None`` si rien
    à mettre à jour ou si toutes les valeurs candidates sont invalides.

    ``is_exact_match`` : True ssi ``entry`` provient d'un match EXACT du nom
    (pas d'un longest-prefix-match vers un modèle voisin). Conditionne le
    marquage ``context_window_verified`` (fail-closed par défaut : False)."""
    new_cw = _validate_int_in_range(
        entry.get("max_input_tokens"), _MIN_CONTEXT_WINDOW, _MAX_CONTEXT_WINDOW
    )
    new_max_out = _validate_int_in_range(
        entry.get("max_output_tokens"), _MIN_MAX_OUTPUT, _MAX_MAX_OUTPUT
    )
    new_in_price = _convert_per_token_to_per_mtok(entry.get("input_cost_per_token"))
    new_out_price = _convert_per_token_to_per_mtok(entry.get("output_cost_per_token"))
    new_cache_read_price = _convert_per_token_to_per_mtok(entry.get("cache_read_input_token_cost"))
    new_cache_creation_price = _convert_per_token_to_per_mtok(
        entry.get("cache_creation_input_token_cost")
    )
    if all(
        v is None
        for v in (
            new_cw,
            new_max_out,
            new_in_price,
            new_out_price,
            new_cache_read_price,
            new_cache_creation_price,
        )
    ):
        stats["skipped_invalid"] += 1
        return None

    diff: Dict[str, Any] = {"name": row.name, "provider": row.provider}
    changed = False

    def _maybe_apply_int(field: str, new_val: Optional[int]) -> None:
        nonlocal changed
        old = getattr(row, field)
        if new_val is None or new_val == old:
            return
        if new_val < old and not allow_regression:
            logger.warning(
                "LiteLLM enrich: %s.%s régression %d → %d ignorée (allow_regression=False).",
                row.name,
                field,
                old,
                new_val,
            )
            stats["skipped_regression"] += 1
            return
        diff[field] = {"old": old, "new": new_val}
        setattr(row, field, new_val)
        changed = True

    def _maybe_apply_price(field: str, new_val: Optional[float]) -> None:
        nonlocal changed
        old = getattr(row, field) or 0.0
        if new_val is None:
            return
        # Tolérance flottante : 1e-6 USD/Mtok ≈ négligeable
        if abs(new_val - old) < 1e-6:
            return
        diff[field] = {"old": old, "new": new_val}
        setattr(row, field, new_val)
        changed = True

    _maybe_apply_int("context_window", new_cw)
    _maybe_apply_int("max_output_tokens", new_max_out)
    _maybe_apply_price("input_price_per_mtok_usd", new_in_price)
    _maybe_apply_price("output_price_per_mtok_usd", new_out_price)
    _maybe_apply_price("cache_read_price_per_mtok_usd", new_cache_read_price)
    _maybe_apply_price("cache_creation_price_per_mtok_usd", new_cache_creation_price)

    # Confirmation de la fenêtre de contexte — FAIL-CLOSED (revue adversariale
    # 2026-06-03). On ne marque ``verified=True`` QUE si les DEUX conditions
    # tiennent :
    #   (a) ``is_exact_match`` : la fenêtre vient d'un match EXACT du nom dans
    #       LiteLLM — un longest-prefix-match donne la fenêtre d'un modèle
    #       VOISIN (ex. ``...-20260101`` résolu vers le préfixe nu), pas du
    #       modèle exact → on ne peut pas affirmer qu'elle est juste ;
    #   (b) ``row.context_window == new_cw`` : la fenêtre stockée correspond
    #       bien à celle annoncée par LiteLLM. Exclut le cas anti-régression
    #       où ``_maybe_apply_int`` a CONSERVÉ une valeur provisoire (200K)
    #       que LiteLLM contredit (fenêtre plus petite) — confirmer ce 200K
    #       reviendrait à estampiller « vérifié » un chiffre faux.
    # Hors de ces cas, la fenêtre reste « à confirmer » côté UI (honnête)
    # plutôt qu'un faux positif. Un modèle découvert à 200K provisoire dont
    # LiteLLM connaît la VRAIE fenêtre (appliquée) passe bien vérifié.
    if (
        new_cw is not None
        and is_exact_match
        and row.context_window == new_cw
        and not row.context_window_verified
    ):
        row.context_window_verified = True
        diff["context_window_verified"] = {"old": False, "new": True}
        changed = True

    # Plan dynamicité 2026-05-14 option B : déduction des 5 flags Komptia-
    # spécifiques que LiteLLM ne couvre pas (extended_thinking,
    # reasoning_effort, tool_call_format, system_prompt_format,
    # cache_ttl_options + supports_streaming en bonus). Localisée à la
    # couche sync — JAMAIS d'`if provider_name == "anthropic"` dans le
    # runtime métier (cf. ``test_no_provider_name_eq_string_in_business_code``).
    # Garantit que tout modèle ajouté via sync (LiteLLM ou provider native)
    # reçoit des valeurs raisonnables au lieu des defaults SQL qui seraient
    # FAUX pour Anthropic (tool_call_format default="openai").
    _deduce_komptia_flags(row, diff)
    if any(
        k.startswith("supports_") or k.endswith("_format") or k == "cache_ttl_options" for k in diff
    ):
        changed = True

    return diff if changed else None


# Defaults SQL des 6 champs Komptia-spécifiques (cf. app/models/llm_model.py).
# La déduction n'écrase un champ QUE s'il est au default — sinon l'admin a
# choisi une valeur (via PATCH override OU seed _MODELS avec override
# explicite). Évite la régression "Bedrock-via-OpenAI-compat qui marche
# devient cassé après sync" (review adversariale 2026-05-14 BLOCKING #1).
_FIELD_DEFAULT_SQL: Final[Dict[str, Any]] = {
    "tool_call_format": "openai",
    "system_prompt_format": "string",
    "supports_extended_thinking": False,
    "supports_reasoning_effort": False,
    "supports_streaming": True,
    # ``cache_ttl_options`` colonne JSON NULL par défaut. ``[]`` vs ``None``
    # vs ``()`` (frozen dataclass) — normalisé en ``[]`` côté lecture.
    "cache_ttl_options": None,
}

# Regex word-boundary pour matcher les modèles reasoning OpenAI (o1/o3/o4/
# gpt-5/gpt-6) SANS faux positif sur "co1lab", "do1phin", "openrouter/o1"
# etc. Cf. review adversariale 2026-05-14 BLOCKING #2.
_OPENAI_REASONING_PATTERN: Final = re.compile(r"(?:^|[-_/])(?:o[134]|gpt-[56])(?:[-_/]|$)")

# Restreint le cache TTL 1h aux modèles Anthropic qui le supportent réellement
# (introduit avec Sonnet 3.5+ et Opus 4+). Cf. review adversariale 2026-05-14
# CRITICAL #6 — éviter d'envoyer ``ttl=1h`` à un Sonnet 3 legacy qui rejette.
_ANTHROPIC_1H_CACHE_PATTERN: Final = re.compile(r"(?:sonnet-(?:3-5|3-7|4|5)|opus-(?:4|5))")


def _deduce_komptia_flags(row: LlmModel, diff: Dict[str, Any]) -> None:
    """Pose les 6 flags Komptia-spécifiques que LiteLLM n'expose pas.

    **Idempotent + non-destructif** : ne modifie un flag QUE si sa valeur
    courante == default SQL (= jamais touchée par seed `_MODELS` override
    ou admin PATCH). ``manually_overridden=True`` est déjà filtré côté
    caller (``_enrich_locked``), mais on ajoute ici un garde-fou champ-
    par-champ pour les overrides partiels (proxy Anthropic-via-OpenAI-
    compat avec ``tool_call_format="openai"`` volontaire, etc.). Cf.
    review adversariale 2026-05-14.

    Déduction par ``(provider, name)`` :
    - **Anthropic** Sonnet 3.5+/Opus 4+ : tool_call=anthropic, system=array,
      cache_ttl=["5m","1h"], extended_thinking=True.
    - **Anthropic** Haiku, Sonnet 3, Opus 3 : cache_ttl=["5m"] (pas de 1h),
      extended_thinking=False pour Haiku.
    - **OpenAI** : tool_call=openai, system=string, reasoning_effort=True
      pour o1/o3/o4/gpt-5/gpt-6 (regex word-boundary).
    - **Autres (Mistral, Groq, DeepSeek, Together, Gemini-compat)** :
      tool_call=openai (format universel), system=string, cache_ttl=[].
    - **Streaming** : True partout (tous les providers majeurs supportent
      SSE). Cas exotique (modèle batch-only) à override admin manuel.
    """
    provider = (row.provider or "").lower().strip()
    name_lower = (row.name or "").lower()

    if provider == "anthropic":
        new_tool_format = "anthropic"
        new_system_format = "array"
        # Haiku ne supporte pas extended_thinking. Sonnet/Opus oui.
        new_extended_thinking = ("opus" in name_lower or "sonnet" in name_lower) and (
            "haiku" not in name_lower
        )
        new_reasoning_effort = False
        # TTL 1h supporté uniquement sur Sonnet 3.5+/Opus 4+ (cf. release
        # notes Anthropic 2024-12 prompt caching v2). Sonnet 3 legacy →
        # 5m only.
        if _ANTHROPIC_1H_CACHE_PATTERN.search(name_lower):
            new_cache_ttl = ["5m", "1h"]
        else:
            new_cache_ttl = ["5m"]
    elif provider == "openai":
        new_tool_format = "openai"
        new_system_format = "string"
        new_extended_thinking = False
        new_reasoning_effort = bool(_OPENAI_REASONING_PATTERN.search(name_lower))
        new_cache_ttl = []
    else:
        # Mistral, Groq, DeepSeek, Together, Gemini-compat, Ollama, etc.
        new_tool_format = "openai"
        new_system_format = "string"
        new_extended_thinking = False
        new_reasoning_effort = False
        new_cache_ttl = []

    new_streaming = True

    def _maybe_set_if_default(field: str, new_val: Any) -> None:
        """Pose ``new_val`` UNIQUEMENT si la valeur courante == default SQL.
        Respecte les overrides partiels admin/seed (cf. BLOCKING #1).

        **Pré-flush SQLAlchemy** : une row fraîchement construite via
        ``LlmModel(...)`` sans passer ce champ retourne ``None`` (les
        defaults SQL ne sont posés qu'au flush). ``None`` est donc traité
        comme équivalent au default — sinon la fonction skip toute pose
        de flag pour les nouveaux modèles insérés via
        ``sync_from_provider`` (review adversariale 2026-05-14 BLOCKING #1).
        """
        old = getattr(row, field, None)
        default = _FIELD_DEFAULT_SQL[field]
        # Normalisation `cache_ttl_options` : None / [] / () traités comme
        # "défaut" (= jamais touché). Évite les 3 représentations divergentes.
        if field == "cache_ttl_options":
            old_normalized = list(old) if old else []
            default_normalized = list(default) if default else []
            if old_normalized != default_normalized:
                return  # admin a posé une valeur, on respecte
        else:
            # ``None`` (pré-flush) traité comme equivalent au default :
            # row jamais flush → attribute non posé → admin n'a évidemment
            # rien touché. On peut écrire en sécurité.
            is_default = (old is None) or (old == default)
            if not is_default:
                return
        if old == new_val:
            return
        diff[field] = {"old": old, "new": new_val}
        setattr(row, field, new_val)

    _maybe_set_if_default("tool_call_format", new_tool_format)
    _maybe_set_if_default("system_prompt_format", new_system_format)
    _maybe_set_if_default("supports_extended_thinking", new_extended_thinking)
    _maybe_set_if_default("supports_reasoning_effort", new_reasoning_effort)
    _maybe_set_if_default("supports_streaming", new_streaming)
    # cache_ttl_options : normaliser ``[]`` au lieu de ``None`` pour éviter
    # les 3 représentations divergentes (CRITICAL #10 review).
    _maybe_set_if_default("cache_ttl_options", new_cache_ttl if new_cache_ttl else [])
