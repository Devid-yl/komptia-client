"""Token budget limits per LLM model — wrapper léger autour du registre
unique ``app.constants_ai`` (qui peut lui-même être backé par la BDD via
``LlmModelRegistry`` à terme).

**Source unique de vérité** : ``constants_ai.get_context_window_for_model``
et ``constants_ai.get_max_tokens_for_model``. Aucune liste de modèles
n'est dupliquée ici — le report generator hérite automatiquement des
mises à jour faites dans le registre central (ou en BDD via la sync admin).

Ce module reste utile pour :
- ``estimate_tokens`` : heuristique légère (4 chars ≈ 1 token) qui ne
  dépend d'aucun provider et reste indépendante du tokenizer exact.
- ``get_active_model_limits`` : aggrège ``context_window`` (du registre)
  et ``max_output_tokens`` (du registre aussi) pour calculer le budget
  utilisable par les rapports.
"""

from __future__ import annotations

from typing import Any, Dict

from app.constants_ai import (
    get_context_window_for_model,
    get_max_tokens_for_model,
)
from app.services.ai.config_service import get_ai_config_service
from app.services.ai.model_display import model_display_name
from app.utils.logger import get_logger

logger = get_logger(__name__)


# Réservation pour l'overhead du prompt (system + schema + instructions
# techniques). Volontairement petit : la majorité du budget input doit
# pouvoir partir au LLM. Si un futur prompt monte significativement, c'est
# qu'il faut refactorer le prompt — pas augmenter cette constante.
_PROMPT_OVERHEAD = 2_000


async def get_active_model_limits() -> Dict[str, Any]:
    """Retourne le budget tokens du modèle LLM actif (lu depuis la BDD).

    Utilise le registre central ``constants_ai`` pour résoudre
    ``context_window`` et ``max_output_tokens`` — ainsi un changement de
    pricing/window dans le registre (ou en BDD via la sync admin) se
    propage automatiquement à toutes les utilisations.

    **Fail-closed sur "rien configuré"** : si AUCUN provider n'est chargé
    par le ``LLMManager`` (= pas d'``api_key`` dans ``/admin/ai-config``),
    on retourne ``configured=False`` plutôt que ``ANTHROPIC_DEFAULT_MODEL``
    silencieusement. Sans ça, l'UI /reports affichait
    « Modèle : claude-haiku-4-5-... » alors que ``/admin/ai-config``
    indiquait correctement « Aucun provider configuré » — incohérence qui
    laissait l'utilisateur tenter une génération vouée à l'échec.

    Returns:
        dict avec :
            - model: str | None (None si aucun provider configuré)
            - configured: bool (True ssi un provider est chargé)
            - context_window: int (0 si non configuré)
            - reserved_output: int (0 si non configuré)
            - reserved_overhead: int (toujours ``_PROMPT_OVERHEAD``)
            - max_input_tokens: int (0 si non configuré)
    """
    # ⚠️ Avant de sonder le manager : forcer la première initialisation
    # depuis la BDD si elle n'a pas encore eu lieu. Sans ce ``await``, un
    # premier appel /api/reports/llm-limits juste après le boot voyait un
    # manager vide et retournait `configured=False` alors que tout est OK
    # côté config admin. Idempotent (guard interne ``_providers_initialized_from_db``).
    from app.services.ai.llm_providers import ensure_providers_from_db, get_llm_manager

    try:
        await ensure_providers_from_db()
    except Exception as e:  # noqa: BLE001 — on retombe sur le sonde ci-dessous
        logger.warning("ensure_providers_from_db failed (continuing): %s", e)

    model_name = ""
    try:
        config = await get_ai_config_service().get_all()
        model_name = config.get("primary_model") or ""
    except Exception as e:
        logger.warning("Could not load LLM config for limits: %s", e)

    # Sonde le manager pour distinguer "rien configuré" (pas d'api_key)
    # de "configuré mais primary_model absent" (cas dégradé légitime).
    provider_loaded = False
    manager_default_model = ""
    try:
        mgr = get_llm_manager()
        provider_loaded = bool(mgr.default_provider_name)
        manager_default_model = mgr.default_model_name or ""
    except Exception as e:
        logger.warning("Could not resolve LLM manager for limits: %s", e)

    if not provider_loaded:
        return {
            "model": None,
            "configured": False,
            "context_window": 0,
            "reserved_output": 0,
            "reserved_overhead": _PROMPT_OVERHEAD,
            "max_input_tokens": 0,
        }

    # Provider chargé — résolution du modèle effectif :
    # 1) ``primary_model`` (choix admin explicite)
    # 2) ``default_model_name`` du manager (souvent set au boot par
    #    ``set_default(provider, primary_model)``)
    # Branche morte « ou ANTHROPIC_DEFAULT_MODEL » supprimée (review adversariale
    # 2026-04-30) : la branche ``not provider_loaded`` ci-dessus couvre déjà
    # l'absence totale de configuration, le 3e fallback était inatteignable.
    effective_model = model_name or manager_default_model
    if not effective_model:
        # Cas paradoxal (provider chargé mais aucun modèle disponible) : on
        # signale comme non-configuré plutôt que de retourner un nom vide.
        return {
            "model": None,
            "configured": False,
            "context_window": 0,
            "reserved_output": 0,
            "reserved_overhead": _PROMPT_OVERHEAD,
            "max_input_tokens": 0,
        }
    # Garde-fou ``deprecated_at`` (review #4 du 2026-05-09) : la génération
    # LLM est déjà bloquée par ``llm_providers.py:304`` quand le modèle est
    # déprécié, mais sans ce check ici, l'UI afficherait un budget tokens
    # plausible et l'utilisateur cliquerait « Générer » avant de voir
    # l'erreur. On signale ``configured=False`` côté limits pour que l'UI
    # affiche directement le message admin actionable.
    deprecated_at = None
    try:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        deprecated_at = get_llm_model_registry().get_field_sync(effective_model, "deprecated_at")
    except Exception as e:  # noqa: BLE001 — fail-soft : on continue sans gate
        logger.warning("get_active_model_limits: registry lookup failed: %s", e)

    if deprecated_at:
        return {
            "model": effective_model,
            "configured": False,
            "context_window": 0,
            "reserved_output": 0,
            "reserved_overhead": _PROMPT_OVERHEAD,
            "max_input_tokens": 0,
            "deprecation_reason": (
                f"Modèle '{effective_model}' marqué obsolète "
                f"(depuis {deprecated_at}). Choisir un autre modèle dans "
                "/admin/ai-models avant de générer un rapport."
            ),
        }

    context_window = get_context_window_for_model(effective_model)
    reserved_output = get_max_tokens_for_model(effective_model)
    max_input = max(1_000, context_window - reserved_output - _PROMPT_OVERHEAD)

    # Fenêtre vérifiée ? (flag registre BDD). None / modèle absent → False
    # (prudent : on n'affirme pas « vérifié » pour un modèle pas encore
    # persisté — ex. choisi dans la dropdown live mais sans refresh). Le flag
    # ne change PAS ``context_window`` (qui reste >0 pour les calculs) : il
    # pilote uniquement l'affichage « ≈ à confirmer » de l'indicateur /iris,
    # pour ne jamais montrer un chiffre faux comme une vérité.
    cw_verified = False
    try:
        from app.services.ai.llm_model_registry import get_llm_model_registry

        cw_verified = bool(
            get_llm_model_registry().get_field_sync(effective_model, "context_window_verified")
        )
    except Exception as e:  # noqa: BLE001 — fail-soft, défaut « non vérifié »
        logger.debug("get_active_model_limits: lecture context_window_verified KO: %s", e)

    return {
        "model": effective_model,
        "configured": True,
        "context_window": context_window,
        "context_window_verified": cw_verified,
        "reserved_output": reserved_output,
        "reserved_overhead": _PROMPT_OVERHEAD,
        "max_input_tokens": max_input,
    }


def estimate_tokens(text_or_data) -> int:
    """Rough token estimate: ~4 chars = 1 token.

    For datasets with shape ``{columns, rows}``, estimates the markdown table
    size (matches what's actually sent to the LLM — see
    ``llm_report_planner._render_datasets_markdown``).
    """
    if text_or_data is None:
        return 0
    if isinstance(text_or_data, str):
        return max(1, len(text_or_data) // 4)

    # Structured dataset {columns: [...], rows: [...]}
    if isinstance(text_or_data, dict) and "columns" in text_or_data and "rows" in text_or_data:
        columns = text_or_data.get("columns") or []
        rows = text_or_data.get("rows") or []
        if not columns:
            return 1
        # Header + separator
        header_len = sum(len(c) for c in columns) + len(columns) * 3 + 10
        sep_len = len(columns) * 4 + 5
        total = header_len + sep_len
        # Rows — estimate cell content length
        for row in rows:
            if isinstance(row, dict):
                row_len = sum(len(str(row.get(c, ""))) for c in columns) + len(columns) * 3 + 5
            elif isinstance(row, list):
                row_len = sum(len(str(v)) for v in row) + len(row) * 3 + 5
            else:
                row_len = 10
            total += row_len
        return max(1, total // 4)

    # Fallback: JSON serialization
    import json

    try:
        s = json.dumps(text_or_data, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        s = str(text_or_data)
    return max(1, len(s) // 4)


async def resolve_active_window_snapshot() -> Dict[str, Any]:
    """Snapshot du modèle actif + sa fenêtre + son libellé UI.

    Single source of truth pour les *consommateurs* qui ont besoin du triplet
    ``(model_name, context_window, model_display)`` :

    - ``IrisPageHandler.get`` : pour rendre l'indicateur initial dans iris.html
    - ``IrisAgent.run`` : pour augmenter le ``done`` event WebSocket

    Wrap fail-soft autour de :func:`get_active_model_limits` — si la résolution
    échoue (BDD down, provider non chargé), on retourne un snapshot ``None``
    plutôt que de propager. Le frontend hide l'indicateur dans ce cas.

    Returns:
        dict :
            - ``model_name`` (``str | None``)
            - ``context_window`` (``int | None``)
            - ``model_display`` (``str | None``)
            - ``configured`` (``bool``)
    """
    try:
        limits = await get_active_model_limits()
    except Exception as exc:  # noqa: BLE001 — fail-soft, ne bloque jamais le caller
        logger.warning("resolve_active_window_snapshot: get_active_model_limits failed: %s", exc)
        return {
            "model_name": None,
            "context_window": None,
            "context_window_verified": False,
            "model_display": None,
            "configured": False,
        }
    if not limits.get("configured"):
        return {
            "model_name": None,
            "context_window": None,
            "context_window_verified": False,
            "model_display": None,
            "configured": False,
        }
    name = limits.get("model")
    cw = int(limits.get("context_window") or 0) or None
    display = model_display_name(name) if name else None
    return {
        "model_name": name,
        "context_window": cw,
        "context_window_verified": bool(limits.get("context_window_verified")),
        "model_display": display,
        "configured": True,
    }
