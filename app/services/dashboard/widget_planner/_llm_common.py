"""Helpers LLM partagés entre Analyst, Composer et Designer.

Ce module est un **thin wrapper** au-dessus de :mod:`app.services.ai.llm_runtime`
pour préserver l'API publique consommée par ``analyst.py``, ``composer.py`` et
``designer.py``. Toute la logique de retry / model resolution / erreur mapping
est désormais dans le runtime unifié — ici on traduit juste l'API et on choisit
le ``caller`` correct selon le stage.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from app.services.ai.llm_providers import LLMRequest, get_llm_manager
from app.utils.logger import get_logger

logger = get_logger(__name__)


# Stage label → caller sémantique enregistré dans KNOWN_CALLERS. Le caller
# précis permet au dashboard /admin/ai-performance de distinguer la conso
# de chaque étape du pipeline widget-planner.
_STAGE_TO_CALLER = {
    "Analyst": "dashboard_widget_analyst",
    "Composer": "dashboard_widget_composer",
    "Designer": "dashboard_widget_designer",
}


class LLMCallError(Exception):
    """Échec d'un call LLM stage (Analyst / Composer / Designer)."""


async def get_llm_and_model() -> tuple[Any, str, str]:
    """Retourne ``(manager, model_name, provider_name)`` depuis la config AI.

    ``manager`` est conservé pour rétrocompat (les callers passent ``llm``
    à :func:`call_llm_with_retry`, qui ignore en réalité ce param depuis la
    refacto). Le routing effectif utilise ``provider_name``.

    **Source de vérité unique** : délègue à
    :func:`app.services.ai.llm_runtime.resolve_active_model` qui combine
    le check ``has_any_provider_configured`` + la résolution config DB
    + fallback ``manager.default_*``. Le wrapper traduit l'exception
    runtime en ``LLMCallError`` local (le contrat des callers
    composer/analyst/designer attend cette classe).
    """
    from app.services.ai.llm_runtime import LLMCallError as _RuntimeError
    from app.services.ai.llm_runtime import resolve_active_model

    try:
        provider_name, model_name = await resolve_active_model()
    except _RuntimeError as exc:
        raise LLMCallError(str(exc)) from exc
    return get_llm_manager(), model_name, provider_name


async def call_llm_with_retry(
    llm: Any,  # noqa: ARG001 — gardé pour compat API, ignoré (call_llm gère le manager)
    request: LLMRequest,
    stage: str,
    max_attempts: int = 3,  # noqa: ARG001 — RetryPolicy.STANDARD = 3 tentatives
    base_delay: float = 2.0,  # noqa: ARG001 — backoff exp 2-4-8s
    provider_name: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
    context_kind: Optional[str] = None,
) -> str:
    """Exécute le call LLM via :func:`call_llm` du runtime unifié.

    Source de vérité unique : le retry, le mapping erreur, le tracking
    AIPerformanceLog sont gérés par ``llm_runtime``. Cette fonction reste
    comme façade compatible pour ``analyst.py`` / ``composer.py`` /
    ``designer.py``.

    Args:
        request: ``LLMRequest`` du caller (prompt + system + model + ...).
        stage: ``"Analyst"`` / ``"Composer"`` / ``"Designer"`` — utilisé
            pour résoudre le ``caller`` du tracker.
        provider_name: override explicite du provider si non par défaut.
        user_id: identifiant utilisateur pour le proxy d'anonymisation.
            ``None`` ou ``context_kind`` ``None`` → proxy désactivé
            (compat. tests existants qui n'envoient pas de user_id).
        context_kind: discriminant proxy (``"WIDGET_PLAN"`` typiquement).
            Si fourni, ``request.prompt`` est anonymisé et ``request.system``
            est préfixé par le bloc « Confidentialité ». La réponse est
            dé-anonymisée avant retour.

    Returns:
        Le contenu textuel de la réponse, déjà dé-anonymisé si le proxy
        a été activé. Strip appliqué.
    """
    from app.services.ai.llm_runtime import (
        CallProfile,
        LLMCallError as _RuntimeError,
        RetryPolicy,
        call_llm,
    )

    final_request = request
    restore_fn: Optional[Any] = None

    # Proxy d'anonymisation activé si le caller fournit ``context_kind``
    # explicitement. Sinon, comportement legacy préservé pour ne pas
    # casser les tests existants qui ne thread pas user_id.
    #
    # **Garde anti-régression** (review adversariale tâche #7, finding
    # MEDIUM) : on log un warning quand un caller PROD oublie
    # ``context_kind`` — silence = leak potentiel non détectable. Les
    # tests legacy (qui patchent ``call_llm`` directement et ne testent
    # pas l'anonymisation) émettent ce warning mais c'est explicite et
    # acceptable pour la rétrocompat. Toute callsite prod (analyst /
    # composer / designer) DOIT passer ``context_kind="WIDGET_PLAN"``.
    if context_kind is None:
        logger.warning(
            "call_llm_with_retry[%s]: context_kind absent — proxy "
            "d'anonymisation BYPASS. Si appel prod, threader "
            "user_id+context_kind. Si test legacy, ignorer.",
            stage,
        )
    if context_kind is not None:
        from app.services.anonymization import anonymize_for_llm
        from app.services.anonymization.proxy import (
            get_confidentiality_prompt,
        )

        prompt_anon, restore_fn = await anonymize_for_llm(user_id, request.prompt, context_kind)
        existing_system = request.system or ""
        new_system = get_confidentiality_prompt(context_kind) + (
            "\n\n" + existing_system if existing_system else ""
        )
        final_request = LLMRequest(
            prompt=prompt_anon,
            system=new_system,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            options=dict(request.options) if request.options else {},
            prompt_cache_prefix=request.prompt_cache_prefix,
        )

    caller = _STAGE_TO_CALLER.get(stage, "dashboard_widget_planner")
    try:
        response = await call_llm(
            CallProfile(
                caller=caller,
                retry=RetryPolicy.STANDARD,
                provider_name_override=provider_name,
            ),
            final_request,
        )
        raw_text = response.content or ""

        # **Phase P1-5 (#23) — Garde-fou mode invisible sur sortie LLM
        # widget_planner.** Le LLM peut halluciner un nom de table denied
        # dans le JSON retourné (titre/description widget, SQL généré).
        # Le content finit dans la grille dashboard user-facing.
        #
        # On **fail-closed** via ``DataAccessLeakDetectedError`` plutôt
        # qu'un scrub textuel qui corromprait la syntaxe JSON. Le caller
        # (analyst/composer/designer) ne catche pas cette exception
        # spécifiquement — elle propage à la pipeline qui ressort
        # ``LLMCallError`` au handler → message générique côté UI.
        #
        # Restore-then-check : assert_safe_llm_response cible les noms
        # réels (post-restore), pas les pseudos §…§. Quand restore_fn
        # est None (context_kind absent), on check direct (le raw_text
        # est déjà clear).
        if user_id is not None and raw_text:
            from types import SimpleNamespace as _SimpleNamespace

            from app.services.data_access.error_messages import (
                DataAccessLeakDetectedError,
                assert_safe_llm_response,
            )

            if restore_fn is not None:
                try:
                    # On restore juste pour le check, sans modifier raw_text.
                    # Le restore final (post-JSON) reste fait plus bas par le
                    # caller (parse JSON → restore structurel via walker).
                    cleartext_for_check = restore_fn(raw_text)
                    if not isinstance(cleartext_for_check, str):
                        cleartext_for_check = raw_text
                except Exception:  # noqa: BLE001
                    cleartext_for_check = raw_text
            else:
                cleartext_for_check = raw_text

            _user_stub = _SimpleNamespace(id=user_id, role=None)
            _leak_msg = await assert_safe_llm_response(
                cleartext_for_check,
                _user_stub,
                context_label=f"widget_planner.{stage}",
                strict_when_no_user=True,
            )
            if _leak_msg is not None:
                logger.critical(
                    "widget_planner._llm_common[%s]: sortie LLM fuite un "
                    "nom denied user_id=%s (content_len=%d)",
                    stage,
                    user_id,
                    len(raw_text),
                )
                raise DataAccessLeakDetectedError(_leak_msg)

        # Restauration : tous les callers prod (analyst/composer/designer)
        # parsent le retour via :func:`parse_json_response`. Un restore
        # string-based AVANT parse JSON est fragile (EPIC E4) — un terme
        # user contenant ``"``, ``\`` ou ``\n`` (libellé ``Jean "JJ"
        # Dupont``, chemin ``C:\\data``, multi-ligne accidentel) cassera
        # ``json.loads`` du caller silencieusement → fallback degraded UX.
        #
        # Solution : on parse le JSON ENCORE anonymisé ici (les tokens
        # ``[TYPE_N]`` et ``§…§`` ne contiennent jamais de chars JSON-
        # spéciaux), on restaure la STRUCTURE via le walker récursif du
        # proxy (qui sait gérer dict/list/str), puis on re-dumpe. Les
        # caractères spéciaux dans les valeurs cleartext sont alors
        # correctement échappés par ``json.dumps`` — le caller
        # ``parse_json_response`` peut re-parser sans risque.
        if restore_fn is not None and raw_text:
            block = extract_json_object(raw_text)
            if block is not None:
                try:
                    parsed_anon = json.loads(block)
                    parsed_restored = restore_fn(parsed_anon)
                    raw_text = json.dumps(parsed_restored, ensure_ascii=False)
                except (json.JSONDecodeError, TypeError):
                    # raw_text reste anonymisé. Le caller logguera
                    # l'erreur via ``parse_json_response``. Pas de
                    # fallback string-based (E4) ici — préférer un
                    # échec loud plutôt qu'un JSON corrompu silencieux.
                    pass
            # else : pas de JSON détecté ; ``parse_json_response``
            # raise quoi qu'il arrive.
        return raw_text.strip()
    except _RuntimeError as exc:
        # Préserver la classe d'exception attendue par les callers (analyst/etc).
        raise LLMCallError(str(exc)) from exc


def extract_json_object(raw: str) -> Optional[str]:
    """Retourne le premier objet JSON bien balancé trouvé dans `raw`.

    Gère les chaînes (échappements, guillemets) pour ne pas être trompé par
    des { } à l'intérieur d'un string JSON. Strip également les fences ```…```.
    """
    if not raw:
        return None
    s = raw.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)

    depth = 0
    in_string = False
    escape = False
    start = -1
    for i, ch in enumerate(s):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                return s[start : i + 1]
    return None


def parse_json_response(raw: str, stage: str) -> dict[str, Any]:
    """Extrait + parse le JSON de la réponse LLM, ou lève LLMCallError."""
    block = extract_json_object(raw)
    if not block:
        logger.warning("WidgetPlanner[%s]: aucun JSON trouvé. Head: %s", stage, raw[:300])
        raise LLMCallError("La réponse de l'IA n'est pas un JSON valide")
    try:
        data = json.loads(block)
    except json.JSONDecodeError as e:
        logger.warning("WidgetPlanner[%s]: JSON invalide (%s). Head: %s", stage, e, block[:300])
        raise LLMCallError("La réponse de l'IA n'est pas un JSON valide") from e
    if not isinstance(data, dict):
        raise LLMCallError("La réponse de l'IA n'est pas un objet JSON")
    return data
