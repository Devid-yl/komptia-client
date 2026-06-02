"""
Planificateur de rapports via LLM.

Principe : le LLM reçoit les données sélectionnées (colonnes schema + lignes
anonymisées via le proxy unifié) et, optionnellement, un prompt utilisateur.
Il propose un plan de rapport en JSON (titre, intro, sections avec graphiques
et analyses). Les tokens sont ensuite restaurés dans le plan final avant
génération du PDF — l'utilisateur reçoit les vraies valeurs, le LLM ne voit
que les tokens.

Confidentialité : passe par le proxy unifié
:func:`app.services.anonymization.anonymize_for_llm` (single source of truth
des call sites Komptia, contexte ``REPORT``). Ce proxy compose la couche
PII regex (``[TYPE_N]``) + le pseudonymizer user-scoped (``§…§``) en un seul
appel pour toute la payload (datasets + textes utilisateur), garantissant
la cohérence des tokens cross-dataset/cross-text via le ``pii_counters``
partagé du proxy. Migration tâche #8 du loop d'anonymisation Komptia
(remplacement des appels ``ConfidentialityManager.anonymize_dataset_for_llm``
+ ``sanitize_user_input`` qui produisaient le format legacy ``~xxx``).
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from app.constants_ai import clamped_max_tokens
from app.services.ai.llm_providers import LLMRequest
from app.services.anonymization import anonymize_for_llm
from app.services.anonymization.proxy import get_confidentiality_prompt
from app.utils.logger import get_logger

logger = get_logger(__name__)


# Valeur généreuse par défaut — les modèles modernes (Haiku 4.5, Sonnet, GPT-4o)
# acceptent largement plus. Ajustable via get_ai_config_service si besoin.
_DEFAULT_MAX_OUTPUT_TOKENS = 16000


# Bascule auto vers le mode agent (tool-loop) quand le payload approche le
# plafond de tokens du modèle actif. À 70%, on garde une marge confortable
# pour les overheads (system prompt + schéma JSON) et on évite le fail-tard
# côté LLM (truncation max_tokens) qui produit un retour inutilisable.
_AGENT_MODE_TOKEN_THRESHOLD_RATIO = 0.7


@dataclass
class ReportPlan:
    """Plan de rapport validé, prêt à être exécuté."""

    title: str
    introduction: Optional[str]
    sections: List[Dict[str, Any]]


class ReportPlanError(Exception):
    """Raised when the LLM plan is invalid or cannot be generated."""


async def plan_report(
    datasets: List[Dict[str, Any]],
    user_prompt: Optional[str] = None,
    user_title_hint: Optional[str] = None,
    max_output_tokens: Optional[int] = None,
    *,
    user_id: Optional[int] = None,
    cancel_event: Optional[asyncio.Event] = None,
) -> ReportPlan:
    """Ask the LLM to design a report plan from N datasets.

    Args:
        datasets: List of dataset descriptors. Each descriptor MUST contain:
            - id: int (dataset index, referenced by sections)
            - label: str (real sheet label, e.g. "Résultat (148)")
            - columns: list[str]
            - rows: list[dict] (real rows — anonymized via le proxy avant
              envoi LLM ; restored in the returned plan)
            - row_count: int
        user_prompt: Optional user instructions. If present, the LLM follows
            them. Anonymisé via le proxy avant envoi LLM.
        user_title_hint: Optional imposed title. Anonymisé comme user_prompt.
        max_output_tokens: Cap on generated tokens. Defaults to generous value.
        user_id: Identifiant utilisateur — utilisé par le proxy pour charger
            le pseudonymizer user-scoped (table ``anonymization_terms``).
            ``None`` → contexte système / batch (ex : automation runs sans
            user attaché) — le proxy garde la couche PII regex mais skip
            le pseudonymizer user-scoped.

    Returns:
        Validated ReportPlan with real values restored in every text field
        (title, introduction, sections, chart labels…). The downstream PDF
        generator therefore shows real data; the LLM only saw les tokens
        du proxy (``§…§`` user + ``[TYPE_N]`` PII auto).

    Raises:
        ReportPlanError if the plan is invalid or the LLM is unavailable.
    """
    if not datasets:
        raise ReportPlanError("Aucun dataset fourni")

    # --- Dispatcher hybride : oneshot vs agent ------------------------------
    # Quand le payload (datasets en markdown) dépasse 70% du budget d'input
    # du modèle actif, le mode oneshot est voué à échouer (réponse tronquée
    # ou rejet pré-LLM). On bascule alors vers le tool-loop agent qui fait
    # de la lazy access (read 60 lignes / aggregate côté Python) et scale
    # à des datasets arbitrairement gros, capés uniquement par la mémoire
    # (cf. report_planner_agent.MEMORY_HARD_CAP_BYTES = 100 MB).
    #
    # API publique inchangée : le caller reçoit toujours un ReportPlan
    # validé, peu importe le mode emprunté.
    #
    # **Race admin** (review #8 du 2026-05-09) : si l'admin change le
    # ``primary_model`` entre le ``GET /api/reports/llm-limits`` (qui sert
    # au frontend à projeter la zone "mode étendu") et le ``POST
    # /api/reports/generate-llm`` qui arrive ici, le frontend a pu prédire
    # "vert" mais on bascule en agent. C'est ACCEPTABLE — c'est ici (le
    # backend) qui tranche, le frontend est purement informatif. Côté UX,
    # le bouton "Génération en cours…" suffit à couvrir la transition,
    # même si elle est en mode étendu. Pas de toast à afficher post-hoc :
    # l'utilisateur recevra le PDF, c'est le contrat respecté.
    if await _should_use_agent_mode(datasets):
        from app.services.reporting.report_planner_agent import run_report_agent

        return await run_report_agent(
            datasets,
            user_prompt=user_prompt,
            user_title_hint=user_title_hint,
            max_output_tokens=max_output_tokens,
            user_id=user_id,
            cancel_event=cancel_event,
        )

    # --- Anonymisation via proxy unifié (tâche #8) --------------------------
    # Le LLM ne doit jamais voir les valeurs réelles. Le proxy applique :
    #   1. PII regex (`[TYPE_N]`) sur emails/SIRET/IBAN/téléphones/montants
    #   2. Pseudonymizer user-scoped (`§…§`) sur les termes ``enabled=True``
    #      du dictionnaire utilisateur
    #
    # Tout le payload (datasets + textes utilisateur) passe par UN SEUL
    # appel proxy : les ``pii_counters`` partagés garantissent que deux
    # occurrences de la même valeur PII dans des datasets différents
    # reçoivent le même token (`[EMAIL_1]` apparaît à l'identique dans
    # le dataset 0 et le dataset 1). Le pseudonymizer user-scoped est par
    # essence bijectif sur le state user, donc cohérent cross-payload.
    full_input: Dict[str, Any] = {
        "datasets": [],
        "user_prompt": user_prompt or "",
        "user_title_hint": user_title_hint or "",
    }
    for ds in datasets:
        ds_id = ds.get("id")
        if ds_id is None:
            raise ReportPlanError("Dataset sans id")
        raw_label = ds.get("label") or f"Dataset {ds_id}"
        rows = ds.get("rows") or []
        columns = ds.get("columns") or []
        full_input["datasets"].append(
            {
                "id": ds_id,
                "label": raw_label,
                "columns": columns,  # structurel — laissé en clair, mais walker récursif les ignore (keys préservées)
                "row_count": ds.get("row_count", len(rows)),
                "rows": rows,
            }
        )

    anon_input, restore_fn = await anonymize_for_llm(user_id, full_input, "REPORT")
    prompt_datasets: List[Dict[str, Any]] = list(anon_input.get("datasets", []))
    sanitized_user_prompt = anon_input.get("user_prompt") or None
    sanitized_title_hint = anon_input.get("user_title_hint") or None

    system = (
        get_confidentiality_prompt("REPORT") + "\n\n" + _build_system_prompt(sanitized_user_prompt)
    )
    user_payload = _build_user_payload(prompt_datasets, sanitized_user_prompt, sanitized_title_hint)

    # Load config + model
    # Délégation à :func:`resolve_active_model` — source de vérité unique
    # qui combine ``has_any_provider_configured`` (env vars + config BDD)
    # avec la résolution ``primary_provider``/``primary_model`` + fallback
    # ``manager.default_*``. Avant ce refactor, le check inline était
    # dupliqué dans 3 modules (cohérent avec ``widget_planner/_llm_common``).
    from app.services.ai.llm_runtime import (
        CallProfile,
        LLMCallError,
        RetryPolicy,
        call_llm,
        resolve_active_model,
    )

    try:
        provider_name, model_name = await resolve_active_model()
    except LLMCallError as exc:
        raise ReportPlanError("Provider LLM non configuré") from exc

    try:
        response = await call_llm(
            CallProfile(
                caller="report_planner",
                retry=RetryPolicy.STANDARD,
                provider_name_override=provider_name,
            ),
            LLMRequest(
                prompt=user_payload,
                system=system,
                model=model_name,
                temperature=0.3,
                # Clamp au cap réel du modèle actif (registre BDD) : un modèle
                # à 8K de sortie rejetterait un ``max_tokens`` explicite de 16K.
                # Le soft-limit reste respecté quand il est < cap.
                max_tokens=clamped_max_tokens(
                    max_output_tokens or _DEFAULT_MAX_OUTPUT_TOKENS, model_name
                ),
            ),
        )
        raw = (response.content or "").strip()
    except LLMCallError as exc:
        # Traduire vers ReportPlanError pour préserver l'API publique du module.
        raise ReportPlanError(str(exc)) from exc

    if not raw:
        raise ReportPlanError("Réponse LLM vide")

    # Extract + parse JSON robustly
    plan_json = _extract_json(raw)
    if not plan_json:
        logger.warning("Plan LLM: aucun JSON trouvé. Raw head: %s", raw[:300])
        raise ReportPlanError("Le plan retourné par l'IA n'est pas un JSON valide")
    try:
        plan_data_anon = json.loads(plan_json)
    except json.JSONDecodeError as e:
        logger.warning(
            "Plan LLM: JSON invalide (%s). Extracted head: %s. Raw head: %s",
            e,
            plan_json[:300],
            raw[:300],
        )
        raise ReportPlanError("Le plan retourné par l'IA n'est pas un JSON valide")

    # Parse JSON ENCORE anonymisé puis restaure la STRUCTURE (cf. EPIC E4 —
    # restore-then-parse fragile aux PII contenant `"`/`\`/`\n`). Les
    # tokens du proxy (`[TYPE_N]`, `§…§`) ne contiennent aucun caractère
    # JSON-spécial donc le parse est sûr. Le ``restore_fn`` du proxy
    # est récursif sur dict/list/str — restaure chaque valeur string
    # à la vraie valeur (mapping pseudonymizer + PII regex chained).
    #
    # On restaure AVANT `_validate_plan` car la validation tronque
    # (title≤200, commentary≤20k, etc.) ; tronquer après aurait pu
    # couper un token au milieu (`§nn_4§` → `§nn_4`). En restaurant
    # d'abord, la troncature s'applique aux vraies valeurs.
    plan_restored = restore_fn(plan_data_anon)
    if not isinstance(plan_restored, dict):
        plan_restored = {}

    # Task #18 (M6, 2026-05-22) — fail-closed sur data_access leak
    # APRÈS restore (cleartext). Aligné sur le pattern sibling
    # `report_planner_agent.py:639-645` qui utilise `assert_safe_llm_blocks`
    # sur le cleartext. Ici on serialise le dict en JSON pour
    # scanner toutes les valeurs textuelles (title, introduction,
    # sections.commentary, chart labels, etc.) en un seul passage.
    # Si un nom denied a survécu jusqu'ici (hallucination LLM dans le
    # plan), on REFUSE le plan (le PDF ne doit pas leak en aval).
    #
    # Adversarial review session 17 BLOCKING #1 : scrub APRÈS restore
    # est l'invariant ; scrub AVANT (sur pseudos `§…§`) = NO-OP.
    if user_id is not None:
        from types import SimpleNamespace as _SimpleNamespace

        from app.services.data_access.error_messages import (
            DataAccessLeakDetectedError,
            assert_safe_llm_response,
        )

        _user_for_check = _SimpleNamespace(id=user_id, role=None)
        try:
            _plan_text = json.dumps(plan_restored, ensure_ascii=False)
        except (TypeError, ValueError):
            _plan_text = str(plan_restored)
        _leak_msg = await assert_safe_llm_response(
            _plan_text,
            _user_for_check,
            context_label="llm_report_planner.plan_report",
            strict_when_no_user=True,
        )
        if _leak_msg is not None:
            logger.critical(
                "llm_report_planner: sortie LLM fuite un nom denied user_id=%s",
                user_id,
            )
            raise DataAccessLeakDetectedError(_leak_msg)

    validated = _validate_plan(plan_restored, datasets)

    return ReportPlan(
        title=validated["title"],
        introduction=validated.get("introduction"),
        sections=validated["sections"],
    )


# ------------------------------------------------------------------
# Dispatcher hybride oneshot / agent (cf. plan_report ci-dessus)
# ------------------------------------------------------------------


async def _should_use_agent_mode(datasets: List[Dict[str, Any]]) -> bool:
    """Décide si la requête doit emprunter la route agent (tool-loop) plutôt
    que le oneshot (markdown monolithique).

    Compare l'estimation tokens du payload datasets au ``max_input_tokens``
    du modèle actif (registre BDD source de vérité, single source via
    :func:`app.services.reporting.llm_limits.get_active_model_limits`).
    Bascule à :data:`_AGENT_MODE_TOKEN_THRESHOLD_RATIO` (70%) pour garder
    une marge sur les overheads (system prompt + schéma JSON ~2K tokens
    déjà comptés côté ``llm_limits._PROMPT_OVERHEAD``).

    Fail-safe : si les limites ne sont pas résolvables (provider non chargé,
    BDD down…), on retourne ``False`` — laisse l'erreur historique remonter
    via le mode oneshot, qui pose le bon message à l'utilisateur. On
    n'invente PAS un fallback agent silencieux dans ce cas.
    """
    try:
        from app.services.reporting.llm_limits import (
            estimate_tokens,
            get_active_model_limits,
        )

        limits = await get_active_model_limits()
    except Exception as exc:  # noqa: BLE001 — fail-safe sur dispatcher
        logger.warning("plan_report dispatcher: limits non résolues (%s) — fallback oneshot", exc)
        return False

    if not limits.get("configured"):
        return False

    max_input = int(limits.get("max_input_tokens") or 0)
    if max_input <= 0:
        return False

    total = sum(
        estimate_tokens({"columns": ds.get("columns") or [], "rows": ds.get("rows") or []})
        for ds in datasets
    )
    threshold = int(max_input * _AGENT_MODE_TOKEN_THRESHOLD_RATIO)
    use_agent = total > threshold
    if use_agent:
        logger.info(
            "plan_report: payload %d tokens > seuil %d (= %.0f%% × %d) — bascule mode agent",
            total,
            threshold,
            _AGENT_MODE_TOKEN_THRESHOLD_RATIO * 100,
            max_input,
        )
    return use_agent


# ------------------------------------------------------------------
# Prompt building
# ------------------------------------------------------------------


def _build_system_prompt(user_prompt: Optional[str]) -> str:
    """Domain-neutral system prompt.

    The LLM deduces the domain from the data itself. No hardcoded
    "expert-comptable" — Komptia is a generic data app.
    """
    base = (
        "Tu es un analyste de données. Tu reçois des jeux de données tabulaires et "
        "tu dois concevoir un rapport d'analyse clair et professionnel en français. "
        "Tu décides librement de la longueur, du nombre de sections et de graphiques "
        "en fonction de la richesse des données. "
        "Tu réponds UNIQUEMENT avec un JSON strict, sans texte avant/après, sans "
        "code fence markdown."
    )
    if user_prompt:
        base += (
            " L'utilisateur t'a donné des instructions spécifiques — respecte-les "
            "prioritairement."
        )
    return base


def _build_user_payload(
    prompt_datasets: List[Dict[str, Any]],
    user_prompt: Optional[str],
    user_title_hint: Optional[str],
) -> str:
    """Build the user message with datasets + instructions + JSON schema."""
    parts: List[str] = []

    # User instructions take priority if provided
    if user_prompt:
        parts.append(f"Instructions de l'utilisateur :\n{user_prompt.strip()}")
        parts.append("")

    parts.append(
        f"Tu analyses {len(prompt_datasets)} jeu(x) de données. "
        "Utilise les données ci-dessous pour écrire un rapport pertinent."
    )

    if user_title_hint:
        parts.append(f'Titre imposé : "{user_title_hint}".')
    else:
        parts.append("Propose un titre adapté au contenu.")

    parts.append("")
    parts.append(
        "Pour chaque section que tu crées, tu peux citer des valeurs "
        "précises des données si c'est pertinent pour l'analyse."
    )
    parts.append("")
    parts.append(
        "GRAPHIQUES — tu fournis les données FINALES du graphique, déjà "
        "agrégées/groupées/triées. Le moteur se contente de tracer ce que tu "
        "donnes. Si tu veux une somme par catégorie, fais la somme toi-même à "
        "partir des données brutes et livre le résultat. Trois formats :"
    )
    parts.append("")
    parts.append("""BAR chart (comparaison de catégories) :
{
  "type": "bar",
  "title": "Titre",
  "x_label": "Catégorie" (optionnel),
  "y_label": "Montant" (optionnel),
  "bars": [{"label": "<label_A>", "value": 123456.78}, {"label": "<label_B>", "value": 98765.43}, ...]
}

LINE chart (évolutions, comparaisons temporelles, multi-séries) :
{
  "type": "line",
  "title": "Titre",
  "x_label": "Période",
  "y_label": "Montant",
  "series": [
    {"name": "<série_A>", "points": [{"x":"<période_1>","y":100},{"x":"<période_2>","y":200}]},
    {"name": "<série_B>", "points": [{"x":"<période_1>","y":150},{"x":"<période_2>","y":250}]}
  ]
}

PIE chart (répartitions, parts d'un tout) :
{
  "type": "pie",
  "title": "Titre",
  "slices": [{"label": "<catégorie_A>", "value": 1000000}, {"label": "<catégorie_B>", "value": 250000}, ...]
}
""")
    parts.append(
        "Limites : max 30 barres, max 10 tranches de pie, max 8 séries, "
        "max 100 points par série. Préfère line pour des évolutions "
        "temporelles, bar pour des comparaisons de catégories, pie pour des "
        "répartitions (≤ 8 catégories)."
    )
    parts.append("")
    parts.append("DONNÉES (format markdown — colonnes déclarées une seule fois par dataset) :")
    parts.append(_render_datasets_markdown(prompt_datasets))
    parts.append("")
    parts.append("SCHÉMA DE RÉPONSE (JSON strict — UNIQUEMENT ça) :")
    parts.append("""{
  "title": "Titre du rapport",
  "introduction": "Paragraphe d'introduction ou null",
  "sections": [
    {
      "title": "Titre de section",
      "dataset_id": 0,
      "description": "Courte description ou null",
      "charts": [
        {"type": "bar", "title": "Titre", "bars": [{"label":"X","value":123}]}
      ],
      "commentary": "Analyse libre, de la longueur que tu juges nécessaire."
    }
  ]
}""")
    parts.append("")
    parts.append(
        "Règles strictes :\n"
        "- `dataset_id` DOIT correspondre à un id existant ci-dessus.\n"
        "- Chaque graphique contient ses données finales agrégées (pas de "
        "référence à des colonnes x_column/y_column — ce format est refusé).\n"
        "- Les valeurs des graphiques doivent être des NOMBRES FINIS "
        "(pas NaN, pas infini). Pour un pie chart, toutes les valeurs doivent "
        "être strictement positives.\n"
        "- `charts` peut être `[]` si aucun graphique n'est pertinent.\n"
        "- Pas de texte markdown autour du JSON. Pas de fence ```.\n"
        "- La longueur des analyses n'est PAS limitée — écris ce qui est utile."
    )
    return "\n".join(parts)


# ------------------------------------------------------------------
# Markdown data rendering (LLM-friendly, token-efficient)
# ------------------------------------------------------------------


def _render_datasets_markdown(datasets: List[Dict[str, Any]]) -> str:
    """Render datasets as markdown tables — ~3x fewer tokens than JSON rows.

    Why markdown: LLMs are heavily trained on markdown and parse it natively.
    Column names are declared ONCE per table, not repeated per row. The visual
    column alignment helps the LLM spot patterns in the data.
    """
    parts: List[str] = []
    for ds in datasets:
        ds_id = ds.get("id")
        label = str(ds.get("label", f"Dataset {ds_id}"))
        row_count = ds.get("row_count", 0)
        columns = ds.get("columns") or []
        rows = ds.get("rows") or []

        parts.append(f'## Dataset {ds_id} — "{label}" · {row_count} lignes')
        parts.append("")

        if not columns or not rows:
            parts.append("_(aucune donnée)_")
            parts.append("")
            continue

        # Header
        parts.append("| " + " | ".join(columns) + " |")
        parts.append("|" + "|".join(["---"] * len(columns)) + "|")

        # Rows
        for row in rows:
            cells: List[str] = []
            for col in columns:
                val = row.get(col) if isinstance(row, dict) else None
                cells.append(_format_cell(val))
            parts.append("| " + " | ".join(cells) + " |")

        parts.append("")  # blank line between datasets

    return "\n".join(parts)


def _format_cell(val: Any) -> str:
    """Format a cell value for markdown table display.

    - None → empty
    - numbers → as-is (preserve precision)
    - strings → escape `|` and newlines
    """
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    # Escape markdown table separators inside cells
    s = s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    # Cap individual cell length to avoid absurd values from malformed data
    if len(s) > 300:
        s = s[:297] + "..."
    return s


# ------------------------------------------------------------------
# JSON extraction (brace-balanced)
# ------------------------------------------------------------------


def _extract_json(text: str) -> str:
    """Extract the FIRST balanced top-level JSON object from text.

    Handles:
    - leading/trailing prose
    - ```json ... ``` code fences
    - multiple JSON blobs (returns only the first)
    - embedded `}` inside strings (proper string-aware scanning)

    Returns "" if no balanced object is found.
    """
    if not text:
        return ""

    # Strip code fences if present
    stripped = text.strip()
    fence_match = re.search(r"```(?:json)?\s*\n", stripped)
    if fence_match:
        stripped = stripped[fence_match.end() :]
        # Find closing fence
        close_fence = stripped.rfind("```")
        if close_fence != -1:
            stripped = stripped[:close_fence]

    # Scan for a balanced {...} block, string-aware
    in_string = False
    escape_next = False
    depth = 0
    start: Optional[int] = None

    for i, ch in enumerate(stripped):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    return stripped[start : i + 1]

    return ""


# ------------------------------------------------------------------
# Plan validation
# ------------------------------------------------------------------


# Length caps (prevent DoS via enormous LLM output reaching the PDF)
_MAX_TITLE_LEN = 200
_MAX_DESCRIPTION_LEN = 1000
_MAX_INTRODUCTION_LEN = 4000
_MAX_COMMENTARY_LEN = 20000
_MAX_CHART_TITLE_LEN = 200
_MAX_SECTIONS = 20
_MAX_CHARTS_PER_SECTION = 5


def _truncate(value: Any, limit: int) -> Optional[str]:
    """Return value as a truncated string or None if not a string."""
    if not isinstance(value, str):
        return None
    return value[:limit]


def _coerce_int(value: Any) -> Optional[int]:
    """Coerce to int if possible (handles '0', '1', True). Rejects bool silently."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _validate_plan(plan: Any, datasets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Strict validation + sanitization. Drops invalid parts, raises on structural errors."""
    if not isinstance(plan, dict):
        raise ReportPlanError("Plan invalide : doit être un objet JSON")

    title = _truncate(plan.get("title"), _MAX_TITLE_LEN)
    if not title or not title.strip():
        raise ReportPlanError("Plan invalide : `title` manquant")

    sections_raw = plan.get("sections")
    if not isinstance(sections_raw, list) or not sections_raw:
        raise ReportPlanError("Plan invalide : `sections` manquant ou vide")

    dataset_by_id = {ds["id"]: ds for ds in datasets}

    validated_sections: List[Dict[str, Any]] = []
    for i, section in enumerate(sections_raw[:_MAX_SECTIONS]):
        validated = _validate_section(section, dataset_by_id, index=i)
        if validated is not None:
            validated_sections.append(validated)

    if not validated_sections:
        raise ReportPlanError("Aucune section valide dans le plan retourné par l'IA")

    return {
        "title": title.strip(),
        "introduction": _truncate(plan.get("introduction"), _MAX_INTRODUCTION_LEN),
        "sections": validated_sections,
    }


def _validate_section(
    section: Any, dataset_by_id: Dict[int, Dict[str, Any]], index: int
) -> Optional[Dict[str, Any]]:
    """Validate one section. Returns None if it must be dropped."""
    if not isinstance(section, dict):
        logger.warning("Section %d ignorée (pas un objet)", index)
        return None

    title = _truncate(section.get("title"), _MAX_TITLE_LEN)
    if not title or not title.strip():
        logger.warning("Section %d ignorée (titre manquant)", index)
        return None

    dataset_id = _coerce_int(section.get("dataset_id"))
    if dataset_id is None or dataset_id not in dataset_by_id:
        logger.warning("Section '%s' ignorée : dataset_id=%s invalide", title, dataset_id)
        return None

    ds = dataset_by_id[dataset_id]
    ds_columns = set(ds.get("columns") or [])

    validated_charts: List[Dict[str, Any]] = []
    for chart in (section.get("charts") or [])[:_MAX_CHARTS_PER_SECTION]:
        v = _validate_chart(chart, ds_columns)
        if v is not None:
            validated_charts.append(v)

    return {
        "title": title.strip(),
        "dataset_id": dataset_id,
        "description": _truncate(section.get("description"), _MAX_DESCRIPTION_LEN),
        "charts": validated_charts,
        "commentary": _truncate(section.get("commentary"), _MAX_COMMENTARY_LEN),
    }


_CHART_TYPES_AGGREGATED = {"bar", "line", "pie"}

_MAX_BARS_IN_CHART = 30
_MAX_SLICES_IN_CHART = 10
_MAX_SERIES_IN_CHART = 8
_MAX_POINTS_PER_SERIES = 100


def _validate_chart(chart: Any, ds_columns: set) -> Optional[Dict[str, Any]]:
    """Validate one chart (pre-aggregated format).

    The LLM provides the final chart data (bars/series/slices) directly.
    `ds_columns` is unused but kept in the signature for back-compat with
    section validation. Returns None if the chart must be dropped.
    """
    if not isinstance(chart, dict):
        return None

    ctype = chart.get("type") or chart.get("chart_type")
    if ctype not in _CHART_TYPES_AGGREGATED:
        logger.warning("Chart skipped: type invalide '%s'", ctype)
        return None

    title = _truncate(chart.get("title"), _MAX_CHART_TITLE_LEN)
    x_label = _truncate(chart.get("x_label"), 100)
    y_label = _truncate(chart.get("y_label"), 100)

    if ctype == "bar":
        cleaned = _clean_bars(chart.get("bars"))
        if not cleaned:
            logger.warning("Chart bar skipped: pas de barres valides")
            return None
        return {
            "type": "bar",
            "title": title,
            "x_label": x_label,
            "y_label": y_label,
            "bars": cleaned,
        }

    if ctype == "line":
        cleaned = _clean_series(chart.get("series"))
        if not cleaned:
            logger.warning("Chart line skipped: pas de séries valides")
            return None
        return {
            "type": "line",
            "title": title,
            "x_label": x_label,
            "y_label": y_label,
            "series": cleaned,
        }

    if ctype == "pie":
        cleaned = _clean_slices(chart.get("slices"))
        if not cleaned:
            logger.warning("Chart pie skipped: pas de tranches valides")
            return None
        return {"type": "pie", "title": title, "slices": cleaned}

    return None


def _clean_bars(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw[:_MAX_BARS_IN_CHART]:
        if not isinstance(item, dict):
            continue
        label = _truncate(item.get("label"), 60)
        val = _coerce_number(item.get("value"))
        if label is None or val is None:
            continue
        out.append({"label": label, "value": val})
    return out


def _clean_slices(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw[:_MAX_SLICES_IN_CHART]:
        if not isinstance(item, dict):
            continue
        label = _truncate(item.get("label"), 40)
        val = _coerce_number(item.get("value"))
        if label is None or val is None or val <= 0:
            continue
        out.append({"label": label, "value": val})
    return out


def _clean_series(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for s in raw[:_MAX_SERIES_IN_CHART]:
        if not isinstance(s, dict):
            continue
        name = _truncate(s.get("name"), 60)
        points_raw = s.get("points")
        if not isinstance(points_raw, list):
            continue
        points: List[Dict[str, Any]] = []
        for p in points_raw[:_MAX_POINTS_PER_SERIES]:
            if not isinstance(p, dict):
                continue
            x = p.get("x")
            y = _coerce_number(p.get("y"))
            if x is None or y is None:
                continue
            # x is kept as-is (string or number); renderer handles stringification
            points.append({"x": x, "y": y})
        if len(points) >= 2:  # need 2+ points for a line
            out.append({"name": name or "", "points": points})
    return out


def _coerce_number(v: Any) -> Optional[float]:
    """Accept int/float/numeric string. Reject bool, NaN, infinity."""
    import math as _math

    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        f = float(v)
    elif isinstance(v, str):
        try:
            f = float(v.strip().replace(" ", "").replace(",", "."))
        except ValueError:
            return None
    else:
        return None
    if not _math.isfinite(f):  # reject NaN, +/-inf
        return None
    return f
