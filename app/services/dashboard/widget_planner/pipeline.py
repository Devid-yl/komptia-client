"""Orchestrateur du pipeline widget LLM-driven — version 3 (multi-widget).

Pipeline v3 :
    SQL → execute → profile → obfuscate →
        Composer LLM (N proposals — profile obfusqué uniquement) →
            pour chaque proposal :
                transform (Python) → ANONYMIZE shape →
                Designer LLM (tokens ~xxx) → RESTORE tokens locaux →
                    WidgetPlanV2
        → list[WidgetPlanV2]

Confidentialité : le Designer recevait auparavant les VRAIES données
transformées (noms clients, montants dans labels/cellules). On applique
maintenant la même anonymisation bidirectionnelle que /reports — le LLM
ne voit que des ~tokens, l'utilisateur voit les vraies valeurs dans le
widget persisté.

Le Composer décompose UN résultat SQL riche en 1-6 widgets spécialisés
(KPIs d'en-tête + chart principal + secondaire + détail). Chaque widget
est ensuite rendu par le Designer.

Fallback : si le Composer échoue, on retombe sur l'ancien mode
mono-widget (Analyst seul) → 1 WidgetPlanV2 detail_table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.anonymization.strategies import get_confidentiality_manager
from app.services.dashboard.widget_planner.analyst import (
    IntentPlan,
    analyze_intent,
)
from app.services.dashboard.widget_planner.composer import (
    WidgetProposal,
    compose_widgets,
)
from app.services.dashboard.widget_planner.designer import (
    RenderSpec,
    design_render_spec,
)
from app.services.dashboard.widget_planner._llm_common import LLMCallError
from app.services.dashboard.widget_planner.profiler import (
    columns_by_role,
    profile_columns,
)
from app.services.dashboard.widget_planner.transformations import (
    TransformationError,
    apply_transformation,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class WidgetPipelineError(Exception):
    """Erreur irrécupérable du pipeline (SQL vide, provider LLM non configuré…)."""


# Nb de lignes échantillonnées pour exécution "peek". On en a besoin pour
# profile + transformation preview côté Designer.
_PEEK_MAX_ROWS = 200


@dataclass
class WidgetPlanV2:
    """Résultat complet du pipeline — prêt à persister dans un widget."""

    # Partie présentation
    render_spec: RenderSpec
    # Recette de transformation à rejouer à chaque refresh (stockée dans le widget)
    transformation: dict[str, Any]
    # Décision analytique
    intent: str
    # Colonne de drill-down (si pertinente)
    drill_column: Optional[str] = None
    # Preview du rendu à la création (le frontend peut l'utiliser pour afficher
    # tout de suite sans attendre le fetch initial)
    preview_data: dict[str, Any] = field(default_factory=dict)
    # Traces des décisions — utile pour le debug et le log llm_log.md
    analyst_reasoning: Optional[str] = None
    designer_reasoning: Optional[str] = None


async def plan_widget_v2(
    sql: str,
    user_hint: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
    user: Any = None,
) -> WidgetPlanV2:
    """Pipeline complet. Peut lever WidgetPipelineError.

    Args:
        sql: requête SELECT/WITH fournie par l'utilisateur
        user_hint: instructions libres (optionnel)
        user_id: identifiant utilisateur, forwardé au proxy
            d'anonymisation via :func:`analyze_intent` et
            :func:`design_render_spec`. ``None`` (défaut) = couche PII
            regex seule, sans pseudonymizer user-scoped.

    Returns:
        WidgetPlanV2 (render_spec + transformation + intent + preview).
    """
    if not isinstance(sql, str) or not sql.strip():
        raise WidgetPipelineError("Requête SQL vide.")

    # ── 1. Exécute le SQL ─────────────────────────────────────────────
    columns, rows, real_row_count, sample_truncated = await _execute_sql(sql, user=user)
    if not rows:
        raise WidgetPipelineError(
            "La requête n'a retourné aucune ligne — impossible de planifier "
            "un widget sans données."
        )

    # ── 2. Sanitize user_hint EN PREMIER — il va aux 3 LLM calls ──────
    # Analyst et Composer reçoivent le hint avant Designer. Sans sanitize
    # ici, les vrais noms tapés par l'utilisateur leakaient à Anthropic via
    # les 2 premières étapes.
    cm = get_confidentiality_manager()
    sanitized_user_hint, hint_mapping = await _sanitize_user_hint(user_hint, cm)

    # ── 3. Profile déterministe (zéro LLM) ────────────────────────────
    profile = profile_columns(columns, rows)
    profile["real_row_count"] = real_row_count
    profile["sample_truncated"] = sample_truncated
    roles = columns_by_role(profile)

    # ── 4. Construit le profile pour l'Analyst (proxy anonymise au call site)
    profile_for_llm = _build_profile_for_llm(profile, columns, rows)

    # ── 5. LLM Analyst : intent + recette (user_hint sanitisé) ────────
    try:
        intent_plan = await analyze_intent(
            profile_for_llm,
            roles,
            user_hint=sanitized_user_hint,
            user_id=user_id,
        )
    except LLMCallError as exc:
        logger.warning("Pipeline: Analyst échec (%s) — fallback detail_table", exc)
        intent_plan = IntentPlan(
            intent="detail_table",
            transformation={"kind": "passthrough", "params": {}},
            drill_column=None,
            reasoning=f"Fallback: {exc}",
        )

    recipe = intent_plan.transformation or {"kind": "passthrough", "params": {}}

    # ── 6. Applique la transformation en Python sur les VRAIES data ───
    try:
        transformed = apply_transformation(columns, rows, recipe)
    except TransformationError as exc:
        logger.warning("Pipeline: transform échec (%s) — fallback passthrough", exc)
        recipe = {"kind": "passthrough", "params": {}}
        transformed = apply_transformation(columns, rows, recipe)
        intent_plan.intent = "detail_table"

    # Ne PAS envoyer 500 lignes au Designer : trim si table/detail massive
    trimmed_for_designer = _trim_for_designer(transformed)

    # ── 7. Anonymise shape — état partagé initialisé avec les tokens
    # du hint_mapping pour qu'aucune collision silencieuse ne se produise.
    shared_used = set(hint_mapping.keys())
    shared_v2t = {v: k for k, v in hint_mapping.items()}
    anon_shape, shape_mapping = cm.anonymize_widget_payload(
        trimmed_for_designer,
        shared_used_tokens=shared_used,
        shared_value_to_token=shared_v2t,
    )
    merged_mapping = {**hint_mapping, **shape_mapping}
    # Défense en profondeur : couvre anon_shape + sanitized_user_hint + analyst_hints
    _assert_no_leak_in_payload(anon_shape, sanitized_user_hint, intent_plan.hints, merged_mapping)

    # ── 8. LLM Designer : rendu (ne voit que des tokens) ──────────────
    try:
        spec = await design_render_spec(
            intent_plan.intent,
            anon_shape,
            analyst_hints=intent_plan.hints,
            user_hint=sanitized_user_hint,
            user_id=user_id,
        )
    except LLMCallError as exc:
        logger.warning("Pipeline: Designer échec (%s) — fallback spec par défaut", exc)
        spec = _default_render_spec(intent_plan.intent, transformed)

    # ── 9. Restaure les ~tokens → vraies valeurs dans le render_spec ─
    _restore_spec_fields(spec, merged_mapping)
    # Passe secondaire DB pour ~tokens globaux (autres flows Iris)
    await _restore_spec_from_db(spec, cm)

    return WidgetPlanV2(
        render_spec=spec,
        transformation=recipe,
        intent=intent_plan.intent,
        drill_column=intent_plan.drill_column,
        preview_data=transformed,
        analyst_reasoning=intent_plan.reasoning,
        designer_reasoning=spec.reasoning,
    )


# ==================================================================
# Pipeline v3 — 1 SQL → N widgets (Composer + per-widget Designer)
# ==================================================================


async def plan_widgets_batch(
    sql: str,
    user_hint: Optional[str] = None,
    *,
    user_id: Optional[int] = None,
    user: Any = None,
) -> list[WidgetPlanV2]:
    """Compose une mini-dashboard à partir d'un SQL : 1 à 6 widgets.

    - Exécute le SQL une fois, profile, obfusque.
    - Appelle le Composer LLM pour obtenir la liste de proposals.
    - Pour chaque proposal, applique la transformation puis appelle le
      Designer pour obtenir le render_spec final.
    - Si le Composer fail complètement, tombe en mono-widget via
      ``plan_widget_v2`` (Analyst tout seul).

    Args:
        sql: requête SELECT/WITH fournie par l'utilisateur.
        user_hint: instructions libres optionnelles.
        user_id: identifiant utilisateur, forwardé au proxy d'anonymisation
            via :func:`compose_widgets` et :func:`design_render_spec`.
            ``None`` (défaut) = couche PII regex seule.

    Raises:
        WidgetPipelineError si le SQL est vide ou ne retourne aucune ligne.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise WidgetPipelineError("Requête SQL vide.")

    columns, rows, real_row_count, sample_truncated = await _execute_sql(sql, user=user)
    if not rows:
        raise WidgetPipelineError(
            "La requête n'a retourné aucune ligne — impossible de planifier "
            "un widget sans données."
        )

    # Sanitize user_hint au début — partagé par Composer + tous les Designer.
    cm = get_confidentiality_manager()
    sanitized_user_hint, hint_mapping = await _sanitize_user_hint(user_hint, cm)

    profile = profile_columns(columns, rows)
    profile["real_row_count"] = real_row_count
    profile["sample_truncated"] = sample_truncated
    roles = columns_by_role(profile)
    profile_for_llm = _build_profile_for_llm(profile, columns, rows)

    # ── Composer (user_hint sanitisé) ──────────────────────────────────
    try:
        proposals = await compose_widgets(
            profile_for_llm,
            roles,
            user_hint=sanitized_user_hint,
            user_id=user_id,
        )
    except LLMCallError as exc:
        logger.warning("Pipeline: Composer échec (%s) — fallback mono-widget", exc)
        # Fallback : mono-widget via l'ancien flow Analyst (qui re-sanitize).
        try:
            single = await plan_widget_v2(sql, user_hint=user_hint, user_id=user_id, user=user)
            return [single]
        except Exception as exc2:  # noqa: BLE001
            logger.warning("Pipeline: fallback mono-widget échec (%s)", exc2)
            return [_emergency_detail_plan(columns, rows)]

    # ── Pour chaque proposal : transform + Designer ────────────────────
    plans: list[WidgetPlanV2] = []
    for i, prop in enumerate(proposals):
        try:
            plan = await _materialize_proposal(
                prop,
                columns,
                rows,
                sanitized_user_hint=sanitized_user_hint,
                hint_mapping=hint_mapping,
                user_id=user_id,
            )
            plans.append(plan)
        except WidgetPipelineError:
            # Security invariant violation — ne jamais avaler en silence
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Pipeline: widget %d (intent=%s) échec (%s) — skip",
                i,
                prop.intent,
                exc,
            )

    if not plans:
        # Garantit toujours au moins 1 widget rendu
        plans.append(_emergency_detail_plan(columns, rows))

    # Déduplication des KPIs identiques : 2 widgets KPI qui produisent la
    # MÊME valeur scalaire ne servent à rien (cas typique : "Total Général"
    # via scalar_from_column ET "Somme Montants" via scalar_aggregate qui
    # se résolvent en la même valeur). On garde le 1er, on drop les autres.
    plans = _dedup_identical_kpis(plans)

    return plans


def _dedup_identical_kpis(plans: list[WidgetPlanV2]) -> list[WidgetPlanV2]:
    """Drop les KPIs qui produisent une valeur scalaire identique à un KPI déjà gardé.

    Compare via la valeur de ``preview_data['value']`` (calculée à la création).
    Les widgets non-KPI sont préservés tels quels.
    """
    seen_values: set = set()
    out: list[WidgetPlanV2] = []
    for plan in plans:
        if plan.preview_data and plan.preview_data.get("type") == "kpi":
            value = plan.preview_data.get("value")
            # Normalise : float/int comparables, None unique.
            try:
                key = float(value) if value is not None else None
            except (TypeError, ValueError):
                key = repr(value)
            if key in seen_values:
                logger.info(
                    "Pipeline: KPI dupliqué (value=%r, title=%r) → drop",
                    value,
                    getattr(plan.render_spec, "title", None),
                )
                continue
            seen_values.add(key)
        out.append(plan)
    return out


async def _materialize_proposal(
    proposal: WidgetProposal,
    columns: list[str],
    rows: list[list[Any]],
    sanitized_user_hint: Optional[str],
    hint_mapping: dict[str, str],
    *,
    user_id: Optional[int] = None,
) -> WidgetPlanV2:
    """Transforme une proposal Composer en WidgetPlanV2 complet.

    `sanitized_user_hint` et `hint_mapping` sont partagés par tous les widgets
    d'un batch (déjà sanitisés au niveau de `plan_widgets_batch`).

    Applique la transformation Python, puis laisse le Designer choisir titre,
    format, insight. Les proposals avec une recette cassée retombent en
    passthrough (ne DOIT pas casser l'ensemble du batch).

    Args:
        user_id: forwardé au proxy d'anonymisation via
            :func:`design_render_spec`. ``None`` (défaut) compat. tests.
    """
    recipe = proposal.transformation or {"kind": "passthrough", "params": {}}
    try:
        transformed = apply_transformation(columns, rows, recipe)
    except TransformationError as exc:
        logger.info("Pipeline: transform proposal échec (%s) — fallback passthrough", exc)
        recipe = {"kind": "passthrough", "params": {}}
        transformed = apply_transformation(columns, rows, recipe)

    trimmed = _trim_for_designer(transformed)

    hints = dict(proposal.hints or {})
    hints.setdefault("suggested_col_span", proposal.suggested_col_span)
    hints.setdefault("role", proposal.role)

    # État partagé initialisé avec les tokens du hint pour éviter collision
    cm = get_confidentiality_manager()
    shared_used = set(hint_mapping.keys())
    shared_v2t = {v: k for k, v in hint_mapping.items()}
    anon_shape, shape_mapping = cm.anonymize_widget_payload(
        trimmed,
        shared_used_tokens=shared_used,
        shared_value_to_token=shared_v2t,
    )
    merged_mapping = {**hint_mapping, **shape_mapping}
    _assert_no_leak_in_payload(anon_shape, sanitized_user_hint, hints, merged_mapping)

    try:
        spec = await design_render_spec(
            proposal.intent,
            anon_shape,
            analyst_hints=hints,
            user_hint=sanitized_user_hint,
            user_id=user_id,
        )
    except LLMCallError as exc:
        logger.info("Pipeline: Designer échec proposal — fallback spec par défaut : %s", exc)
        spec = _default_render_spec(proposal.intent, transformed)

    if spec.col_span not in (3, 4, 6, 8, 12):
        spec.col_span = proposal.suggested_col_span

    _restore_spec_fields(spec, merged_mapping)
    await _restore_spec_from_db(spec, cm)

    return WidgetPlanV2(
        render_spec=spec,
        transformation=recipe,
        intent=proposal.intent,
        drill_column=proposal.drill_column,
        preview_data=transformed,
        analyst_reasoning=proposal.reasoning,
        designer_reasoning=spec.reasoning,
    )


def _emergency_detail_plan(columns: list[str], rows: list[list[Any]]) -> WidgetPlanV2:
    """Dernier recours si TOUT a échoué : widget table brut avec spec par défaut."""
    spec = RenderSpec(
        title="Résultats",
        widget_type="table",
        chart_type=None,
        col_span=12,
        number_format="number",
    )
    return WidgetPlanV2(
        render_spec=spec,
        transformation={"kind": "passthrough", "params": {}},
        intent="detail_table",
        drill_column=None,
        preview_data={"type": "table", "columns": columns, "rows": rows},
        analyst_reasoning="Emergency fallback (Composer + Analyst both failed)",
        designer_reasoning=None,
    )


# ------------------------------------------------------------------
# Helpers de confidentialité (anonymisation / restauration)
# ------------------------------------------------------------------


# Scrub les ~tokens injectés par l'utilisateur (anti-exfiltration — un user
# qui tape littéralement ~DPNT pourrait faire écho-ter par le LLM un token
# présent dans les données et récupérer la vraie valeur via restore).
_USER_TILDE_PATTERN = re.compile(r"~(?=[A-Za-z0-9_.]{2,})")


async def _sanitize_user_hint(
    user_hint: Optional[str],
    cm: Any,
) -> tuple[Optional[str], dict[str, str]]:
    """Scrub ~tokens user-injectés puis sanitize via ConfidentialityManager.

    Appelé AVANT l'anonymisation du shape — le résultat (tokens + sanitized
    text) est ensuite passé en shared state à anonymize_widget_payload pour
    éviter toute collision.
    """
    if not user_hint:
        return None, {}
    scrubbed = _USER_TILDE_PATTERN.sub(" ", user_hint)
    sanitized, local_mapping = await cm.sanitize_user_input(scrubbed)
    return sanitized, local_mapping


def _assert_no_leak_in_payload(
    anon_shape: Any,
    sanitized_hint: Optional[str],
    analyst_hints: Any,
    mapping: dict[str, str],
) -> None:
    """Defense-in-depth : aucune valeur réelle (mapping.values) ne doit
    apparaître (même en substring) dans ce qui part au LLM — shape +
    user_hint sanitisé + analyst_hints inclus.

    Fail-closed : raise WidgetPipelineError si invariant violé.
    Le substring check rattrape les cas où une vraie valeur serait
    concaténée dans une cellule ou un champ (cas improbable mais défensif).
    """
    real_values = {v for v in mapping.values() if isinstance(v, str) and len(v) > 3}
    if not real_values:
        return

    # Sérialise tout le payload en une string — simple et exhaustif.
    import json as _json

    try:
        combined = _json.dumps(
            {"shape": anon_shape, "hint": sanitized_hint, "hints": analyst_hints},
            ensure_ascii=False,
            default=str,
        )
    except Exception:  # noqa: BLE001
        combined = f"{anon_shape!r}|{sanitized_hint!r}|{analyst_hints!r}"

    for rv in real_values:
        if rv in combined:
            raise WidgetPipelineError(
                "Violation d'invariant d'anonymisation — valeur réelle "
                "détectée dans le payload Designer"
            )


def _restore_spec_fields(spec: Any, mapping: dict[str, str]) -> None:
    """Remplace les ~tokens par leurs valeurs réelles dans tous les champs
    texte du RenderSpec (mutation en place). Utilise une regex avec
    word-boundary (?!\\w) pour éviter deux bugs : remplacement partiel
    (~ann dans ~anna_2) et corruption de mots naturels (~ann dans ~annotation).
    """
    if not mapping:
        return
    sorted_items = sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True)
    pattern = re.compile("(?:" + "|".join(re.escape(t) for t, _ in sorted_items) + r")(?!\w)")
    lookup = {t: v for t, v in sorted_items}

    def restore(text: Optional[str]) -> Optional[str]:
        if not text or not isinstance(text, str):
            return text
        return pattern.sub(lambda m: lookup.get(m.group(0), m.group(0)), text)

    for attr in ("title", "insight", "x_label", "y_label", "reasoning"):
        current = getattr(spec, attr, None)
        if current:
            setattr(spec, attr, restore(current))


async def _restore_spec_from_db(spec: Any, cm: Any) -> None:
    """Seconde passe de restauration via ``anonymization_terms`` (tokens
    globaux des autres flows Iris). Non-bloquante si la DB est indispo."""
    for attr in ("title", "insight", "x_label", "y_label"):
        val = getattr(spec, attr, None)
        if not val:
            continue
        try:
            restored = await cm.restore_anonymized_values(val)
            setattr(spec, attr, restored)
        except Exception as exc:  # noqa: BLE001
            logger.info("restore_anonymized_values(%s): %s — valeur inchangée", attr, exc)


# ------------------------------------------------------------------
# Helpers privés
# ------------------------------------------------------------------


async def _execute_sql(
    sql: str, *, user: Any = None
) -> tuple[list[str], list[list[Any]], int, bool]:
    """Exécute le SQL via QueryExecutor avec cap peek.

    Retourne ``(cols, rows, row_count, sample_truncated)``.

    ``sample_truncated`` (flag AUTORITATIF du connector, basé sur le cap
    EFFECTIF ``min(_PEEK_MAX_ROWS, DatabaseConnection.max_rows)``) vaut True
    quand la requête réelle a PLUS de lignes que le peek : ``row_count`` est
    alors la taille de l'échantillon, PAS le total de la requête. #50 — sans
    ce signal, l'Analyst/Composer LLM croit que la table fait ``row_count``
    lignes et choisit une mauvaise intent / affirme des totaux portant sur
    l'échantillon comme s'ils étaient globaux.

    ``user`` : objet ORM User pour activation RLS data_access. Sans user,
    l'enforcer logue ``RLS skip`` et la requête passe sans filtrage
    (fail-OPEN historique). Le widget planner ayant un user en scope via
    ``plan_widget_v2(user_id)`` / ``compose_widgets(user_id)``, le caller
    DOIT charger l'objet User et le forwarder ici.
    """
    from app.services.database.query_executor import QueryExecutor

    try:
        executor = QueryExecutor()
        qr = await executor.execute(
            sql,
            max_rows=_PEEK_MAX_ROWS,
            user=user,
            rls_source="widget_planner.pipeline._execute_sql",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Pipeline: exécution SQL échouée : %s", exc)
        raise WidgetPipelineError(f"Impossible d'exécuter la requête : {exc}") from exc

    columns = list(qr.columns or [])
    dict_rows = qr.to_dicts() or []
    rows = [[drow.get(col) for col in columns] for drow in dict_rows]
    # QueryResult.row_count reflète ce qui a été ramené (≤ max_rows). On n'a
    # pas accès au count total sans un second COUNT(*) — on reporte ce qu'on
    # a + le flag truncated pour que le LLM sache que c'est un échantillon.
    real_row_count = getattr(qr, "row_count", len(rows)) or len(rows)
    sample_truncated = bool(getattr(qr, "truncated", False))
    return columns, rows, real_row_count, sample_truncated


def _build_profile_for_llm(
    profile: dict[str, Any], columns: list[str], rows: list[list[Any]]
) -> dict[str, Any]:
    """Construit le payload profile passé aux LLM Analyst/Composer.

    Les valeurs (top_values, mini-sample) sont passées **en clair** : le
    proxy d'anonymisation (:func:`anonymize_for_llm`) appliqué au site
    d'appel LLM (cf. ``_llm_common.call_llm_with_retry`` et
    ``analyze_intent`` / ``compose_widgets``) gère la pseudonymisation
    user-scoped + PII auto. Appliquer ici une obfuscation lossy
    supplémentaire ferait double anonymisation et empêcherait le proxy
    de mapper correctement les termes user.

    Les types, cardinalités, stats numériques et ranges de dates restent
    intacts — non sensibles en eux-mêmes.
    """
    sample_size = min(5, len(rows))
    sample_dicts = [
        {col: row[i] if i < len(row) else None for i, col in enumerate(columns)}
        for row in rows[:sample_size]
    ]

    payload: dict[str, Any] = {
        "row_count": profile.get("row_count"),
        "real_row_count": profile.get("real_row_count"),
        "columns": [dict(c) for c in profile.get("columns", [])],
        "sample": sample_dicts,
    }
    # #50 (2026-06-10) — quand le peek a été tronqué au cap (_PEEK_MAX_ROWS),
    # row_count/real_row_count = taille de l'ÉCHANTILLON, PAS le total réel de
    # la requête. Ce dict est sérialisé tel quel dans le prompt Analyst
    # (analyst.py:87) ET Composer : sans signal, le LLM croit que la table
    # fait N lignes (200) → mauvaise intent (ex. detail_table « tout afficher »
    # sur une table en réalité énorme) et totaux/superlatifs portant sur
    # l'échantillon présentés comme globaux. On annonce explicitement le sample.
    if profile.get("sample_truncated"):
        # Revue adv. #50 — sinon le nombre 200 apparaît sous 3 noms
        # (row_count, real_row_count, sample_size) et seul total_row_count est
        # null : un LLM faible peut ancrer sur 200 comme total. On retire les
        # 2 noms trompeurs (« real_row_count » ment quand c'est un échantillon)
        # et on ne laisse qu'UN compteur honnête (sample_size) + le total null.
        payload.pop("row_count", None)
        payload.pop("real_row_count", None)
        payload["is_sample"] = True
        payload["sample_size"] = profile.get("real_row_count")
        payload["total_row_count"] = None  # inconnu sans COUNT(*) séparé
        payload["sample_note"] = (
            "⚠ ÉCHANTILLON : sample_size = nombre de lignes LUES (premières "
            "lignes seulement), PAS le total réel de la requête (total_row_count "
            "inconnu, SUPÉRIEUR). Choisis l'intent sur la STRUCTURE des colonnes, "
            "pas sur ce nombre. N'affirme aucun total/somme/moyenne/max/"
            "classement comme global."
        )
    return payload


def _trim_for_designer(transformed: dict[str, Any]) -> dict[str, Any]:
    """Limite la taille envoyée au Designer pour éviter la surcharge tokens.

    - Table / passthrough : max 15 lignes envoyées + row_count réel
    - Chart : max 20 labels envoyés
    - KPI : tel quel (déjà minuscule)
    """
    t = transformed.get("type")
    if t == "table":
        rows = transformed.get("rows") or []
        return {
            "type": "table",
            "columns": transformed.get("columns"),
            "rows": rows[:15],
            "row_count": len(rows),
            # #18f (verdict #51, 2026-06-10) — le designer LLM rédige un
            # « insight » (classement, max…) depuis cet échantillon : sans
            # flag explicite, il affirme des superlatifs FAUX (le vrai max
            # peut être dans les lignes 16+), affichés tels quels au pied
            # du widget.
            "rows_truncated": len(rows) > 15,
        }
    if t == "chart":
        labels = transformed.get("labels") or []
        datasets = transformed.get("datasets") or []
        # Revue adv. lot 3 — sans cap sur le NOMBRE de datasets, un pivot
        # SQL large (100 colonnes métriques) bypasse toute la réduction du
        # designer → prompt non borné. 20 séries suffisent largement à
        # choisir un type de visuel.
        trimmed_datasets = [
            {
                "label": ds.get("label"),
                "data": (ds.get("data") or [])[:20],
            }
            for ds in datasets[:20]
        ]
        out_chart: dict[str, Any] = {
            "type": "chart",
            "labels": labels[:20],
            "datasets": trimmed_datasets,
            "label_count": len(labels),
            "labels_truncated": len(labels) > 20,
            "datasets_truncated": len(datasets) > 20,
            "dataset_count": len(datasets),
        }
        # #48 — PRÉSERVER le marqueur de catégories droppées (agg non additive) :
        # sinon ce rebuild le mange et le designer ne sait pas que le chart est
        # partiel (insight superlatif faux). Canal consommé par designer._is_partial.
        if transformed.get("truncated_categories"):
            out_chart["truncated_categories"] = transformed["truncated_categories"]
        return out_chart
    return transformed


def _default_render_spec(intent: str, shape: dict[str, Any]) -> RenderSpec:
    """Spec safe quand le Designer fail (réseau, parse, etc.)."""
    if shape.get("type") == "kpi":
        return RenderSpec(
            title="Indicateur",
            widget_type="kpi",
            chart_type=None,
            col_span=3,
            number_format="number",
        )
    if shape.get("type") == "table" or intent == "detail_table":
        return RenderSpec(
            title="Résultats",
            widget_type="table",
            chart_type=None,
            col_span=12,
            number_format="number",
        )
    chart_type = "line" if intent == "trend" else ("donut" if intent == "distribution" else "bar")
    return RenderSpec(
        title="Analyse",
        widget_type="chart",
        chart_type=chart_type,
        col_span=6,
        number_format="number",
    )
