"""
WorkflowEngine — Moteur d'execution de workflows multi-etapes.

Execute les etapes d'un workflow dans l'ordre, en passant les donnees
de chaque etape a la suivante (pipeline pattern).

Chaque etape recoit un WorkflowContext contenant:
- Les donnees (lignes + colonnes) de l'etape precedente
- Les metadonnees accumulees (warnings, stats, fichiers generes)
- La configuration de l'etape

Architecture:
    WorkflowEngine.execute(steps, initial_context)
        -> pour chaque step: handler = _STEP_HANDLERS[step.step_type]
        -> handler(step.config, context) -> context modifie
        -> retourne le contexte final
"""

import operator
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class StepResult:
    """Resultat d'une etape individuelle."""

    step_order: int
    step_name: str
    step_type: str
    success: bool
    rows_in: int = 0
    rows_out: int = 0
    duration_ms: float = 0.0
    warnings: list = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class WorkflowContext:
    """Contexte partage entre les etapes d'un workflow.

    Chaque etape lit `rows`/`columns` en entree, et les modifie pour l'etape suivante.
    """

    # Donnees courantes
    rows: List[Dict[str, Any]] = field(default_factory=list)
    columns: List[str] = field(default_factory=list)

    # Metadonnees accumulees
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    generated_files: List[str] = field(default_factory=list)
    step_results: List[StepResult] = field(default_factory=list)

    # Variables inter-etapes (cle: "step_name.var_name", valeur: Any)
    variables: Dict[str, Any] = field(default_factory=dict)

    # Configuration globale (injectee par l'executeur)
    automation_id: int = 0
    execution_id: int = 0
    user_id: int = 0

    # Controle de flux — mis a True par une etape condition pour sauter le reste
    skip_remaining: bool = False

    # Goto conditionnel — nom de l'etape cible; les etapes intermediaires sont sautees
    skip_to_step: Optional[str] = None

    # Resultat de la derniere etape condition (True si condition remplie)
    condition_last_result: Optional[bool] = None

    # -------------------------------------------------------------------------
    # Retires en Phase 1 DAG (nodes LOOP/FOR_EACH/TRY_CATCH supprimes) :
    # - loop_counters, restart_from_step (support de LOOP)
    # - foreach_state (support de FOR_EACH)
    # - try_catch_state (support de TRY_CATCH)
    # Cf. docs/design_automations_dag.md §7 D18. Ces concepts lineaires sont
    # incompatibles avec un DAG pur. Aucun workflow en base ne les utilisait.
    # -------------------------------------------------------------------------

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def set_variable(self, step_name: str, key: str, value: Any) -> None:
        """Stocke une variable associee a une etape.

        La cle finale est "{sanitized_step_name}.{key}".
        """
        sanitized = _sanitize_step_name(step_name)
        self.variables[f"{sanitized}.{key}"] = value

    def set_variables(self, step_name: str, vars_dict: Dict[str, Any]) -> None:
        """Stocke plusieurs variables pour une etape."""
        sanitized = _sanitize_step_name(step_name)
        for key, value in vars_dict.items():
            self.variables[f"{sanitized}.{key}"] = value

    def get_variable(self, key: str, default: Any = None) -> Any:
        """Recupere une variable par sa cle complete (step.var)."""
        return self.variables.get(key, default)


class WorkflowEngine:
    """Moteur d'execution de workflows multi-etapes."""

    def __init__(self):
        # D2 cycle 13 — Audit du dormant code (adversarial cycle 1) :
        # Le registre ``_step_handlers`` reste VIDE en runtime. Aucun
        # call site ne peuple ce dict, donc ``execute_step()`` retourne
        # systematiquement ``StepResult(success=False, ...)`` apres un
        # ``handler is None`` check.
        #
        # Etat des 14 methodes ``_step_*`` :
        # - **Testees directement** (test_iter40_fixes.py l.118-158) :
        #   _step_analyze_stats, _step_map_values → coverage existant,
        #   ne pas supprimer (risque casse tests).
        # - **Mortes** (jamais appelees, jamais testees) : 12 autres —
        #   filter_rows, filter_columns, sort, deduplicate, rename_columns,
        #   compute_column, validate_not_null/types/range/unique,
        #   analyze_anomalies, set_variable, aggregate.
        #
        # Suppression complete BLOQUEE par D1 (kill linear pipeline) car
        # ``executor._run_workflow_pipeline`` instancie WorkflowEngine.
        # Apres D1 → D2 supprime workflow_engine.py entierement.
        #
        # En attendant : registre vide volontaire = no-op safe.
        # Cluster-L (L1) 2026-05-26 — `_step_handlers` est intentionnellement
        # VIDE au runtime depuis le cycle D1 (refacto DAG unifié). Les
        # méthodes ``_step_*`` ci-dessous sont conservées comme DEPRECATED
        # mais ne sont JAMAIS appelées au runtime — leur seul caller est
        # ``execute_step()`` qui retourne (success=False, "non géré par le
        # moteur") car le registre est vide. Si on souhaite réactiver une
        # méthode, il faudrait : (1) revoir L2 eval safety, (2) ajouter
        # tests d'intégration runtime, (3) documenter dans le DAG.
        # Public API (``WorkflowContext``, ``resolve_template_variables``,
        # ``get_workflow_engine``, ``capture_step_variables``) RESTE active
        # car utilisée par ``executor.py`` pour le contexte template.
        self._step_handlers: Dict[str, Any] = {}

    def execute_step(
        self, step_type: str, config: Dict[str, Any], context: WorkflowContext
    ) -> StepResult:
        """Execute une etape individuelle.

        Les etapes extract_sql, report, email sont gerees
        par l'executor (elles necessitent des connexions DB/SMTP).
        """
        import time

        start = time.perf_counter()
        rows_in = context.row_count
        step_name = config.get("_step_name", step_type)

        handler = self._step_handlers.get(step_type)
        if handler is None:
            return StepResult(
                step_order=config.get("_step_order", 0),
                step_name=step_name,
                step_type=step_type,
                success=False,
                rows_in=rows_in,
                error=f"Type d'etape non gere par le moteur: {step_type}",
            )

        try:
            warnings = handler(config, context)
            elapsed = (time.perf_counter() - start) * 1000

            result = StepResult(
                step_order=config.get("_step_order", 0),
                step_name=step_name,
                step_type=step_type,
                success=True,
                rows_in=rows_in,
                rows_out=context.row_count,
                duration_ms=elapsed,
                warnings=warnings or [],
            )
            context.step_results.append(result)
            context.warnings.extend(warnings or [])

            logger.info(
                "Etape %s (%s) terminee: %d -> %d lignes (%.1fms)",
                step_name,
                step_type,
                rows_in,
                context.row_count,
                elapsed,
            )
            return result

        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            logger.error(
                "Erreur etape %s (%s): %s",
                step_name,
                step_type,
                type(e).__name__,
                exc_info=True,
            )
            result = StepResult(
                step_order=config.get("_step_order", 0),
                step_name=step_name,
                step_type=step_type,
                success=False,
                rows_in=rows_in,
                rows_out=context.row_count,
                duration_ms=elapsed,
                error=f"Erreur lors de l'etape '{step_name}': {type(e).__name__}",
            )
            context.step_results.append(result)
            return result

    # ── Transformation steps ──

    def _step_filter_rows(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Filtre les lignes selon une condition."""
        col = config.get("column", "")
        op = config.get("operator", "==")
        value = config.get("value")

        if not col:
            return ["Filtre: aucune colonne specifiee"]

        if col not in context.columns:
            return [f"Filtre: colonne '{col}' introuvable"]

        # `in`/`not_in` attendent `value` = list/tuple/set. Comparaison via
        # str() pour tolerer les types heterogenes que peuvent renvoyer les
        # drivers SQL.
        def _in_set(a: Any, b: Any) -> bool:
            if not isinstance(b, (list, tuple, set)):
                return False
            return any(str(a) == str(x) for x in b)

        ops = {
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            ">": lambda a, b: _safe_compare(a, b, operator.gt),
            "<": lambda a, b: _safe_compare(a, b, operator.lt),
            ">=": lambda a, b: _safe_compare(a, b, operator.ge),
            "<=": lambda a, b: _safe_compare(a, b, operator.le),
            "contains": lambda a, b: (
                b is not None and str(b).lower() in str(a).lower() if a is not None else False
            ),
            "not_contains": lambda a, b: (
                b is None or str(b).lower() not in str(a).lower() if a is not None else True
            ),
            "starts_with": lambda a, b: (
                str(a).lower().startswith(str(b).lower())
                if a is not None and b is not None
                else False
            ),
            "ends_with": lambda a, b: (
                str(a).lower().endswith(str(b).lower())
                if a is not None and b is not None
                else False
            ),
            "is_null": lambda a, _: a is None,
            "is_not_null": lambda a, _: a is not None,
            "in": _in_set,
            "not_in": lambda a, b: not _in_set(a, b),
        }

        op_fn = ops.get(op)
        if op_fn is None:
            return [f"Filtre: operateur inconnu '{op}'"]

        context.rows = [row for row in context.rows if op_fn(row.get(col), value)]
        return []

    def _step_filter_columns(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Selectionne ou exclut des colonnes."""
        columns = config.get("columns", [])
        mode = config.get("mode", "include")

        if not columns:
            return ["Selection colonnes: aucune colonne specifiee"]

        if mode == "include":
            missing = [c for c in columns if c not in context.columns]
            keep = [c for c in columns if c in context.columns]
            context.columns = keep
            context.rows = [{k: row.get(k) for k in keep} for row in context.rows]
            if missing:
                return [f"Colonnes introuvables (ignorees): {', '.join(missing)}"]
        elif mode == "exclude":
            keep = [c for c in context.columns if c not in columns]
            context.columns = keep
            context.rows = [{k: row.get(k) for k in keep} for row in context.rows]
        else:
            return [f"Mode inconnu: {mode}"]

        return []

    def _step_sort(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Trie les lignes."""
        col = config.get("column", "")
        direction = config.get("direction", "asc")

        if not col or col not in context.columns:
            return [f"Tri: colonne '{col}' introuvable"]

        reverse = direction == "desc"
        context.rows.sort(
            key=lambda row: (_sort_key(row.get(col)),),
            reverse=reverse,
        )
        return []

    def _step_deduplicate(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Supprime les doublons."""
        columns = config.get("columns", [])
        if not columns:
            columns = context.columns

        seen = set()
        unique_rows = []
        duplicates = 0

        for row in context.rows:
            key = tuple(str(row.get(c, "")) for c in columns)
            if key not in seen:
                seen.add(key)
                unique_rows.append(row)
            else:
                duplicates += 1

        context.rows = unique_rows
        warnings = []
        if duplicates > 0:
            warnings.append(f"Deduplication: {duplicates} doublons supprimes")
        return warnings

    def _step_rename_columns(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Renomme des colonnes."""
        mapping = config.get("mapping", {})
        if not mapping or not isinstance(mapping, dict):
            return ["Renommage: aucun mapping specifie"]

        warnings = []
        for old_name, new_name in mapping.items():
            if old_name not in context.columns:
                warnings.append(f"Renommage: colonne '{old_name}' introuvable")
                continue
            idx = context.columns.index(old_name)
            context.columns[idx] = new_name
            for row in context.rows:
                if old_name in row:
                    row[new_name] = row.pop(old_name)

        return warnings

    def _step_compute_column(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Calcule une nouvelle colonne avec des expressions simples.

        Expressions supportees: col1 + col2, col1 - col2, col1 * col2, col1 / col2,
        col1 * 1.2, col1 + 100, concat(col1, col2).
        """
        new_col = config.get("new_column", "")
        expression = config.get("expression", "")

        if not new_col or not expression:
            return ["Calcul: colonne ou expression manquante"]

        # Parser l'expression simple: col1 op col2 ou col1 op number
        # _parse_expression utilise un whitelist (seuls colonnes, operateurs, nombres acceptes)
        expr_result = _parse_expression(expression, context.columns)
        if expr_result is None:
            return [f"Calcul: expression non reconnue '{expression}'"]

        warnings = []
        errors = 0
        for row in context.rows:
            try:
                row[new_col] = expr_result(row)
            except (TypeError, ValueError, ZeroDivisionError):
                row[new_col] = None
                errors += 1

        if new_col not in context.columns:
            context.columns.append(new_col)

        if errors > 0:
            warnings.append(f"Calcul: {errors} erreurs sur {len(context.rows)} lignes")

        return warnings

    # ── Validation steps ──

    def _step_validate_not_null(
        self, config: Dict[str, Any], context: WorkflowContext
    ) -> List[str]:
        """Verifie l'absence de NULL dans les colonnes specifiees."""
        columns = config.get("columns", [])
        on_failure = config.get("on_failure", "warn")

        if not columns:
            return ["Validation NULL: aucune colonne specifiee"]

        warnings = []
        null_rows = set()

        for col in columns:
            if col not in context.columns:
                warnings.append(f"Validation NULL: colonne '{col}' introuvable")
                continue
            for i, row in enumerate(context.rows):
                if row.get(col) is None:
                    null_rows.add(i)

        if null_rows:
            msg = (
                f"Validation NULL: {len(null_rows)} lignes avec des valeurs NULL "
                f"dans {', '.join(columns)}"
            )
            if on_failure == "stop":
                raise ValueError(msg)
            elif on_failure == "remove_rows":
                context.rows = [row for i, row in enumerate(context.rows) if i not in null_rows]
                warnings.append(f"{msg} — lignes supprimees")
            else:
                warnings.append(msg)

        return warnings

    def _step_validate_types(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Verifie les types de donnees."""
        checks = config.get("checks", {})
        on_failure = config.get("on_failure", "warn")

        if not checks or not isinstance(checks, dict):
            return ["Validation types: aucun check specifie"]

        type_checkers = {
            "int": lambda v: isinstance(v, int) or (isinstance(v, str) and v.lstrip("-").isdigit()),
            "float": lambda v: isinstance(v, (int, float)) or _is_float_str(v),
            "str": lambda v: isinstance(v, str),
            "date": lambda v: _is_date_str(v),
        }

        warnings = []
        bad_rows = set()

        for col, expected_type in checks.items():
            if col not in context.columns:
                warnings.append(f"Validation types: colonne '{col}' introuvable")
                continue
            checker = type_checkers.get(expected_type)
            if checker is None:
                warnings.append(f"Validation types: type inconnu '{expected_type}'")
                continue

            for i, row in enumerate(context.rows):
                val = row.get(col)
                if val is not None and not checker(val):
                    bad_rows.add(i)

        if bad_rows:
            msg = f"Validation types: {len(bad_rows)} lignes avec des types incorrects"
            if on_failure == "stop":
                raise ValueError(msg)
            elif on_failure == "remove_rows":
                context.rows = [row for i, row in enumerate(context.rows) if i not in bad_rows]
                warnings.append(f"{msg} — lignes supprimees")
            else:
                warnings.append(msg)

        return warnings

    def _step_validate_range(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Verifie que les valeurs sont dans une plage."""
        col = config.get("column", "")
        min_val = config.get("min_value")
        max_val = config.get("max_value")
        on_failure = config.get("on_failure", "warn")

        if not col or col not in context.columns:
            return [f"Validation plage: colonne '{col}' introuvable"]

        if min_val is None and max_val is None:
            return ["Validation plage: aucune borne specifiee"]

        warnings = []
        out_of_range = set()

        for i, row in enumerate(context.rows):
            val = row.get(col)
            if val is None:
                continue
            try:
                num = float(val)
                if min_val is not None and num < float(min_val):
                    out_of_range.add(i)
                if max_val is not None and num > float(max_val):
                    out_of_range.add(i)
            except (ValueError, TypeError):
                out_of_range.add(i)

        if out_of_range:
            msg = f"Validation plage: {len(out_of_range)} valeurs hors plage pour '{col}'"
            if on_failure == "stop":
                raise ValueError(msg)
            elif on_failure == "remove_rows":
                context.rows = [row for i, row in enumerate(context.rows) if i not in out_of_range]
                warnings.append(f"{msg} — lignes supprimees")
            else:
                warnings.append(msg)

        return warnings

    def _step_validate_unique(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Verifie l'unicite des valeurs."""
        columns = config.get("columns", [])
        on_failure = config.get("on_failure", "warn")

        if not columns:
            return ["Validation unicite: aucune colonne specifiee"]

        warnings = []
        seen = {}
        duplicate_rows = set()

        for i, row in enumerate(context.rows):
            key = tuple(str(row.get(c, "")) for c in columns if c in context.columns)
            if key in seen:
                duplicate_rows.add(i)
                duplicate_rows.add(seen[key])
            else:
                seen[key] = i

        if duplicate_rows:
            msg = f"Validation unicite: {len(duplicate_rows)} lignes dupliquees"
            if on_failure == "stop":
                raise ValueError(msg)
            elif on_failure == "remove_rows":
                # Garder la premiere occurrence uniquement
                seen2 = set()
                kept = []
                for i, row in enumerate(context.rows):
                    key = tuple(str(row.get(c, "")) for c in columns if c in context.columns)
                    if key not in seen2:
                        seen2.add(key)
                        kept.append(row)
                context.rows = kept
                warnings.append(f"{msg} — doublons supprimes")
            else:
                warnings.append(msg)

        return warnings

    # ── Analysis steps ──

    def _step_analyze_stats(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Calcule des statistiques descriptives."""
        columns = config.get("columns", [])

        # Si pas de colonnes specifiees, prendre toutes les numeriques
        if not columns:
            columns = [
                c
                for c in context.columns
                if any(
                    isinstance(row.get(c), (int, float))
                    for row in context.rows[:10]
                    if row.get(c) is not None
                )
            ]

        if not columns:
            return ["Statistiques: aucune colonne numerique trouvee"]

        stats = {}
        for col in columns:
            values = [
                float(row.get(col))
                for row in context.rows
                if row.get(col) is not None and _is_numeric(row.get(col))
            ]
            if not values:
                null_count = sum(1 for r in context.rows if r.get(col) is None)
                stats[col] = {"count": 0, "nulls": null_count}
                continue

            values.sort()
            n = len(values)
            total = sum(values)
            mean = total / n
            variance = sum((v - mean) ** 2 for v in values) / (n - 1) if n > 1 else 0
            std_dev = variance**0.5

            stats[col] = {
                "count": n,
                "nulls": sum(1 for r in context.rows if r.get(col) is None),
                "min": values[0],
                "max": values[-1],
                "mean": round(mean, 2),
                "median": values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2,
                "std_dev": round(std_dev, 2),
                "sum": round(total, 2),
            }

        context.stats["descriptive"] = stats
        return []

    def _step_analyze_anomalies(
        self, config: Dict[str, Any], context: WorkflowContext
    ) -> List[str]:
        """Detecte les anomalies avec la methode IQR."""
        columns = config.get("columns", [])
        threshold = float(config.get("threshold", 1.5))

        if not columns:
            columns = [
                c
                for c in context.columns
                if any(
                    isinstance(row.get(c), (int, float))
                    for row in context.rows[:10]
                    if row.get(c) is not None
                )
            ]

        if not columns:
            return ["Anomalies: aucune colonne numerique trouvee"]

        anomalies = {}
        warnings = []

        for col in columns:
            values = sorted(
                (
                    float(row.get(col))
                    for row in context.rows
                    if row.get(col) is not None and _is_numeric(row.get(col))
                )
            )
            if len(values) < 4:
                continue

            n = len(values)
            q1 = values[n // 4]
            q3 = values[3 * n // 4]
            iqr = q3 - q1
            lower = q1 - threshold * iqr
            upper = q3 + threshold * iqr

            outlier_count = sum(1 for v in values if v < lower or v > upper)
            if outlier_count > 0:
                anomalies[col] = {
                    "outlier_count": outlier_count,
                    "lower_bound": round(lower, 2),
                    "upper_bound": round(upper, 2),
                    "q1": round(q1, 2),
                    "q3": round(q3, 2),
                    "iqr": round(iqr, 2),
                }
                warnings.append(
                    f"Anomalies: {outlier_count} valeurs aberrantes dans '{col}' "
                    f"(hors [{round(lower, 2)}, {round(upper, 2)}])"
                )

        context.stats["anomalies"] = anomalies
        return warnings

    # ── Variable assignment ──

    def _step_set_variable(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Definit ou modifie des variables inter-etapes.

        Chaque assignment a un nom, une source et une valeur.
        Sources:
        - literal: la valeur est utilisee telle quelle
        - template: la valeur est un template {{step.var}} a resoudre
        - row_field: la valeur est le nom d'une colonne (premiere ligne)
        - row_count: la variable recoit le nombre de lignes courantes
        - expression: evaluation arithmetique simple (+, -, *, /, %)
        """
        assignments = config.get("assignments", [])
        step_name = config.get("_step_name", "set_variable")
        warnings: List[str] = []

        if not assignments or not isinstance(assignments, list):
            return ["Set variable: aucune affectation definie"]

        for i, assignment in enumerate(assignments):
            if not isinstance(assignment, dict):
                warnings.append(f"Set variable: affectation #{i + 1} invalide (pas un objet)")
                continue

            var_name = str(assignment.get("name", "")).strip()
            if not var_name:
                warnings.append(f"Set variable: affectation #{i + 1} sans nom")
                continue

            source = assignment.get("source", "literal")
            raw_value = assignment.get("value", "")

            resolved_value: Any = None

            if source == "literal":
                resolved_value = raw_value

            elif source == "template":
                if isinstance(raw_value, str) and raw_value:
                    resolved, unresolved = resolve_template_variables(raw_value, context.variables)
                    resolved_value = resolved
                    if unresolved:
                        warnings.append(
                            f"Set variable '{var_name}': variables non resolues: "
                            f"{', '.join(unresolved)}"
                        )
                else:
                    resolved_value = raw_value

            elif source == "row_field":
                col_name = str(raw_value).strip()
                if not col_name:
                    warnings.append(f"Set variable '{var_name}': nom de colonne vide")
                    continue
                if col_name not in context.columns:
                    warnings.append(f"Set variable '{var_name}': colonne '{col_name}' introuvable")
                    continue
                if context.rows:
                    resolved_value = context.rows[0].get(col_name)
                else:
                    resolved_value = None
                    warnings.append(f"Set variable '{var_name}': aucune ligne disponible")

            elif source == "row_count":
                resolved_value = len(context.rows)

            elif source == "expression":
                resolved_value = self._evaluate_expression(
                    str(raw_value), context, var_name, warnings
                )

            else:
                warnings.append(f"Set variable '{var_name}': source inconnue '{source}'")
                continue

            context.set_variable(step_name, var_name, resolved_value)

        return warnings

    @staticmethod
    def _evaluate_expression(
        expr: str,
        context: WorkflowContext,
        var_name: str,
        warnings: List[str],
    ) -> Any:
        """Evalue une expression arithmetique simple et securisee.

        Supporte: nombres, +, -, *, /, //, %, parentheses, unary +/-, et
        references aux variables via {{step.var}}.

        Cluster-L (L2) 2026-05-26 — Remplace l'``eval()`` historique
        gated par regex permissive. Maintenant : AST walker pur (pas
        d'eval Python !) qui interprète UNIQUEMENT les nodes whitelistés
        (Constant numeric, BinOp avec Add/Sub/Mult/Div/FloorDiv/Mod,
        UnaryOp avec USub/UAdd). Cap depth à 50 pour bloquer le DoS
        nested ``(((((...)))))``. Tokenizer surprises (``1_000_000``)
        passent par AST mais sont rejetées si non-Constant numeric.
        """
        import ast as _ast
        import operator as _op

        if not expr.strip():
            warnings.append(f"Set variable '{var_name}': expression vide")
            return 0

        # Resoudre les templates d'abord
        resolved, unresolved = resolve_template_variables(expr, context.variables)
        if unresolved:
            warnings.append(
                f"Set variable '{var_name}': variables non resolues dans expression: "
                f"{', '.join(unresolved)}"
            )
        resolved_str = str(resolved)

        # AST whitelist : aucun call, aucun identifier, aucun attribute.
        # Le cap depth empêche les DoS via nested parens.
        _MAX_AST_DEPTH = 50
        _BIN_OPS = {
            _ast.Add: _op.add,
            _ast.Sub: _op.sub,
            _ast.Mult: _op.mul,
            _ast.Div: _op.truediv,
            _ast.FloorDiv: _op.floordiv,
            _ast.Mod: _op.mod,
        }

        def _walk(node, depth=0):
            if depth > _MAX_AST_DEPTH:
                raise ValueError(
                    f"Expression trop profondément imbriquée (>{_MAX_AST_DEPTH})"
                )
            if isinstance(node, _ast.Expression):
                return _walk(node.body, depth + 1)
            if isinstance(node, _ast.Constant):
                if not isinstance(node.value, (int, float)) or isinstance(
                    node.value, bool
                ):
                    raise ValueError(
                        f"Constante non numérique : {type(node.value).__name__}"
                    )
                return node.value
            if isinstance(node, _ast.BinOp):
                op_fn = _BIN_OPS.get(type(node.op))
                if op_fn is None:
                    raise ValueError(f"Opérateur interdit : {type(node.op).__name__}")
                left = _walk(node.left, depth + 1)
                right = _walk(node.right, depth + 1)
                return op_fn(left, right)
            if isinstance(node, _ast.UnaryOp):
                operand = _walk(node.operand, depth + 1)
                if isinstance(node.op, _ast.USub):
                    return -operand
                if isinstance(node.op, _ast.UAdd):
                    return +operand
                raise ValueError(f"Opérateur unaire interdit : {type(node.op).__name__}")
            raise ValueError(f"Type de node interdit : {type(node).__name__}")

        try:
            tree = _ast.parse(resolved_str, mode="eval")
            result = _walk(tree)
            if isinstance(result, (int, float)) and not isinstance(result, bool):
                return result
            warnings.append(
                f"Set variable '{var_name}': resultat non numerique ({type(result).__name__})"
            )
            return 0
        except (SyntaxError, ValueError, ZeroDivisionError, TypeError) as e:
            warnings.append(
                f"Set variable '{var_name}': erreur evaluation '{resolved_str}': "
                f"{type(e).__name__}"
            )
            return 0

    # ── Aggregation + Map steps ──

    def _step_aggregate(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Agregation GROUP BY avec fonctions d'agregat.

        group_by: liste de colonnes pour le regroupement
        aggregations: dict {colonne: fonction} avec sum, avg, count, min, max
        """
        group_by = config.get("group_by", [])
        aggregations = config.get("aggregations", {})

        if not group_by:
            return ["Agregation: aucune colonne de regroupement specifiee"]
        if not aggregations or not isinstance(aggregations, dict):
            return ["Agregation: aucune fonction d'agregat specifiee"]

        warnings = []

        # Verifier que les colonnes existent
        missing_group = [c for c in group_by if c not in context.columns]
        if missing_group:
            warnings.append(
                f"Agregation: colonnes de regroupement introuvables: " f"{', '.join(missing_group)}"
            )
            group_by = [c for c in group_by if c in context.columns]
            if not group_by:
                return warnings + ["Agregation: aucune colonne de regroupement valide"]

        missing_agg = [c for c in aggregations if c not in context.columns]
        if missing_agg:
            warnings.append(
                f"Agregation: colonnes d'agregat introuvables (ignorees): "
                f"{', '.join(missing_agg)}"
            )

        valid_fns = {"sum", "avg", "count", "min", "max"}
        valid_aggs = {
            c: fn for c, fn in aggregations.items() if c in context.columns and fn in valid_fns
        }

        if not valid_aggs:
            return warnings + ["Agregation: aucune agregation valide specifiee"]

        # Regrouper les lignes
        groups: Dict[tuple, List[Dict[str, Any]]] = {}
        for row in context.rows:
            key = tuple(row.get(c) for c in group_by)
            groups.setdefault(key, []).append(row)

        # Construire les lignes agregees
        result_rows = []
        for key, group_rows in groups.items():
            result = {}
            # Ajouter les colonnes de regroupement
            for i, col in enumerate(group_by):
                result[col] = key[i]

            # Calculer les agregats
            for col, fn in valid_aggs.items():
                values = [row.get(col) for row in group_rows if row.get(col) is not None]
                numeric_values = []
                for v in values:
                    if _is_numeric(v):
                        numeric_values.append(float(v))

                agg_col = f"{col}_{fn}"
                if fn == "count":
                    result[agg_col] = len(values)
                elif fn == "sum":
                    result[agg_col] = round(sum(numeric_values), 2) if numeric_values else 0
                elif fn == "avg":
                    result[agg_col] = (
                        round(sum(numeric_values) / len(numeric_values), 2)
                        if numeric_values
                        else None
                    )
                elif fn == "min":
                    result[agg_col] = min(numeric_values) if numeric_values else None
                elif fn == "max":
                    result[agg_col] = max(numeric_values) if numeric_values else None

            result_rows.append(result)

        # Mettre a jour le contexte
        context.rows = result_rows
        context.columns = list(result_rows[0].keys()) if result_rows else group_by

        return warnings

    def _step_map_values(self, config: Dict[str, Any], context: WorkflowContext) -> List[str]:
        """Mappe/transforme les valeurs d'une colonne.

        Deux modes:
        - mapping: dict {valeur_source: valeur_cible} — remplacement explicite
        - transform: fonction de transformation (uppercase, lowercase, trim, etc.)

        Les deux peuvent etre combines (mapping applique d'abord, transform ensuite).
        """
        col = config.get("column", "")
        mapping = config.get("mapping", {})
        transform = config.get("transform", "none")
        default_value = config.get("default_value")

        if not col:
            return ["Transformation valeurs: aucune colonne specifiee"]
        if col not in context.columns:
            return [f"Transformation valeurs: colonne '{col}' introuvable"]
        if not mapping and transform == "none":
            return ["Transformation valeurs: aucun mapping ni transformation specifie"]

        warnings = []
        mapped_count = 0
        transformed_count = 0

        for row in context.rows:
            val = row.get(col)

            # Appliquer le mapping explicite
            if mapping and isinstance(mapping, dict):
                str_val = str(val) if val is not None else ""
                if str_val in mapping:
                    row[col] = mapping[str_val]
                    mapped_count += 1
                    val = row[col]  # Utiliser la valeur mappee pour le transform
                elif default_value is not None and str_val not in mapping:
                    # default_value s'applique si la valeur n'est pas dans le mapping
                    # mais seulement si on a un mapping (pas en mode transform seul)
                    row[col] = default_value
                    mapped_count += 1
                    val = row[col]

            # Appliquer la transformation
            if transform and transform != "none":
                new_val = _apply_transform(val, transform)
                if new_val != val:
                    row[col] = new_val
                    transformed_count += 1

        if mapped_count > 0:
            warnings.append(f"Transformation: {mapped_count} valeurs mappees dans '{col}'")
        if transformed_count > 0:
            warnings.append(
                f"Transformation: {transformed_count} valeurs transformees dans '{col}'"
            )

        return warnings


# ── Helpers ──


def _safe_compare(a: Any, b: Any, op) -> bool:
    """Comparaison securisee avec conversion numerique."""
    if a is None or b is None:
        return False
    try:
        return op(float(a), float(b))
    except (ValueError, TypeError):
        try:
            return op(str(a), str(b))
        except TypeError:
            return False


def _sort_key(value: Any):
    """Cle de tri qui gere les None et les types mixtes."""
    if value is None:
        return (1, "")  # None en dernier
    if isinstance(value, (int, float)):
        return (0, value)
    return (0, str(value))


def _is_numeric(value: Any) -> bool:
    """Verifie si une valeur est numerique ou convertible."""
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        try:
            float(value)
            return True
        except ValueError:
            return False
    return False


def _is_float_str(value: Any) -> bool:
    """Verifie si une string represente un float."""
    if not isinstance(value, str):
        return False
    try:
        float(value)
        return True
    except ValueError:
        return False


def _is_date_str(value: Any) -> bool:
    """Verifie si une valeur ressemble a une date."""
    if isinstance(value, datetime):
        return True
    if not isinstance(value, str):
        return False
    date_patterns = [
        r"^\d{4}-\d{2}-\d{2}",  # ISO 8601
        r"^\d{2}/\d{2}/\d{4}",  # DD/MM/YYYY
        r"^\d{2}-\d{2}-\d{4}",  # DD-MM-YYYY
    ]
    return any(re.match(p, value) for p in date_patterns)


def _apply_transform(value: Any, transform: str) -> Any:
    """Applique une transformation a une valeur."""
    if transform == "uppercase":
        return str(value).upper() if value is not None else value
    elif transform == "lowercase":
        return str(value).lower() if value is not None else value
    elif transform == "trim":
        return str(value).strip() if value is not None else value
    elif transform == "strip_spaces":
        return re.sub(r"\s+", " ", str(value)).strip() if value is not None else value
    elif transform == "to_number":
        if value is None:
            return None
        try:
            f = float(value)
            return int(f) if f.is_integer() else f
        except (ValueError, TypeError, OverflowError):
            return None
    elif transform == "to_text":
        return str(value) if value is not None else ""
    elif transform == "null_to_empty":
        return "" if value is None else value
    elif transform == "null_to_zero":
        return 0 if value is None else value
    return value


def _parse_expression(expression: str, columns: List[str]):
    """Parse une expression simple et retourne une callable.

    Whitelist-only: seuls les noms de colonnes connues, operateurs arithmetiques,
    nombres litteraux et concat() sont acceptes.

    Expressions supportees:
    - col1 + col2, col1 - col2, col1 * col2, col1 / col2
    - col1 * 1.2, col1 + 100, col1 * -1.5
    - concat(col1, col2)
    """
    expression = expression.strip()

    # concat(col1, col2, ...)
    concat_match = re.match(r"^concat\((.+)\)$", expression, re.IGNORECASE)
    if concat_match:
        parts = [p.strip() for p in concat_match.group(1).split(",")]
        # Whitelist: chaque partie doit etre un nom de colonne connu
        invalid = [p for p in parts if p not in columns]
        if invalid:
            return None
        return lambda row, _parts=parts: "".join(str(row.get(p, "")) for p in _parts)

    # Binary op: col op col/number (ou col op -number)
    # Utiliser regex pour trouver l'operateur au bon endroit (pas dans un nombre negatif)
    # Pattern: <identifier> <op> <identifier_or_number>
    bin_match = re.match(
        r"^(.+?)\s*([+\-*/])\s*(.+)$",
        expression,
    )
    if not bin_match:
        return None

    left = bin_match.group(1).strip()
    sym = bin_match.group(2)
    right = bin_match.group(3).strip()

    # Whitelist: left MUST be a known column
    if left not in columns:
        return None

    ops = {"+": operator.add, "-": operator.sub, "*": operator.mul, "/": operator.truediv}
    op_fn = ops.get(sym)
    if op_fn is None:
        return None

    # Whitelist: right is either a known column or a literal number (including negative)
    if right in columns:
        return lambda row, _l=left, _r=right, _op=op_fn: _op(
            float(row.get(_l, 0) or 0), float(row.get(_r, 0) or 0)
        )

    try:
        num = float(right)
        return lambda row, _l=left, _n=num, _op=op_fn: _op(float(row.get(_l, 0) or 0), _n)
    except ValueError:
        return None


# ── Variable system ──

# Pattern pour les templates {{step_name.var_name}}
# Accepte uniquement les identifiants valides (lettres, chiffres, _, .)
_TEMPLATE_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")


def _sanitize_step_name(name: str) -> str:
    """Normalise un nom d'etape en identifiant Python-safe.

    - Supprime les accents (NFD + strip combining marks)
    - Convertit en minuscules
    - Remplace les caracteres non-alphanumeriques par des underscores
    - Supprime les underscores en debut/fin
    - Tronque a 50 caracteres
    - Retourne "step" si le resultat est vide
    """
    if not name or not name.strip():
        return "step"

    # Minuscules + remplacer tout caractere non-alnum (y compris accents) par underscore
    result = re.sub(r"[^a-zA-Z0-9]", "_", name.lower())
    # Supprimer les caracteres non-ASCII restants (accents decomposes)
    result = result.encode("ascii", "ignore").decode("ascii")

    # Supprimer les underscores multiples consecutifs
    result = re.sub(r"_+", "_", result)

    # Supprimer les underscores en debut/fin
    result = result.strip("_")

    # Tronquer a 50 caracteres
    result = result[:50]

    return result if result else "step"


def resolve_template_variables(value: Any, variables: Dict[str, Any]) -> Tuple[Any, List[str]]:
    """Resout les templates {{step.var}} dans une valeur.

    Supporte: str, dict, list. Les autres types sont retournes tels quels.

    Si la valeur entiere est UN seul template (ex: "{{step1.count}}"),
    retourne le type brut (int, list, etc.) au lieu d'une string.

    Returns:
        (resolved_value, list_of_unresolved_keys)
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value, []

    if isinstance(value, str):
        return _resolve_template_string(value, variables)

    if isinstance(value, dict):
        resolved = {}
        all_unresolved = []
        for k, v in value.items():
            rv, unresolved = resolve_template_variables(v, variables)
            resolved[k] = rv
            all_unresolved.extend(unresolved)
        return resolved, all_unresolved

    if isinstance(value, list):
        resolved = []
        all_unresolved = []
        for item in value:
            rv, unresolved = resolve_template_variables(item, variables)
            resolved.append(rv)
            all_unresolved.extend(unresolved)
        return resolved, all_unresolved

    return value, []


def _resolve_template_string(text: str, variables: Dict[str, Any]) -> Tuple[Any, List[str]]:
    """Resout les templates dans une chaine.

    Cas special: si la chaine est exactement UN template (ex: "{{step1.count}}"),
    retourne le type brut de la variable (int, list, etc.) sans conversion string.
    """
    if not text:
        return text, []

    matches = list(_TEMPLATE_PATTERN.finditer(text))
    if not matches:
        return text, []

    unresolved = []

    # Cas special: chaine = un seul template -> retourne le type brut
    if len(matches) == 1 and matches[0].group(0) == text.strip():
        key = matches[0].group(1)
        if key in variables:
            return variables[key], []
        unresolved.append(key)
        return text, unresolved

    # Cas general: interpolation string
    def replace_match(match: re.Match) -> str:
        key = match.group(1)
        if key in variables:
            return str(variables[key])
        unresolved.append(key)
        return match.group(0)  # Laisser tel quel si non resolu

    result = _TEMPLATE_PATTERN.sub(replace_match, text)
    return result, unresolved


def capture_step_variables(
    ctx: WorkflowContext,
    step_name: str,
    step_type: str,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Capture les variables de sortie d'une etape dans le contexte.

    Variables communes capturees pour toute etape:
    - row_count: nombre de lignes en sortie
    - column_count: nombre de colonnes
    - columns: liste des colonnes (copie)
    - status: "success"

    Args:
        ctx: Contexte du workflow
        step_name: Nom de l'etape (sera sanitize)
        step_type: Type de l'etape (pour variables specifiques)
        extra: Variables supplementaires specifiques au type d'etape
    """
    common_vars = {
        "row_count": len(ctx.rows),
        "column_count": len(ctx.columns),
        "columns": list(ctx.columns),  # Copie pour eviter les references partagees
        "status": "success",
    }
    ctx.set_variables(step_name, common_vars)

    if extra:
        ctx.set_variables(step_name, extra)


# Singleton
_engine: Optional[WorkflowEngine] = None


def get_workflow_engine() -> WorkflowEngine:
    """Recupere l'instance singleton du moteur de workflow."""
    global _engine
    if _engine is None:
        _engine = WorkflowEngine()
    return _engine
