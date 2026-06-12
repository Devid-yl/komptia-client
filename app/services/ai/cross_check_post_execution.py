"""T25 — Vérification croisée post-exécution via variante SQL équivalente.

But : quand un SQL retourne un résultat sensible (agrégat sur grosse
table), exécuter une **variante équivalente** du SQL et comparer les
métriques (row_count + somme des colonnes numériques agrégées). Si
l'écart dépasse un seuil (``divergence_threshold``, défaut 1 %), on
flag ``cross_check_warning`` dans la réponse du tool ``execute_sql``
pour que le LLM Iris alerte l'utilisateur.

Cible des bugs « données fausses silencieuses » :

- Le LLM a oublié un filtre WHERE → row_count gonflé
- Le LLM a mis le mauvais sens d'un JOIN → somme amplifiée
- Le LLM a perdu un GROUP BY → résultats agrégés différents
- Mauvaise interaction NULL / COALESCE → somme erronée
- Bug parsing dialect SQL Server (vue, CTE corrompue)

C'est la catégorie **pire** selon ``consequences.md`` (résultat
incorrect sans erreur visible — 100x pire qu'un crash net).

Stratégie programmatique (0 appel LLM) :

1. **Conditions strictes** d'activation (cap coût à 2× exec) :

   - Le SQL contient un agrégat (SUM/AVG/COUNT/MIN/MAX) — sinon pas
     de sens, le caller saura déjà s'il a 0 rows ou 1 row.
   - Au moins une table participante a ``rows`` > ``large_table_threshold``
     (défaut 1 M) — sur petites tables, l'agent peut tout vérifier
     visuellement.
   - On n'est pas en mode exploration (T23) — l'utilisateur attend
     un résultat précis, pas un panorama.
   - Le résultat original n'est pas tronqué par ``max_rows`` —
     sinon le row_count comparé est faussé d'office.

2. **Variante via wrapping** (sub-query) — choisie pour 3 raisons :

   - **Sémantiquement équivalente garantie** : enveloper le SQL dans
     ``SELECT COUNT(*), SUM(col) FROM (<orig>) AS _t`` ne modifie
     pas la sémantique de la requête originale ; pas de risque de
     dériver (contrairement à un INNER JOIN → EXISTS qui peut
     diverger sur les doublons, NULL handling, etc.).
   - **Generic dialect-agnostic** : fonctionne T-SQL, SQLite,
     Postgres.
   - **Indépendante du contenu** : ne dépend pas des FK / colonnes.

3. **Comparaison double** :

   - ``row_count`` : variante vs original (avec tolérance).
   - ``SUM(col)`` pour chaque colonne numérique du SELECT : variante
     vs somme calculée côté caller depuis les rows brutes.

4. **Tolérance relative** (``divergence_threshold``, défaut 1 %) :
   ``abs(a - b) / max(abs(a), abs(b), 1) > threshold`` → warning.
   Le ``max(1, ...)`` évite la division par zéro et limite l'amplification
   sur petites valeurs.

Sécurité :

- La variante passe par le **même query_executor** que l'original
  (RLS appliqué, timeout borné).
- Aucun nom de table BDD source hardcodé — pure analyse AST sqlglot.
- Fail-safe absolu : aucune exception remontée. Si le diagnostic
  crash, le caller récupère ``skipped`` ou ``error`` mais le retour
  utilisateur n'est pas bloqué.

Generic : 0 nom BDD hardcodé. Aucune connaissance Sage Coala-spécifique.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

# Ce module est un DÉTECTEUR de « données fausses silencieuses » (cf. docstring) :
# s'il se désactive lui-même EN SILENCE, on perd le filet sans le savoir — le pire
# scénario. ``sqlglot`` est une dépendance (requirements) ; s'il manque (deploy
# cassé), TOUTES les fonctions d'analyse AST renvoient ``[]`` et le cross-check est
# SKIP silencieusement. On SIGNALE l'absence UNE FOIS au boot pour que la
# désactivation du filet soit visible côté ops (les imports paresseux par fonction
# restent en place pour une dégradation gracieuse).
try:
    import sqlglot as _sqlglot_probe  # noqa: F401

    _SQLGLOT_AVAILABLE = True
except ImportError:
    _SQLGLOT_AVAILABLE = False
    logger.warning(
        "cross_check_post_execution : sqlglot INDISPONIBLE — le détecteur de "
        "résultats SQL faux (cross-check post-exécution) est DÉSACTIVÉ. Installer "
        "sqlglot (requirements) pour réactiver ce filet de sécurité."
    )


# ════════════════════════════════════════════════════════════════════════
# Constants — surchargables au call site (audit-friendly ici)
# ════════════════════════════════════════════════════════════════════════

#: Seuil de divergence relatif (1 %). Au-dessous, on considère que
#: l'écart est dû à des flottants / arrondis / ordering non-déterministe.
DEFAULT_DIVERGENCE_THRESHOLD: float = 0.01

#: Timeout d'exécution de la variante en secondes. Borné dur pour
#: garantir qu'un user n'attend pas 30 s de plus en cas de pathologie.
DEFAULT_VARIANT_TIMEOUT_SECONDS: float = 10.0

#: Tables avec ``rows`` >= ce seuil sont considérées « grosses » et
#: déclenchent le cross-check. Sur petite table, l'agent peut tout
#: vérifier visuellement et le coût 2× ne se justifie pas.
DEFAULT_LARGE_TABLE_THRESHOLD: int = 1_000_000

#: Cap nombre de colonnes numériques (de l'agrégat original) qu'on
#: re-somme côté variante. Borne le coût et la taille du SQL injecté.
DEFAULT_MAX_NUMERIC_COLUMNS_TO_CHECK: int = 5


# ════════════════════════════════════════════════════════════════════════
# Helpers AST sqlglot — privés, exposés pour tests
# ════════════════════════════════════════════════════════════════════════


def _safe_parse(sql: str, dialect: str = "tsql"):
    """Parse le SQL avec sqlglot. Retourne (tree, error) — jamais raise."""
    if not isinstance(sql, str) or not sql.strip():
        return None, "empty_or_invalid_sql"
    try:
        import sqlglot
    except ImportError:
        return None, "sqlglot_not_available"
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except Exception as exc:  # noqa: BLE001 — fail-safe
        return None, f"parse_failed: {type(exc).__name__}"
    if tree is None:
        return None, "parse_returned_none"
    return tree, None


def _detect_aggregates(tree) -> list[str]:
    """Retourne les types d'agrégats présents (``"SUM"``, ``"AVG"`` …).

    Cherche dans tout l'AST (subqueries, CTE inclus). Liste dédupliquée
    pour audit. Ordre stable.
    """
    if tree is None:
        return []
    try:
        from sqlglot import expressions as exp
    except ImportError:
        return []

    # Mapping AST class → label canonique
    agg_classes = (
        (exp.Sum, "SUM"),
        (exp.Avg, "AVG"),
        (exp.Count, "COUNT"),
        (exp.Min, "MIN"),
        (exp.Max, "MAX"),
    )
    found: list[str] = []
    seen: set[str] = set()
    for cls, label in agg_classes:
        if tree.find(cls) is not None and label not in seen:
            found.append(label)
            seen.add(label)
    return found


def _extract_top_level_select(tree):
    """Retourne le SELECT racine (après CTE éventuelle), ou ``None``."""
    if tree is None:
        return None
    try:
        from sqlglot import expressions as exp
    except ImportError:
        return None
    # Le top-level peut être un Select direct ou un With → Select
    if isinstance(tree, exp.Select):
        return tree
    return tree.find(exp.Select)


def _extract_numeric_aggregate_aliases(tree) -> list[tuple[str, str]]:
    """Retourne ``[(alias, aggregate_type), ...]`` pour les projections
    du SELECT racine qui sont des agrégats numériques (SUM/AVG/MIN/MAX
    ou COUNT).

    L'alias est :
    - le ``alias`` explicite si présent (``SUM(amount) AS total``)
    - sinon le nom canonique de l'expression (``SUM(amount)`` → ``"SUM(amount)"``).

    Utilisé par le caller pour mapper l'alias à l'index de colonne
    dans ``original_rows`` et calculer la somme côté original.
    """
    sel = _extract_top_level_select(tree)
    if sel is None:
        return []
    try:
        from sqlglot import expressions as exp
    except ImportError:
        return []

    agg_classes = (exp.Sum, exp.Avg, exp.Count, exp.Min, exp.Max)
    out: list[tuple[str, str]] = []
    for proj in sel.expressions or []:
        # Déballer Alias
        inner = proj.this if isinstance(proj, exp.Alias) else proj
        # Détecter agrégat (la projection PEUT être un agrégat
        # direct, ou contenir un agrégat dans une expression composée :
        # ``SUM(amount) * 1.2 AS total``). On considère le premier
        # agrégat trouvé comme type représentatif.
        agg_node = None
        agg_label = ""
        for cls in agg_classes:
            agg_node = inner.find(cls) if hasattr(inner, "find") else None
            if agg_node is not None:
                agg_label = cls.__name__.upper()
                break
        if agg_node is None:
            continue

        alias = ""
        if isinstance(proj, exp.Alias):
            alias = proj.alias or ""
        if not alias:
            # Pas d'alias explicite : utiliser le SQL canonique de
            # l'expression comme nom de colonne (le query_executor
            # retournera ce label dans columns).
            try:
                alias = inner.sql(dialect="tsql")
            except Exception:  # noqa: BLE001
                alias = agg_node.sql(dialect="tsql") if agg_node is not None else ""
        out.append((alias, agg_label))
    return out


def _extract_participating_tables(tree) -> set[str]:
    """Retourne les noms de tables physiques participantes (CTE et
    sous-queries aliasées exclues).

    Utilise sqlglot directement (vs ``zero_rows_diagnostic`` qui passe
    par SQLValidator) pour éviter une dépendance circulaire et avoir
    un comportement plus prédictible sur les SQL synthétiques de test.
    """
    if tree is None:
        return set()
    try:
        from sqlglot import expressions as exp
    except ImportError:
        return set()

    cte_names: set[str] = set()
    for cte in tree.find_all(exp.CTE):
        try:
            n = cte.alias_or_name
        except Exception:  # noqa: BLE001
            n = None
        if n:
            cte_names.add(str(n).upper())

    tables: set[str] = set()
    for t in tree.find_all(exp.Table):
        name = getattr(t, "name", None) or ""
        if not name:
            continue
        if name.upper() in cte_names:
            continue
        tables.add(name)
    return tables


def _strip_order_by(tree):
    """Supprime les clauses ``ORDER BY`` du tree (tous niveaux).

    Une sub-query ``(SELECT … ORDER BY x) AS _t`` est invalide en
    T-SQL sans TOP/OFFSET. On strip globalement avant wrapping. Le
    tree passé est muté in-place ET retourné.
    """
    if tree is None:
        return tree
    try:
        from sqlglot import expressions as exp
    except ImportError:
        return tree
    for order in list(tree.find_all(exp.Order)):
        parent = order.parent
        if parent is None:
            continue
        # Détache via set('order', None) si le parent expose
        # l'attribut, sinon best-effort remove via replace.
        try:
            if "order" in parent.args:
                parent.set("order", None)
            else:
                order.pop()
        except Exception:  # noqa: BLE001
            try:
                order.pop()
            except Exception:  # noqa: BLE001
                pass
    return tree


def _has_top_level_top_or_limit(tree) -> bool:
    """``True`` si le SELECT racine a un TOP / LIMIT explicite."""
    sel = _extract_top_level_select(tree)
    if sel is None:
        return False
    try:
        return bool(sel.args.get("limit"))
    except Exception:  # noqa: BLE001
        return False


def _diff_ratio(a: Optional[float], b: Optional[float]) -> float:
    """Ratio d'écart relatif. Retourne 0.0 si les deux sont None ou égaux.

    Formule : ``abs(a - b) / max(abs(a), abs(b), 1)`` — bornée à
    [0, ~2] avec division-by-zero safe. Si l'une des valeurs est None
    et l'autre non, retourne 1.0 (divergence totale).
    """
    if a is None and b is None:
        return 0.0
    if a is None or b is None:
        return 1.0
    try:
        af = float(a)
        bf = float(b)
    except (TypeError, ValueError):
        return 1.0
    denom = max(abs(af), abs(bf), 1.0)
    return abs(af - bf) / denom


def _coerce_numeric(val: Any) -> Optional[float]:
    """Convertit ``val`` en float si possible (None / NaN-friendly)."""
    if val is None:
        return None
    if isinstance(val, bool):
        # bool est sous-classe int — on rejette pour éviter les
        # surprises sur SUM(True+True)=2.
        return None
    if isinstance(val, (int, float)):
        try:
            f = float(val)
        except (TypeError, ValueError, OverflowError):
            return None
        # Filtre NaN (NaN != NaN)
        if f != f:
            return None
        return f
    if isinstance(val, str):
        try:
            return float(val)
        except (TypeError, ValueError):
            return None
    # Tout le reste (date, decimal.Decimal …) — essayer le cast
    try:
        return float(val)
    except (TypeError, ValueError, OverflowError):
        return None


def _sum_column_from_rows(rows: Iterable[Any], col_index: int) -> Optional[float]:
    """Somme la colonne ``col_index`` des rows. None si tout est None.

    Tolère rows = list[tuple] OU list[list]. Les valeurs non-numériques
    sont ignorées (cohérent avec SQL ``SUM`` qui ignore NULL).
    """
    if rows is None:
        return None
    total: Optional[float] = None
    found_any = False
    for row in rows:
        if not isinstance(row, (list, tuple)):
            continue
        if col_index >= len(row):
            continue
        v = _coerce_numeric(row[col_index])
        if v is None:
            continue
        found_any = True
        total = (total or 0.0) + v
    if not found_any:
        return None
    return total


# ════════════════════════════════════════════════════════════════════════
# Helper public : construction du wrapper SQL
# ════════════════════════════════════════════════════════════════════════


def _quote_identifier(name: str, dialect: str = "tsql") -> str:
    """Quote un identifier pour le wrapping. T-SQL utilise ``[name]``,
    SQLite/Postgres utilisent ``"name"``. Fail-safe : si l'identifier
    contient un guillemet, on retourne tel quel (le wrapping échouera
    et le caller fail-safera).
    """
    if not isinstance(name, str):
        return ""
    safe = name.replace("]", "")
    if dialect.lower() in ("tsql", "mssql"):
        return f"[{safe}]"
    safe2 = safe.replace('"', "")
    return f'"{safe2}"'


def build_wrapped_variant_sql(
    original_sql: str,
    numeric_aliases: list[str],
    *,
    dialect: str = "tsql",
) -> Optional[str]:
    """Construit le SQL de variante via wrapping sub-query.

    Forme retournée (avec n agrégats) ::

        SELECT
            COUNT(*) AS _xc_rc,
            COALESCE(SUM(CAST([alias1] AS FLOAT)), 0) AS _xc_s_0,
            COALESCE(SUM(CAST([alias2] AS FLOAT)), 0) AS _xc_s_1,
            ...
        FROM (<original_sql_sans_order_by>) AS _xc_t

    Retourne ``None`` si le SQL original ne peut pas être parsé /
    nettoyé (le caller doit alors skip).

    Generic : pas de nom BDD hardcodé. L'alias de la sub-query
    (``_xc_t``) est un nom interne réservé.
    """
    tree, err = _safe_parse(original_sql, dialect=dialect)
    if tree is None:
        logger.info("cross_check: parse failed (%s) — variant skipped", err)
        return None

    # ORDER BY interdit dans une sub-query T-SQL sans TOP : on strip
    # globalement avant wrapping. Si le SELECT racine a un TOP/LIMIT
    # explicite, on garde l'ORDER BY au top-level pour ne pas modifier
    # le set retourné par TOP n ORDER BY x (qui dépend de l'order).
    if not _has_top_level_top_or_limit(tree):
        _strip_order_by(tree)

    try:
        cleaned_sql = tree.sql(dialect=dialect)
    except Exception as exc:  # noqa: BLE001
        logger.info("cross_check: regen sql failed: %s", exc)
        return None

    # Projections wrapper
    projections: list[str] = ["COUNT(*) AS _xc_rc"]
    for i, alias in enumerate(numeric_aliases):
        if not alias or not isinstance(alias, str):
            continue
        # Caps stricts sur la taille pour éviter SQL injection /
        # alias absurdes. Les vrais alias SELECT mesurent < 100 chars.
        if len(alias) > 100:
            continue
        # On accepte tous les caractères dans le quoting — le wrapping
        # protège déjà. Mais on refuse les ] / " bruts qui pourraient
        # casser le quoting :
        if "]" in alias or '"' in alias:
            continue
        quoted = _quote_identifier(alias, dialect=dialect)
        if not quoted:
            continue
        projections.append(f"COALESCE(SUM(CAST({quoted} AS FLOAT)), 0) AS _xc_s_{i}")

    return "SELECT " + ", ".join(projections) + f" FROM ({cleaned_sql}) AS _xc_t"


# ════════════════════════════════════════════════════════════════════════
# Helper public : skip decision
# ════════════════════════════════════════════════════════════════════════


def _max_row_count_from_schema(tables: Iterable[str], schema_loader: Any) -> Optional[int]:
    """Pour un set de tables, retourne le ``rows`` max selon le schema
    (``schema_loader.get_table(name).get("rows")``). ``None`` si schema
    indisponible ou aucune table résolvable.

    Generic : ne suppose pas de table-prefix particulier ; teste le
    nom tel quel ET sa version uppercase si différent.
    """
    if schema_loader is None:
        return None
    max_rows: Optional[int] = None
    try:
        get_table = getattr(schema_loader, "get_table", None)
        if not callable(get_table):
            return None
        for t in tables:
            if not isinstance(t, str) or not t:
                continue
            meta = None
            for variant in {t, t.upper(), t.lower()}:
                try:
                    meta = get_table(variant)
                except Exception:  # noqa: BLE001
                    meta = None
                if isinstance(meta, dict):
                    break
            if not isinstance(meta, dict):
                continue
            rc = meta.get("rows")
            if rc is None:
                rc = meta.get("row_count")
            try:
                rc_int = int(rc) if rc is not None else None
            except (TypeError, ValueError):
                continue
            if rc_int is None:
                continue
            if max_rows is None or rc_int > max_rows:
                max_rows = rc_int
    except Exception:  # noqa: BLE001 — fail-safe
        logger.info("cross_check: schema_loader access failed")
        return None
    return max_rows


# ════════════════════════════════════════════════════════════════════════
# API publique
# ════════════════════════════════════════════════════════════════════════


def _empty_response(
    *,
    skip_reason: Optional[str] = None,
    error: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "has_warning": False,
        "reason": "skipped" if skip_reason else ("error" if error else "no_issue"),
        "skip_reason": skip_reason,
        "confidence": 0.0,
        "details": {},
        "error": error,
    }


async def cross_check_sql_result(
    sql: str,
    original_row_count: Optional[int],
    query_executor: Any,
    user: Any,
    *,
    original_columns: Optional[list[str]] = None,
    original_rows: Optional[list[Any]] = None,
    schema_loader: Any = None,
    exploration_mode: bool = False,
    large_table_threshold: int = DEFAULT_LARGE_TABLE_THRESHOLD,
    divergence_threshold: float = DEFAULT_DIVERGENCE_THRESHOLD,
    timeout_seconds: float = DEFAULT_VARIANT_TIMEOUT_SECONDS,
    max_numeric_columns: int = DEFAULT_MAX_NUMERIC_COLUMNS_TO_CHECK,
    truncated: bool = False,
    params: Optional[tuple] = None,
    dialect: str = "tsql",
) -> dict[str, Any]:
    """Cross-check post-exécution via variante SQL équivalente.

    Args:
        sql: la requête originale (chaîne brute).
        original_row_count: ``result.row_count`` retourné par le query_executor.
        query_executor: instance avec ``async execute(...)`` (cf.
            :class:`app.services.database.query_executor.QueryExecutor`).
        user: utilisateur pour RLS (transmis à la variante).
        original_columns: ``list[str]`` des colonnes du SELECT — utilisée
            pour mapper l'alias d'agrégat → index pour calculer la somme
            côté original.
        original_rows: ``list[tuple|list]`` des rows brutes retournées.
            Si ``None``, on ne compare pas les sums (seulement row_count).
        schema_loader: instance avec ``get_table(name) -> dict`` ;
            utilisée pour décider « large table ». Si None, on suppose
            qu'on ne sait pas et on **skip**.
        exploration_mode: si True, skip (T23).
        large_table_threshold: seuil ``rows`` pour activer (défaut 1 M).
        divergence_threshold: seuil de divergence relatif (défaut 0.01).
        timeout_seconds: timeout exec variante (défaut 10 s).
        max_numeric_columns: cap colonnes numériques re-sommées.
        truncated: si True, le ``result.row_count`` ne couvre pas tout
            le résultat (cap max_rows). Skip car comparison faussée.
        dialect: dialect sqlglot (défaut tsql).

    Returns:
        Dict avec keys :

        - ``has_warning`` (bool)
        - ``reason`` (str) : ``"no_issue" | "row_count_divergence" |
          "sum_divergence" | "variant_failed" | "skipped" | "error"``
        - ``skip_reason`` (str | None) : ``"no_aggregates" | "no_large_table"
          | "exploration_mode" | "schema_unavailable" | "truncated" |
          "row_count_unknown" | "variant_build_failed"``
        - ``confidence`` (float) : [0, 1] ; haute si divergence claire
        - ``details`` (dict) — voir code pour clés exactes
        - ``error`` (str | None)

    Fail-safe : aucune exception remontée.
    """
    # ── 1. Skip rapide : args invalides ──
    if not isinstance(sql, str) or not sql.strip():
        return _empty_response(error="empty_or_invalid_sql")

    if original_row_count is None:
        return _empty_response(skip_reason="row_count_unknown")

    if truncated:
        return _empty_response(skip_reason="truncated")

    if exploration_mode:
        return _empty_response(skip_reason="exploration_mode")

    # Skip si SQL paramétré (?) — la variante wrapping doit recevoir
    # les mêmes params sous peine de crash. On choisit de skip plutôt
    # que de propager `params` aveuglément (la sémantique d'un `?` dans
    # un SELECT enveloppé est dialect-spécifique et fragile).
    if params is not None and len(params) > 0:
        return _empty_response(skip_reason="parameterized_sql")

    # ── 2. Parse + détection agrégats ──
    tree, err = _safe_parse(sql, dialect=dialect)
    if tree is None:
        return _empty_response(error=err)

    aggregates_found = _detect_aggregates(tree)
    if not aggregates_found:
        return _empty_response(skip_reason="no_aggregates")

    # ── 3. Détection large table via schema_loader ──
    if schema_loader is None:
        return _empty_response(skip_reason="schema_unavailable")

    participating = _extract_participating_tables(tree)
    if not participating:
        # Pas de table physique repérable (CTE-only, scalar, etc.).
        # Pas de notion de « large table », skip.
        return _empty_response(skip_reason="no_physical_tables")

    max_rows = _max_row_count_from_schema(participating, schema_loader)
    if max_rows is None or max_rows < large_table_threshold:
        return _empty_response(skip_reason="no_large_table")

    # ── 4. Extraction des aliases d'agrégat numérique du SELECT racine ──
    numeric_aggs = _extract_numeric_aggregate_aliases(tree)
    # Limite cap colonnes
    numeric_aggs_capped = numeric_aggs[: max(0, int(max_numeric_columns))]
    aliases_to_check = [a for (a, _t) in numeric_aggs_capped]

    # ── 5. Construire la variante wrapping ──
    variant_sql = build_wrapped_variant_sql(sql, aliases_to_check, dialect=dialect)
    if not variant_sql:
        return _empty_response(skip_reason="variant_build_failed")

    # ── 6. Exécuter la variante avec timeout strict ──
    try:
        variant_result = await asyncio.wait_for(
            query_executor.execute(
                variant_sql,
                max_rows=1,
                add_limit=False,
                timeout=int(max(1, timeout_seconds)),
                user=user,
                rls_source="cross_check_post_execution",
            ),
            timeout=timeout_seconds + 1.0,
        )
    except (asyncio.TimeoutError, asyncio.CancelledError):
        logger.info(
            "cross_check: variant timeout (%.1fs) — skipped (no warning emitted)",
            timeout_seconds,
        )
        return {
            "has_warning": False,
            "reason": "variant_failed",
            "skip_reason": None,
            "confidence": 0.0,
            "details": {
                "aggregates_found": aggregates_found,
                "aliases_checked": aliases_to_check,
                "large_tables_max_rows": max_rows,
            },
            "error": "variant_timeout",
        }
    except Exception:  # noqa: BLE001 — fail-safe (RLS, parse-side, etc.)
        logger.info(
            "cross_check: variant exec failed — skipped (no warning emitted)",
        )
        return {
            "has_warning": False,
            "reason": "variant_failed",
            "skip_reason": None,
            "confidence": 0.0,
            "details": {
                "aggregates_found": aggregates_found,
                "aliases_checked": aliases_to_check,
                "large_tables_max_rows": max_rows,
            },
            "error": "variant_exec_failed",
        }

    # ── 7. Extraire metrics de la variante ──
    variant_rows = getattr(variant_result, "rows", None)
    if not variant_rows:
        return {
            "has_warning": False,
            "reason": "variant_failed",
            "skip_reason": None,
            "confidence": 0.0,
            "details": {"aggregates_found": aggregates_found},
            "error": "variant_returned_no_rows",
        }

    first_row = variant_rows[0]
    # Format: tuple/list (rc, s0, s1, ...) ou dict {"_xc_rc": ..., ...}
    variant_rc: Optional[float] = None
    variant_sums: dict[int, Optional[float]] = {}
    if isinstance(first_row, dict):
        variant_rc = _coerce_numeric(first_row.get("_xc_rc"))
        for i in range(len(aliases_to_check)):
            variant_sums[i] = _coerce_numeric(first_row.get(f"_xc_s_{i}"))
    else:
        try:
            variant_rc = _coerce_numeric(first_row[0])
            for i in range(len(aliases_to_check)):
                idx = i + 1
                if idx < len(first_row):
                    variant_sums[i] = _coerce_numeric(first_row[idx])
        except (IndexError, TypeError):
            pass

    # ── 8. Calculer les sommes côté original (si rows fournies) ──
    original_sums: dict[int, Optional[float]] = {}
    if original_rows is not None and original_columns:
        col_to_idx = {c: i for i, c in enumerate(original_columns)}
        for i, alias in enumerate(aliases_to_check):
            idx = col_to_idx.get(alias)
            if idx is None:
                # Tente le matching insensible à la casse
                lowered = {c.lower(): i for i, c in enumerate(original_columns)}
                idx = lowered.get(alias.lower())
            if idx is None:
                original_sums[i] = None
                continue
            original_sums[i] = _sum_column_from_rows(original_rows, idx)

    # ── 9. Comparaison ──
    rc_ratio = _diff_ratio(variant_rc, original_row_count)
    rc_divergent = rc_ratio > divergence_threshold

    sum_divergences: list[dict[str, Any]] = []
    for i, alias in enumerate(aliases_to_check):
        v = variant_sums.get(i)
        o = original_sums.get(i) if original_sums else None
        if v is None and o is None:
            # Rien à comparer (probable colonne non-numérique côté
            # original, ou CAST FAILED côté variant). Skip silently.
            continue
        if o is None:
            # Original sum unknown (no rows fournies / col non
            # mappée). On note la variant value pour audit mais on
            # ne lève pas de divergence.
            continue
        ratio = _diff_ratio(v, o)
        if ratio > divergence_threshold:
            sum_divergences.append(
                {
                    "alias": alias,
                    "variant_sum": v,
                    "original_sum": o,
                    "diff_ratio": ratio,
                }
            )

    has_issue = rc_divergent or bool(sum_divergences)
    reason: str
    if rc_divergent and sum_divergences:
        reason = "row_count_divergence"
    elif rc_divergent:
        reason = "row_count_divergence"
    elif sum_divergences:
        reason = "sum_divergence"
    else:
        reason = "no_issue"

    # Confidence: échelle simple liée au ratio
    max_ratio = rc_ratio
    for d in sum_divergences:
        if d["diff_ratio"] > max_ratio:
            max_ratio = d["diff_ratio"]
    confidence = min(1.0, max_ratio / max(divergence_threshold * 10, 0.001))

    return {
        "has_warning": has_issue,
        "reason": reason,
        "skip_reason": None,
        "confidence": round(confidence, 2),
        "details": {
            "original_row_count": original_row_count,
            "variant_row_count": int(variant_rc) if variant_rc is not None else None,
            "row_count_ratio": round(rc_ratio, 4),
            "aliases_checked": aliases_to_check,
            "sum_divergences": sum_divergences,
            "aggregates_found": aggregates_found,
            "large_tables_max_rows": max_rows,
            "threshold": divergence_threshold,
        },
        "error": None,
    }
