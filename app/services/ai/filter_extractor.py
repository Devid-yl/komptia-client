"""Extraction structurée des filtres WHERE d'un SQL (fix B10).

Permet de répondre à la question "quels filtres ont été appliqués ?"
— utile pour :
- Traçabilité : afficher à l'utilisateur les filtres réellement utilisés
- Debug : corréler un résultat inattendu avec un filtre hardcodé inattendu
- Audit : détecter les prédicats inventés par le LLM

Utilise sqlglot (déjà en dépendance) pour un parsing robuste des dialectes
T-SQL / SQL Server. Les prédicats de JOIN (ON) sont ignorés — on ne veut
que les filtres effectifs du WHERE. Fail-open : si le SQL ne parse pas,
retourne une liste vide plutôt que de lever.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    import sqlglot
    from sqlglot import exp

    _SQLGLOT_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SQLGLOT_AVAILABLE = False


@dataclass(frozen=True)
class FilterPredicate:
    """Un prédicat WHERE atomique."""

    column: str  # ex: "f.facDate"
    operator: str  # "=", "<>", ">", ">=", "<", "<=", "IN", "LIKE",
    # "BETWEEN", "IS NULL", "IS NOT NULL"
    value: Any  # str | int | float | list | (low, high) | None
    raw: str  # Le prédicat tel qu'écrit dans le SQL
    negated: bool = False  # True si sous un NOT


def extract_filters_from_sql(
    sql: str,
    dialect: str = "tsql",
) -> list[FilterPredicate]:
    """Parse le SQL et retourne la liste des prédicats WHERE.

    Les conditions ON de JOIN et les prédicats de sous-requêtes sont
    ignorés — on ne veut que les filtres du niveau outer pour la
    traçabilité user.

    Retourne ``[]`` si :
    - sqlglot indisponible
    - parsing échoue
    - pas de WHERE dans le SQL
    - SQL non-SELECT

    Ne lève jamais : tout échec produit une liste vide.
    """
    if not _SQLGLOT_AVAILABLE or not sql or not isinstance(sql, str):
        return []

    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except Exception:
        return []

    if tree is None:
        return []

    where = tree.args.get("where")
    if where is None:
        return []

    predicates: list[FilterPredicate] = []
    try:
        _walk_predicates(where.this, predicates)
    except Exception:
        # Arbre AST cassé : ne pas planter, retourner ce qui a été extrait
        return predicates
    return predicates


def extract_filter_strings(
    sql: str,
    dialect: str = "tsql",
) -> list[str]:
    """Version "texte" pour stockage dans le journal.

    Retourne les prédicats sous forme de strings compactes :
        ``[facDate] >= '2024-01-01'``
        ``[grpCode] IN ('A', 'B')``
        ``[facCancel] IS NULL``

    Format compatible avec l'ancien extracteur regex de
    ``discovery_journal._extract_where_filters``.
    """
    filters = extract_filters_from_sql(sql, dialect=dialect)
    return [_format_for_journal(f) for f in filters]


def extract_sql_scope(
    sql: str,
    dialect: str = "tsql",
) -> Optional[dict[str, list[Any]]]:
    """Extrait le "scope" effectif d'un SQL : {col: [vals]} des filtres positifs du WHERE.

    Ne garde que ``col = v`` et ``col IN (...)`` non-négatifs. Ignore ``NOT IN``,
    ``BETWEEN``, ``LIKE``, ``IS NULL``, les comparaisons <>/> etc. — le scope
    représente ce qui est *inclus*, pas ce qui est borné.

    Retourne :
    - ``None`` si sqlglot indisponible, SQL ne parse pas, OU si la structure
      empêche d'inférer un scope univoque (UNION/INTERSECT/EXCEPT, sous-requête
      FROM avec WHERE interne) — scope indéterminable, signal explicite au LLM
      qu'il doit regarder le `sql` à la main.
    - ``{}`` si SQL parse comme SELECT simple sans WHERE OU si WHERE n'a aucun
      filtre IN/= positif.
    - ``{col: [v1, v2, ...]}`` sinon.

    Les valeurs sont dédupliquées en préservant l'ordre. Le nom de colonne est
    pris tel que retourné par sqlglot (ex: ``dosNomDossierEntite``, sans brackets).
    Si plusieurs prédicats visent la même colonne (``col=a AND col IN (b,c)``),
    les valeurs sont agrégées.
    """
    if not _SQLGLOT_AVAILABLE or not sql or not isinstance(sql, str):
        return None

    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
    except Exception:
        return None

    if tree is None:
        return None

    # Structures polysémiques → scope indéterminable plutôt que mensonge
    # silencieux "{}". Le LLM doit alors lire le sql brut.
    if isinstance(tree, (exp.Union, exp.Intersect, exp.Except)):
        return None
    # Sous-requêtes FROM avec WHERE interne : on ne peut pas combiner le WHERE
    # externe + WHERE interne sans risquer de fausser. Ex: `SELECT * FROM
    # (SELECT * FROM T WHERE a=1) s WHERE s.b=2` — les deux filtres s'appliquent
    # sémantiquement, mais l'extraction n'expose qu'un niveau. Préfère None.
    outer_where = tree.args.get("where") if hasattr(tree, "args") else None
    for sub in tree.find_all(exp.Subquery):
        inner = sub.this
        if inner is None:
            continue
        inner_where = inner.args.get("where") if hasattr(inner, "args") else None
        if inner_where is not None and inner_where is not outer_where:
            return None

    if outer_where is None:
        return {}

    predicates: list[FilterPredicate] = []
    try:
        _walk_predicates(outer_where.this, predicates)
    except Exception:
        return {}

    scope: dict[str, list[Any]] = {}
    for f in predicates:
        if f.negated:
            continue
        col = f.column.strip("[]")
        if not col:
            continue
        if f.operator == "IN":
            vals = [v for v in (f.value or []) if v is not None]
        elif f.operator == "=":
            vals = [f.value] if f.value is not None else []
        else:
            continue
        if not vals:
            continue
        existing = scope.setdefault(col, [])
        for v in vals:
            if v not in existing:
                existing.append(v)
    return scope


def summarize_filters_fr(filters: list[FilterPredicate]) -> str:
    """Rendu français lisible pour l'utilisateur (transparence)."""
    if not filters:
        return ""
    lines = []
    for f in filters:
        neg_prefix = "NON " if f.negated else ""
        col = f.column.strip("[]")
        if f.operator == "=":
            lines.append(f"  • {col} {neg_prefix}vaut {_fmt(f.value)}")
        elif f.operator == "<>":
            lines.append(f"  • {col} différent de {_fmt(f.value)}")
        elif f.operator == "IN":
            joined = ", ".join(_fmt(v) for v in (f.value or []))
            lines.append(f"  • {col} {neg_prefix}parmi [{joined}]")
        elif f.operator == "LIKE":
            lines.append(f"  • {col} {neg_prefix}ressemble à {_fmt(f.value)}")
        elif f.operator == "BETWEEN":
            low, high = f.value if isinstance(f.value, tuple) else (None, None)
            lines.append(f"  • {col} {neg_prefix}entre {_fmt(low)} et {_fmt(high)}")
        elif f.operator.startswith("IS"):
            lines.append(f"  • {col} {f.operator}")
        else:
            lines.append(f"  • {col} {neg_prefix}{f.operator} {_fmt(f.value)}")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
# Internals
# ══════════════════════════════════════════════════════════════════════


def _walk_predicates(
    node: Any,
    predicates: list[FilterPredicate],
    negated: bool = False,
) -> None:
    """Descend récursivement dans les And/Or/Not/Paren pour extraire les
    prédicats atomiques."""
    if node is None:
        return

    if isinstance(node, (exp.And, exp.Or)):
        _walk_predicates(node.this, predicates, negated)
        _walk_predicates(node.expression, predicates, negated)
        return

    if isinstance(node, exp.Not):
        _walk_predicates(node.this, predicates, not negated)
        return

    if isinstance(node, exp.Paren):
        _walk_predicates(node.this, predicates, negated)
        return

    pred = _predicate_from_node(node, negated)
    if pred is not None:
        predicates.append(pred)


def _predicate_from_node(
    node: Any,
    negated: bool,
) -> Optional[FilterPredicate]:
    """Construit un FilterPredicate à partir d'un nœud atomique."""
    if isinstance(node, exp.EQ):
        return _make(node, "=", _val(node.expression), negated)
    if isinstance(node, exp.NEQ):
        return _make(node, "<>", _val(node.expression), negated)
    if isinstance(node, exp.GT):
        return _make(node, ">", _val(node.expression), negated)
    if isinstance(node, exp.GTE):
        return _make(node, ">=", _val(node.expression), negated)
    if isinstance(node, exp.LT):
        return _make(node, "<", _val(node.expression), negated)
    if isinstance(node, exp.LTE):
        return _make(node, "<=", _val(node.expression), negated)
    if isinstance(node, exp.In):
        values = [_val(e) for e in (node.expressions or [])]
        return _make(node, "IN", values, negated)
    if isinstance(node, exp.Like):
        return _make(node, "LIKE", _val(node.expression), negated)
    if isinstance(node, exp.Between):
        low = _val(node.args.get("low"))
        high = _val(node.args.get("high"))
        return _make(node, "BETWEEN", (low, high), negated)
    if isinstance(node, exp.Is):
        is_not = bool(node.args.get("not"))
        # negated externe (NOT (x IS NULL)) s'inverse avec is_not interne
        effective_is_not = is_not ^ negated
        op = "IS NOT NULL" if effective_is_not else "IS NULL"
        return FilterPredicate(
            column=_col_str(node),
            operator=op,
            value=None,
            raw=_safe_sql(node),
            negated=False,  # déjà reflété dans l'operator
        )
    return None


def _make(
    node: Any,
    op: str,
    value: Any,
    negated: bool,
) -> FilterPredicate:
    return FilterPredicate(
        column=_col_str(node),
        operator=op,
        value=value,
        raw=_safe_sql(node),
        negated=negated,
    )


def _col_str(node: Any) -> str:
    """Extrait la partie "colonne" (left side) en string lisible.

    Pour une référence de colonne simple ``[code]`` ou ``"code"`` on
    retourne le nom naturel ``code`` (sans quotes/brackets), ou
    ``table.col`` s'il y a un préfixe. Pour une expression plus
    complexe (fonction, cast…), on retombe sur ``sql()``.
    """
    this = node.this if hasattr(node, "this") else None
    if this is None:
        return ""
    # Cas fréquent : Column(this=Identifier, table=Identifier?)
    if isinstance(this, exp.Column):
        name = this.name or ""
        table = this.table or ""
        return f"{table}.{name}" if table and name else (name or _safe_sql(this))
    if isinstance(this, exp.Identifier):
        return this.name or _safe_sql(this)
    return _safe_sql(this)


def _safe_sql(node: Any) -> str:
    """sql() avec fallback str() si indisponible."""
    if hasattr(node, "sql"):
        try:
            return node.sql()
        except Exception:
            pass
    return str(node)


def _val(node: Any) -> Any:
    """Convertit un nœud valeur en Python natif (str/int/float/None)."""
    if node is None:
        return None
    if isinstance(node, exp.Literal):
        raw = node.this
        if node.is_string:
            return raw
        # Tenter int puis float
        try:
            return int(raw)
        except (ValueError, TypeError):
            try:
                return float(raw)
            except (ValueError, TypeError):
                return raw
    if isinstance(node, exp.Null):
        return None
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    # Référence de colonne, expression, fonction → on garde le sql()
    return _safe_sql(node)


def _format_for_journal(f: FilterPredicate) -> str:
    """Format compact compatible avec le storage existant."""
    col = f.column.strip("[]")
    col_bracketed = f"[{col}]"
    neg = "NOT " if f.negated else ""
    if f.operator in ("=", "<>", ">", ">=", "<", "<="):
        return f"{col_bracketed} {neg}{f.operator} {_fmt_sql(f.value)}"
    if f.operator == "IN":
        joined = ", ".join(_fmt_sql(v) for v in (f.value or []))
        return f"{col_bracketed} {neg}IN ({joined})"
    if f.operator == "LIKE":
        return f"{col_bracketed} {neg}LIKE {_fmt_sql(f.value)}"
    if f.operator == "BETWEEN":
        low, high = f.value if isinstance(f.value, tuple) else (None, None)
        return f"{col_bracketed} {neg}BETWEEN {_fmt_sql(low)} " f"AND {_fmt_sql(high)}"
    if f.operator.startswith("IS"):
        return f"{col_bracketed} {f.operator}"
    return f"{col_bracketed} {f.operator} {_fmt_sql(f.value)}"


def _fmt_sql(v: Any) -> str:
    """Format SQL literal (strings quotées, rest brut)."""
    if v is None:
        return "NULL"
    if isinstance(v, str):
        # Echapper quotes simples pour éviter SQL injection si ré-executé
        escaped = v.replace("'", "''")
        return f"'{escaped}'"
    return str(v)


def _fmt(v: Any) -> str:
    """Format humain (français)."""
    if v is None:
        return "NULL"
    if isinstance(v, str):
        return f'"{v}"'
    return str(v)
