"""Validateur AST pour les opérations d'écriture SQL proposées par Iris.

Doctrine sénior :

1. **AST > regex (CWE-89, OWASP A03 Injection).** Les blocklists regex
   sont contournables par prompt injection (cf. CVE-2024-5565 Vanna,
   CVE-2024-23751 LlamaIndex). On parse le SQL en arbre via sqlglot et
   on raisonne sur la STRUCTURE — pas le texte.

2. **Whitelist d'opérations.** Seuls INSERT/UPDATE/DELETE sont
   autorisés. Tout le reste (DDL, DCL, MERGE, EXEC, BACKUP, etc.) est
   refusé par défaut. Ajouter un type d'op = décision explicite.

3. **WHERE obligatoire pour UPDATE/DELETE.** Plus précisément : la
   WHERE clause doit référencer au moins une colonne (pas juste
   ``WHERE 1=1`` ou ``WHERE TRUE``). Garde-fou contre l'oubli classique
   du LLM qui produit "UPDATE T SET col=val" et touche TOUT.

4. **Single statement.** sqlglot peut parser plusieurs statements
   séparés par ``;``. On en accepte exactement 1 — un INSERT suivi d'un
   DROP serait catastrophique.

5. **Pas de tables système.** sys.*, INFORMATION_SCHEMA.*, master,
   tempdb, msdb refusés. La détection se fait sur les noms de tables
   extraits par sqlglot, pas sur le texte brut.

6. **Pas de subquery destructrice cachée.** Walk récursif de l'AST :
   si un nœud DROP/TRUNCATE/MERGE/EXEC apparaît N'IMPORTE OÙ (même
   dans une CTE ou subquery), refus.

7. **Pas de SELECT ... INTO new_table.** Crée une table — interdit
   (équivalent à un CREATE TABLE).

Références :
- sqlglot AST : https://github.com/tobymao/sqlglot
- OWASP Top 10:2025 A03 Injection
- CWE-89 SQL Injection
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

import sqlglot
from sqlglot import expressions as exp

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Dialecte SQL Server (T-SQL). Les automations Komptia ciblent Sage Coala
# (SQL Server) en prod, et SQLite local en dev — sqlglot supporte les deux,
# mais on parse en T-SQL (mode prod) pour ne pas laisser passer une syntaxe
# qui marcherait en SQLite mais pas en SQL Server.
_DIALECT: Final[str] = "tsql"

# Opérations explicitement autorisées. Tout le reste = refus.
_ALLOWED_OPERATIONS: Final[frozenset[str]] = frozenset({"INSERT", "UPDATE", "DELETE"})

# Schémas/databases système SQL Server à rejeter (case-insensitive).
_SYSTEM_SCHEMAS: Final[frozenset[str]] = frozenset(
    {"sys", "information_schema", "master", "tempdb", "msdb"}
)

# Nœuds AST sqlglot représentant des opérations destructrices ou
# inappropriées qui ne doivent JAMAIS apparaître dans une écriture
# proposée — même dans une subquery ou CTE imbriquée. Le walk récursif
# refuse l'instant où un de ces nœuds est trouvé.
_FORBIDDEN_NODE_TYPES: Final[tuple[type[exp.Expression], ...]] = (
    exp.Drop,
    exp.Alter,
    exp.AlterColumn,
    exp.AddConstraint,
    exp.Create,
    exp.TruncateTable,
    exp.Merge,
    exp.Use,
)

# Frontières sub-requêtes : tout walk côté `_has_real_where` doit prune
# ICI pour rester au niveau outer du WHERE. La doctrine est fail-closed :
# le validator ne peut pas inférer la restrictiveness sémantique d'une
# sous-requête (le scalar pourrait retourner NULL, des milliers de rows,
# ou matcher toutes les rows cible). Seules les comparaisons DIRECTES du
# WHERE outer (`Column OP Literal`) comptent comme garantie de restriction.
_SUBQUERY_BOUNDARY_TYPES: Final[tuple[type[exp.Expression], ...]] = (
    exp.Subquery,
    exp.Select,
    exp.Any,
    exp.All,
    exp.Exists,
)


# Wrappers transparents : ces nœuds enveloppent un unique argument `.this`
# sans déformer sémantiquement la VALEUR (négation arithmétique unaire,
# parenthèses de groupage). `_contains_node` descend itérativement (boucle
# bornée par `_MAX_TRANSPARENT_WRAPPER_DEPTH`) à
# travers eux pour permettre `WHERE id = -1` (Neg(Literal)) ou
# `WHERE (id) = (42)` (Paren(Column)/Paren(Literal)) — mais s'arrête sur
# tout autre nœud (Add, Sub, Mul, Div, If, Case, Coalesce, Cast, TryCast,
# fonctions, …). Sinon, un literal ou une colonne enseveli au fond d'une
# expression opaque satisferait à tort le check « opérande direct » du
# contrat `_has_real_where` (cf. Finding 1779287100-04 — bypass via
# `id + 0`, `IIF(1=1, id, id)`, `CASE … ELSE 1 END`,
# `COALESCE(col, 0)`, `CAST(42 AS INT)`).
#
# Intentionnellement EXCLU :
# - `exp.Not` : opérateur BOOLÉEN, pas un wrapper de valeur. `NOT 0`
#   renvoie un booléen, pas la valeur 0 — l'inclure ouvre un bypass
#   `WHERE id = NOT 0`. `WHERE NOT (id = 42)` est géré par le walk
#   principal de `_has_real_where` qui traverse Not pour atteindre
#   l'EQ interne (operands directs Column/Literal trouvés là).
# - `exp.Cast`, `exp.TryCast`, `exp.Convert` : transformation de type
#   opaque.
# - `exp.Coalesce`, `exp.If`, `exp.Case` : branches conditionnelles.
# - Arithmétique (Add/Sub/Mul/Div) et fonctions (Anonymous, Concat,
#   Substring, JSONExtract, etc.) : combinent / dérivent les operands.
_TRANSPARENT_WRAPPERS: Final[tuple[type[exp.Expression], ...]] = (
    exp.Paren,
    exp.Neg,
)

# Profondeur max d'imbrication des wrappers transparents que le walk
# traverse. Borne explicite contre une recursion non-bornée (CWE-674,
# Finding 1779287900-01). Un LLM cohérent ne produit pas plus de 3-5
# wrappers consécutifs dans une expression légitime ; 64 est largement
# au-dessus du max observé en pratique. Au-delà : fail-closed (return
# False) — un input avec >64 Paren/Neg imbriqués n'est pas un opérande
# direct légitime au sens du contrat « Column OP Literal ».
_MAX_TRANSPARENT_WRAPPER_DEPTH: Final[int] = 64


def _is_subquery_boundary(node: exp.Expression) -> bool:
    """Helper de pruning utilisé par `_has_real_where` et `_contains_node`
    pour s'arrêter aux frontières de sous-requêtes."""
    return isinstance(node, _SUBQUERY_BOUNDARY_TYPES)


# ---------------------------------------------------------------------------
# Datatypes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WriteValidationResult:
    """Résultat de validation d'une écriture SQL.

    Si ``is_valid=True``, ``operation`` et ``tables`` sont garantis non-None
    et non-vides. Le caller peut s'y fier.

    Si ``is_valid=False``, ``error`` est garanti non-None et explique la
    raison du refus en français — peut être affiché à l'utilisateur tel
    quel (pas de fuite de path/secret).
    """

    is_valid: bool
    operation: str | None = None  # "INSERT" / "UPDATE" / "DELETE"
    tables: list[str] = field(default_factory=list)
    error: str | None = None
    # Statement normalisé (utile pour audit + dry-run consistent)
    normalized_sql: str | None = None


# Note: pas d'exception dédiée — l'API du module est strictement
# result-object (``WriteValidationResult.is_valid``). Un caller qui
# voudrait raise sur invalid fait ``if not res.is_valid: raise ...``
# avec son exception métier. Ne pas réintroduire un type d'exception
# qui ne serait jamais levé par ce module (costume sans corps).


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------


def _table_full_name(node: exp.Table) -> str:
    """Nom qualifié d'une table : ``schema.name`` ou ``catalog.schema.name``
    si présents, sinon juste ``name``. Insensitive à la casse en sortie."""
    parts: list[str] = []
    if node.args.get("catalog"):
        parts.append(str(node.args["catalog"]).strip('[]"'))
    if node.args.get("db"):
        parts.append(str(node.args["db"]).strip('[]"'))
    parts.append(str(node.name).strip('[]"'))
    return ".".join(p for p in parts if p)


def _is_system_table(table_node: exp.Table) -> bool:
    """Test : table dans un schéma système ?"""
    candidates: list[str] = []
    if table_node.args.get("db"):
        candidates.append(str(table_node.args["db"]).strip('[]"').lower())
    if table_node.args.get("catalog"):
        candidates.append(str(table_node.args["catalog"]).strip('[]"').lower())
    # Vérifier aussi le nom lui-même (parfois le schéma est dans le name)
    name_lower = str(table_node.name).strip('[]"').lower()
    candidates.append(name_lower)
    return any(c in _SYSTEM_SCHEMAS for c in candidates)


def _has_real_where(stmt: exp.Update | exp.Delete) -> bool:
    """Vérifie qu'une UPDATE/DELETE a une WHERE clause restrictive.

    Critère **strict** : il doit exister AU MOINS UNE comparaison directe
    ``Column OP Literal`` (ou ``Literal OP Column``) dans la WHERE clause,
    où ``OP`` est un opérateur de comparaison (``=``, ``!=``, ``<``,
    ``<=``, ``>``, ``>=``, ``IN``, ``LIKE``, ``BETWEEN``).

    « Direct » est interprété strictement : les opérandes peuvent être
    enveloppés dans des wrappers transparents (`_TRANSPARENT_WRAPPERS` :
    `Paren`, `Neg`) qui ne déforment pas sémantiquement la valeur, mais
    PAS dans une expression opaque (Add/Sub/Mul/Div, fonctions, Not,
    If/Case/Coalesce/Cast/TryCast). Le walk s'arrête aussi aux frontières
    sous-requête (`_SUBQUERY_BOUNDARY_TYPES`).

    Cette règle élimine les bypass classiques :
        - ``WHERE 1 = 1`` (pas de colonne dans la comparaison)
        - ``WHERE col = col`` (pas de littéral dans la comparaison)
        - ``WHERE id = id OR 1 = 2`` (les comparaisons sont col=col et
          literal=literal, aucune ``Column OP Literal``)
        - ``WHERE col IS NOT NULL`` (pas une comparaison Literal)
        - ``WHERE col IN (col2, col3)`` (pas de Literal dans le IN)
        - ``WHERE id = id + 0`` / ``id * 1`` (literal enseveli dans Add/Mul)
        - ``WHERE id = IIF(1=1, id, id)`` / ``CASE ... ELSE 1 END``
        - ``WHERE id = COALESCE(col, 0)`` / ``CAST(42 AS INT)``
        - ``WHERE id IN (SELECT … WHERE col != lit)`` (literal en subquery)

    Et accepte les cas légitimes :
        - ``WHERE id = 42``
        - ``WHERE id = -1`` (Neg(Literal) — Neg transparent)
        - ``WHERE (id) = (42)`` (Paren transparent)
        - ``WHERE id BETWEEN 1 AND 100``
        - ``WHERE name LIKE '%bar'``
        - ``WHERE col1 = 1 OR col2 IS NULL`` (col1=1 est une comparaison
          Column OP Literal, suffit)
    """
    where_clause = stmt.args.get("where")
    if where_clause is None:
        return False

    comparison_ops: tuple[type[exp.Expression], ...] = (
        exp.EQ,
        exp.NEQ,
        exp.LT,
        exp.LTE,
        exp.GT,
        exp.GTE,
        exp.In,
        exp.Like,
        exp.ILike,
        exp.Between,
    )
    literal_types: tuple[type[exp.Expression], ...] = (
        exp.Literal,
        exp.Boolean,
        exp.Parameter,
        exp.Placeholder,
    )

    # Fail-closed : on prune le walk aux frontières Subquery/Select/Any/All/Exists
    # (cf. `_SUBQUERY_BOUNDARY_TYPES`). Sans ça, un `Column OP Literal`
    # trouvé DANS une sous-requête (ex : `WHERE id IN (SELECT id FROM t
    # WHERE id != -99999)`, `WHERE id = (SELECT ...)`, `WHERE id = ANY (...)`)
    # satisferait le check restrictive du WHERE outer — bypass de la
    # garantie. Le caller doit ajouter un filtre direct outer (ex:
    # `WHERE id = 42 AND id IN (subquery)`) s'il veut wrapper du SQL avec
    # une sous-requête.
    for node in where_clause.walk(prune=_is_subquery_boundary):
        if not isinstance(node, comparison_ops):
            continue
        # Récupère left + right (et expressions pour IN/BETWEEN)
        operands: list[exp.Expression] = []
        if hasattr(node, "this") and isinstance(node.this, exp.Expression):
            operands.append(node.this)
        if hasattr(node, "expression") and isinstance(node.expression, exp.Expression):
            operands.append(node.expression)
        # IN(...) et BETWEEN ont des listes d'expressions
        if isinstance(node, exp.In):
            operands.extend(node.args.get("expressions") or [])
        if isinstance(node, exp.Between):
            for k in ("low", "high"):
                v = node.args.get(k)
                if isinstance(v, exp.Expression):
                    operands.append(v)

        has_col = any(_contains_node(op, exp.Column) for op in operands)
        has_lit = any(_contains_node(op, literal_types) for op in operands)
        if has_col and has_lit:
            return True
    return False


def _contains_node(
    expression: exp.Expression,
    target_types: type[exp.Expression] | tuple[type[exp.Expression], ...],
) -> bool:
    """True si ``expression`` est instance de l'un des types ciblés, ou si
    elle est un wrapper TRANSPARENT (Paren/Neg) dont l'argument direct
    ``.this`` (itérativement) l'est.

    Le walk s'arrête sur :

    - Frontières sous-requête (`_SUBQUERY_BOUNDARY_TYPES`) — un
      Column/Literal trouvé dans une sous-requête imbriquée ne compte pas
      comme preuve de restrictiveness au niveau du WHERE outer (fail-closed
      task 3, Finding 1779253534-02).
    - Expressions opaques (Add/Sub/Mul/Div/Func/If/Case/Coalesce/Cast/…) —
      un literal ou une colonne enseveli au fond d'une telle expression
      n'est PAS un opérande direct de la comparaison et ne doit pas
      satisfaire `has_col`/`has_lit`. Sinon `WHERE id = id + 0`,
      `IIF(1=1, id, id)`, `CASE … ELSE 1 END`, `COALESCE(col, 0)`,
      `CAST(42 AS INT)` deviennent des bypass triviaux de la garantie
      `Column OP Literal` direct (fail-closed task 8,
      Finding 1779287100-04).
    - Profondeur d'imbrication > `_MAX_TRANSPARENT_WRAPPER_DEPTH` —
      fail-closed sur excessive nesting (CWE-674, Finding 1779287900-01).
      Un input pathologique avec des centaines de Paren/Neg imbriqués
      provoquait précédemment `RecursionError` (limite Python par défaut
      = 1000). L'implémentation est désormais itérative et bornée :
      `_MAX_TRANSPARENT_WRAPPER_DEPTH` wrappers consécutifs sont tolérés,
      au-delà la fonction retourne False.

    Le contrat documenté de `_has_real_where` parle d'« opérande direct
    Column OP Literal » — ce helper l'implémente strictement, en ne
    traversant que les wrappers neutres énumérés dans
    `_TRANSPARENT_WRAPPERS`.
    """
    current: exp.Expression = expression
    # `range(_MAX + 1)` permet jusqu'à `_MAX` descentes consécutives suivies
    # d'une dernière vérification cible — soit la sémantique intuitive
    # « `_MAX` wrappers tolérés, `_MAX + 1` rejeté ».
    for _ in range(_MAX_TRANSPARENT_WRAPPER_DEPTH + 1):
        if isinstance(current, target_types):
            return True
        if _is_subquery_boundary(current):
            return False
        if not isinstance(current, _TRANSPARENT_WRAPPERS):
            return False
        inner = current.this if hasattr(current, "this") else None
        if not isinstance(inner, exp.Expression):
            return False
        current = inner
    # Profondeur dépassée (> _MAX_TRANSPARENT_WRAPPER_DEPTH) : fail-closed.
    return False


def _has_select_into(stmt: exp.Expression) -> bool:
    """Détecte le pattern ``SELECT ... INTO new_table`` (T-SQL crée une
    table). Un INSERT INTO existing_table SELECT ... est OK ; c'est
    différent.

    sqlglot représente SELECT INTO comme un Select avec un argument
    'into' sur le Select node lui-même.
    """
    for node in stmt.walk():
        if isinstance(node, exp.Select) and node.args.get("into"):
            return True
    return False


def _has_output_into(stmt: exp.Expression) -> bool:
    """Détecte le pattern T-SQL ``... OUTPUT inserted.* INTO target_table``.

    SQL Server permet d'attacher une clause OUTPUT à INSERT/UPDATE/DELETE
    qui copie les rows touchées dans une AUTRE table. Si le ``INTO``
    cible une table autre que la cible principale, c'est une opération
    d'exfiltration ou de copie silencieuse — refusée.

    sqlglot représente OUTPUT comme un argument ``returning`` ou
    ``output`` sur le statement (selon version). On vérifie les deux
    formes pour robustesse cross-version.
    """
    for arg_name in ("returning", "output"):
        if stmt.args.get(arg_name):
            return True
    return False


def _has_bulk_or_external_source(stmt: exp.Expression) -> bool:
    """Détecte les INSERT à source externe : BULK INSERT, OPENROWSET,
    OPENQUERY, OPENDATASOURCE — chargent depuis fichier serveur ou
    serveur lié, hors du scope autorisé pour Iris-DBA-write.

    sqlglot peut représenter ces constructions comme `exp.Anonymous`
    ou `exp.Command` selon la version. On grep le SQL normalisé en
    fallback (le validateur a déjà refusé multi-stmt en amont).
    """
    sql_text = stmt.sql(dialect=_DIALECT).upper()
    forbidden_keywords = (
        "BULK INSERT",
        "OPENROWSET",
        "OPENQUERY",
        "OPENDATASOURCE",
    )
    return any(kw in sql_text for kw in forbidden_keywords)


def _find_forbidden_subnode(stmt: exp.Expression) -> str | None:
    """Cherche un nœud destructeur dans toute l'AST (subqueries
    incluses). Retourne le nom de la classe AST si trouvé, sinon None."""
    for node in stmt.walk():
        if isinstance(node, _FORBIDDEN_NODE_TYPES):
            return type(node).__name__
    return None


def _find_unsafe_function_call(stmt: exp.Expression) -> str | None:
    """Détecte les appels à des procédures stockées dangereuses :
    sp_executesql, xp_cmdshell, OPENROWSET, OPENQUERY, OPENDATASOURCE.
    """
    dangerous = {
        "sp_executesql",
        "xp_cmdshell",
        "openrowset",
        "openquery",
        "opendatasource",
    }
    for node in stmt.walk():
        # ``exp.Anonymous`` couvre les appels de fonction non reconnus
        # par sqlglot. ``exp.Func.this`` peut être le nom.
        name = getattr(node, "name", None) or ""
        if isinstance(name, str) and name.lower() in dangerous:
            return name.lower()
    return None


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------


def parse_and_validate_write(sql: str) -> WriteValidationResult:
    """Parse + valide un SQL d'écriture proposé par Iris.

    Args:
        sql: Le SQL brut tel que produit par le LLM (pas encore exécuté).

    Returns:
        WriteValidationResult — le caller doit checker ``is_valid``
        avant de transmettre à ``sage_connector.execute_write()``.
    """
    if not isinstance(sql, str) or not sql.strip():
        return WriteValidationResult(is_valid=False, error="SQL vide ou invalide.")

    # Parse
    try:
        statements = sqlglot.parse(sql, dialect=_DIALECT)
    except sqlglot.errors.ParseError as exc:
        logger.warning("parse_and_validate_write: parse error: %s", exc)
        return WriteValidationResult(
            is_valid=False,
            error="SQL impossible à parser. Vérifie la syntaxe T-SQL.",
        )

    # Filtrer les None (sqlglot retourne parfois None pour les statements vides)
    statements = [s for s in statements if s is not None]
    if not statements:
        return WriteValidationResult(is_valid=False, error="Aucun statement détecté.")

    if len(statements) > 1:
        return WriteValidationResult(
            is_valid=False,
            error=(
                f"Multi-statements interdits ({len(statements)} détectés). "
                "Une seule opération INSERT/UPDATE/DELETE par appel."
            ),
        )

    stmt = statements[0]

    # Type d'opération autorisé ?
    if isinstance(stmt, exp.Insert):
        operation = "INSERT"
    elif isinstance(stmt, exp.Update):
        operation = "UPDATE"
    elif isinstance(stmt, exp.Delete):
        operation = "DELETE"
    else:
        return WriteValidationResult(
            is_valid=False,
            error=(
                f"Opération non autorisée ({type(stmt).__name__}). "
                "Seuls INSERT/UPDATE/DELETE sont permis dans cette casquette."
            ),
        )

    # SELECT ... INTO new_table → forme déguisée de CREATE TABLE
    if _has_select_into(stmt):
        return WriteValidationResult(
            is_valid=False,
            error="SELECT INTO interdit (équivalent à un CREATE TABLE).",
        )

    # OUTPUT ... INTO target_table → exfiltration/copie silencieuse
    if _has_output_into(stmt):
        return WriteValidationResult(
            is_valid=False,
            error="Clause OUTPUT INTO interdite (copie de données vers une autre table).",
        )

    # BULK INSERT / OPENROWSET / OPENQUERY / OPENDATASOURCE
    if _has_bulk_or_external_source(stmt):
        return WriteValidationResult(
            is_valid=False,
            error="Source externe interdite (BULK INSERT, OPENROWSET, OPENQUERY, OPENDATASOURCE).",
        )

    # Subnodes interdits (DROP/TRUNCATE/ALTER/CREATE/MERGE/USE)
    forbidden = _find_forbidden_subnode(stmt)
    if forbidden is not None:
        return WriteValidationResult(
            is_valid=False,
            error=f"Construction SQL interdite : {forbidden}.",
        )

    # Procédures stockées dangereuses (sp_executesql, xp_cmdshell, etc.)
    unsafe_fn = _find_unsafe_function_call(stmt)
    if unsafe_fn is not None:
        return WriteValidationResult(
            is_valid=False,
            error=f"Appel de procédure interdit : {unsafe_fn}.",
        )

    # WHERE obligatoire pour UPDATE/DELETE
    if isinstance(stmt, (exp.Update, exp.Delete)):
        if not _has_real_where(stmt):
            return WriteValidationResult(
                is_valid=False,
                error=(
                    f"{operation} sans clause WHERE référençant une colonne. "
                    "Refuse de toucher toutes les lignes en bloc — précise un filtre."
                ),
            )

    # Tables touchées
    tables: list[str] = []
    for tnode in stmt.find_all(exp.Table):
        if _is_system_table(tnode):
            return WriteValidationResult(
                is_valid=False,
                error=(
                    f"Table système interdite : {_table_full_name(tnode)}. "
                    "Aucun accès à sys.*, INFORMATION_SCHEMA, master, tempdb, msdb."
                ),
            )
        full = _table_full_name(tnode)
        if full and full not in tables:
            tables.append(full)

    if not tables:
        # Cas anormal : un INSERT/UPDATE/DELETE sans table identifiable
        # est suspect. Refus par défaut.
        return WriteValidationResult(
            is_valid=False,
            error="Aucune table cible identifiable dans le SQL.",
        )

    # Re-sérialise via sqlglot pour normaliser (utile pour l'audit ; le
    # SQL stocké est canonique).
    try:
        normalized = stmt.sql(dialect=_DIALECT)
    except (sqlglot.errors.SqlglotError, ValueError):
        normalized = sql

    return WriteValidationResult(
        is_valid=True,
        operation=operation,
        tables=tables,
        normalized_sql=normalized,
    )


__all__ = [
    "WriteValidationResult",
    "parse_and_validate_write",
]
