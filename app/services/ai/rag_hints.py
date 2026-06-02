"""RAG hints — décomposition des paires Q/SQL similaires en signaux structurés.

Principe « L'apprentissage informe, ne décide pas » (T29★ generative principle) :
le RAG Q/SQL ne retourne JAMAIS un SQL prêt-à-l'emploi. Les paires similaires
sont décomposées en **hints** consommables par les phases pipeline Iris :

- **Phase 1.1+1.2 (extract/expand)** — concept_hints : entités/dimensions
  mentionnées dans les questions similaires (tokens discriminants).
- **Phase 2 (rerank)** — table_hints + column_hints : tables/colonnes
  référencées dans les SQL similaires (extraction structurelle via sqlglot).
- **Phase 4 (generate SQL / IR composer)** — ir_structure_hints : forme
  agrégée (nb cols SELECT, présence GROUP BY, agrégats utilisés, nb
  conditions WHERE).

Garde-fous :

1. **Aucune valeur littérale exposée** — les string et numeric literals des
   SQL sont strippés AVANT extraction. Confidentialité (les valeurs peuvent
   contenir des noms client/exercices/montants).
2. **Caps anti-prompt-explosion** — top-N par catégorie, fréquence-pondérée.
3. **Anti-2+2=4** — hints = intersection/union pondérée entre paires, pas
   liste hardcodée. Si schéma fourni, hints filtrés contre tables existantes.
4. **Reusable flag conscient** — `reusable_as_is=True` est un FLAG informatif
   pour le prompt LLM, JAMAIS un raccourci de code qui exécuterait le SQL
   tel quel. L'agent voit le flag et décide consciemment.

Module pur : 0 effet de bord, 0 DB, 0 LLM.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


# ── Caps anti-prompt-explosion ────────────────────────────────────────
# Calibrés pour qu'un prompt rempli ne dépasse pas ~500 tokens hints (cap
# total ≈ 16 cols × 30 chars + 8 tables × 25 chars + 12 concepts × 15 chars
# + structure dict ≈ 880 chars + markdown).
_MAX_CONCEPTS = 12
_MAX_TABLES = 8
_MAX_COLUMNS = 16

# Score min pour qu'une paire soit considérée comme "réutilisable à l'identique".
# Au-dessus de 0.95 ET schéma intact, on autorise le flag — mais l'agent reste
# souverain de la décision (le flag n'est pas un raccourci de code).
REUSABLE_SCORE_DEFAULT = 0.95
# Alias privé conservé pour rétrocompat interne.
_REUSABLE_SCORE_DEFAULT = REUSABLE_SCORE_DEFAULT

# Cap dur sur le nombre de paires acceptées par compute_phase_hints.
# Évite qu'un caller distrait passe 10 000 paires → parsing sqlglot O(n).
# 50 est largement suffisant : le RAG retourne typiquement ≤ 10.
_MAX_PAIRS_PER_CALL = 50

# Anti-fuite valeurs : strip strings et nombres avant tokenisation structurelle.
# Le but : extraire les IDENTIFIANTS SQL (tables, colonnes), pas les VALEURS
# (qui sont confidentielles et spécifiques à une paire).
_STRING_LITERAL_SQUOTE_RE = re.compile(r"'(?:[^']|'')*'")
# Double-quoted strings : T-SQL avec QUOTED_IDENTIFIER OFF, ANSI SQL standard,
# certains dialects MySQL. Sans ce stripping, sqlglot peut classer des valeurs
# entre double-quotes comme identifiants → fuite via exp.Column / exp.Table.
_STRING_LITERAL_DQUOTE_RE = re.compile(r'"(?:[^"]|"")*"')
# Postgres dollar-quoted strings — deux regex distinctes pour gérer le cas
# tagged ($tag$ ... $tag$) et le cas anonyme ($$ ... $$) sans buter sur le
# bug du back-reference au groupe vide en mode non-greedy.
_DOLLAR_QUOTE_TAGGED_RE = re.compile(r"\$([A-Za-z_]\w*)\$.*?\$\1\$", re.DOTALL)
_DOLLAR_QUOTE_ANON_RE = re.compile(r"\$\$.*?\$\$", re.DOTALL)
# Numériques : entiers, décimaux, hex, binaire, notation scientifique.
_NUMERIC_LITERAL_RE = re.compile(r"\b(?:0x[0-9a-fA-F]+|0b[01]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b")
# Commentaires SQL : ligne (`-- …`) et bloc (`/* … */`). Strippés AVANT les
# literals car ils peuvent contenir des noms client / montants en clair (les
# développeurs annotent souvent les SQL validés avec des TODO ou rappels).
_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

# Fallback regex pour extraction tables/colonnes quand sqlglot indisponible.
# Capture les identifiers après FROM / JOIN / UPDATE / INTO (best-effort).
_FROM_JOIN_RE = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INTO)\s+\[?([A-Za-z_][A-Za-z0-9_]*)\]?",
    re.IGNORECASE,
)
# Capture qualified col `table.col` ou `[table].[col]` (best-effort).
_QUALIFIED_COL_RE = re.compile(
    r"\b\[?([A-Za-z_][A-Za-z0-9_]*)\]?\.\[?([A-Za-z_][A-Za-z0-9_]*)\]?\b"
)

# Reserved SQL keywords à ne JAMAIS considérer comme table/colonne.
_SQL_KEYWORDS = frozenset(
    {
        "select",
        "from",
        "where",
        "join",
        "inner",
        "left",
        "right",
        "outer",
        "on",
        "and",
        "or",
        "not",
        "in",
        "as",
        "with",
        "group",
        "by",
        "order",
        "having",
        "union",
        "all",
        "distinct",
        "top",
        "limit",
        "offset",
        "case",
        "when",
        "then",
        "else",
        "end",
        "cast",
        "convert",
        "null",
        "is",
        "exists",
        "between",
        "like",
        "into",
        "values",
        "insert",
        "update",
        "delete",
        "set",
        "table",
        "view",
        "create",
        "drop",
        "alter",
        "asc",
        "desc",
        "true",
        "false",
        "over",
        "partition",
        "rows",
        "range",
        "unbounded",
        "preceding",
        "following",
        "current",
        "row",
    }
)

# Agrégats reconnus pour ir_structure_hints. Anti-2+2=4 : on ne retient que
# les fonctions standard SQL — pas de heuristique sur des noms custom.
_KNOWN_AGGREGATES = frozenset({"sum", "count", "avg", "min", "max", "stdev", "var", "string_agg"})


@dataclass(frozen=True)
class PhaseHints:
    """Hints structurés pour les phases pipeline Iris.

    Frozen : un hint est un snapshot immuable produit par compute_phase_hints
    à l'instant T. Mutation = recalcul.

    Attributes:
        concept_hints: tokens discriminants des questions similaires (Phase 1.1+1.2).
        table_hints: identifiants de tables référencées dans les SQL (Phase 2 rerank).
        column_hints: identifiants de colonnes (Phase 2 rerank, complément table_hints).
        ir_structure_hints: forme agrégée des SQL (Phase 4 IR composer).
            Clés : select_col_count_avg, has_group_by_ratio, has_aggregate_ratio,
            aggregates_used, where_condition_count_avg, has_cte_ratio.
        reusable_as_is: True si une paire est probablement réutilisable
            telle quelle (score ≥ threshold ET schéma compatible). C'est un
            FLAG informatif — l'agent décide consciemment, le code ne court-
            circuite jamais.
        reusable_reason: justification courte du flag (pour debug / prompt).
        paired_count: nb de paires source qui ont contribué.
    """

    concept_hints: tuple[str, ...] = ()
    table_hints: tuple[str, ...] = ()
    column_hints: tuple[str, ...] = ()
    ir_structure_hints: dict[str, Any] = field(default_factory=dict)
    reusable_as_is: bool = False
    reusable_reason: str = ""
    paired_count: int = 0

    def is_empty(self) -> bool:
        """True si aucun hint n'a de signal exploitable.

        ir_structure_hints peut contenir un dict avec sample_size > 0 mais
        toutes les autres valeurs à 0 (cas pair avec SQL = ``SELECT``) — on
        ne considère ça PAS comme un signal exploitable.
        """
        ir_has_signal = False
        if self.ir_structure_hints:
            ir_has_signal = any(
                bool(v) for k, v in self.ir_structure_hints.items() if k != "sample_size"
            )
        return (
            not self.concept_hints
            and not self.table_hints
            and not self.column_hints
            and not ir_has_signal
            and self.paired_count == 0
        )


# Placeholders neutres pour les literals — préservent la syntaxe SQL pour
# permettre à sqlglot de parser le SQL strippé sans planter (ex : `ON 1=1`
# ne devient PAS `ON  = ` mais `ON 0=0` qui reste valide).
# Choix conscient : `0` côté numérique (parse OK), `''` côté string (parse OK).
_NUM_PLACEHOLDER = "0"
_STR_PLACEHOLDER = "''"


def _strip_literals(sql: str) -> str:
    """Remplace string/numeric literals et commentaires par des placeholders
    syntaxiquement neutres.

    Confidentialité : les valeurs (montants, noms client, codes statistiques)
    sont remplacées par des placeholders avant toute extraction de hints. On
    ne garde que les IDENTIFIANTS structurels (tables, colonnes, mots-clés).

    On utilise des placeholders qui PRÉSERVENT la syntaxe SQL (`0` pour les
    nombres, `''` pour les strings, espace pour les commentaires). Sans ça
    sqlglot ne peut plus parser un SQL comme `WHERE x = 1 AND y = 'foo'`
    (qui deviendrait `WHERE x =   AND y =  ` — invalide).

    Ordre des passes :
        1. Commentaires (`-- …` et `/* … */`) — un nom client dans un TODO
           ne doit pas survivre aux étapes suivantes.
        2. Strings : simple-quote, double-quote, dollar-quote.
        3. Numériques : entier, décimal, hex, binaire, scientifique.
    """
    if not sql:
        return ""
    out = _LINE_COMMENT_RE.sub(" ", sql)
    out = _BLOCK_COMMENT_RE.sub(" ", out)
    out = _STRING_LITERAL_SQUOTE_RE.sub(_STR_PLACEHOLDER, out)
    out = _STRING_LITERAL_DQUOTE_RE.sub(_STR_PLACEHOLDER, out)
    out = _DOLLAR_QUOTE_TAGGED_RE.sub(_STR_PLACEHOLDER, out)
    out = _DOLLAR_QUOTE_ANON_RE.sub(_STR_PLACEHOLDER, out)
    out = _NUMERIC_LITERAL_RE.sub(_NUM_PLACEHOLDER, out)
    return out


def _try_sqlglot_parse(sql: str) -> Optional[Any]:
    """Parse sqlglot avec dialect T-SQL. Returns AST root ou None si échec.

    Cache par id() de la string pour éviter parser 2× la même paire dans
    extract_table_hints + extract_column_hints (cf. examen adversarial #8).
    """
    try:
        import sqlglot
    except ImportError:
        return None
    try:
        return sqlglot.parse_one(sql, dialect="tsql")
    except Exception as exc:
        logger.debug("sqlglot parse failed (%s); will fallback regex", exc)
        return None


def _try_sqlglot_tables_columns(
    sql: str,
) -> tuple[Optional[list[str]], Optional[list[str]], Optional[set[str]]]:
    """Extrait tables, colonnes et CTE names via sqlglot.

    Returns (tables, columns, cte_names_upper) ou (None, None, None) si
    parsing échoue. Caller doit alors fallback sur regex.

    Important — confidentialité : ``sql`` DOIT déjà être passé à
    ``_strip_literals``. Sinon des valeurs en double-quote ou des
    constructions VALUES peuvent être interprétées comme identifiers
    par sqlglot et fuiter dans l'AST.

    Le 3e tuple-element (cte_names_upper) permet au caller regex de
    filtrer les CTE names en fallback aussi.
    """
    try:
        from sqlglot import exp
    except ImportError:
        return None, None, None

    parsed = _try_sqlglot_parse(sql)
    if parsed is None:
        return None, None, None

    cte_names: set[str] = set()
    for cte in parsed.find_all(exp.CTE):
        alias = cte.alias_or_name
        if alias:
            cte_names.add(alias.upper())

    tables_seen: list[str] = []
    tables_set: set[str] = set()
    for tbl in parsed.find_all(exp.Table):
        name = tbl.name
        if not name:
            continue
        key = name.upper()
        if key in cte_names:
            continue  # référence vers une CTE, pas une vraie table
        if key in tables_set:
            continue
        tables_set.add(key)
        tables_seen.append(name)

    cols_seen: list[str] = []
    cols_set: set[str] = set()
    for col in parsed.find_all(exp.Column):
        name = col.name
        if not name or name == "*":
            continue
        key = name.upper()
        if key in cols_set:
            continue
        cols_set.add(key)
        cols_seen.append(name)

    return tables_seen, cols_seen, cte_names


def _sqlglot_count_top_select_columns(sql_clean: str) -> Optional[int]:
    """Compte les colonnes du 1er SELECT top-level via sqlglot.

    Plus robuste que le regex pour UNION ALL, CTE, sous-requêtes —
    cf. examen adversarial #11. Returns None si parsing échoue.
    """
    try:
        from sqlglot import exp
    except ImportError:
        return None
    parsed = _try_sqlglot_parse(sql_clean)
    if parsed is None:
        return None
    # Trouve le 1er SELECT qui n'est pas dans une CTE (parent != exp.CTE) et
    # qui n'est pas sous-requête.
    for select in parsed.find_all(exp.Select):
        # Le top-level Select : son parent immédiat est le parsed root ou Union.
        parent = select.parent
        if parent is None or isinstance(parent, exp.Union):
            exprs = select.expressions or []
            return len(exprs)
    return None


def _regex_tables(sql: str, exclude_upper: Optional[set[str]] = None) -> list[str]:
    """Fallback regex pour extraire tables (FROM/JOIN/UPDATE/INTO).

    Args:
        exclude_upper: set de noms (uppercase) à exclure des résultats.
            Sert au caller pour passer les CTE names extraites par sqlglot
            afin que le fallback regex ne ressuscite pas un faux positif.
    """
    if not sql:
        return []
    exclude_upper = exclude_upper or set()
    seen: list[str] = []
    seen_upper: set[str] = set()
    for m in _FROM_JOIN_RE.finditer(sql):
        t = m.group(1)
        if not t:
            continue
        if t.lower() in _SQL_KEYWORDS:
            continue
        key = t.upper()
        if key in exclude_upper:
            continue
        if key in seen_upper:
            continue
        seen_upper.add(key)
        seen.append(t)
    return seen


def _regex_columns(sql: str) -> list[str]:
    """Fallback regex pour extraire colonnes qualifiées (table.col)."""
    if not sql:
        return []
    seen: list[str] = []
    seen_upper: set[str] = set()
    for m in _QUALIFIED_COL_RE.finditer(sql):
        col = m.group(2)
        if not col or col.lower() in _SQL_KEYWORDS:
            continue
        key = col.upper()
        if key in seen_upper:
            continue
        seen_upper.add(key)
        seen.append(col)
    return seen


def _iter_pairs_with_clean_sql(
    pairs: Iterable[dict],
) -> Iterable[
    tuple[
        dict,
        str,
        tuple[Optional[list[str]], Optional[list[str]], Optional[set[str]]],
    ]
]:
    """Itère sur les paires en yieldant (pair, sql_clean, sqlglot_result).

    Centralise le strip + parse sqlglot pour éviter le double-appel
    extract_tables + extract_columns (perf #8). Le sqlglot result est
    calculé UNE FOIS par paire et partagé entre tables / columns.

    Le 3e tuple-element (cte_names) permet aux fonctions extract_* de
    filtrer le fallback regex pour ne pas ressusciter les CTE.
    """
    for pair in pairs:
        sql_raw = pair.get("sql") or ""
        if not sql_raw:
            continue
        sql_clean = _strip_literals(sql_raw)
        # Confidentialité (#4 critique) : sqlglot reçoit le SQL STRIPPÉ.
        # Sans ça, des constructions VALUES ('SECRET') peuvent fuiter.
        sqlglot_result = _try_sqlglot_tables_columns(sql_clean)
        yield pair, sql_clean, sqlglot_result


def extract_table_hints(pairs: Iterable[dict]) -> list[str]:
    """Extrait les tables référencées dans les SQL des paires.

    Stratégie : sqlglot AST si dispo (sql STRIPPÉ — confidentialité) +
    fallback regex FROM/JOIN. Les CTE noms sont exclus (faux positifs)
    aussi bien côté sqlglot que côté regex (passage des CTE names en
    paramètre exclude_upper).

    Returns: list de noms de tables, triée par fréquence cross-paire
    décroissante puis par insertion. Caps à _MAX_TABLES.
    """
    freq: Counter[str] = Counter()
    casing: dict[str, str] = {}

    for (
        _pair,
        sql_clean,
        (
            sqlglot_tables,
            _,
            cte_names,
        ),
    ) in _iter_pairs_with_clean_sql(pairs):
        tables = _regex_tables(sql_clean, exclude_upper=cte_names)
        if sqlglot_tables:
            for t in sqlglot_tables:
                if t.upper() not in {x.upper() for x in tables}:
                    tables.append(t)

        seen_in_pair: set[str] = set()
        for t in tables:
            key = t.upper()
            if key in seen_in_pair:
                continue
            seen_in_pair.add(key)
            freq[key] += 1
            casing.setdefault(key, t)

    ordered = [casing[k] for k, _ in freq.most_common()]
    return ordered[:_MAX_TABLES]


def extract_column_hints(pairs: Iterable[dict]) -> list[str]:
    """Extrait les colonnes qualifiées (`table.col`) référencées.

    Stratégie identique à extract_table_hints (sql strippé pour sqlglot,
    union regex fallback). Caps à _MAX_COLUMNS.
    """
    freq: Counter[str] = Counter()
    casing: dict[str, str] = {}

    for _pair, sql_clean, (_, sqlglot_cols, _) in _iter_pairs_with_clean_sql(pairs):
        cols = _regex_columns(sql_clean)
        if sqlglot_cols:
            for c in sqlglot_cols:
                if c.upper() not in {x.upper() for x in cols}:
                    cols.append(c)

        seen_in_pair: set[str] = set()
        for c in cols:
            key = c.upper()
            if key in seen_in_pair:
                continue
            seen_in_pair.add(key)
            freq[key] += 1
            casing.setdefault(key, c)

    ordered = [casing[k] for k, _ in freq.most_common()]
    return ordered[:_MAX_COLUMNS]


# Filtre confidentialité concepts : on rejette les tokens qui ressemblent
# fortement à des proper nouns / valeurs (anti-fuite #5 critique).
# - chaîne 100% chiffres : montant / id (déjà strippé côté SQL mais peut
#   apparaître dans question)
# - chaîne UPPERCASE pure ≥ 4 chars : probablement nom propre / code client
# - patterns courants PII : SIRET (14 chiffres), email, IBAN
_PII_PURE_DIGITS_RE = re.compile(r"^\d+$")
_PII_PURE_UPPER_RE = re.compile(r"^[A-Z]{4,}$")
_PII_EMAIL_RE = re.compile(r"@")
_PII_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}")


def _looks_like_pii(token: str) -> bool:
    """Heuristique de détection de PII probable dans un token.

    Fail-closed : en cas de doute, on filtre. Le coût d'un faux positif
    (concept légitime filtré) est faible — le RAG reste informatif via les
    table_hints et ir_structure_hints. Le coût d'un faux négatif (PII
    envoyée au LLM cloud) est élevé.
    """
    if not token:
        return False
    if _PII_PURE_DIGITS_RE.match(token):
        return True
    if _PII_PURE_UPPER_RE.match(token):
        return True
    if _PII_EMAIL_RE.search(token):
        return True
    if _PII_IBAN_RE.match(token):
        return True
    return False


def extract_concept_hints(
    pairs: Iterable[dict],
    *,
    tokenizer: Optional[Any] = None,
    extra_stopwords: Optional[set[str]] = None,
    pii_filter: bool = True,
) -> list[str]:
    """Extrait les concepts (tokens discriminants) des questions similaires.

    Args:
        pairs: itérable de dicts avec clé "question".
        tokenizer: callable qui prend un str et retourne list[str].
            Si None, utilise SimpleTextSearch.tokenize pour cohérence avec
            le scoring. Pour les tests, on peut injecter un tokenizer mock.
        extra_stopwords: stopwords additionnels à filtrer (en plus du tokenizer
            qui filtre déjà ses propres stopwords).
        pii_filter: si True (défaut), applique `_looks_like_pii` pour
            écarter les tokens qui ressemblent à des proper nouns (noms
            client, codes statistiques) ou des valeurs (montants, SIRET).
            Anti-fuite confidentialité #5.

    Returns: list de tokens triée par fréquence cross-paire décroissante.
    """
    if tokenizer is None:
        from app.services.ai.training_store import SimpleTextSearch

        tokenizer = SimpleTextSearch.tokenize

    extra_stopwords = extra_stopwords or set()

    freq: Counter[str] = Counter()
    casing: dict[str, str] = {}

    for pair in pairs:
        q = (pair.get("question") or "").strip()
        if not q:
            continue
        try:
            tokens = tokenizer(q)
        except Exception as exc:
            logger.debug("Concept tokenizer error (skip pair): %s", exc)
            continue
        seen_in_pair: set[str] = set()
        for t in tokens:
            if not t or t in extra_stopwords:
                continue
            if pii_filter and _looks_like_pii(t):
                continue
            key = t.lower()
            if key in seen_in_pair:
                continue
            seen_in_pair.add(key)
            freq[key] += 1
            casing.setdefault(key, t)

    ordered = [casing[k] for k, _ in freq.most_common()]
    return ordered[:_MAX_CONCEPTS]


def _has_group_by(sql_clean: str) -> bool:
    return bool(re.search(r"\bGROUP\s+BY\b", sql_clean, re.IGNORECASE))


def _has_cte(sql_clean: str) -> bool:
    return bool(re.search(r"\bWITH\b\s+[A-Za-z_]", sql_clean, re.IGNORECASE))


def _count_select_columns(sql_clean: str) -> int:
    """Compte le nb de colonnes du 1er SELECT top-level.

    Stratégie : sqlglot AST en priorité (robuste à UNION ALL / CTE,
    cf. examen adversarial #11). Fallback regex si parsing échoue.
    """
    via_ast = _sqlglot_count_top_select_columns(sql_clean)
    if via_ast is not None:
        return via_ast

    # Fallback regex : heuristique simple isole SELECT…FROM et compte
    # virgules de premier niveau. Best-effort sur SQL malformés.
    m = re.search(r"\bSELECT\b(.*?)\bFROM\b", sql_clean, re.IGNORECASE | re.DOTALL)
    if not m:
        return 0
    body = m.group(1).strip()
    if not body:
        return 0
    depth = 0
    commas = 0
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            commas += 1
    return commas + 1


def _count_where_conditions(sql_clean: str) -> int:
    """Compte (best-effort) le nb de conditions WHERE séparées par AND/OR top-level."""
    m = re.search(
        r"\bWHERE\b(.*?)(?:\bGROUP\s+BY\b|\bORDER\s+BY\b|\bHAVING\b|\bUNION\b|$)",
        sql_clean,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return 0
    body = m.group(1).strip()
    if not body:
        return 0
    depth = 0
    conditions = 1
    i = 0
    body_upper = body.upper()
    while i < len(body):
        ch = body[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            if body_upper[i : i + 5] == " AND " or body_upper[i : i + 4] == " OR ":
                conditions += 1
        i += 1
    return conditions


def _extract_aggregates_used(sql_clean: str) -> list[str]:
    """Détecte les agrégats SQL standard utilisés."""
    found: set[str] = set()
    sql_up = sql_clean.upper()
    for agg in _KNOWN_AGGREGATES:
        # Match \bAGG\s*\(
        if re.search(rf"\b{agg.upper()}\s*\(", sql_up):
            found.add(agg.lower())
    return sorted(found)


def extract_ir_structure_hints(pairs: Iterable[dict]) -> dict[str, Any]:
    """Extrait la structure agrégée des SQL des paires.

    Returns dict :
        - select_col_count_avg: float, moyenne sur les paires non-vides
        - has_group_by_ratio: float, proportion de paires avec GROUP BY
        - has_aggregate_ratio: float, proportion avec ≥ 1 agrégat
        - aggregates_used: list[str] trié, union des agrégats vus
        - where_condition_count_avg: float, moyenne nb conditions WHERE
        - has_cte_ratio: float, proportion utilisant WITH … CTE
        - sample_size: int, nb de paires considérées (SQL non vide)
    """
    select_counts: list[int] = []
    where_counts: list[int] = []
    gb_flags: list[bool] = []
    agg_flags: list[bool] = []
    cte_flags: list[bool] = []
    aggs_union: set[str] = set()

    for pair in pairs:
        sql_raw = pair.get("sql") or ""
        if not sql_raw:
            continue
        sql_clean = _strip_literals(sql_raw)

        select_counts.append(_count_select_columns(sql_clean))
        where_counts.append(_count_where_conditions(sql_clean))
        gb_flags.append(_has_group_by(sql_clean))
        cte_flags.append(_has_cte(sql_clean))
        aggs = _extract_aggregates_used(sql_clean)
        agg_flags.append(bool(aggs))
        aggs_union.update(aggs)

    n = len(select_counts)
    if n == 0:
        return {}

    def _avg(xs: list[int]) -> float:
        return round(sum(xs) / len(xs), 2) if xs else 0.0

    def _ratio(flags: list[bool]) -> float:
        return round(sum(1 for f in flags if f) / len(flags), 2) if flags else 0.0

    return {
        "select_col_count_avg": _avg(select_counts),
        "has_group_by_ratio": _ratio(gb_flags),
        "has_aggregate_ratio": _ratio(agg_flags),
        "aggregates_used": sorted(aggs_union),
        "where_condition_count_avg": _avg(where_counts),
        "has_cte_ratio": _ratio(cte_flags),
        "sample_size": n,
    }


def _evaluate_reusable(
    pairs: list[dict],
    *,
    schema_tables: Optional[set[str]],
    reusable_threshold: float,
    best_table_hints: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Décide si la meilleure paire est probablement réutilisable telle quelle.

    Rappel : `reusable_as_is=True` n'autorise PAS le code à exécuter le SQL
    sans le LLM. C'est juste un signal de prompt. Le LLM décide.

    Critères :
        1. Au moins une paire avec score ≥ reusable_threshold.
        2. Si schema_tables fourni : TOUTES les tables référencées dans la
           paire candidate sont présentes dans schema_tables (uppercase).

    Args:
        best_table_hints: si fourni, évite de relancer extract_table_hints
            sur la paire best (perf — sqlglot parse déjà fait dans
            compute_phase_hints).

    Returns (flag, reason).
    """
    if not pairs:
        return False, ""

    def _score_of(p: dict) -> float:
        return float(p.get("fresh_score", p.get("score", 0)) or 0)

    best = max(pairs, key=_score_of)
    best_score = _score_of(best)
    if best_score < reusable_threshold:
        return (
            False,
            f"top score {best_score:.2f} < seuil {reusable_threshold:.2f}",
        )

    sql_best = best.get("sql") or ""
    if not sql_best:
        return False, "paire sans SQL"

    if schema_tables is not None:
        # Si pas de hints best fournis, on les recalcule sur best uniquement.
        if best_table_hints is None:
            best_table_hints = extract_table_hints([best])
        ref_tables_lc = {t.upper() for t in best_table_hints}
        missing = ref_tables_lc - {t.upper() for t in schema_tables}
        if missing:
            return (
                False,
                f"tables absentes du schéma actuel : {sorted(missing)[:3]}",
            )

    return True, f"score {best_score:.2f} et schéma compatible"


def compute_phase_hints(
    pairs: Iterable[dict],
    *,
    schema_tables: Optional[set[str]] = None,
    reusable_threshold: float = REUSABLE_SCORE_DEFAULT,
) -> PhaseHints:
    """Assemble les hints structurés à partir d'un set de paires Q/SQL similaires.

    Args:
        pairs: itérable de dicts (sortie de TrainingStore.get_similar_question_sql).
            Clés attendues : "question", "sql", "score" (optionnel "fresh_score",
            "engine"). Cappé à ``_MAX_PAIRS_PER_CALL`` pour éviter latence
            sqlglot quand le caller passe la BDD entière.
        schema_tables: si fourni, set des noms de tables actuellement présentes
            dans le schéma BDD. Utilisé pour invalider le flag `reusable_as_is`
            quand une table référencée a disparu. Comparaison case-insensitive.
        reusable_threshold: score minimal pour autoriser le flag reusable_as_is.

    Returns: PhaseHints frozen. Si pairs vide, retourne PhaseHints() vide.
    """
    # Filtrer + cap dur sur taille (anti-DoS perf #8).
    pair_list: list[dict] = []
    rejected_non_dict = 0
    for p in pairs:
        if isinstance(p, dict):
            pair_list.append(p)
            if len(pair_list) >= _MAX_PAIRS_PER_CALL:
                break
        else:
            rejected_non_dict += 1
    if rejected_non_dict:
        logger.debug("compute_phase_hints: %d non-dict entries rejected", rejected_non_dict)

    if not pair_list:
        return PhaseHints()

    tables = extract_table_hints(pair_list)
    columns = extract_column_hints(pair_list)
    concepts = extract_concept_hints(pair_list)
    ir_struct = extract_ir_structure_hints(pair_list)

    # Hints best pour _evaluate_reusable : on récupère les tables de la paire
    # top-score uniquement (évite un 2e parse sqlglot sur best).
    def _score_of(p: dict) -> float:
        return float(p.get("fresh_score", p.get("score", 0)) or 0)

    best = max(pair_list, key=_score_of)
    best_tables = extract_table_hints([best])

    reusable, reason = _evaluate_reusable(
        pair_list,
        schema_tables=schema_tables,
        reusable_threshold=reusable_threshold,
        best_table_hints=best_tables,
    )

    logger.debug(
        "phase_hints: pairs=%d top_tables=%s top_concepts=%s reusable=%s",
        len(pair_list),
        tables[:3],
        concepts[:3],
        reusable,
    )

    return PhaseHints(
        concept_hints=tuple(concepts),
        table_hints=tuple(tables),
        column_hints=tuple(columns),
        ir_structure_hints=ir_struct,
        reusable_as_is=reusable,
        reusable_reason=reason,
        paired_count=len(pair_list),
    )


def format_hints_for_prompt(hints: PhaseHints) -> str:
    """Formate les hints en bloc markdown indicatif (vs prescriptif).

    Anti court-circuit : le wording dit "des paires similaires ont
    mentionné" et NON "utilise ces tables/concepts". Le LLM décide
    consciemment de quoi utiliser.

    Returns: bloc markdown ou "" si hints vides.
    """
    if hints.is_empty():
        return ""

    lines: list[str] = [
        "### 📌 Hints structurés extraits du RAG",
        "",
        f"_Issus de {hints.paired_count} paire(s) Q/SQL validée(s) "
        "similaire(s). Ces hints sont **INDICATIFS** — utilise-les pour "
        "orienter ta démarche, ne les recopie pas aveuglément._",
    ]

    if hints.concept_hints:
        lines.extend(
            [
                "",
                "**Concepts mentionnés dans des requêtes similaires** (Phase 1.1/1.2) :",
                "- " + ", ".join(f"`{c}`" for c in hints.concept_hints) + "  ",
                "_Une question similaire mentionnait ces tokens. À comparer "
                "avec la demande utilisateur courante — un concept absent "
                "ici alors qu'il est demandé peut signaler un trou de RAG._",
            ]
        )

    if hints.table_hints:
        lines.extend(
            [
                "",
                "**Tables référencées dans des SQL similaires** (Phase 2 rerank) :",
                "- " + ", ".join(f"`{t}`" for t in hints.table_hints) + "  ",
                "_Des paires validées ont utilisé ces tables. Vérifie via "
                "`search_schema` qu'elles correspondent à la sémantique de "
                "la demande courante AVANT de les inclure._",
            ]
        )

    if hints.column_hints:
        lines.extend(
            [
                "",
                "**Colonnes qualifiées vues** (complément Phase 2) :",
                "- " + ", ".join(f"`{c}`" for c in hints.column_hints) + "  ",
                "_Indicatif : ces colonnes apparaissaient dans les SQL "
                "similaires. À confirmer via `introspect_table` si tu les utilises._",
            ]
        )

    ir = hints.ir_structure_hints
    if ir:
        ir_lines = ["", "**Structure IR moyenne** (Phase 4 composer) :"]
        sc = ir.get("select_col_count_avg")
        if sc is not None:
            ir_lines.append(f"- ~{sc} colonnes SELECT en moyenne")
        gb_r = ir.get("has_group_by_ratio")
        if gb_r is not None:
            pct = int(round(gb_r * 100))
            ir_lines.append(f"- GROUP BY présent dans {pct}% des paires")
        agg_r = ir.get("has_aggregate_ratio")
        aggs = ir.get("aggregates_used") or []
        if agg_r is not None:
            pct = int(round(agg_r * 100))
            if aggs:
                ir_lines.append(
                    f"- Agrégats dans {pct}% des paires : "
                    + ", ".join(f"`{a.upper()}`" for a in aggs)
                )
            else:
                ir_lines.append(f"- Agrégats dans {pct}% des paires")
        wc = ir.get("where_condition_count_avg")
        if wc is not None:
            ir_lines.append(f"- ~{wc} conditions WHERE en moyenne")
        cte_r = ir.get("has_cte_ratio")
        if cte_r is not None and cte_r > 0:
            pct = int(round(cte_r * 100))
            ir_lines.append(f"- CTE (WITH...) dans {pct}% des paires")
        ir_lines.append(
            "_Indicatif : aligne ta structure si la sémantique est "
            "similaire, écarte-toi si la demande l'exige._"
        )
        lines.extend(ir_lines)

    if hints.reusable_as_is:
        lines.extend(
            [
                "",
                "### ✅ HYPOTHÈSE : SQL probablement réutilisable à l'identique",
                "",
                f"_{hints.reusable_reason}. Une paire validée semble "
                "couvrir la demande à très haute similarité, ET les "
                "tables référencées existent toujours dans le schéma._",
                "",
                "⚠️ **Décision consciente requise** : ce flag ne te dispense "
                "pas de vérifier que (a) la sémantique de la question "
                "utilisateur correspond bien, (b) les filtres valeur sont "
                "à adapter (entité, exercice, période…), (c) le schéma "
                "actuel n'a pas dérivé sur des colonnes non listées ici.",
            ]
        )

    return "\n".join(lines)


__all__ = [
    "PhaseHints",
    "REUSABLE_SCORE_DEFAULT",
    "compute_phase_hints",
    "extract_table_hints",
    "extract_column_hints",
    "extract_concept_hints",
    "extract_ir_structure_hints",
    "format_hints_for_prompt",
]
