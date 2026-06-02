"""
Moteur de recherche 5D pour l'orchestrateur Iris.

Construit des index en memoire depuis le TrainingStore + ValueMapping,
puis recherche des termes utilisateur dans 5 dimensions :
  1. Noms de tables
  2. Noms de vues
  3. Noms de colonnes (de tables)
  4. Noms de colonnes de vues (associees a leur vue)
  5. Valeurs (depuis ValueMapping — valeurs reelles locales, jamais envoyees au LLM)

Chaque resultat est classe par qualite de match :
  - exact : le terme == le nom/la valeur (case-insensitive)
  - contains : le terme est contenu dans le nom/la valeur, ou l'inverse
  - fuzzy : match TF-IDF avec un score de similarite

Confidentialite (niveau 2) :
  - L'index 'values' contient les valeurs REELLES (depuis ValueMapping)
  - La recherche se fait cote SYSTEME (code Python, local)
  - Ce qui est envoye au LLM = metadonnees (table, colonne, stats) + valeur ANONYMISEE
"""

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any


from app.core.database import get_session

logger = logging.getLogger(__name__)

# Regex pour parser les colonnes depuis un DDL CREATE TABLE
_COL_RE = re.compile(r"^\s{2,}(\w+)\s+\w+", re.MULTILINE)
_SQL_KEYWORDS = frozenset({"CONSTRAINT", "PRIMARY", "FOREIGN", "KEY", "INDEX", "UNIQUE", "CHECK"})


# ── Dataclasses pour les index ──────────────────────────────────────


@dataclass
class TableStats:
    """Stats d'une table ou vue."""

    real_name: str  # Casse originale
    row_count: int = 0
    is_view: bool = False


@dataclass
class ColumnLocation:
    """Localisation d'une colonne dans une table."""

    column_name: str  # Casse originale
    table_name: str
    data_type: str = ""
    distinct_count: int = 0
    null_pct: float = 0.0
    is_pk: bool = False
    is_fk: bool = False


@dataclass
class ValueLocation:
    """Localisation d'une valeur dans une colonne.

    La vraie valeur est exposée par défaut : l'anonymisation runtime est
    désormais centralisée dans ``anonymization_terms`` (/data-privacy) via
    le Pseudonymizer, plus dans ce dataclass.
    """

    value: str  # Vraie valeur (anonymisation gérée en aval par Pseudonymizer)
    table_name: str = ""
    column_name: str = ""
    distinct_count: int = 0
    null_pct: float = 0.0
    estimated_occurrence: int = 0  # row_count / distinct_count (estimation)


@dataclass
class SearchIndexes:
    """Index 5D construit une fois, utilise pour toutes les recherches."""

    tables: dict[str, TableStats] = field(default_factory=dict)
    views: dict[str, TableStats] = field(default_factory=dict)
    columns: dict[str, list[ColumnLocation]] = field(default_factory=dict)
    view_columns: dict[str, list[ColumnLocation]] = field(default_factory=dict)
    values: dict[str, list[ValueLocation]] = field(default_factory=dict)


# ── Dataclasses pour les resultats ──────────────────────────────────


@dataclass
class SearchMatch:
    """Un resultat de recherche dans une dimension."""

    match_type: str  # "exact", "contains", "fuzzy"
    score: float = 1.0  # 1.0 pour exact, 0.8 pour contains, variable pour fuzzy
    dimension: str = ""  # "table", "view", "column", "view_column", "value"

    # Metadata commune
    table_name: str = ""
    row_count: int = 0

    # Column-specific
    column_name: str = ""
    data_type: str = ""
    distinct_count: int = 0
    null_pct: float = 0.0
    is_pk: bool = False
    is_fk: bool = False

    # Value-specific. ``real_value`` est la vraie valeur Sage — elle peut être
    # envoyée au LLM si pas configurée dans /data-privacy (le Pseudonymizer
    # runtime intercepte à l'envoi quand un terme y figure avec un pseudo).
    real_value: str = ""
    is_view: bool = False
    estimated_occurrence: int = 0  # Estimation occurrences (row_count / distinct_count)

    @property
    def sort_key(self) -> tuple:
        """Tri : exact > contains > fuzzy, puis par score decroissant, puis row_count decroissant.

        Le row_count sert de départage : à qualité de match égale, les tables volumineuses
        (souvent les plus pertinentes métier) apparaissent en premier.
        """
        type_order = {"exact": 0, "contains": 1, "fuzzy": 2}
        return (type_order.get(self.match_type, 9), -self.score, -self.row_count)


@dataclass
class TermSearchResults:
    """Resultats de recherche pour un terme, dans les 4 dimensions."""

    term: str
    matches: list[SearchMatch] = field(default_factory=list)

    def add(self, match: SearchMatch) -> None:
        self.matches.append(match)

    def sort_results(self) -> None:
        """Trie les resultats par qualite (exact > contains > fuzzy, puis score)."""
        self.matches.sort(key=lambda m: m.sort_key)

    @property
    def has_results(self) -> bool:
        return len(self.matches) > 0


# ── Extraction colonnes de vues depuis DDL ────────────────────────

# Regex pour détecter si un fragment SELECT est une expression complexe
# (contient des parenthèses, opérateurs, mots-clés de contrôle)
_EXPR_PATTERN = re.compile(
    r"[\(\)+\-*/=<>]|"
    r"\bCASE\b|\bWHEN\b|\bTHEN\b|\bELSE\b|\bEND\b|"
    r"\bISNULL\b|\bCOALESCE\b|\bCAST\b|\bCONVERT\b|"
    r"\bSUBSTRING\b|\bCHARINDEX\b",
    re.IGNORECASE,
)


def _find_top_level_keyword(text_upper: str, keyword: str) -> int:
    """Trouve un mot-clé SQL au niveau 0 (hors parenthèses)."""
    depth = 0
    kw_len = len(keyword)
    for i in range(len(text_upper)):
        c = text_upper[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and text_upper[i : i + kw_len] == keyword:
            before_ok = i == 0 or not text_upper[i - 1].isalnum()
            after_ok = i + kw_len >= len(text_upper) or not text_upper[i + kw_len].isalnum()
            if before_ok and after_ok:
                return i
    return -1


def _split_top_level_commas(text: str) -> list[str]:
    """Split par virgules au niveau 0 (hors parenthèses)."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for c in text:
        if c == "(":
            depth += 1
            current.append(c)
        elif c == ")":
            depth = max(0, depth - 1)
            current.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(c)
    if current:
        parts.append("".join(current))
    return parts


def _extract_column_from_select_part(part: str) -> str | None:
    """Extrait le nom de colonne de sortie d'un élément SELECT.

    Priorité :
    1. "expression AS alias" → alias (toujours fiable)
    2. "table.column" → column (toujours fiable)
    3. "bare_column" → seulement si le fragment est un simple identifiant
       (pas une expression SQL complexe)
    """
    part = part.strip()
    if not part:
        return None

    # 1. Check for AS alias (case insensitive) — toujours fiable
    m = re.search(r"\bAs\s+\[?(\w+)\]?\s*$", part, re.IGNORECASE)
    if m:
        return m.group(1)

    # 2. Check for table.column at end — toujours fiable
    m = re.search(r"(\w+)\.\[?(\w+)\]?\s*$", part)
    if m:
        return m.group(2)

    # 3. Bare column — SEULEMENT si le fragment est un simple identifiant
    #    (pas une expression avec parenthèses, opérateurs, CASE/WHEN, etc.)
    if _EXPR_PATTERN.search(part):
        # C'est une expression complexe sans alias AS → on ne peut pas
        # extraire un nom de colonne fiable → skip
        return None

    m = re.search(r"\[?(\w+)\]?\s*$", part)
    if m:
        candidate = m.group(1)
        if candidate.isdigit():
            return None
        return candidate

    return None


def _extract_view_columns(ddl_content: str, all_column_stats: dict[str, Any]) -> list[str]:
    """Extrait les noms de colonnes de sortie depuis le DDL d'une vue.

    Handles:
    - SELECT * FROM table → résolution depuis column_stats de la table source
    - SELECT col1, table.col2, expr AS alias → extraction par parsing

    Args:
        ddl_content: Texte DDL complet (CREATE VIEW ... AS SELECT ...)
        all_column_stats: Dict {table_name: {columns: {col: stats}}} pour résolution SELECT *

    Returns:
        Liste de noms de colonnes (vide si parsing échoue)
    """
    upper = ddl_content.upper()

    # Trouver SELECT après CREATE VIEW ... AS (AS peut être suivi de \n ou espace)
    view_idx = upper.find("CREATE VIEW")
    if view_idx == -1:
        return []
    select_start = upper.find("SELECT", view_idx + 11)
    if select_start == -1:
        return []

    after_select = ddl_content[select_start + 6 :].strip()
    upper_after = after_select.upper().lstrip()

    # Handle SELECT *
    star_match = re.match(r"\*\s+FROM\s+(\w+)", upper_after, re.IGNORECASE)
    if star_match:
        source_table = star_match.group(1)
        for table_name, stats in all_column_stats.items():
            if table_name.lower() == source_table.lower():
                return list(stats.get("columns", {}).keys())
        logger.debug("SELECT * FROM %s : table source introuvable dans column_stats", source_table)
        return []

    # Find first top-level FROM
    from_idx = _find_top_level_keyword(upper_after, "FROM")
    select_body = after_select[:from_idx] if from_idx != -1 else after_select

    # Split by top-level commas
    parts = _split_top_level_commas(select_body)

    columns: list[str] = []
    for part in parts:
        col = _extract_column_from_select_part(part)
        if col:
            columns.append(col)

    return columns


# ── Construction des index ──────────────────────────────────────────


async def build_search_indexes(
    store: Any,
    excluded_entities: set[str] | None = None,
) -> SearchIndexes:
    """Construit les 4 index en memoire depuis TrainingStore + ValueMapping.

    Args:
        store: Instance de TrainingStore
        excluded_entities: si fourni, les tables/vues dont le nom est dans ce
            set (case-insensitive) sont exclues de l'index — leurs colonnes
            et valeurs ne seront jamais matchées. Permet à Phase 1.2.5
            (llm_filter_entities) de réduire le corpus AVANT la search.

    Returns:
        SearchIndexes pret pour la recherche
    """
    indexes = SearchIndexes()
    excluded_lower = {n.lower() for n in excluded_entities} if excluded_entities else set()

    # 1. Charger tous les DDL pour extraire tables, vues et colonnes
    try:
        # Phase α.4.D : orchestrator désactivé. user=None legacy + refactor
        # à faire si réactivation (propager user de la requête en amont).
        all_ddl = await store.get_all_ddl_contents(user=None)
    except Exception:
        logger.exception("Erreur chargement DDL pour index 4D")
        all_ddl = []

    # 2. Charger les stats
    try:
        all_table_stats = await store.get_all_table_stats()
    except Exception:
        logger.exception("Erreur chargement table_stats pour index 4D")
        all_table_stats = {}

    try:
        all_column_stats = await store.get_all_column_stats()
    except Exception:
        logger.exception("Erreur chargement column_stats pour index 4D")
        all_column_stats = {}

    # 3. Construire index tables + vues depuis DDL
    n_excluded = 0
    for ddl_entry in all_ddl:
        table_name = ddl_entry.get("table_name", "")
        source = ddl_entry.get("source", "")
        if not table_name:
            continue

        # Skip si l'entité est dans la liste d'exclusion (Phase 1.2.5 filter).
        # On compare en lower-case pour robustesse.
        if table_name.lower() in excluded_lower:
            n_excluded += 1
            continue

        is_view = source == "auto_sync_view"
        row_count = all_table_stats.get(table_name, 0)
        stats_obj = TableStats(real_name=table_name, row_count=row_count, is_view=is_view)
        key = table_name.lower()

        if is_view:
            indexes.views[key] = stats_obj
        else:
            indexes.tables[key] = stats_obj
    if n_excluded:
        logger.info("build_search_indexes: %d entités exclues (Phase 1.2.5)", n_excluded)

    # 4. Construire index colonnes depuis column_stats (pas le DDL regex)
    #    Les column_stats viennent de INFORMATION_SCHEMA — noms fiables.
    #    Skip les colonnes des entités exclues (Phase 1.2.5).
    for table_name, stats_data in all_column_stats.items():
        if table_name.lower() in excluded_lower:
            continue
        col_stats_columns = stats_data.get("columns", {})
        for col_name, cs in col_stats_columns.items():
            loc = ColumnLocation(
                column_name=col_name,
                table_name=table_name,
                data_type=cs.get("type", ""),
                distinct_count=cs.get("distinct", 0),
                null_pct=cs.get("null_pct", 0.0),
                is_pk=cs.get("is_pk", False),
                is_fk=cs.get("is_fk", False),
            )
            col_key = col_name.lower()
            indexes.columns.setdefault(col_key, []).append(loc)

    # 5. Colonnes de vues depuis leur DDL
    #    Les vues n'ont pas de column_stats — on extrait les noms depuis le DDL
    view_col_count = 0
    for ddl_entry in all_ddl:
        if ddl_entry.get("source") != "auto_sync_view":
            continue
        view_name = ddl_entry.get("table_name", "")
        ddl_text = ddl_entry.get("content", "")
        if not view_name or not ddl_text:
            continue
        # Skip colonnes des vues exclues (Phase 1.2.5)
        if view_name.lower() in excluded_lower:
            continue

        view_columns = _extract_view_columns(ddl_text, all_column_stats)
        for col_name in view_columns:
            col_key = col_name.lower()
            existing = indexes.view_columns.get(col_key, [])
            if any(loc.table_name == view_name for loc in existing):
                continue
            indexes.view_columns.setdefault(col_key, []).append(
                ColumnLocation(column_name=col_name, table_name=view_name)
            )
            view_col_count += 1

    # 6. Valeurs : PAS chargées en mémoire (28M+ entrées)
    #    Recherche directe dans SQLite via search_values_in_db()

    logger.info(
        "Index 5D construit : %d tables, %d vues, %d colonnes, "
        "%d colonnes de vues (%d vues) (valeurs: SQLite direct)",
        len(indexes.tables),
        len(indexes.views),
        len(indexes.columns),
        view_col_count,
        len([1 for v in all_ddl if v.get("source") == "auto_sync_view"]),
    )

    return indexes


# ── Recherche ───────────────────────────────────────────────────────


def search_term(term: str, indexes: SearchIndexes) -> TermSearchResults:
    """Recherche un terme dans les dimensions en mémoire (tables, vues, colonnes).

    Si indexes.values est peuplé (tests), cherche aussi les valeurs en mémoire.
    En production, les valeurs sont cherchées via SQLite dans search_all_terms().

    Args:
        term: Terme a chercher
        indexes: Index 4D pre-construit

    Returns:
        TermSearchResults avec les matches tries par qualite
    """
    results = TermSearchResults(term=term)
    term_lower = term.lower().strip()
    if not term_lower or not indexes:
        return results

    view_keys = set(indexes.views.keys()) if indexes.views else set()

    # 1. Tables (en mémoire)
    for name, stats in (indexes.tables or {}).items():
        result = _check_match(term_lower, name)
        if result:
            match_type, score = result
            results.add(
                SearchMatch(
                    match_type=match_type,
                    score=score,
                    dimension="table",
                    table_name=stats.real_name,
                    row_count=stats.row_count,
                    is_view=False,
                )
            )

    # 2. Vues (en mémoire)
    for name, stats in (indexes.views or {}).items():
        result = _check_match(term_lower, name)
        if result:
            match_type, score = result
            results.add(
                SearchMatch(
                    match_type=match_type,
                    score=score,
                    dimension="view",
                    table_name=stats.real_name,
                    row_count=stats.row_count,
                    is_view=True,
                )
            )

    # 3. Colonnes de tables (en mémoire)
    for col_name, locations in (indexes.columns or {}).items():
        result = _check_match(term_lower, col_name)
        if result:
            match_type, score = result
            for loc in locations:
                results.add(
                    SearchMatch(
                        match_type=match_type,
                        score=score,
                        dimension="column",
                        table_name=loc.table_name,
                        column_name=loc.column_name,
                        data_type=loc.data_type,
                        distinct_count=loc.distinct_count,
                        null_pct=loc.null_pct,
                        is_pk=loc.is_pk,
                        is_fk=loc.is_fk,
                        row_count=_get_table_row_count(loc.table_name, indexes),
                    )
                )

    # 3b. Colonnes de vues (en mémoire)
    for col_name, locations in (indexes.view_columns or {}).items():
        result = _check_match(term_lower, col_name)
        if result:
            match_type, score = result
            for loc in locations:
                results.add(
                    SearchMatch(
                        match_type=match_type,
                        score=score,
                        dimension="view_column",
                        table_name=loc.table_name,
                        column_name=loc.column_name,
                        data_type=loc.data_type,
                        is_view=True,
                        row_count=_get_table_row_count(loc.table_name, indexes),
                    )
                )

    # 4. Valeurs en mémoire (pour les tests avec sample_indexes)
    for value_lower, locations in (indexes.values or {}).items():
        result = _check_match_no_fuzzy(term_lower, value_lower)
        if result:
            match_type, score = result
            for loc in locations:
                results.add(
                    SearchMatch(
                        match_type=match_type,
                        score=score,
                        dimension="value",
                        table_name=loc.table_name,
                        column_name=loc.column_name,
                        distinct_count=loc.distinct_count,
                        null_pct=loc.null_pct,
                        real_value=loc.value,
                        row_count=_get_table_row_count(loc.table_name, indexes),
                        estimated_occurrence=loc.estimated_occurrence,
                    )
                )

    results.sort_results()
    return results


async def _search_all_values_in_db(
    cache: dict[str, TermSearchResults],
    indexes: SearchIndexes,
    excluded_entities: set[str] | None = None,
) -> None:
    """Recherche de valeurs pour TOUS les termes en 2 requêtes SQLite.

    1 requête exact (IN) + 1 requête contains (OR LIKE).
    Au lieu de 2 requêtes × N termes = 2N requêtes.
    """
    import time as _time

    all_terms = [k for k in cache if k]
    if not all_terms:
        return

    # Construit la clause d'exclusion par table_name (Phase 1.2.5 filter).
    # On garde les noms en case-original pour le AND NOT IN, plus les versions
    # avec/sans préfixe `dbo_` pour matcher les variantes Sage SQL Server.
    excluded_set: set[str] = set()
    if excluded_entities:
        for n in excluded_entities:
            excluded_set.add(n)
            if n.startswith("dbo_"):
                excluded_set.add(n[4:])
            else:
                excluded_set.add(f"dbo_{n}")

    # Pre-compute strip-accent for every cache term ONCE (called many times
    # in the dispatch loops below — O(rows × terms) iterations).
    cache_unacc: dict[str, str] = {ct: _strip_accents(ct) for ct in cache}

    # Build SQL search list = original terms ∪ strip-accent versions.
    # SQLite n'a pas de COLLATE accent-insensitive ; on doit donc passer
    # les deux variantes pour matcher 'identité' avec 'entite' sans accent
    # ET 'identite' avec 'entité' avec accent.
    sql_terms_set: set[str] = set(all_terms)
    sql_terms_set.update(cache_unacc[ct] for ct in all_terms if cache_unacc[ct])
    sql_terms = sorted(sql_terms_set)

    try:
        from sqlalchemy import text

        async with get_session() as session:
            # --- REQUÊTE 1 : EXACT (1 seule requête IN pour tous les termes) ---
            _t0 = _time.time()
            placeholders = ", ".join(f":t{i}" for i in range(len(sql_terms)))
            params = {f"t{i}": t for i, t in enumerate(sql_terms)}

            # Phase 1.2.5 filter — exclut les rows des tables/vues droppées.
            # On ajoute `AND table_name NOT IN (...)` à la WHERE clause.
            excl_clause = ""
            if excluded_set:
                excl_placeholders = ", ".join(f":x{i}" for i in range(len(excluded_set)))
                excl_clause = f" AND table_name NOT IN ({excl_placeholders})"
                for i, n in enumerate(sorted(excluded_set)):
                    params[f"x{i}"] = n

            exact_rows = (
                await session.execute(
                    text(
                        f"SELECT real_value_lower, table_name, column_name, "
                        f"real_value "
                        f"FROM value_mapping "
                        f"WHERE real_value_lower IN ({placeholders})"
                        f"{excl_clause}"
                    ),
                    params,
                )
            ).fetchall()
            _t1 = _time.time()
            print(
                f"  [exact] {len(sql_terms)} termes (orig+unaccented) → "
                f"{len(exact_rows)} hits ({_t1-_t0:.2f}s)",
                flush=True,
            )

            for real_lower, table_name, column_name, real_val in exact_rows:
                # Dispatcher accent-insensitive : pour chaque cache term,
                # check if it equals (with accents stripped) the real_lower.
                # Utilise le dict pré-calculé pour éviter O(N) strip par row.
                real_unacc = _strip_accents(real_lower)
                matched_terms = [
                    ct for ct, ct_unacc in cache_unacc.items() if ct_unacc == real_unacc
                ]
                if not matched_terms:
                    continue
                col_key = column_name.lower()
                col_locs = indexes.columns.get(col_key, [])
                col_match = next((c for c in col_locs if c.table_name == table_name), None)
                dc = col_match.distinct_count if col_match else 0
                rc = _get_table_row_count(table_name, indexes)
                # Add a SearchMatch for each cache term that matches (after
                # stripping accents). Different cache terms may differ only
                # by accents; downstream rendering dedups on (dim, tbl, col,
                # anon, term) so each variant gets its own visible entry.
                for ct in matched_terms:
                    cache[ct].add(
                        SearchMatch(
                            match_type="exact",
                            score=1.0,
                            dimension="value",
                            table_name=table_name,
                            column_name=column_name,
                            distinct_count=dc,
                            null_pct=col_match.null_pct if col_match else 0.0,
                            real_value=real_val,
                            row_count=rc,
                            estimated_occurrence=rc // dc if dc > 0 else 0,
                        )
                    )

            # --- REQUÊTE 2 : CONTAINS (1 seul scan pour tous les termes) ---
            # Filtrer les termes trop courts (< 3 chars). Inclure aussi les
            # versions strip-accent pour matcher 'identite' avec 'entite' ET
            # 'identité' avec 'entité' (SQLite n'a pas de COLLATE accent-
            # insensitive). Le dispatch côté Python utilise le cache_unacc
            # pré-calculé pour dispatcher correctement vers le bon terme
            # même si la query a matché une variante.
            contains_set: set[str] = set()
            for t in all_terms:
                if len(t) >= 3:
                    contains_set.add(t)
                t_unacc = cache_unacc[t]
                if t_unacc and len(t_unacc) >= 3:
                    contains_set.add(t_unacc)
            contains_terms = sorted(contains_set)
            # Liste des (cache_term, cache_term_unacc) pour le dispatch — filtrée
            # à ≥3 chars (équivalent au filtre de l'ancien `contains_terms`).
            cache_unacc_for_dispatch = [
                (ct, ct_unacc) for ct, ct_unacc in cache_unacc.items() if len(ct) >= 3
            ]
            if contains_terms:
                _t2 = _time.time()

                # Phase 1.2.5 filter — exclut les rows des tables droppées.
                excl_clause = ""
                excl_params: dict = {}
                if excluded_set:
                    placeholders_x = ", ".join(f":x{i}" for i in range(len(excluded_set)))
                    excl_params = {f"x{i}": n for i, n in enumerate(sorted(excluded_set))}
                    excl_clause_fts = f" AND vm.table_name NOT IN ({placeholders_x})"
                    excl_clause_like = f" AND table_name NOT IN ({placeholders_x})"
                else:
                    excl_clause_fts = ""
                    excl_clause_like = ""

                # Détecte la présence de la FTS5 trigram sur ``real_value_lower``
                # (recréée le 2026-05-22 sur la nouvelle ``value_mapping`` sans
                # anonymized_value). Si présente → MATCH (×30 à ×800 plus rapide
                # qu'un OR LIKE sur 29M+ rows). Sinon → fallback OR LIKE.
                _fts_check = await session.execute(
                    text(
                        "SELECT 1 FROM sqlite_master "
                        "WHERE type='table' AND name='value_mapping_fts' LIMIT 1"
                    )
                )
                use_fts = _fts_check.fetchone() is not None

                if use_fts:
                    # Quote chaque terme en phrase littérale FTS5 (les
                    # caractères spéciaux `/`, `-`, `+`, `*`, `(`, `:`, espace,
                    # apostrophe…) sont neutralisés. ``"`` interne doublé.
                    def _quote_for_fts(t: str) -> str:
                        return '"' + t.replace('"', '""') + '"'

                    fts_match = " OR ".join(_quote_for_fts(t) for t in contains_terms)
                    fts_params = {"q": fts_match, **excl_params}
                    contains_rows = (
                        await session.execute(
                            text(
                                "SELECT vm.real_value_lower, vm.table_name, "
                                "vm.column_name, vm.real_value "
                                "FROM value_mapping_fts AS fts "
                                "JOIN value_mapping AS vm ON vm.id = fts.rowid "
                                "WHERE fts.value_mapping_fts MATCH :q"
                                f"{excl_clause_fts}"
                            ),
                            fts_params,
                        )
                    ).fetchall()
                    _backend = "FTS5"
                else:
                    # Fallback OR LIKE — lent sur grosse value_mapping mais
                    # garde la compat si la FTS5 n'a pas encore été recréée.
                    like_clauses = []
                    like_params = dict(excl_params)
                    for i, t in enumerate(contains_terms):
                        like_clauses.append(f"real_value_lower LIKE :p{i}")
                        like_params[f"p{i}"] = f"%{t}%"
                    where_clause = " OR ".join(like_clauses)
                    contains_rows = (
                        await session.execute(
                            text(
                                f"SELECT real_value_lower, table_name, column_name, "
                                f"real_value "
                                f"FROM value_mapping "
                                f"WHERE ({where_clause})"
                                f"{excl_clause_like}"
                            ),
                            like_params,
                        )
                    ).fetchall()
                    _backend = "LIKE"
                _t3 = _time.time()
                print(
                    f"  [contains/{_backend}] {len(contains_terms)} termes "
                    f"(orig+unaccented) → {len(contains_rows)} hits "
                    f"({_t3-_t2:.2f}s)",
                    flush=True,
                )

                # Dispatcher chaque résultat vers le bon terme du cache,
                # accent-insensitive.
                for real_lower, table_name, column_name, real_val in contains_rows:
                    real_unacc = _strip_accents(real_lower)
                    for ct, ct_unacc in cache_unacc_for_dispatch:
                        if ct_unacc == real_unacc:
                            continue
                        if ct_unacc in real_unacc:
                            col_key = column_name.lower()
                            col_locs = indexes.columns.get(col_key, [])
                            col_match = next(
                                (c for c in col_locs if c.table_name == table_name), None
                            )
                            dc = col_match.distinct_count if col_match else 0
                            rc = _get_table_row_count(table_name, indexes)
                            cache[ct].add(
                                SearchMatch(
                                    match_type="contains",
                                    score=0.8,
                                    dimension="value",
                                    table_name=table_name,
                                    column_name=column_name,
                                    distinct_count=dc,
                                    null_pct=col_match.null_pct if col_match else 0.0,
                                    real_value=real_val,
                                    row_count=rc,
                                    estimated_occurrence=rc // dc if dc > 0 else 0,
                                )
                            )

    except Exception:
        logger.exception("Erreur recherche valeurs SQLite batch")


async def search_all_terms(
    listo: list[str],
    indexes: SearchIndexes,
    excluded_entities: set[str] | None = None,
) -> dict[str, TermSearchResults]:
    """Recherche tous les termes de listo dans les 4 dimensions.

    Dimensions 1-3 (tables, vues, colonnes) : sync en mémoire via search_term().
    Dimension 4 (valeurs) : 2 requêtes SQLite batch (exact IN + contains MATCH/LIKE).

    Args:
        listo: Liste de termes a chercher
        indexes: Index 4D pre-construit
        excluded_entities: si fourni, les rows de value_mapping appartenant à
            ces tables/vues sont exclues de la search SQLite (Phase 1.2.5).
            Indexes doit déjà avoir été construit avec le même excluded_entities
            pour cohérence avec les dimensions 1-3.

    Returns:
        {terme: TermSearchResults} pour chaque terme
    """
    # Phase 1 : recherche sync (tables, vues, colonnes + valeurs en mémoire si présentes)
    cache: dict[str, TermSearchResults] = {}
    for term in listo:
        key = term.lower().strip()
        if key and key not in cache:
            cache[key] = search_term(term, indexes)

    # Phase 2 : recherche valeurs dans SQLite (si pas de valeurs en mémoire)
    if not indexes.values:
        await _search_all_values_in_db(cache, indexes, excluded_entities=excluded_entities)
        for results in cache.values():
            results.sort_results()

    return cache



async def search_exclusion_values(
    term: str,
    indexes: SearchIndexes,
    max_values: int = 50,
) -> dict[str, list[dict]]:
    """Find ALL real values containing the given term across all columns.

    Used for auto-resolving exclusion filters: when user says
    "not the X containing ABC", this finds every real value with "ABC" in it,
    grouped by table.column.

    Queries SQLite directly (ValueMapping) — no in-memory index needed.
    """
    if not term:
        return {}

    term_lower = term.lower().strip()
    if not term_lower:
        return {}

    try:
        from sqlalchemy import text

        grouped: dict[str, list[dict]] = {}
        async with get_session() as session:
            rows = (
                await session.execute(
                    text(
                        "SELECT table_name, column_name, real_value "
                        "FROM value_mapping "
                        "WHERE real_value_lower LIKE :pattern "
                        "LIMIT :limit"
                    ),
                    {"pattern": f"%{term_lower}%", "limit": max_values},
                )
            ).fetchall()

        for table_name, column_name, real_val in rows:
            col_key = column_name.lower()
            col_locs = indexes.columns.get(col_key, []) if indexes else []
            col_match = next((c for c in col_locs if c.table_name == table_name), None)
            dc = col_match.distinct_count if col_match else 0
            rc = _get_table_row_count(table_name, indexes) if indexes else 0
            key = f"{table_name}.{column_name}"
            grouped.setdefault(key, []).append(
                {
                    "value": real_val,
                    "occurrence": rc // dc if dc > 0 else 0,
                }
            )

        return grouped
    except Exception:
        logger.exception("Erreur search_exclusion_values pour '%s'", term)
        return {}


def merge_new_results(
    existing_cache: dict[str, TermSearchResults],
    new_results: dict[str, TermSearchResults],
) -> dict[str, TermSearchResults]:
    """Fusionne les nouveaux resultats dans le cache existant sans ecraser.

    Args:
        existing_cache: Cache existant
        new_results: Nouveaux resultats a ajouter

    Returns:
        Cache mis a jour (meme reference que existing_cache)
    """
    for key, results in new_results.items():
        if key not in existing_cache:
            existing_cache[key] = results
    return existing_cache


# ── Formatage pour le LLM ──────────────────────────────────────────


def _table_relevance_score(matches: list[dict]) -> float:
    """Score composite par table : qualite des matches > quantite.

    Un match exact vaut 3x un fuzzy, un contains 2x.
    Bonus pour les dimensions colonne/valeur (plus informatives que table/vue).
    """
    score = 0.0
    for m in matches:
        if m["match_type"] == "exact":
            score += 3.0
        elif m["match_type"] == "contains":
            score += 2.0
        else:
            score += m.get("score", 0.75)

        # Bonus par dimension (colonne et valeur sont plus informatives)
        if m["dimension"] in ("column", "view_column"):
            score += 0.5
        elif m["dimension"] == "value":
            score += 0.3
    return score


def _build_top_candidates_summary(
    all_results: dict,  # {terme: TermSearchResults}
    by_table: dict[str, list[dict]],
) -> list[str]:
    """Construit un résumé des meilleurs candidats par terme recherché.

    Au lieu de laisser le LLM parcourir des centaines de lignes de résultats,
    cette fonction identifie les 3-5 meilleurs candidats COLONNE pour chaque
    terme, en priorisant :
    - Les colonnes FK (relient les tables, utiles pour les JOINs)
    - Les colonnes avec des valeurs distinctes (contiennent des données réelles)
    - Les match "exact" ou "contains" (pas les fuzzy faibles)
    - Les colonnes non-NULL (données exploitables)

    Retourne des lignes formatées pour le début du prompt LLM.
    """
    lines: list[str] = []
    seen_cols: set[tuple] = set()

    for term, results in all_results.items():
        if not results.matches:
            continue

        # Collecter les candidats par dimension
        table_candidates: list[dict] = []
        col_candidates: list[dict] = []
        val_candidates: list[dict] = []
        for m in results.matches:
            if m.dimension in ("table", "view"):
                table_candidates.append(
                    {
                        "table": m.table_name,
                        "match_type": m.match_type,
                        "score": m.score,
                        "row_count": m.row_count or 0,
                        "is_view": m.is_view,
                    }
                )
            elif m.dimension in ("column", "view_column"):
                col_candidates.append(
                    {
                        "table": m.table_name,
                        "column": m.column_name,
                        "match_type": m.match_type,
                        "score": m.score,
                        "is_fk": m.is_fk,
                        "is_pk": m.is_pk,
                        "distinct": m.distinct_count or 0,
                        "null_pct": m.null_pct or 0,
                        "data_type": m.data_type or "",
                        "is_view": m.is_view,
                        "dimension": m.dimension,
                    }
                )
            elif m.dimension == "value" and m.match_type in ("exact", "contains"):
                val_candidates.append(
                    {
                        "table": m.table_name,
                        "column": m.column_name,
                        "value": m.real_value or "",
                    }
                )

        if not table_candidates and not col_candidates and not val_candidates:
            continue

        # Trier les colonnes par UTILITÉ pour le SQL, pas juste par score brut :
        # 1. FK (relient les tables) > non-FK
        # 2. Score de match (exact > contains > fuzzy)
        # 3. Colonnes avec des données (distinct > 0, null < 90%)
        def _col_utility(c: dict) -> tuple:
            fk_bonus = 1 if c["is_fk"] else 0
            has_data = 1 if c["distinct"] > 0 and c["null_pct"] < 90 else 0
            return (-fk_bonus, -c["score"], -has_data, c["null_pct"])

        col_candidates.sort(key=_col_utility)

        # Dédupliquer (même table.colonne)
        unique_cols = []
        for c in col_candidates:
            key = (c["table"], c["column"])
            if key not in seen_cols:
                seen_cols.add(key)
                unique_cols.append(c)

        # Afficher les tables/vues qui matchent par NOM (le plus important !)
        if table_candidates:
            # Trier : exact > contains > fuzzy, puis par row_count décroissant
            table_candidates.sort(key=lambda t: (-t["score"], -t["row_count"]))
            lines.append(f'**"{term}"** → tables/vues :')
            seen_tables: set[str] = set()
            for t in table_candidates[:5]:
                if t["table"] in seen_tables:
                    continue
                seen_tables.add(t["table"])
                kind = "vue" if t["is_view"] else "table"
                rc = f" ({t['row_count']:,} lignes)" if t["row_count"] else ""
                lines.append(f"  → **{t['table']}** [{kind}] [{t['match_type']}]{rc}")

        # Afficher les top 5 colonnes pour ce terme
        if unique_cols:
            lines.append(f'**"{term}"** → colonnes :')
            for c in unique_cols[:5]:
                badges = []
                if c["is_fk"]:
                    badges.append("FK")
                if c["is_pk"]:
                    badges.append("PK")
                badge_str = f" [{','.join(badges)}]" if badges else ""
                view_tag = " (vue)" if c["is_view"] else ""
                lines.append(
                    f"  → {c['table']}.{c['column']}{badge_str}{view_tag} "
                    f"[{c['match_type']}] distinct={c['distinct']}"
                )

        # Afficher les top 3 valeurs trouvées (vraies valeurs ; le Pseudonymizer
        # intercepte avant envoi LLM si le terme est dans /data-privacy).
        if val_candidates:
            unique_vals = []
            seen_v: set[tuple] = set()
            for v in val_candidates[:5]:
                key = (v["table"], v["column"], v["value"])
                if key not in seen_v:
                    seen_v.add(key)
                    unique_vals.append(v)
            if unique_vals:
                lines.append(f'**"{term}"** → valeurs trouvées :')
                for v in unique_vals[:3]:
                    lines.append(
                        f"  → {v['table']}.{v['column']} " f"contient \"{v['value']}\""
                    )

    return lines


def _has_strong_match(matches: list[dict]) -> bool:
    """True si au moins un match exact ou contains dans la liste."""
    return any(m["match_type"] in ("exact", "contains") for m in matches)


# Maximum de matches affichés par table. Au-delà, les résultats sont résumés.
# Un seul terme comme "2023" peut matcher 185K valeurs — sans cap, un seul
# tableau pourrait consommer tout le budget chars du prompt.
_MAX_MATCHES_PER_TABLE = 15


def _format_table_block(table_name: str, matches: list[dict]) -> list[str]:
    """Formate le bloc de resultats pour une table."""
    lines: list[str] = []

    # Trier par qualité : exact > contains > fuzzy, puis par score desc
    _type_order = {"exact": 0, "contains": 1, "fuzzy": 2}
    matches_sorted = sorted(
        matches,
        key=lambda m: (_type_order.get(m["match_type"], 3), -m["score"]),
    )
    truncated_count = 0
    if len(matches_sorted) > _MAX_MATCHES_PER_TABLE:
        truncated_count = len(matches_sorted) - _MAX_MATCHES_PER_TABLE
        matches_sorted = matches_sorted[:_MAX_MATCHES_PER_TABLE]

    # En-tete table avec stats enrichies
    row_counts = [m["row_count"] for m in matches if m["row_count"] > 0]
    rc_str = f"{max(row_counts)} lignes" if row_counts else "? lignes"
    n_cols = len([m for m in matches if m["dimension"] in ("column", "view_column")])
    n_fk = len([m for m in matches if m.get("is_fk")])
    obj_type = "Vue" if any(m["is_view"] for m in matches) else "Table"
    stats_parts = [rc_str]
    if n_cols:
        stats_parts.append(f"{n_cols} cols matchees")
    if n_fk:
        stats_parts.append(f"{n_fk} FK")
    lines.append(f"\n--- {obj_type}: {table_name} ({', '.join(stats_parts)}) ---")

    # Regrouper par dimension (sur les matches triés et tronqués)
    for dimension in ("value", "column", "view_column", "table", "view"):
        dim_matches = [m for m in matches_sorted if m["dimension"] == dimension]
        if not dim_matches:
            continue

        for entry in dim_matches:
            mt = entry["match_type"]
            mt_label = f"fuzzy {int(entry['score'] * 100)}%" if mt == "fuzzy" else mt

            null_warning = ""
            if (entry.get("null_pct") or 0) >= 90:
                null_warning = " *** ATTENTION: >=90% NULL ***"

            if dimension == "value":
                occ_str = (
                    f" occurrence~{entry['estimated_occurrence']}"
                    if entry.get("estimated_occurrence")
                    else ""
                )
                lines.append(
                    f"  VALEUR [{mt_label}] "
                    f"colonne={entry['column_name']} "
                    f"valeur=\"{entry.get('real_value', '')}\" "
                    f"(terme: \"{entry['term']}\") "
                    f"distinct={entry['distinct_count']} "
                    f"null={entry['null_pct']}%{occ_str}{null_warning}"
                )
            elif dimension in ("column", "view_column"):
                dim_label = "COLONNE_VUE" if dimension == "view_column" else "COLONNE"
                badges = []
                if entry.get("is_pk"):
                    badges.append("PK")
                if entry.get("is_fk"):
                    badges.append("FK")
                badge_str = " [" + ",".join(badges) + "]" if badges else ""
                type_str = f" ({entry['data_type']})" if entry.get("data_type") else ""
                lines.append(
                    f"  {dim_label} [{mt_label}] "
                    f"{entry['column_name']}{type_str}{badge_str} "
                    f"(terme: \"{entry['term']}\") "
                    f"distinct={entry.get('distinct_count', 0)} "
                    f"null={entry.get('null_pct', 0)}%{null_warning}"
                )
            else:
                lines.append(f"  {dimension.upper()} [{mt_label}] " f"(terme: \"{entry['term']}\")")

    if truncated_count > 0:
        lines.append(
            f"  ... +{truncated_count} résultats tronqués. "
            f"Utilise introspect_table ou get_resolved_values pour plus de détails."
        )

    return lines


def format_results_for_llm(
    all_results: dict[str, TermSearchResults],
    max_total: int = 0,
    max_chars: int = 30_000,
) -> str:
    """Formate les resultats de recherche pour injection dans un prompt LLM.

    Regroupe par table, dedoublonne, anonymise les valeurs.
    Tri par QUALITE des matches (exact/contains > fuzzy).

    Garantie : toute table avec au moins 1 match exact ou contains est TOUJOURS
    incluse, meme si d'autres tables ont plus de matches.

    Args:
        all_results: {terme: TermSearchResults} depuis search_all_terms
        max_total: Compat legacy — si > 0, utilise comme cap de lignes en fallback
        max_chars: Budget maximum en caracteres (~30000 = ~7500 tokens)

    Returns:
        Texte structure pour le prompt LLM
    """
    # 1. Collecter tous les matches uniques, regroupes par table
    by_table: dict[str, list[dict]] = {}
    seen: set[tuple] = set()

    for term, results in all_results.items():
        for m in results.matches:
            dedup_key = (m.dimension, m.table_name, m.column_name, m.real_value, term)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            entry = {
                "term": term,
                "dimension": m.dimension,
                "match_type": m.match_type,
                "score": m.score,
                "column_name": m.column_name,
                "data_type": m.data_type,
                "distinct_count": m.distinct_count,
                "null_pct": m.null_pct,
                "is_pk": m.is_pk,
                "is_fk": m.is_fk,
                "row_count": m.row_count,
                "real_value": m.real_value,
                "is_view": m.is_view,
                "estimated_occurrence": m.estimated_occurrence,
            }
            by_table.setdefault(m.table_name, []).append(entry)

    if not by_table:
        return "Aucun resultat trouve dans la base de donnees."

    # 2. Separer : tables avec matches forts (exact/contains) vs fuzzy-only
    must_include = {t: m for t, m in by_table.items() if _has_strong_match(m)}
    nice_to_have = {t: m for t, m in by_table.items() if t not in must_include}

    # Trier chaque groupe par score de pertinence (qualite > quantite)
    sorted_must = sorted(must_include.items(), key=lambda kv: -_table_relevance_score(kv[1]))
    sorted_nice = sorted(nice_to_have.items(), key=lambda kv: -_table_relevance_score(kv[1]))

    # 2b. Construire un résumé des meilleurs candidats par terme recherché.
    # Ceci aide le LLM à identifier rapidement les colonnes les plus pertinentes
    # au lieu de parcourir des centaines de lignes de résultats bruts.
    top_candidates = _build_top_candidates_summary(all_results, by_table)

    # 3. Formater avec budget chars
    lines: list[str] = []
    lines.append("=== RESULTATS DE RECHERCHE DANS LA BASE DE DONNEES ===\n")
    if top_candidates:
        lines.append("## MEILLEURS CANDIDATS (résumé)\n")
        lines.extend(top_candidates)
        lines.append("")
    lines.append("## DÉTAILS PAR TABLE\n")
    char_count = sum(len(l) + 1 for l in lines)
    total_entries = 0
    tables_included = 0
    tables_truncated = 0

    def _append_table(table_name: str, matches: list[dict], force: bool = False) -> bool:
        """Ajoute un bloc table. Retourne False si budget depasse (sauf si force=True)."""
        nonlocal char_count, total_entries, tables_included
        block = _format_table_block(table_name, matches)
        block_chars = sum(len(line) + 1 for line in block)

        # Budget check — force=True bypasse (must_include tables)
        if not force and max_chars > 0 and char_count + block_chars > max_chars:
            return False

        lines.extend(block)
        char_count += block_chars
        total_entries += len(matches)
        tables_included += 1
        return True

    # must_include : exact/contains tables. Budget séparé pour éviter qu'un seul
    # concept (ex: "2023" → 185K valeurs) consomme tout le budget.
    must_budget = int(max_chars * 0.7)  # 70% du budget pour must_include
    for table_name, matches in sorted_must:
        if char_count < must_budget:
            _append_table(table_name, matches, force=True)
        else:
            # Budget must_include dépassé → ajouter mais plus en force
            if not _append_table(table_name, matches, force=False):
                tables_truncated += 1

    # nice_to_have : inclus si budget reste
    for table_name, matches in sorted_nice:
        if not _append_table(table_name, matches):
            tables_truncated += 1

    if tables_truncated:
        lines.append(f"\n... ({tables_truncated} tables fuzzy-only tronquees par budget)")

    lines.append(f"\n=== {total_entries} resultats, {tables_included} tables ===")
    return "\n".join(lines)


def format_results_by_term(
    all_results: dict[str, TermSearchResults],
    max_chars: int = 20_000,
) -> str:
    """Formate les résultats de recherche GROUPÉS PAR TERME de recherche.

    Complémentaire à format_results_for_llm() (qui groupe par table).
    Permet au LLM de voir la couverture terme par terme.

    Args:
        all_results: Dict terme → TermSearchResults (de search_all_terms)
        max_chars: Budget max en caractères

    Returns:
        Texte formaté montrant, pour chaque terme, les matches dans les 4 dimensions
    """
    lines: list[str] = ["=== RÉSULTATS PAR TERME DE RECHERCHE ===\n"]
    char_count = len(lines[0])

    # Trier les termes : ceux avec des résultats forts d'abord
    def _term_priority(item: tuple[str, TermSearchResults]) -> tuple[int, int]:
        _term, results = item
        has_exact = any(m.match_type == "exact" for m in results.matches)
        has_contains = any(m.match_type == "contains" for m in results.matches)
        priority = 0 if has_exact else (1 if has_contains else 2)
        return (priority, -len(results.matches))

    sorted_terms = sorted(all_results.items(), key=_term_priority)
    terms_shown = 0

    for term, results in sorted_terms:
        if not results.has_results:
            continue

        # Build block for this term
        block_lines: list[str] = []
        block_lines.append(f"\n── « {term} » ({len(results.matches)} résultats) ──")

        # Group by dimension
        by_dim: dict[str, list[SearchMatch]] = {}
        for m in results.matches:
            by_dim.setdefault(m.dimension, []).append(m)

        # Show dimensions in order: value > column > view_column > table > view
        for dim in ("value", "column", "view_column", "table", "view"):
            dim_matches = by_dim.get(dim, [])
            if not dim_matches:
                continue

            dim_label = {
                "value": "Valeurs",
                "column": "Colonnes",
                "view_column": "Colonnes de vues",
                "table": "Tables",
                "view": "Vues",
            }.get(dim, dim)
            block_lines.append(f"  [{dim_label}]")

            for m in dim_matches[:5]:  # Max 5 per dimension per term
                match_badge = {"exact": "=", "contains": "⊃", "fuzzy": f"~{m.score}"}.get(
                    m.match_type, "?"
                )

                if dim == "value":
                    # Show real value + source table.column. Pseudonymizer
                    # runtime intercepte avant LLM si le terme est configuré
                    # dans /data-privacy.
                    stats = ""
                    if m.estimated_occurrence:
                        stats = f" (~{m.estimated_occurrence} occ.)"
                    block_lines.append(
                        f'    [{match_badge}] "{m.real_value}" '
                        f"dans {m.table_name}.{m.column_name}{stats}"
                    )
                elif dim in ("column", "view_column"):
                    # Show column with type + table + stats
                    null_warn = " ⚠NULL" if m.null_pct >= 90 else ""
                    fk_badge = " FK" if m.is_fk else ""
                    pk_badge = " PK" if m.is_pk else ""
                    block_lines.append(
                        f"    [{match_badge}] {m.table_name}.{m.column_name} "
                        f"({m.data_type}, {m.distinct_count} dist.{pk_badge}{fk_badge}{null_warn})"
                    )
                else:
                    # Table or view
                    obj_type = "vue" if m.is_view else "table"
                    block_lines.append(
                        f"    [{match_badge}] {m.table_name} ({obj_type}, {m.row_count} lignes)"
                    )

        block_text = "\n".join(block_lines)
        block_chars = len(block_text) + 1  # +1 for newline

        if char_count + block_chars > max_chars and terms_shown > 5:
            remaining = sum(1 for _t, r in sorted_terms[terms_shown:] if r.has_results)
            lines.append(f"\n... ({remaining} termes tronqués par budget)")
            break

        lines.append(block_text)
        char_count += block_chars
        terms_shown += 1

    lines.append(f"\n=== {terms_shown} termes affichés ===")
    return "\n".join(lines)


# ── Utilitaires internes ────────────────────────────────────────────


def _get_table_row_count(table_name: str, indexes: SearchIndexes) -> int:
    """Recupere le row_count d'une table depuis les index."""
    key = table_name.lower()
    stats = indexes.tables.get(key) or indexes.views.get(key)
    return stats.row_count if stats else 0


# Seuil fuzzy à 0.75 (pas 0.6) — les identifiants SQL sont courts,
# un seuil bas génère trop de faux positifs qui gaspillent des tokens.
# Minimum 4 chars pour fuzzy — les termes courts matchent trop facilement.
_FUZZY_THRESHOLD = 0.75
_FUZZY_MIN_LEN = 4


def _strip_accents(s: str | None) -> str:
    """Strip Unicode accents/diacritics for accent-insensitive matching.

    Normalizes to NFD then drops the combining marks. Idempotent.
    Tolère `None` et chaîne vide (retourne "" — contrat str-toujours).
    Used by `_check_match*` so that 'entité' matches 'grpCodeEntite' and
    inversely 'entite' matches 'libelleEntité' — convention bidirectionnelle.

    Coût : ~1 µs/appel — pré-calculer côté caller pour les boucles inner.
    """
    if not s:
        return ""
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))


def _check_match_no_fuzzy(term_lower: str, target_lower: str) -> tuple[str, float] | None:
    """Fast match: exact + contains only, no fuzzy (for large indexes like values).

    Strip accents bidirectionally before comparison so that 'entité' matches
    'entite' and inversely.
    """
    if not term_lower or not target_lower:
        return None
    # Strip accents on both sides for accent-insensitive matching
    t = _strip_accents(term_lower)
    g = _strip_accents(target_lower)
    if t == g:
        return ("exact", 1.0)
    if len(t) >= 3 and t in g:
        return ("contains", 0.8)
    return None


def _check_match(term_lower: str, target_lower: str) -> tuple[str, float] | None:
    """Verifie le type de match entre un terme et une cible.

    Contains = le terme est contenu dans la cible (unidirectionnel).
    Ex: "facture" in "factures" ✓, "facture" in "commentairefacture" ✓
    Mais PAS "0" in "2023/2024" (la cible "0" est trop courte pour être pertinente).

    Strip accents bidirectionally before comparison ('entité' ↔ 'entite').

    Returns:
        ("exact", 1.0), ("contains", 0.8), ("fuzzy", score) ou None si pas de match
    """
    if not term_lower or not target_lower:
        return None

    # Strip accents bidirectionally — 'entité' ↔ 'entite'
    t = _strip_accents(term_lower)
    g = _strip_accents(target_lower)

    if t == g:
        return ("exact", 1.0)

    # Unidirectionnel : le terme est contenu dans la cible (sans accents)
    if len(t) >= 3 and t in g:
        return ("contains", 0.8)

    # Fuzzy matching via SequenceMatcher (termes >= 4 chars, seuil 75%)
    # Comparaison aussi sans accents pour cohérence avec contains.
    if len(t) >= _FUZZY_MIN_LEN and len(g) >= _FUZZY_MIN_LEN:
        ratio = SequenceMatcher(None, t, g).ratio()
        if ratio >= _FUZZY_THRESHOLD:
            return ("fuzzy", round(ratio, 2))

    return None
