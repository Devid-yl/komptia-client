"""
Internal tools for Iris orchestrator — system-side helpers AND LLM tool schemas.

System-side helpers: extract DDL/docs, navigate FK graph,
verify COUNT deltas, search keywords, and execute SQL for validation.

Phase 2 LLM tools: Anthropic tool schemas + dispatcher for the agent loop.
"""

import asyncio
import json
import re
from collections import deque
from typing import Optional

from typing import Any

from app.services.ai.training_store import TrainingStore
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Module-level FK regexes — used by _extract_real_table_name, get_table_info, and build_fk_graph
_FK_SORTANTE_RE = re.compile(r"FK sortante:\s*(\w+)\((\w+)\s*→\s*(\w+)\)\s*REFERENCES\s+(\w+)")
_FK_ENTRANTE_RE = re.compile(r"FK entrante:\s*(\w+)\((\w+)\s*→\s*(\w+)\)\s*→\s*(\w+)")
# Relations inférées par convention de nommage + containment au sync
# Format: "Relation inférée (...): SourceTable.sourceCol → TargetTable.targetCol. ..."
_FK_INFERRED_RE = re.compile(
    r"Relation inf[ée]r[ée]e\s*\([^)]*\):\s*(\w+)\.(\w+)\s*→\s*(\w+)\.(\w+)"
)


async def _fetch_training_docs(
    store: TrainingStore,
    query: str,
    n_results: int = 5,
) -> list[dict]:
    """Fetch training store documents by query, returning empty list on error."""
    try:
        return await store.get_related_documentation(query, n_results=n_results)
    except Exception as e:
        logger.debug("Training store query failed for '%s': %s", query[:50], e)
        return []


async def get_table_info(table_name: str, store: TrainingStore) -> dict:
    """
    Get comprehensive table metadata: DDL, FKs, stats, anonymized values, role, row_count.

    Handles:
    - Tables stored as "TableName" and views stored as "dbo_ViewName"
    - FK relations stored as "relation:Table→Table" (real format)
    - column_values stored as "column_values:Table.Column" → JSON list
    - column_stats/table_stats stored as "column_stats:Table" → JSON dict
    - Direct SQL lookup for data that semantic search misses

    Args:
        table_name: Table name to fetch info for
        store: TrainingStore instance

    Returns:
        dict with keys: ddl, fk_outgoing, fk_incoming, column_stats, column_values, role, row_count
    """
    result = {
        "ddl": None,
        "fk_outgoing": [],
        "fk_incoming": [],
        "column_stats": {},
        "column_values": {},
        "role": None,
        "row_count": None,
    }

    try:
        # Phase α.4.D : orchestrator désactivé. user=None legacy + refactor
        # à faire si réactivation.
        # Fetch DDL — try exact name first, then with dbo_ prefix (for views)
        ddl_docs = await store.get_ddl_by_table_names([table_name], user=None)
        if not ddl_docs and not table_name.startswith("dbo_"):
            ddl_docs = await store.get_ddl_by_table_names([f"dbo_{table_name}"], user=None)
        if ddl_docs:
            result["ddl"] = ddl_docs[0].get("content")

        # Fetch related documentation — semantic search
        docs = await _fetch_training_docs(store, table_name, n_results=30)

        # Direct SQL lookup for data that semantic search misses
        try:
            from app.core.database import get_session
            from sqlalchemy import text

            async with get_session() as session:
                # Stats (table_stats, column_stats)
                for cat_prefix in [
                    f"column_stats:{table_name}",
                    f"table_stats:{table_name}",
                ]:
                    r = await session.execute(
                        text(
                            "SELECT category, content FROM training_data "
                            "WHERE category = :cat AND is_active = 1 LIMIT 1"
                        ),
                        {"cat": cat_prefix},
                    )
                    row = r.fetchone()
                    if row:
                        docs.append({"category": row[0], "content": row[1], "score": 1.0})

                # Column values (column_values:Table.Column)
                r2 = await session.execute(
                    text(
                        "SELECT category, content FROM training_data "
                        "WHERE category LIKE :pat AND is_active = 1 LIMIT 50"
                    ),
                    {"pat": f"column_values:{table_name}.%"},
                )
                for row in r2.fetchall():
                    docs.append({"category": row[0], "content": row[1], "score": 1.0})

                # FK relations — the REAL format: "relation:Table→*" and "relation:*→Table"
                r3 = await session.execute(
                    text(
                        "SELECT category, content FROM training_data "
                        "WHERE (category LIKE :pat1 OR category LIKE :pat2) "
                        "AND is_active = 1 LIMIT 100"
                    ),
                    {
                        "pat1": f"relation:{table_name}→%",
                        "pat2": f"relation:%→{table_name}",
                    },
                )
                for row in r3.fetchall():
                    docs.append({"category": row[0], "content": row[1], "score": 1.0})
                # Also search with reversed arrow
                r4 = await session.execute(
                    text(
                        "SELECT category, content FROM training_data "
                        "WHERE (category LIKE :pat1 OR category LIKE :pat2) "
                        "AND is_active = 1 LIMIT 100"
                    ),
                    {
                        "pat1": f"relation:{table_name}←%",
                        "pat2": f"relation:%←{table_name}",
                    },
                )
                for row in r4.fetchall():
                    docs.append({"category": row[0], "content": row[1], "score": 1.0})
        except Exception as e:
            logger.debug("Direct category lookup failed for %s: %s", table_name, e)

        # Regex to parse FK content from relation: docs
        for doc in docs:
            category = doc.get("category", "")
            content = doc.get("content", "")

            try:
                # Parse FK from relation: format (the REAL format in TrainingStore)
                if category.startswith("relation:"):
                    m = _FK_SORTANTE_RE.search(content)
                    if m:
                        child_table, child_col, parent_col, parent_table = m.groups()
                        fk_entry = {
                            "table": parent_table,
                            "column": parent_col,
                            "fk_column": child_col,
                            "constraint": (
                                content.split("Constraint:")[-1].strip().rstrip(".")
                                if "Constraint:" in content
                                else ""
                            ),
                        }
                        if child_table.upper() == table_name.upper():
                            result["fk_outgoing"].append(fk_entry)
                        elif parent_table.upper() == table_name.upper():
                            result["fk_incoming"].append(
                                {
                                    "table": child_table,
                                    "column": child_col,
                                    "fk_column": parent_col,
                                    "constraint": fk_entry["constraint"],
                                }
                            )
                        continue

                    m = _FK_ENTRANTE_RE.search(content)
                    if m:
                        child_table, child_col, parent_col, parent_table = m.groups()
                        if parent_table.upper() == table_name.upper():
                            result["fk_incoming"].append(
                                {
                                    "table": child_table,
                                    "column": child_col,
                                    "fk_column": parent_col,
                                }
                            )
                        elif child_table.upper() == table_name.upper():
                            result["fk_outgoing"].append(
                                {
                                    "table": parent_table,
                                    "column": parent_col,
                                    "fk_column": child_col,
                                }
                            )
                        continue

                    # Inferred relations (naming convention + containment)
                    m = _FK_INFERRED_RE.search(content)
                    if m:
                        src_table, src_col, tgt_table, tgt_col = m.groups()
                        if src_table.upper() == table_name.upper():
                            result["fk_outgoing"].append(
                                {
                                    "table": tgt_table,
                                    "column": tgt_col,
                                    "fk_column": src_col,
                                    "inferred": True,
                                }
                            )
                        elif tgt_table.upper() == table_name.upper():
                            result["fk_incoming"].append(
                                {
                                    "table": src_table,
                                    "column": src_col,
                                    "fk_column": tgt_col,
                                    "inferred": True,
                                }
                            )
                        continue

                # Legacy fk: format (kept for backwards compatibility)
                elif category.startswith("fk:"):
                    parts = category.split(":")
                    if len(parts) >= 4:
                        direction = parts[1]
                        source_table = parts[2]
                        target_table = parts[3]
                        fk_data = json.loads(content)

                        if direction == "sortante" and source_table.upper() == table_name.upper():
                            result["fk_outgoing"].append(fk_data)
                        elif direction == "entrante" and target_table.upper() == table_name.upper():
                            result["fk_incoming"].append(fk_data)

                elif category.startswith("column_values:"):
                    # Real format: "column_values:Table.Column" → content is JSON list
                    try:
                        cat_suffix = category[len("column_values:") :]
                        # Extract column name from "Table.Column" format
                        if "." in cat_suffix:
                            cat_table, col_name = cat_suffix.rsplit(".", 1)
                            if cat_table.upper() == table_name.upper():
                                values_list = json.loads(content)
                                if isinstance(values_list, list):
                                    result["column_values"][col_name] = values_list
                                elif isinstance(values_list, dict):
                                    result["column_values"].update(values_list)
                        else:
                            # Legacy format: "column_values:Table" → content is dict
                            values_data = json.loads(content)
                            if isinstance(values_data, dict):
                                result["column_values"].update(values_data)
                    except (json.JSONDecodeError, ValueError):
                        logger.warning(
                            f"Failed to parse column_values for {table_name}: {category}"
                        )

                elif category.startswith("column_stats:"):
                    # Format: "column_stats:TableName" → {"row_count": N, "columns": {"col": {...}}}
                    try:
                        cat_table = category[len("column_stats:") :]
                        if cat_table.upper() == table_name.upper():
                            stats_data = json.loads(content)
                            if isinstance(stats_data, dict):
                                # Extract row_count if present
                                if "row_count" in stats_data and result["row_count"] is None:
                                    result["row_count"] = stats_data["row_count"]
                                # Extract per-column stats
                                columns = stats_data.get("columns", {})
                                if isinstance(columns, dict):
                                    result["column_stats"].update(columns)
                    except (json.JSONDecodeError, ValueError):
                        logger.warning(
                            f"Failed to parse column_stats for {table_name}: {content[:100]}"
                        )

                elif category.startswith("table_stats:"):
                    # Format: "table_stats:TableName" → {"row_count": N, "columns": {...}}
                    try:
                        cat_table = category[len("table_stats:") :]
                        if cat_table.upper() == table_name.upper():
                            stats_data = json.loads(content)
                            if isinstance(stats_data, dict):
                                if "row_count" in stats_data and result["row_count"] is None:
                                    result["row_count"] = stats_data["row_count"]
                                columns = stats_data.get("columns", {})
                                if isinstance(columns, dict):
                                    result["column_stats"].update(columns)
                    except (json.JSONDecodeError, ValueError):
                        pass

                elif category.startswith("table_role:"):
                    # table_role:{table_name}
                    result["role"] = content

                elif category.startswith("cardinality:"):
                    # cardinality:{table_name}
                    try:
                        card_data = json.loads(content)
                        result["row_count"] = card_data.get("row_count")
                    except json.JSONDecodeError:
                        logger.warning(
                            f"Failed to parse cardinality JSON for {table_name}: {content[:100]}"
                        )

            except Exception as e:
                logger.warning(f"Error parsing doc category {category}: {e}")

        # Deduplicate FK lists (multiple storage formats can produce duplicates)
        def _dedup_fk(fk_list: list[dict]) -> list[dict]:
            seen: set[tuple] = set()
            deduped: list[dict] = []
            for fk in fk_list:
                # Handle both relation: format (table/column/fk_column)
                # and legacy fk: format (src_col/tgt_col)
                key = (
                    (fk.get("table") or fk.get("target") or "").upper(),
                    (fk.get("column") or fk.get("tgt_col") or "").upper(),
                    (fk.get("fk_column") or fk.get("src_col") or "").upper(),
                )
                if key not in seen:
                    seen.add(key)
                    deduped.append(fk)
            return deduped

        result["fk_outgoing"] = _dedup_fk(result["fk_outgoing"])
        result["fk_incoming"] = _dedup_fk(result["fk_incoming"])

        return result

    except Exception as e:
        logger.error(f"Error fetching table info for {table_name}: {e}")
        return result


async def get_column_values(table_name: str, column_name: str, store: TrainingStore) -> list:
    """
    Get max 15 anonymized non-null values for a specific column.

    Real storage format: category = "column_values:Table.Column", content = JSON list.
    Uses a direct SQL query by category (not semantic search) for reliability.

    Args:
        table_name: Table name
        column_name: Column name
        store: TrainingStore instance

    Returns:
        List of anonymized string values (max 15)
    """
    from app.core.database import get_session
    from app.models.training_data import TrainingData, TrainingDataType
    from sqlalchemy import select as sa_select

    try:
        # Direct SQL query — much more reliable than semantic search
        # category format: "column_values:TableName.ColumnName"
        # Try exact match first, then case-insensitive fallback via .ilike()
        target_category = f"column_values:{table_name}.{column_name}"

        async with get_session() as session:
            result = await session.execute(
                sa_select(TrainingData.content).where(
                    TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                    TrainingData.is_active == True,  # noqa: E712
                    TrainingData.category == target_category,
                )
            )
            row = result.scalar_one_or_none()

            # Fallback: case-insensitive search if exact match failed
            if row is None:
                result = await session.execute(
                    sa_select(TrainingData.content).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.ilike(target_category),
                    )
                )
                row = result.scalar_one_or_none()

        if row:
            try:
                values_list = json.loads(row)
            except json.JSONDecodeError:
                logger.warning(
                    "Failed to parse column_values for %s.%s",
                    table_name,
                    column_name,
                )
                return []
            if isinstance(values_list, list):
                return values_list[:15]

        logger.debug(
            "No column_values found for %s.%s — column may not have been synced",
            table_name,
            column_name,
        )
        return []

    except (json.JSONDecodeError, ValueError, TypeError) as e:
        logger.warning("Data error in get_column_values for %s.%s: %s", table_name, column_name, e)
        return []
    except Exception as e:
        logger.error("Error fetching column values for %s.%s: %s", table_name, column_name, e)
        return []


# ── Détection d'homonymes dans la source (A5) ──────────────────────
# Regex conservative sur les identifiants SQL : lettre ou underscore
# suivie d'au plus 127 chars alphanumériques/underscore. Rejette
# tout ce qui ressemble à une injection (espaces, quotes, etc.).
# Dupliquée ici pour ne pas importer depuis agent_tools (éviter un
# cycle d'imports).
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_@#$]{0,127}$")


# Cache LRU minuscule pour les lookups de type d'objet SQL (vue vs
# table). La valeur ne change pas durant une session — on évite un
# round-trip INFORMATION_SCHEMA par appel à ``get_resolved_values``.
# clef = table_name.upper(), valeur = "BASE TABLE" | "VIEW" | "" (absent).
_TABLE_TYPE_CACHE: dict[str, str] = {}
_TABLE_TYPE_CACHE_MAX = 512


# Cache LRU des COUNT homonymes pour cette session. Même (table, col,
# value) dans la même session → count identique : inutile de ré-interroger
# SQL Server à chaque tour. TTL implicite = durée de vie du process.
_HOMONYM_COUNT_CACHE: dict[tuple, int] = {}
_HOMONYM_COUNT_CACHE_MAX = 512


async def _fetch_table_type(table_name: str) -> Optional[str]:
    """Retourne ``'BASE TABLE'``, ``'VIEW'`` ou ``None`` (inconnu).

    Cache applicatif : évite un round-trip SQL Server à chaque appel.
    """
    if not _SAFE_IDENTIFIER_RE.match(table_name or ""):
        return None
    key = table_name.upper()
    if key in _TABLE_TYPE_CACHE:
        return _TABLE_TYPE_CACHE[key] or None
    try:
        from app.services.database.sage_connector import (
            get_sage_connector,
            get_current_sage_mode,
        )

        if get_current_sage_mode() == "sqlite":
            return None
        connector = get_sage_connector()
        import asyncio as _asyncio

        result = await _asyncio.wait_for(
            connector.execute(
                "SELECT TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES " "WHERE TABLE_NAME = ?",
                params=(table_name,),
                max_rows=1,
            ),
            timeout=3.0,
        )
        rows = result.to_dicts() if hasattr(result, "to_dicts") else []
        table_type = ""
        if rows:
            raw = rows[0].get("TABLE_TYPE") or rows[0].get("table_type") or ""
            table_type = str(raw).upper().strip()
        # Éviction basique : si plein, on vide (pas un vrai LRU mais OK
        # pour un cache de quelques centaines d'entrées stable).
        if len(_TABLE_TYPE_CACHE) >= _TABLE_TYPE_CACHE_MAX:
            _TABLE_TYPE_CACHE.clear()
        _TABLE_TYPE_CACHE[key] = table_type
        return table_type or None
    except Exception as _exc:
        logger.debug("table_type lookup failed for %s: %s", table_name, _exc)
        return None


async def _count_homonyms_in_source(
    value: str,
    table_name: str,
    column_name: str,
) -> Optional[dict]:
    """Compte les lignes de la source ayant cette valeur exacte.

    Utilisé pour détecter les homonymes : si une même valeur apparaît
    dans N > 1 lignes, elles peuvent représenter des entités
    différentes distinguées par une autre colonne. ValueMapping ne
    stocke qu'une entrée unique par valeur (table, colonne, valeur)
    et ne peut donc pas répondre à cette question.

    Important : le COUNT est fait sur l'objet tel qu'il est — si
    ``table_name`` est une VUE qui fait du ``GROUP BY``/``DISTINCT``
    en amont, le count retourné est le nombre de lignes AGRÉGÉES et
    n'équivaut pas au nombre d'occurrences réelles dans les tables
    sous-jacentes. On détecte ce cas et on l'annote dans la réponse
    pour que l'appelant ne conclue pas à tort "count=1 = pas
    d'homonyme".

    Fail-safe : retourne ``None`` si la requête échoue. L'appelant
    traite ``None`` comme "pas d'info supplémentaire" plutôt que
    d'empêcher la réponse principale.

    Args:
        value: Valeur exacte à compter (paramétrisée, pas interpolée).
        table_name: Nom de la table (validé contre injection).
        column_name: Nom de la colonne (validé contre injection).

    Returns:
        Dict avec ``{"count": N, "is_view": bool}`` ou ``None`` si
        indisponible. ``is_view=True`` = le count peut être agrégé.
    """
    # Validation stricte : seulement identifiants SQL légitimes. Si la
    # validation échoue, on ne tente pas la requête (fail-safe).
    if not _SAFE_IDENTIFIER_RE.match(table_name or ""):
        return None
    if not _SAFE_IDENTIFIER_RE.match(column_name or ""):
        return None
    if not value:
        return None

    # Cache hit : retour immédiat sans round-trip SQL.
    cache_key = (table_name.upper(), column_name.upper(), str(value))
    if cache_key in _HOMONYM_COUNT_CACHE:
        cached_count = _HOMONYM_COUNT_CACHE[cache_key]
        # On ré-attache is_view depuis le cache de types.
        cached_type = _TABLE_TYPE_CACHE.get(table_name.upper(), "")
        return {
            "count": cached_count,
            "is_view": cached_type == "VIEW",
        }

    # Détection vue/table — critique pour interpréter le COUNT.
    table_type = await _fetch_table_type(table_name)
    if table_type is None:
        # Objet inconnu ou mode sqlite : pas de count fiable.
        return None
    if table_type not in ("BASE TABLE", "VIEW"):
        # Synonym, external table, temporary, etc. : trop de risques.
        return None
    is_view = table_type == "VIEW"

    try:
        from app.services.database.sage_connector import get_sage_connector

        connector = get_sage_connector()
        # Value paramétrisée (pas d'interpolation) — seule la
        # structure SQL contient les identifiants déjà validés.
        sql = f"SELECT COUNT(*) AS row_count " f"FROM [{table_name}] WHERE [{column_name}] = ?"
        # Timeout court : c'est un enrichissement, pas un chemin
        # critique. Si la BDD traîne, on skip proprement.
        import asyncio as _asyncio

        result = await _asyncio.wait_for(
            connector.execute(sql, params=(value,), max_rows=1),
            timeout=4.0,
        )
        rows = result.to_dicts() if hasattr(result, "to_dicts") else []
        if not rows:
            return None
        count_val = rows[0].get("row_count")
        if not isinstance(count_val, (int, float)):
            return None
        count_int = int(count_val)
        # Mise en cache (éviction basique si plein).
        if len(_HOMONYM_COUNT_CACHE) >= _HOMONYM_COUNT_CACHE_MAX:
            _HOMONYM_COUNT_CACHE.clear()
        _HOMONYM_COUNT_CACHE[cache_key] = count_int
        return {"count": count_int, "is_view": is_view}
    except Exception as _exc:
        logger.debug(
            "homonym count failed for %s.%s=%s: %s",
            table_name,
            column_name,
            str(value)[:30],
            _exc,
        )
        return None


async def get_resolved_values(term: str, table_name: str, column_name: str) -> dict[str, Any]:
    """Resolve a partial term to exact real values in a specific column.

    Searches ValueMapping for all real values of table.column that CONTAIN
    the given term (case-insensitive). Returns anonymized values + count.

    This is critical for building accurate IN/NOT IN filters instead of
    imprecise LIKE patterns.

    Args:
        term: Partial term to search for (e.g. "EXAMPLE")
        table_name: Table name
        column_name: Column name

    Returns:
        Dict with matched_values (anonymized), total_found, and term used
    """
    from app.core.database import get_session
    from app.models.value_mapping import ValueMapping
    from sqlalchemy import select as sa_select, func

    term_clean = str(term).strip()
    if not term_clean:
        return {"matched_values": [], "total_found": 0, "term": term}

    try:
        async with get_session() as session:
            # Search for values CONTAINING the term (case-insensitive). On ne
            # remonte QUE la vraie valeur (real_value pour préserver la casse,
            # real_value_lower pour le compare exact). L'anonymisation runtime
            # est gérée séparément par le Pseudonymizer (anonymization_terms).
            result = await session.execute(
                sa_select(
                    ValueMapping.real_value,
                    ValueMapping.real_value_lower,
                )
                .where(
                    ValueMapping.real_value_lower.contains(term_clean.lower()),
                    func.upper(ValueMapping.table_name) == table_name.upper(),
                    func.upper(ValueMapping.column_name) == column_name.upper(),
                )
                .order_by(ValueMapping.real_value_lower)
                .limit(50)
            )
            rows = result.all()

        matched = []
        for row in rows:
            is_exact = row.real_value_lower == term_clean.lower()
            # Doctrine 2026-05-22 : ``/data-privacy`` est SEULE source des
            # pseudos runtime. Cet outil retourne les VRAIES valeurs Sage —
            # le LLM les voit en clair sauf si l'utilisateur a configuré un
            # mapping dans ``anonymization_terms`` (auquel cas
            # ``ConfidentialityManager.sanitize_user_input`` tokenise les
            # noms propres en amont du prompt user, et le SQL final passe
            # par ``substitute_sql_placeholders`` pour reconvertir vers les
            # vraies valeurs). Aucune obfuscation auto à la frontière de cet
            # outil — c'est le trade-off explicitement validé par David :
            # « si tu veux qu'un terme soit anonymisé, configure-le ».
            entry: dict[str, Any] = {
                "use_in_sql": term_clean if is_exact else row.real_value,
                "match": "exact" if is_exact else "contains",
            }
            matched.append(entry)

        # Build clear instructions for the LLM
        exact_matches = [m for m in matched if m["match"] == "exact"]
        contains_matches = [m for m in matched if m["match"] == "contains"]

        hint_parts = []
        if exact_matches:
            exact_values = [m["use_in_sql"] for m in exact_matches]
            hint_parts.append(
                f"MATCH EXACT trouvé : la valeur '{exact_values[0]}' EXISTE dans "
                f"{table_name}.{column_name}. Utilise '{exact_values[0]}' directement "
                f"dans ta clause WHERE."
            )
        if contains_matches:
            hint_parts.append(
                f"{len(contains_matches)} valeur(s) CONTENANT '{term_clean}' trouvée(s). "
                f"Les vraies valeurs sont retournées dans ``use_in_sql``. Pour un filtre "
                f"NOT IN, chaque ``use_in_sql`` représente une vraie valeur à exclure."
            )
        if not matched:
            hint_parts.append(
                f"Aucune valeur contenant '{term_clean}' trouvée dans "
                f"{table_name}.{column_name}."
            )

        response = {
            "matched_values": matched,
            "total_found": len(matched),
            "exact_count": len(exact_matches),
            "contains_count": len(contains_matches),
            "term": term_clean,
            "table": table_name,
            "column": column_name,
            "hint": " ".join(hint_parts),
        }

        # ── Détection d'homonymes (A5) ────────────────────────────────
        # ValueMapping stocke une unique ligne par (table, colonne, valeur),
        # donc un match "exact" ne dit PAS combien de lignes réelles ont
        # cette valeur dans la source. Cas classique : une même valeur
        # existe sous plusieurs contextes (même nom sous plusieurs
        # identifiants d'entité). Sans cette info, le LLM écrit un filtre
        # WHERE col='X' et croit cibler une entité unique, alors qu'il
        # en récupère plusieurs en réalité.
        #
        # Générique : on compte simplement COUNT(*) pour ce couple
        # (table, colonne, valeur). Aucune logique métier ni nom de
        # colonne contextuelle hardcodée. Si > 1, on alerte le LLM et
        # on lui suggère d'explorer lui-même la colonne discriminante.
        #
        # Piège évité : si ``table_name`` est une VUE qui agrège
        # (GROUP BY / DISTINCT), le COUNT renvoie un nombre trompeur.
        # On annote avec ``is_view`` pour que le LLM en tienne compte.
        if exact_matches:
            # Dédupe les exact_matches par la vraie valeur utilisée
            # dans le SQL : plusieurs lignes de ValueMapping peuvent
            # pointer vers la même valeur réelle (collation ambiguë,
            # re-anonymisation historique). Sans dédup, on ferait N
            # COUNT redondants sur la même valeur.
            _seen_values: set[str] = set()
            _unique_exact = []
            for m in exact_matches:
                v = m.get("use_in_sql") or ""
                if v and v not in _seen_values:
                    _seen_values.add(v)
                    _unique_exact.append(m)
            source_counts: dict[str, dict] = {}
            for match in _unique_exact:
                real_val = match.get("use_in_sql") or ""
                if not real_val:
                    continue
                info = await _count_homonyms_in_source(
                    real_val,
                    table_name,
                    column_name,
                )
                if info is not None:
                    source_counts[real_val] = info
            if source_counts:
                response["source_row_counts"] = source_counts
                homonym_warnings: list[str] = []
                inconsistency_warnings: list[str] = []
                view_caveats: list[str] = []
                for val, info in source_counts.items():
                    c = info.get("count", 0)
                    iv = info.get("is_view", False)
                    if iv:
                        # Caveat spécifique : la vue peut agréger.
                        view_caveats.append(val)
                    if c > 1:
                        homonym_warnings.append(f"'{val}' → {c} lignes")
                    elif c == 0:
                        # Incohérence ValueMapping ↔ source (sync
                        # obsolète, soft-delete, vue filtrée) —
                        # signaler pour que le LLM ne base pas son
                        # filtre sur une valeur absente.
                        inconsistency_warnings.append(val)
                if homonym_warnings or inconsistency_warnings or view_caveats:
                    hint_extras = []
                    if homonym_warnings:
                        response["homonym_warning"] = True
                        hint_extras.append(
                            "⚠️ HOMONYMES POTENTIELS dans "
                            f"{table_name} : "
                            + ", ".join(homonym_warnings)
                            + ". Ces lignes peuvent représenter des "
                            "entités différentes distinguées par "
                            "une autre colonne (contexte, "
                            "regroupement, entité parente). Avant "
                            f"d'écrire un filtre sur {column_name}, "
                            "utilise les outils d'introspection et "
                            "de peek disponibles pour identifier la "
                            "colonne discriminante ; si l'utilisateur "
                            "n'a pas précisé le contexte, demande-lui."
                        )
                    if inconsistency_warnings:
                        response["mapping_inconsistency_warning"] = True
                        hint_extras.append(
                            "⚠️ INCOHÉRENCE mapping/source : valeur(s) "
                            "présente(s) dans le mapping mais 0 ligne "
                            f"trouvée dans {table_name} : "
                            + ", ".join(f"'{v}'" for v in inconsistency_warnings)
                            + ". Le schéma a peut-être bougé — vérifie "
                            "avec un peek avant d'écrire un filtre "
                            "qui ne retournera rien."
                        )
                    if view_caveats:
                        response["view_count_caveat"] = True
                        hint_extras.append(
                            f"ℹ️ {table_name} est une VUE : le COUNT "
                            "ci-dessus reflète les lignes agrégées de la "
                            "vue, pas forcément les occurrences dans les "
                            "tables sous-jacentes. Un COUNT=1 sur une "
                            "vue groupée ne garantit pas l'unicité."
                        )
                    response["hint"] = response["hint"] + " " + " ".join(hint_extras)
        return response

    except Exception as e:
        logger.error("get_resolved_values(%s, %s.%s) failed: %s", term, table_name, column_name, e)
        return {"matched_values": [], "total_found": 0, "term": term_clean, "error": str(e)}


def find_fk_path(
    from_table: str, to_table: str, fk_graph: dict[str, list[dict]]
) -> Optional[list[dict]]:
    """
    BFS to find shortest path from from_table to to_table via FK relationships.

    FK graph format: {table_upper: [{target, src_col, tgt_col, nullable, direction}]}

    Args:
        from_table: Source table name
        to_table: Target table name
        fk_graph: Foreign key graph dictionary

    Returns:
        List of dicts representing the path, or None if no path found.
        Each dict has: {source, target, src_col, tgt_col, nullable}
    """
    from_upper = from_table.upper()
    to_upper = to_table.upper()

    if from_upper == to_upper:
        return []

    visited = set()
    queue = deque([(from_upper, [])])
    visited.add(from_upper)

    while queue:
        current_table, path = queue.popleft()

        # Follow ALL edges from current node (both outgoing and incoming).
        # build_fk_graph already stores edges bidirectionally, so every
        # reachable neighbor is in graph[current_table].
        for fk in fk_graph.get(current_table, []):
            neighbor = fk.get("target", "").upper()
            if not neighbor or neighbor in visited:
                continue

            new_edge = {
                "source": current_table,
                "target": neighbor,
                "src_col": fk.get("src_col"),
                "tgt_col": fk.get("tgt_col"),
                "nullable": fk.get("nullable", True),
                "null_pct": fk.get("null_pct"),  # Exact value if resolved
            }
            new_path = path + [new_edge]

            if neighbor == to_upper:
                return new_path

            visited.add(neighbor)
            queue.append((neighbor, new_path))

    return None


_AGG_START_RE = re.compile(r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\(", re.IGNORECASE)


def _alias_first_bare_aggregate(sql: str) -> str:
    """Add ``AS _agg`` to the first aggregate expression that has no alias.

    Handles nested parentheses correctly — e.g. ``SUM(ISNULL(x, 0))`` is
    left intact if it already has an ``AS`` alias, and correctly aliased
    if it doesn't.  The previous regex-only approach matched the *first*
    closing paren, corrupting expressions like ``SUM(ISNULL(x,0))`` into
    ``SUM(ISNULL(x,0) AS _agg)`` (invalid SQL).
    """
    match = _AGG_START_RE.search(sql)
    if not match:
        return sql

    # Walk from the opening '(' to find the matching ')'.
    open_pos = match.end() - 1  # index of '('
    depth = 0
    pos = open_pos
    while pos < len(sql):
        ch = sql[pos]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_pos = pos + 1  # first char after ')'
                # Check whether an AS alias already follows.
                rest = sql[close_pos:].lstrip()
                if re.match(r"(?i)AS\s+\w", rest):
                    return sql  # already aliased — nothing to do
                return sql[:close_pos] + " AS _agg" + sql[close_pos:]
        pos += 1

    return sql  # unbalanced parens — return unchanged


from app.utils.sql_scan import skip_sql_string, strip_leading_sql_comments

# Keep module-level alias for existing imports in tests
_strip_leading_sql_comments = strip_leading_sql_comments


async def execute_count(sql: str, connector, user: Any = None) -> int | str | dict:
    """
    Execute a COUNT(*) query on the given SQL.

    Wraps sql in: SELECT COUNT(*) FROM ({sql}) AS _count_sub

    Args:
        sql: SQL query to count
        connector: SageConnector instance
        user: utilisateur authentifié pour application RLS. Cas :
            - User réel → enforcement (check + apply row filters)
            - ``enforcer.SYSTEM_USER`` → bypass explicite
            - ``None`` → bypass legacy (logué WARNING si enforcement ON)

    Returns:
        Count as int, -1 on error, or str message if trivial query rejected.
        Returns dict ``{"count": -1, "error": ..., "blocked_by": "data_access_rule"}``
        if RLS denies the query.
    """
    try:
        # ── Application RLS centralisée (avant les guards trivials) ──
        # On applique d'abord le guard (rejet si write keyword) plus loin,
        # mais on peut faire le check RLS en amont pour éviter d'attaquer
        # la BDD si la table est interdite.
        try:
            from app.services.data_access import enforcer as _da_enforcer

            sql = await _da_enforcer.enforce_for_executor(sql, user, source="execute_count")
        except _da_enforcer.DataAccessDeniedError as exc:
            return {
                "count": -1,
                "error": exc.user_message,
                "blocked_by": "data_access_rule",
                "sql_tested": (sql or "")[:200],
            }
    except Exception:
        # Si l'enforcer crashe (corner case), on continue avec la SQL
        # d'origine — les guards ci-dessous (write keywords, etc.)
        # restent en place. Logué en warning.
        logger.warning(
            "execute_count: enforcer failed (continuing without RLS)",
            exc_info=True,
        )

    try:
        sql_stripped = sql.strip()
        # Strip leading comments (e.g. "-- Étape 1\nSELECT ...") for checks
        sql_body = _strip_leading_sql_comments(sql_stripped)
        sql_upper = sql_body.upper()

        # Trivial COUNT rejection : RETIRÉ 2026-05-26 (doctrine "100% justifié").
        # Le rejet "REJETÉ: Le row_count est déjà disponible via get_table_info" était
        # une OPINION système ("tu n'as pas besoin de ce COUNT") non vérifiable à 100% :
        # - Iris peut vouloir vérifier la fraîcheur après une modif externe
        # - Iris peut vouloir comparer avec un cache get_table_info périmé
        # - Iris peut vouloir valider que la BDD répond avant une analyse coûteuse
        # → Iris décide. Le système exécute le COUNT comme tout autre query.

        # Safety: only allow SELECT/WITH statements (block DDL/DML injection)
        if not sql_upper.startswith(("SELECT", "WITH")):
            logger.warning("execute_count: rejected non-SELECT SQL: %s", sql_stripped[:50])
            return {
                "count": -1,
                "error": "SQL doit commencer par SELECT ou WITH",
                "sql_tested": sql_stripped[:200],
            }
        # Block dangerous keywords that should never appear in a read-only COUNT
        _BLOCKED = re.compile(
            r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|EXEC|EXECUTE|MERGE)\b",
            re.IGNORECASE,
        )
        if _BLOCKED.search(sql_body):
            logger.warning("execute_count: rejected SQL with write keyword: %s", sql_stripped[:80])
            return {
                "count": -1,
                "error": "SQL contient un mot-clé interdit (INSERT, DELETE, DROP, etc.)",
                "sql_tested": sql_stripped[:200],
            }

        # SQL Server subquery rules:
        # 1. Every column in a subquery must have an alias
        # 2. ORDER BY is forbidden in subqueries unless TOP/OFFSET is present
        # Strip ONLY the trailing ORDER BY at depth 0 (pas ceux dans OVER())
        inner_sql = sql_body
        if not re.search(r"\bTOP\b|\bOFFSET\b", inner_sql, re.IGNORECASE):
            # Trouver le dernier ORDER BY au depth 0 (pas dans des parenthèses)
            depth = 0
            last_order_by_pos = -1
            sql_upper_scan = inner_sql.upper()
            i = 0
            while i < len(inner_sql):
                if inner_sql[i] == "'":
                    i = skip_sql_string(inner_sql, i) + 1  # +1: past closing quote
                elif inner_sql[i] == "(":
                    depth += 1
                    i += 1
                elif inner_sql[i] == ")":
                    depth -= 1
                    i += 1
                elif depth == 0 and sql_upper_scan[i : i + 8] == "ORDER BY":
                    last_order_by_pos = i
                    i += 1
                else:
                    i += 1
            if last_order_by_pos > 0:
                inner_sql = inner_sql[:last_order_by_pos].rstrip()

        # SQL Server subquery rules: every column must have an alias.
        # Fix 1: alias bare aggregates (COUNT(*), SUM(x), etc.) without AS.
        # Uses parenthesis-matching (not regex) to handle nested calls
        # like SUM(ISNULL(x, 0)) correctly.
        inner_sql = _alias_first_bare_aggregate(inner_sql)

        # Fix 2: alias bare literals in SELECT (e.g. "SELECT 1 FROM" → "SELECT 1 AS _v FROM")
        # This handles patterns like "SELECT 1 FROM table" or "SELECT 'x' FROM table"
        # that SQL Server rejects in subqueries because the column has no name.
        inner_sql = re.sub(
            r"(?i)^(SELECT\s+(?:DISTINCT\s+)?)((?:\d+|'[^']*'))\s+(FROM\b)",
            r"\1\2 AS _v \3",
            inner_sql,
        )

        # CTE (WITH ... AS) ne peut PAS être dans une sous-requête en T-SQL.
        # Stratégie : transformer en WITH ..., _q AS (SELECT final) SELECT COUNT(*) FROM _q
        if inner_sql.upper().lstrip().startswith("WITH"):
            # Trouver le SELECT final (celui hors du CTE) par comptage de parenthèses
            depth = 0
            final_select_pos = -1
            i = 0
            while i < len(inner_sql):
                c = inner_sql[i]
                if c == "'":
                    i = skip_sql_string(inner_sql, i) + 1  # +1: past closing quote
                elif c == "(":
                    depth += 1
                    i += 1
                elif c == ")":
                    depth -= 1
                    i += 1
                elif depth == 0 and inner_sql[i : i + 6].upper() == "SELECT":
                    # SELECT au niveau 0 = le SELECT final (pas dans le CTE)
                    # Ignorer le premier si c'est dans WITH X AS (SELECT ...)
                    if i > 0:  # Pas le tout début
                        final_select_pos = i
                    i += 1
                else:
                    i += 1

            if final_select_pos > 0:
                cte_part = inner_sql[:final_select_pos].rstrip()
                select_part = inner_sql[final_select_pos:]
                # Ajouter une CTE wrapper : WITH ..., _q AS (SELECT ...) SELECT COUNT(*) FROM _q
                wrapped = f"{cte_part}, _q AS ({select_part}) SELECT COUNT(*) FROM _q"
            else:
                # Fallback : essayer quand même
                wrapped = f"SELECT COUNT(*) FROM ({inner_sql}) AS _count_sub"
        else:
            wrapped = f"SELECT COUNT(*) FROM ({inner_sql}) AS _count_sub"
        try:
            count = await connector.execute_scalar(wrapped)
            return int(count) if count is not None else 0
        except Exception as inner_exc:
            # Return a rich error dict so the LLM knows the EXACT SQL Server error
            error_msg = str(inner_exc)
            logger.error("Error executing COUNT query: %s", error_msg)
            return {
                "count": -1,
                "error": error_msg,
                "sql_tested": wrapped,
            }
    except Exception as e:
        logger.error("Error in execute_count setup: %s", e, exc_info=True)
        return {
            "count": -1,
            "error": f"Erreur interne execute_count (setup): {e}",
            "sql_tested": sql[:200] if sql else "",
        }


def check_count_delta(before: int, after: int) -> Optional[dict]:
    """
    Analyze COUNT delta for anomalies.

    Returns None if normal (1x to 3x range, no loss).
    Otherwise returns dict with type and details.

    Args:
        before: Count before JOIN
        after: Count after JOIN

    Returns:
        None if normal, or dict with keys: type, ratio, before, after, message
    """
    if before == 0 or after == 0:
        if before == 0 and after > 0:
            return None  # Normal: expanded from no rows
        if after == 0:
            return {
                "type": "zero",
                "ratio": 0,
                "before": before,
                "after": after,
                "message": "JOIN resulted in 0 rows — likely INNER JOIN with no matching rows",
            }
        return None

    ratio = after / before

    # Cartesian product: ×5+ rows
    if ratio >= 5:
        return {
            "type": "cartesian",
            "ratio": ratio,
            "before": before,
            "after": after,
            "message": f"Possible cartesian product: {before} → {after} (ratio {ratio:.1f}x)",
        }

    # Loss from INNER JOIN: -50%+ rows
    if ratio <= 0.5:
        return {
            "type": "loss",
            "ratio": ratio,
            "before": before,
            "after": after,
            "message": f"Data loss detected: {before} → {after} (ratio {ratio:.1f}x) — check JOIN conditions",
        }

    # Normal range: 1x to 3x
    return None


def _extract_real_table_name(doc: dict, fallback: str) -> str:
    """Extract the real SQL table name from a training store document.

    The training store indexes docs with categories like:
      - relation:DossierSuppl→Collaborateurs
      - column_values:Factures.facDate
      - table_stats:Factures
      - column_stats:Factures
      - ddl:Factures
      - table_role:Factures
      - cardinality:Factures

    Instead of returning the search keyword as table_name (which gives
    phantom names like "expert comptable"), we extract the real table name(s)
    from the category or content.

    Returns:
        The real table name, or fallback if extraction fails.
    """
    category = doc.get("category", "") or ""
    if not category.strip():
        # No category — try content-based extraction, then fallback
        content = doc.get("content", "") or ""
        if content:
            m = re.match(
                r"CREATE\s+(?:TABLE|VIEW)\s+(?:\[?\w+\]?\.)?\[?(\w+)\]?",
                content,
                re.IGNORECASE,
            )
            if m:
                return m.group(1)
        return fallback

    # relation:TableA→TableB — return both tables
    if category.startswith("relation:"):
        suffix = category[len("relation:") :]
        for sep in ("→", "←", "->", "<-"):
            if sep in suffix:
                parts = [p.strip() for p in suffix.split(sep) if p.strip()]
                if parts:
                    return parts[0]  # First table in the relation

    # column_values:Table.Column — extract Table
    if category.startswith("column_values:") and "." in category:
        suffix = category[len("column_values:") :]
        table_part = suffix.rsplit(".", 1)[0]
        if table_part:
            return table_part

    # Patterns: prefix:TableName (table_stats, column_stats, ddl, table_role, cardinality)
    for prefix in ("table_stats:", "column_stats:", "ddl:", "table_role:", "cardinality:"):
        if category.startswith(prefix):
            name = category[len(prefix) :].strip()
            if name:
                return name

    # Try to extract from DDL content: CREATE TABLE [TableName] or CREATE VIEW [dbo].[ViewName]
    content = doc.get("content", "")
    if content:
        m = re.match(
            r"CREATE\s+(?:TABLE|VIEW)\s+(?:\[?\w+\]?\.)?\[?(\w+)\]?",
            content,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)

    # Try to extract table name from FK content patterns
    if content:
        m_fk = _FK_SORTANTE_RE.search(content)
        if m_fk:
            return m_fk.group(1)  # child_table
        m_fk = _FK_ENTRANTE_RE.search(content)
        if m_fk:
            return m_fk.group(1)  # child_table

    return fallback


async def search_all_keywords(keywords: dict, store: TrainingStore) -> list[dict]:
    """
    Search keywords across DDL and documentation.

    Args:
        keywords: dict with "tables" and "colonnes" lists
        store: TrainingStore instance

    Returns:
        List of dicts: {type, table_name, content, score}
        Sorted by score descending, deduplicated by content.
        table_name is the REAL SQL table name extracted from docs, not the search keyword.
    """
    results = []
    seen_content = set()

    try:
        tables = keywords.get("tables", [])
        columns = keywords.get("colonnes", [])

        # Search for each table (capped at n_results to prevent memory bloat)
        for table in tables:
            try:
                # Phase α.4.D : orchestrator désactivé. user=None legacy.
                ddl_results = await store.get_related_ddl(table, n_results=5, user=None)
                for res in ddl_results:
                    content_key = res.get("content", "")[:50]
                    if content_key not in seen_content:
                        seen_content.add(content_key)
                        real_name = _extract_real_table_name(res, table)
                        results.append(
                            {
                                "type": "ddl",
                                "table_name": real_name,
                                "content": res.get("content"),
                                "score": res.get("score", 0),
                            }
                        )

                doc_results = await store.get_related_documentation(table, n_results=5)
                for res in doc_results:
                    content_key = res.get("content", "")[:50]
                    if content_key not in seen_content:
                        seen_content.add(content_key)
                        real_name = _extract_real_table_name(res, table)
                        results.append(
                            {
                                "type": "doc",
                                "table_name": real_name,
                                "content": res.get("content"),
                                "score": res.get("score", 0),
                            }
                        )
            except Exception as e:
                logger.warning(f"Error searching table keyword '{table}': {e}")

        # Search for each column (capped at n_results to prevent memory bloat)
        for column in columns:
            try:
                doc_results = await store.get_related_documentation(column, n_results=5)
                for res in doc_results:
                    content_key = res.get("content", "")[:50]
                    if content_key not in seen_content:
                        seen_content.add(content_key)
                        real_name = _extract_real_table_name(res, column)
                        results.append(
                            {
                                "type": "doc",
                                "table_name": real_name,
                                "content": res.get("content"),
                                "score": res.get("score", 0),
                            }
                        )
            except Exception as e:
                logger.warning(f"Error searching column keyword '{column}': {e}")

        # Sort by score descending and cap at 50 results (memory efficiency)
        results.sort(key=lambda x: x.get("score", 0), reverse=True)
        return results[:50]

    except Exception as e:
        logger.error(f"Error searching keywords: {e}")
        return []


async def build_fk_graph(store: TrainingStore) -> dict[str, list[dict]]:
    """
    Build bidirectional FK graph from stored documentation.

    Parses the real TrainingStore format:
    - Category: "relation:ParentTable→ChildTable" or "relation:ParentTable←ChildTable"
    - Content: "FK sortante: ChildTable(childCol → parentCol) REFERENCES ParentTable. Constraint: ..."
    - Content: "FK entrante: ChildTable(childCol → parentCol) → ParentTable. Constraint: ..."

    Returns:
        dict: {TABLE_UPPER: [{target, src_col, tgt_col, nullable, direction}]}
    """
    graph: dict[str, list[dict]] = {}

    try:
        # Fetch relation docs (the real category prefix)
        all_docs = await store.get_related_documentation("relation:", n_results=2000)

        parsed = 0
        for doc in all_docs:
            if not isinstance(doc, dict):
                continue
            category = doc.get("category", "")
            content = doc.get("content", "")

            if not category.startswith("relation:"):
                continue

            # Try sortante format
            m = _FK_SORTANTE_RE.search(content)
            if m:
                child_table, child_col, parent_col, parent_table = m.groups()
                child_upper = child_table.upper()
                parent_upper = parent_table.upper()

                # child_table has a FK column pointing to parent_table
                # Outgoing from child → parent
                graph.setdefault(child_upper, []).append(
                    {
                        "target": parent_upper,
                        "src_col": child_col,
                        "tgt_col": parent_col,
                        "nullable": True,  # Conservative default
                        "direction": "outgoing",
                    }
                )
                # Reverse: parent sees incoming from child
                graph.setdefault(parent_upper, []).append(
                    {
                        "target": child_upper,
                        "src_col": parent_col,
                        "tgt_col": child_col,
                        "nullable": True,
                        "direction": "incoming",
                    }
                )
                parsed += 1
                continue

            # Try entrante format
            m = _FK_ENTRANTE_RE.search(content)
            if m:
                child_table, child_col, parent_col, parent_table = m.groups()
                child_upper = child_table.upper()
                parent_upper = parent_table.upper()

                # Same FK, just stored from parent's perspective
                graph.setdefault(child_upper, []).append(
                    {
                        "target": parent_upper,
                        "src_col": child_col,
                        "tgt_col": parent_col,
                        "nullable": True,
                        "direction": "outgoing",
                    }
                )
                graph.setdefault(parent_upper, []).append(
                    {
                        "target": child_upper,
                        "src_col": parent_col,
                        "tgt_col": child_col,
                        "nullable": True,
                        "direction": "incoming",
                    }
                )
                parsed += 1
                continue

            # Try inferred format (detected at sync via naming convention + containment)
            m = _FK_INFERRED_RE.search(content)
            if m:
                src_table, src_col, tgt_table, tgt_col = m.groups()
                src_upper = src_table.upper()
                tgt_upper = tgt_table.upper()

                graph.setdefault(src_upper, []).append(
                    {
                        "target": tgt_upper,
                        "src_col": src_col,
                        "tgt_col": tgt_col,
                        "nullable": True,
                        "direction": "outgoing",
                    }
                )
                graph.setdefault(tgt_upper, []).append(
                    {
                        "target": src_upper,
                        "src_col": tgt_col,
                        "tgt_col": src_col,
                        "nullable": True,
                        "direction": "incoming",
                    }
                )
                parsed += 1

        logger.info("FK graph: %d tables, %d relations parsed", len(graph), parsed)

        # Second pass: resolve actual nullability from column_stats
        # Load ALL column_stats in ONE query instead of N individual RAG lookups
        import json as _json
        from app.core.database import get_session
        from app.models.training_data import TrainingData, TrainingDataType

        all_column_stats: dict[str, dict] = {}  # TABLE_UPPER → {"col": {"null_pct": ...}}
        try:
            async with get_session() as session:
                from sqlalchemy import select as sa_select

                result = await session.execute(
                    sa_select(TrainingData.category, TrainingData.content).where(
                        TrainingData.data_type == TrainingDataType.DOCUMENTATION,
                        TrainingData.is_active == True,  # noqa: E712
                        TrainingData.category.like("column_stats:%"),
                    )
                )
                for cat, content in result.all():
                    table_name = cat[len("column_stats:") :]
                    try:
                        data = _json.loads(content or "{}")
                        columns = data.get("columns", {})
                        if columns:
                            all_column_stats[table_name.upper()] = columns
                    except (_json.JSONDecodeError, TypeError):
                        pass
            logger.debug(
                "FK graph: loaded column_stats for %d tables in batch", len(all_column_stats)
            )
        except Exception as e:
            logger.warning("FK graph: batch column_stats load failed: %s", e)

        stats_resolved = 0
        for table_upper, edges in graph.items():
            table_stats = all_column_stats.get(table_upper, {})
            if not table_stats:
                continue
            for edge in edges:
                if edge["direction"] != "outgoing":
                    continue
                src_col = edge["src_col"]
                # Try exact match, then case-insensitive
                col_data = table_stats.get(src_col)
                if col_data is None:
                    src_col_lower = src_col.lower()
                    for k, v in table_stats.items():
                        if k.lower() == src_col_lower:
                            col_data = v
                            break
                if col_data and isinstance(col_data, dict):
                    null_pct = col_data.get("null_pct", col_data.get("null_percent"))
                    if null_pct is not None:
                        try:
                            edge["nullable"] = float(null_pct) > 0
                            edge["null_pct"] = float(null_pct)  # Keep exact value
                            stats_resolved += 1
                        except (ValueError, TypeError):
                            pass

        if stats_resolved:
            logger.info(
                "FK graph: resolved nullability for %d edges via column_stats", stats_resolved
            )

        return graph

    except Exception as e:
        logger.error("Error building FK graph: %s", e)
        return {}


# ────────────────────────────────────────────────────────────────────
# Phase 2 — LLM tool schemas (Anthropic format) + dispatcher
# ────────────────────────────────────────────────────────────────────

PHASE2_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "search_schema",
        "description": (
            "Recherche dans la documentation de la base de données (DDL, relations FK, "
            "statistiques colonnes, valeurs anonymisées) par mots-clés. "
            "Retourne les résultats les plus pertinents triés par score. "
            "Utilise cette recherche comme un moteur de recherche : essaie plusieurs "
            "formulations si les premiers résultats ne sont pas concluants."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Liste de mots-clés à chercher (noms de tables, colonnes, "
                        "concepts métier). Essaie des variantes : pluriel, abréviations, "
                        "camelCase, snake_case."
                    ),
                },
            },
            "required": ["keywords"],
        },
    },
    {
        "name": "get_table_info",
        "description": (
            "Obtient les métadonnées complètes d'une table : DDL (CREATE TABLE), "
            "clés étrangères sortantes et entrantes, statistiques par colonne "
            "(distinct_count, null_pct, min/max), valeurs anonymisées, rôle sémantique, "
            "nombre de lignes. Utilise cet outil pour inspecter une table prometteuse."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Nom exact de la table à inspecter.",
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "get_column_values",
        "description": (
            "Obtient jusqu'à 15 valeurs anonymisées non-null d'une colonne spécifique. "
            "Utile pour vérifier que le contenu correspond au concept recherché "
            "(ex: vérifier qu'une colonne 'code' contient bien des codes statistiques "
            "et pas des codes postaux)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Nom de la table.",
                },
                "column_name": {
                    "type": "string",
                    "description": "Nom de la colonne.",
                },
            },
            "required": ["table_name", "column_name"],
        },
    },
    {
        "name": "get_fk_neighbors",
        "description": (
            "Obtient la liste des tables liées par clé étrangère (FK) à une ou "
            "plusieurs tables données. Utile pour explorer les relations : si le concept "
            "n'est pas dans la table trouvée par RAG, il est peut-être dans une table "
            "liée par FK."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Liste de noms de tables dont on veut les voisins FK.",
                },
            },
            "required": ["table_names"],
        },
    },
    {
        "name": "confirm_location",
        "description": (
            "Déclare que tu as trouvé l'emplacement exact du concept dans la base. "
            "Appelle cet outil UNIQUEMENT quand tu es SÛR de la localisation, "
            "après avoir vérifié le type de colonne, les valeurs, et les relations FK. "
            "Cet appel termine la boucle de recherche pour ce concept."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table": {
                    "type": "string",
                    "description": "Nom de la table contenant le concept.",
                },
                "column": {
                    "type": "string",
                    "description": "Nom de la colonne (vide si concept = table entière).",
                },
                "retrieval": {
                    "type": "string",
                    "enum": ["direct", "via_fk", "calculated", "aggregation"],
                    "description": (
                        "Comment accéder à la donnée : "
                        "'direct' = colonne accessible directement, "
                        "'via_fk' = accessible via une jointure FK, "
                        "'calculated' = valeur calculée (formule dans calculation), "
                        "'aggregation' = nécessite SUM/COUNT/AVG etc."
                    ),
                },
                "notes": {
                    "type": "string",
                    "description": (
                        "Explication du raisonnement : pourquoi cette table/colonne, "
                        "quelles vérifications faites, FK utilisées."
                    ),
                },
                "is_calculated": {
                    "type": "boolean",
                    "description": "True si le concept est calculé (pas stocké directement).",
                },
                "calculation": {
                    "type": "string",
                    "description": "Expression SQL si calculé (ex: 'SUM(montant)'), sinon vide.",
                },
                "join_path": {
                    "type": "string",
                    "description": (
                        "Chemin de jointure si via_fk (ex: 'TableA.colFK → TableB.colPK'), "
                        "sinon vide."
                    ),
                },
            },
            "required": ["table", "column", "retrieval", "notes"],
        },
    },
    {
        "name": "mark_not_found",
        "description": (
            "Déclare que le concept est introuvable dans la base de données après "
            "exploration. Utilise cet outil quand tu as épuisé les pistes de recherche. "
            "Cet appel termine la boucle de recherche pour ce concept."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Explication de pourquoi le concept n'a pas été trouvé.",
                },
                "is_calculated": {
                    "type": "boolean",
                    "description": (
                        "True si le concept n'est pas stocké mais peut être calculé "
                        "à partir d'autres données."
                    ),
                },
                "calculation": {
                    "type": "string",
                    "description": "Formule de calcul si is_calculated=true, sinon vide.",
                },
                "needs_clarification": {
                    "type": "boolean",
                    "description": "True si une clarification de l'utilisateur aiderait.",
                },
                "suggested_question": {
                    "type": "string",
                    "description": "Question suggérée pour l'utilisateur si needs_clarification.",
                },
            },
            "required": ["reason"],
        },
    },
]


# Phase 2 — Exploration tool schemas (NO search_schema — search is done by the system)
PHASE2_EXPLORE_TOOL_SCHEMAS: list[dict[str, Any]] = [
    schema for schema in PHASE2_TOOL_SCHEMAS if schema["name"] != "search_schema"
]


async def aggregate_rag_results(
    table_keywords: list[str],
    column_keywords: list[str],
    store: TrainingStore,
) -> list[dict[str, Any]]:
    """
    System-side RAG aggregation: search ALL keywords, aggregate scores, rank candidates.

    Unlike search_schema (called by the LLM one keyword at a time), this function:
    1. Searches ALL keywords in parallel (tables + columns)
    2. Aggregates results: a table found by N different keywords gets a composite score
    3. Returns a ranked shortlist of candidates with rich metadata

    Args:
        table_keywords: Sorted list of potential table names (most probable first)
        column_keywords: Sorted list of potential column names (most probable first)
        store: TrainingStore instance

    Returns:
        List of dicts sorted by composite_score descending:
        {
            "table_name": str,
            "composite_score": float,
            "keyword_hits": int,  # how many keywords found this table
            "keywords_matched": list[str],  # which keywords matched
            "best_excerpt": str,  # best matching content excerpt
            "source_type": str,  # "ddl" or "doc"
        }
    """
    # Aggregate: table_name -> {scores, keywords, best_excerpt, source_type}
    table_scores: dict[str, dict] = {}

    # Search ALL keywords in parallel (asyncio.gather) for O(1) latency instead of O(N)
    all_keywords = table_keywords + column_keywords

    async def _search_one(keyword: str) -> tuple[str, list[dict]]:
        """Search a single keyword, return (keyword, results)."""
        try:
            kw_dict = {"tables": [keyword], "colonnes": [keyword]}
            results = await search_all_keywords(kw_dict, store)
            return (keyword, results[:10])
        except Exception as e:
            logger.warning("aggregate_rag_results: error searching '%s': %s", keyword, e)
            return (keyword, [])

    search_tasks = [_search_one(kw) for kw in all_keywords]
    search_results = await asyncio.gather(*search_tasks)

    # Merge results from all parallel searches
    for keyword, results in search_results:
        for r in results:
            tname = r.get("table_name", "").strip()
            if not tname or tname == "?":
                continue
            tname_upper = tname.upper()
            score = r.get("score", 0)
            content = (r.get("content") or "")[:300]

            if tname_upper not in table_scores:
                table_scores[tname_upper] = {
                    "table_name": tname,  # Keep original casing
                    "total_score": 0.0,
                    "keyword_hits": 0,
                    "keywords_matched": [],
                    "best_score": 0.0,
                    "best_excerpt": "",
                    "source_type": r.get("type", "?"),
                }

            entry = table_scores[tname_upper]
            entry["total_score"] += score
            if keyword not in entry["keywords_matched"]:
                entry["keyword_hits"] += 1
                entry["keywords_matched"].append(keyword)
            if score > entry["best_score"]:
                entry["best_score"] = score
                entry["best_excerpt"] = content
                entry["source_type"] = r.get("type", "?")

    # Compute composite score: total_score + bonus for being found by multiple keywords
    candidates = []
    for _key, entry in table_scores.items():
        # Bonus: each additional keyword hit adds 20% of the best individual score
        hit_bonus = (entry["keyword_hits"] - 1) * entry["best_score"] * 0.2
        composite = entry["total_score"] + hit_bonus
        candidates.append(
            {
                "table_name": entry["table_name"],
                "composite_score": round(composite, 3),
                "keyword_hits": entry["keyword_hits"],
                "keywords_matched": entry["keywords_matched"][:10],  # Cap for readability
                "best_excerpt": entry["best_excerpt"],
                "source_type": entry["source_type"],
            }
        )

    # Sort by composite score descending
    candidates.sort(key=lambda x: x["composite_score"], reverse=True)
    return candidates[:10]  # Top 10 candidates



async def get_fk_neighbors(table_names: list[str], store: TrainingStore) -> list[str]:
    """
    Get FK-linked neighbor tables for the given table names.

    Args:
        table_names: List of table names to find neighbors for
        store: TrainingStore instance

    Returns:
        List of neighbor table names (deduplicated)
    """
    try:
        return await store.get_fk_linked_tables(table_names)
    except Exception as e:
        logger.error("Error fetching FK neighbors for %s: %s", table_names, e)
        return []


async def recommend_join(
    from_table: str,
    to_table: str,
    fk_graph: dict[str, list[dict]],
    store: TrainingStore,
) -> dict[str, Any]:
    """
    Analyze FK metadata programmatically and return a structured JOIN recommendation.

    This replaces "11 rules in a prompt" with actual code that:
    1. Finds the FK path (BFS)
    2. Checks nullability of each FK column (from column_stats null_pct)
    3. Computes cardinality ratio (risk of cartesian product)
    4. Detects composite keys (multiple columns in ON)
    5. Handles multi-hop paths
    6. Returns a complete recommendation with SQL template + reasoning + warnings

    The LLM receives this recommendation and follows it — it doesn't need to
    interpret abstract rules. It can only override for user-intent reasons.

    Args:
        from_table: Table already in the query
        to_table: Table to join
        fk_graph: Pre-built FK graph
        store: TrainingStore for stats

    Returns:
        dict with: found, recommendation, path_details, sql_template, reasoning, warnings
    """
    from_table.upper()
    to_table.upper()

    # Step 1: Find FK path
    path = find_fk_path(from_table, to_table, fk_graph)
    if path is None:
        return {
            "found": False,
            "from_table": from_table,
            "to_table": to_table,
            "recommendation": "LEFT JOIN",
            "reasoning": (
                f"Aucun chemin FK trouvé entre {from_table} et {to_table}. "
                "Utiliser LEFT JOIN par sécurité (pas de FK déclarée = risque de 1-to-N caché). "
                "Vérifier le COUNT après la jointure."
            ),
            "warnings": ["Pas de FK déclarée — jointure sur clé métier, vérifier COUNT"],
            "sql_template": "",
            "path_details": [],
        }

    # Step 2: Analyze each hop
    path_details = []
    warnings = []
    sql_parts = []
    overall_recommendation = "INNER JOIN"  # Start optimistic, downgrade if needed

    for i, step in enumerate(path):
        source = step["source"]
        target = step["target"]
        src_col = step.get("src_col", "?")
        tgt_col = step.get("tgt_col", "?")
        fk_nullable = step.get("nullable", True)

        # Step 2a: Check actual null percentage — prefer FK graph (already resolved
        # at build time from column_stats), fallback to get_table_info
        actual_null_pct = step.get("null_pct")  # Exact value from FK graph

        if actual_null_pct is None:
            # FK graph didn't have stats for this edge — try get_table_info
            try:
                info = await get_table_info(source, store)
                col_stats = info.get("column_stats", {})
                for key in [src_col, src_col.upper(), src_col.lower()]:
                    if key in col_stats:
                        stats = col_stats[key]
                        if isinstance(stats, dict):
                            actual_null_pct = stats.get("null_pct", stats.get("null_percent", None))
                        break
            except Exception as e:
                logger.debug("Could not fetch stats for %s.%s: %s", source, src_col, e)

        # Step 2b: Determine nullability with real data
        if actual_null_pct is not None:
            is_nullable = actual_null_pct > 0
            nullability_source = f"vérifié (null_pct={actual_null_pct:.1f}%)"
        else:
            is_nullable = fk_nullable  # Fall back to FK graph metadata
            nullability_source = "métadonnée FK (non vérifié avec stats)"

        # Step 2c: Compute cardinality ratio
        cardinality_warning = None
        source_rows = None
        target_rows = None
        try:
            source_info = await get_table_info(source, store)
            target_info = await get_table_info(target, store)
            source_rows = source_info.get("row_count")
            target_rows = target_info.get("row_count")

            if source_rows and target_rows and source_rows > 0:
                ratio = target_rows / source_rows
                if ratio >= 5:
                    cardinality_warning = (
                        f"⚠️ RISQUE CARTÉSIEN ÉLEVÉ : {target} a {target_rows} lignes "
                        f"vs {source} a {source_rows} lignes (ratio {ratio:.1f}x). "
                        "Utiliser subquery, DISTINCT ou ROW_NUMBER()."
                    )
                    warnings.append(cardinality_warning)
                elif ratio >= 2.5:
                    cardinality_warning = (
                        f"⚠ Cardinalité élevée : {target} a {target_rows} lignes "
                        f"vs {source} a {source_rows} lignes (ratio {ratio:.1f}x). "
                        "Vérifier le COUNT après la jointure."
                    )
                    warnings.append(cardinality_warning)
        except Exception:
            pass

        # Step 2d: Determine JOIN type for this hop
        if is_nullable:
            hop_join = "LEFT JOIN"
            hop_reason = (
                f"{src_col} est NULLABLE ({nullability_source}) → LEFT JOIN "
                "pour ne pas perdre les lignes avec FK = NULL"
            )
            overall_recommendation = "LEFT JOIN"  # One nullable hop → whole path is LEFT
        else:
            hop_join = "INNER JOIN"
            hop_reason = f"{src_col} est NOT NULL ({nullability_source}) → INNER JOIN sûr"

        # Step 2e: Build SQL fragment for this hop
        sql_fragment = f"{hop_join} {target} ON {source}.{src_col} = {target}.{tgt_col}"
        sql_parts.append(sql_fragment)

        path_details.append(
            {
                "hop": i + 1,
                "source": source,
                "target": target,
                "source_column": src_col,
                "target_column": tgt_col,
                "nullable": is_nullable,
                "null_pct": actual_null_pct,
                "nullability_source": nullability_source,
                "join_type": hop_join,
                "reasoning": hop_reason,
                "source_rows": source_rows,
                "target_rows": target_rows,
                "cardinality_warning": cardinality_warning,
            }
        )

    # Step 3: Build overall reasoning
    if len(path) == 1:
        overall_reasoning = path_details[0]["reasoning"]
    else:
        nullable_hops = [d for d in path_details if d["nullable"]]
        if nullable_hops:
            overall_reasoning = (
                f"Chemin multi-hop ({len(path)} étapes). "
                f"{len(nullable_hops)} étape(s) avec FK NULLABLE → {overall_recommendation} "
                "pour ne pas perdre de lignes."
            )
        else:
            overall_reasoning = (
                f"Chemin multi-hop ({len(path)} étapes). "
                f"Toutes les FK sont NOT NULL → INNER JOIN sûr sur tout le chemin."
            )

    # Step 4: Build complete SQL template
    sql_template = "\n".join(sql_parts)

    return {
        "found": True,
        "from_table": from_table,
        "to_table": to_table,
        "hops": len(path),
        "recommendation": overall_recommendation,
        "reasoning": overall_reasoning,
        "warnings": warnings,
        "sql_template": sql_template,
        "path_details": path_details,
    }


async def execute_phase2_tool(
    tool_name: str,
    tool_input: dict,
    store: TrainingStore,
    cache: dict | None = None,
) -> dict[str, Any]:
    """
    Execute a Phase 2 tool call and return the result as a JSON-serializable dict.

    For terminal tools (confirm_location, mark_not_found), returns the input directly
    since the orchestrator uses them to build the ConceptSynthesis.

    Args:
        tool_name: Name of the tool to execute
        tool_input: Input dict from the LLM's tool_use block
        store: TrainingStore instance
        cache: Optional dict for caching get_table_info results across calls.
               Pass a shared dict to avoid redundant lookups within a Phase 2 run.

    Returns:
        dict with the tool result
    """
    try:
        if tool_name == "search_schema":
            keywords = tool_input.get("keywords", [])
            if not keywords:
                return {"results": [], "message": "Aucun mot-clé fourni."}
            kw_dict = {"tables": keywords, "colonnes": keywords}
            results = await search_all_keywords(kw_dict, store)
            # Truncate for token efficiency — keep top 20 results
            truncated = []
            for r in results[:20]:
                truncated.append(
                    {
                        "type": r.get("type", "?"),
                        "table_name": r.get("table_name", "?"),
                        "content": (r.get("content") or "")[:600],
                        "score": round(r.get("score", 0), 3),
                    }
                )
            return {"results": truncated, "count": len(results)}

        elif tool_name == "get_table_info":
            table_name = tool_input.get("table_name", "")
            if not table_name:
                return {"error": "table_name requis."}
            # Cache lookup — avoid redundant calls within same Phase 2 run
            cache_key = table_name.upper()
            if cache is not None and cache_key in cache:
                return cache[cache_key]
            info = await get_table_info(table_name, store)
            # Truncate DDL — higher limit for views (their FROM/JOIN is critical)
            ddl = info.get("ddl") or ""
            is_view = ddl.strip().upper().startswith("CREATE VIEW") if ddl else False
            ddl_limit = 6000 if is_view else 3000
            if ddl and len(ddl) > ddl_limit:
                info["ddl"] = ddl[:ddl_limit] + "\n-- [tronqué]"
            # Store in cache for subsequent calls
            if cache is not None:
                cache[cache_key] = info
            return info

        elif tool_name == "get_column_values":
            table_name = tool_input.get("table_name", "")
            column_name = tool_input.get("column_name", "")
            if not table_name or not column_name:
                return {"error": "table_name et column_name requis."}
            values = await get_column_values(table_name, column_name, store)
            return {"table": table_name, "column": column_name, "values": values}

        elif tool_name == "get_fk_neighbors":
            table_names = tool_input.get("table_names", [])
            if not table_names:
                return {"neighbors": [], "message": "Aucune table fournie."}
            neighbors = await get_fk_neighbors(table_names, store)
            return {"tables_requested": table_names, "neighbors": neighbors}

        elif tool_name == "confirm_location":
            # Terminal tool — return input as-is for orchestrator to process
            return tool_input

        elif tool_name == "mark_not_found":
            # Terminal tool — return input as-is for orchestrator to process
            return tool_input

        else:
            return {"error": f"Outil inconnu: {tool_name}"}

    except Exception as e:
        logger.error("Phase 2 tool '%s' failed: %s", tool_name, e)
        return {"error": f"Erreur lors de l'exécution de {tool_name}: {str(e)}"}


# ────────────────────────────────────────────────────────────────────
# Phase 3 — LLM tool schemas (Anthropic format) + dispatcher
# ────────────────────────────────────────────────────────────────────

PHASE3_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "get_fk_path",
        "description": (
            "Analyse le chemin FK entre deux tables et retourne une RECOMMANDATION "
            "complète de jointure. Le système vérifie programmatiquement : "
            "nullability FK (via column_stats null_pct), ratio de cardinalité "
            "(risque cartésien), chemin multi-hop, et génère un template SQL. "
            "Tu reçois : recommendation (INNER/LEFT JOIN), reasoning (pourquoi), "
            "warnings (risques), sql_template (le SQL prêt à utiliser). "
            "SUIS la recommandation sauf si l'intention de l'utilisateur "
            "demande explicitement un autre type de jointure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_table": {
                    "type": "string",
                    "description": "Table de départ (déjà dans la requête SQL).",
                },
                "to_table": {
                    "type": "string",
                    "description": "Table cible à joindre.",
                },
            },
            "required": ["from_table", "to_table"],
        },
    },
    {
        "name": "get_table_info",
        "description": (
            "Obtient les métadonnées complètes d'une table : DDL (CREATE TABLE), "
            "clés étrangères sortantes et entrantes, statistiques par colonne "
            "(distinct_count, null_pct, min/max), valeurs anonymisées, rôle sémantique, "
            "nombre de lignes. Utilise cet outil pour vérifier la structure d'une table "
            "avant de l'ajouter à la requête."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Nom exact de la table à inspecter.",
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "get_column_values",
        "description": (
            "Obtient jusqu'à 15 valeurs anonymisées non-null d'une colonne. "
            "Utile pour vérifier qu'une colonne contient le bon type de données "
            "avant de l'utiliser dans un filtre ou une jointure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "table_name": {
                    "type": "string",
                    "description": "Nom de la table.",
                },
                "column_name": {
                    "type": "string",
                    "description": "Nom de la colonne.",
                },
            },
            "required": ["table_name", "column_name"],
        },
    },
    {
        "name": "test_sql",
        "description": (
            "Teste une requête SQL en exécutant COUNT(*) dessus. "
            "Retourne le nombre de lignes. Utilise cet outil après chaque modification "
            "du SQL (ajout de JOIN, de filtre, etc.) pour vérifier que le COUNT est "
            "cohérent. RÈGLES de COUNT :\n"
            "- ×1 ou stable = OK\n"
            "- ×1.5 à ×3 = normal (1-to-N attendu)\n"
            "- ×5+ = CARTÉSIEN ⚠️ (mauvaise condition JOIN)\n"
            "- ÷2 ou moins = perte de lignes ⚠️ (INNER JOIN inattendu)\n"
            "- = 0 = pas de données (filtre impossible ou mauvaise condition)"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "Requête SQL SELECT à tester (SQL Server syntax).",
                },
            },
            "required": ["sql"],
        },
    },
    {
        "name": "finalize_sql",
        "description": (
            "Déclare que la requête SQL est terminée et prête à être exécutée. "
            "Appelle cet outil UNIQUEMENT quand :\n"
            "1. Toutes les colonnes nécessaires sont dans le SELECT\n"
            "2. Tous les JOINs sont corrects (vérifiés via test_sql)\n"
            "3. Les filtres WHERE sont appliqués\n"
            "4. Le GROUP BY / ORDER BY est en place si nécessaire\n"
            "5. Le COUNT final est cohérent\n"
            "Cet appel termine la boucle de construction SQL."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "Requête SQL finale complète (SQL Server syntax).",
                },
                "explanation": {
                    "type": "string",
                    "description": "Explication de la requête : quelles tables, JOINs, filtres.",
                },
                "final_count": {
                    "type": "integer",
                    "description": "Dernier COUNT(*) connu de la requête.",
                },
            },
            "required": ["sql", "explanation"],
        },
    },
    {
        "name": "step_done",
        "description": (
            "Signale que l'étape de construction en cours est terminée. "
            "Appelle quand le FROM et tous les JOINs nécessaires sont en place, "
            "et que toutes les colonnes du SELECT sont ajoutées. "
            "Le système passera automatiquement à l'étape suivante (filtres)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {
                    "type": "string",
                    "description": "SQL actuel (FROM + JOINs + SELECT sans WHERE ni GROUP BY).",
                },
                "count": {
                    "type": "integer",
                    "description": "Dernier COUNT(*) vérifié.",
                },
                "columns_added": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Liste des colonnes ajoutées au SELECT.",
                },
            },
            "required": ["sql", "count"],
        },
    },
    {
        "name": "report_failure",
        "description": (
            "Signale que la requête SQL ne peut pas être construite. "
            "Utilise cet outil quand :\n"
            "- Les tables nécessaires n'existent pas\n"
            "- Aucun chemin FK ne relie les tables\n"
            "- Le COUNT reste à 0 malgré les corrections\n"
            "- Les données demandées sont incompatibles\n"
            "Cet appel termine la boucle de construction SQL."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Explication de pourquoi la requête ne peut pas être construite.",
                },
                "partial_sql": {
                    "type": "string",
                    "description": "SQL partiel construit jusqu'ici (si disponible).",
                },
            },
            "required": ["reason"],
        },
    },
    {
        "name": "explore_alternatives",
        "description": (
            "Explore TOUS les chemins FK possibles entre deux tables (pas juste le plus court). "
            "Retourne tous les chemins avec le nombre de hops, les colonnes FK, "
            "et une recommandation du meilleur chemin. "
            "Utilise cet outil AVANT de choisir un JOIN quand plusieurs chemins sont possibles."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "from_table": {
                    "type": "string",
                    "description": "Nom de la table source (déjà dans la requête SQL).",
                },
                "to_table": {
                    "type": "string",
                    "description": "Nom de la table cible à joindre.",
                },
            },
            "required": ["from_table", "to_table"],
        },
    },
    {
        "name": "propose_approaches",
        "description": (
            "Structure ta réflexion en proposant 2-5 approches DIFFÉRENTES pour trouver "
            "une donnée dans la BDD. Pour chaque approche, indique la/les table(s), "
            "colonne(s), méthode d'accès (direct, JOIN, sous-requête, CASE WHEN), "
            "et les avantages/inconvénients. Appelle cet outil AVANT de choisir une approche."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "element": {
                    "type": "string",
                    "description": "L'élément de la requête à résoudre.",
                },
                "approaches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "integer",
                                "description": "Numéro de l'approche (1, 2, 3...)",
                            },
                            "tables": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Tables impliquées.",
                            },
                            "columns": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Colonnes utilisées.",
                            },
                            "method": {
                                "type": "string",
                                "description": (
                                    "Méthode d'accès : 'direct' (dans table existante), "
                                    "'join' (nouvelle jointure), 'subquery' (sous-requête), "
                                    "'case_when' (expression calculée)."
                                ),
                            },
                            "pros": {
                                "type": "string",
                                "description": "Avantages de cette approche.",
                            },
                            "cons": {
                                "type": "string",
                                "description": "Inconvénients de cette approche.",
                            },
                        },
                        "required": ["id", "tables", "method"],
                    },
                    "description": "Liste des approches proposées (2-5).",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Raisonnement global sur les approches.",
                },
            },
            "required": ["element", "approaches"],
        },
    },
    {
        "name": "evaluate_approaches",
        "description": (
            "Après avoir testé les approches (test_sql, get_table_info), "
            "compare les résultats et choisis la MEILLEURE approche. "
            "Justifie ton choix."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "chosen_approach_id": {
                    "type": "integer",
                    "description": "L'ID de l'approche choisie.",
                },
                "reasoning": {
                    "type": "string",
                    "description": (
                        "Pourquoi cette approche est la meilleure "
                        "(cohérence COUNT, réutilise tables existantes, "
                        "moins de JOINs, null_pct bas, etc.)."
                    ),
                },
                "rejected_reasons": {
                    "type": "object",
                    "description": ("Pour chaque approche rejetée : {id: raison}."),
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["chosen_approach_id", "reasoning"],
        },
    },
    {
        "name": "get_resolved_values",
        "description": (
            "Résout un terme partiel en valeurs EXACTES dans une colonne donnée. "
            "Cherche toutes les valeurs réelles de table.column qui CONTIENNENT le terme. "
            "Essentiel pour construire des filtres IN / NOT IN avec des valeurs exactes "
            "au lieu d'utiliser LIKE qui est imprécis. "
            "Retourne les valeurs anonymisées correspondantes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "term": {
                    "type": "string",
                    "description": "Terme partiel à chercher (ex: un code, un nom partiel).",
                },
                "table_name": {
                    "type": "string",
                    "description": "Nom de la table où chercher.",
                },
                "column_name": {
                    "type": "string",
                    "description": "Nom de la colonne où chercher.",
                },
            },
            "required": ["term", "table_name", "column_name"],
        },
    },
]


# =============================================================================
# Phase 2 FUSION — Tool schemas combining exploration + SQL building
# Used when Phase 2 both locates AND builds SQL per element
# =============================================================================

# Terminal tool for the fused Phase 2 element resolution+build
_ELEMENT_DONE_SCHEMA = {
    "name": "element_done",
    "description": (
        "Signale qu'un élément est résolu et intégré au SQL courant. "
        "Appelle quand tu as : (1) choisi la meilleure approche, "
        "(2) ajouté le JOIN/colonne au SQL, (3) vérifié le COUNT. "
        "Cet outil termine la boucle pour cet élément."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "sql": {
                "type": "string",
                "description": "SQL actuel après intégration de cet élément.",
            },
            "count": {
                "type": "integer",
                "description": "Dernier COUNT(*) vérifié.",
            },
            "table": {
                "type": "string",
                "description": "Table utilisée pour cet élément.",
            },
            "column": {
                "type": "string",
                "description": "Colonne utilisée pour cet élément.",
            },
            "join_path": {
                "type": "string",
                "description": "Chemin de jointure si via FK (ex: A.col → B.col).",
            },
            "retrieval": {
                "type": "string",
                "description": "Méthode: direct, via_fk, aggregation, case_when.",
            },
            "notes": {
                "type": "string",
                "description": "Notes sur comment cet élément est intégré.",
            },
        },
        "required": ["sql", "table"],
    },
}


# Combine exploration tools (Phase 2) + SQL build tools (Phase 3) + element_done
PHASE2_FUSED_TOOL_SCHEMAS: list[dict[str, Any]] = [
    # From Phase 2: exploration tools (without search_schema — search done by system)
    *[
        s
        for s in PHASE2_TOOL_SCHEMAS
        if s["name"]
        not in (
            "search_schema",
            "confirm_location",
            "mark_not_found",
        )
    ],
    # From Phase 3: SQL build tools
    *[
        s
        for s in PHASE3_TOOL_SCHEMAS
        if s["name"]
        in (
            "get_fk_path",
            "test_sql",
            "explore_alternatives",
            "propose_approaches",
            "evaluate_approaches",
            "get_resolved_values",
        )
    ],
    # Terminal tools for fused Phase 2
    _ELEMENT_DONE_SCHEMA,
    # Keep report_failure as terminal
    *[s for s in PHASE3_TOOL_SCHEMAS if s["name"] == "report_failure"],
]


async def execute_phase2_fused_tool(
    tool_name: str,
    tool_input: dict,
    store: TrainingStore,
    connector: Any,
    fk_graph: dict[str, list[dict]],
    cache: dict | None = None,
) -> dict[str, Any]:
    """Execute a tool in the fused Phase 2 (exploration + SQL building).

    Dispatches to either Phase 2 or Phase 3 tool handlers depending on tool type.
    """
    # Phase 2 exploration tools
    if tool_name in ("get_table_info", "get_column_values", "get_fk_neighbors", "search_schema"):
        return await execute_phase2_tool(tool_name, tool_input, store, cache=cache)

    # Phase 3 SQL building tools (need connector + fk_graph)
    if tool_name in (
        "get_fk_path",
        "test_sql",
        "explore_alternatives",
        "propose_approaches",
        "evaluate_approaches",
        "get_resolved_values",
    ):
        return await execute_phase3_tool(tool_name, tool_input, store, connector, fk_graph)

    # Terminal tools — return input as-is
    if tool_name in ("element_done", "report_failure"):
        return tool_input

    return {"error": f"Outil inconnu pour Phase 2 fusionnée: {tool_name}"}


def find_all_fk_paths(
    from_table: str, to_table: str, fk_graph: dict, max_hops: int = 4
) -> list[list[dict]]:
    """Find ALL FK paths between two tables (not just the shortest).

    Args:
        from_table: Source table name
        to_table: Target table name
        fk_graph: Adjacency list from build_fk_graph() :
                  {TABLE_UPPER: [{target, src_col, tgt_col, nullable, direction}]}
        max_hops: Maximum path length to search

    Returns:
        List of paths, where each path is a list of edge dicts
    """
    from collections import deque

    if not fk_graph:
        return []

    from_key = from_table.upper()
    to_key = to_table.upper()

    # BFS to find all paths (fk_graph IS already an adjacency list)
    all_paths: list[list[dict]] = []
    queue: deque = deque([([from_key], [])])  # (visited_tables, edge_path)

    while queue:
        table_path, edge_path = queue.popleft()
        current = table_path[-1]

        if len(edge_path) >= max_hops:
            continue

        if current == to_key and edge_path:
            all_paths.append(edge_path)
            continue

        # Explore neighbors from adjacency list
        for edge in fk_graph.get(current, []):
            next_table = edge.get("target", "").upper()
            if next_table and next_table not in table_path:  # Avoid cycles
                queue.append((table_path + [next_table], edge_path + [edge]))

    return all_paths


async def explore_alternatives(
    from_table: str,
    to_table: str,
    fk_graph: dict,
    store,
) -> dict:
    """Explore ALL possible paths between two tables.

    Returns dict with 'fk_paths' (BFS results) and 'recommendation'.
    """
    paths = find_all_fk_paths(from_table, to_table, fk_graph, max_hops=4)

    if not paths:
        return {
            "found": False,
            "reason": f"No FK path found from {from_table} to {to_table}",
            "fk_paths": [],
        }

    # Format paths for display
    formatted_paths = []
    for i, path in enumerate(paths[:5]):  # Limit to top 5 paths
        hop_count = len(path)
        # Reconstruct table chain from edges (edges only have "target")
        tables = [from_table.upper()]
        for edge in path:
            tables.append(edge.get("target", "?"))
        path_str = " → ".join(tables)
        formatted_paths.append(
            {
                "path_number": i + 1,
                "hop_count": hop_count,
                "path": path_str,
                "edges": path,
            }
        )

    recommendation = {
        "best_path": formatted_paths[0] if formatted_paths else None,
        "all_paths": formatted_paths,
        "notes": f"Found {len(paths)} path(s), showing top {min(5, len(paths))}",
    }

    return {
        "found": True,
        "fk_paths": formatted_paths,
        "recommendation": recommendation,
    }


async def execute_phase3_tool(
    tool_name: str,
    tool_input: dict,
    store: TrainingStore,
    connector: Any,
    fk_graph: dict[str, list[dict]],
) -> dict[str, Any]:
    """
    Execute a Phase 3 tool call and return the result.

    Args:
        tool_name: Name of the tool to execute
        tool_input: Input dict from the LLM's tool_use block
        store: TrainingStore instance
        connector: SageConnector instance (for test_sql)
        fk_graph: Pre-built FK graph (for get_fk_path)

    Returns:
        dict with the tool result
    """
    try:
        if tool_name == "get_fk_path":
            from_table = tool_input.get("from_table", "")
            to_table = tool_input.get("to_table", "")
            if not from_table or not to_table:
                return {"error": "from_table et to_table requis."}
            # Use recommend_join() for rich programmatic analysis
            return await recommend_join(from_table, to_table, fk_graph, store)

        elif tool_name == "get_table_info":
            table_name = tool_input.get("table_name", "")
            if not table_name:
                return {"error": "table_name requis."}
            info = await get_table_info(table_name, store)
            if info.get("ddl") and len(info["ddl"]) > 2000:
                info["ddl"] = info["ddl"][:2000] + "\n-- [tronqué]"
            return info

        elif tool_name == "get_column_values":
            table_name = tool_input.get("table_name", "")
            column_name = tool_input.get("column_name", "")
            if not table_name or not column_name:
                return {"error": "table_name et column_name requis."}
            values = await get_column_values(table_name, column_name, store)
            return {"table": table_name, "column": column_name, "values": values}

        elif tool_name == "test_sql":
            sql = tool_input.get("sql", "")
            if not sql:
                return {"error": "sql requis."}
            count = await execute_count(sql, connector)
            # Guard: trivial COUNT rejected — return guidance message
            if isinstance(count, str):
                return {
                    "success": False,
                    "rejected": True,
                    "message": count,
                    "sql_tested": sql[:200],
                }
            # Rich error dict from execute_count (SQL Server error details)
            if isinstance(count, dict):
                return {
                    "success": False,
                    "error": count.get("error", "Erreur inconnue"),
                    "sql_tested": sql[:200],
                }
            if count == -1:
                return {
                    "success": False,
                    "error": "Erreur d'exécution SQL — vérifiez la syntaxe.",
                    "sql_tested": sql[:200],
                }
            return {
                "success": True,
                "count": count,
                "sql_tested": sql[:200],
            }

        elif tool_name == "finalize_sql":
            return tool_input

        elif tool_name == "report_failure":
            return tool_input

        elif tool_name == "explore_alternatives":
            from_table = tool_input.get("from_table", "")
            to_table = tool_input.get("to_table", "")
            if not from_table or not to_table:
                return {"error": "from_table et to_table requis."}
            return await explore_alternatives(from_table, to_table, fk_graph, store)

        elif tool_name == "finalize_element":
            return tool_input

        elif tool_name == "propose_approaches":
            # Structured reflection tool — returns input as-is for the agent
            # to use in subsequent reasoning
            return {
                "status": "approaches_recorded",
                "count": len(tool_input.get("approaches", [])),
                "message": (
                    "Approches enregistrées. Teste chaque approche avec "
                    "get_table_info/get_fk_path/test_sql, puis appelle "
                    "evaluate_approaches pour choisir la meilleure."
                ),
            }

        elif tool_name == "evaluate_approaches":
            # Structured decision tool — returns input as-is
            return {
                "status": "approach_chosen",
                "chosen": tool_input.get("chosen_approach_id"),
                "message": (
                    "Approche choisie. Implémente-la dans le SQL et "
                    "appelle test_sql pour vérifier."
                ),
            }

        elif tool_name == "get_resolved_values":
            term = tool_input.get("term", "")
            table = tool_input.get("table_name", "")
            column = tool_input.get("column_name", "")
            if not term or not table or not column:
                return {"error": "term, table_name et column_name requis."}
            return await get_resolved_values(term, table, column)

        elif tool_name == "step_done":
            # Terminal tool — returned as-is for orchestrator to process
            return tool_input

        else:
            return {"error": f"Outil inconnu: {tool_name}"}

    except Exception as e:
        logger.error("Phase 3 tool '%s' failed: %s", tool_name, e)
        return {"error": f"Erreur lors de l'exécution de {tool_name}: {str(e)}"}
