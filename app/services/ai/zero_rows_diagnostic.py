"""T16 — Diagnostic différentiel pour SQL retournant 0 rows.

But : distinguer **bug silencieux** (joints/filtres masquent les données)
vs **0-rows légitime** (la donnée n'existe pas).

Stratégie programmatique (0 appel LLM) :

1. Parse le SQL pour extraire les tables physiques participantes (réutilise
   :func:`app.services.ai.sql_validator.SQLValidator`).
2. Pour chaque table (cap ``max_tables_to_probe``), exécute
   ``SELECT COUNT(*) FROM <table>`` via le query_executor (RLS appliqué).
3. Agrège les résultats en signal sémantique :

   - **Toutes** les tables ont ≥1 row → ``filters_or_joins_too_restrictive``
     (probable bug : les filtres ou les jointures du SQL final éliminent
     toutes les rows alors que les données existent).
   - **Toutes** les tables sont vides → ``data_absent`` (légitime : aucune
     donnée n'existe dans aucune table participante — l'utilisateur n'a
     simplement pas la donnée recherchée).
   - **Mix** → ``partial_data_absent`` (au moins une table participante
     est vide ; le 0-rows final est probablement légitime mais le caller
     est invité à vérifier).
   - Échec parse / aucun COUNT exploitable → ``unknown``.

Generic : 0 nom BDD hardcodé. Aucune connaissance Sage Coala-spécifique.
Le caller (agent_tools._handle_execute_sql) injecte le résultat dans la
réponse du tool ``execute_sql`` ; l'agent IA présente alors une réponse
adaptée à l'utilisateur.

Sécurité :

- Les COUNT(*) passent par le ``query_executor`` qui applique le RLS sur
  l'utilisateur courant — un user qui n'a pas accès à une table aura
  ``per_table_counts[table] = None`` (l'absence d'info n'est PAS une
  fuite).
- Timeout par table (``per_table_timeout_seconds``) borne le coût même
  sur tables énormes.
- Fail-safe complet : aucune exception remontée — fallback ``unknown``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Cap defaults — surchargables au call site, mais documentés ici comme
# valeurs de référence pour audits.
DEFAULT_MAX_TABLES_TO_PROBE: int = 5
DEFAULT_PER_TABLE_TIMEOUT_SECONDS: float = 5.0
DEFAULT_GLOBAL_DIAGNOSTIC_TIMEOUT_SECONDS: float = 30.0


def _extract_physical_tables(sql: str) -> set[str]:
    """Extrait les tables physiques d'un SQL T-SQL (CTE et sous-queries exclues).

    Réutilise ``SQLValidator`` qui est robuste (sqlglot + fallback regex).
    Fail-safe : retourne ``set()`` sur SQL malformé.
    """
    if not isinstance(sql, str) or not sql.strip():
        return set()
    try:
        from app.services.ai.sql_validator import SQLValidator

        # Strip commentaires (cohérent avec _extract_real_tables_from_sql)
        clean = re.sub(r"--[^\n]*", "", sql)
        clean = re.sub(r"/\*.*?\*/", "", clean, flags=re.DOTALL)

        validator = SQLValidator()
        tables_in_query = validator.extract_tables_from_sql_text(clean) or set()
        cte_names = validator._extract_cte_names(clean) or set()
        subquery_aliases = validator._extract_subquery_aliases(clean) or set()
        return set(tables_in_query) - set(cte_names) - set(subquery_aliases)
    except Exception:  # noqa: BLE001 — fail-safe, log + fallback
        logger.exception("zero_rows_diagnostic: SQL parse failed")
        return set()


async def _probe_table_count(
    table: str,
    query_executor: Any,
    user: Any,
    *,
    timeout_seconds: float,
) -> Optional[int]:
    """Exécute ``SELECT COUNT(*) FROM <table>`` avec timeout. ``None`` si échec.

    Le query_executor applique le RLS sur ``user`` (cf. ``enforcer.enforce_for_executor``).
    Si l'utilisateur n'a pas accès à cette table, le COUNT échoue → on retourne
    ``None`` (différence sémantique avec ``0``).

    Generic : aucune assumption sur le dialect, pas de quoting BDD-spécifique.
    Pour SQL Server / SQLite / autres, ``SELECT COUNT(*) FROM <unquoted>``
    fonctionne tant que ``<table>`` ne contient pas de caractères spéciaux —
    et `_extract_physical_tables` retourne déjà des noms canoniques.
    """
    # Anti-injection défensif : refuser tout nom de table avec caractère non
    # alphanumérique/underscore. Les noms canoniques de tables passent toujours
    # ce filtre. Sans ce filtre, une CTE ou sous-query qui contiendrait un
    # nom corrompu (rare mais possible) pourrait injecter du SQL.
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", table):
        logger.warning(
            "zero_rows_diagnostic: rejected non-canonical table name: %r",
            table,
        )
        return None

    count_sql = f"SELECT COUNT(*) AS n FROM {table}"
    try:
        result = await asyncio.wait_for(
            query_executor.execute(
                count_sql,
                max_rows=1,
                # Add limit doit être False : SELECT COUNT(*) ne supporte pas TOP
                # en SQL Server quand on a un seul scalar, et la valeur n'a pas
                # de sens à limiter.
                add_limit=False,
                timeout=int(max(1, timeout_seconds)),
                user=user,
                rls_source="zero_rows_diagnostic",
            ),
            timeout=timeout_seconds + 1.0,  # +1s pour la marge wait_for
        )
    except (asyncio.TimeoutError, asyncio.CancelledError):
        logger.info(
            "zero_rows_diagnostic: COUNT(*) timed out for table %r (timeout=%.1fs)",
            table,
            timeout_seconds,
        )
        return None
    except Exception:  # noqa: BLE001 — fail-safe (RLS refuse, table inexistante, etc.)
        logger.info(
            "zero_rows_diagnostic: COUNT(*) failed for table %r (probably RLS or missing)",
            table,
        )
        return None

    # Le query_executor retourne un QueryResult avec rows: List[tuple|list].
    rows = getattr(result, "rows", None)
    if not rows:
        return None
    first_row = rows[0]
    # Le row peut être tuple, list, ou dict selon le connecteur. On extrait
    # la 1re valeur quel que soit le format.
    try:
        if isinstance(first_row, dict):
            count_val = next(iter(first_row.values()))
        else:
            count_val = first_row[0]
    except (IndexError, StopIteration, KeyError):
        return None

    try:
        return int(count_val)
    except (TypeError, ValueError):
        return None


def _aggregate_cause(per_table_counts: dict[str, Optional[int]]) -> tuple[str, float]:
    """Agrège les counts par table en (probable_cause, confidence).

    Sémantique :
    - Aucun count exploitable (toutes ``None``) → ``unknown``, conf 0.0
    - Toutes les tables ≥ 1 row → ``filters_or_joins_too_restrictive``, conf
      proportionnelle au nombre de tables probées avec succès
    - Toutes les tables == 0 row → ``data_absent``, idem
    - Mix → ``partial_data_absent``, conf moyenne

    Generic : aucune connaissance BDD.
    """
    known_counts = {t: c for t, c in per_table_counts.items() if c is not None}
    if not known_counts:
        return "unknown", 0.0

    n_known = len(known_counts)
    n_empty = sum(1 for c in known_counts.values() if c == 0)
    n_with_data = n_known - n_empty

    # Confidence augmente avec le nombre de tables probées avec succès,
    # capée à 1.0 quand on a couvert au moins 3 tables (ou 100% du SQL).
    confidence = min(1.0, n_known / max(3, len(per_table_counts)))

    if n_empty == 0:
        return "filters_or_joins_too_restrictive", confidence
    if n_with_data == 0:
        return "data_absent", confidence
    return "partial_data_absent", confidence * 0.7  # mix = moins fiable


async def diagnose_zero_rows(
    sql: str,
    query_executor: Any,
    user: Any,
    *,
    max_tables_to_probe: int = DEFAULT_MAX_TABLES_TO_PROBE,
    per_table_timeout_seconds: float = DEFAULT_PER_TABLE_TIMEOUT_SECONDS,
    global_timeout_seconds: float = DEFAULT_GLOBAL_DIAGNOSTIC_TIMEOUT_SECONDS,
) -> dict:
    """Diagnostique un SQL retournant 0 rows.

    Args:
        sql: la requête originale qui a retourné 0 rows.
        query_executor: objet avec une méthode ``async execute(...)`` (typiquement
            ``app.services.database.query_executor.QueryExecutor`` ou un mock test).
        user: utilisateur courant pour RLS (transmis au query_executor).
        max_tables_to_probe: cap nombre de COUNT(*) émis (défaut 5).
        per_table_timeout_seconds: timeout par COUNT (défaut 5s).
        global_timeout_seconds: timeout total du diagnostic (défaut 30s) — si
            dépassé, on retourne le diagnostic partiel calculé jusque-là.

    Returns:
        Dict avec keys :
        - ``probable_cause`` (str) : ``filters_or_joins_too_restrictive`` |
          ``data_absent`` | ``partial_data_absent`` | ``unknown``
        - ``confidence`` (float) : [0, 1]
        - ``per_table_counts`` (dict[str, int|None]) : COUNT(*) par table probée
        - ``tables_probed`` (list[str]) : tables effectivement probées (capées)
        - ``tables_skipped`` (list[str]) : tables au-delà du cap (audit)
        - ``error`` (str | absent) : description si fallback

    Fail-safe : aucune exception remontée. ``unknown`` en cas de problème.

    Generic : aucun nom BDD hardcodé.
    """
    # 1. Parse → tables physiques.
    tables = _extract_physical_tables(sql)
    if not tables:
        return {
            "probable_cause": "unknown",
            "confidence": 0.0,
            "per_table_counts": {},
            "tables_probed": [],
            "tables_skipped": [],
            "error": "no_physical_tables_extracted",
        }

    # 2. Cap nombre de tables probées (tri lexicographique pour déterminisme).
    sorted_tables = sorted(tables)
    tables_probed = sorted_tables[:max_tables_to_probe]
    tables_skipped = sorted_tables[max_tables_to_probe:]

    per_table_counts: dict[str, Optional[int]] = {}

    # 3. Probe en parallèle borné par max_tables_to_probe, avec global timeout.
    async def _probe_one(table: str) -> tuple[str, Optional[int]]:
        count = await _probe_table_count(
            table,
            query_executor,
            user,
            timeout_seconds=per_table_timeout_seconds,
        )
        return table, count

    try:
        gathered = await asyncio.wait_for(
            asyncio.gather(*(_probe_one(t) for t in tables_probed), return_exceptions=True),
            timeout=global_timeout_seconds,
        )
        for item in gathered:
            if isinstance(item, BaseException):
                logger.info("zero_rows_diagnostic: probe coroutine raised: %s", item)
                continue
            table, count = item
            per_table_counts[table] = count
    except (asyncio.TimeoutError, asyncio.CancelledError):
        logger.info(
            "zero_rows_diagnostic: global timeout (%.1fs) — returning partial diagnostic",
            global_timeout_seconds,
        )
    except Exception:  # noqa: BLE001 — fail-safe absolu
        logger.exception("zero_rows_diagnostic: unexpected gather error")

    # Tables non probées (au-delà du cap) ne reçoivent pas de count.
    for t in tables_probed:
        per_table_counts.setdefault(t, None)

    # 4. Agrégation sémantique.
    probable_cause, confidence = _aggregate_cause(per_table_counts)

    return {
        "probable_cause": probable_cause,
        "confidence": round(confidence, 2),
        "per_table_counts": per_table_counts,
        "tables_probed": list(tables_probed),
        "tables_skipped": list(tables_skipped),
    }
