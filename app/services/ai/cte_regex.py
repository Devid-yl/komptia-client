"""Source unique des regex CTE T-SQL utilisées par Komptia.

Centralise le pattern d'extraction des en-têtes de CTE T-SQL pour éviter
la duplication entre ``sql_validator`` et ``result_assistant`` (anti-pattern
identifié lors de l'audit du run Iris 14:05 — 5 régex copiées-collées).

**Grammaire couverte** (cf. Microsoft Learn — Transact-SQL CTE) :

    WITH [ RECURSIVE ] cte_name [ ( column_name [,...n] ) ] AS ( query )
    [, cte_name [ ( column_name [,...n] ) ] AS ( query ) ]...

Référence officielle :
https://learn.microsoft.com/en-us/sql/t-sql/queries/with-common-table-expression-transact-sql

**Cas matchés** :
    WITH foo AS (              ← standard
    WITH foo(a) AS (           ← liste de colonnes (1 col)
    WITH foo(a, b, c) AS (     ← liste de colonnes (N cols)
    WITH foo (a, b) AS (       ← espace avant la liste
    WITH RECURSIVE tree(n) AS ( ← CTE récursive PostgreSQL (toléré pour
                                  compat multi-providers — un LLM non-T-SQL
                                  peut émettre ce mot-clé)
    , bar(x) AS (              ← CTE suivante dans un multi-CTE

Group 1 = nom du CTE. La liste de colonnes optionnelle ``(...)``
et le mot-clé ``RECURSIVE`` ne sont PAS capturés.
"""

from __future__ import annotations

import re

# Fragment string du header CTE — building block pour composer des régex
# plus larges (extraction du body, splitting du WITH ... SELECT, etc.).
# Group 1 = nom du CTE. Pas de flag inline — le caller applique IGNORECASE.
CTE_HEADER_PATTERN = (
    r"(?:\bWITH\b(?:\s+RECURSIVE\b)?|,)"  # ancre : début WITH (avec RECURSIVE optionnel) ou ,
    r"\s+(\w+)"  # nom du CTE (group 1)
    r"(?:\s*\([^)]*\))?"  # liste de colonnes optionnelle (non-capturante)
    r"\s+AS\s*\("  # AS (
)


# Pattern principal — avec ancre ``WITH`` ou ``,`` pour scanner un SQL complet.
# Group 1 = nom du CTE (case-insensitive).
CTE_HEADER_RE = re.compile(CTE_HEADER_PATTERN, re.IGNORECASE)


__all__ = ["CTE_HEADER_PATTERN", "CTE_HEADER_RE"]
