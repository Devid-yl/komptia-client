"""Helpers de parsing schéma pour le module data_access.

Le seul helper exposé aujourd'hui est :func:`extract_columns_from_ddl`,
utilisé par le handler ``DataAccessTablesAPIHandler`` pour alimenter
l'autocomplete colonnes de l'UI admin.

Heuristique regex (pas un vrai parser SQL) — suffisant pour les DDL
``CREATE TABLE`` stockés dans ``TrainingData`` (générés par le sync
``schema_sync``). Si le besoin évolue (parser fidèle, support de
``ALTER TABLE``, etc.), on pourra réutiliser ``sqlglot`` ici.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Tuple

#: Regex : matche ``[col_name] type`` ou ``col_name type`` en début de ligne
#: ou après une virgule. Tolère les types complexes (``varchar(50)``,
#: ``decimal(18,2)``).
_DDL_COLUMN_RE = re.compile(
    r"^\s*\[?([A-Za-z_][A-Za-z0-9_]*)\]?\s+[A-Za-z]",
    re.MULTILINE,
)

#: Mots-clés SQL fréquents à filtrer (matchent le pattern mais ne sont
#: pas des noms de colonnes).
_SQL_KEYWORDS_TO_SKIP = frozenset(
    {
        "CONSTRAINT",
        "PRIMARY",
        "FOREIGN",
        "UNIQUE",
        "INDEX",
        "KEY",
        "CHECK",
        "REFERENCES",
        "CREATE",
        "TABLE",
    }
)


@lru_cache(maxsize=512)
def _extract_columns_from_ddl_cached(ddl: str) -> Tuple[str, ...]:
    """Implémentation parsing (pure) protégée par ``@lru_cache``.

    Bug 2026-05-26 (Agent 4 DA-M11) : sur la page admin data-access,
    ``extract_columns_from_ddl`` était appelée 2× par request (validation
    + autocomplete) sur chaque DDL — 200 tables × 2 = 400 parses par
    page-load alors que la fonction est pure. Cache LRU de 512 entrées
    (couvre confortablement l'inventaire schéma de 200-300 tables).
    Le wrapper public ``extract_columns_from_ddl`` retourne une List
    (interface stable) ; le cache stocke un Tuple immuable (hashable).
    """
    if not ddl or "CREATE" not in ddl.upper():
        return ()
    # Garder uniquement le contenu entre la première ``(`` et la dernière
    # ``)`` de ``CREATE TABLE`` pour limiter le bruit (KEYS, FOREIGN KEYS, etc.)
    open_idx = ddl.find("(")
    close_idx = ddl.rfind(")")
    if open_idx == -1 or close_idx == -1 or close_idx <= open_idx:
        return ()
    body = ddl[open_idx + 1 : close_idx]
    cols: List[str] = []
    for match in _DDL_COLUMN_RE.finditer(body):
        name = match.group(1)
        if name.upper() in _SQL_KEYWORDS_TO_SKIP:
            continue
        if name not in cols:
            cols.append(name)
    return tuple(cols)


def extract_columns_from_ddl(ddl: str) -> List[str]:
    """Extrait les noms de colonnes d'un DDL ``CREATE TABLE``.

    Heuristique simple (pas de parser complet) : matche tout identifiant
    en début de ligne suivi d'un type. Suffisant pour l'autocomplete UI
    et le contexte LLM. Retourne une liste sans doublons (ordre préservé).

    Wrapper autour de ``_extract_columns_from_ddl_cached`` qui est cachée
    via ``@lru_cache(512)``. Le wrapper retourne une nouvelle ``list``
    (mutable) à chaque appel pour ne pas exposer le tuple immuable du
    cache aux callers (qui pourraient le passer à du code qui mute).
    """
    return list(_extract_columns_from_ddl_cached(ddl))
