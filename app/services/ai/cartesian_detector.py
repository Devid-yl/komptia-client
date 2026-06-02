"""T22 — Détection de cartésien masqué (JOIN sans condition ON/USING).

But : signaler les SQL contenant un ``JOIN`` (inner par défaut) sans clause
``ON`` ni ``USING``, ce qui produit silencieusement un produit cartésien
(résultat × N rows de la table jointe sans condition de matching).

Catégorie de bug typique :
- LLM Phase 4 IR composer oublie la condition ON sur un JOIN
- LLM agent IA Iris écrit un SQL libre avec JOIN sans ON

C'est le scénario **"données fausses silencieuses"** — la pire catégorie
selon le principe ``consequences.md`` (un résultat × 100 sans erreur visible
est 100x pire qu'un crash net).

Stratégie :
1. Parse via sqlglot (dialect tsql, robuste pour CTE/sous-queries)
2. Itère sur tous les nœuds ``exp.Join`` du tree
3. Pour chaque JOIN :
   - ``kind='CROSS'`` → cartésien explicite (légitime — l'utilisateur l'a
     demandé sciemment)
   - ``on != None`` OU ``using != None`` → condition présente (légitime)
   - sinon → SUSPECT (cartésien masqué, probable bug LLM)

V1 (cette implémentation) : cible UNIQUEMENT le cas le plus net. V2 future
étendra à :
- ``ON`` référençant des colonnes inexistantes (cartésien via prédicat faux)
- ``FROM A, B WHERE`` sans condition liant (style legacy implicite)
- Validation graphe FK BFS pour s'assurer que le ON utilise une vraie FK

Generic : 0 nom BDD hardcodé. Aucune connaissance Sage Coala-spécifique.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def detect_cartesian_joins(sql: str) -> dict[str, Any]:
    """Détecte les JOIN sans clause ON/USING dans un SQL T-SQL.

    Args:
        sql: la requête à analyser.

    Returns:
        Dict avec :
        - ``has_suspect_joins`` (bool) : True si au moins 1 JOIN sans
          condition ON/USING détecté (hors CROSS JOIN explicite).
        - ``suspect_joins`` (list[dict]) : list de
          ``{"table_name": str, "join_kind": str}``
          — un par JOIN suspect.
        - ``total_joins`` (int) : nombre total de nœuds JOIN dans l'AST.
        - ``cross_joins_explicit`` (int) : nombre de CROSS JOIN légitimes.
        - ``error`` (str | None) : description si parse échoue.

    Fail-safe : SQL malformé / vide / non-string → retourne sans raise avec
    ``has_suspect_joins=False`` et un ``error`` explicatif.
    """
    out: dict[str, Any] = {
        "has_suspect_joins": False,
        "suspect_joins": [],
        "total_joins": 0,
        "cross_joins_explicit": 0,
        "error": None,
    }

    if not isinstance(sql, str) or not sql.strip():
        out["error"] = "empty_or_invalid_sql"
        return out

    try:
        import sqlglot
        from sqlglot import expressions as exp
    except ImportError:
        out["error"] = "sqlglot_not_available"
        return out

    try:
        tree = sqlglot.parse_one(sql, dialect="tsql")
    except Exception as exc:  # noqa: BLE001 — fail-safe, log + return clean
        logger.info("cartesian_detector: SQL parse failed: %s", exc)
        out["error"] = f"parse_failed: {type(exc).__name__}"
        return out

    if tree is None:
        out["error"] = "parse_returned_none"
        return out

    suspect_joins: list[dict[str, Any]] = []
    total_joins = 0
    cross_joins_explicit = 0

    for join in tree.find_all(exp.Join):
        total_joins += 1
        kind = (join.args.get("kind") or "").upper()
        side = (join.args.get("side") or "").upper()
        on_clause = join.args.get("on")
        using_clause = join.args.get("using")
        method = join.args.get("method")  # APPLY, etc.

        # CROSS JOIN explicite : légitime
        if kind == "CROSS":
            cross_joins_explicit += 1
            continue

        # CROSS APPLY / OUTER APPLY (T-SQL) : sémantique différente de JOIN cartésien
        # — le côté droit dépend du côté gauche. Légitime.
        if method and str(method).upper() in {"CROSS", "OUTER"}:
            continue

        # Condition explicite via ON ou USING : légitime
        if on_clause is not None or using_clause is not None:
            continue

        # Suspect : JOIN sans condition
        # Extraction du nom de la table jointe (best-effort, generic)
        table_name = ""
        this = join.this
        if isinstance(this, exp.Table):
            table_name = this.name or ""
        elif this is not None:
            # Sous-requête ou autre expression → utilise alias si dispo
            alias = join.alias_or_name
            table_name = alias or "(subquery)"

        # Construire un descripteur lisible pour le LLM/admin (sans révéler
        # plus que nécessaire — le table_name est déjà dans le SQL exécuté
        # donc pas une nouvelle fuite).
        join_kind_descr = ""
        if side:
            join_kind_descr += f"{side} "
        if kind:
            join_kind_descr += f"{kind} "
        join_kind_descr = (join_kind_descr + "JOIN").strip()

        suspect_joins.append(
            {
                "table_name": table_name,
                "join_kind": join_kind_descr,
            }
        )

    out["total_joins"] = total_joins
    out["cross_joins_explicit"] = cross_joins_explicit
    out["suspect_joins"] = suspect_joins
    out["has_suspect_joins"] = len(suspect_joins) > 0
    return out
