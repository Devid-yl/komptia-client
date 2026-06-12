"""Handlers pour le drill-down SQL interactif (clic cellule → détail).

Conventions équipe sénior (aligné session B ``datastore.py`` + session A
``dashboard.py``) :

* **Décorateurs fail-closed eager** — Tous les endpoints exposant un pont
  vers le moteur SQL Server Sage utilisent ``@require_role("admin", "user")``.
  ``reader`` est bloqué au niveau du décorateur (résolution à l'import,
  ``ValueError`` immédiat si un rôle inconnu est listé). Ne jamais régresser
  vers ``@authenticated`` : un reader qui peut exécuter du SQL custom
  (``/api/cell-detail/execute``) serait un privilege escalation direct.

* **Rate-limit par utilisateur** — Quatre ``RateLimiter`` module-scope,
  un par endpoint coûteux. Les constantes ``RATE_LIMIT_*`` sont des
  ``Final[tuple[int, int]]`` (max_requests, window_seconds) — tunables
  sans toucher les handlers.

* **Messages d'erreur neutralisés** — Jamais ``str(exc)`` renvoyé au
  client (CWE-209). On log ``exc_info=True`` côté serveur avec
  ``extra={"request_id", "user_id"}`` et on répond un message FR
  générique + status HTTP sémantique. Les détails techniques (trace,
  SQL généré, erreur driver) restent dans les logs.

* **Validation d'entrée stricte** — ``col_index`` doit être un ``int``
  ≥ 0, ``row_values`` un ``dict``, ``max_rows`` un ``int`` dans
  ``[1, MAX_CELL_DETAIL_ROWS]``. Aucun ``TypeError`` ne doit remonter
  jusqu'à un 500 : toute entrée mal typée → 400 + message FR.

* **Body size cap** — ``MAX_SQL_PAYLOAD_BYTES`` (aligné sur
  ``datastore.py``) borne la taille du SQL envoyé. Sans ce cap, un
  client peut générer un SQL de plusieurs MB que sqlglot va parser en
  bloquant le worker event-loop (DoS asymétrique).

* **Caps multi-CTE + expand** — ``MAX_MULTI_CTE_QUERIES`` borne le
  nombre de sous-requêtes générées par ``build_drilldown_query`` en
  mode multi-CTE (si le service retourne anormalement beaucoup de
  sous-queries, on préfère tronquer que noyer le worker SQL Server).
  ``MAX_EXPANDED_EXTRA_COLS`` borne le nombre de colonnes injectées
  par ``_build_expanded_sql`` (anti-explosion combinatoire sur joins
  de tables larges).

* **Imports top-level** — ``get_sage_connector``, ``tornado.web``,
  ``Final``, ``RateLimiter`` en tête de module. Plus aucun ``import``
  à l'intérieur d'une fonction (cf. base.py règle 6).

* **TestExecuteHandler supprimé** — L'endpoint ``/api/test-execute``
  exécutait du SQL arbitraire sans validation au-delà du filtre
  ``sage_connector`` (SELECT/WITH only). Il n'était appelé par aucun
  code frontend ni test ; conserver un tel endpoint "pour debug"
  violerait le principe de moindre privilège (CWE-1220). La
  fonctionnalité "exécuter un SQL arbitraire" est déjà couverte par
  ``/api/cell-detail/execute`` avec un cap de lignes configurable.
"""

from __future__ import annotations

import re
from typing import Any, Final

import sqlglot
import tornado.web
from sqlglot import exp as sqlglot_exp

from app.core.exceptions import QueryError, SageConnectionError
from app.handlers.base import BaseHandler, _Messages, require_role, is_admin as _is_admin
from app.services.ai.drilldown import (
    analyze_columns,
    build_drill_predicate,
    build_drilldown_query,
)
from app.services.database.sage_connector import get_sage_connector
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.sql_scan import skip_sql_string, strip_leading_sql_comments

logger = get_logger(__name__)


# ── Caps & budgets ───────────────────────────────────────────────
#: Cap taille payload SQL (aligné sur ``datastore.py`` — une seule
#: source de vérité pour les SQL serialisés côté client). Au-delà,
#: sqlglot parse-lock le worker event-loop — DoS asymétrique.
MAX_SQL_PAYLOAD_BYTES: Final[int] = 256 * 1024

#: Convention Komptia : la SEULE source de vérité du plafond SQL est
#: ``DatabaseConnection.max_rows`` (saisi via /admin/database). Les caps
#: ci-dessous sont volontairement à un niveau pratiquement infini pour
#: que ``sage_connector.execute()`` applique toujours ``min(caller, admin)``
#: = config admin. **Ne JAMAIS abaisser ces valeurs** sans changer la
#: convention — un cap caller plus bas que admin écrase silencieusement
#: l'intention de l'admin (bug historique : 5_000 << admin 50_000).
MAX_DRILLDOWN_ROWS: Final[int] = 1_000_000_000
CELL_DETAIL_DEFAULT_ROWS: Final[int] = 1_000_000_000
MAX_CELL_DETAIL_ROWS: Final[int] = 1_000_000_000

#: Nombre max de sous-requêtes d'un drill-down multi-CTE. Protection
#: contre un ``build_drilldown_query`` qui exploserait (bug service)
#: et enverrait 50 queries à Sage en séquence.
MAX_MULTI_CTE_QUERIES: Final[int] = 10

#: Nombre max de colonnes additionnelles injectées par
#: ``_build_expanded_sql``. Sans cap, un SQL avec 20 joins × 50 colonnes
#: par table produit 1000 colonnes — SQL Server refuse, et le parser
#: ralentit. 200 couvre les cas raisonnables (5-10 tables × 20 col).
MAX_EXPANDED_EXTRA_COLS: Final[int] = 200

#: Largeur max de la valeur affichée dans un breadcrumb de drill-down.
#: Au-delà, on tronque avec ``..`` — pas pour la sécurité, pour l'UX.
BREADCRUMB_VALUE_MAX_LEN: Final[int] = 20

#: Fenêtre de recherche ``_build_expanded_sql`` pour détecter un alias
#: dans un fragment SQL après ``FROM``. 800 caractères couvrent des
#: joins complexes sans scanner le SQL entier pour chaque FROM.
_FROM_LOOKAHEAD_BYTES: Final[int] = 800


# ── Rate-limit quotas ────────────────────────────────────────────
#: ``/api/expand-columns`` — lourd (INFORMATION_SCHEMA query + execute
#: d'un SELECT augmenté). 30/min = plus que suffisant pour un usage
#: humain, bloque les clics rapides en boucle / abus scripté.
RATE_LIMIT_EXPAND: Final[tuple[int, int]] = (30, 60)

#: ``/api/drilldown`` — utilisé dans les boucles de paste du grid (un
#: paste peut déclencher N drills). On autorise plus généreux (60/min)
#: mais on garde le cap pour bloquer un attacker script.
RATE_LIMIT_DRILLDOWN: Final[tuple[int, int]] = (60, 60)

#: ``/api/drilldown/analyze`` — parse-only, très léger (sqlglot en RAM,
#: pas de DB). Cap plus généreux puisque le coût CPU est borné par
#: ``MAX_SQL_PAYLOAD_BYTES``.
RATE_LIMIT_ANALYZE: Final[tuple[int, int]] = (120, 60)

#: ``/api/cell-detail/execute`` — re-exécute un SQL stocké côté classeur.
#: Utilisé en lazy-load au scroll dans un détail, donc peut être appelé
#: plusieurs fois par seconde au user flow naturel.
RATE_LIMIT_CELL_DETAIL: Final[tuple[int, int]] = (60, 60)


# ── Rate-limiters instances (module-scope, thread-safe) ──────────
_expand_limiter = RateLimiter()
_drilldown_limiter = RateLimiter()
_analyze_limiter = RateLimiter()
_cell_detail_limiter = RateLimiter()


# ── Mots-clés SQL à exclure lors de l'extraction d'alias ─────────
_SQL_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "on",
        "where",
        "and",
        "or",
        "left",
        "right",
        "inner",
        "outer",
        "full",
        "cross",
        "set",
        "as",
        "select",
        "group",
        "order",
        "having",
        "union",
        "except",
        "intersect",
        "into",
        "values",
        "with",
        "case",
    }
)


# ── SQL Server : types où MAX() est invalide (error 421) ─────────
_MAX_INCOMPATIBLE_TYPES: Final[frozenset[str]] = frozenset(
    {"text", "ntext", "image", "xml", "geography", "geometry", "sql_variant"}
)


# ── Identifier validation (alphanumeric + underscore) ────────────
_SAFE_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"^\w+$")


#: Mot-clés T-SQL bannis explicitement dans ``/api/cell-detail/execute``.
#: ``sage_connector`` bloque déjà INSERT/UPDATE/DELETE/DROP/TRUNCATE/ALTER/
#: CREATE/EXEC (cf. ``sage_connector.execute`` dangerous_keywords). On
#: complète ici les vecteurs SSRF / file I/O SQL Server (CWE-918, CWE-78)
#: non couverts là-bas : un SELECT avec ``OPENROWSET('SQLOLEDB', 'server',
#: 'select ...')`` peut exfiltrer via linked server, ``BULK INSERT`` peut
#: lire un fichier réseau depuis le process SQL Server, etc.
_CELL_DETAIL_BANNED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "OPENROWSET",
        "OPENQUERY",
        "OPENDATASOURCE",
        "BULK",
        "RESTORE",
        "BACKUP",
        "MERGE",
    }
)
_CELL_DETAIL_BANNED_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(" + "|".join(_CELL_DETAIL_BANNED_KEYWORDS) + r")\b",
    re.IGNORECASE,
)


#: Cap dur sur le nombre de colonnes renvoyées par la query
#: ``INFORMATION_SCHEMA.COLUMNS`` dans ``_get_columns_for_tables``. Sans ce
#: ``TOP``, un attaquant pointant vers des vues système (``sys.columns``)
#: ou un schéma avec des tables pathologiques (>10k colonnes) ferait
#: exploser la RAM du worker et le SELECT généré. Le cap de lignes fait
#: double-emploi avec ``MAX_EXPANDED_EXTRA_COLS`` mais s'applique AVANT
#: la construction du SQL (defense-in-depth).
_INFORMATION_SCHEMA_COL_CAP: Final[int] = 10_000


#: Caractères de contrôle interdits dans le SQL reçu du client. NULL-byte
#: (``\x00``) est tronquant côté ODBC driver (la chaîne C-style), les
#: autres caractères (C0 sauf ``\t\n\r``) n'ont aucun sens dans un SQL
#: valide et servent surtout à masquer du payload dans des logs ou à
#: perturber un parseur downstream.
_FORBIDDEN_CONTROL_CHARS: Final[frozenset[str]] = frozenset(
    chr(c) for c in range(0x00, 0x20) if chr(c) not in "\t\n\r"
)


# ── Re-export pour compat backward tests ─────────────────────────
#: Les tests importent ``_skip_sql_string`` depuis ce module comme nom
#: privé. On garde le re-export pour ne pas casser la suite de tests
#: existante (``tests/unit/test_drilldown.py``).
_skip_sql_string = skip_sql_string


# ── Sentinelle de contrôle pour le chemin LLM de drill-down ──────
#: ``_try_llm_drilldown`` retourne soit un ``str`` (SQL prêt à exécuter), soit
#: ``_DRILL_DENIED`` (refus data-access, 403 déjà écrite), soit ``None``
#: (échec doux OU verdict « rien à détailler » → on laisse le programmatique
#: trancher — cf. S1). On n'a plus de sentinelle « unchanged » dédiée : le
#: fallback programmatique produit lui-même ``{"unchanged": True}`` au besoin.
_DRILL_DENIED: Final[object] = object()  # refus data-access (réponse 403 déjà écrite)


# ═══════════════════════════════════════════════════════════════════
# Helpers : extraction de tables / colonnes
# ═══════════════════════════════════════════════════════════════════


def _extract_tables(sql: str) -> dict[str, str]:
    """Extrait ``{alias: table_name}`` depuis un SQL, en excluant les CTE.

    Utilise sqlglot (dialect TSQL) pour parser les identifiants entre
    crochets, les noms schema-qualifiés, les joins virgule, etc.
    Fallback regex si sqlglot échoue (SQL très non-standard).
    """
    try:
        return _extract_tables_sqlglot(sql)
    except Exception:
        logger.debug("sqlglot parse failed, falling back to regex", exc_info=True)
        return _extract_tables_regex(sql)


def _extract_tables_sqlglot(sql: str) -> dict[str, str]:
    """Extrait les tables via l'AST sqlglot — gère toute la syntaxe SQL Server."""
    parsed = sqlglot.parse(sql, dialect="tsql")
    if not parsed or parsed[0] is None:
        raise ValueError("sqlglot returned empty parse")

    ast = parsed[0]

    cte_names: set[str] = set()
    for cte_node in ast.find_all(sqlglot_exp.CTE):
        name = cte_node.alias
        if name:
            cte_names.add(name.lower())

    tables: dict[str, str] = {}
    for table_node in ast.find_all(sqlglot_exp.Table):
        table_name = table_node.name
        alias = table_node.alias or table_name

        if not table_name:
            continue
        # Les tables schema-qualifiées (``dbo.Orders``) sont réelles même
        # si un CTE partage le même nom de base — on ne filtre que les
        # refs non-qualifiées. Note : un SQL ``WITH x AS (...) SELECT *
        # FROM dbo.x`` est syntaxiquement invalide côté SQL Server (CTE
        # ne peut pas être schema-qualifié), donc la requête échoue côté
        # Sage si un attaquant tente ce bypass — ``connector.execute``
        # remonte alors un ``QueryError`` géré par le handler.
        is_schema_qualified = bool(table_node.args.get("db") or table_node.args.get("catalog"))
        if not is_schema_qualified and table_name.lower() in cte_names:
            continue
        if alias.lower() in _SQL_KEYWORDS:
            continue
        if alias not in tables:
            tables[alias] = table_name

    return tables


def _extract_tables_regex(sql: str) -> dict[str, str]:
    """Fallback regex : extrait les tables (gère brackets + préfixes schema)."""
    cte_names: set[str] = set()
    for m in re.finditer(r"\bWITH\s+\[?(\w+)\]?\s+AS\s*\(", sql, re.IGNORECASE):
        cte_names.add(m.group(1).lower())
    for m in re.finditer(r",\s*\[?(\w+)\]?\s+AS\s*\(", sql, re.IGNORECASE):
        cte_names.add(m.group(1).lower())

    tables: dict[str, str] = {}
    for m in re.finditer(
        r"\b(?:FROM|JOIN)\s+"
        r"(?:(?:\[?\w+\]?\.){0,2})"  # schema optionnel (jusqu'à 2 niveaux)
        r"\[?(\w+)\]?"  # nom de table
        r"\s+(?:AS\s+)?"  # whitespace + AS optionnel
        r"\[?(\w+)\]?",  # alias
        sql,
        re.IGNORECASE,
    ):
        table, alias = m.group(1), m.group(2)
        if alias.lower() in _SQL_KEYWORDS or table.lower() in cte_names:
            continue
        if alias not in tables:
            tables[alias] = table
    return tables


async def _get_columns_for_tables(connector: Any, tables: dict[str, str]) -> dict[str, list[str]]:
    """Retourne ``{alias: [col_name, ...]}`` via INFORMATION_SCHEMA.

    Exclut les types où MAX() est invalide côté SQL Server (text, ntext,
    image, xml, geography, geometry, sql_variant) — sinon les SQL avec
    GROUP BY expansés via ``_build_expanded_sql`` crashent avec
    l'erreur 421 à l'exécution.
    """
    result: dict[str, list[str]] = {}
    table_names = list(set(tables.values()))
    if not table_names:
        return result

    # Valide les noms de tables : alphanum + underscore uniquement. Les
    # noms exotiques (avec espaces, accents) ne passent pas — defense in
    # depth contre SQL injection via nom de table user-fourni (même si
    # le SQL est déjà parsé par sqlglot avant).
    safe_names = [t for t in table_names if _SAFE_IDENT_RE.match(t)]
    if not safe_names:
        return result

    placeholders = ", ".join(["?"] * len(safe_names))
    # ``TOP N`` — defense-in-depth contre une table pathologique ou un
    # attaquant qui pointerait vers ``sys.columns``. Au-delà de ``N``
    # colonnes, ``_build_expanded_sql`` ferait de toute façon sauter le
    # cap ``MAX_EXPANDED_EXTRA_COLS`` ; on n'a aucun intérêt à charger
    # 500k lignes en RAM juste pour en jeter 99%.
    qr = await connector.execute(
        f"SELECT TOP {_INFORMATION_SCHEMA_COL_CAP} "
        f"TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS "
        f"WHERE TABLE_NAME IN ({placeholders}) ORDER BY TABLE_NAME, ORDINAL_POSITION",
        params=safe_names,
    )
    cols_by_table: dict[str, list[str]] = {}
    for row in qr.rows:
        data_type = (row[2] or "").lower()
        if data_type in _MAX_INCOMPATIBLE_TYPES:
            continue
        cols_by_table.setdefault(row[0], []).append(row[1])

    for alias, table_name in tables.items():
        result[alias] = cols_by_table.get(table_name, [])
    return result


def _has_group_by_at_depth(sql: str, from_pos: int, target_depth: int) -> bool:
    """Indique si un ``GROUP BY`` existe au même niveau de parenthèses que ``FROM``."""
    depth = target_depth
    i = from_pos
    while i < len(sql):
        ch = sql[i]
        if ch == "'":
            i = _skip_sql_string(sql, i)
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < target_depth:
                return False
        elif depth == target_depth and sql[i : i + 5].upper() == "GROUP":
            if i == 0 or not sql[i - 1].isalnum():
                rest = sql[i + 5 : i + 20].lstrip()
                if rest.upper().startswith("BY") and (len(rest) < 3 or not rest[2:3].isalnum()):
                    return True
        i += 1
    return False


def _build_expanded_sql(sql: str, columns_by_alias: dict[str, list[str]]) -> str:
    """Insère les colonnes désambiguisées dans le SELECT ciblant les tables réelles.

    Quand le SELECT cible contient un GROUP BY, les colonnes extra sont
    wrappées dans ``MAX(...)`` pour éviter l'erreur SQL Server 8120
    (colonne hors agrégat ou GROUP BY).

    Cap total via ``MAX_EXPANDED_EXTRA_COLS`` — un SQL avec 20 joins × 50
    colonnes/table produirait 1000 colonnes, ce qui (a) refuse côté SQL
    Server (max 1024), (b) explose en parsing.
    """
    alias_set = set(columns_by_alias.keys())

    # Cherche le ``FROM`` dont le contexte voisin contient au moins un
    # alias de table réelle. Avec des CTE, les vraies tables sont INSIDE
    # le body CTE (depth > 0) alors que le SELECT externe référence le
    # nom du CTE (pas d'alias réel).
    depth = 0
    i = 0
    target_from = None
    target_depth = 0
    while i < len(sql):
        if sql[i] == "'":
            i = _skip_sql_string(sql, i)
        elif sql[i] == "(":
            depth += 1
        elif sql[i] == ")":
            depth -= 1
        elif sql[i : i + 4].upper() == "FROM" and (i == 0 or not sql[i - 1].isalnum()):
            # Fenêtre ``_FROM_LOOKAHEAD_BYTES`` = heuristique performante
            # (éviter de scanner 256KB pour chaque FROM) MAIS on élargit
            # au scope complet du FROM s'il s'étend au-delà : on cherche
            # le prochain ``)`` qui ramène au depth courant (fin du scope)
            # ou la fin du SQL. Cela couvre les JOIN chains longues (>800
            # chars) où l'alias apparaît tardivement.
            rest_window = sql[i : i + _FROM_LOOKAHEAD_BYTES]
            has_alias = any(re.search(r"\b" + re.escape(a) + r"\b", rest_window) for a in alias_set)
            if not has_alias and len(sql) - i > _FROM_LOOKAHEAD_BYTES:
                # Seconde passe : scope complet du FROM (jusqu'à la fin
                # du scope ou du SQL). Plus cher mais borné par
                # MAX_SQL_PAYLOAD_BYTES donc O(n) maîtrisé.
                rest_full = sql[i:]
                has_alias = any(
                    re.search(r"\b" + re.escape(a) + r"\b", rest_full) for a in alias_set
                )
            if has_alias:
                target_from = i
                target_depth = depth
                break
        i += 1

    if target_from is None:
        return sql

    has_group_by = _has_group_by_at_depth(sql, target_from, target_depth)

    # Construit les expressions de colonnes supplémentaires, borné par
    # MAX_EXPANDED_EXTRA_COLS. Si on atteint le cap, on log en warning
    # et on tronque — la feature devient partielle mais n'explose pas.
    extra_parts: list[str] = []
    for alias, cols in columns_by_alias.items():
        if not _SAFE_IDENT_RE.match(alias):
            continue
        for col in cols:
            if not _SAFE_IDENT_RE.match(col):
                continue
            if has_group_by:
                extra_parts.append(f"MAX([{alias}].[{col}]) AS [{alias}_{col}]")
            else:
                extra_parts.append(f"[{alias}].[{col}] AS [{alias}_{col}]")
            if len(extra_parts) >= MAX_EXPANDED_EXTRA_COLS:
                break
        if len(extra_parts) >= MAX_EXPANDED_EXTRA_COLS:
            logger.warning(
                "expand-columns: cap atteint, colonnes extra tronquées",
                extra={"cap": MAX_EXPANDED_EXTRA_COLS, "aliases": list(alias_set)},
            )
            break

    if not extra_parts:
        return sql

    extra_select = ", ".join(extra_parts)
    return sql[:target_from] + ", " + extra_select + " " + sql[target_from:]


# ═══════════════════════════════════════════════════════════════════
# Helpers : rate-limit, validation, error shape
# ═══════════════════════════════════════════════════════════════════


def _check_rate_limit(
    limiter: RateLimiter, user_id: Any, max_requests: int, window_seconds: int
) -> None:
    """Lève ``HTTPError(429)`` si le rate-limit user est dépassé.

    Pattern aligné sur ``app/handlers/datastore.py`` et
    ``app/handlers/contacts.py`` — un seul endroit où décider du status,
    du message et du format de la clé.

    **Refus d'un ``user_id`` non-int** : si un régression de l'auth faisait
    remonter ``current_user.id is None`` ou un type exotique, la clé
    devient ``"user:None"`` et tous les clients anonymes partageraient le
    même bucket (DoS croisé ou bypass trivial). On fail-close en 500 —
    préférable à un silent share-bucket.
    """
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        logger.error(
            "rate-limit: user_id invalide (fail-closed)",
            extra={"user_id_type": type(user_id).__name__},
        )
        raise tornado.web.HTTPError(500, _Messages.INTERNAL_ERROR)
    key = f"user:{user_id}"
    if not limiter.check(key, max_requests=max_requests, window_seconds=window_seconds):
        raise tornado.web.HTTPError(
            429,
            "Trop de requêtes. Veuillez patienter quelques secondes.",
        )


def _quote_sql_identifier(name: str) -> str:
    """Bracket-quote un identifiant T-SQL pour usage comme membre gauche de
    prédicat (``[name]``), en échappant ``]`` → ``]]``.

    Utilisé pour la normalisation de scope du drill-down : quand le marqueur de
    filtre est dans la requête externe, on binde la COLONNE DE SORTIE plutôt que
    l'expression interne du LLM (alias de CTE invisible dehors). Même convention
    que les filtres externes du LLM (``[grpCodeEntite]``) et que le chemin
    programmatique (``drilldown._build_where_conditions`` → ``f"[{dim}]"``), mais
    avec échappement défensif de ``]`` (anti-injection sur noms exotiques)."""
    return "[" + str(name).replace("]", "]]") + "]"


def _is_safe_bound_sql(sql: str) -> bool:
    """Re-vérifie qu'un SQL de détail (drill-down) bindé est une lecture pure.

    ``iris_oneshot.build_drilldown_sql_via_llm`` a déjà validé le squelette via
    ``_is_safe_select`` ; on revalide APRÈS l'injection locale des prédicats de
    dimension — premier mot-clé SELECT/WITH + aucun mot-clé SSRF/file-I/O banni.
    Le ``sage_connector`` re-filtre de toute façon à l'exécution : c'est une
    couche de défense en profondeur, pas l'unique rempart. Module-level (pas
    une méthode) pour rester testable indépendamment du handler."""
    sql_body = strip_leading_sql_comments(sql)
    first_keyword = sql_body.split(None, 1)[0].upper() if sql_body else ""
    if first_keyword not in ("SELECT", "WITH"):
        return False
    if _CELL_DETAIL_BANNED_RE.search(sql_body):
        return False
    return True


def _enforce_sql_size(sql: str) -> None:
    """Lève ``HTTPError(413)`` si le SQL dépasse ``MAX_SQL_PAYLOAD_BYTES``.

    Mesure la taille **avant** tout ``strip()`` pour éviter qu'un attaquant
    envoie 256KB de SQL + 10MB de whitespace : la chaîne brute reste
    allouée dans le body JSON parsé, et un ``sql.strip()`` préalable
    masquerait l'abus sans libérer la RAM déjà consommée.
    """
    if len(sql.encode("utf-8")) > MAX_SQL_PAYLOAD_BYTES:
        raise tornado.web.HTTPError(
            413,
            f"Requête SQL trop volumineuse (max {MAX_SQL_PAYLOAD_BYTES // 1024} Ko).",
        )


def _require_sql(body: dict[str, Any], key: str = "sql") -> str:
    """Extrait et valide une clé SQL du body — lève ``HTTPError(400)`` si vide.

    Rejette les caractères de contrôle C0 (hors ``\\t\\n\\r``) : un NULL-byte
    peut être tronquant côté driver ODBC (C-style strings), et les autres
    C0 n'ont pas leur place dans un SQL valide. Refuser plutôt que
    sanitiser — c'est le client qui est buggé/malveillant.
    """
    raw = body.get(key)
    if not isinstance(raw, str):
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    # Cap de taille appliqué sur la string brute avant ``.strip()`` pour
    # ne pas masquer un padding whitespace gigantesque.
    _enforce_sql_size(raw)
    if any(ch in _FORBIDDEN_CONTROL_CHARS for ch in raw):
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    sql = raw.strip()
    if not sql:
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    return sql


# Sentinel privé pour distinguer "default absent" de "default=None valide".
_MISSING: Final[object] = object()


def _require_int(
    body: dict[str, Any],
    key: str,
    *,
    default: Any = _MISSING,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Extrait et valide un entier du body.

    ``body[key]`` doit être un ``int`` (et pas ``bool``, car ``isinstance(True, int)``
    vaut ``True`` en Python — un attacker pourrait passer ``true`` qui serait
    accepté comme ``1``). Lève ``HTTPError(400)`` si mal typé ou hors bornes.

    Si ``default`` est fourni (même ``None``), un ``body[key] is None``
    explicite ou une clé absente rebascule sur ``default`` **sans** rejet ;
    passer le défaut dédouane d'un fail 400 sur absence.
    """
    raw = body.get(key, _MISSING)
    if raw is _MISSING or raw is None:
        if default is _MISSING:
            raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
        raw = default
    # bool est une sous-classe de int — on refuse explicitement.
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    if minimum is not None and raw < minimum:
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    if maximum is not None and raw > maximum:
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    return raw


def _require_dict(body: dict[str, Any], key: str) -> dict[str, Any]:
    """Extrait et valide un dict du body — lève ``HTTPError(400)`` si mal typé."""
    raw = body.get(key, {})
    if not isinstance(raw, dict):
        raise tornado.web.HTTPError(400, _Messages.INVALID_PARAMETER)
    return raw


def _log_extra(handler: BaseHandler, **extra: Any) -> dict[str, Any]:
    """Prépare un dict ``extra=`` pour ``logger`` avec request_id + user_id."""
    data = {
        "request_id": getattr(handler, "request_id", "?"),
        "user_id": getattr(handler.current_user, "id", None),
    }
    data.update(extra)
    return data


def _safe_truncate(value: Any, max_len: int) -> str:
    """Tronque la str de ``value`` à ``max_len`` caractères + ``..``.

    Sûr pour Unicode (slice sur codepoint, pas sur byte). Utilisé pour
    construire des breadcrumbs user-facing.
    """
    s = str(value)
    if len(s) <= max_len:
        return s
    return s[:max_len] + ".."


def _build_breadcrumb(
    column_metadata: list[dict[str, Any]],
    col_index: int,
    row_values: dict[str, Any],
) -> str:
    """Construit un breadcrumb lisible pour le drill-down."""
    if col_index < 0 or col_index >= len(column_metadata):
        return "Détail"

    col = column_metadata[col_index]
    dims = col.get("filter_dimensions", [])

    if not dims:
        return f"Détail — {col['name']} (tout)"

    parts = []
    for dim in dims:
        val = row_values.get(dim)
        if val is None:
            parts.append(f"{dim}=NULL")
        else:
            parts.append(f"{dim}={_safe_truncate(val, BREADCRUMB_VALUE_MAX_LEN)}")

    return "Détail — " + ", ".join(parts)


def _json_query_error(message: str) -> dict[str, Any]:
    """Shape JSON standard pour une erreur de query (multi-CTE partial fail).

    Pour les erreurs SQL qui doivent inclure SQLSTATE + catégorie + sanitization
    PII mode invisible, préférer :func:`_json_query_error_for_exc` (async,
    audit P2.4 2026-05-26).
    """
    return {"error": message}


async def _json_query_error_for_exc(
    exc: BaseException,
    user: Any,
    *,
    audience: str = "user",
) -> dict[str, Any]:
    """**P2.4 (audit 2026-05-26)** — Shape JSON enrichi pour une exception SQL.

    Délègue à :func:`sanitize_sql_for_client` (SSoT P2.1) : retourne un dict
    ``{error, category, sqlstate}`` au lieu du message générique précédent
    « Cette sous-requête n'a pas pu être exécutée. » / « La requête de détail
    n'a pas pu être exécutée. » qui masquait totalement le diagnostic.

    Args:
        exc: l'exception SQL (``QueryError``, ``SageConnectionError``, etc.).
        user: l'utilisateur courant — sert à la sanitization PII mode invisible.
        audience: ``"user"`` (défaut) ou ``"admin"``. Utilisé via ``is_admin()``
            côté caller pour différencier.

    Returns:
        ``{"error": <hint catégoriel FR>, "category": <str>, "sqlstate": <str|None>}``
    """
    from app.services.data_access.error_messages import sanitize_sql_for_client

    payload = await sanitize_sql_for_client(exc, user, audience=audience)
    return {
        "error": payload["message"],
        "category": payload["category"],
        "sqlstate": payload["sqlstate"],
    }


# ═══════════════════════════════════════════════════════════════════
# Handlers
# ═══════════════════════════════════════════════════════════════════


class ExpandColumnsHandler(BaseHandler):
    """``POST /api/expand-columns`` — Élargit le SELECT à toutes les colonnes.

    Appelé quand l'utilisateur clique « Charger toutes les colonnes ».
    Stratégie : délègue la transformation à ``ask_iris`` en mode
    ``transform_via_llm=True`` — le LLM lit le SQL et y rajoute les
    colonnes manquantes, ce qui couvre les cas que la version programmatique
    sqlglot/regex (UNION, TVF, window functions, identifiants exotiques,
    sous-requêtes corrélées) ne savait pas traiter.

    La consigne envoyée au LLM est ``LOAD_ALL_COLUMNS_TASK_PROMPT`` —
    statique côté handler, seul ``draft_sql`` varie. Defense-in-depth :

    * validation post-LLM contre INFORMATION_SCHEMA (gérée par ``ask_iris``)
    * SQL transformé re-soumis au RLS centralisé
    * exécution via le ``QueryExecutor`` standard
    * cap dur ``MAX_DRILLDOWN_ROWS`` côté driver

    Helpers programmatiques (``_extract_tables``, ``_get_columns_for_tables``,
    ``_build_expanded_sql``) conservés dans ce module — ils ne sont plus
    appelés ici mais peuvent servir de fallback ad-hoc ou à des tests.
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_expand_limiter, user.id, *RATE_LIMIT_EXPAND)

        body = self.get_json_body() or {}
        sql = _require_sql(body)

        # ── 1. RLS pré-flight sur le SQL d'entrée ──
        # On bloque AVANT le LLM si l'utilisateur n'a pas accès aux tables
        # référencées : sinon le DDL des tables interdites partirait au LLM
        # cloud (fuite de schéma multi-tenant) avant même d'être refusé.
        # ``enforce_for_executor`` ajoute des WHERE RLS au SQL si besoin et
        # lève si une table est totalement interdite. On le ré-applique APRÈS
        # transformation pour couvrir le SQL final (idempotent côté enforcer).
        from app.services.data_access import enforcer as _da_enforcer

        try:
            sql = await _da_enforcer.enforce_for_executor(
                sql, user, source="drilldown_expand_columns_preflight"
            )
        except _da_enforcer.DataAccessDeniedError as exc:
            self.write_json({"error": exc.user_message}, 403)
            return

        # ── 2. Délégation à ask_iris en mode transformation LLM ──
        from app.services.ai.copilot_iris_bridge import ask_iris
        from app.services.ai.iris_oneshot import LOAD_ALL_COLUMNS_TASK_PROMPT
        from app.utils.request_context import llm_call_context

        try:
            with llm_call_context(caller="iris_oneshot_load_all_cols"):
                bridge_result = await ask_iris(
                    task=LOAD_ALL_COLUMNS_TASK_PROMPT,
                    draft_sql=sql,
                    execute=False,  # on exécute manuellement après RLS
                    max_rows=MAX_DRILLDOWN_ROWS,
                    pseudonymizer=None,  # contexte HTTP, pas de pseudo
                    cache=None,
                    # ``user`` (objet ORM) : sans lui, le dry-run interne de
                    # ``ask_iris`` (execute=False → TOP 5) tournait SANS RLS
                    # (``enforcer`` loggue « RLS skip ») — un user restreint
                    # validait alors un SQL qu'il n'a pas le droit d'exécuter,
                    # incohérent avec l'enforce post-transform plus bas. On
                    # propage l'objet pour que le RLS s'applique dès le dry-run
                    # (defense-in-depth, aligné copilot_iris_bridge).
                    user=user,
                    # ``user.id`` thread le proxy d'anonymisation jusqu'à
                    # ``transform_sql_via_llm`` (pseudonymizer user-scoped
                    # + couche PII regex). Le draft_sql peut contenir des
                    # littéraux (emails / SIRET dans les WHERE) — sans
                    # ``user_id``, ils partiraient cleartext au LLM cloud.
                    user_id=getattr(user, "id", None),
                )
        except Exception as exc:
            logger.error(
                "expand-columns: ask_iris transform a levé",
                extra=_log_extra(self, error=exc.__class__.__name__),
                exc_info=True,
            )
            self.write_json({"error": "Erreur interne lors de la transformation IA."}, 500)
            return

        bridge_errors = bridge_result.get("errors") or []
        validated = bool(bridge_result.get("validated"))
        expanded_sql = bridge_result.get("sql") or ""

        if not validated or not isinstance(expanded_sql, str) or not expanded_sql.strip():
            # Message CLAIR par audience (taxonomie 4-cas, axe distinction
            # admin/user). Le détail technique du bridge (``sql_server_says`` /
            # ``suggested_fix`` de l'oracle — ex. « Lis le message SQL Server…
            # datepart keywords… ») est conçu pour qu'IRIS-AGENT s'auto-corrige,
            # PAS pour une analyste financière. On le réserve donc aux admins +
            # logs ; l'utilisateur voit un message métier actionnable. Les cas
            # fréquents (colonnes en double) sont déjà corrigés en amont par la
            # déduplication déterministe (``ask_iris``) → ce chemin ne reste que
            # pour les requêtes réellement non-élargissables.
            _audience_admin = _is_admin(self.current_user)
            if _audience_admin and bridge_errors:
                user_msg = bridge_errors[0]
            else:
                user_msg = (
                    "L'élargissement automatique n'a pas pu être appliqué à cette "
                    "requête (trop complexe pour l'IA). Le tableau actuel est "
                    "conservé. Réessaie, ou contacte ton administrateur si le "
                    "problème persiste."
                )
            logger.warning(
                "expand-columns: transformation IA refusée",
                extra=_log_extra(
                    self,
                    errors_count=len(bridge_errors),
                    # Détail technique en LOG (traçable admin), jamais au user.
                    first_error=(str(bridge_errors[0])[:200] if bridge_errors else None),
                    has_suggestions=bool(bridge_result.get("schema_suggestions")),
                ),
            )
            payload: dict[str, Any] = {"error": user_msg}
            suggestions = bridge_result.get("schema_suggestions")
            if suggestions:
                payload["schema_suggestions"] = suggestions
            self.write_json(payload, 400)
            return

        # Compare SQL d'entrée et SQL transformé en normalisant les espaces —
        # le LLM peut rajouter du formatting cosmétique sans rien ajouter
        # comme colonne. Si vraiment rien de neuf après normalisation : 400.
        def _norm_ws(s: str) -> str:
            return " ".join(s.split()).lower()

        if _norm_ws(expanded_sql) == _norm_ws(sql):
            self.write_json({"error": "Aucune colonne supplémentaire trouvée."}, 400)
            return

        # ── 3. RLS post-transform sur le SQL final ──
        try:
            expanded_sql = await _da_enforcer.enforce_for_executor(
                expanded_sql, user, source="drilldown_expand_columns"
            )
        except _da_enforcer.DataAccessDeniedError as exc:
            self.write_json({"error": exc.user_message}, 403)
            return

        connector = get_sage_connector()
        try:
            result = await connector.execute(expanded_sql, max_rows=MAX_DRILLDOWN_ROWS)
        except QueryError as exc:
            logger.warning(
                "expand-columns: exécution du SQL élargi a échoué",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
            )
            # P2.4 follow-up (audit P7 2026-05-26) — site manqué dans la
            # première passe P2.4. Migration vers le helper SSoT P2.1.
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 400)
            return
        except SageConnectionError as exc:
            logger.error(
                "expand-columns: Sage indisponible",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
                exc_info=True,
            )
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 503)
            return

        rows_data = [list(row) for row in result.rows]
        self.write_json(
            {
                "columns": result.columns,
                "rows": rows_data,
                "row_count": result.row_count,
                "execution_time_ms": result.execution_time_ms,
                "sql": expanded_sql,
                "truncated": result.truncated,
            }
        )


class DrillDownHandler(BaseHandler):
    """``POST /api/drilldown`` — « Voir le détail » : génère + exécute la requête
    de détail derrière une cellule agrégée.

    Input : ``original_sql``, ``col_index``, ``row_values`` (valeurs de la
    ligne cliquée). Output : single-query (``columns``, ``rows``, ...) ou
    multi-query (``multi=True``, ``results=[...]`` si CTE multiples).

    **Génération via LLM** (``iris_oneshot.build_drilldown_sql_via_llm``) : le
    LLM reçoit toute la STRUCTURE (SQL d'origine + DDL + colonne cliquée +
    métadonnées d'analyse) mais JAMAIS les valeurs de la ligne (confidentialité
    Niveau 4/5) ; il renvoie un squelette SQL + le mapping des dimensions, et le
    SYSTÈME binde ici les vraies valeurs localement. Le générateur programmatique
    ``build_drilldown_query`` reste le FALLBACK (LLM indisponible/échec) et le
    chemin des colonnes multi-CTE (plusieurs result sets — UX préservée).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_drilldown_limiter, user.id, *RATE_LIMIT_DRILLDOWN)

        body = self.get_json_body() or {}
        original_sql = _require_sql(body, "original_sql")
        col_index = _require_int(body, "col_index", default=-1)
        row_values = _require_dict(body, "row_values")

        # col_index négatif = pas de dimension ciblée → breadcrumb "tout".
        column_metadata = analyze_columns(original_sql)
        breadcrumb = _build_breadcrumb(column_metadata, col_index, row_values)
        connector = get_sage_connector()

        clicked_meta = (
            column_metadata[col_index]
            if isinstance(column_metadata, list) and 0 <= col_index < len(column_metadata)
            else {}
        )

        # ── 1. Chemin LLM (mono-requête uniquement) ──
        # Les colonnes multi-CTE (mesure calculée référençant plusieurs CTE
        # agrégées) gardent le chemin programmatique : il produit N result sets
        # distincts (UX multi-blocs) que le one-shot mono-SQL ne reproduit pas.
        if not (isinstance(clicked_meta, dict) and clicked_meta.get("source_ctes")):
            llm_outcome = await self._try_llm_drilldown(
                original_sql, col_index, row_values, column_metadata, clicked_meta
            )
            if llm_outcome is _DRILL_DENIED:
                return  # refus data-access : réponse 403 déjà écrite
            if isinstance(llm_outcome, str):
                await self._execute_single(llm_outcome, breadcrumb, connector)
                return
            # llm_outcome is None → fallback programmatique ci-dessous

        # ── 2. Fallback programmatique (LLM indisponible/échec, ou multi-CTE) ──
        try:
            drilldown_result = build_drilldown_query(
                original_sql, col_index, row_values, column_metadata
            )
        except Exception:
            logger.exception(
                "[DrillDown] build_drilldown_query a crashé",
                extra=_log_extra(self, col_index=col_index),
            )
            self.write_json({"error": _Messages.INTERNAL_ERROR}, 500)
            return

        if drilldown_result is None:
            self.write_json({"unchanged": True})
            return

        if isinstance(drilldown_result, list):
            await self._execute_multi_cte(drilldown_result, breadcrumb, connector)
        else:
            await self._execute_single(drilldown_result, breadcrumb, connector)

    async def _try_llm_drilldown(
        self,
        original_sql: str,
        col_index: int,
        row_values: dict[str, Any],
        column_metadata: list[dict[str, Any]],
        clicked_meta: dict[str, Any],
    ) -> Any:
        """Génère le SQL de détail via LLM puis binde LOCALEMENT les valeurs.

        **Confidentialité** : ``row_values`` (vraies données Sage) n'est JAMAIS
        passé au LLM — seuls les NOMS de colonnes le sont. Les valeurs sont
        injectées ici, à la place du marqueur ``_DRILL_FILTERS_SENTINEL``.

        Returns:
            * ``str`` : SQL final prêt à exécuter ;
            * ``_DRILL_DENIED`` : refus data-access (réponse 403 déjà écrite) ;
            * ``None`` : échec doux OU verdict LLM « rien à détailler » → le
              caller bascule sur le fallback programmatique, qui tranche
              (``{"unchanged": True}`` s'il n'y a vraiment rien). Jamais un
              crash visible.
        """
        from app.services.ai.iris_oneshot import (
            _DRILL_FILTERS_SENTINEL,
            build_drilldown_sql_via_llm,
            marker_outer_scope_over_cte,
            outer_select_computed_aliases,
        )
        from app.services.data_access.error_messages import DataAccessLeakDetectedError

        user = self.current_user
        clicked_column = ""
        expected_dims: list[str] = []
        if isinstance(clicked_meta, dict):
            clicked_column = str(clicked_meta.get("name") or "")
            # Vérité-terrain des dimensions de regroupement (analyze_columns) :
            # sert (a) à guider le LLM dans le prompt, (b) au garde de couverture
            # fail-closed ci-dessous (F1/F3/F7).
            raw_fd = clicked_meta.get("filter_dimensions")
            if isinstance(raw_fd, list):
                expected_dims = [d for d in raw_fd if isinstance(d, str) and d]

        try:
            skeleton, dimensions, errors = await build_drilldown_sql_via_llm(
                original_sql=original_sql,
                clicked_column=clicked_column,
                result_columns=list(row_values.keys()),
                col_index=col_index,
                column_metadata=column_metadata,
                expected_dimensions=expected_dims,
                user_role="admin" if _is_admin(user) else "user",
                user_id=getattr(user, "id", None),
            )
        except DataAccessLeakDetectedError as exc:
            # Nom de table interdit halluciné par le LLM (mode invisible) →
            # refus net, PAS de fallback (le nom ne doit pas réapparaître).
            logger.info(
                "[DrillDown] refus data_access sur SQL LLM (mode invisible)",
                extra=_log_extra(self),
            )
            self.write_json({"error": exc.user_message}, 403)
            return _DRILL_DENIED
        except Exception:
            logger.warning(
                "[DrillDown] build_drilldown_sql_via_llm a levé — fallback programmatique",
                extra=_log_extra(self),
                exc_info=True,
            )
            return None

        if errors or skeleton is None:
            # Échec doux (parse/troncature/anonymisation/DDL absent) → fallback
            # programmatique silencieux. On log pour traçabilité.
            if errors:
                logger.info(
                    "[DrillDown] LLM drilldown errors — fallback programmatique",
                    extra=_log_extra(self, first_error=str(errors[0])[:120]),
                )
            return None

        if skeleton == "":
            # S1 — Le LLM juge la cellule « rien à détailler ». On ne s'y fie
            # PAS aveuglément : un LLM trop prudent refuserait un drill que le
            # programmatique trouverait. On bascule donc sur le programmatique,
            # qui tranche (None → « unchanged » s'il n'y a vraiment rien à
            # détailler, sinon il produit le détail).
            logger.info(
                "[DrillDown] LLM juge non-drillable — arbitrage via programmatique",
                extra=_log_extra(self),
            )
            return None

        # ── Binding LOCAL des valeurs (jamais envoyées au LLM) ──
        # Normalisation de scope (FIX RACINE incident 2026-06-03) : si le
        # marqueur de filtre est dans la requête EXTERNE (hors CTE), les alias
        # de table internes fournis par le LLM (ex. ``Col01.colCodeCollabo``) n'y
        # sont PAS visibles → SQL Server 4104 « multi-part identifier cannot be
        # bound ». Dans ce scope on binde la COLONNE DE SORTIE ``[col]`` (qui,
        # elle, EST visible), exactement comme le chemin programmatique
        # (``drilldown._build_where_conditions`` R4 : ``amap.get(dim) or [dim]``).
        # Sinon (marqueur dans le corps d'une CTE), l'expression interne du LLM
        # est le bon référent. Le système TRANCHE programmatiquement le scope —
        # le LLM ne devine pas.
        bind_output_column = marker_outer_scope_over_cte(skeleton)
        # En scope externe sur CTE : résoudre les alias CALCULÉS dans la requête
        # externe (``YEAR(c.d) AS annee``) vers leur expression — sinon ``[annee]``
        # est soit non référençable en WHERE (207), soit pire un shadowing sur une
        # colonne de base homonyme = filtre faux silencieux (adversarial review,
        # Q5). Colonnes matérialisées / ``SELECT *`` → absentes de la map →
        # fallback ``[col]``. Mirror du chemin programmatique R4.
        outer_alias_map = outer_select_computed_aliases(skeleton) if bind_output_column else {}
        predicates: list[str] = []
        bound_cols: set[str] = set()
        for col, expr in dimensions.items():
            if col not in row_values:
                continue
            if bind_output_column:
                lhs = outer_alias_map.get(col.lower()) or _quote_sql_identifier(col)
            else:
                lhs = expr
            predicate = build_drill_predicate(lhs, row_values[col])
            if predicate is not None:
                predicates.append(predicate)
                bound_cols.add(col)

        # F1/F3/F7 — Garde de COUVERTURE (fail-closed). Le système connaît la
        # vérité-terrain des dimensions de regroupement (``filter_dimensions``
        # d'``analyze_columns``). Si UNE seule n'est pas effectivement bindée,
        # exécuter le détail produirait un filtrage INCOMPLET = des lignes
        # d'autres groupes présentées comme « le détail » de cette cellule
        # (données fausses silencieuses, doctrine Q5). On bascule alors sur le
        # programmatique.
        #
        # Nuance (R3) : pour les causes « LLM a OMIS la dimension » ou « expr
        # rejetée », le programmatique re-dérive le filtre correct depuis sa
        # propre analyse → fallback FIABLE. En revanche si la VALEUR elle-même
        # est inliable (``inf``/``nan``, ou clé absente de ``row_values``),
        # ``build_drill_predicate`` retourne None dans LES DEUX chemins : le
        # programmatique sous-filtrera pareil. Ce cas est pratiquement
        # inatteignable (le front sérialise inf/nan en ``null`` → ``IS NULL``,
        # bindable ; seul un body JSON forgé envoie ``NaN``/``Infinity``), donc
        # on accepte la dégradation plutôt que d'ajouter une branche dédiée.
        expected = {d for d in (expected_dims or []) if isinstance(d, str)}
        if expected and not expected.issubset(bound_cols):
            logger.warning(
                "[DrillDown] dimensions de regroupement non couvertes par le LLM "
                "— fallback programmatique",
                extra=_log_extra(self, missing_dims=sorted(expected - bound_cols)[:10]),
            )
            return None

        # Bloc de filtres PARENTHÉSÉ (F4/F5, defense-in-depth) : même si une
        # expression résiduelle contenait un connecteur, le groupe ``( … )``
        # empêche qu'un OR s'échappe et casse la précédence de l'outer WHERE.
        filters_sql = (" AND (" + " AND ".join(predicates) + ")") if predicates else ""

        if _DRILL_FILTERS_SENTINEL in skeleton:
            if not predicates:
                # Marqueur présent mais AUCUN prédicat bindé → le remplacer par
                # "" donnerait un détail NON filtré. Fail-closed → programmatique.
                logger.warning(
                    "[DrillDown] marqueur présent mais aucun prédicat bindé — fallback",
                    extra=_log_extra(self),
                )
                return None
            final_sql = skeleton.replace(_DRILL_FILTERS_SENTINEL, filters_sql)
        elif predicates:
            # Filtres à poser mais aucun emplacement : exécuter tel quel
            # donnerait un détail NON filtré (données fausses silencieuses,
            # pire qu'un crash). Fail-closed → fallback programmatique.
            logger.warning(
                "[DrillDown] marqueur de filtre absent malgré des dimensions — fallback",
                extra=_log_extra(self),
            )
            return None
        else:
            final_sql = skeleton

        # Aucun marqueur résiduel ne doit subsister dans le SQL exécuté.
        if _DRILL_FILTERS_SENTINEL in final_sql:
            logger.warning(
                "[DrillDown] marqueur résiduel après binding — fallback",
                extra=_log_extra(self),
            )
            return None

        # Defense-in-depth : le SQL bindé doit rester SELECT/WITH sans mot-clé
        # banni (on n'a ajouté que des prédicats ``<expr> = <litéral>`` / IS NULL).
        if not _is_safe_bound_sql(final_sql):
            logger.warning(
                "[DrillDown] SQL bindé jugé non sûr — fallback",
                extra=_log_extra(self),
            )
            return None

        # ── Filet de sécurité : oracle SSoT AVANT exécution ──
        # Doctrine « JAMAIS de SQL à l'aveugle » : on valide le SQL bindé via
        # ``validate_for_iris`` (PARSEONLY/FMTONLY, le MÊME validateur que tous
        # les autres tools Iris) avant de le rendre exécutable. La normalisation
        # de scope ci-dessus couvre le cas dominant (alias CTE en scope externe) ;
        # l'oracle attrape TOUTE autre structure invalide que le LLM aurait
        # produite (colonne fantôme, CTE incohérente, fonction inconnue…) → on
        # bascule alors sur le fallback programmatique, safe-by-construction
        # (réutilise la requête d'origine déjà valide). On n'exploite QUE le
        # verdict : la réécriture RLS (``sql_used``) est laissée à
        # ``_execute_single`` (``enforce_for_executor``) pour ne pas appliquer le
        # RLS deux fois.
        from app.services.ai.sql_validator import validate_for_iris

        try:
            verdict = await validate_for_iris(final_sql, user, get_sage_connector())
        except SageConnectionError:
            # Defense-in-depth (dead code attendu depuis 2026-06-12) : la
            # politique d'indisponibilité de l'oracle est désormais centralisée
            # DANS ``validate_for_iris`` (fail-open marqué / fail-closed env
            # ``ORACLE_FAIL_CLOSED``) — l'exception ne remonte plus ici. On
            # garde le catch au cas où, comme les call-sites d'agent_tools.
            logger.warning(
                "[DrillDown] oracle injoignable (Sage indisponible) — "
                "exécution sans pré-vol (le canal d'exécution reportera l'erreur)",
                extra=_log_extra(self),
            )
            return final_sql
        except Exception:
            # Crash inattendu du validateur → fail-closed côté LLM-path : on NE
            # exécute PAS un SQL non validé, on bascule sur le programmatique.
            logger.error(
                "[DrillDown] validate_for_iris a levé — fallback programmatique",
                extra=_log_extra(self),
                exc_info=True,
            )
            return None

        if not verdict.passes:
            # NB : inclut ORACLE_UNAVAILABLE en mode fail-closed → fallback
            # programmatique, qui échouera honnêtement sur Sage down (503).
            logger.warning(
                "[DrillDown] SQL LLM rejeté par l'oracle — fallback programmatique",
                extra=_log_extra(self, rule_id=getattr(verdict.proof, "rule_id", None)),
            )
            return None

        if getattr(verdict, "oracle_validated", None) is False:
            # Fail-open : SQL LLM accepté SANS pré-vol SGBD (base injoignable
            # à la validation). ÉCART DOCUMENTÉ : contrairement aux grilles
            # /iris (bannière ``oracle_prevalidated``), le payload drill-down
            # ne propage pas encore le marqueur jusqu'à l'UI — la fenêtre est
            # minuscule (l'exécution qui suit immédiatement requiert Sage et
            # échouera en 503 si toujours down) ; on trace pour observabilité.
            logger.warning(
                "[DrillDown] SQL LLM exécuté SANS pré-validation SGBD "
                "(oracle injoignable, fail-open marqué)",
                extra=_log_extra(self),
            )

        return final_sql

    async def _execute_multi_cte(
        self,
        queries: list[dict[str, Any]],
        breadcrumb: str,
        connector: Any,
    ) -> None:
        """Exécute N sous-requêtes en séquence (mode multi-CTE).

        Chaque sous-requête a un label métier (ex. « Ventes par mois »).
        Les échecs partiels sont signalés dans ``results[i].error`` sans
        casser le batch — l'UX préfère voir 3 blocs sur 5 que 0/5.
        """
        if len(queries) > MAX_MULTI_CTE_QUERIES:
            logger.warning(
                "[DrillDown] multi-CTE tronqué au cap",
                extra=_log_extra(self, received=len(queries), cap=MAX_MULTI_CTE_QUERIES),
            )
            queries = queries[:MAX_MULTI_CTE_QUERIES]

        results_list: list[dict[str, Any]] = []
        for query_info in queries:
            sql = query_info.get("sql")
            label = query_info.get("label", "")
            if not isinstance(sql, str) or not sql.strip():
                results_list.append(
                    {"label": label, **_json_query_error("Requête vide ou invalide.")}
                )
                continue
            try:
                # RLS check par sub-query
                from app.services.data_access import enforcer as _da_enforcer

                try:
                    sql = await _da_enforcer.enforce_for_executor(
                        sql, self.current_user, source="drilldown_multi"
                    )
                except _da_enforcer.DataAccessDeniedError as _rls_exc:
                    results_list.append(
                        {"label": label, **_json_query_error(_rls_exc.user_message)}
                    )
                    continue
                result = await connector.execute(sql, max_rows=MAX_DRILLDOWN_ROWS)
                rows_data = [list(row) for row in result.rows]
                results_list.append(
                    {
                        "label": label,
                        "columns": result.columns,
                        "rows": rows_data,
                        "sql": sql,
                        "row_count": result.row_count,
                        "execution_time_ms": result.execution_time_ms,
                        # A12-F1 — flag troncature par sous-requête (cap admin).
                        "truncated": result.truncated,
                    }
                )
            except (QueryError, SageConnectionError) as sub_err:
                logger.warning(
                    "[DrillDown] sous-requête multi-CTE échec",
                    extra=_log_extra(
                        self,
                        label=label,
                        error=sub_err.__class__.__name__,
                        raw_error=str(sub_err)[:200],
                    ),
                )
                # P2.4 — au lieu de "Cette sous-requête n'a pas pu être
                # exécutée.", on catégorise + sanitize PII via le helper SSoT.
                _audience = "admin" if _is_admin(self.current_user) else "user"
                _err_payload = await _json_query_error_for_exc(
                    sub_err, self.current_user, audience=_audience
                )
                results_list.append({"label": label, **_err_payload})

        self.write_json({"multi": True, "results": results_list, "breadcrumb": breadcrumb})

    async def _execute_single(self, drilldown_sql: str, breadcrumb: str, connector: Any) -> None:
        """Exécute un drill-down mono-query."""
        # RLS check (enforce_for_executor) avec le user du handler
        try:
            from app.services.data_access import enforcer as _da_enforcer

            drilldown_sql = await _da_enforcer.enforce_for_executor(
                drilldown_sql, self.current_user, source="drilldown_single"
            )
        except _da_enforcer.DataAccessDeniedError as exc:
            self.write_json({"error": exc.user_message}, 403)
            return

        try:
            result = await connector.execute(drilldown_sql, max_rows=MAX_DRILLDOWN_ROWS)
        except QueryError as exc:
            logger.warning(
                "[DrillDown] query error",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
            )
            # P2.4 — catégorisation + sanitization PII via SSoT.
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 400)
            return
        except SageConnectionError as exc:
            logger.error(
                "[DrillDown] Sage indisponible",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
                exc_info=True,
            )
            # P2.4 — SageConnectionError contient depuis P1.1 le SQLSTATE +
            # détail ODBC. Le helper le catégorise en 'connection' et propose
            # un message FR adapté.
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 503)
            return

        rows_data = [list(row) for row in result.rows]
        drilldown_metadata = analyze_columns(drilldown_sql)

        self.write_json(
            {
                "columns": result.columns,
                "rows": rows_data,
                "sql": drilldown_sql,
                "row_count": result.row_count,
                "execution_time_ms": result.execution_time_ms,
                "breadcrumb": breadcrumb,
                "column_metadata": drilldown_metadata,
                # A12-F1 — flag de troncature AUTORITATIF (cap admin
                # ``DatabaseConnection.max_rows`` appliqué par le connector).
                # Sans lui, un drill-down capé afficherait N lignes comme
                # « détail complet » (données fausses silencieuses, même
                # classe que A8-F1 / A7-C6). Aligné sur ExpandColumnsHandler.
                "truncated": result.truncated,
            }
        )


class DrillDownAnalyzeHandler(BaseHandler):
    """``POST /api/drilldown/analyze`` — Analyse un SQL pour les colonnes drillables.

    Parse-only (sqlglot), aucune exécution côté Sage. Retourne la liste
    des métadonnées par colonne SELECT : ``is_drillable``, ``filter_dimensions``,
    ``type``, ``source_cte``.
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_analyze_limiter, user.id, *RATE_LIMIT_ANALYZE)

        body = self.get_json_body() or {}
        sql = _require_sql(body)

        # ``analyze_columns`` catche déjà les ``sqlglot`` parse errors en
        # interne et retourne ``[]`` — pas besoin de try/except ici. Si
        # un jour le service laisse fuiter une exception (régression),
        # elle passera par ``write_error`` qui produira un 500 neutralisé.
        metadata = analyze_columns(sql)
        self.write_json({"columns": metadata})


class CellDetailExecuteHandler(BaseHandler):
    """``POST /api/cell-detail/execute`` — Ré-exécute un SQL de détail stocké.

    Contexte : un classeur Komptia peut contenir des « détails de cellule »
    — chaque cellule est un SQL déjà construit côté serveur et stocké dans
    le classeur. Au lazy-load côté UI, on ré-exécute ce SQL pour afficher
    le détail.

    Sécurité : ``sage_connector.execute`` vérifie déjà que la query est un
    SELECT/WITH (sinon ``QueryError``). On garde ici un double check
    (defense-in-depth) + un cap ``max_rows``. Le SQL arrive SIGNÉ côté
    classeur (cf ``EPIC:CELL-DETAIL-HMAC`` — dette à traiter : actuellement
    un utilisateur authentifié peut envoyer n'importe quel SELECT arbitraire).
    """

    @require_role("admin", "user")
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_cell_detail_limiter, user.id, *RATE_LIMIT_CELL_DETAIL)

        body = self.get_json_body() or {}
        sql = _require_sql(body)
        max_rows = _require_int(
            body,
            "max_rows",
            default=CELL_DETAIL_DEFAULT_ROWS,
            minimum=1,
            maximum=MAX_CELL_DETAIL_ROWS,
        )

        # Defense-in-depth : sage_connector filtre déjà SELECT/WITH mais
        # on veut un 403 clair (pas 400) si un autre verb est envoyé.
        # On retire les commentaires de tête (``--`` et ``/* */``) AVANT
        # le check pour s'aligner sur ``sage_connector`` — sinon un SQL
        # légitime avec un commentaire d'en-tête (pattern LLM ``-- Étape
        # 1``) ferait 403 ici puis succès plus bas, ce qui est incohérent.
        sql_body = strip_leading_sql_comments(sql)
        first_keyword = sql_body.split(None, 1)[0].upper() if sql_body else ""
        if first_keyword not in ("SELECT", "WITH"):
            self.write_json({"error": "Seules les requêtes SELECT sont autorisées."}, 403)
            return

        # Blocage explicite des vecteurs SSRF / file I/O côté SQL Server
        # non couverts par la denylist ``sage_connector`` : OPENROWSET,
        # OPENQUERY, OPENDATASOURCE (linked server → exfiltration vers
        # une IP arbitraire), BULK INSERT / RESTORE / BACKUP (file I/O
        # côté serveur SQL), MERGE (mutation). ``sage_connector`` bloque
        # déjà INSERT/UPDATE/DELETE/DROP/TRUNCATE/ALTER/CREATE/EXEC — ce
        # check ici est une couche supplémentaire spécifique au vecteur
        # "SQL stocké côté classeur" (cf docstring sur HMAC manquant).
        banned_match = _CELL_DETAIL_BANNED_RE.search(sql_body)
        if banned_match:
            logger.warning(
                "[CellDetail] mot-clé banni refusé",
                extra=_log_extra(self, keyword=banned_match.group(1).upper()),
            )
            self.write_json({"error": "Cette requête contient un mot-clé non autorisé."}, 403)
            return

        connector = get_sage_connector()
        # RLS check
        try:
            from app.services.data_access import enforcer as _da_enforcer

            sql = await _da_enforcer.enforce_for_executor(
                sql, self.current_user, source="drilldown_cell_detail"
            )
        except _da_enforcer.DataAccessDeniedError as exc:
            self.write_json({"error": exc.user_message}, 403)
            return

        try:
            result = await connector.execute(sql, max_rows=max_rows)
        except QueryError as exc:
            logger.warning(
                "[CellDetail] query error",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
            )
            # P2.4 — catégorisation + sanitization PII via SSoT.
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 400)
            return
        except SageConnectionError as exc:
            logger.error(
                "[CellDetail] Sage indisponible",
                extra=_log_extra(self, error=exc.__class__.__name__, raw_error=str(exc)[:200]),
                exc_info=True,
            )
            _audience = "admin" if _is_admin(self.current_user) else "user"
            _err_payload = await _json_query_error_for_exc(
                exc, self.current_user, audience=_audience
            )
            self.write_json(_err_payload, 503)
            return

        rows_data = [list(row) for row in result.rows]
        self.write_json(
            {
                "columns": result.columns,
                "rows": rows_data,
                "row_count": result.row_count,
                "execution_time_ms": result.execution_time_ms,
                # A12-F1 — flag troncature autoritatif (cap admin appliqué par
                # le connector). Le SQL stocké côté classeur peut retourner plus
                # que ``max_rows`` ; sans ce flag, le détail capé passerait pour
                # complet (données fausses silencieuses).
                "truncated": result.truncated,
            }
        )
