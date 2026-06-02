"""Shared SQL scanning utilities for character-by-character SQL analysis.

These helpers solve two recurring problems in the codebase:

1. **Leading SQL comments** — The LLM prefixes queries with ``-- Étape 1`` etc.
   Python-side ``startswith("SELECT")`` checks fail unless comments are stripped.

2. **String literals in scanners** — Character-by-character scans for SQL keywords
   (GROUP BY, ORDER BY, FROM, etc.) must skip ``'...'`` string literals to avoid
   false positives on values like ``WHERE note = 'GROUP BY date'``.
"""

import logging

logger = logging.getLogger(__name__)


# Cap dur sur la taille du SQL à scanner (anti-DoS via SQL géant). Au-delà,
# on ne strippe pas — le driver SQL rejettera de toute façon un SQL >1MB.
STRIP_COMMENTS_MAX_SQL_LEN: int = 1_000_000


def strip_leading_sql_comments(sql: str) -> str:
    """Strip leading SQL comments (``--`` and ``/* */``) and whitespace.

    Returns the SQL body with leading comments removed.  The original SQL
    remains unchanged — this is for Python-side checks only.
    """
    s = sql.lstrip()
    while s:
        if s.startswith("--"):
            newline = s.find("\n")
            if newline == -1:
                return ""
            s = s[newline + 1 :].lstrip()
        elif s.startswith("/*"):
            end = s.find("*/", 2)
            if end == -1:
                return ""
            s = s[end + 2 :].lstrip()
        else:
            break
    return s


def skip_sql_string(sql: str, i: int) -> int:
    """Advance past a single-quoted SQL string literal (handles ``''`` escaping).

    Call when ``sql[i] == "'"``.  Returns the index of the closing quote,
    or ``len(sql)`` if the string is unclosed.
    """
    i += 1  # skip opening quote
    while i < len(sql):
        if sql[i] == "'":
            if i + 1 < len(sql) and sql[i + 1] == "'":
                i += 2  # skip escaped ''
                continue
            return i  # closing quote
        i += 1
    return i  # unclosed string — return end


def _skip_quoted_identifier(sql: str, i: int, close: str) -> int:
    """Skip past a quoted identifier (``"col"`` SQL standard ou ``[col]`` T-SQL).

    L'escape pour les deux est le doublement du caractère de fermeture :
    ``""`` (SQL standard) ou ``]]`` (T-SQL). Le caractère d'ouverture
    initial à ``i`` est consommé. Retourne l'index du caractère de fermeture,
    ou ``len(sql)`` si l'identifier n'est jamais clos.

    Factorise la logique commune entre ``"`` et ``[`` (single source of
    truth — éviter divergence sur évolution d'escape).
    """
    j = i + 1
    n = len(sql)
    while j < n:
        if sql[j] == close:
            # Doublement = escape — passer
            if j + 1 < n and sql[j + 1] == close:
                j += 2
                continue
            return j  # closing char
        j += 1
    return j  # unclosed identifier — return end


class _UnclosedTokenError(Exception):
    """Erreur interne : string literal ou identifier quoted non clos.

    Levée par les sub-scanners pour signaler à ``strip_all_sql_comments`` que
    le SQL est malformé. Le caller catche et retourne le SQL inchangé
    (fail-safe : ne pas créer de parser differential en altérant un SQL
    malformé — le driver SQL le rejettera de toute façon avec un message
    cohérent).
    """


def strip_all_sql_comments(sql: str) -> str:
    """Strip ALL SQL comments (line ``--`` and block ``/* */``) from a query.

    Préserve :
        - String literals ``'...'`` (escape ``''``)
        - Identifiers SQL standard ``"col"`` (escape ``""``)
        - Identifiers T-SQL ``[col]`` (escape ``]]``)
        - Newlines ``\\n`` après un commentaire ligne (préservation du
          mapping ``lineno`` côté driver)

    **Pourquoi** (chantier T6, observation log 2026-05-10 session 2) :
    certains drivers (pyodbc en mode qmark, notamment) parsent les ``?`` à
    l'intérieur des commentaires SQL comme des placeholders, ce qui décale
    le binding des paramètres et produit des résultats faux silencieux
    (0 rows au lieu du résultat attendu — l'agent a perdu ~10 itérations
    à diagnostiquer le faux problème). Stripper les commentaires AVANT
    ``cursor.execute()`` élimine cette ambiguïté quel que soit le driver.

    **Fail-safe** : si le SQL est malformé (string ou identifier non clos),
    on retourne le SQL **INCHANGÉ** plutôt que d'essayer de stripper —
    altérer un SQL malformé pourrait créer une divergence d'interprétation
    avec le parser du driver (parser differential bug). Le driver verra le
    même SQL malformé qu'avant ce helper et raisera une erreur cohérente.

    Generic : aucune connaissance dialecte-spécifique au-delà des escapes
    standard SQL (``''``, ``""``, ``]]``). Les commentaires imbriqués
    (``/* /* */ */``) ne sont PAS supportés (SQL standard ne les supporte
    pas non plus ; PostgreSQL via extension uniquement).

    Args:
        sql: la requête SQL à nettoyer.

    Returns:
        Le SQL avec commentaires retirés, OU le SQL inchangé si :
            - ``sql`` est ``None`` / vide → ``""``
            - ``len(sql) > STRIP_COMMENTS_MAX_SQL_LEN`` (anti-DoS) → ``sql`` tel quel
            - SQL malformé (string/identifier non clos) → ``sql`` tel quel + log warning
    """
    if sql is None:
        return ""
    if not sql:
        return sql
    if len(sql) > STRIP_COMMENTS_MAX_SQL_LEN:
        logger.warning(
            "strip_all_sql_comments: SQL too large (%d > %d) — skipping strip",
            len(sql),
            STRIP_COMMENTS_MAX_SQL_LEN,
        )
        return sql

    try:
        return _strip_comments_inner(sql)
    except _UnclosedTokenError as exc:
        logger.warning(
            "strip_all_sql_comments: unclosed token (%s) — returning SQL unchanged",
            exc,
        )
        return sql


def _strip_comments_inner(sql: str) -> str:
    """Implémentation effective. Lève ``_UnclosedTokenError`` si SQL malformé.

    Le wrapper ``strip_all_sql_comments`` catche et retourne le SQL inchangé.
    """
    out_chars: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]

        # String literal simple-quoted — préserver tout ce qui est dedans,
        # y compris les `--` et `/*` qui ne sont PAS des commentaires.
        if ch == "'":
            end = skip_sql_string(sql, i)
            if end >= n:
                raise _UnclosedTokenError("single-quoted string literal not closed")
            out_chars.append(sql[i : end + 1])
            i = end + 1
            continue

        # Identifiant double-quoted (SQL standard / PostgreSQL).
        if ch == '"':
            end = _skip_quoted_identifier(sql, i, '"')
            if end >= n:
                raise _UnclosedTokenError("double-quoted identifier not closed")
            out_chars.append(sql[i : end + 1])
            i = end + 1
            continue

        # Identifiant T-SQL entre crochets [col].
        if ch == "[":
            end = _skip_quoted_identifier(sql, i, "]")
            if end >= n:
                raise _UnclosedTokenError("bracket identifier not closed")
            out_chars.append(sql[i : end + 1])
            i = end + 1
            continue

        # Commentaire ligne `-- ... \n`. On strippe le contenu MAIS on
        # préserve le `\n` final (préservation du mapping lineno côté driver).
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            newline = sql.find("\n", i + 2)
            if newline == -1:
                # Commentaire en fin de query (sans \n final) — on stoppe ici.
                break
            # Préserver le \n pour ne pas casser le mapping ligne.
            out_chars.append("\n")
            i = newline + 1
            continue

        # Commentaire bloc `/* ... */`
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                # Bloc non clos — fail-safe : on signale via exception.
                raise _UnclosedTokenError("block comment not closed")
            i = end + 2
            continue

        # Caractère ordinaire
        out_chars.append(ch)
        i += 1

    return "".join(out_chars)
