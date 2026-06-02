"""
Traducteur SQL Server → SQLite.

Convertit les requêtes SQL Server (T-SQL) générées par Iris en syntaxe SQLite
pour permettre l'exécution sur la copie locale de la base Sage.

Utilise sqlglot comme moteur principal de transpilation AST, avec du
post-processing pour les cas non couverts nativement.
"""

import re

import sqlglot

from app.utils.logger import get_logger

logger = get_logger(__name__)

# Garde-fou contre les boucles infinies dans le post-processing
_MAX_LOOP = 100

# ── DATEDIFF : sémantique calendaire SQL Server (franchissements de bornes) ──
# sqlglot émet une approximation FAUSSE pour les unités calendaires :
#   month → CAST((JULIANDAY(b)-JULIANDAY(a)) / 30.0 AS INTEGER)
#   year  → CAST((JULIANDAY(b)-JULIANDAY(a)) / 365.0 AS INTEGER)
# Ces formules comptent des JOURS ÉCOULÉS / diviseur, alors que SQL Server compte
# les FRANCHISSEMENTS DE BORNES de calendrier. Exemple typique en compta (aging) :
#   DATEDIFF(month, '2023-12-31', '2024-01-01') = 1 sous SQL Server (on franchit la
#   borne de mois) mais 0 via /30.0 → données fausses SILENCIEUSES (le SQLite
#   s'exécute sans erreur et renvoie un nombre faux). Idem year aux bornes d'année,
#   et quarter (que sqlglot ne traduit même pas → diff de jours bruts).
# On pré-corrige donc year/quarter/month (+ la famille jour, cf. plus bas) EN
# AMONT de sqlglot avec la sémantique exacte de franchissement de bornes : pour
# ces unités le calcul est locale-INDÉPENDANT (différence d'index calendaire
# absolu) donc sûr. DATEDIFF(week)
# et les unités sous-journalières ont une sémantique de borne plus subtile (et, pour
# week, des conventions de premier-jour-de-semaine) : on ne les pré-corrige PAS ici
# pour ne pas substituer une approximation à une AUTRE approximation fausse —
# laissées à sqlglot et tracées comme limite connue (cf. tasks de suivi).
# ATTENTION abréviations T-SQL : 'y' = dayofyear (PAS year), 'n' = minute,
# 'm'/'mm' = month, 'q'/'qq' = quarter, 'yy'/'yyyy' = year.
_DATEDIFF_YEAR_UNITS = frozenset({"year", "yyyy", "yy"})
_DATEDIFF_QUARTER_UNITS = frozenset({"quarter", "qq", "q"})
_DATEDIFF_MONTH_UNITS = frozenset({"month", "mm", "m"})
# Famille "jour" : pour DATEDIFF, SQL Server traite day, dayofyear ET weekday de
# façon IDENTIQUE = nombre de bornes de DATE (minuit) franchies — locale-INDÉP.
# (cf. doc Microsoft DATEDIFF). sqlglot les traduit en JULIANDAY(b)-JULIANDAY(a)
# (périodes de 24h écoulées) → FAUX quand les bornes portent une heure (ex.
# '...23:00'→'...01:00' = 1 borne minuit mais ≈0 en 24h écoulées). On pré-corrige
# avec une diff de JULIANDAY(DATE(...)) qui compte exactement les bornes de date.
# Abréviations T-SQL : day=dd/d, dayofyear=dy/y, weekday=dw/w ('w' = weekday, PAS
# week — week = wk/ww, cf. _DATEDIFF_DEGRADED_UNITS).
_DATEDIFF_DAY_UNITS = frozenset({"day", "dd", "d", "dayofyear", "dy", "y", "weekday", "dw", "w"})

# Unités que sqlglot dégrade SILENCIEUSEMENT sur le mirror SQLite (cf. #121) :
#   - week (wk/ww) + ISO week (iso_week/isowk/isoww)
#                         → sqlglot émet la diff de JOURS bruts (pas de
#                           franchissement de borne de semaine, pas de /7) ;
#   - sous-journalières   → jours-écoulés × facteur au lieu de bornes
#     (hour/minute/second + abréviations hh/mi/n/ss/s/ms/mcs/ns) — les
#     abréviations ne sont même pas reconnues par sqlglot (diff de jours bruts).
# On NE pré-corrige PAS ces unités à l'aveugle (la sémantique exacte dépend de
# @@DATEFIRST / du premier-jour-de-semaine, NON vérifiable hors d'un vrai SQL
# Server — coder une formule risquerait de substituer une approximation fausse à
# une autre). À la place on LOGGE la dégradation pour qu'elle ne soit pas
# silencieuse (donnée fausse VISIBLE > donnée fausse muette). NB : 'day'/'dd'/'d'
# + la famille dayofyear ('dy'/'y') + weekday ('dw'/'w') NE sont PAS ici car
# PRÉ-CORRIGÉES (bornes de DATE, cf. _DATEDIFF_DAY_UNITS) : la diff de jours brute
# de sqlglot serait fausse pour elles aussi quand les bornes portent une heure.
_DATEDIFF_DEGRADED_UNITS = frozenset(
    {
        "week",
        "wk",
        "ww",
        # ISO 8601 week (iso_week/isowk/isoww) : sqlglot ne les reconnaît pas non
        # plus → diff de jours bruts (vérifié sqlglot 30.x). Dégradées comme week.
        "iso_week",
        "isowk",
        "isoww",
        "hour",
        "hh",
        "minute",
        "mi",
        "n",
        "second",
        "ss",
        "s",
        "millisecond",
        "ms",
        "microsecond",
        "mcs",
        "nanosecond",
        "ns",
    }
)


def translate_sqlserver_to_sqlite(sql: str) -> str:
    """
    Traduit une requête SQL Server en syntaxe SQLite.

    Pipeline :
    1. Pré-processing (N'string', [dbo]. schema, DATEDIFF calendaire) — voir note
       module : DATEDIFF year/quarter/month est pré-corrigé ICI car sqlglot émet
       une approximation jours/diviseur fausse aux bornes (données fausses).
    2. sqlglot transpile (tsql → sqlite) — gère TOP, ISNULL, GETDATE,
       DATEDIFF (day + unités sous-journalières), LEN, CHARINDEX, CONVERT,
       DATEADD, STRING_AGG, CONCAT, NOLOCK, CTE, fonctions imbriquées, etc.
    3. Post-processing pour les gaps sqlglot (YEAR/MONTH/DAY, UUID,
       RIGHT/LEFT, string concat avec +, NUMBER_TO_STR)
    """
    if not sql or not sql.strip():
        return sql

    result = sql.strip()

    # ── Pré-processing ────────────────────────────────────────────────
    result = _preprocess(result)

    # ── sqlglot transpile ─────────────────────────────────────────────
    result = _sqlglot_transpile(result)

    # ── Post-processing ───────────────────────────────────────────────
    result = _postprocess(result)

    return result.strip()


# ═══════════════════════════════════════════════════════════════════════
# Pré-processing (avant sqlglot)
# ═══════════════════════════════════════════════════════════════════════


def _preprocess(sql: str) -> str:
    """Nettoyages que sqlglot ne gère pas bien en entrée."""
    # N'string' → 'string' (sqlglot ne strip pas le préfixe N)
    sql = re.sub(r"\bN'", "'", sql)

    # [dbo]. ou dbo. → rien (sqlglot convertit en "dbo"."table", on veut juste "table")
    sql = re.sub(r"\[?dbo\]?\s*\.\s*", "", sql)

    # GETUTCDATE() → GETDATE() (SQLite datetime('now') est déjà UTC)
    sql = re.sub(r"\bGETUTCDATE\s*\(\s*\)", "GETDATE()", sql, flags=re.IGNORECASE)

    # (VALUES (v1),(v2),...) AS alias(col_name) → SQLite-compatible
    # SQL Server supporte les alias de colonnes sur VALUES (RFC SQL:2003),
    # SQLite NON. sqlglot transpile en perdant `(col_name)` → SQLite ne
    # connait pas la colonne → "no such column" au runtime.
    # Solution : réécrire en SELECT ... AS col_name UNION ALL SELECT ...
    sql = _fix_values_named_cols(sql)

    # DATEDIFF calendaire (year/quarter/month) : pré-correction des bornes SQL
    # Server AVANT sqlglot (sinon /30.0 et /365.0 donnent des nombres faux aux
    # bornes de mois/année — cf. note module). Les autres unités → sqlglot.
    sql = _fix_datediff(sql)

    return sql


def _datediff_formula(unit: str, start_expr: str, end_expr: str):
    """Formule SQLite exacte pour ``DATEDIFF(unit, start, end)`` selon la
    sémantique SQL Server (nombre de bornes calendaires franchies de ``start``
    vers ``end``, négatif si ``end < start``).

    Gère les unités calendaires locale-INDÉPENDANTES (year/quarter/month) + la
    famille jour (day/dayofyear/weekday → bornes de DATE). Retourne ``None`` pour
    les unités week/sous-journalières → laissées à sqlglot (cf. note module pour
    le pourquoi de l'exclusion de week/sous-jour).
    """
    y_start = f"CAST(strftime('%Y', {start_expr}) AS INTEGER)"
    y_end = f"CAST(strftime('%Y', {end_expr}) AS INTEGER)"
    if unit in _DATEDIFF_YEAR_UNITS:
        return f"({y_end} - {y_start})"

    m_start = f"CAST(strftime('%m', {start_expr}) AS INTEGER)"
    m_end = f"CAST(strftime('%m', {end_expr}) AS INTEGER)"
    if unit in _DATEDIFF_MONTH_UNITS:
        # mois absolus = année*12 + mois ; la différence compte les bornes franchies.
        return f"(({y_end} - {y_start}) * 12 + ({m_end} - {m_start}))"
    if unit in _DATEDIFF_QUARTER_UNITS:
        # index de trimestre = année*4 + (mois-1)//3 ; division entière SQLite.
        return f"(({y_end} * 4 + ({m_end} - 1) / 3) - ({y_start} * 4 + ({m_start} - 1) / 3))"

    if unit in _DATEDIFF_DAY_UNITS:
        # bornes de DATE (minuit) franchies = diff des JULIANDAY au minuit ;
        # ``DATE()`` tronque l'heure → correct pour date-only ET datetime,
        # contrairement à ``JULIANDAY(b) - JULIANDAY(a)`` brut de sqlglot qui
        # compte des périodes de 24h écoulées (faux aux bornes horaires).
        return f"CAST(JULIANDAY(DATE({end_expr})) - JULIANDAY(DATE({start_expr})) AS INTEGER)"

    return None


def _fix_datediff(sql: str) -> str:
    """Pré-corrige ``DATEDIFF(year|quarter|month, start, end)`` avec la sémantique
    exacte de franchissement de bornes SQL Server, AVANT sqlglot.

    sqlglot traduit ces unités en ``(jours écoulés) / diviseur`` (ou diff de jours
    bruts pour quarter), ce qui est FAUX aux bornes calendaires et s'exécute
    silencieusement sur SQLite (données fausses). On remplace donc l'appel par la
    formule ``strftime`` correcte. Les unités non calendaires (day/week/sous-jour)
    sont laissées intactes pour que sqlglot les traite (cf. note module).

    Robuste aux expressions imbriquées (parenthèses/virgules dans ``start``/``end``)
    via ``_extract_balanced_args``. Les expressions de date conservées sont ensuite
    traduites par sqlglot comme le reste de la requête (ex. ``GETDATE()``).
    """
    pattern = re.compile(r"\bDATEDIFF\s*\(", re.IGNORECASE)
    search_from = 0
    iterations = 0
    degraded_seen: set[str] = set()  # unités week/sous-jour rencontrées (cf. #121)
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql, search_from)
        if not match:
            break
        args, close = _extract_balanced_args(sql, match.end())
        # DATEDIFF attend exactement 3 arguments (unit, start, end). Toute autre
        # arité = forme inattendue → ne pas y toucher, sqlglot tentera sa traduction.
        if not (args and len(args) == 3 and close != -1):
            search_from = match.end()
            continue
        unit = sql[args[0][0] : args[0][1]].strip().strip("'\"").lower()
        start_expr = sql[args[1][0] : args[1][1]].strip()
        end_expr = sql[args[2][0] : args[2][1]].strip()
        formula = _datediff_formula(unit, start_expr, end_expr)
        if formula is None:
            if unit in _DATEDIFF_DEGRADED_UNITS:
                # week / sous-jour : sqlglot produira une approximation FAUSSE aux
                # bornes. On ne corrige pas à l'aveugle (cf. note module) mais on
                # mémorise pour LOGGER la dégradation après le scan (#121).
                degraded_seen.add(unit)
            # Unité non gérée ici (day/week/sous-jour) → laissée à sqlglot. On
            # avance juste après « DATEDIFF( » (et NON après la parenthèse fermante)
            # pour que les DATEDIFF calendaires éventuellement IMBRIQUÉS dans
            # start/end soient quand même visités au tour suivant — sinon ils
            # tomberaient dans l'approximation fausse de sqlglot. ``match.end()``
            # garantit la progression (le « DATEDIFF( » courant est désormais avant
            # le curseur, donc pas de re-match infini de la même occurrence).
            search_from = match.end()
            continue
        sql = sql[: match.start()] + formula + sql[close + 1 :]
        # Re-scan À PARTIR du début de la formule insérée : elle ne contient pas
        # « DATEDIFF » en propre, mais start/end ré-injectés peuvent contenir un
        # DATEDIFF calendaire imbriqué (ex. DATEDIFF(month, DATEDIFF(month, a, b), c))
        # → corrigé au tour suivant. Terminaison garantie : chaque tour « matched »
        # retire exactement un token DATEDIFF de la chaîne.
        search_from = match.start()
    if degraded_seen:
        # UNE seule ligne par traduction (dédup par unité) — anti log-flood même
        # si la requête contient N DATEDIFF(week). La requête sur le vrai SQL
        # Server reste correcte ; seul le mirror SQLite local est concerné.
        logger.warning(
            "sql_translator: DATEDIFF unité(s) %s traduite(s) de façon "
            "APPROXIMATIVE par sqlglot sur le mirror SQLite — résultat "
            "potentiellement FAUX aux bornes (semaine/heure/minute/seconde). "
            "Limite connue (#121) : non corrigée à l'aveugle (sémantique exacte "
            "non vérifiable hors d'un vrai SQL Server). Le mirror local seul est "
            "concerné, pas l'exécution sur SQL Server.",
            sorted(degraded_seen),
        )
    return sql


def _fix_values_named_cols(sql: str) -> str:
    """Réécrit `(VALUES (v1),(v2),...) AS alias(col)` en
    `(SELECT v1 AS col UNION ALL SELECT v2 UNION ALL ...) AS alias`.

    Cas couvert : 1 seule colonne par tuple VALUES (pattern observé chez
    Komptia, ex. liste de codes collab `WITH COLLABS(cod) AS (...) AS c(cod)`).
    Le cas multi-colonnes n'est pas implémenté (pas de besoin actuel et
    parsing balancé plus complexe).

    Pattern matched :
        (VALUES ('a'),('b'),('c')) AS c(col_name)
    Réécrit en :
        (SELECT 'a' AS col_name UNION ALL SELECT 'b' UNION ALL SELECT 'c') AS c
    """
    pattern = re.compile(
        r"""
        \(\s*VALUES\s+                  # ouverture VALUES
        (?P<vals>                       # capture la liste des tuples
            (?:\(\s*[^()]+?\s*\)\s*,?\s*)+
        )
        \)\s*                           # fermeture VALUES
        AS\s+(?P<alias>\w+)\s*          # alias
        \(\s*(?P<col>\w+)\s*\)          # (col_name) — perdu par sqlglot
        """,
        re.IGNORECASE | re.VERBOSE | re.DOTALL,
    )

    def _replace(m: "re.Match[str]") -> str:
        vals_str = m.group("vals")
        alias = m.group("alias")
        col_name = m.group("col")
        # Extraire chaque tuple `(value)` → on ne supporte qu'une valeur par tuple.
        values = re.findall(r"\(\s*([^()]+?)\s*\)", vals_str)
        if not values:
            return m.group(0)
        first = f"SELECT {values[0]} AS {col_name}"
        rest_parts = [f"SELECT {v}" for v in values[1:]]
        if rest_parts:
            inner = first + " UNION ALL " + " UNION ALL ".join(rest_parts)
        else:
            inner = first
        return f"({inner}) AS {alias}"

    return pattern.sub(_replace, sql)


# ═══════════════════════════════════════════════════════════════════════
# sqlglot transpile (le gros du travail)
# ═══════════════════════════════════════════════════════════════════════


def _sqlglot_transpile(sql: str) -> str:
    """
    Transpile T-SQL → SQLite via sqlglot.

    En cas d'erreur de parsing, retourne le SQL tel quel (le post-processing
    tentera quand même de corriger ce qu'il peut).
    """
    try:
        results = sqlglot.transpile(sql, read="tsql", write="sqlite", error_level=None)
        if results:
            return results[0]
    except Exception as transpile_exc:  # noqa: BLE001
        # P5.2 (audit 2026-05-26) — Promu silent pass → WARNING : sans ce log,
        # quand sqlglot rate la traduction T-SQL→SQLite (ex: T-SQL spécifique
        # CROSS APPLY, OPENQUERY, OUTPUT), le SQL T-SQL est renvoyé tel quel
        # et SQLite lève ensuite une erreur cryptique (``near "TOP": syntax
        # error``). L'admin perd la cause racine (translation manquée).
        # WARNING permet de tracer les cas non couverts par sqlglot pour
        # enrichissement futur.
        logger.warning(
            "sqlglot transpile T-SQL→SQLite failed (SQL renvoyé tel quel — "
            "SQLite va probablement lever une erreur cryptique): %s — SQL: %.200s",
            transpile_exc,
            sql,
        )
    return sql


# ═══════════════════════════════════════════════════════════════════════
# Post-processing (après sqlglot)
# ═══════════════════════════════════════════════════════════════════════


def _postprocess(sql: str) -> str:
    """Corrige les gaps de sqlglot pour SQLite."""
    sql = _fix_union_limit(sql)
    sql = _fix_date_extract_functions(sql)
    sql = _fix_extract(sql)
    sql = _fix_uuid(sql)
    sql = _fix_right_left(sql)
    sql = _fix_string_concat(sql)
    sql = _fix_number_to_str(sql)
    sql = _fix_stuff(sql)
    sql = _fix_repeat(sql)
    sql = _fix_last_day(sql)
    sql = _fix_date_from_parts(sql)
    sql = _fix_datalength(sql)
    sql = _strip_dbo_quotes(sql)
    return sql


def _fix_union_limit(sql: str) -> str:
    """
    Corrige LIMIT dans les branches d'un UNION/EXCEPT/INTERSECT.

    SQLite interdit LIMIT dans les branches individuelles d'un compound SELECT.
    Solution : envelopper chaque branche qui a un LIMIT dans SELECT * FROM (...).

    Exemple :
        SELECT a FROM T1 LIMIT 3 UNION ALL SELECT b FROM T2 LIMIT 3
      → SELECT * FROM (SELECT a FROM T1 LIMIT 3) UNION ALL SELECT * FROM (SELECT b FROM T2 LIMIT 3)
    """
    # Détecter si c'est un compound SELECT
    compound_ops = re.compile(r"\b(UNION\s+ALL|UNION|EXCEPT|INTERSECT)\b", re.IGNORECASE)
    if not compound_ops.search(sql):
        return sql

    # Découper en branches sur les opérateurs compound (hors parenthèses/strings)
    branches = []
    operators = []
    depth = 0
    in_string = False
    current_start = 0
    i = 0

    while i < len(sql):
        c = sql[i]
        if c == "'" and not in_string:
            in_string = True
        elif c == "'" and in_string:
            if i + 1 < len(sql) and sql[i + 1] == "'":
                i += 1  # quote échappée
            else:
                in_string = False
        elif not in_string:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif depth == 0:
                match = compound_ops.match(sql[i:])
                if match:
                    branches.append(sql[current_start:i].strip())
                    operators.append(match.group(0))
                    i += match.end()
                    current_start = i
                    continue
        i += 1

    branches.append(sql[current_start:].strip())

    if len(branches) <= 1:
        return sql

    # Envelopper chaque branche qui contient LIMIT
    limit_pattern = re.compile(r"\bLIMIT\s+\d+", re.IGNORECASE)
    fixed = []
    for branch in branches:
        if limit_pattern.search(branch):
            fixed.append(f"SELECT * FROM ({branch})")
        else:
            fixed.append(branch)

    # Recombiner avec les opérateurs
    result = fixed[0]
    for op, branch in zip(operators, fixed[1:]):
        result += f" {op} {branch}"
    return result


def _fix_date_extract_functions(sql: str) -> str:
    """
    YEAR(x) → CAST(strftime('%Y', x) AS INTEGER)
    MONTH(x) → CAST(strftime('%m', x) AS INTEGER)
    DAY(x) → CAST(strftime('%d', x) AS INTEGER)

    sqlglot les laisse tels quels, mais SQLite n'a pas ces fonctions.
    """
    for func, fmt in [("YEAR", "%Y"), ("MONTH", "%m"), ("DAY", "%d")]:
        pattern = re.compile(rf"\b{func}\s*\(", re.IGNORECASE)
        iterations = 0
        while iterations < _MAX_LOOP:
            iterations += 1
            match = pattern.search(sql)
            if not match:
                break
            start = match.end()  # après '('
            args, close = _extract_balanced_args(sql, start)
            if args and len(args) == 1 and close != -1:
                expr = sql[args[0][0] : args[0][1]].strip()
                replacement = f"CAST(strftime('{fmt}', {expr}) AS INTEGER)"
                sql = sql[: match.start()] + replacement + sql[close + 1 :]
                continue
            break
    return sql


def _fix_extract(sql: str) -> str:
    """
    EXTRACT(part FROM expr) → CAST(strftime(fmt, expr) AS INTEGER)

    sqlglot convertit DATEPART(part, expr) en EXTRACT(part FROM expr),
    mais SQLite ne supporte pas EXTRACT.
    """
    extract_map = {
        "year": "%Y",
        "month": "%m",
        "day": "%d",
        "hour": "%H",
        "minute": "%M",
        "second": "%S",
        "dayofweek": "%w",
        "dow": "%w",
        "week": "%W",
        "dayofyear": "%j",
        "doy": "%j",
    }
    pattern = re.compile(
        r"\bEXTRACT\s*\(\s*(\w+)\s+FROM\s+(.+?)\)",
        re.IGNORECASE,
    )
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        part = match.group(1).lower()
        expr = match.group(2).strip()
        fmt = extract_map.get(part, "%Y")
        replacement = f"CAST(strftime('{fmt}', {expr}) AS INTEGER)"
        sql = sql[: match.start()] + replacement + sql[match.end() :]
    return sql


def _fix_uuid(sql: str) -> str:
    """UUID() → hex(randomblob(16)) — SQLite n'a pas UUID()."""
    return re.sub(r"\bUUID\s*\(\s*\)", "hex(randomblob(16))", sql, flags=re.IGNORECASE)


def _fix_right_left(sql: str) -> str:
    """
    RIGHT(s, n) → SUBSTR(s, -n)
    LEFT(s, n) → SUBSTR(s, 1, n)

    sqlglot garde RIGHT/LEFT, mais SQLite ne les a pas.
    """
    for func in ("RIGHT", "LEFT"):
        pattern = re.compile(rf"\b{func}\s*\(", re.IGNORECASE)
        iterations = 0
        while iterations < _MAX_LOOP:
            iterations += 1
            match = pattern.search(sql)
            if not match:
                break
            start = match.end()
            args, close = _extract_balanced_args(sql, start)
            if args and len(args) == 2 and close != -1:
                s = sql[args[0][0] : args[0][1]].strip()
                n = sql[args[1][0] : args[1][1]].strip()
                if func == "RIGHT":
                    replacement = f"SUBSTR({s}, -{n})"
                else:
                    replacement = f"SUBSTR({s}, 1, {n})"
                sql = sql[: match.start()] + replacement + sql[close + 1 :]
                continue
            break
    return sql


def _fix_string_concat(sql: str) -> str:
    """
    Traduit la concaténation SQL Server (+) en SQLite (||).

    Heuristique : remplace + par || quand au moins un opérande est une
    chaîne littérale ('...') ou un CAST(...AS TEXT).
    """
    result = re.sub(
        r"('(?:[^']|'')*')\s*\+\s*",
        r"\1 || ",
        sql,
    )
    result = re.sub(
        r"\s*\+\s*('(?:[^']|'')*')",
        r" || \1",
        result,
    )
    return result


def _fix_number_to_str(sql: str) -> str:
    """
    NUMBER_TO_STR(expr, fmt) → CAST(expr AS TEXT)

    sqlglot convertit FORMAT() en NUMBER_TO_STR() qui n'existe pas en SQLite.
    On simplifie en CAST AS TEXT (le formatage n'est pas supporté en SQLite).
    """
    pattern = re.compile(r"\bNUMBER_TO_STR\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) >= 1 and close != -1:
            expr = sql[args[0][0] : args[0][1]].strip()
            replacement = f"CAST({expr} AS TEXT)"
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _fix_stuff(sql: str) -> str:
    """
    STUFF(s, start, length, insert) → SUBSTR(s, 1, start-1) || insert || SUBSTR(s, start+length)

    Remplace une sous-chaîne par une autre.
    """
    pattern = re.compile(r"\bSTUFF\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) == 4 and close != -1:
            s = sql[args[0][0] : args[0][1]].strip()
            pos = sql[args[1][0] : args[1][1]].strip()
            length = sql[args[2][0] : args[2][1]].strip()
            insert = sql[args[3][0] : args[3][1]].strip()
            replacement = (
                f"(SUBSTR({s}, 1, {pos} - 1) || {insert} || " f"SUBSTR({s}, {pos} + {length}))"
            )
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _fix_repeat(sql: str) -> str:
    """
    REPEAT(s, n) → replace(substr(quote(zeroblob(((n)+1)/2)),3,(n)),'0',(s))

    Note : workaround SQLite pur. Fonctionne pour les cas simples.
    Alternative simple pour les cas courants : utilise printf si n <= 1000.
    """
    pattern = re.compile(r"\bREPEAT\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) == 2 and close != -1:
            s = sql[args[0][0] : args[0][1]].strip()
            n = sql[args[1][0] : args[1][1]].strip()
            # Workaround SQLite : générer n zéros puis les remplacer par s
            replacement = f"replace(substr(quote(zeroblob(({n} + 1) / 2)), 3, {n}), '0', {s})"
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _fix_last_day(sql: str) -> str:
    """
    LAST_DAY(expr) → date(expr, 'start of month', '+1 month', '-1 day')

    sqlglot convertit EOMONTH() en LAST_DAY() qui n'existe pas en SQLite.
    """
    pattern = re.compile(r"\bLAST_DAY\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) >= 1 and close != -1:
            expr = sql[args[0][0] : args[0][1]].strip()
            replacement = f"date({expr}, 'start of month', '+1 month', '-1 day')"
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _fix_date_from_parts(sql: str) -> str:
    """
    DATE_FROM_PARTS(y, m, d) → date(printf('%04d-%02d-%02d', y, m, d))

    sqlglot convertit DATEFROMPARTS() en DATE_FROM_PARTS().
    """
    pattern = re.compile(r"\bDATE_FROM_PARTS\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) == 3 and close != -1:
            y = sql[args[0][0] : args[0][1]].strip()
            m = sql[args[1][0] : args[1][1]].strip()
            d = sql[args[2][0] : args[2][1]].strip()
            replacement = f"date(printf('%04d-%02d-%02d', {y}, {m}, {d}))"
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _fix_datalength(sql: str) -> str:
    """DATALENGTH(expr) → LENGTH(expr) (approximation suffisante pour SQLite)."""
    pattern = re.compile(r"\bDATALENGTH\s*\(", re.IGNORECASE)
    iterations = 0
    while iterations < _MAX_LOOP:
        iterations += 1
        match = pattern.search(sql)
        if not match:
            break
        start = match.end()
        args, close = _extract_balanced_args(sql, start)
        if args and len(args) == 1 and close != -1:
            expr = sql[args[0][0] : args[0][1]].strip()
            replacement = f"LENGTH({expr})"
            sql = sql[: match.start()] + replacement + sql[close + 1 :]
            continue
        break
    return sql


def _strip_dbo_quotes(sql: str) -> str:
    """
    "dbo"."table" → "table"

    Si le pré-processing n'a pas tout attrapé (cas edge), nettoyer les restes.
    """
    return re.sub(r'"dbo"\s*\.\s*', "", sql, flags=re.IGNORECASE)


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _extract_balanced_args(sql: str, start: int) -> tuple[list[tuple[int, int]], int]:
    """
    Extrait les positions des arguments d'une fonction à partir de 'start'
    (juste après la parenthèse ouvrante).

    Retourne (args, close_pos) :
    - args : liste de (start, end) pour chaque argument
    - close_pos : position de la parenthèse fermante (-1 si non trouvée)

    Gère les parenthèses imbriquées et les littéraux string (y compris
    les quotes échappées '' en SQL).
    """
    args = []
    depth = 0
    arg_start = start
    i = start

    while i < len(sql):
        c = sql[i]
        if c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                if i > arg_start:
                    args.append((arg_start, i))
                return args, i
            depth -= 1
        elif c == "," and depth == 0:
            args.append((arg_start, i))
            arg_start = i + 1
        elif c == "'":
            # Skip string literal (gère les '' échappées)
            i += 1
            while i < len(sql):
                if sql[i] == "'":
                    # Vérifier si c'est un '' (quote échappée)
                    if i + 1 < len(sql) and sql[i + 1] == "'":
                        i += 2  # Sauter les deux quotes
                        continue
                    break  # Fin du littéral
                i += 1
        i += 1

    return args, -1
