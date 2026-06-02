"""
Déjà-vu prefetch — exécute le SQL validé le plus proche et condense les
métadonnées pour Iris, en remplacement de l'Exploration Guard.

Principe
--------
Quand une paire Question/SQL validée par l'utilisateur match la demande
courante (via `training_store.get_similar_question_sql`), on **exécute** ce SQL
sur la BDD connectée et on envoie au LLM uniquement des **métadonnées
agrégées** (colonnes, row_count, distinct_count, null_count par colonne).

Le LLM a alors la preuve que le SQL fonctionne sur la BDD courante ET la
structure du résultat, sans JAMAIS voir les valeurs individuelles — ni
strings (obfusquées ailleurs), ni nombres (montants), ni dates brutes.

Fail-closed
-----------
Si le SQL validé échoue (table supprimée, timeout, tokens anonymisés, 0
lignes retournées, etc.), on retourne None pour que le caller retombe sur
l'Exploration Guard classique. Aucun succès silencieux, aucun résultat
trompeur.

Confidentialité — Niveau 2+
---------------------------
Contrairement à `execute_sql` qui envoie un échantillon obfusqué, le
prefetch n'envoie AUCUNE ligne de données au LLM : seulement des counts et
des types. La raison : on exécute un SQL pour UNE AUTRE question (celle
qui a matché), potentiellement un autre client/exercice. L'utilisateur
courant n'a rien demandé qui justifie que ces lignes sortent vers le LLM
cloud.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Timeout du prefetch — bornage strict pour ne pas bloquer l'UX si le SQL
# validé est lent. Si ça saute, fallback sur exploration classique.
# Aligné avec le timeout executor.execute ci-dessous : ça coupe aussi côté
# pyodbc, pas seulement côté asyncio wait_for.
PREFETCH_TIMEOUT_SECONDS = 8.0

# Nombre max de lignes ramenées de la BDD pour le prefetch. Les stats se
# calculent sur cet échantillon ; inutile de scanner 100k lignes juste pour
# donner au LLM une idée de la forme du résultat.
PREFETCH_MAX_ROWS = 100

# Score minimal au-dessus duquel on prefetch. Aligné sur DEJA_VU_THRESHOLD :
# si une paire est jugée assez proche pour être injectée au LLM comme
# référence textuelle, elle est aussi assez proche pour être pré-exécutée.
# Importer à l'usage pour éviter les cycles d'import et respecter la valeur
# runtime si l'admin a ajusté la constante.
PREFETCH_MIN_SCORE: Optional[float] = None  # None → utilise DEJA_VU_THRESHOLD

# Limite de concurrence : pas plus de N prefetches simultanés côté BDD.
# Évite la saturation du serveur SQL Server (incident passé : 776 connexions
# Sage simultanées au lieu d'1 partagée). La valeur est volontairement basse
# — c'est un chemin "nice to have", pas un chemin critique.
_PREFETCH_SEMAPHORE = asyncio.Semaphore(2)

# Détection de tokens d'anonymisation (`~xxx`) dans les string literals du
# SQL validé. Si présents, exécuter le SQL retournerait 0 lignes (le token
# n'existe pas en BDD) → silent fail. On skip proprement.
_TOKEN_IN_LITERAL = re.compile(r"'[^']*~[^']*'")

# Détection ``STRING_AGG(...) WITHIN GROUP (...)`` — syntaxe supportée
# uniquement par SQL Server ≥ 2017 (compatibility_level ≥ 140). Sur les
# serveurs en compat 130/120/110 (SQL Server 2016/2014/2012 ou DBs en
# downgrade mode), la fonction ``STRING_AGG`` existe mais la clause
# ``WITHIN GROUP`` est rejetée avec l'erreur 10757 :
#     "La fonction 'STRING_AGG' ne peut pas avoir une clause WITHIN GROUP."
# Le pattern ``[^()]*`` est volontairement simple : il ne matche pas les
# STRING_AGG avec sous-appel imbriqué (ex: ``STRING_AGG(CAST(x AS VARCHAR),
# ',') WITHIN GROUP``) — ces cas (rares en pratique) tomberont sur le
# fallback runtime classique (capture du QueryError ci-dessous). Le but
# du pré-check est d'éliminer la majorité des cas sans connecter Sage,
# pas d'être exhaustif. ``re.DOTALL`` permet aux SQL multilignes (newlines
# entre args/parens) d'être matchés.
_STRING_AGG_WITHIN_GROUP_RE = re.compile(
    r"\bSTRING_AGG\s*\([^()]*\)\s*WITHIN\s+GROUP\b",
    re.IGNORECASE | re.DOTALL,
)

# Strippers de SQL comments + string literals, appliqués AVANT le regex
# ci-dessus pour éviter les faux positifs :
# - ``/* STRING_AGG(x) WITHIN GROUP */`` → commenté → skip ne devrait pas
#   matcher.
# - ``WHERE col = 'STRING_AGG(...) WITHIN GROUP'`` → littéral → idem.
# Les patterns sont conservateurs : on retire les blocs, ce qui suffit pour
# le check booléen "présence du pattern dans du code SQL réel". On ne fait
# PAS une analyse syntaxique complète (coûteux + dépendance sqlglot inutile
# ici). Cas exotiques restants (commentaire imbriqué style ``/* /* x */ */``)
# tomberont sur le fallback runtime.
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_SQL_STRING_LITERAL_RE = re.compile(r"'(?:''|[^'])*'")


def _strip_sql_comments_and_literals(sql: str) -> str:
    """Retire commentaires ``/* */`` + ``--`` et string literals ``'...'``.

    Le résultat n'est PAS du SQL exécutable — c'est une projection
    "code utile" sur laquelle on applique les regex de détection de
    pattern. Préserve la longueur approximative (remplace par espaces
    pour ne pas faire fusionner des tokens adjacents).
    """
    out = _SQL_BLOCK_COMMENT_RE.sub(" ", sql)
    out = _SQL_LINE_COMMENT_RE.sub(" ", out)
    out = _SQL_STRING_LITERAL_RE.sub("''", out)
    return out

# Parsing du compat-level depuis le label cached
# ``DatabaseConnection.server_version`` (format produit par
# :func:`db_config_service.build_server_version_label`). Deux formes :
# - "SQL Server 2019 (compatibilité 130 = syntaxe SQL Server 2016)"
#     → moteur 2019 EN MODE compat 130 (downgrade DB). On extrait 130.
# - "SQL Server 2016" (sans parens)
#     → moteur 2016, compat = base = 130. Aucun mention parens car
#       :func:`build_server_version_label` omet le suffix quand
#       version moteur = compat-version.
# Pattern bilingue (FR + EN) — la version actuelle de
# :func:`build_server_version_label` produit du FR, mais un futur i18n
# pourrait basculer en EN. Le regex couvre les deux formes pour rester
# robuste à un éventuel pivot du label sans nécessiter une bump
# coordonnée des deux fichiers. Tolérance ``[ée]`` pour FR
# (avec/sans accent selon encodage), ``y`` pour EN (``compatibility``).
_COMPAT_FROM_LABEL_RE = re.compile(
    r"\bcompatibilit[éey]+\s*(?:level\s+)?(\d{2,3})",
    re.IGNORECASE,
)
_VERSION_YEAR_FROM_LABEL_RE = re.compile(r"SQL Server\s+(\d{4})", re.IGNORECASE)

# Mapping interne version-year → compatibility_level — duplique
# :data:`db_config_service._COMPAT_LEVEL_TO_VERSION` inversé. On garde
# une copie locale pour éviter un cycle d'import au boot
# (deja_vu_prefetch est importé tôt par agent_service). Cf. test de
# garde ``test_compat_mapping_in_sync_with_db_config``.
_VERSION_YEAR_TO_COMPAT: dict[str, int] = {
    "2000": 80,
    "2005": 90,
    "2008": 100,
    "2012": 110,
    "2014": 120,
    "2016": 130,
    "2017": 140,
    "2019": 150,
    "2022": 160,
}

# Seuil de compatibility_level minimum pour ``STRING_AGG ... WITHIN GROUP``.
# SQL Server 2017 introduit la syntaxe (compat 140+).
_STRING_AGG_WITHIN_GROUP_MIN_COMPAT = 140


def _resolve_active_compat_level() -> Optional[int]:
    """Retourne le ``compatibility_level`` numérique du SQL Server actif,
    ou ``None`` si indéterminable.

    Pas d'I/O — lecture O(1) du cache module-level
    ``db_config_service._cached_version_label`` (peuplé au schema_sync).
    Si le cache est vide (boot fresh, sync jamais joué), retourne ``None``
    → le caller laisse l'exécution se faire normalement (fail-open prudent
    pour ne pas bloquer un prefetch valide sur un serveur récent).
    """
    try:
        from app.services.database.db_config_service import (
            get_sql_server_version_label_sync,
        )

        label = get_sql_server_version_label_sync()
    except Exception:  # noqa: BLE001 — pré-check, jamais bloquant
        return None
    if not label:
        return None
    # Cas 1 : mention explicite ``compatibilité NNN``. Domine la version
    # moteur (un SQL Server 2019 peut servir une DB en compat 130).
    m = _COMPAT_FROM_LABEL_RE.search(label)
    if m:
        try:
            return int(m.group(1))
        except ValueError:  # pragma: no cover — regex garantit \d
            return None
    # Cas 2 : label sans suffix compat → compat = version moteur. Reverse
    # map via le mapping local.
    year_m = _VERSION_YEAR_FROM_LABEL_RE.search(label)
    if year_m:
        return _VERSION_YEAR_TO_COMPAT.get(year_m.group(1))
    return None


async def prefetch_deja_vu_sql(
    pair: Dict[str, Any],
    *,
    timeout: float = PREFETCH_TIMEOUT_SECONDS,
    max_rows: int = PREFETCH_MAX_ROWS,
    min_score: Optional[float] = None,
    user: Any = None,
) -> Optional[Dict[str, Any]]:
    """Exécute le SQL d'une paire Q/SQL validée et condense les résultats.

    Args:
        pair: Dict avec au minimum `question`, `sql`, `score`.
        timeout: Coupe l'exécution si elle dépasse ce temps (secondes).
        max_rows: Nombre max de lignes rapatriées (pour le calcul des stats).
        min_score: Seuil de similarité en dessous duquel on refuse de prefetch.
        user: Objet ORM User pour activation du RLS data_access dans
            ``executor.execute``. Sans user, l'enforcer logue ``RLS skip``
            et la requête traverse sans filtrage (fail-OPEN historique).
            **Critique** : le déjà-vu peut servir le SQL d'un user A à
            la question similaire d'un user B — sans RLS, B recevrait
            les résultats du SQL de A même si B n'a pas les droits sur
            les tables référencées. À fournir systématiquement.

    Returns:
        Dict condensé (question, sql, score, columns, row_count, column_stats)
        ou None si échec/skip. Pas d'échantillon — cf. docstring module.
    """
    score = float(pair.get("score", 0) or 0)
    sql = (pair.get("sql") or "").strip()
    question = (pair.get("question") or "").strip()

    # Seuil unique : les deux engines produisent des scores dans [0,1]
    # (cosine pour le vectoriel, rappel pondéré IDF pour le TF-IDF).
    # Source SSoT : /admin/ai-config → confidence_threshold (BDD).
    # Fallback static DEJA_VU_THRESHOLD si BDD indispo. Cf. doctrine
    # feedback_no_double_cap — un seul cap admin, pas de hard-cap caché.
    if min_score is None:
        try:
            from app.services.ai.training_store import get_rag_runtime_config

            _cfg = await get_rag_runtime_config()
            min_score = _cfg["min_score"]
        except Exception:  # noqa: BLE001 — fallback static safe
            from app.constants_ai import DEJA_VU_THRESHOLD

            min_score = DEJA_VU_THRESHOLD

    # Gardes d'entrée : fail-fast sur données dégénérées.
    if not sql or not question:
        return None
    if score < min_score:
        logger.debug("Déjà-vu prefetch skipped: score %.2f < %.2f", score, min_score)
        return None

    # Anti-token : si le SQL validé contient un token anonymisé dans un
    # string literal, l'exécuter donnerait 0 lignes silencieusement. Skip.
    # Cas typique : une paire enregistrée après une session anonymisée où
    # le token n'a pas été réhydraté côté stockage.
    if _TOKEN_IN_LITERAL.search(sql):
        logger.warning(
            "Déjà-vu prefetch skipped: SQL contains anonymization tokens "
            "(~xxx) in string literals — would return 0 rows on real DB"
        )
        return None

    # Anti-cycle ``STRING_AGG ... WITHIN GROUP`` (fix audit 2026-05-22) :
    # une paire stockée à l'époque où la BDD active était en compat ≥ 140
    # (SQL Server 2017+) qu'on re-prefetch sur une BDD en compat < 140
    # produit systématiquement l'erreur 10757 ("La fonction 'STRING_AGG'
    # ne peut pas avoir une clause WITHIN GROUP"). Le fallback aval marche
    # mais on consomme un cycle Sage connect/exec/close inutile + un
    # WARNING log par run Iris. Le pré-check ici évite l'aller-retour :
    # on retombe direct sur Exploration Guard. Si le compat-level est
    # indéterminable (sync jamais joué), on laisse exécuter (fail-open).
    #
    # Strip commentaires + littéraux AVANT le regex pour éliminer les
    # faux positifs (``/* STRING_AGG(x) WITHIN GROUP */`` ou
    # ``WHERE col = '...WITHIN GROUP...'``) qui matcheraient sinon.
    sql_for_check = _strip_sql_comments_and_literals(sql)
    if _STRING_AGG_WITHIN_GROUP_RE.search(sql_for_check):
        compat = _resolve_active_compat_level()
        if compat is not None and compat < _STRING_AGG_WITHIN_GROUP_MIN_COMPAT:
            logger.info(
                "Déjà-vu prefetch skipped: STRING_AGG WITHIN GROUP incompatible "
                "avec SQL Server compat=%d (requis ≥ %d / SQL Server 2017) — "
                "fallback Exploration Guard",
                compat,
                _STRING_AGG_WITHIN_GROUP_MIN_COMPAT,
            )
            return None

    # Imports locaux : évite les cycles (agent_tools importe training_store
    # qui pourrait à terme importer ce module), et diffère les imports lourds.
    from app.core.exceptions import QueryError, ValidationError
    from app.services.ai.agent_tools import _compute_column_stats
    from app.services.database.query_executor import get_query_executor

    # pyodbc est optionnel au niveau module — on l'utilise uniquement pour
    # le catch d'erreurs. Si absent, on prend Exception en fallback prudent.
    try:
        import pyodbc

        pyodbc_error: tuple = (pyodbc.Error,)
    except ImportError:
        pyodbc_error = ()

    executor = get_query_executor()

    # Semaphore : borne la concurrence pour ne pas saturer SQL Server quand
    # plusieurs users tapent en même temps.
    async with _PREFETCH_SEMAPHORE:
        try:
            result = await asyncio.wait_for(
                # add_limit=True → TOP N bien formé (compatible DISTINCT/CTE).
                # timeout passé aussi à l'executor pour que pyodbc coupe côté
                # SQL Server (le wait_for asyncio ne suffit pas : pyodbc tourne
                # dans un thread exécuteur et ne respecte pas CancelledError).
                executor.execute(
                    sql,
                    max_rows=max_rows,
                    add_limit=True,
                    timeout=int(timeout),
                    user=user,
                    rls_source="deja_vu_prefetch",
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Déjà-vu prefetch timeout after %.0fs — fallback to Exploration Guard",
                timeout,
            )
            return None
        except (QueryError, ValidationError) as exc:
            # Erreurs de validation/execution attendues : SQL mal formé,
            # table supprimée, mot-clé interdit dans une vieille paire.
            logger.warning(
                "Déjà-vu prefetch rejected (%s) — fallback to Exploration Guard: %.200s",
                type(exc).__name__,
                exc,
            )
            return None
        except pyodbc_error as exc:  # type: ignore[misc]
            # Erreur ODBC côté pilote (connection refused, etc.).
            logger.warning(
                "Déjà-vu prefetch pyodbc error — fallback to Exploration Guard: %.200s",
                exc,
            )
            return None
        # Volontairement : on ne catch PAS Exception. Les bugs de code
        # (NameError, AttributeError) doivent bubble au caller qui a son
        # propre catch pour ne pas crasher le tour utilisateur.

    # Skip si le SQL validé ne retourne rien sur cette BDD : l'Exploration
    # Guard classique sera plus utile (le pattern est peut-être obsolète).
    if result.row_count == 0:
        logger.info(
            "Déjà-vu prefetch returned 0 rows — fallback to Exploration Guard "
            "(SQL validé peut-être obsolète pour cette BDD)"
        )
        return None

    rows_data = result.to_dicts()
    column_stats = _safe_stats(_compute_column_stats(rows_data, list(result.columns)))

    logger.info(
        "Déjà-vu prefetch OK: %d rows, %d cols (score=%.0f%%, truncated=%s)",
        result.row_count,
        len(result.columns),
        score * 100,
        result.truncated,
    )

    return {
        "question": question,
        "sql": sql,
        "score": score,
        # Engine utilisé par le RAG pour scorer cette paire — nécessaire à
        # ``format_prefetch_for_prompt`` pour choisir le bon seuil d'affichage
        # (TF-IDF et embeddings n'ont pas la même échelle).
        "engine": pair.get("engine"),
        "columns": list(result.columns),
        "row_count": result.row_count,
        "truncated": result.truncated,
        "column_stats": column_stats,
    }


def _safe_stats(stats: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Retire des column_stats les champs potentiellement sensibles.

    `_compute_column_stats` expose `min_value`/`max_value` pour les dates.
    Sur un SQL exécuté pour une question d'un AUTRE client/période, ces
    bornes fuitent la période d'activité réelle du client de la question
    originelle. On les retire — le LLM n'en a pas besoin pour adapter les
    filtres.
    """
    safe: Dict[str, Dict[str, Any]] = {}
    for col, s in stats.items():
        clean = {k: v for k, v in s.items() if k not in ("min_value", "max_value")}
        safe[col] = clean
    return safe


# Score en dessous duquel le SQL complet n'est PAS injecté dans le prompt
# (B7). En dessous de ce seuil, la similarité est trop faible pour que le
# LLM puisse raisonnablement "adapter" le SQL — il serait plus utile de
# juste montrer la structure (tables, nombre de colonnes) pour inspirer
# une nouvelle construction.
#
# Seuil unique pour les deux engines : le TF-IDF utilise maintenant
# ``compute_query_recall_idf`` qui produit des scores dans [0, 1] de même
# sémantique que les cosines d'embeddings ("à quel point la query est
# couverte").
_FULL_SQL_DUMP_MIN_SCORE = 0.60
# Seuil "quasi-identique" (message strict de copie à l'identique des structures).
_VERY_STRICT_MIN_SCORE = 0.80


def _extract_tables_from_sql(sql: str) -> list[str]:
    """Extrait (best-effort) les tables mentionnées dans un SQL.

    Utilisé uniquement pour le mode skeleton — on montre les tables
    impliquées sans dumper le SQL complet. Heuristique simple
    (FROM/JOIN + identifier). Pas besoin d'être exhaustif : c'est
    indicatif pour inspirer le LLM.
    """
    if not sql:
        return []
    # Capture FROM [table] ou FROM table et idem pour JOIN
    pattern = re.compile(
        r"\b(?:FROM|JOIN)\s+\[?([A-Za-z_][A-Za-z0-9_@#$]*)\]?",
        re.IGNORECASE,
    )
    seen: list[str] = []
    for m in pattern.finditer(sql):
        t = m.group(1)
        if t and t not in seen:
            seen.append(t)
    return seen[:10]  # cap à 10 pour éviter les SQL monstrueux


def _format_skeleton_only(
    pf: Dict[str, Any],
    extra_pairs: Optional[list[Dict[str, Any]]] = None,
) -> str:
    """Injection réduite pour score faible : structure sans SQL brut.

    À bas score (< 0.60), dumper le SQL complet induit en erreur : le
    LLM essaie de l'adapter alors qu'il faudrait reconstruire depuis
    zéro. Cette branche donne juste la forme du résultat (colonnes,
    tables utilisées) comme inspiration, sans figer la structure.
    """
    score = pf.get("score", 0) or 0
    tables = _extract_tables_from_sql(pf.get("sql", ""))
    columns = pf.get("columns", []) or []

    lines: list[str] = [
        "\n\n## 💡 Référence structurelle (similarité faible)",
        "",
        f"Une requête validée précédemment a une similarité de "
        f"**{score:.0%}** avec ta demande — trop faible pour être une "
        "base d'adaptation fiable. On te montre juste la **structure** "
        "de sa sortie pour inspirer ta construction, sans le SQL brut "
        "(qui risquerait de te figer sur une approche non pertinente).",
        "",
        f"**Question originale** : {pf.get('question', '')}",
        "",
    ]
    if tables:
        lines.append(f"**Tables impliquées** : {', '.join(tables)}")
    if columns:
        lines.append(
            f"**Colonnes résultat** ({len(columns)}) : "
            + ", ".join(f"`{c}`" for c in columns[:15])
            + (" …" if len(columns) > 15 else "")
        )
    lines.append("")
    # Anti-2+2=4 : on ne dicte PAS les noms de colonnes exacts (le LLM ne
    # doit pas recopier ce squelette). Mais on demande de motiver les
    # différences — une sortie notablement plus pauvre que la référence
    # sur des cas similaires trahit souvent une dimension oubliée par le
    # LLM. Le serveur compare aussi post-execute le nb de colonnes
    # produites vs la référence et injecte un warning si le ratio est
    # faible.
    if columns:
        lines.append(
            "**Cadre attendu** : la référence produit "
            f"**{len(columns)} colonnes** de sortie. Construis librement "
            "ta propre requête, mais si ta sortie compte nettement moins "
            "de dimensions/mesures, explicite la raison dans `[ANALYSIS]` "
            "— une simplification légitime OU une dimension oubliée. Les "
            "noms exacts n'ont pas besoin de coller : seuls les RÔLES "
            "comptent (dimension temporelle, acteur, catégorie, "
            "mesure agrégée)."
        )
    else:
        lines.append(
            "**Construction** : procède normalement — `search_schema`, "
            "`introspect_table`, puis assemble ton SQL. Cette référence "
            "est indicative."
        )

    # Hints structurés par phase (T8) — même en mode skeleton, on extrait
    # les signaux. À bas score, la valeur du SQL en tant que template est
    # faible, mais les concepts/tables/structure restent informatifs.
    try:
        from app.services.ai.rag_hints import (
            compute_phase_hints,
            format_hints_for_prompt,
        )

        _hint_pairs: list[Dict[str, Any]] = [
            {
                "question": pf.get("question", ""),
                "sql": pf.get("sql", ""),
                "score": pf.get("score", 0) or 0,
            }
        ]
        _hints = compute_phase_hints(_hint_pairs)
        _hints_block = format_hints_for_prompt(_hints)
        if _hints_block:
            lines.append("")
            lines.append(_hints_block)
    except Exception as _hint_exc:  # noqa: BLE001
        logger.debug("Hints rendering failed in skeleton mode: %s", _hint_exc)

    # Pas d'injection des extra_pairs en mode skeleton — on reste léger.
    return "\n".join(lines)


def format_prefetch_for_prompt(
    prefetch: Dict[str, Any],
    extra_pairs: Optional[list[Dict[str, Any]]] = None,
) -> str:
    """Formate le prefetch + paires complémentaires en bloc Markdown.

    Dès lors qu'un SQL validé est affiché ici, il a franchi `DEJA_VU_THRESHOLD`
    (0.40) côté `prefetch_deja_vu_sql` — le RAG a jugé qu'il était
    suffisamment pertinent. Le message encourage donc systématiquement à
    **partir du SQL validé** et à n'adapter que ce qui diffère.

    Seuil ``_FULL_SQL_DUMP_MIN_SCORE`` (0.60) : en dessous, on n'envoie
    que la STRUCTURE (tables, colonnes, score) — pas le SQL complet. À
    42% de similarité, le SQL est trop éloigné pour être une base
    d'adaptation fiable ; le dumper aurait tendance à figer le LLM sur
    une structure non pertinente (bug observé : 25 tours sans résultat
    car le LLM essaie d'adapter un SQL trop éloigné).

    `extra_pairs` permet de lister d'autres paires matchées (sans les
    exécuter) comme références additionnelles.
    """
    pf = prefetch
    score = pf.get("score", 0) or 0
    # Seuils uniques — les deux engines produisent des scores comparables
    # dans [0, 1] avec la même sémantique (couverture de la query).
    skeleton_only = score < _FULL_SQL_DUMP_MIN_SCORE
    very_strict = score >= _VERY_STRICT_MIN_SCORE

    if skeleton_only:
        return _format_skeleton_only(pf, extra_pairs)

    lines: list[str] = [
        "\n\n## 🎯 SQL VALIDÉ SIMILAIRE — POINT DE DÉPART INDICATIF",
        "",
        f"Une requête validée par l'utilisateur match ta demande à **{score:.0%}**.",
        "Elle vient d'être exécutée sur la BDD connectée : les tables/colonnes "
        "existaient au moment de la validation ET au moment de cette exécution. "
        "**Ce SQL est un INDICATIF, pas un template à recopier sans réflexion.** "
        "Le schéma a pu dériver, la sémantique de la demande peut être "
        "subtilement différente — c'est à toi de raisonner.",
        "",
        "### Comment l'utiliser",
        "",
        "1. **Compare** la question d'origine (ci-dessous) et la demande "
        "utilisateur courante. Repère les différences : valeurs de filtres "
        "(entité/dossier, exercices, codes, périodes), filtres en plus ou en "
        "moins, colonnes additionnelles demandées, sémantique métier.",
        "2. **Examine** la structure du SQL validé. Considère-la comme un "
        "exemple de construction qui a marché — pas comme une réponse à recopier.",
        "3. **Construis** ta requête en t'inspirant : reprends les JOINs / "
        "agrégats / CASE quand la sémantique correspond ; adapte-les ou "
        "reconstruis-les sinon. Les hints structurés ci-dessous (tables, "
        "concepts, structure IR) résument ce qui se répète entre paires "
        "similaires — ils sont un guide, pas une prescription.",
        "4. **Adapte explicitement** :",
        "   - valeurs dans les `WHERE ... IN (...) / = ...` — quasi toujours à changer,",
        "   - ajouter/retirer un filtre selon la demande courante,",
        "   - ajouter/retirer une colonne dans le SELECT/GROUP BY selon ce qui " "est demandé.",
        "5. **Vérifie la cohérence schéma** : si tu réutilises une table/colonne "
        "de l'exemple, confirme-la via `search_schema` ou `introspect_table` — "
        "un schéma sync peut avoir renommé/supprimé une colonne depuis la "
        "validation de cette paire.",
        "6. Vérifie avec `test_sql` puis `execute_sql`.",
    ]

    if very_strict:
        # Anti court-circuit #6 critique : on NE dit plus "réutilise la
        # structure telle quelle en n'adaptant que les valeurs". À haute
        # similarité, la tentation de blind copy est précisément le risque
        # T8 voulait neutraliser. Le bloc plus bas `format_hints_for_prompt`
        # affichera un flag `reusable_as_is` SI le schéma est confirmé compatible.
        lines.extend(
            [
                "",
                "**Score ≥ 0.80 : les deux questions paraissent très "
                "similaires. Tentation : recopier la structure et n'adapter "
                "que les valeurs. Risque : la sémantique métier de la "
                "demande utilisateur peut différer subtilement (granularité "
                "temporelle, exclusion implicite, périmètre élargi). "
                "Analyse la question courante en propre AVANT de te fier "
                "à la structure de la paire.**",
            ]
        )

    lines.extend(
        [
            "",
            f"**Question ayant produit ce SQL** :",
            f"> {pf['question']}",
            "",
            "### SQL validé",
            "```sql",
            pf["sql"],
            "```",
            "",
            "### Métadonnées du résultat (tel que ce SQL s'exécute actuellement)",
            f"- **Colonnes** ({len(pf['columns'])}) : "
            + ", ".join(f"`{c}`" for c in pf["columns"]),
            "",
            "⚠️ `row_count` et les stats ci-dessous reflètent le SQL **tel qu'il "
            "est écrit** (avec ses filtres d'origine). Tes adaptations (autres "
            "valeurs de filtres, autre périmètre) changeront ces chiffres — ne "
            "recopie pas ces nombres dans ta réponse finale, exécute ton SQL "
            "adapté via `execute_sql` pour obtenir les vrais.",
            "",
            f"- **row_count (référence SQL d'origine)** : {pf['row_count']}"
            + (" (tronqué)" if pf.get("truncated") else ""),
        ]
    )

    if pf["column_stats"]:
        lines.append("")
        lines.append("### Profil des colonnes (stats sur l'exécution d'origine)")
        for col, stats in pf["column_stats"].items():
            ctype = stats.get("type", "?")
            distinct = stats.get("distinct_count", "?")
            nulls = stats.get("null_count", 0)
            total = stats.get("total_rows", 0)
            parts = [f"`{col}` ({ctype})", f"{distinct} distincts"]
            if total:
                pct_null = round(nulls / total * 100) if total else 0
                parts.append(f"{pct_null}% NULL")
            if ctype == "string":
                parts.append(f"long {stats.get('min_length', '?')}-{stats.get('max_length', '?')}")
            lines.append(f"- {' · '.join(parts)}")

    # Paires additionnelles non exécutées : source d'inspiration si la
    # meilleure ne couvre pas tout. Le LLM peut les lire, voire les combiner.
    if extra_pairs:
        lines.append("")
        lines.append("### Autres SQL validés similaires (non exécutés — pour inspiration)")
        for p in extra_pairs:
            q = (p.get("question") or "").strip().replace("#", "").replace("---", "")
            s = (p.get("sql") or "").strip().replace("```", "")
            sc = p.get("score", 0) or 0
            if not q or not s:
                continue
            lines.append("")
            lines.append(f"**Question** ({sc:.0%}) : {q}")
            lines.append("```sql")
            lines.append(s)
            lines.append("```")

    # Hints structurés par phase pipeline (T8) — décomposition du SQL+question
    # en signaux par phase (concepts/tables/IR). Anti court-circuit : le LLM
    # voit ces signaux et décide consciemment, JAMAIS un raccourci de code.
    # Le bloc est additif aux sections ci-dessus ; il les contextualise.
    try:
        from app.services.ai.rag_hints import (
            compute_phase_hints,
            format_hints_for_prompt,
        )

        # On combine la paire prefetch + paires extra pour donner plus de
        # signal aux hints (le RAG informe, ne décide pas — donc plus de
        # paires = plus d'information à fournir).
        _hint_pairs: list[Dict[str, Any]] = [
            {
                "question": pf.get("question", ""),
                "sql": pf.get("sql", ""),
                "score": pf.get("score", 0) or 0,
            }
        ]
        for _p in extra_pairs or []:
            if isinstance(_p, dict) and _p.get("sql"):
                _hint_pairs.append(
                    {
                        "question": _p.get("question", ""),
                        "sql": _p.get("sql", ""),
                        "score": _p.get("score", 0) or 0,
                    }
                )

        _hints = compute_phase_hints(_hint_pairs)
        _hints_block = format_hints_for_prompt(_hints)
        if _hints_block:
            lines.append("")
            lines.append(_hints_block)
    except Exception as _hint_exc:  # noqa: BLE001 — fail-soft, on log et continue
        logger.debug("Hints by phase rendering failed (skipped): %s", _hint_exc)

    return "\n".join(lines)


__all__ = [
    "PREFETCH_TIMEOUT_SECONDS",
    "PREFETCH_MAX_ROWS",
    "PREFETCH_MIN_SCORE",
    "prefetch_deja_vu_sql",
    "format_prefetch_for_prompt",
]
