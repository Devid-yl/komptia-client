"""T27 — Plan d'exécution préventif sur queries lentes.

But : avant d'exécuter une requête SQL coûteuse sur la BDD source, demander
au moteur (SQL Server) le plan d'exécution estimé et signaler les patterns
suspects (Table Scan massif, Hash/Nested Loops sans condition, cost
estimé > seuil). Le warning est purement informationnel — il ne bloque
pas l'exécution mais permet à l'agent IA Iris d'alerter l'utilisateur
("cette requête risque d'être longue, X rows scannées en estimation").

Workflow déclenché côté caller :

- Si SQL > ``char_threshold`` caractères OU contient ≥ ``multi_join_threshold``
  JOIN au top-level → on demande le plan.
- Sinon → on skip (overhead non justifié, query simple).

Connector contract (générique, agnostique du dialecte) :

- ``connector.explain_plan(sql, params=..., timeout=...) -> Optional[str]``
  retourne le XML brut SHOWPLAN_XML ou ``None`` si non supporté / erreur.
- Les connecteurs qui ne supportent pas (SQLite, MySQL stub) retournent
  ``None`` — le warning est alors silencieusement skippé.

Catégories "données fausses silencieuses" couvertes (cf. ``consequences.md``) :

- Table Scan sur table massive (estimation > seuil) = bug perf masqué
- Hash Match / Nested Loops sans clé / sans prédicat = cartésien probable
- Cost agrégé > seuil = la query va saturer la BDD source

Anti-hardcode (CONTRAT) :

- 0 nom de table/colonne BDD source dans ce module
- Seuils paramétrables au call-site (pas de magic number métier)
- Aucune hypothèse propre à un éditeur de logiciel particulier

Fail-safe absolu : ce module ne raise JAMAIS. Toute erreur (parse XML,
connecteur down, timeout) → retourne ``{"skipped": True, "skip_reason": ...}``.
Le caller (``agent_tools._handle_execute_sql``) ignore alors le warning
et continue l'exécution normale.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional
from xml.etree import ElementTree as ET  # noqa: S405 — parse SHOWPLAN XML connu

logger = logging.getLogger(__name__)

# ── Constantes de référence (paramétrables au call-site) ──────────────────
# Valeurs documentées ici pour audit, mais le caller peut surcharger.

DEFAULT_CHAR_THRESHOLD: int = 200
"""Longueur SQL (chars) au-delà de laquelle on déclenche le plan preview."""

DEFAULT_MULTI_JOIN_THRESHOLD: int = 2
"""Nombre de JOIN top-level au-delà duquel on déclenche le plan preview."""

DEFAULT_LARGE_TABLE_ROWS_THRESHOLD: float = 1_000_000.0
"""Seuil ``EstimateRows`` au-delà duquel un Table/Index Scan est suspect."""

DEFAULT_COST_THRESHOLD: float = 1000.0
"""Seuil ``StatementSubTreeCost`` au-delà duquel le plan est suspect."""

DEFAULT_TIMEOUT_SECONDS: float = 5.0
"""Timeout pour l'appel ``explain_plan`` (court — un plan est rapide)."""

# Namespace SHOWPLAN_XML SQL Server (stable depuis 2005)
_SHOWPLAN_NS = "http://schemas.microsoft.com/sqlserver/2004/07/showplan"
_NS_PREFIX = f"{{{_SHOWPLAN_NS}}}"

# Cap parse XML pour éviter OOM sur plans pathologiques (> 10 MB)
_MAX_XML_PARSE_BYTES: int = 10 * 1024 * 1024

# Severities exposées au LLM agent (cohérent avec T16/T22/T25)
SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


def _count_all_joins(sql: str) -> int:
    """Compte TOUS les JOIN du SQL (top-level ET sous-queries/CTE).

    Pour la trigger condition T27, on compte large : un JOIN coûteux dans
    un CTE expose autant de risque qu'un JOIN top-level. Sqlglot
    ``find_all(Join)`` traverse l'arbre entier.

    Fallback regex (avec strip commentaires + strings) si sqlglot KO.

    Generic : 0 hardcode dialect.
    """
    if not isinstance(sql, str) or not sql.strip():
        return 0

    try:
        import sqlglot
        from sqlglot import expressions as exp

        try:
            tree = sqlglot.parse_one(sql, dialect="tsql")
        except Exception:  # noqa: BLE001 — fallback
            try:
                tree = sqlglot.parse_one(sql)
            except Exception:  # noqa: BLE001 — final fallback regex
                tree = None
        if tree is not None:
            return sum(1 for _ in tree.find_all(exp.Join))
    except ImportError:
        pass

    # Fallback regex : strip commentaires + literals strings AVANT compter
    # JOIN pour éviter les faux positifs ('JOIN' string, -- JOIN comment).
    try:
        from app.utils.sql_scan import strip_all_sql_comments

        stripped = strip_all_sql_comments(sql)
    except Exception:  # noqa: BLE001 — fallback
        stripped = sql
    # Strip également les strings literals SQL (simple quoted) — best-effort.
    no_strings = re.sub(r"'(?:[^']|'')*'", "''", stripped)
    return len(re.findall(r"\bJOIN\b", no_strings, flags=re.IGNORECASE))


# Backward-compat alias : conserve l'ancien nom utilisé par les tests/sources
# pré-fix T27 si jamais. La sémantique a changé (all joins vs top-level
# seulement) — c'est volontaire pour couvrir les CTE.
_count_top_level_joins = _count_all_joins


def _is_eligible(
    sql: str,
    *,
    char_threshold: int,
    multi_join_threshold: int,
) -> tuple[bool, str]:
    """Détermine si la query mérite un plan preview.

    Returns:
        (eligible, reason). ``eligible=False`` avec ``reason`` explicatif.

    Cas CTE (``WITH ... SELECT``) : un CTE peut cacher une grosse query
    dans le bloc de définition. On baisse le seuil de longueur à 60%
    pour rester sensible (ex: ``WITH c AS (SELECT * FROM huge JOIN ...) SELECT * FROM c``
    a un wrapper court mais un coût élevé).
    """
    if not isinstance(sql, str) or not sql.strip():
        return False, "empty_sql"

    sql_len = len(sql)
    join_count = _count_all_joins(sql)

    # Boost sensibilité CTE : seuil chars × 0.6 pour les SQL démarrant
    # par WITH (les CTE wrappant un gros SELECT ont un préambule court).
    stripped_prefix = sql.lstrip().upper()
    is_cte = stripped_prefix.startswith("WITH")
    effective_char_threshold = int(char_threshold * 0.6) if is_cte else char_threshold

    if sql_len > effective_char_threshold:
        return True, f"sql_len_{sql_len}{'_cte' if is_cte else ''}"
    if join_count >= multi_join_threshold:
        return True, f"multi_join_{join_count}"

    return False, f"below_threshold(len={sql_len},joins={join_count})"


def _strip_ns(tag: str) -> str:
    """Retire le namespace ``{uri}local`` -> ``local``."""
    if tag.startswith("{"):
        end = tag.find("}")
        if end != -1:
            return tag[end + 1 :]
    return tag


def _safe_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _parse_showplan_xml(
    xml_text: str,
    *,
    large_table_rows_threshold: float,
    cost_threshold: float,
) -> dict[str, Any]:
    """Parse un SHOWPLAN_XML SQL Server et détecte les patterns suspects.

    Returns:
        Dict :
        - ``signals`` (list[dict]) : un dict par signal détecté
            ``{"kind": str, "details": dict}``
        - ``estimated_total_cost`` (float | None) : somme des
          ``StatementSubTreeCost`` (StmtSimple top-level).
        - ``estimated_total_rows`` (float | None) : somme des EstimateRows
          du RelOp racine de chaque statement.
        - ``parse_error`` (str | None) : si XML invalide / vide.

    Fail-safe : ne raise pas.
    """
    result: dict[str, Any] = {
        "signals": [],
        "estimated_total_cost": None,
        "estimated_total_rows": None,
        "parse_error": None,
    }

    if not isinstance(xml_text, str) or not xml_text.strip():
        result["parse_error"] = "empty_xml"
        return result

    raw_bytes = xml_text.encode("utf-8", errors="replace")
    if len(raw_bytes) > _MAX_XML_PARSE_BYTES:
        result["parse_error"] = f"xml_too_large_{len(raw_bytes)}"
        return result

    try:
        root = ET.fromstring(xml_text)  # noqa: S314 — pas un input user, vient de SQL Server
    except ET.ParseError as exc:
        logger.info("query_plan_preview: XML parse failed: %s", exc)
        result["parse_error"] = f"parse_error: {type(exc).__name__}"
        return result
    except Exception as exc:  # noqa: BLE001 — fail-safe absolu
        logger.info("query_plan_preview: unexpected XML error: %s", exc)
        result["parse_error"] = f"unexpected: {type(exc).__name__}"
        return result

    signals: list[dict[str, Any]] = []
    total_cost: float = 0.0
    total_cost_known: bool = False
    total_rows: float = 0.0
    total_rows_known: bool = False

    # StmtSimple / RelOp — la lecture du namespace est gérée par `_strip_ns`.
    # Pas de pré-calcul de tag avec/sans NS : on itère tout l'arbre avec
    # `_find_all_local` qui compare le local-name.

    def _find_all_local(node: ET.Element, local_name: str) -> list[ET.Element]:
        out: list[ET.Element] = []
        for el in node.iter():
            if _strip_ns(el.tag) == local_name:
                out.append(el)
        return out

    statements = _find_all_local(root, "StmtSimple")

    for stmt in statements:
        stmt_cost = _safe_float(stmt.attrib.get("StatementSubTreeCost"))
        if stmt_cost is not None:
            total_cost += stmt_cost
            total_cost_known = True
            if stmt_cost > cost_threshold:
                signals.append(
                    {
                        "kind": "high_cost",
                        "details": {
                            "statement_cost": round(stmt_cost, 3),
                            "threshold": cost_threshold,
                            "statement_text": (stmt.attrib.get("StatementText", "")[:200]),
                        },
                    }
                )
        # Pour chaque statement, on capture les EstimateRows du RelOp
        # racine (NodeId="0" en SQL Server, ou 1er enfant direct du
        # QueryPlan). Sommer par statement = totaux multi-stmt corrects.
        for child in stmt.iter():
            if _strip_ns(child.tag) == "RelOp":
                root_rows = _safe_float(child.attrib.get("EstimateRows"))
                if root_rows is not None:
                    total_rows += root_rows
                    total_rows_known = True
                break  # 1er RelOp = racine du statement

    # Scan tous les RelOp (à tous niveaux, y compris sous-queries) — c'est
    # là que les Table Scan / Hash Match / Nested Loops apparaissent.
    relops = _find_all_local(root, "RelOp")
    if not relops:
        # Plan sans aucun opérateur — XML probablement vide ou de
        # transition. On retourne un parse_error explicite plutôt que
        # silencieusement vide.
        result["parse_error"] = "no_relop_found"
        return result

    for relop in relops:
        physical_op = (relop.attrib.get("PhysicalOp") or "").strip()
        logical_op = (relop.attrib.get("LogicalOp") or "").strip()
        estimate_rows = _safe_float(relop.attrib.get("EstimateRows"))
        subtree_cost = _safe_float(relop.attrib.get("EstimatedTotalSubtreeCost"))

        # Cas où aucun StmtSimple n'a fourni de rows : fallback sur le
        # 1er RelOp rencontré (best-effort).
        if not total_rows_known and estimate_rows is not None:
            total_rows = estimate_rows
            total_rows_known = True

        # Signal 1 : Table Scan / Clustered Index Scan / Index Scan sur grosse table
        if physical_op in ("Table Scan", "Clustered Index Scan", "Index Scan"):
            if estimate_rows is not None and estimate_rows > large_table_rows_threshold:
                # Récupère le nom de l'objet scanné (table) si dispo, pour log
                obj_name = _extract_table_name(relop)
                signals.append(
                    {
                        "kind": "large_table_scan",
                        "details": {
                            "physical_op": physical_op,
                            "estimate_rows": round(estimate_rows, 0),
                            "threshold": large_table_rows_threshold,
                            "object_name": obj_name,
                            "subtree_cost": (
                                round(subtree_cost, 3) if subtree_cost is not None else None
                            ),
                        },
                    }
                )

        # Signal 2 : Hash Match sans HashKeysBuild/HashKeysProbe = cartésien
        if physical_op == "Hash Match":
            # Cherche les sous-éléments HashKeysBuild / HashKeysProbe
            has_build = any(_strip_ns(child.tag) == "HashKeysBuild" for child in relop.iter())
            has_probe = any(_strip_ns(child.tag) == "HashKeysProbe" for child in relop.iter())
            if not has_build and not has_probe:
                signals.append(
                    {
                        "kind": "hash_join_without_keys",
                        "details": {
                            "logical_op": logical_op,
                            "estimate_rows": (
                                round(estimate_rows, 0) if estimate_rows is not None else None
                            ),
                            "subtree_cost": (
                                round(subtree_cost, 3) if subtree_cost is not None else None
                            ),
                        },
                    }
                )

        # Signal 3 : Nested Loops sans Predicate ni OuterReferences = cartésien
        if physical_op == "Nested Loops":
            has_predicate = any(_strip_ns(child.tag) == "Predicate" for child in relop.iter())
            # OuterReferences indique une corrélation latérale (légitime)
            has_outer_refs = any(
                _strip_ns(child.tag) == "OuterReferences" for child in relop.iter()
            )
            if not has_predicate and not has_outer_refs:
                # Cartesian only si on a vraiment un LogicalOp Join (pas un
                # "Get" intermédiaire qui aura toujours pas de predicate).
                # Case-insensitive : couvre les variantes "Join" / "JOIN" /
                # "join" selon les dialectes / version SQL Server.
                is_join = "join" in logical_op.lower()
                if is_join:
                    signals.append(
                        {
                            "kind": "nested_loops_without_predicate",
                            "details": {
                                "logical_op": logical_op,
                                "estimate_rows": (
                                    round(estimate_rows, 0) if estimate_rows is not None else None
                                ),
                                "subtree_cost": (
                                    round(subtree_cost, 3) if subtree_cost is not None else None
                                ),
                            },
                        }
                    )

    result["signals"] = signals
    result["estimated_total_cost"] = round(total_cost, 3) if total_cost_known else None
    result["estimated_total_rows"] = round(total_rows, 0) if total_rows_known else None
    return result


def _extract_table_name(relop: ET.Element) -> str:
    """Best-effort : extrait le nom de l'objet scanné par un RelOp.

    Generic : aucun nom hardcodé. Retourne string vide si non trouvé.
    """
    for el in relop.iter():
        local = _strip_ns(el.tag)
        if local == "Object":
            # SQL Server expose Database/Schema/Table/Index attribs
            tbl = el.attrib.get("Table") or ""
            # Retire les [brackets] T-SQL pour avoir un nom propre
            return tbl.strip("[]")
    return ""


def _build_warning(
    parsed: dict[str, Any],
    *,
    cost_threshold: float,
) -> dict[str, Any]:
    """Construit le warning final à partir du parse XML.

    Severity :
    - 0 signal → severity ``info`` (mais ``has_warning=False``)
    - ≥ 1 signal high_cost OU cost > cost_threshold → ``critical``
    - sinon (large_table_scan / cartésien) → ``warning``
    """
    signals = parsed.get("signals") or []
    estimated_cost = parsed.get("estimated_total_cost")

    has_warning = len(signals) > 0
    severity = SEVERITY_INFO

    if has_warning:
        # Critical si cost agrégé > seuil ou un signal high_cost présent
        cost_critical = estimated_cost is not None and estimated_cost > cost_threshold
        any_high_cost = any(s.get("kind") == "high_cost" for s in signals)
        if cost_critical or any_high_cost:
            severity = SEVERITY_CRITICAL
        else:
            severity = SEVERITY_WARNING

    return {
        "has_warning": has_warning,
        "severity": severity,
        "signals": signals,
        "estimated_total_cost": estimated_cost,
        "estimated_total_rows": parsed.get("estimated_total_rows"),
    }


async def analyze_query_plan(
    sql: str,
    connector: Any,
    *,
    params: Optional[tuple] = None,
    char_threshold: int = DEFAULT_CHAR_THRESHOLD,
    multi_join_threshold: int = DEFAULT_MULTI_JOIN_THRESHOLD,
    large_table_rows_threshold: float = DEFAULT_LARGE_TABLE_ROWS_THRESHOLD,
    cost_threshold: float = DEFAULT_COST_THRESHOLD,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Analyse le plan d'exécution d'un SQL et retourne un warning si suspect.

    **Pré-condition de sécurité** : le caller DOIT avoir appliqué le RLS
    (``data_access_enforcer.enforce_sql``) sur le SQL AVANT d'appeler
    ``analyze_query_plan``. SHOWPLAN_XML envoie le SQL brut à SQL Server
    pour planification ; un SQL non-RLSé peut référencer des tables/colonnes
    interdites pour l'utilisateur et provoquer une erreur côté serveur qui
    révèle leur existence dans les logs. Defense-in-depth, pas une fuite
    de données (le plan est structurel) mais une fuite d'information.
    Le call-site standard (``agent_tools._handle_execute_sql``) respecte
    cette pré-condition (RLS appliqué ligne 3701 avant le hook T27).

    Args:
        sql: requête SQL (DÉJÀ RLS-modifiée par le caller — pré-condition).
        connector: instance du connecteur BDD source ou compatible (doit exposer
            ``async explain_plan(sql, params=..., timeout=...) -> Optional[str]``).
            Si ``None`` ou méthode absente → skip silencieux.
        params: paramètres positionnels ``?`` à binder pour le plan
            (utilisé si le SQL contient des placeholders).
        char_threshold: longueur SQL au-delà de laquelle on déclenche.
        multi_join_threshold: nb JOIN au-delà duquel on déclenche.
        large_table_rows_threshold: seuil suspect pour Table Scan.
        cost_threshold: seuil suspect pour cost agrégé.
        timeout_seconds: timeout de l'appel explain_plan.

    Returns:
        Dict :
        - ``skipped`` (bool) : True si pas analysé (raisons : SQL court,
          pas de JOIN, connector sans explain_plan, plan None, etc.)
        - ``skip_reason`` (str) : explication si ``skipped=True``
        - ``has_warning`` (bool) : True si au moins 1 signal suspect
        - ``severity`` (str) : info / warning / critical
        - ``signals`` (list[dict]) : un dict par signal détecté
        - ``estimated_total_cost`` (float | None) : cost agrégé
        - ``estimated_total_rows`` (float | None) : rows estimées root
        - ``triggered_by`` (str) : raison d'éligibilité ("sql_len_..." | "multi_join_...")

    Fail-safe : ne raise JAMAIS.
    """
    out: dict[str, Any] = {
        "skipped": False,
        "skip_reason": None,
        "has_warning": False,
        "severity": SEVERITY_INFO,
        "signals": [],
        "estimated_total_cost": None,
        "estimated_total_rows": None,
        "triggered_by": None,
    }

    # 1. Éligibilité côté caller-thresholds
    eligible, reason = _is_eligible(
        sql,
        char_threshold=char_threshold,
        multi_join_threshold=multi_join_threshold,
    )
    if not eligible:
        out["skipped"] = True
        out["skip_reason"] = reason
        return out
    out["triggered_by"] = reason

    # 2. Connector capable ?
    if connector is None or not hasattr(connector, "explain_plan"):
        out["skipped"] = True
        out["skip_reason"] = "connector_no_explain_plan"
        return out

    # 3. Appel explain_plan — fail-safe absolu
    try:
        xml_text = await connector.explain_plan(
            sql,
            params=params,
            timeout=timeout_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — fail-safe
        logger.info("query_plan_preview: explain_plan raised: %s", exc)
        out["skipped"] = True
        out["skip_reason"] = f"explain_plan_error: {type(exc).__name__}"
        return out

    if not xml_text:
        out["skipped"] = True
        out["skip_reason"] = "explain_plan_returned_none"
        return out

    # 4. Parse XML
    parsed = _parse_showplan_xml(
        xml_text,
        large_table_rows_threshold=large_table_rows_threshold,
        cost_threshold=cost_threshold,
    )
    if parsed.get("parse_error"):
        out["skipped"] = True
        out["skip_reason"] = f"parse_error: {parsed['parse_error']}"
        return out

    # 5. Build warning
    warning = _build_warning(parsed, cost_threshold=cost_threshold)
    out.update(warning)
    return out
