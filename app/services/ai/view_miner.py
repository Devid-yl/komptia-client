"""View miner — extraction générique de contexte métier depuis les vues SQL.

Principe
--------
Les vues SQL sont une documentation exécutable : leur auteur a cristallisé dans
les JOINs, les alias de tables et les alias de colonnes une sémantique métier
qui dépasse ce que dit le schéma brut. Ce module reconnaît cette sémantique par
des **empreintes structurelles** universelles, sans aucune connaissance du
domaine ni de la BDD source.

Les 4 détecteurs
----------------
1. `_detect_multiple_aliases` — Même table référencée N fois avec alias distincts
   ⇒ elle joue N rôles selon le chemin de JOIN (ex. `T AS T1` et `T AS T2`
   dans la même vue avec 2 conditions de JOIN différentes).
2. `_detect_column_alias_roles` — `X AS Y` où Y diffère de X encode une étiquette
   sémantique (ex. `t.col AS colWithRole` — le suffix `WithRole` est la sémantique).
3. `mine_fk_suffix_roles` — Plusieurs FK source→target avec des suffixes distincts
   encodent des rôles spécialisés (ex. `aNoEnregBRoleX` vs `aNoEnregBRoleY`
   pointant tous deux vers la table `B`).
4. `mine_cooccurrence` — Tables co-présentes dans ≥ N vues = grappe fonctionnelle.

Contrat de sortie
-----------------
Toutes les fonctions retournent des `BusinessContextDraft`:
    {
        "content": str,             # texte français destiné au LLM
        "tags_tables": list[str],   # UPPER, normalisé
        "priority": int,            # 1 pour les auto-extraits
        "source": str,              # "view_mining:{identifiant}"
        "detector": str,            # identifiant du détecteur
        "evidence_view": str|None,  # vue source quand applicable
    }

Ce module est PUR (pas d'I/O). Il est consommé par `schema_sync.py` qui appelle
`TrainingStore.upsert_auto_business_contexts()` pour persister.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from itertools import combinations
from typing import Any, Dict, Iterable, List, Optional, Tuple

import sqlglot
from sqlglot import exp

logger = logging.getLogger(__name__)

# ── Paramètres des détecteurs ─────────────────────────────────
# Nombre minimum de vues partagées pour qu'une paire de tables soit considérée
# comme une grappe fonctionnelle (détecteur 4).
_COOCCURRENCE_THRESHOLD = 3

# Longueur minimale d'un rôle sémantique extrait (filtre le bruit type "01", "s").
_MIN_ROLE_LENGTH = 3

# Nombre max de voisins affichés par grappe de co-occurrence.
_COOCCURRENCE_MAX_NEIGHBORS = 6

# Expression pour repérer un qualificateur de colonne `alias.column` dans du SQL
# (extraction des alias de tables utilisés dans les conditions de JOIN).
_QUALIFIED_COL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.\w+")


# ──────────────────────────────────────────────────────────────────────────────
# Parsing défensif
# ──────────────────────────────────────────────────────────────────────────────


def _parse_view(view_ddl: str) -> Optional[exp.Expression]:
    """Parse un CREATE VIEW / SELECT. Retourne None sur échec (jamais d'exception)."""
    if not view_ddl or not view_ddl.strip():
        return None
    try:
        return sqlglot.parse_one(view_ddl, dialect="tsql")
    except sqlglot.errors.ParseError as exc:
        logger.debug("view_miner: parse error: %s", exc)
        return None
    except Exception as exc:  # robustesse absolue : jamais casser le sync
        logger.warning("view_miner: unexpected parse failure: %s", exc)
        return None


def _select_node(parsed: exp.Expression) -> Optional[exp.Select]:
    """Retourne le noeud SELECT principal (corps de la vue)."""
    if isinstance(parsed, exp.Select):
        return parsed
    found = parsed.find(exp.Select)
    return found if isinstance(found, exp.Select) else None


def _extract_tables_with_aliases(select_node: exp.Select) -> List[Dict[str, Any]]:
    """Liste les tables du FROM et des JOINs de ce SELECT (premier niveau uniquement).

    Exclut :
    - La vue cible du CREATE VIEW (pas présente dans le SELECT lui-même)
    - Les tables nichées dans des sous-requêtes
    """
    results: List[Dict[str, Any]] = []

    # FROM — on utilise find() plutôt que args.get("from") car sqlglot nomme la
    # clé "from_" (suffix underscore) et cette convention peut évoluer.
    from_clause = select_node.find(exp.From)
    if from_clause is not None:
        for tbl in from_clause.find_all(exp.Table):
            if _is_direct_child(tbl, from_clause):
                results.append(
                    {
                        "name": tbl.name,
                        "alias": tbl.alias_or_name or tbl.name,
                        "source": "FROM",
                        "on": None,
                    }
                )

    # JOINs
    for join in select_node.args.get("joins", []) or []:
        target = join.this
        if isinstance(target, exp.Table):
            on_expr = join.args.get("on")
            results.append(
                {
                    "name": target.name,
                    "alias": target.alias_or_name or target.name,
                    "source": (join.side or join.kind or "INNER").upper(),
                    "on": on_expr.sql() if on_expr else None,
                }
            )
    return results


def _is_direct_child(node: exp.Expression, ancestor: exp.Expression) -> bool:
    """True si `node` est dans la hiérarchie directe de `ancestor` sans traverser
    une sous-requête (pour filtrer les tables internes des Subquery)."""
    current = node.parent
    while current is not None and current is not ancestor:
        if isinstance(current, exp.Subquery):
            return False
        current = current.parent
    return current is ancestor


# ──────────────────────────────────────────────────────────────────────────────
# Détecteur 1 — Alias multiples = rôles multiples
# ──────────────────────────────────────────────────────────────────────────────


_EQUALITY_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\b"
)


def _extract_access_path_from_on(
    on_clause: str,
    alias: str,
) -> Optional[Dict[str, str]]:
    """Parse une condition ON pour identifier le chemin FK qui mène à `alias`.

    Exemple générique : on = "(TA.fk_col = TB.pk_col)" et alias = "TB"
    → retourne {"other_alias": "TA", "other_col": "fk_col", "pk_col": "pk_col"}

    Retourne None si :
    - La condition n'est pas une simple égalité X.col = Y.col
    - L'alias recherché n'apparaît pas dans la condition
    - La condition est trop complexe (AND/OR multi-clause — on prend le 1er match seulement)
    """
    if not on_clause or not alias:
        return None
    for match in _EQUALITY_RE.finditer(on_clause):
        left_alias, left_col, right_alias, right_col = match.groups()
        if right_alias == alias:
            return {
                "other_alias": left_alias,
                "other_col": left_col,
                "pk_col": right_col,
            }
        if left_alias == alias:
            return {
                "other_alias": right_alias,
                "other_col": right_col,
                "pk_col": left_col,
            }
    return None


def _detect_multiple_aliases(
    tables: List[Dict[str, Any]],
    view_name: str,
    column_aliases: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Détecte qu'une table est référencée N fois avec alias distincts = N rôles.

    Enrichit chaque règle avec :
    - Les chemins de JOIN de chaque alias (structurel)
    - La clause discriminatrice SQL (IN/NOT IN) dérivée structurellement quand
      un alias est accessible via OtherTable.FK — permet au LLM d'appliquer un
      filtre sur l'un des sous-ensembles sans deviner
    - Les aliases sémantiques de colonnes (si column_aliases passé) — hint sur
      le nom métier du rôle, mais ne conclut rien (laisse le LLM inférer)

    Args:
        tables: liste {name, alias, source, on} depuis _extract_tables_with_aliases
        view_name: nom de la vue (pour la source key)
        column_aliases: liste des {table_alias, alias, semantic_role} détectés
            dans la même vue par _extract_column_aliases (optionnel — si fourni,
            enrichit sémantiquement les règles concernant la table cible).
    """
    by_name: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for t in tables:
        by_name[t["name"]].append(t)

    # Map alias → table name pour tagger les tables liées via ON
    alias_to_table = {t["alias"]: t["name"] for t in tables}

    # Map alias_de_table → [semantic_role, …] depuis les column_aliases.
    # Ex générique : pour un alias "T2" qui a une colonne "name" aliasée en
    # "nameOwner" dans le SELECT, on enrichit T2 avec le rôle sémantique "Owner".
    semantic_by_alias: Dict[str, List[str]] = defaultdict(list)
    if column_aliases:
        for ca in column_aliases:
            ta = ca.get("table_alias")
            role = ca.get("semantic_role")
            if ta and role:
                semantic_by_alias[ta].append(role)

    drafts: List[Dict[str, Any]] = []
    for table_name, instances in by_name.items():
        distinct_aliases = {inst["alias"] for inst in instances}
        if len(distinct_aliases) < 2:
            continue

        related: set = {table_name.upper()}
        lines = [
            f"La table `{table_name}` est référencée {len(distinct_aliases)} fois "
            f"dans `{view_name}` avec des alias distincts. Elle joue donc "
            f"{len(distinct_aliases)} rôles métier différents selon le chemin de JOIN :",
            "",
        ]

        # Collecter les chemins discriminables (alias avec FK identifiable)
        discriminable_paths: List[Dict[str, Any]] = []

        for inst in instances:
            alias = inst["alias"]
            side = inst.get("source", "")
            on = inst.get("on")
            path = on or "FROM (table de base)"
            # Hint sémantique : si cet alias a été utilisé dans un alias de colonne
            # avec un suffixe métier, le mentionner (sans conclure).
            sem_hints = semantic_by_alias.get(alias, [])
            sem_str = ""
            if sem_hints:
                # Unique + joined
                uniq = sorted(set(sem_hints))
                sem_str = (
                    f"  → cet alias est nommé **{', '.join(uniq)}** dans les alias "
                    f"de colonnes de la vue"
                )

            lines.append(f"  • alias `{alias}` ({side} JOIN) — chemin : `{path}`")
            if sem_str:
                lines.append(sem_str)

            # Extraire la FK d'accès pour la clause discriminatrice
            if on:
                access = _extract_access_path_from_on(on, alias)
                if access:
                    other_alias = access["other_alias"]
                    other_col = access["other_col"]
                    pk_col = access["pk_col"]
                    other_table = alias_to_table.get(other_alias)
                    if other_table:
                        related.add(other_table.upper())
                        discriminable_paths.append(
                            {
                                "alias": alias,
                                "other_table": other_table,
                                "other_col": other_col,
                                "pk_col": pk_col,
                                "semantic_hints": sem_hints,
                            }
                        )
                # En plus : tagger toutes les tables mentionnées dans l'ON
                for ident in _QUALIFIED_COL_RE.findall(on):
                    parent_table = alias_to_table.get(ident)
                    if parent_table:
                        related.add(parent_table.upper())

        lines.append("")

        # Cadre conceptuel : les 2 rôles NE SONT PAS 2 sous-ensembles exclusifs,
        # ce sont 2 attributs complémentaires qui coexistent dans chaque ligne
        # de la vue (quand on joint les 2 alias, chaque ligne expose les 2).
        # Le LLM doit comprendre qu'il a plusieurs patterns d'usage — pas un
        # simple choix binaire include/exclude.
        lines.append(
            f"**Les {len(distinct_aliases)} rôles COEXISTENT dans chaque ligne** "
            f"de la vue (ce sont des attributs complémentaires, pas des "
            f"sous-ensembles exclusifs). Patterns d'usage possibles :"
        )
        lines.append("")
        lines.append(
            f"• **AFFICHER les {len(distinct_aliases)} rôles côte à côte** "
            f"(très fréquent — les vues natives le font déjà) : joins chaque "
            f"alias séparément et expose ses colonnes dans `SELECT`."
        )
        lines.append(
            f"• **FILTRER** sur un rôle (ex: une valeur précise dans un des rôles) : "
            f"joins l'alias correspondant puis `WHERE {{alias}}.{{col}} = <valeur>`."
        )
        lines.append(
            f"• **AGRÉGER** par un rôle (ex: somme par entité, somme par client) : "
            f"joins l'alias correspondant puis `GROUP BY {{alias}}.{{col_id}}`."
        )

        # Section "test de collision" : pour chaque chemin identifiable, donner
        # le SQL booléen qui teste si le Dossier courant joue AUSSI l'autre rôle.
        # Ce test sert aux cas où l'utilisateur veut discriminer les lignes où
        # un même enregistrement joue plusieurs rôles simultanément.
        if discriminable_paths:
            lines.append(
                f"• **DÉTECTER la collision entre rôles** — quand un même "
                f"enregistrement de `{table_name}` joue simultanément plusieurs "
                f"rôles dans la même ligne (typique des flux internes/récursifs). "
                f"Tests booléens disponibles :"
            )
            for dp in discriminable_paths:
                other_table = dp["other_table"]
                other_col = dp["other_col"]
                pk_col = dp["pk_col"]
                alias = dp["alias"]
                sem = dp["semantic_hints"]
                sem_note = ""
                if sem:
                    sem_note = (
                        f" — nommé **{', '.join(sorted(set(sem)))}** dans les alias de colonnes"
                    )
                lines.append(
                    f"    ◦ Pour tester si un `{table_name}` joue le rôle "
                    f"« via `{other_table}.{other_col}` » (alias `{alias}`){sem_note} :"
                )
                lines.append(
                    f"      `{table_name}.{pk_col} IN "
                    f"(SELECT DISTINCT {other_col} FROM {other_table} "
                    f"WHERE {other_col} IS NOT NULL)`"
                )
                lines.append(
                    f"      → TRUE si l'enregistrement courant joue aussi ce rôle. "
                    f"Utilise ce test en `WHERE ... IN` pour INCLURE cette classe, "
                    f"ou `WHERE ... NOT IN` pour l'EXCLURE, selon l'intention."
                )
            lines.append("")
            first_alias = sorted(distinct_aliases)[0]
            lines.append(f"🔴 OBLIGATOIRE — Avant d'écrire tout SQL impliquant `{table_name}` :")
            lines.append("")
            lines.append(f"Dans ton bloc [ANALYSIS], tu DOIS écrire explicitement :")
            lines.append(
                f"(a) quel(s) alias/rôle(s) de `{table_name}` tu retiens — "
                f"et pourquoi la demande utilisateur correspond à ce(s) rôle(s)"
            )
            lines.append(
                f"(b) si tu inclus ou exclus les collisions inter-rôles "
                f"(utilise le test `IN` ou `NOT IN` ci-dessus) — OU si tu ignores "
                f"la distinction (et pourquoi c'est acceptable ici)"
            )
            lines.append(
                f"(c) le nom d'alias (ex: `{first_alias}`) que tu utilises " f"dans le SQL"
            )
            lines.append("")
            lines.append(
                f"Ne pars PAS de l'hypothèse \"un seul rôle mentionné = un seul "
                f'rôle à joindre". Les rôles coexistent dans la même ligne des '
                f"vues natives."
            )
        else:
            lines.append("")
            lines.append(f"🔴 OBLIGATOIRE — Avant d'écrire tout SQL impliquant `{table_name}` :")
            lines.append("")
            lines.append(f"Dans ton bloc [ANALYSIS], tu DOIS écrire explicitement :")
            lines.append(
                f"(a) lequel des {len(distinct_aliases)} rôles de `{table_name}` " f"tu retiens"
            )
            lines.append(f"(b) pourquoi ce choix correspond à la demande utilisateur")
            lines.append("")
            lines.append(
                f"(Pas de test SQL de collision disponible — fie-toi aux patterns "
                f"AFFICHER/FILTRER/AGRÉGER ci-dessus.)"
            )

        drafts.append(
            {
                "content": "\n".join(lines),
                "tags_tables": sorted(related),
                # primary_table : la table réellement ambiguë (celle qui a
                # plusieurs alias). Utilisé par le guard `coexistent_role_not_
                # justified` pour ne fire QUE sur cette table, pas sur les tables
                # liées (tags_tables contient aussi les tables du chemin de JOIN).
                "primary_table": table_name.upper(),
                "priority": 5,
                "source": _mined_view_source_key(view_name),
                "detector": "multiple_aliases",
                "evidence_view": view_name,
            }
        )
    return drafts


# ──────────────────────────────────────────────────────────────────────────────
# Détecteur 2 — Alias de colonne = étiquette sémantique
# ──────────────────────────────────────────────────────────────────────────────


def _extract_column_aliases(
    select_node: exp.Select,
    tables: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Extrait les `X.col AS aliasY` où aliasY ≠ col (sémantique encodée)."""
    alias_to_table = {t["alias"]: t["name"] for t in tables}
    found: List[Dict[str, Any]] = []
    for item in select_node.expressions or []:
        if not isinstance(item, exp.Alias):
            continue
        inner = item.this
        if not isinstance(inner, exp.Column):
            continue  # expressions/fonctions : moins clair, on ignore
        col_name = inner.name
        table_alias = inner.table
        new_alias = item.alias
        if not col_name or not new_alias:
            continue
        if new_alias.lower() == col_name.lower():
            continue
        role = _extract_semantic_role(col_name, new_alias)
        if role is None or len(role) < _MIN_ROLE_LENGTH:
            continue
        found.append(
            {
                "original_column": f"{table_alias}.{col_name}" if table_alias else col_name,
                "table_alias": table_alias,
                "target_table": alias_to_table.get(table_alias),
                "alias": new_alias,
                "semantic_role": role,
            }
        )
    return found


def _extract_semantic_role(col_name: str, alias: str) -> Optional[str]:
    """Retourne la portion de `alias` qui ajoute une info par rapport à `col_name`.

    - Si `alias` commence par `col_name` (case-insensitive) → suffix après.
    - Sinon → l'alias entier (renommage complet = l'info sémantique est l'alias).
    """
    if not col_name or not alias:
        return None
    if alias.lower().startswith(col_name.lower()):
        suffix = alias[len(col_name) :]
        return suffix or None
    return alias


def _detect_column_alias_roles(
    aliases: List[Dict[str, Any]],
    view_name: str,
) -> List[Dict[str, Any]]:
    """Transforme les col-aliases en drafts, groupés par table cible."""
    if not aliases:
        return []
    by_target: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for a in aliases:
        target = a.get("target_table")
        if target:
            by_target[target].append(a)

    drafts: List[Dict[str, Any]] = []
    for target_table, col_aliases in by_target.items():
        lines = [
            f"Dans `{view_name}`, des colonnes de `{target_table}` sont exposées "
            "sous un alias qui encode leur rôle métier :",
            "",
        ]
        for a in col_aliases:
            lines.append(
                f"  • `{a['original_column']}` → `{a['alias']}`  "
                f"(rôle détecté : **{a['semantic_role']}**)"
            )
        lines.append("")
        lines.append(
            f"Quand la demande utilisateur mentionne un de ces rôles, privilégie "
            f"le chemin de JOIN qui aboutit à l'alias correspondant de `{target_table}`."
        )
        drafts.append(
            {
                "content": "\n".join(lines),
                "tags_tables": sorted({target_table.upper()}),
                "priority": 4,
                "source": _mined_view_source_key(view_name),
                "detector": "column_alias",
                "evidence_view": view_name,
            }
        )
    return drafts


# ──────────────────────────────────────────────────────────────────────────────
# Détecteur 3 — FK avec suffix sémantique (s'applique sur le schéma, pas sur
# une vue particulière)
# ──────────────────────────────────────────────────────────────────────────────

FK_ANALYSIS_SOURCE = "view_mining:fk_analysis"


def mine_fk_suffix_roles(
    fks: Iterable[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Détecteur 3 — plusieurs FK source→target avec noms distincts ⇒ rôles spécialisés.

    Args:
        fks: itérable de dicts {source_table, source_column, target_table}.

    Returns:
        Un draft par paire (source_table, target_table) ayant ≥ 2 FK.
    """
    try:
        by_pair: Dict[Tuple[str, str], List[str]] = defaultdict(list)
        for fk in fks:
            st = fk.get("source_table")
            sc = fk.get("source_column")
            tt = fk.get("target_table")
            if not (st and sc and tt):
                continue
            by_pair[(st, tt)].append(sc)

        drafts: List[Dict[str, Any]] = []
        for (source_t, target_t), cols in by_pair.items():
            if len(cols) < 2:
                continue
            roles = _extract_fk_suffix_roles(cols)
            if not any(role for _, role in roles):
                # Aucune distinction sémantique exploitable (LCP = colonnes identiques)
                continue
            lines = [
                f"La table `{source_t}` possède {len(cols)} clés étrangères distinctes "
                f"vers `{target_t}`. Chacune représente un rôle métier différent :",
                "",
            ]
            for col, role in roles:
                if role:
                    lines.append(f"  • `{source_t}.{col}` → `{target_t}` (rôle : **{role}**)")
                else:
                    lines.append(f"  • `{source_t}.{col}` → `{target_t}` (rôle neutre / base)")
            lines.append("")
            lines.append(
                f"Quand la demande mentionne un de ces rôles, choisis la FK correspondante "
                f"pour joindre `{target_t}` — pas la version neutre."
            )
            drafts.append(
                {
                    "content": "\n".join(lines),
                    "tags_tables": sorted({source_t.upper(), target_t.upper()}),
                    "priority": 3,
                    "source": FK_ANALYSIS_SOURCE,
                    "detector": "fk_suffix",
                    "evidence_view": None,
                }
            )
        return drafts
    except Exception as exc:
        logger.warning("view_miner: mine_fk_suffix_roles failed: %s", exc, exc_info=True)
        return []


def _extract_fk_suffix_roles(cols: List[str]) -> List[Tuple[str, Optional[str]]]:
    """Pour N FK vers la même cible, retourne [(col, role)].

    Deux stratégies, dans l'ordre :
    1. Si une colonne est préfixe (case-insensitive) de toutes les autres → elle est
       "neutre", les autres ont pour rôle la portion ajoutée.
    2. Sinon, rôle = portion après le préfixe commun de toutes les colonnes.
    """
    if len(cols) < 2:
        return []
    sorted_cols = sorted(cols, key=len)
    shortest = sorted_cols[0]
    others = [c for c in cols if c != shortest]
    shortest_lower = shortest.lower()

    if all(c.lower().startswith(shortest_lower) for c in others):
        result: List[Tuple[str, Optional[str]]] = []
        for c in cols:
            if c == shortest:
                result.append((c, None))
            else:
                suffix = c[len(shortest) :]
                result.append((c, suffix if len(suffix) >= _MIN_ROLE_LENGTH else None))
        return result

    # Préfixe commun à toutes
    lcp_len = _longest_common_prefix_length([c.lower() for c in cols])
    result = []
    for c in cols:
        role = c[lcp_len:] if lcp_len < len(c) else None
        result.append((c, role if role and len(role) >= _MIN_ROLE_LENGTH else None))
    return result


def _longest_common_prefix_length(strings: List[str]) -> int:
    if not strings:
        return 0
    min_len = min(len(s) for s in strings)
    for i in range(min_len):
        char = strings[0][i]
        if any(s[i] != char for s in strings):
            return i
    return min_len


# ──────────────────────────────────────────────────────────────────────────────
# Détecteur 4 — Co-occurrence dans les vues = grappe fonctionnelle
# ──────────────────────────────────────────────────────────────────────────────

COOCCURRENCE_SOURCE = "view_mining:cooccurrence"


def mine_cooccurrence(
    views: Iterable[Dict[str, Any]],
    threshold: int = _COOCCURRENCE_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Détecteur 4 — tables co-présentes dans ≥ `threshold` vues.

    Args:
        views: itérable de dicts {view_name: str, tables: list[str]}.
        threshold: seuil minimum de vues partagées (défaut 3).

    Returns:
        Un draft par table "centrale" ayant ≥ 2 voisins fréquents.
    """
    try:
        pair_counts: Counter = Counter()
        for v in views:
            tables_raw = v.get("tables") or []
            tables = sorted({t.upper() for t in tables_raw if isinstance(t, str) and t})
            if len(tables) < 2:
                continue
            for a, b in combinations(tables, 2):
                pair_counts[(a, b)] += 1

        neighbors: Dict[str, List[Tuple[str, int]]] = defaultdict(list)
        for (a, b), count in pair_counts.items():
            if count >= threshold:
                neighbors[a].append((b, count))
                neighbors[b].append((a, count))

        drafts: List[Dict[str, Any]] = []
        for center, others in neighbors.items():
            if len(others) < 2:
                continue
            others.sort(key=lambda x: (-x[1], x[0]))
            top = others[:_COOCCURRENCE_MAX_NEIGHBORS]
            top_names = [o[0] for o in top]
            lines = [
                f"La table `{center}` apparaît fréquemment avec d'autres tables dans "
                "les vues de cette base (grappe fonctionnelle détectée) :",
                "",
            ]
            for other, count in top:
                lines.append(f"  • `{other}` (co-présente dans {count} vues)")
            lines.append("")
            lines.append(
                f"Si une question implique `{center}`, ces tables sont probablement "
                "utiles pour construire la réponse complète."
            )
            drafts.append(
                {
                    "content": "\n".join(lines),
                    "tags_tables": sorted({center, *top_names}),
                    "priority": 1,
                    "source": COOCCURRENCE_SOURCE,
                    "detector": "cooccurrence",
                    "evidence_view": None,
                }
            )
        return drafts
    except Exception as exc:
        logger.warning("view_miner: mine_cooccurrence failed: %s", exc, exc_info=True)
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Entrée publique : mine_view()
# ──────────────────────────────────────────────────────────────────────────────


def mine_view(view_name: str, view_ddl: str) -> List[Dict[str, Any]]:
    """Applique les détecteurs 1 et 2 sur une vue donnée.

    Les détecteurs 3 (FK) et 4 (co-occurrence) opèrent sur d'autres inputs et
    ont leurs propres fonctions publiques (`mine_fk_suffix_roles`, `mine_cooccurrence`).

    Args:
        view_name: nom de la vue (utilisé comme identifiant de source).
        view_ddl: DDL complet (CREATE VIEW ... AS SELECT ...).

    Returns:
        Liste de BusinessContextDraft. Vide si rien de détectable ou si parsing échoue.
    """
    if not view_name or not view_ddl:
        return []
    parsed = _parse_view(view_ddl)
    if parsed is None:
        return []
    try:
        select_node = _select_node(parsed)
        if select_node is None:
            return []
        tables = _extract_tables_with_aliases(select_node)
        if not tables:
            return []
        # On calcule d'abord les column_aliases pour pouvoir enrichir les
        # règles multiple_aliases avec les hints sémantiques (ex. rôles extraits
        # depuis les alias de colonnes de la vue).
        col_aliases = _extract_column_aliases(select_node, tables)
        drafts: List[Dict[str, Any]] = []
        drafts.extend(_detect_multiple_aliases(tables, view_name, col_aliases))
        drafts.extend(_detect_column_alias_roles(col_aliases, view_name))
        return drafts
    except Exception as exc:
        logger.warning(
            "view_miner.mine_view(%s) failed: %s",
            view_name,
            exc,
            exc_info=True,
        )
        return []


def extract_view_tables(view_ddl: str) -> List[str]:
    """Utilitaire : liste les noms (distincts) de tables référencées dans une vue.

    Utile pour construire l'input de `mine_cooccurrence`.
    """
    parsed = _parse_view(view_ddl)
    if parsed is None:
        return []
    select_node = _select_node(parsed)
    if select_node is None:
        return []
    tables = _extract_tables_with_aliases(select_node)
    return sorted({t["name"] for t in tables if t.get("name")})


def _mined_view_source_key(view_name: str) -> str:
    """Clé de source canonique pour les drafts issus d'une vue donnée."""
    return f"view_mining:{view_name}"
