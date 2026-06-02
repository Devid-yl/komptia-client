"""Helpers pour exposer le schéma BDD à un LLM en mode "invisible".

**Invariant fondamental** : tout texte produit par ce module et destiné à
un prompt LLM ne mentionne **jamais** une table, colonne ou FK qui n'est
pas dans la :class:`UserSchemaView` de l'utilisateur courant.

**Architecture** : ce module ne se substitue pas aux call-sites LLM
existants — il leur fournit des **briques utilitaires** qui consomment
une :class:`UserSchemaView`. Les call-sites continuent à gérer leur
cache et leur formatting, mais s'appuient sur ces helpers pour filtrer.

**API principale** :

- :func:`visible_table_names` — liste triée des tables visibles
- :func:`filter_to_visible` — filtre une liste candidate
- :func:`rewrite_ddl_for_view` — réécrit un DDL pour retirer FK et
  colonnes invisibles (fail-closed sur parse failure)
- :func:`build_compact_table_list` — format texte court (alternative
  au catalogue actuel d'``agent_knowledge``)
- :func:`build_ddl_block` — format multi-DDL pour les call-sites qui
  consomment un set de tables référencées (``result_assistant``,
  ``widget_planner``, ``reporting``)

**Fail-closed** : si la réécriture d'un DDL échoue (sqlglot plante, regex
ne match pas), la fonction retourne une chaîne vide pour ce DDL plutôt
que de risquer une fuite. Le LLM verra "DDL indisponible" et utilisera
ses outils (``search_documentation``, ``get_database_schema`` filtré)
pour récupérer l'info.

Anti-patterns à éviter :

- Construire un prompt schéma sans passer par ces helpers
- Bypasser la vue (``view.visible_tables``) avec une liste hardcodée
- Logguer le DDL réécrit côté serveur — ce n'est pas sensible mais on
  préfère que les logs serveur restent verbeux avec les vrais noms
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, List, Optional, Sequence

from app.services.data_access.visible_schema import UserSchemaView

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers de filtrage simples (consomment UserSchemaView)
# ---------------------------------------------------------------------------


def visible_table_names(view: UserSchemaView) -> List[str]:
    """Retourne les noms de tables visibles, triés alphabétiquement.

    Format des noms : tel qu'ils sont dans ``view.visible_tables``
    (UPPERCASE par convention de la vue).
    """
    return sorted(view.visible_tables)


def filter_to_visible(
    view: UserSchemaView,
    candidate_names: Iterable[str],
) -> List[str]:
    """Filtre une liste de noms de tables candidates en ne gardant que
    celles visibles dans la vue.

    Préserve l'**ordre d'entrée** (pratique pour les listes pré-triées
    par pertinence — ex: résultats RAG ranked by similarity). Comparaison
    insensible à la casse. Ne modifie pas la casse en sortie : on retourne
    le nom tel qu'il était dans ``candidate_names``.

    Args:
        view: vue utilisateur (immutable).
        candidate_names: noms candidats (peut être un générateur).

    Returns:
        Liste filtrée, dans l'ordre d'entrée, sans doublons.
    """
    seen: set[str] = set()
    out: List[str] = []
    for name in candidate_names:
        if not name:
            continue
        upper = name.upper()
        if upper in seen:
            continue
        seen.add(upper)
        if view.can_see_table(upper):
            out.append(name)
    return out


def visible_columns_for(
    view: UserSchemaView,
    table_name: str,
) -> Optional[frozenset[str]]:
    """Retourne le set de colonnes visibles pour une table donnée.

    Renvoie ``None`` si la table n'est pas dans la vue (le caller doit
    décider quoi faire — typiquement retourner un DDL vide). Renvoie
    ``frozenset()`` si la table est visible mais DDL inconnu (laisser
    passer côté caller — comportement permissif documenté).
    """
    if not view.can_see_table(table_name):
        return None
    return view.columns_by_table.get(table_name.upper(), frozenset())


# ---------------------------------------------------------------------------
# Réécriture DDL — retire FK + colonnes invisibles
# ---------------------------------------------------------------------------


#: Regex : capture une clause ``FOREIGN KEY ... REFERENCES <Table>(<col>)``
#: ou une clause inline ``REFERENCES <Schema>.<Table>(<col>)``. Capture
#: le nom de la table cible (group 1).
_FK_REFERENCES_RE = re.compile(
    r"REFERENCES\s+(?:\[?[\w]+\]?\.)?\[?([\w]+)\]?\s*\(",
    re.IGNORECASE,
)

#: Regex : ligne entière d'une clause FOREIGN KEY autonome (pas inline)
#: dans un CREATE TABLE. Format : ``[CONSTRAINT name] FOREIGN KEY (...) REFERENCES <Table>(...)``.
#: On veut retirer cette ligne entière si la table cible est invisible.
_STANDALONE_FK_RE = re.compile(
    r"(?:CONSTRAINT\s+\[?[\w]+\]?\s+)?FOREIGN\s+KEY\s*\([^)]+\)\s+"
    r"REFERENCES\s+(?:\[?[\w]+\]?\.)?\[?([\w]+)\]?\s*\([^)]+\)",
    re.IGNORECASE,
)

#: Regex : capture une ligne de colonne dans un CREATE TABLE.
#: Format : ``[col_name] type ...``. Group 1 = nom de colonne.
_COLUMN_LINE_RE = re.compile(
    r"^\s*\[?([A-Za-z_][A-Za-z0-9_]*)\]?\s+[A-Za-z][\w]*",
)


def rewrite_ddl_for_view(
    ddl: str,
    view: UserSchemaView,
    table_name: Optional[str] = None,
) -> str:
    """Réécrit un DDL ``CREATE TABLE`` pour le mode invisible.

    Transformations appliquées :

    1. **Si la table elle-même est invisible** : retourne ``""``.
       Le caller (typiquement un builder LLM context) skippe ce DDL.
    2. **Colonnes invisibles** : les lignes de colonnes dont le nom
       figure dans ``view.columns_by_table[table].symmetric_difference``
       sont retirées du corps du CREATE TABLE.
    3. **FK vers tables invisibles** : les clauses ``REFERENCES <T>(...)``
       sont retirées (clause autonome ou inline).
    4. **Fail-closed** : si la transformation échoue (regex misfire,
       structure inattendue), retourne ``""`` plutôt que de risquer une
       fuite.

    Args:
        ddl: contenu DDL ``CREATE TABLE`` ou ``CREATE VIEW``.
        view: vue utilisateur.
        table_name: nom de la table pour résoudre les colonnes visibles.
            Si ``None``, on tente d'extraire depuis le DDL (best-effort).

    Returns:
        DDL réécrit, ou ``""`` si la table est invisible ou si la
        réécriture a échoué.

    **Limite V0** : approche regex, pas sqlglot. Suffisant pour les DDL
    générés par le sync (format SQL Server standard). Si un DDL exotique
    casse, on fail-closed (DDL vide retourné). À durcir avec sqlglot
    en Phase 1.5 si nécessaire.
    """
    if not ddl or not isinstance(ddl, str):
        return ""

    # 1. Identifier la table cible
    target_table = table_name
    if not target_table:
        # Best-effort extraction depuis "CREATE TABLE [schema].[name]" ou "CREATE VIEW ..."
        m = re.search(
            r"CREATE\s+(?:TABLE|VIEW)\s+(?:\[?[\w]+\]?\.)?\[?([\w]+)\]?",
            ddl,
            re.IGNORECASE,
        )
        if m:
            target_table = m.group(1)

    if not target_table:
        # Pas pu identifier — fail-closed (on ne sait pas si visible).
        logger.warning(
            "llm_context: rewrite_ddl_for_view — impossible d'identifier "
            "la table cible, fail-closed (DDL vide retourné)."
        )
        return ""

    # 2. Vérifier la visibilité de la table
    if not view.can_see_table(target_table):
        return ""

    target_up = target_table.upper()
    visible_cols = view.columns_by_table.get(target_up)

    try:
        out = _rewrite_ddl_internal(ddl, view, visible_cols)
    except Exception as exc:
        logger.warning(
            "llm_context: rewrite_ddl_for_view exception sur %s — fail-closed: %s",
            target_table,
            exc,
        )
        return ""

    return out


def _rewrite_ddl_internal(
    ddl: str,
    view: UserSchemaView,
    visible_cols: Optional[frozenset[str]],
) -> str:
    """Implémentation de la réécriture, séparée pour clarté + try/except externe."""
    lines = ddl.split("\n")
    out_lines: List[str] = []

    for line in lines:
        # 1. Détecter une clause FOREIGN KEY autonome avec table cible
        # invisible → retirer la ligne entière.
        fk_match = _STANDALONE_FK_RE.search(line)
        if fk_match:
            target_table = fk_match.group(1).upper()
            if not view.can_see_table(target_table):
                continue  # skip cette ligne

        # 2. Détecter une clause inline ``REFERENCES <T>(...)`` sur une
        # ligne de colonne avec table cible invisible → retirer la
        # clause REFERENCES (mais garder la colonne).
        inline_match = _FK_REFERENCES_RE.search(line)
        if inline_match and not fk_match:
            target_table = inline_match.group(1).upper()
            if not view.can_see_table(target_table):
                # Retire tout ce qui est à partir de "REFERENCES"
                # jusqu'à la prochaine virgule ou fin de ligne.
                line = _strip_inline_references(line)

        # 3. Détecter une ligne de colonne, vérifier si la colonne est visible
        if visible_cols is not None:
            col_match = _COLUMN_LINE_RE.match(line)
            if col_match:
                col_name = col_match.group(1).upper()
                # Filtrer uniquement les colonnes nommées dans le DDL
                # qui ne matchent pas les mots-clés SQL fréquents.
                if col_name not in _SQL_KEYWORDS_TO_SKIP_IN_COLUMNS:
                    if visible_cols and col_name not in visible_cols:
                        # Colonne interdite pour cet user — retire la ligne.
                        continue

        out_lines.append(line)

    return "\n".join(out_lines)


#: Mots-clés SQL qui ressemblent à un nom de colonne mais n'en sont pas
#: (à ne pas filtrer). Aligné sur ``schema_utils._SQL_KEYWORDS_TO_SKIP``.
_SQL_KEYWORDS_TO_SKIP_IN_COLUMNS = frozenset(
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
        "VIEW",
    }
)


def _strip_inline_references(line: str) -> str:
    """Retire la clause inline ``REFERENCES <T>(...)`` d'une ligne de colonne.

    Garde le reste de la ligne intact. Si la regex ne match pas, retourne
    la ligne inchangée (defense-in-depth — le caller a déjà vérifié que
    la table cible est invisible).
    """
    # Match "REFERENCES [schema].[Table](col)" optionnellement avec ON DELETE/ON UPDATE
    pattern = re.compile(
        r"\s*(?:CONSTRAINT\s+\[?[\w]+\]?\s+)?"
        r"REFERENCES\s+(?:\[?[\w]+\]?\.)?\[?[\w]+\]?\s*\([^)]+\)"
        r"(?:\s+ON\s+(?:DELETE|UPDATE)\s+(?:CASCADE|SET\s+NULL|NO\s+ACTION|SET\s+DEFAULT))*",
        re.IGNORECASE,
    )
    stripped = pattern.sub("", line)
    return stripped


# ---------------------------------------------------------------------------
# Builders de contexte LLM (texte prêt à injecter dans un prompt)
# ---------------------------------------------------------------------------


def build_compact_table_list(
    view: UserSchemaView,
    *,
    documented_names: Optional[Sequence[str]] = None,
    max_tables: Optional[int] = None,
    header: bool = True,
) -> str:
    """Format compact "catalogue de tables" pour le system prompt LLM.

    Variante minimaliste du flow ``agent_knowledge._get_table_catalogue`` :
    elle produit le même type de bloc mais consomme une ``UserSchemaView``
    plutôt que d'appeler ``filter_table_catalogue`` séparément.

    Args:
        view: vue utilisateur.
        documented_names: optionnel — sous-ensemble des tables visibles
            qui sont "documentées" (enrichies, doc métier). Si fourni,
            le texte distingue "Tables documentées" et "Tables
            supplémentaires (non documentées)".
        max_tables: cap optionnel (None = pas de cap).
        header: si True, inclut un header explicatif.

    Returns:
        Texte UTF-8 prêt à concaténer dans un system prompt. Chaîne
        vide si aucune table visible.
    """
    visible = visible_table_names(view)
    if not visible:
        return ""

    if max_tables is not None and max_tables > 0:
        visible = visible[:max_tables]

    parts: List[str] = []
    if header:
        parts.append("### CATALOGUE DES TABLES DISPONIBLES")
        parts.append(
            "**RÈGLE** : utilise UNIQUEMENT les tables listées ci-dessous. "
            "N'invente PAS de nom de table. Utilise `search_documentation` "
            "ou `get_database_schema` pour explorer."
        )

    if documented_names:
        documented_filtered = filter_to_visible(view, documented_names)
        undocumented = [
            t for t in visible if t.upper() not in {d.upper() for d in documented_filtered}
        ]
        if documented_filtered:
            parts.append(
                f"\n**Tables documentées** ({len(documented_filtered)}) :\n"
                + ", ".join(documented_filtered)
            )
        if undocumented:
            parts.append(
                f"\n**{len(undocumented)} tables supplémentaires** disponibles "
                "(non encore documentées). Utilise `get_database_schema` pour les explorer."
            )
    else:
        parts.append(f"\n**Tables disponibles** ({len(visible)}) :\n" + ", ".join(visible))

    return "\n".join(parts) + "\n"


#: Regex : capture les noms de tables référencées dans un SQL via les
#: clauses ``FROM <table>``, ``JOIN <table>``, ``UPDATE <table>``, etc.
#: Best-effort textuel (pas sqlglot pour la perf — on est appelé par pair
#: RAG, potentiellement N=100×). Capture group 1 = nom de la table.
_SQL_TABLE_REF_RE = re.compile(
    r"\b(?:FROM|JOIN|UPDATE|INTO|TABLE)\s+(?:\[?[\w]+\]?\.)?\[?([\w]+)\]?",
    re.IGNORECASE,
)


def is_sql_safe_for_view(sql: str, view: UserSchemaView) -> bool:
    """Vérifie qu'un SQL ne référence que des tables visibles par cet user.

    Utilisé par le filtrage RAG (Phase 5.1) pour exclure les exemples
    Q/SQL qui mentionnent une table interdite — sinon ces exemples
    fuiteraient dans le contexte LLM même quand le schéma est filtré.

    **Sémantique** :

    - Admin / enforcement off / pas de restrictions → True (laisse passer)
    - User restreint → True ssi toutes les tables référencées sont dans
      ``view.visible_tables``
    - SQL vide / None / non parsable → True (permissif : on n'a pas pu
      identifier de table, donc on ne peut pas confirmer une fuite). Le
      runtime SQL bloquera de toute façon si fuite.

    **Heuristique regex** : best-effort textuel sur ``FROM``, ``JOIN``,
    ``UPDATE``, ``INTO``, ``TABLE``. Faux négatif possible sur SQL exotique
    (dynamic SQL, EXEC), mais le runtime check_sql_access fail-closed
    ces cas.

    Args:
        sql: requête SQL d'un exemple Q/SQL ou d'un document RAG.
        view: vue utilisateur courante.

    Returns:
        True si le SQL est safe à exposer au LLM, False sinon.
    """
    if not sql or not isinstance(sql, str):
        return True  # pas de SQL = pas de fuite via SQL
    if not view.has_restrictions:
        return True  # admin / enforcement off / pas de règles

    found_tables = _SQL_TABLE_REF_RE.findall(sql)
    if not found_tables:
        return True  # rien d'identifié → permissif (runtime check bloquera)

    for table_name in found_tables:
        if not view.can_see_table(table_name):
            return False
    return True


def build_ddl_block(
    view: UserSchemaView,
    ddl_entries: Iterable[dict],
) -> str:
    """Format multi-DDL pour les call-sites qui passent du DDL au LLM.

    Itère sur des entrées ``{table_name, ddl, table_role?, column_roles?}``
    (format de ``training_store.get_related_ddl_with_roles``), réécrit
    chaque DDL via :func:`rewrite_ddl_for_view`, et concatène les blocs.

    Les entrées dont la table est invisible ou dont le DDL est
    invalide (rewrite retourne ``""``) sont **silencieusement** skippées
    — c'est le point central du mode invisible : le LLM ne reçoit pas
    de marker "telle table existe mais cachée", il reçoit juste rien.

    Args:
        view: vue utilisateur.
        ddl_entries: iterable de dicts ``{table_name, ddl, ...}``.

    Returns:
        Concaténation des blocs DDL réécrits, séparés par ``\\n\\n``.
        Chaîne vide si aucun DDL ne passe le filtre.
    """
    blocks: List[str] = []
    for entry in ddl_entries:
        if not isinstance(entry, dict):
            continue
        ddl = entry.get("ddl") or entry.get("content")
        table_name = entry.get("table_name") or ""
        if not ddl:
            continue

        rewritten = rewrite_ddl_for_view(ddl, view, table_name=table_name)
        if not rewritten:
            continue

        # Annotations optionnelles (rôle table, rôles colonnes) — filtrées
        # pour ne pas mentionner une colonne interdite.
        block = rewritten
        table_role = entry.get("table_role")
        if table_role:
            block += f"\n-- Rôle: {table_role}"

        col_roles = entry.get("column_roles") or {}
        if col_roles:
            visible_cols = visible_columns_for(view, table_name)
            for col, role in col_roles.items():
                if visible_cols is None:
                    break  # table devenue invisible entre temps
                if visible_cols and col.upper() not in visible_cols:
                    continue  # colonne interdite, on n'expose pas le rôle
                block += f"\n-- {col}: {role}"

        blocks.append(block)

    return "\n\n".join(blocks)
