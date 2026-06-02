"""Extraction des dépendances SQL pour le closure transitif (Phase 1.5 / #17).

**Rôle** : étant donnée une définition SQL (``CREATE VIEW``, ``CREATE
FUNCTION``, ou juste un SELECT), retourner la liste des **tables atomiques
référencées**. Cette liste est ensuite stockée dans
``TrainingData.depends_on`` pour permettre le calcul de la fermeture
transitive (Phase 2.1 / #44).

**Approche** : sqlglot pour parser l'AST, parcours des Table nodes,
exclusion des CTE (qui sont des aliases internes, pas des tables physiques).
Aligné sur l'approche utilisée par ``app.services.data_access.enforcer.
extract_tables_and_columns`` — même bibliothèque, même dialecte ``tsql``,
même règles d'exclusion CTE.

**Fail-safe** : si sqlglot échoue (SQL malformé, T-SQL exotique non
supporté, version sqlglot incompatible), retourne ``[]``. Ce n'est PAS un
silent leak du closure transitif :
- Pour les SYNONYM : ``depends_on`` est posé par le sync directement
  depuis ``sys.synonyms.base_object_name`` (pas de parsing nécessaire).
- Pour les VIEW / FUNCTION dont le parsing échoue : ``depends_on=None``
  signale à Phase 2.1 « dépendances inconnues, fail-closed strict » →
  l'objet est traité comme dépendant de TOUT (bloqué dès qu'au moins
  une table existe dans les deny rules). C'est conservateur (faux
  positifs côté admin, jamais de faux négatifs).

**Pourquoi pas un module générique de SQL parsing** : ce parser est
spécifique au use case mode invisible. Il N'EXTRAIT QUE les tables
physiques (utiles pour le closure). Il ignore délibérément les colonnes,
alias, fonctions appelées dans le SELECT, etc. — ces métriques sont déjà
exposées par ``enforcer.extract_tables_and_columns`` et ``rag_hints``
pour leurs usages respectifs.
"""

from __future__ import annotations

import logging
import re
from typing import List, Set

logger = logging.getLogger(__name__)


def extract_dependencies_from_sql(sql: str) -> List[str]:
    """Extrait les tables physiques référencées par une définition SQL.

    Args:
        sql: Texte SQL complet. Peut être ``CREATE VIEW``, ``CREATE
            FUNCTION``, ou directement le SELECT. sqlglot tolère les 3.

    Returns:
        Liste **triée + dédupliquée** de noms de tables en UPPERCASE
        (convention Komptia). Exemples :

        - ``CREATE VIEW V AS SELECT * FROM F_ECRITURE JOIN F_DOSSIER``
          → ``["F_DOSSIER", "F_ECRITURE"]``
        - ``WITH C AS (SELECT FROM F_X) SELECT * FROM C`` → ``["F_X"]``
          (le CTE C est exclu)
        - ``SELECT * FROM dbo.F_X`` → ``["F_X"]`` (schéma stripé)
        - ``SELECT 1`` → ``[]`` (pas de table)
        - SQL invalide → ``[]`` (fail-safe, logged en warning)

    **Garantie** : la liste retournée ne contient JAMAIS de CTE name
    ni d'alias. Uniquement des noms de tables physiques.
    """
    if not sql or not isinstance(sql, str):
        return []

    # Strip simple : on retire les comments SQL (-- et /* */) avant parsing.
    # sqlglot les gère, mais certains commentaires exotiques (-- nested)
    # peuvent perturber. Strip défensif.
    cleaned = re.sub(r"--[^\n]*", "", sql)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

    try:
        import sqlglot
        from sqlglot import exp
    except ImportError:
        logger.error(
            "dependency_parser: sqlglot indisponible, fail-safe [] retourné. " "Installez sqlglot."
        )
        return []

    try:
        # Dialecte tsql pour cohérence avec le reste de Komptia (BDD source
        # = SQL Server). Si parsing échoue, on essaie dialecte générique en
        # fallback (utile pour les définitions copiées d'autres SGBD).
        try:
            parsed = sqlglot.parse_one(cleaned, dialect="tsql")
        except Exception:
            parsed = sqlglot.parse_one(cleaned)
    except Exception as exc:
        # Catastrophic parse error — SQL exotique non géré par sqlglot.
        logger.warning(
            "dependency_parser: parse failed (fail-safe [] retourné): %s",
            exc,
        )
        return []

    if parsed is None:
        return []

    # Indexer les CTE pour les exclure du résultat. ``find_all(exp.CTE)``
    # retourne tous les CTE peu importe leur profondeur (utile pour les
    # CTE imbriqués).
    cte_names: Set[str] = set()
    try:
        for cte in parsed.find_all(exp.CTE):
            alias = getattr(cte, "alias_or_name", None)
            if alias:
                cte_names.add(alias.upper())
    except Exception as exc:
        logger.warning("dependency_parser: CTE indexing failed: %s", exc)

    # Exclure l'objet créé lui-même. sqlglot parse ``CREATE VIEW V AS
    # SELECT * FROM A`` comme :
    #   Create
    #     ├── this = Table(V)   ← l'objet créé (à exclure)
    #     └── expression = Select(... From=Table(A) ...)
    # Sans cette exclusion, le résultat inclurait V parmi les "dépendances"
    # alors que V est ce qu'on définit, pas ce dont on dépend.
    # On extrait via une regex sur le SQL brut (simple, robuste) plutôt
    # que de descendre l'AST — la regex est insensible aux dialectes.
    self_object: Set[str] = set()
    m_create = re.search(
        r"\bCREATE\s+(?:OR\s+ALTER\s+)?(?:VIEW|FUNCTION|PROCEDURE|TRIGGER|SYNONYM)\s+"
        r"(?:\[?\w+\]?\.)?\[?([\w]+)\]?",
        cleaned,
        re.IGNORECASE,
    )
    if m_create:
        self_object.add(m_create.group(1).upper())

    # Parcourir tous les nodes Table et accumuler les noms réels.
    # ``exp.Table`` couvre les FROM, JOIN, sous-requêtes, UNION, etc.
    tables: Set[str] = set()
    try:
        for tbl in parsed.find_all(exp.Table):
            name = (getattr(tbl, "name", None) or "").strip()
            if not name:
                continue
            name_up = name.upper()
            # Exclure les CTE (aliases internes) et l'objet créé lui-même.
            if name_up in cte_names or name_up in self_object:
                continue
            tables.add(name_up)
    except Exception as exc:
        logger.warning("dependency_parser: table walk failed: %s", exc)
        return []

    return sorted(tables)
