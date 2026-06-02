"""Détection des capabilities SQL Server utilisées dans un texte SQL.

Sert au feature #7 (auto-refactor SQL stockés quand la BDD change de
version) : quand un sync détecte un downgrade de compat avec
``broken_capabilities``, ce module trouve les paires Q/SQL stockées
dont le SQL utilise ces capabilities — c'est la liste à passer au LLM
rewrite.

Patterns regex
--------------
Chaque capability a un pattern simple qui matche son usage. Les patterns
sont conservateurs (faux positifs OK, faux négatifs pas OK) — la pipeline
LLM réécrira inutilement quelques paires si elles utilisent le nom dans
un commentaire ou un literal, ce qui est moins grave que de RATER une
paire qui crash sur le nouveau serveur.

Pour limiter les vrais faux positifs (mention du nom dans un commentaire
ou un literal SQL), on strip les commentaires et string literals avant
de matcher (même approche que ``deja_vu_prefetch._strip_sql_comments_and_literals``).
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Set

from sqlalchemy import select

from app.core.database import get_session
from app.models.training_data import TrainingData, TrainingDataType


logger = logging.getLogger(__name__)


# Patterns regex par capability. Match insensible à la casse.
# ``\b`` aux bornes pour éviter les sous-strings (ex: STRING_AGG ne doit
# pas matcher MY_STRING_AGG_HELPER).
_CAPABILITY_PATTERNS: Dict[str, re.Pattern[str]] = {
    # SQL Server 2012+
    "IIF": re.compile(r"\bIIF\s*\(", re.IGNORECASE),
    "OFFSET_FETCH": re.compile(r"\bOFFSET\s+\d+.*\bFETCH\s+(?:NEXT|FIRST)", re.IGNORECASE | re.DOTALL),
    "TRY_CONVERT": re.compile(r"\bTRY_CONVERT\s*\(", re.IGNORECASE),
    "CONCAT": re.compile(r"\bCONCAT\s*\(", re.IGNORECASE),
    # SQL Server 2016+
    "STRING_SPLIT": re.compile(r"\bSTRING_SPLIT\s*\(", re.IGNORECASE),
    "OPENJSON": re.compile(r"\bOPENJSON\s*\(", re.IGNORECASE),
    "JSON_VALUE": re.compile(r"\bJSON_VALUE\s*\(", re.IGNORECASE),
    "JSON_QUERY": re.compile(r"\bJSON_QUERY\s*\(", re.IGNORECASE),
    # SQL Server 2017+
    "STRING_AGG": re.compile(r"\bSTRING_AGG\s*\(", re.IGNORECASE),
    # STRING_AGG WITHIN GROUP : strictement plus contraint que STRING_AGG.
    # Pattern dédié pour le cas spécifique (rejeté par 10757 sur compat<140
    # MÊME quand STRING_AGG existe — cf. incident 2026-05-26 paire 8741).
    "STRING_AGG_WITHIN_GROUP": re.compile(
        r"\bSTRING_AGG\s*\([^()]*\)\s*WITHIN\s+GROUP\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "TRIM": re.compile(r"\bTRIM\s*\(", re.IGNORECASE),
    "TRANSLATE": re.compile(r"\bTRANSLATE\s*\(", re.IGNORECASE),
    # SQL Server 2022+
    "GREATEST_LEAST": re.compile(r"\b(?:GREATEST|LEAST)\s*\(", re.IGNORECASE),
    "DATE_BUCKET": re.compile(r"\bDATE_BUCKET\s*\(", re.IGNORECASE),
}


# Strippers SQL comments + string literals — évite les faux positifs où
# une capability est citée dans un commentaire ou une chaîne. Approche
# alignée sur ``deja_vu_prefetch._strip_sql_comments_and_literals``.
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_SQL_STRING_LITERAL_RE = re.compile(r"'(?:''|[^'])*'")


def _strip_sql_noise(sql: str) -> str:
    """Retire commentaires + string literals pour limiter les faux positifs."""
    out = _SQL_BLOCK_COMMENT_RE.sub(" ", sql)
    out = _SQL_LINE_COMMENT_RE.sub(" ", out)
    out = _SQL_STRING_LITERAL_RE.sub("''", out)
    return out


def extract_capabilities_from_sql(sql: str) -> Set[str]:
    """Retourne l'ensemble des capabilities détectées dans le SQL fourni.

    Args:
        sql: Texte SQL à scanner. Commentaires + string literals sont
            strippés avant matching.

    Returns:
        Set de noms de capabilities (clés de ``_CAPABILITY_PATTERNS``).
        Set vide si aucune capability détectée (ex: SELECT simple).
    """
    if not sql:
        return set()
    cleaned = _strip_sql_noise(sql)
    found: Set[str] = set()
    for cap_name, pattern in _CAPABILITY_PATTERNS.items():
        if pattern.search(cleaned):
            found.add(cap_name)
    return found


async def find_active_pairs_affected_by_capabilities(
    broken_capabilities: List[str],
) -> List[Dict]:
    """Cherche les paires Q/SQL ``is_active=True`` qui utilisent une
    capability cassée.

    Args:
        broken_capabilities: Liste de capability names (clés de
            ``_CAPABILITY_PATTERNS``) qui ne fonctionnent plus sur la
            nouvelle version BDD. Vide → retourne [] (no-op).

    Returns:
        Liste de dicts ``{"id": int, "question": str, "sql": str,
        "matched_capabilities": list[str]}`` — un dict par paire impactée.
        Vide si aucune paire n'utilise aucune des capabilities données.

    Note:
        Le scan est O(N rows × N patterns) — pour 10K paires et 16
        patterns c'est < 100ms. Pas de SQL filtering (LIKE) côté BDD
        car les patterns sont regex Python (plus précis que LIKE).
        Si la table devient massive (> 100K), optimiser via FTS5 ou
        index inversé sur les capability names.
    """
    if not broken_capabilities:
        return []

    broken_set = set(broken_capabilities)
    affected: List[Dict] = []

    async with get_session() as session:
        # SELECT projection minimal — on n'a besoin que des 3 champs
        # pour la pipeline rewrite. Pas d'hydration ORM lourde (cf.
        # même optim que Bug n°8 GET /terms).
        stmt = (
            select(TrainingData.id, TrainingData.question, TrainingData.sql)
            .where(
                TrainingData.data_type == TrainingDataType.QUESTION_SQL,
                TrainingData.is_active.is_(True),
                TrainingData.sql.isnot(None),
            )
        )
        rows = (await session.execute(stmt)).all()

    for row_id, row_question, row_sql in rows:
        if not row_sql:
            continue
        capabilities_in_sql = extract_capabilities_from_sql(row_sql)
        matched = capabilities_in_sql & broken_set
        if matched:
            affected.append(
                {
                    "id": int(row_id),
                    "question": row_question or "",
                    "sql": row_sql,
                    "matched_capabilities": sorted(matched),
                }
            )

    if affected:
        logger.info(
            "Feature #7 — %d paire(s) Q/SQL impactée(s) par les "
            "capabilities cassées %s (à réécrire par LLM)",
            len(affected),
            sorted(broken_set),
        )
    return affected
