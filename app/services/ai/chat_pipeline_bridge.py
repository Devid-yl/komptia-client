"""Pont apprentissage chat ↔ pipeline autonome (todo #9).

La pipeline ``scripts/pipeline.py`` est un runtime autonome qui peut
être invoqué soit en CLI (test/debug), soit via l'outil ``run_pipeline``
depuis le chat Iris. Dans les deux cas, elle exécute les 8 phases sans
accès direct aux Q/SQL validés et insights métier appris en chat (via
``learn_insight`` / `save_memory`).

Ce module ouvre le pont : il expose des helpers async qui fetch depuis
le ``training_store`` (single source of truth des apprentissages) les
paires Q/SQL similaires à une query courante, pour injection dans les
prompts pipeline en tant que few-shot examples.

**Doctrine** :
- Pont à sens unique chat → pipeline. La pipeline NE écrit JAMAIS dans
  le training_store (c'est le chat agent qui apprend, pas la pipeline).
- Fail-safe sur toute erreur : la pipeline DOIT continuer même si le
  training_store est inaccessible (BDD locale down, mode CLI hors
  process, etc.). Retour : liste vide.
- Filtré par user si `user` fourni (mode invisible compatible).

**Pas de hardcode BDD** : utilise uniquement les API génériques du
training_store. Tout cabinet/secteur compatible.
"""

from __future__ import annotations

import logging
from typing import Any, List, Dict, Optional


logger = logging.getLogger(__name__)


# Cap conservateur : un récap raisonnable de few-shot examples.
# 5 paires Q/SQL = ~5KB de prompt en plus, négligeable vs le coût
# d'opportunité de mieux orienter le LLM sur les patterns appris.
_DEFAULT_N_RESULTS: int = 5


async def fetch_learned_q_sql_pairs_for(
    query: str,
    n_results: int = _DEFAULT_N_RESULTS,
    *,
    user: Any = None,
) -> List[Dict[str, Any]]:
    """Récupère les Q/SQL validés similaires à ``query``.

    Permet à la pipeline autonome de bénéficier des apprentissages
    accumulés via le chat Iris (insights validés par feedback user,
    Q/SQL ajoutés par ``learn_insight`` ou ``add_question_sql``).

    Args:
        query: Question NL courante (utilisée pour matcher les Q
            similaires via ``compute_query_recall_idf`` interne).
        n_results: Cap sur le nombre de paires retournées. Défaut 5.
        user: optionnel — si fourni et que l'enforcement RLS est ON,
            les paires référençant des tables hors-scope user sont
            filtrées (mode invisible compatible).

    Returns:
        Liste de paires ``{"question": str, "sql": str, "score": float,
        ...}`` issues du training_store. Liste vide en cas d'erreur
        (BDD down, training_store non initialisé en CLI, etc.) —
        fail-safe, la pipeline continue toujours.

    Doctrine : pont à sens unique. La pipeline NE doit JAMAIS écrire
    via ce helper (cf. ``learn_insight`` côté agent_service pour
    l'écriture).
    """
    if not query or not query.strip():
        return []
    try:
        from app.services.ai.training_store import get_training_store

        store = get_training_store()
        pairs = await store.get_similar_question_sql(
            query.strip(),
            n_results=n_results,
            user=user,
        )
        if not isinstance(pairs, list):
            return []
        return pairs
    except Exception as exc:  # noqa: BLE001 — fail-safe pipeline
        # La pipeline doit continuer même si le training_store est down.
        # En CLI (sans BDD locale init), get_training_store peut lever
        # une RuntimeError — log + return liste vide.
        logger.debug(
            "fetch_learned_q_sql_pairs_for: training_store inaccessible "
            "(query=%r): %s — pipeline continue sans few-shot examples",
            query[:80],
            exc,
        )
        return []


def format_learned_pairs_for_prompt(
    pairs: List[Dict[str, Any]],
    *,
    max_chars_per_pair: int = 800,
    max_pairs: int = 5,
) -> str:
    """Formate une liste de paires Q/SQL pour injection dans un prompt LLM.

    Format compact, lisible, sans surcharge tokenique inutile. Cap par
    paire pour éviter qu'une seule paire monstrueuse occupe tout le
    budget context. Cap global à ``max_pairs`` pour rester dans un
    ordre de grandeur prévisible (~5KB de prompt en plus).

    Si la liste est vide → string vide (le caller doit gérer l'absence
    de section "Apprentissages précédents" dans le prompt).

    Generic : aucun nom de table/concept BDD hardcodé.
    """
    if not pairs:
        return ""
    lines: List[str] = []
    for i, pair in enumerate(pairs[:max_pairs], 1):
        if not isinstance(pair, dict):
            continue
        q = str(pair.get("question") or "").strip()
        sql = str(pair.get("sql") or "").strip()
        if not q or not sql:
            continue
        if len(sql) > max_chars_per_pair:
            sql = sql[: max_chars_per_pair - 3] + "..."
        lines.append(f"Exemple {i} — Question : {q}")
        lines.append(f"SQL validé : {sql}")
        lines.append("")  # blank line entre exemples
    return "\n".join(lines).rstrip()
