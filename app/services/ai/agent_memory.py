"""
Système de mémoire dynamique pour Iris.

Iris peut sauvegarder des apprentissages pendant les conversations
et les retrouver automatiquement dans les conversations futures.

Architecture mise à jour 2026-05-22 :
- L'injection inconditionnelle dans le prompt Iris (``format_for_prompt``)
  est SUPPRIMÉE (cf. PR2 dans ``agent_service.py``). Vision user « knowledge
  unique = RAG by-correspondence ».
- Les nouvelles mémoires sauvegardées via ``save()`` sont écrites en
  ``DOCUMENTATION`` cabinet-wide pour être consultables par le RAG
  canonique (``compute_query_recall_idf`` via ``training_store``).
- 3 catégories actives : ``error_pattern`` / ``business_rule`` / ``sql_pattern``.
- La catégorie ``user_preference`` (qui « dormait » sans consommateur)
  a été supprimée le 2026-05-22 ; elle est remplacée par la mémoire
  user-scopée ``User.iris_memory`` (cf.
  ``app/services/ai/iris_user_memory.py``). Les anciennes entries
  ``category='user_preference'`` ont été désactivées par la migration
  ``deactivate_legacy_agent_memory_user_preference`` (cf.
  ``app/core/database.py``) — pas de perte de données, juste
  ``is_active=False``.

Contraintes inchangées :
- Budget strict : max ~800 tokens (~3200 chars) — désormais consommé par
  le RAG canonique au lieu de l'injection inconditionnelle.
- Déduplication par similarité TF-IDF (>0.85 = consolide au lieu de créer).
- Decay temporel : les mémoires non utilisées perdent en priorité.
- Validation : contenu min 10 chars, max 500 chars.
"""

import logging
from datetime import timezone
from typing import Any, List, Optional

from sqlalchemy import select, func, update

from app.core import clock
from app.core.database import get_session
from app.models.training_data import TrainingData, TrainingDataType
from app.services.ai.training_store import SimpleTextSearch

logger = logging.getLogger(__name__)

# --- Constantes ---
MAX_MEMORIES_INJECTED = 8
MAX_MEMORY_CHARS = 3200  # ~800 tokens
DEDUP_THRESHOLD = 0.85
MIN_CONTENT_LEN = 10
MAX_CONTENT_LEN = 500
DECAY_DAYS = 30  # Après 30 jours sans usage, quality_score -= 0.3
VALID_CATEGORIES = {"error_pattern", "business_rule", "sql_pattern"}

# Suite à la suppression de ``user_preference`` (2026-05-22, remplacée par
# ``User.iris_memory``), toutes les catégories restantes sont cabinet-wide
# et stockées en ``DOCUMENTATION`` (consultable par le RAG canonique
# ``compute_query_recall_idf`` via ``training_store``).
_CABINET_WIDE_CATEGORIES = {"error_pattern", "business_rule", "sql_pattern"}
# Sanity check au boot : la liste cabinet-wide doit couvrir toutes les
# VALID_CATEGORIES. Anti-régression silencieuse — si une nouvelle catégorie
# est ajoutée à ``VALID_CATEGORIES`` sans être classée, le module crash
# au boot au lieu de router silencieusement vers le mauvais data_type.
assert _CABINET_WIDE_CATEGORIES == VALID_CATEGORIES, (
    "agent_memory: VALID_CATEGORIES doit être couvert par "
    "_CABINET_WIDE_CATEGORIES — toute nouvelle catégorie doit être "
    "classée explicitement. Les mémoires user-scopées passent désormais "
    "par ``app/services/ai/iris_user_memory.py`` (champ ``User.iris_memory``)."
)

_CATEGORY_EMOJI = {
    "error_pattern": "⚠",
    "business_rule": "📌",
    "sql_pattern": "🔧",
}


class AgentMemory:
    """Mémoire persistante de Iris — stocke et retrouve des apprentissages."""

    def __init__(self):
        self._search = SimpleTextSearch()

    async def save(
        self,
        content: str,
        category: str,
        user_id: Optional[int] = None,
    ) -> dict:
        """
        Sauvegarde une mémoire. Déduplique automatiquement.

        Returns:
            dict avec "status" (created|consolidated|rejected) et "message"
        """
        content = content.strip()

        # Validation
        if len(content) < MIN_CONTENT_LEN:
            return {"status": "rejected", "message": "Contenu trop court (min 10 caractères)."}
        if len(content) > MAX_CONTENT_LEN:
            content = content[:MAX_CONTENT_LEN]

        if category not in VALID_CATEGORIES:
            return {
                "status": "rejected",
                "message": f"Catégorie invalide. Choix : {', '.join(sorted(VALID_CATEGORIES))}.",
            }

        # Vérifier déduplication
        existing = await self._get_all_active()
        if existing:
            query_tokens = SimpleTextSearch.tokenize(content)
            doc_tokens = [SimpleTextSearch.tokenize(m["content"]) for m in existing]
            # Todo #28 — Migration tfidf → compute_query_recall_idf pour
            # cohérence avec le RAG canonique (training_store retrieval).
            # Signature identique, scores [0,1]. La métrique de rappel
            # pondéré IDF est plus adaptée au pattern few-shot (cherche
            # l'exemple le plus applicable) qu'au retrieval documentaire
            # classique. Cf. compute_query_recall_idf docstring.
            scores = SimpleTextSearch.compute_query_recall_idf(query_tokens, doc_tokens)

            best_idx = max(range(len(scores)), key=lambda i: scores[i])
            if scores[best_idx] >= DEDUP_THRESHOLD:
                # Consolider : mettre à jour la mémoire existante
                target_id = existing[best_idx]["id"]
                return await self._consolidate(target_id, content, category)

        # Créer nouvelle mémoire. Toutes les catégories actives sont
        # cabinet-wide → ``DOCUMENTATION`` (consultable par RAG canonique
        # ``compute_query_recall_idf``). La catégorie ``user_preference``
        # supprimée le 2026-05-22 — la mémoire user-scopée vit désormais
        # dans ``User.iris_memory`` (cf. ``app/services/ai/iris_user_memory.py``).
        try:
            async with get_session() as session:
                record = TrainingData(
                    data_type=TrainingDataType.DOCUMENTATION,
                    content=content,
                    category=category,
                    # Tag `memory,<cat>` préservé : distingue les entries Iris
                    # `save_memory` des autres `DOCUMENTATION` (sync schéma,
                    # etc.) côté UI admin et requêtes ciblées.
                    tags=f"memory,{category}",
                    source="iris_memory",
                    is_active=True,
                    quality_score=1.0,
                    usage_count=0,
                    created_by=user_id,
                )
                session.add(record)
                await session.commit()

                logger.info(
                    "Mémoire créée (id=%s, cat=%s): %s",
                    record.id,
                    category,
                    content[:80],
                )
                return {
                    "status": "created",
                    "message": f"Mémoire sauvegardée [{category}].",
                }
        except Exception as e:
            logger.warning("Erreur sauvegarde mémoire: %s", e)
            return {"status": "rejected", "message": f"Erreur: {e}"}

    async def retrieve(
        self,
        question: str,
        max_chars: int = MAX_MEMORY_CHARS,
        *,
        user: Any = None,
    ) -> List[dict]:
        """
        Retrouve les mémoires pertinentes pour une question donnée.

        Applique le decay temporel, trie par pertinence + qualité,
        et respecte le budget de caractères.

        **Phase 5.2 (#62) — Filtrage mode invisible.** Si ``user`` est
        fourni ET a des règles ``deny`` actives, les mémoires dont le
        ``content`` mentionne un nom denied (atomique OU via closure
        transitive) sont retirées du résultat. Cohérent avec le scrub
        d'historique conversationnel (#97) : le LLM ne doit jamais voir
        un nom denied via une mémoire partagée par un autre user.

        L'apprentissage collectif (mémoires partagées entre users) est
        préservé : seules les mémoires CONTENANT le nom denied sont
        filtrées pour CE user, pas toutes les mémoires créées par un
        autre user.

        ``user=None`` (caller système / pré-Phase 5.2) → pas de filtrage,
        comportement legacy.

        Returns:
            Liste de dicts {"content", "category", "score", "id"}
        """
        all_memories = await self._get_all_active()
        if not all_memories:
            return []

        # **#62 — Filtre mode invisible** : retire les mémoires dont le
        # content contient un nom denied pour cet user. Defense-in-depth :
        # le LLM ne doit pas re-mentionner un nom interdit via une
        # mémoire issue d'un autre user (cas typique : user A a posé
        # une question contenant ``F_SALAIRES``, l'agent a appris
        # « pour ce type de question utiliser F_SALAIRES » ; admin
        # pose ensuite deny F_SALAIRES sur user B ; sans filtre, user B
        # verrait l'apprentissage de A re-mentionner F_SALAIRES).
        if user is not None and getattr(user, "role", None) != "admin":
            try:
                from app.services.data_access.error_messages import (
                    contains_protected_name,
                )
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                # 1 lookup view (cache 60s) + 1 frozenset des tables denied
                # (atomique ∪ closure transitive — cf. Phase 2.1).
                view = await build_user_schema_view(user)
                denied_tables: frozenset[str] = view.denied_tables_with_closure or frozenset()

                if denied_tables:
                    filtered: List[dict] = []
                    hidden_count = 0
                    for mem in all_memories:
                        content = mem.get("content") or ""
                        # contains_protected_name est SYNC : juste regex
                        # word-boundary case-insensitive. Pas de coût BDD.
                        if contains_protected_name(content, denied_tables):
                            hidden_count += 1
                        else:
                            filtered.append(mem)
                    if hidden_count > 0:
                        logger.info(
                            "agent_memory.retrieve: %d mémoire(s) cachée(s) "
                            "pour user_id=%s (closure data_access)",
                            hidden_count,
                            getattr(user, "id", None),
                        )
                    all_memories = filtered
                    if not all_memories:
                        return []
            except Exception:  # noqa: BLE001 — fail-safe
                # Si la lecture des règles plante, on garde all_memories
                # tel quel (le scrub final côté agent_service
                # scrub_llm_blocks_for_user est le filet de sécurité ultime).
                logger.warning(
                    "agent_memory.retrieve: filtre user=%s a crashé — "
                    "on continue sans filtrage (scrub LLM output reste actif)",
                    getattr(user, "id", None),
                    exc_info=True,
                )

        # Appliquer le decay temporel sur quality_score
        now = clock.now()
        scored_memories = []
        for mem in all_memories:
            # Decay : -0.01 par jour d'inactivité (basé sur updated_at ou created_at)
            last_used = mem["updated_at"] or mem["created_at"]
            if last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            days_idle = (now - last_used).days
            decay_penalty = min(days_idle * 0.01, 0.5)  # Max -0.5
            effective_quality = max((mem["quality_score"] or 1.0) - decay_penalty, 0.1)
            scored_memories.append((mem, effective_quality))

        # Calculer la pertinence par rappel pondéré IDF (todo #28).
        # Migration tfidf → compute_query_recall_idf pour cohérence avec
        # le RAG canonique. Same signature, [0,1]. Rappel-IDF est mieux
        # adapté que le cosine TF-IDF au pattern few-shot où l'on cherche
        # l'exemple le plus applicable au besoin courant (insensible à la
        # verbosité du document, pondération naturelle par rareté).
        query_tokens = SimpleTextSearch.tokenize(question)
        doc_tokens = [SimpleTextSearch.tokenize(m["content"]) for m, _ in scored_memories]
        tfidf_scores = SimpleTextSearch.compute_query_recall_idf(query_tokens, doc_tokens)

        # Score final = recall_idf * quality * (1 + log(usage_count + 1))
        # Cap usage_count à 100 pour éviter que le log ne croisse indéfiniment.
        # Variable name ``tfidf_scores`` historique préservé (sans renommage
        # invasif sur le bloc qui suit — sémantique [0,1] inchangée).
        import math

        results = []
        for i, (mem, eff_quality) in enumerate(scored_memories):
            capped_usage = min(mem["usage_count"] or 0, 100)
            usage_boost = 1 + math.log(1 + capped_usage)
            final_score = tfidf_scores[i] * eff_quality * usage_boost
            results.append(
                {
                    "id": mem["id"],
                    "content": mem["content"],
                    "category": mem["category"],
                    "score": round(final_score, 4),
                }
            )

        # Trier par score décroissant
        results.sort(key=lambda x: x["score"], reverse=True)

        # Couper au budget de caractères + max count
        selected = []
        total_chars = 0
        for r in results:
            if r["score"] < 0.01:
                break
            entry_chars = len(r["content"]) + 20  # overhead pour le formatage
            if total_chars + entry_chars > max_chars:
                break
            if len(selected) >= MAX_MEMORIES_INJECTED:
                break
            selected.append(r)
            total_chars += entry_chars

        # Incrémenter usage_count des mémoires sélectionnées
        if selected:
            ids = [r["id"] for r in selected]
            try:
                async with get_session() as session:
                    await session.execute(
                        update(TrainingData)
                        .where(TrainingData.id.in_(ids))
                        .values(
                            usage_count=TrainingData.usage_count + 1,
                            updated_at=now,
                        )
                    )
                    await session.commit()
            except Exception as e:
                logger.debug("Erreur incrémentation usage mémoires: %s", e)

        return selected

    def format_for_prompt(self, memories: List[dict]) -> str:
        """
        Formate les mémoires pour injection dans le system prompt.

        Format compact, une ligne par mémoire. Retourne "" si aucune mémoire.
        """
        if not memories:
            return ""

        lines = ["## Tes mémoires (apprentissages passés)", ""]
        for m in memories:
            emoji = _CATEGORY_EMOJI.get(m["category"], "•")
            lines.append(f"- {emoji} [{m['category']}] {m['content']}")

        lines.append("")
        lines.append(
            "_Utilise `save_memory` pour sauvegarder de nouveaux apprentissages "
            "quand tu découvres quelque chose d'utile pour le futur._"
        )
        return "\n".join(lines)

    async def count(self) -> int:
        """Nombre total de mémoires actives."""
        async with get_session() as session:
            result = await session.execute(
                select(func.count(TrainingData.id)).where(
                    TrainingData.data_type == TrainingDataType.AGENT_MEMORY,
                    TrainingData.is_active.is_(True),
                )
            )
            return result.scalar_one()

    async def _get_all_active(self) -> List[dict]:
        """Récupère toutes les mémoires actives, matérialisées en dicts (session-safe).

        Task #93 PR2.5 (2026-05-22) — couvre AUSSI les mémoires migrées
        vers ``DOCUMENTATION`` (cabinet-wide cf. ``_CABINET_WIDE_CATEGORIES``)
        en filtrant par ``source == "iris_memory"``. Garantit que le
        dédoublonnage (cf. ``save()`` ligne ~95) couvre toutes les
        entries Iris-memory peu importe leur ``data_type``, et que
        l'admin UI / les introspections (``count``, ``retrieve``) restent
        cohérentes avec ce qui est sauvé.
        """
        async with get_session() as session:
            result = await session.execute(
                select(TrainingData)
                .where(
                    # Match `DOCUMENTATION` taguée comme mémoire Iris
                    # (cabinet-wide depuis PR2.5) ET d'éventuelles entries
                    # `AGENT_MEMORY` legacy non migrées (couvre les anciennes
                    # entries `user_preference` désactivées 2026-05-22 — vu
                    # qu'on filtre aussi sur `is_active=True`, ces dernières
                    # sont implicitement écartées). `source == "iris_memory"`
                    # est plus robuste qu'un LIKE sur `tags` — c'est la SSOT
                    # pour « entry créée par save_memory » depuis le début.
                    TrainingData.source == "iris_memory",
                    TrainingData.is_active.is_(True),
                )
                .order_by(TrainingData.quality_score.desc())
            )
            return [
                {
                    "id": r.id,
                    "content": r.content,
                    "category": r.category,
                    "quality_score": r.quality_score,
                    "usage_count": r.usage_count,
                    "updated_at": r.updated_at,
                    "created_at": r.created_at,
                }
                for r in result.scalars().all()
            ]

    async def _consolidate(self, existing_id: int, new_content: str, new_category: str) -> dict:
        """Consolide une mémoire existante avec un nouveau contenu similaire."""
        try:
            async with get_session() as session:
                record = await session.get(TrainingData, existing_id)
                if not record:
                    return {"status": "rejected", "message": "Mémoire introuvable."}

                # Garder le contenu le plus long (plus informatif)
                if len(new_content) > len(record.content):
                    record.content = new_content

                # Mettre à jour la catégorie si changée
                if new_category != record.category:
                    record.category = new_category

                # Boost de qualité (la mémoire est confirmée comme utile)
                record.quality_score = min((record.quality_score or 0.5) + 0.1, 1.0)
                record.updated_at = clock.now()
                record.usage_count = (record.usage_count or 0) + 1

                await session.commit()

                logger.info(
                    "Mémoire consolidée (id=%s): %s",
                    record.id,
                    new_content[:80],
                )
                return {
                    "status": "consolidated",
                    "message": "Mémoire existante mise à jour (contenu similaire trouvé).",
                }
        except Exception as e:
            logger.warning("Erreur consolidation mémoire: %s", e)
            return {"status": "rejected", "message": f"Erreur: {e}"}


# Singleton
_agent_memory: Optional[AgentMemory] = None


def get_agent_memory() -> AgentMemory:
    """Récupère le singleton AgentMemory."""
    global _agent_memory
    if _agent_memory is None:
        _agent_memory = AgentMemory()
    return _agent_memory
