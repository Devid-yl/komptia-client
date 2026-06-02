"""Mémoire fin-de-conversation Iris — parité avec ``copilot_memory``.

Objectif
--------

À la clôture d'une conversation Iris (terminal_kind == ``done`` ou
``abandon`` avec un SQL exécuté avec succès auparavant), un appel LLM
**léger** synthétise le **contexte UTILISATEUR** réutilisable d'une
conversation à l'autre :

- Préférences de présentation / format de l'utilisateur.
- Terminologie habituelle de l'utilisateur (comment il désigne les choses).
- Type d'analyses / questions qu'il pose récurremment, domaine de focus.
- Conventions de travail qu'il exprime explicitement.

⚠️ **Pas du savoir BDD générique** (rôles de tables, sémantique de colonnes,
chemins de jointure, business rules) : ça relève du RAG par-correspondance
(``training_store``), pas de ce canal. C'est le contrat déclaré par le
consommateur en aval (``iris_user_memory.build_fusion_system_prompt``) — le
résumeur DOIT s'y conformer, sinon la fusion jette le contenu.

Le résumé est persisté dans ``Conversation.summary`` (TEXT) PUIS fusionné
dans ``User.iris_memory`` via ``iris_user_memory.fuse_user_memory`` — c'est
cette mémoire user consolidée qui est réinjectée dans le system prompt
(``agent_service`` ~ injection ``user_memory_section``). L'injection
**directe** des ``Conversation.summary`` au prompt a été retirée (task #93
PR1, doctrine « connaissance BDD = source unique = RAG », garde
``tests/unit/test_knowledge_unique_pr1.py``).

Différences avec ``copilot_memory``
-----------------------------------

* **Pas d'anonymisation** ici : Iris a déjà ``confidentiality.py`` (4
  niveaux) qui anonymise les valeurs au niveau outil. Les noms de tables
  et colonnes que résume cette mémoire SONT du schéma (Niveau 1 :
  non sensible, libre).
* **Persistance BDD locale** (``Conversation.summary``), pas
  ``.afz.json`` côté frontend (Iris ne manipule pas de classeurs).
* **Trigger** : terminal_kind ``done``/``abandon`` (cf. P2.2).

Sécurité & robustesse
---------------------

* **Sanitization bidirectionnelle** (markdown directifs, accolades,
  délimiteurs section) : à l'écriture (post-LLM) et à la lecture (pré-
  injection prompt) — un user qui injecterait un bloc système via la BDD
  est ainsi neutralisé.
* **Cap dur** 2000 chars en sortie (~ 650 tokens) — ne sature pas le
  prompt cache Anthropic au rechargement.
* **Fail-safe** : toute erreur provider/BDD est loggée mais ne raise pas.
  La conversation est sauvegardée avec ``summary=None``, le run principal
  reste réussi.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

#: Terminal kinds qui déclenchent la génération d'une mémoire fin-de-run.
#: L'abandon **avec** un SQL exécuté en succès en cours de session est
#: éligible (apprend du périmètre exploré). L'abandon sec sans SQL n'est
#: pas éligible (rien d'apprenable).
TERMINAL_KINDS_ELIGIBLE: frozenset[str] = frozenset({"done", "abandon"})

#: Tokens max demandés au LLM pour la synthèse. 800 ≈ 600 mots français.
MEMORY_MAX_TOKENS: int = 800

#: Cap dur sur la taille du résumé persisté (chars).
MEMORY_MAX_OUTPUT_CHARS: int = 2000

#: Sentinelle que le LLM résumeur DOIT renvoyer quand la conversation
#: n'apporte aucun contexte utilisateur réutilisable. Interceptée par
#: :func:`generate_session_memory` (→ ``None``) pour NE PAS la stocker dans
#: ``Conversation.summary`` ni déclencher une fusion LLM sur du vide — sinon
#: « rien à retenir » serait persisté/fusionné comme un faux fait utilisateur.
MEMORY_NOTHING_SENTINEL: str = "(rien à retenir)"

#: Nombre max de SQL réussis pris en compte dans l'input (les plus récents).
MAX_SUCCESSFUL_SQL_IN_INPUT: int = 5

#: Préfixes markdown directifs à stripper en début de ligne — empêche
#: qu'une mémoire passe pour une section système au run suivant.
_MD_PREFIX_RE: re.Pattern[str] = re.compile(r"(?m)^\s*(##+|---+|\*\*+)\s*")

#: Accolades — défense contre un double ``.format()`` accidentel downstream.
_BRACE_RE: re.Pattern[str] = re.compile(r"[{}]")

#: Délimiteurs de section connus dans les system prompts d'Iris.
#: Élargi suite à la review adversariale (C5) : la regex précédente
#: n'attrapait que les lignes ENTIÈREMENT formées comme ``[ANALYSIS]``.
#: Un attaquant pouvait passer ``[MEMORY] secret_payload`` ou
#: ``[ MEMORY ]`` (avec espaces unicode) à travers. La nouvelle regex :
#:  - matche n'importe où dans le texte (pas juste ligne entière)
#:  - tolère des espaces unicode dans le tag (\s couvre U+2007 etc.)
#:  - tolère des attributs/contenu après le mot-clé
#:  - case-insensitive
_SECTION_DELIM_RE: re.Pattern[str] = re.compile(
    r"\[\s*/?\s*(THINKING|ANALYSIS|SUGGESTIONS|MEMORY)\b[^\]]*\]",
    re.IGNORECASE,
)


def sanitize_session_memory(text: Optional[str]) -> str:
    """Nettoie un résumé pour qu'il soit safe à injecter dans le prompt.

    Strip markdown directifs, accolades, délimiteurs section, control chars,
    NFKC-normalise, plafonne à ``MEMORY_MAX_OUTPUT_CHARS``. Idempotent.

    Args:
        text: Résumé brut (LLM output ou contenu BDD).

    Returns:
        Texte nettoyé. Chaîne vide si ``text`` était None/vide.
    """
    if not text:
        return ""
    cleaned = unicodedata.normalize("NFKC", str(text))
    cleaned = _MD_PREFIX_RE.sub("", cleaned)
    cleaned = _BRACE_RE.sub("", cleaned)
    cleaned = _SECTION_DELIM_RE.sub("", cleaned)
    # Strip control chars sauf newline/tab.
    cleaned = "".join(
        ch for ch in cleaned if ch in ("\n", "\t") or unicodedata.category(ch)[0] != "C"
    )
    cleaned = cleaned.strip()
    if len(cleaned) > MEMORY_MAX_OUTPUT_CHARS:
        cleaned = cleaned[:MEMORY_MAX_OUTPUT_CHARS].rstrip() + "…"
    return cleaned


def _is_nothing_to_remember(text: Optional[str]) -> bool:
    """True si le résumeur a émis la sentinelle d'absence de contexte
    (:data:`MEMORY_NOTHING_SENTINEL`).

    Tolère casse, accents et ponctuation enveloppante (parenthèses/point) —
    ``sanitize_session_memory`` ne strippe PAS les parenthèses (``_BRACE_RE``
    ne couvre que ``{}``), donc on normalise ici. La comparaison est dérivée
    de la constante (pas de divergence producteur/consommateur).
    """
    if not text:
        return True

    def _norm(value: str) -> str:
        nfkd = unicodedata.normalize("NFKD", value)
        no_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
        return no_accents.strip().lower().strip("().!:;… \t\n")

    return _norm(text) == _norm(MEMORY_NOTHING_SENTINEL)


def build_memory_input(
    user_question: str,
    discoveries: Optional[str],
    successful_sqls: list[str],
    user_corrections: list[str],
    terminal_kind: str,
) -> str:
    """Construit l'input (user message) du LLM résumeur.

    On ne passe **que** la structure et les décisions (axe 6 : généricité —
    aucune valeur métier réelle hardcodée). Les SQL passés sont déjà
    paramétrés (les valeurs anonymisées via ``confidentiality`` sont déjà
    en place pour les hits PII).
    """
    sqls_section = ""
    if successful_sqls:
        recent = successful_sqls[-MAX_SUCCESSFUL_SQL_IN_INPUT:]
        sqls_section = "\nSQL exécutés avec succès (les plus récents) :\n"
        for sql in recent:
            sqls_section += f"```sql\n{sql.strip()}\n```\n"

    corrections_section = ""
    if user_corrections:
        corrections_section = "\nCorrections apportées par l'utilisateur :\n"
        for c in user_corrections:
            corrections_section += f"- {c}\n"

    discoveries_section = ""
    if discoveries:
        discoveries_section = f"\nCahier de découvertes en cours :\n{discoveries.strip()[:1500]}\n"

    return (
        f"Question initiale de l'utilisateur :\n{user_question.strip()[:500]}\n"
        f"{discoveries_section}"
        f"{sqls_section}"
        f"{corrections_section}"
        f"\nClôture : {terminal_kind}\n"
    )


def build_memory_system_prompt() -> str:
    """System prompt du LLM résumeur.

    Le résumé produit ALIMENTE ``User.iris_memory`` via ``fuse_user_memory``
    (cf. ``iris_user_memory.build_fusion_system_prompt``). Ce canal porte le
    contexte sur l'UTILISATEUR — PAS le savoir BDD générique, qui vit dans le
    RAG par-correspondance (``training_store``) et dont l'injection directe a
    été retirée (PR1, garde ``test_knowledge_unique_pr1``). On extrait donc ce
    qui est réutilisable d'une conversation à l'autre POUR CET UTILISATEUR.
    """
    return (
        "Tu observes une conversation entre un utilisateur et un agent SQL (Iris) "
        "et tu en extrais ce qui aidera l'agent à mieux servir CET UTILISATEUR "
        "lors de ses PROCHAINES conversations.\n\n"
        "Objectif : un mémo court (max 1500 caractères) de contexte UTILISATEUR — "
        "des faits stables et réutilisables d'une conversation à l'autre.\n\n"
        "Inclus uniquement ce qui concerne l'utilisateur lui-même :\n"
        "- Ses préférences de présentation / format (ex: « préfère les montants "
        "  en k€ », « veut un total en bas de tableau »).\n"
        "- Sa terminologie habituelle / comment il désigne les choses.\n"
        "- Le type d'analyses ou de questions qu'il pose récurremment, son "
        "  domaine de focus.\n"
        "- Ses conventions de travail exprimées explicitement.\n\n"
        "Exclus IMPÉRATIVEMENT (c'est le rôle du RAG, pas de cette mémoire) :\n"
        "- Le savoir BDD générique : rôles de tables, sémantique de colonnes, "
        "  chemins de jointure, business rules de la base.\n"
        "- Le détail des outils appelés et le SQL produit.\n"
        "- Les faits propres à CETTE session qui ne se généralisent pas (un "
        "  dossier précis, un millésime, « pas de joins complexes cette fois »).\n"
        "- Les valeurs réelles spécifiques et les hypothèses non confirmées.\n\n"
        "Si la conversation n'apprend RIEN de réutilisable sur l'utilisateur, "
        "réponds exactement : " + MEMORY_NOTHING_SENTINEL + "\n\n"
        "Format : prose concise, 3-8 lignes max, sans titre ni section markdown."
    )


async def generate_session_memory(
    user_question: str,
    discoveries: Optional[str],
    successful_sqls: list[str],
    user_corrections: list[str],
    terminal_kind: str,
    user_id: Optional[int] = None,
) -> Optional[str]:
    """Génère le résumé via un appel LLM léger (utility model).

    Args:
        user_question: question utilisateur à mémoriser (texte brut).
        discoveries: cahier de découvertes (FQCN, joins, filtres validés).
        successful_sqls: SQL exécutés sans erreur dans la session.
        user_corrections: corrections explicites apportées par l'utilisateur.
        terminal_kind: kind de fin (``done`` / ``abandon`` / ``error``…).
        user_id: identifiant utilisateur pour le proxy d'anonymisation
            (pseudonymizer user-scoped). ``None`` autorisé pour les appels
            système / batch — la couche PII regex s'applique quand même.

    Returns:
        Le résumé sanitizé, ou ``None`` en cas d'échec. **Ne raise jamais** —
        un échec de mémoire ne doit pas faire crasher le run principal
        (la conversation reste sauvegardée avec ``summary=None``).
    """
    if terminal_kind not in TERMINAL_KINDS_ELIGIBLE:
        return None
    if not (successful_sqls or discoveries):
        # Rien à mémoriser — abandon avant toute exploration utile.
        return None

    try:
        from app.services.ai.llm_runtime import (
            CallProfile,
            ModelKind,
            RetryPolicy,
            call_llm,
        )
        from app.services.ai.llm_providers import LLMRequest
        from app.services.anonymization import anonymize_for_llm
        from app.services.anonymization.proxy import (
            get_confidentiality_prompt,
        )

        profile = CallProfile(
            caller="iris_session_memory",
            model_kind=ModelKind.UTILITY,
            retry=RetryPolicy.STANDARD,
        )
        prompt = build_memory_input(
            user_question,
            discoveries,
            successful_sqls,
            user_corrections,
            terminal_kind,
        )

        # Proxy d'anonymisation single source of truth. ``user_id`` peut
        # être ``None`` (appel système) — la couche PII regex
        # (EMAIL/SIRET/IBAN/etc.) reste active même sans pseudonymizer
        # user-scoped. Le résumé final est dé-anonymisé pour que la BDD
        # ``conversation_messages.summary`` contienne du cleartext lisible
        # par le futur agent qui reprendra une conv similaire.
        prompt_anon, restore_fn = await anonymize_for_llm(user_id, prompt, "IRIS_CHAT")

        request = LLMRequest(
            prompt=prompt_anon,
            system=(
                get_confidentiality_prompt("IRIS_CHAT") + "\n\n" + build_memory_system_prompt()
            ),
            max_tokens=MEMORY_MAX_TOKENS,
            # Task #5 2026-05-26 : temperature omise → admin config
            # (/admin/ai-config) prime. Single source of truth. L'ancien
            # hardcode 0.2 ignorait silencieusement le réglage admin.
        )
        response = await call_llm(profile, request)
        text = getattr(response, "content", "") or ""
        # Dé-anonymisation : le summary est destiné à être réinjecté dans
        # un prompt user futur (cf. ``format_memory_for_prompt_injection``
        # ci-dessous) — on doit y voir les vrais noms pour que la mémoire
        # soit utile au futur agent.
        if text:
            text = restore_fn(text)
        cleaned = sanitize_session_memory(text)
        # Sentinelle « (rien à retenir) » → traiter comme absence de mémoire
        # (return None) : ne PAS persister dans Conversation.summary ni
        # déclencher la fusion LLM sur du vide. Restaure aussi le fallback
        # ``terminal_summary`` côté caller (agent_service), masqué sinon car
        # la sentinelle est une chaîne truthy. (Bug review adversariale 2026-05-30.)
        if _is_nothing_to_remember(cleaned):
            logger.info(
                "generate_session_memory: sentinelle d'absence de contexte "
                "utilisateur — summary=None (rien persisté, pas de fusion)"
            )
            return None
        return cleaned
    except Exception:  # noqa: BLE001 — fail-soft
        logger.warning(
            "generate_session_memory: échec LLM, conversation sauvée sans summary",
            exc_info=True,
        )
        return None


def format_memory_for_prompt_injection(
    summaries: list[str], header: str = "## Mémoire des conversations précédentes"
) -> str:
    """Formate une liste de résumés pour injection dans un system prompt.

    Le caller passe N résumés (les plus récents en premier idéalement).
    Chaque résumé est sanitizé une seconde fois (défense en profondeur :
    le contenu BDD pourrait avoir été modifié hors de notre code).
    """
    cleaned = [sanitize_session_memory(s) for s in summaries if s]
    cleaned = [s for s in cleaned if s]
    if not cleaned:
        return ""
    blocks = "\n\n".join(f"- {s}" for s in cleaned)
    return f"{header}\n\n{blocks}"
