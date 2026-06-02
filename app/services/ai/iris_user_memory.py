"""Mémoire Iris user-scoped — parité avec ``copilot_memory`` côté workbook.

Objectif
--------

Doter Iris d'une **mémoire fixe par utilisateur** : une seule chaîne
consolidée (~2000 chars max) injectée inconditionnellement dans le system
prompt de toutes les conversations Iris de ce user. Le pattern est calqué
sur ``copilot_memory`` (où la mémoire vit côté classeur), transposé au
scope ``User``.

Différences avec :

* ``agent_session_memory`` : ce dernier produit un résumé **par
  conversation** (persisté dans ``Conversation.summary``). La mémoire user
  ici fusionne ce résumé avec l'historique consolidé du user et écrit dans
  ``User.iris_memory``. ``agent_session_memory`` reste l'étage upstream qui
  alimente cette fusion.
* ``agent_memory`` (catégorie ``user_preference``) : ce système RAG par
  TF-IDF dormait sans consommateur — la nouvelle feature le remplace
  (catégorie ``user_preference`` supprimée le 2026-05-22, anciennes entries
  marquées ``is_active=False``).
* Doctrine **knowledge unique = RAG by-correspondence** (task #93 PR2,
  2026-05-21) : cette doctrine concerne le **savoir BDD** (schéma, table
  semantics, business rules) — d'où le RAG par-correspondance. Le contexte
  sur l'utilisateur lui-même (préférences, identité, conventions
  personnelles) est une autre catégorie, dont l'injection inconditionnelle
  reste légitime — c'est la justification confirmée explicitement par
  l'utilisateur.

Sécurité & robustesse
---------------------

* **Sanitization bidirectionnelle** déléguée à
  ``agent_session_memory.sanitize_session_memory`` (single source of
  truth : markdown directifs, accolades, délimiteurs section, NFKC,
  cap 2000 chars). Appliquée à l'écriture (post-LLM) ET à la lecture
  (pré-injection prompt) — un attaquant qui réussirait à injecter du
  contenu via la BDD est ainsi neutralisé.
* **Cap dur** sur la sortie LLM : ``IRIS_USER_MEMORY_MAX_TOKENS = 800``
  (~ 650 tokens texte), puis cap chars hérité de
  ``MEMORY_MAX_OUTPUT_CHARS`` (2000) côté sanitize.
* **Fail-safe** : toute erreur provider/BDD est loggée mais ne raise pas.
  La mémoire existante est préservée (pas de perte sur fail LLM), le run
  principal reste réussi.
* **Anonymisation runtime** : le contenu passe par ``anonymize_for_llm``
  au moment de l'appel LLM de fusion (PII regex + pseudonymizer
  user-scopé), puis dé-anonymisé pour le stockage (le user voit sa
  propre mémoire en clair via ``/data-privacy``).
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from app.services.ai.agent_session_memory import (
    MEMORY_MAX_OUTPUT_CHARS,
    sanitize_session_memory,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes du domaine user_memory
# ---------------------------------------------------------------------------

#: Soft-limit tokens demandés au LLM pour la fusion. 800 ≈ 600 mots français.
#: TOUJOURS passé via ``clamped_max_tokens(IRIS_USER_MEMORY_MAX_TOKENS, ...)``
#: au site d'appel — JAMAIS en littéral ``max_tokens=<int>`` (doctrine LLM
#: dynamique, cf. ``feedback_max_tokens_must_be_dynamic.md`` + contrat
#: ``CLAUDE.md`` « pas de magic max_tokens »).
IRIS_USER_MEMORY_MAX_TOKENS: int = 800

#: Cap chars hérité de ``agent_session_memory`` (single source of truth).
#: Exposé ici pour les tests + endpoints qui doivent connaître la limite
#: applicable à ``User.iris_memory``.
IRIS_USER_MEMORY_MAX_CHARS: int = MEMORY_MAX_OUTPUT_CHARS


# ---------------------------------------------------------------------------
# Sanitization (déléguée à agent_session_memory + garde delimiters spécifiques)
# ---------------------------------------------------------------------------


#: Délimiteurs ``<<<USER_MEMORY>>>`` / ``<<<END_USER_MEMORY>>>`` introduits par
#: ``format_user_memory_for_prompt_injection`` — un user qui éditerait sa
#: mémoire via PUT ``/api/iris/user-memory`` pourrait y insérer une fausse
#: fermeture pour faire suivre une directive système (prompt injection
#: trivial). On strip ces motifs au sanitize, en amont des délimiteurs
#: génériques de ``agent_session_memory``. Variantes tolérées : casse,
#: espaces internes, suffixe/préfixe ``/``, nombre de ``<``/``>`` ≥ 2.
_USER_MEMORY_DELIM_RE: re.Pattern[str] = re.compile(
    r"<{2,}\s*/?\s*(?:END_)?USER_MEMORY\b[^>]*>{2,}",
    re.IGNORECASE,
)
#: Garde-fou ultra-défensif : strip TOUTE séquence ``<<<`` / ``>>>``
#: restante (3+ angle brackets consécutifs) — ces séquences n'ont aucun
#: usage légitime dans un texte mémoire user et pourraient être assemblées
#: par concaténation pour reconstruire un délimiteur custom.
_TRIPLE_ANGLE_RE: re.Pattern[str] = re.compile(r"<{3,}|>{3,}")


def sanitize_iris_user_memory(text: Optional[str]) -> str:
    """Nettoie un texte mémoire user pour stockage/injection.

    Délégation à ``sanitize_session_memory`` (SSOT : markdown directifs,
    accolades, délimiteurs section, NFKC, cap 2000 chars) **plus** strip
    spécifique aux délimiteurs ``<<<USER_MEMORY>>>`` introduits par cette
    feature (anti prompt-injection F4 review adversariale 2026-05-22).

    Args:
        text: Contenu brut (LLM output, BDD ou input UI).

    Returns:
        Texte nettoyé. Chaîne vide si ``text`` était None/vide.
    """
    if not text:
        return ""
    # Strip user-memory-specific delimiters AVANT le sanitize global pour que
    # le cap chars en aval n'ait pas à compter ces séquences.
    stripped = _USER_MEMORY_DELIM_RE.sub("", str(text))
    stripped = _TRIPLE_ANGLE_RE.sub("", stripped)
    return sanitize_session_memory(stripped)


# ---------------------------------------------------------------------------
# Format injection prompt
# ---------------------------------------------------------------------------


_USER_MEMORY_HEADER: str = (
    "## Ce que tu sais sur cet utilisateur\n"
    "\n"
    "Mémoire factuelle consolidée par tes conversations précédentes avec CET "
    "utilisateur (préférences, conventions, contexte personnel). Utilise-la "
    "comme point de départ — c'est ce que tu sais de lui. Si une demande "
    "courante contredit un point, la demande l'emporte (la mémoire est "
    "indicative, pas prescriptive)."
)

_USER_MEMORY_OPEN: str = "<<<USER_MEMORY>>>"
_USER_MEMORY_CLOSE: str = "<<<END_USER_MEMORY>>>"


def format_user_memory_for_prompt_injection(memory: Optional[str]) -> str:
    """Formate la mémoire user pour injection dans un system prompt.

    Sanitize une deuxième fois (défense en profondeur — le contenu BDD
    pourrait avoir été modifié hors de notre code). Retourne ``""`` si
    la mémoire est vide ou ne survit pas à la sanitization.

    Args:
        memory: Contenu brut de ``User.iris_memory``.

    Returns:
        Bloc prêt à injecter dans le system prompt, ou ``""``.
    """
    cleaned = sanitize_iris_user_memory(memory)
    if not cleaned:
        return ""
    return (
        f"{_USER_MEMORY_HEADER}\n"
        f"\n"
        f"{_USER_MEMORY_OPEN}\n"
        f"{cleaned}\n"
        f"{_USER_MEMORY_CLOSE}"
    )


# ---------------------------------------------------------------------------
# Prompt LLM de fusion
# ---------------------------------------------------------------------------


def build_fusion_system_prompt() -> str:
    """System prompt du LLM fusionneur.

    Demande une consolidation ancien+nouveau qui (1) **conserve tous** les
    faits utiles de l'existant, (2) intègre les nouveaux apprentissages,
    (3) écarte les redondances, (4) reste sous le cap chars. La
    préservation est la règle ; raccourcir n'est légitime que pour
    déduplication ou obsolescence avérée.
    """
    return (
        "Tu reçois deux blocs :\n"
        "1. La MÉMOIRE actuelle qu'un agent SQL a accumulée sur un utilisateur\n"
        "   (préférences, conventions personnelles, contexte de rôle).\n"
        "2. Un RÉSUMÉ de la dernière conversation entre l'agent et cet utilisateur.\n\n"
        "Objectif : produire une MÉMOIRE CONSOLIDÉE (max 1800 caractères) qui :\n"
        "- **conserve TOUS les faits utiles** de la mémoire existante — ne supprime "
        "  un point que s'il est devenu obsolète (contredit par le nouveau résumé) "
        "  ou redondant avec un autre point ;\n"
        "- intègre les nouveaux apprentissages du résumé ;\n"
        "- supprime les redondances ;\n"
        "- garde les éléments les plus récents quand il y a contradiction ;\n"
        "- privilégie ce qui concerne l'utilisateur lui-même (préférences, "
        "  conventions, contexte personnel) — PAS le savoir BDD générique "
        "  (rôles de tables, sémantique de colonnes, business rules) qui est "
        "  stocké séparément dans le RAG par-correspondance.\n\n"
        "**Préservation par défaut** : si la conversation courante n'apporte "
        "rien de nouveau sur l'utilisateur (ex: échange banal), tu DOIS "
        "ré-émettre la mémoire actuelle telle quelle. Ne JAMAIS retourner "
        "une mémoire significativement plus courte que l'existant sans "
        "justification métier (la mémoire user est cumulative par nature).\n\n"
        "Format : prose concise, 5-15 lignes max, sans titre, sans section "
        "markdown, sans accolades, sans délimiteurs de section type [BLOC]."
    )


def build_fusion_input(
    existing_memory: Optional[str],
    new_session_summary: str,
) -> str:
    """Construit le user message du LLM fusionneur.

    Args:
        existing_memory: Contenu actuel de ``User.iris_memory`` (peut être
            ``None`` au tout premier run de l'user).
        new_session_summary: Résumé de la conversation qui vient de se
            terminer (produit par ``agent_session_memory.generate_session_memory``).

    Returns:
        Texte structuré à passer au LLM fusionneur.
    """
    existing_block = (
        f"MÉMOIRE ACTUELLE :\n{existing_memory.strip()}\n"
        if existing_memory and existing_memory.strip()
        else "MÉMOIRE ACTUELLE : (vide — premier run pour cet utilisateur)\n"
    )
    return (
        f"{existing_block}"
        f"\n"
        f"RÉSUMÉ DE LA DERNIÈRE CONVERSATION :\n{new_session_summary.strip()}\n"
    )


# ---------------------------------------------------------------------------
# Orchestration : fusion via LLM utility
# ---------------------------------------------------------------------------


async def fuse_user_memory(
    existing_memory: Optional[str],
    new_session_summary: Optional[str],
    user_id: Optional[int],
) -> Optional[str]:
    """Fusionne mémoire user existante + résumé de la conv qui se termine.

    Appel LLM léger (utility model) avec ``temperature=0.2`` pour rester
    déterministe. Fail-soft : retourne ``None`` sur erreur LLM/BDD, le
    caller doit alors préserver la mémoire existante (ne PAS l'écraser).

    Args:
        existing_memory: Contenu actuel de ``User.iris_memory``.
        new_session_summary: Résumé fin-de-conv (déjà sanitizé en amont).
            ``None`` / vide → on retourne ``None`` (rien à fusionner).
        user_id: Identifiant utilisateur pour l'anonymisation user-scoped
            (pseudonymizer). ``None`` autorisé pour les appels système :
            la couche PII regex reste active sans pseudonymizer.

    Returns:
        Mémoire fusionnée sanitizée + cappée, ou ``None`` en cas d'échec.
    """
    if not new_session_summary or not new_session_summary.strip():
        return None

    try:
        from app.constants_ai import clamped_max_tokens
        from app.services.ai.llm_providers import LLMRequest
        from app.services.ai.llm_runtime import (
            CallProfile,
            ModelKind,
            RetryPolicy,
            call_llm,
        )
        from app.services.anonymization import anonymize_for_llm
        from app.services.anonymization.proxy import get_confidentiality_prompt

        profile = CallProfile(
            caller="iris_user_memory_fuse",
            model_kind=ModelKind.UTILITY,
            retry=RetryPolicy.STANDARD,
        )

        prompt = build_fusion_input(existing_memory, new_session_summary)

        # Anonymisation single source of truth — la mémoire user contient
        # potentiellement des noms (collègues, fournisseurs, etc.) que le
        # pseudonymizer de ce user connaît. On envoie au LLM la version
        # anonymisée, puis on dé-anonymise pour que la BDD reçoive du
        # cleartext lisible par le user via ``/data-privacy``.
        prompt_anon, restore_fn = await anonymize_for_llm(user_id, prompt, "IRIS_CHAT")

        request = LLMRequest(
            prompt=prompt_anon,
            system=(
                get_confidentiality_prompt("IRIS_CHAT") + "\n\n" + build_fusion_system_prompt()
            ),
            # Doctrine LLM dynamique : on passe par ``clamped_max_tokens``
            # pour que le soft-limit ``IRIS_USER_MEMORY_MAX_TOKENS`` soit
            # automatiquement clampé au cap du modèle utility actif (registre
            # BDD admin-éditable). Jamais de littéral ``max_tokens=<int>``
            # dans une call-site (cf. ``feedback_max_tokens_must_be_dynamic.md``).
            max_tokens=clamped_max_tokens(IRIS_USER_MEMORY_MAX_TOKENS),
            # Task #5 2026-05-26 : temperature omise → admin config
            # (/admin/ai-config) prime. Single source of truth pour
            # tous les call-sites Iris user-facing. L'ancien hardcode
            # 0.2 ignorait silencieusement le réglage admin.
        )
        response = await call_llm(profile, request)
        text = getattr(response, "content", "") or ""
        if not text:
            return None
        text = restore_fn(text)
        new_fused = sanitize_iris_user_memory(text) or None
        if new_fused is None:
            return None

        # ── Garde anti-appauvrissement (F5 review adversariale 2026-05-22) ──
        # La mémoire user est cumulative par nature : on ne doit JAMAIS la
        # rétrécir drastiquement à cause d'une conversation banale qui ne
        # parle pas de l'utilisateur. Si l'existant n'est pas vide et que
        # la nouvelle version fait moins de la moitié de l'existant, on
        # préserve l'existant (le prompt fusionneur dit explicitement
        # « préservation par défaut » — un raccourcissement >50% sans
        # justification métier est suspect). Au pire, la session suivante
        # aura l'occasion d'enrichir à nouveau.
        if existing_memory and existing_memory.strip():
            existing_len = len(existing_memory.strip())
            if len(new_fused) < existing_len * 0.5:
                logger.warning(
                    "fuse_user_memory: nouvelle mémoire (%d chars) < 50%% de "
                    "l'existante (%d chars) pour user=%s — préservation de "
                    "l'existante (anti-appauvrissement). Nouvelle ignorée : %r",
                    len(new_fused),
                    existing_len,
                    user_id,
                    new_fused[:100],
                )
                return None  # caller préserve l'existant
        return new_fused
    except Exception:  # noqa: BLE001 — fail-soft
        logger.warning(
            "fuse_user_memory: échec LLM, mémoire existante préservée (user=%s)",
            user_id,
            exc_info=True,
        )
        return None
