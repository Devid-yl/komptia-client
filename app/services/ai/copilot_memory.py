"""Mémoire inter-runs du copilot, persistée *par classeur* dans le ``.afz.json``.

Objectif
--------

À la fin d'un run ``run_copilot_agent`` qui a réussi (terminal_kind ∈
{``emit_tab``, ``patch_tab``, ``rename_tab``, ``delete_tab``}), un appel
LLM **léger** résume les apprentissages utiles pour un **futur run sur le
même classeur** :

- structure du template comprise (sections, colonnes, patterns),
- substitutions sémantiques validées (``original`` → ``replacement``),
- onglets sources pertinents identifiés, et pourquoi,
- décisions de modélisation prises (``source_tab_index`` canonique,
  dimensions-clés, exclusions récurrentes).

Le résumé est retourné via ``ctx.terminal_result["copilot_memory_new"]``
**dé-anonymisé** (cleartext). Le frontend l'intègre dans l'état du
classeur au moment du save ``POST /api/datastore/upload`` — il vit donc
dans le ``.afz.json`` à la clef racine ``copilot_memory``.

Au run suivant, le frontend le relit et le passe dans le body de
``POST /api/result-assistant`` → ``run_copilot_agent(copilot_memory=…)``
→ injection dans le user_preamble.

Objectif NON atteint par ce module
----------------------------------

Ce module **ne sait pas** quel classeur est en train d'être traité. Pas de
``workbook_id``, pas de chemin filesystem. La persistence est *côté
frontend* pour rester cohérent avec l'architecture actuelle (le backend
est stateless vis-à-vis du fichier ``.afz.json``, le front-end porte
l'état du classeur ouvert). Cette décision évite un couplage
backend↔disque qui complexifierait la chaîne sans bénéfice.

Différences avec le compact intra-run
-------------------------------------

:mod:`app.services.ai.llm_providers._maybe_compact_messages` compacte la
conversation **pendant** un run pour rester sous la context window. Son
objectif est "libérer de la place". Ici, l'objectif est "transmettre des
apprentissages à un futur moi". Les deux partagent l'infrastructure
(``provider.generate``, ``_resolve_compact_summarizer_model``) mais
utilisent des prompts distincts :

- intra-run : *"préserve tout ce qui peut resservir pour continuer CE
  run"*.
- fin-de-run (ce module) : *"extrais la structure et les décisions pour
  qu'un FUTUR run sur le même classeur n'ait pas à re-explorer"*.

Sécurité
--------

- **Anonymisation** : l'input envoyé au LLM est construit à partir du
  ``ctx`` qui contient DÉJÀ les valeurs anonymisées (tokens ``§…§``).
  Le résumé sort donc anonymisé. Le caller (``copilot_agent``) le
  dé-anonymise AVANT de l'injecter dans ``terminal_result``.
- **Sanitization bidirectionnelle** : à l'écriture (post-LLM) et à la
  lecture (pré-injection dans user_preamble), on strip les directives
  markdown (``##``, ``---``), les accolades (défense double-format), et
  on plafonne à 2000 chars — un ``.afz.json`` édité à la main ne peut
  pas injecter un bloc système.
- **Fail-safe** : toute exception du provider est loggée + silencieuse.
  Pas de mémoire sauvée, mais le run principal reste considéré comme
  réussi (le compact est un bonus, pas un élément critique).
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

#: Terminal kinds qui déclenchent la génération d'une mémoire fin-de-run.
#: L'abandon et ``emit_tab_error`` NE déclenchent PAS : aucune valeur
#: d'apprentissage fiable à transmettre d'un échec.
_TERMINAL_KINDS_ELIGIBLE: frozenset = frozenset(
    {"emit_tab", "patch_tab", "rename_tab", "delete_tab"}
)

#: Cap de tokens demandé au LLM pour le résumé. 800 tokens ≈ 600 mots
#: français : largement assez pour pointer substitutions + structure +
#: 3-5 décisions clefs. Au-delà, le LLM commencerait à re-lister des
#: données au lieu de synthétiser.
_MEMORY_MAX_TOKENS: int = 800

#: Cap dur sur la taille du résumé final (en caractères). Si le LLM
#: retourne plus, on tronque proprement. Valeur calibrée : 2000 chars ≈
#: 400-500 mots ≈ ~650 tokens à re-injecter au run suivant — soutenable
#: dans le cache Anthropic sans le saturer.
_MEMORY_MAX_OUTPUT_CHARS: int = 2000

#: Nombre max de substitutions incluses dans l'input (évite un run
#: extrême avec 200 substitutions de faire exploser le prompt).
_MAX_SUBSTITUTIONS_IN_INPUT: int = 30

#: Nombre max d'index d'onglets ``tabs_touched`` inclus dans l'input.
_MAX_TABS_TOUCHED_IN_INPUT: int = 50

#: Préfixes markdown directifs à stripper en début de ligne dans le
#: résumé. Empêche qu'une mémoire passe pour une section système au run
#: suivant ou qu'elle injecte un titre non souhaité.
_MD_PREFIX_RE: re.Pattern[str] = re.compile(r"(?m)^\s*(##+|---+|\*\*+)\s*")

#: Accolades — retirées pour la même raison que dans ``user_context`` :
#: défense contre un double ``.format()`` accidentel downstream.
_BRACE_RE: re.Pattern[str] = re.compile(r"[{}]")

#: Délimiteurs de section mémoire — strippés au cas où le LLM aurait
#: tenté de refermer une section qu'il ne connaît pas.
_DELIMITER_RE: re.Pattern[str] = re.compile(r"<<<[^>]*>>>")

#: Séquences de caractères de contrôle (sauf saut de ligne et tab) +
#: contrôles Unicode invisibles (zero-width, bidi markers, paragraph
#: separators). Strippées. Même rationale que ``user_context._CTRL_CHARS_RE``
#: — empêche un bypass type ``"​## Règles système"`` (ZWSP invisible en
#: début de ligne) qui contournerait le strip markdown.
_CTRL_CHARS_RE: re.Pattern[str] = re.compile("[\x00-\x08\x0b-\x1f\x7f​-‏ - " "‪-‮⁠-⁤﻿]")


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_MEMORY_SUMMARIZER_PROMPT = """\
Tu résumes un run d'agent qui vient de modifier un classeur. Ton résumé sera \
relu par un *futur* agent qui travaillera sur le MÊME classeur (une autre demande \
de l'utilisateur plus tard), pour qu'il n'ait pas à re-découvrir ce qui a déjà \
été compris aujourd'hui.

**Objectif unique** : transmettre la STRUCTURE et les DÉCISIONS comprises sur ce \
classeur. PAS les données numériques du run actuel (le futur run aura ses propres \
données).

**À inclure en priorité** :
- Les traductions sémantiques validées (ex : quel terme utilisateur correspond à \
quelle valeur source dans la BDD).
- La structure du ou des templates identifiés : quelles sections, quelles \
dimensions-clés, quels patterns de remplissage (ex : "colonne = trimestre", \
"ligne = section métier").
- Les onglets sources pertinents et leur rôle sémantique (ex : "tab 3 = données \
mensuelles facturation", "tab 7 = référentiel des entités").
- Les décisions de modélisation prises : ``source_tab_index`` canonique pour un \
type de mesure, exclusions récurrentes (``match_exclude``), choix de ``value_column``.
- Les pièges découverts (ex : "attention, tab 5 contient une typo lfaCodeStatistique").

**À NE PAS inclure** :
- Les valeurs chiffrées obtenues dans ce run (elles ne seront plus valables).
- L'instruction précise de ce run (elle est spécifique à cette demande).
- Les résultats numériques bruts.
- Les répétitions.

**Format obligatoire** :
- Texte en puces courtes, **sans aucun titre markdown** (pas de ``##``, pas de \
``---``, pas de ``**``).
- Pas d'accolades ``{{`` ni ``}}``.
- Pas de délimiteur ``<<<...>>>``.
- Pas de préambule ("Voici le résumé…") ni de conclusion meta.
- 2000 caractères MAXIMUM — sois dense.
- Langue : français.

**Contexte du run à résumer** :
---
{run_context}
---

Retourne directement le résumé, rien d'autre.
"""


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------


#: Regex pour identifier un token de pseudonymisation dans un texte. Les
#: sentinelles ``§`` encadrent un middle alphanumerique ou
#: sémantique. Cette regex est générique (pas couplée à un schéma
#: Komptia précis) — on l'utilise pour détecter et filtrer les tokens
#: orphelins (hallucinations du LLM).
_PSEUDO_TOKEN_RE: re.Pattern[str] = re.compile(r"§[^§\s]*§")


def filter_unknown_pseudonym_tokens(
    text: str,
    known_tokens: Any,
) -> str:
    """Retire du texte les tokens ``§…§`` qui ne sont PAS dans
    ``known_tokens``.

    Rationale — **tokens hallucinés** : si le LLM génère un résumé qui
    contient ``§CLIENT_Z§`` alors que seul ``§CLIENT_A§`` existait dans
    le pseudonymizer actif, on a :

    - Un token orphelin que le pseudonymizer ne peut pas dé-anonymiser
      (il reste brut au run suivant).
    - Un risque de corruption du prompt au run N+1 : le LLM voit un
      ``§CLIENT_Z§`` qui ne correspond à aucune donnée réelle et peut
      l'inclure dans un SQL (``ask_iris`` avec draft contenant ce token)
      → SQL Server reçoit la sentinelle littérale → erreur SQL.

    Solution : avant de persister la mémoire dans le ``.afz.json``, on
    whitelist les tokens qui existent réellement dans le pseudonymizer
    du run courant. Les autres sont strippés.

    **Ne jamais fail-closed** : si ``known_tokens`` est None ou vide, on
    renvoie le texte tel quel (on ne peut pas distinguer un token
    légitime d'un halluciné, donc on laisse tout — une run user SANS
    pseudonymisation active est parfaitement valide). Les tokens
    orphelins dégradent l'UX, pas la sécurité.

    Args:
        text: résumé (potentiellement avec des tokens).
        known_tokens: iterable des tokens reconnus (clefs de
            ``pseudo._reverse``). Si None/vide, no-op.

    Returns:
        Texte avec tokens inconnus retirés.
    """
    if not text or not isinstance(text, str):
        return ""
    if not known_tokens:
        return text
    known_set = set(known_tokens)
    return _PSEUDO_TOKEN_RE.sub(
        lambda m: m.group(0) if m.group(0) in known_set else "",
        text,
    )


def sanitize_memory_for_prompt(raw: Any) -> str:
    """Sanitize une mémoire copilot (lue du ``.afz.json`` ou retournée par le
    LLM) avant injection dans un prompt.

    Application bidirectionnelle :

    - **À l'écriture** (output du LLM de résumé) : pour empêcher le LLM
      d'injecter des directives markdown ou des placeholders qui
      pollueront le run suivant.
    - **À la lecture** (input du run suivant) : pour se défendre contre un
      ``.afz.json`` édité manuellement (à la main ou par un script tiers)
      qui aurait injecté un bloc système.

    Retourne chaîne vide si ``raw`` est ``None`` ou non-str.
    """
    if raw is None:
        return ""
    if not isinstance(raw, str):
        # Cas pathologique (dict/list persisté par erreur) — on refuse
        # de convertir aveuglément. Mieux vaut pas de mémoire qu'une
        # mémoire corrompue.
        logger.warning(
            "sanitize_memory_for_prompt: type inattendu %s — ignoré.",
            type(raw).__name__,
        )
        return ""
    # NFKC pour neutraliser les homoglyphes Unicode fullwidth (cf
    # user_context.sanitize_display_name pour le rationale détaillé).
    s = unicodedata.normalize("NFKC", raw)
    s = _CTRL_CHARS_RE.sub("", s)
    s = _DELIMITER_RE.sub("", s)
    # Strip les délimiteurs partiels (``<<<`` ou ``>>>`` isolés) qui ne
    # forment pas une paire complète. Sans ce filet, un LLM pourrait
    # émettre ``<<<END_MEMORY`` seul (sans fermeture) et perturber le
    # bloc mémoire au run suivant.
    s = s.replace("<<<", "").replace(">>>", "")
    s = _MD_PREFIX_RE.sub("", s)
    s = _BRACE_RE.sub("", s)
    s = s.strip()
    if len(s) > _MEMORY_MAX_OUTPUT_CHARS:
        s = s[:_MEMORY_MAX_OUTPUT_CHARS].rstrip()
    return s


def build_memory_input(ctx: Any) -> str:
    """Construit l'input à résumer depuis un ``CopilotContext`` en fin de run.

    Inclut : instruction (cap 500 chars), tabs_touched (indices),
    substitutions validées (original → replacement + reason), terminal_kind,
    structure du résultat (label + columns + row_count — PAS les rows
    elles-mêmes pour rester sur la structure et éviter de leaker du
    cleartext de donnée).

    Toutes les valeurs proviennent du ``ctx`` anonymisé — l'input est
    donc déjà anonymisé au moment de l'appel LLM. La dé-anonymisation a
    lieu après (côté caller), pas ici.
    """
    lines = []

    instruction = getattr(ctx, "instruction", "") or ""
    if instruction:
        snippet = instruction[:500].rstrip()
        if len(instruction) > 500:
            snippet += "…"
        lines.append(f"Instruction du run : {snippet}")

    terminal_kind = getattr(ctx, "terminal_kind", None)
    if terminal_kind:
        lines.append(f"Type de terminal atteint : {terminal_kind}")

    tabs_touched = sorted(getattr(ctx, "tabs_touched", set()) or set())
    if tabs_touched:
        tabs_preview = tabs_touched[:_MAX_TABS_TOUCHED_IN_INPUT]
        suffix = (
            f" (+{len(tabs_touched) - len(tabs_preview)} autres)"
            if len(tabs_touched) > len(tabs_preview)
            else ""
        )
        lines.append(f"Onglets sondés : {tabs_preview}{suffix}")

    # Cap per-element défensif : les champs ``original``/``replacement``/
    # ``reason`` viennent de ``ctx.substitutions`` qui est rempli par le
    # LLM via ``explain_substitution``. En théorie cappé côté schéma tool,
    # en pratique un LLM buggué pourrait produire des strings multi-KiB.
    # On cap dur ici pour éviter que l'input du summarizer explose.
    _SUB_FIELD_MAX = 300

    subs = getattr(ctx, "substitutions", []) or []
    if subs:
        lines.append(f"Substitutions sémantiques validées ({len(subs)}) :")
        for sub in subs[:_MAX_SUBSTITUTIONS_IN_INPUT]:
            if not isinstance(sub, dict):
                continue
            o = str(sub.get("original", ""))[:_SUB_FIELD_MAX]
            r = str(sub.get("replacement", ""))[:_SUB_FIELD_MAX]
            reason = str(sub.get("reason", ""))[:_SUB_FIELD_MAX]
            lines.append(f"  - {o!r} → {r!r} ({reason})")
        if len(subs) > _MAX_SUBSTITUTIONS_IN_INPUT:
            lines.append(f"  - … +{len(subs) - _MAX_SUBSTITUTIONS_IN_INPUT} autres")

    tr = getattr(ctx, "terminal_result", None)
    if isinstance(tr, dict):
        # ``emit_tab`` produit ``tr["tab"]`` (ou ``tr["new_tab"]`` selon la
        # forme historique) avec un dict structure. ``patch_tab``,
        # ``rename_tab`` et ``delete_tab`` ne mettent PAS de clef ``tab`` :
        # on n'émet donc la ligne "Résultat émis" QUE si le dict existe ET
        # est non-vide. Sinon on produit bruit trompeur dans le résumé
        # (ligne vide "Résultat émis : label='', 0 lignes, colonnes=[]"
        # qui induit le summarizer en erreur sur la nature du terminal).
        tab = tr.get("tab") or tr.get("new_tab")
        if isinstance(tab, dict) and tab:
            label = str(tab.get("label", ""))[:200]
            cols = tab.get("columns") or []
            row_count = tab.get("row_count")
            if row_count is None:
                row_count = len(tab.get("rows") or [])
            cols_preview = ", ".join(str(c) for c in cols[:12])
            if len(cols) > 12:
                cols_preview += f" (+{len(cols) - 12})"
            lines.append(
                f"Résultat émis : label={label!r}, {row_count} lignes, "
                f"colonnes=[{cols_preview}]"
            )
        patches = tr.get("patches")
        if patches:
            lines.append(f"Patches appliqués : {len(patches)} cellules modifiées")
        # Cas spécifiques aux terminaux non-émis d'onglet : on signale
        # explicitement au summarizer le type d'action pour éviter qu'il
        # raconte n'importe quoi.
        target_label = tr.get("target_label")
        if target_label:
            lines.append(f"Onglet modifié/renommé/supprimé : label={str(target_label)[:200]!r}")

    plan = getattr(ctx, "plan", []) or []
    if plan:
        completed = [t for t in plan if isinstance(t, dict) and t.get("status") == "completed"]
        if completed:
            lines.append(f"Étapes de plan terminées ({len(completed)}) :")
            for task in completed[:10]:
                subject = str(task.get("subject", ""))[:_SUB_FIELD_MAX]
                if subject:
                    lines.append(f"  - {subject}")
            if len(completed) > 10:
                lines.append(f"  - … +{len(completed) - 10} autres")

    result = "\n".join(lines) if lines else "(pas de contexte utilisable)"
    # Cap global TOTAL : garde-fou final au cas où les caps par-segment
    # auraient laissé passer un contenu cumulatif énorme. Un prompt
    # summarizer au-delà de 20 Ko déraperait sur la context window des
    # petits modèles (Haiku 200K tokens de fenêtre mais ~64K tokens
    # output max).
    _MAX_INPUT_TOTAL_CHARS = 20_000
    if len(result) > _MAX_INPUT_TOTAL_CHARS:
        result = result[:_MAX_INPUT_TOTAL_CHARS].rstrip() + "\n… (input tronqué)"
    return result


async def summarize_copilot_run(ctx: Any, manager: Any) -> str:
    """Génère la mémoire copilot fin-de-run via appel LLM léger.

    Retourne chaîne vide si :
    - ``ctx.terminal_kind`` n'est pas éligible (abandon, None, erreur),
    - pas de contexte utilisable (``build_memory_input`` vide de signal),
    - le provider LLM échoue (exception silencieuse, logguée en WARNING).

    Sinon retourne le résumé LLM **sanitizé** (strip markdown, accolades,
    délimiteurs, control chars, cap à 2000 chars).

    Le résumé retourné est **conservé anonymisé** (tokens ``§…§``) — il
    sera persisté tel quel dans ``copilot_memory_new`` du ``.afz.json``.
    Le caller (:func:`app.services.ai.copilot_agent.run_copilot_agent`)
    applique :func:`filter_unknown_pseudonym_tokens` pour stripper les
    tokens hallucinés (par sécurité), mais NE dé-anonymise PAS le résumé
    avant stockage. Conséquence sécuritaire voulue (review adversariale
    tâche #7) :

    - Au prochain chargement du classeur (potentiellement par un autre
      user que celui qui a généré la mémoire), le pseudonymizer du user
      courant ne reconnaîtra pas les tokens étrangers et les laissera
      opaques (``§abc§``) — pas de leak de cleartext PII cross-user.
    - Le user qui possède le mapping retrouve naturellement les
      cleartexts via son propre pseudonymizer au moment de la lecture.

    Si une variable du caller a besoin du cleartext (ex: ``terminal_result``
    affiché dans l'UI), c'est sur ce flux séparé que ``pseudo.deanonymize``
    s'applique — pas sur le summary qui dort en BDD.
    """
    terminal_kind = getattr(ctx, "terminal_kind", None)
    if terminal_kind not in _TERMINAL_KINDS_ELIGIBLE:
        return ""

    run_context = build_memory_input(ctx)
    if not run_context or run_context == "(pas de contexte utilisable)":
        # Rien à résumer — un run qui a émis un onglet sans exploration
        # (ex: rename_tab minimal) n'a pas d'apprentissage structurel.
        return ""

    try:
        from app.services.ai.llm_providers import (
            LLMRequest,
            _resolve_compact_summarizer_model,
        )
        from app.services.ai.llm_runtime import CallProfile, ModelKind, call_llm
        from app.services.anonymization import anonymize_for_llm
        from app.services.anonymization.proxy import get_confidentiality_prompt

        provider = manager.get_provider() if manager is not None else None
        if provider is None:
            logger.warning("summarize_copilot_run: pas de provider disponible.")
            return ""

        fallback_model = getattr(manager, "default_model_name", "") or ""
        summarizer_model = _resolve_compact_summarizer_model(provider, fallback_model)

        prompt_text = _MEMORY_SUMMARIZER_PROMPT.format(run_context=run_context)

        # Proxy d'anonymisation : single source of truth Komptia. Couche PII
        # regex (defense in depth) + pseudonymizer user-scoped si l'user a
        # des termes enabled. Le ctx.user_id est posé par run_copilot_agent
        # (cf. copilot_agent.py:578) ; absent → calls système → user_id=None.
        #
        # **Note de design** : on ne ré-applique PAS ``restore_fn`` ici. Le
        # contrat de cette fonction (cf. docstring lignes 408-412) est de
        # RETOURNER un résumé encore anonymisé — le caller dans
        # :func:`app.services.ai.copilot_agent.run_copilot_agent` applique
        # sa propre ``pseudo.deanonymize`` sur le résultat final, en
        # utilisant :func:`filter_unknown_pseudonym_tokens` pour stripper
        # les tokens hallucinés. Restaurer ici produirait du cleartext
        # stocké dans ``copilot_memory_new`` du ``.afz.json`` — leak
        # cross-user au prochain chargement du classeur par un autre user.
        ctx_user_id = getattr(ctx, "user_id", None)
        prompt_anon, _ = await anonymize_for_llm(ctx_user_id, prompt_text, "COPILOT")

        # ``provider_name_override`` préserve le routing explicite vers le
        # provider courant. ``model=summarizer_model`` dans la LLMRequest
        # prime sur ModelKind.PRIMARY — le caller pilote le modèle.
        response = await call_llm(
            CallProfile(
                caller="copilot_memory_summarize",
                model_kind=ModelKind.PRIMARY,
                provider_name_override=getattr(provider, "provider_name", None),
            ),
            LLMRequest(
                prompt=prompt_anon,
                system=get_confidentiality_prompt("COPILOT"),
                model=summarizer_model,
                temperature=0.0,
                max_tokens=_MEMORY_MAX_TOKENS,
            ),
        )
        raw_summary = getattr(response, "content", None) or ""
    except Exception as exc:  # noqa: BLE001 — best-effort, ne bloque JAMAIS le run
        logger.warning(
            "summarize_copilot_run a échoué (%s) — pas de mémoire écrite "
            "pour ce run, le run principal reste valide.",
            exc,
        )
        return ""

    if not raw_summary or not isinstance(raw_summary, str):
        return ""

    return sanitize_memory_for_prompt(raw_summary)
