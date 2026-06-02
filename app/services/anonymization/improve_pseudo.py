"""Améliore les pseudonymes d'anonymisation via le LLM local.

**But** : enrichir le ``pseudo_middle`` d'un terme d'anonymisation pour que le
pseudonyme révélé au LLM cloud porte un sens sémantique (``§NOM_4b3§``,
``§ENTREPRISE_4b3§``, ``§SIRET_4b3§``) au lieu d'un fallback opaque
(``§TXT_4b3§`` / ``§NUM_a1d§``). La valeur réelle reste cachée, seul le
TYPE est révélé — Niveau 3 du CLAUDE.md (« données décontextualisées »).

**Architecture (miroir d'auto_classify.py)** :

1. ``compute_dynamic_batch_size()`` dérive le batch_size du modèle local
   configuré dans ``/admin/ai-config`` (``LlmModel.context_window``,
   ``max_output_tokens``). Provider-agnostic : Ollama, LM Studio, TGI,
   vLLM ou tout endpoint OpenAI-compat marche pareil.
2. ``improve_pseudos_chunk()`` envoie un chunk de termes au LLM local et
   reçoit ``{term → suggested_label}``. Stateless / chunkable : le caller
   boucle en autant d'appels que nécessaire (V5 « liste de taille
   infinie », V6 « seule limite = arrêt user »).
3. ``validate_suggested_label()`` filtre les hallucinations : regex strict
   + blacklist anti prompt-injection. Un label rejeté → fallback
   :func:`extract._auto_pseudo_middle` pour ce terme.

**Confidentialité** : le LLM local reçoit UNIQUEMENT le terme. Jamais le
classeur source, jamais le nom de colonne, jamais le contexte sémantique
extérieur. Termes ne quittent pas la machine (LLM local).

**Best-effort** : si le LLM local est down / non configuré / lent, on
retourne ``status != "ok"`` — le frontend gère via la taxonomie 4-cas
erreurs (axe 5 Komptia).
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ─── Constantes ─────────────────────────────────────────────────────────────


#: Estimation conservative tokens/chars (1 token ≈ 4 chars). Standard
#: approximation des tokenizers BPE/SentencePiece utilisés par les LLM
#: modernes (GPT, Claude, Llama, Phi, Mistral, Gemma). C'est la SEULE
#: estimation algorithmique restante après le retrait des caps
#: arbitraires (2026-05-19) — pas un cap, juste la conversion chars↔tokens
#: nécessaire au calcul. Conservative car les chiffres/espaces/ponctuations
#: tokenisent souvent en moins de 4 chars/token côté français.
_CHARS_PER_TOKEN: int = 4

#: Tokens réservés pour l'overhead JSON par item retour
#: (``{"term": "...", "label": "..."}``) — accolades, quotes, virgule.
#: ≈ 20 chars / 4 = 5 tokens fixes par item, indépendamment du contenu.
_JSON_OVERHEAD_TOKENS_PER_OUTPUT_ITEM: int = 5

#: Tokens réservés pour l'overhead JSON par item entrée
#: (``"...", `` virgule séparateur). ≈ 4 chars / 4 = 1 token fixe par item.
_JSON_OVERHEAD_TOKENS_PER_INPUT_ITEM: int = 1

#: Timeout LLM local par défaut (60s = aligné avec ``auto_classify_chunk``).
#: Modèles CPU peuvent dépasser sur cold start ; l'admin peut surcharger
#: via ``local_llm_timeout_seconds`` (lu côté ``llm_providers``).
_DEFAULT_TIMEOUT_SECONDS: float = 60.0


#: Regex strict pour les labels suggérés. MAJUSCULES + underscore, longueur
#: 1-30. Refuse tout ce qui n'est pas ASCII upper alpha — anti accents,
#: anti caractères spéciaux, anti unicode tricky.
_LABEL_REGEX: re.Pattern[str] = re.compile(r"^[A-Z_]{1,30}$")


#: Blacklist anti prompt-injection LLM. Le pseudonyme suggéré finit DANS le
#: prompt envoyé au LLM cloud — un label malicieux pourrait inciter le cloud
#: à des comportements indésirables. Liste conservatrice :
#: - Mots d'injection / contournement (ADMIN, BYPASS, EVAL, …)
#: - Rôles LLM (PROMPT, SYSTEM, ASSISTANT)
#: - Mots-clés SQL/Shell qui pourraient influencer la génération SQL d'Iris
#:   si un label `§DROP_4b3§` atterrit dans un prompt cloud (fix #6 review
#:   adversariale 2026-05-19).
#: Le fallback ``_auto_pseudo_middle`` prend le relai pour les termes dont
#: le label suggéré est rejeté (label sémantique sain TXT/NUM/EMAIL/…).
_LABEL_BLACKLIST: frozenset[str] = frozenset(
    {
        # Injection / contournement
        "INJECTION",
        "XSS",
        "ADMIN",
        "SCRIPT",
        "PASSWORD",
        "TOKEN",
        "SECRET",
        "CLOUD",
        "BYPASS",
        "EVAL",
        "EXEC",
        "SUDO",
        "ROOT",
        # Rôles LLM
        "PROMPT",
        "SYSTEM",
        "ASSISTANT",
        "USER",
        "JAILBREAK",
        "OVERRIDE",
        "IGNORE",
        "DISREGARD",
        # Mots-clés SQL/Shell (fix #6 review 2026-05-19) — si Iris génère du
        # SQL avec un placeholder `§DROP_4b3§` mal interprété par le LLM cloud.
        "DROP",
        "DELETE",
        "TRUNCATE",
        "UPDATE",
        "INSERT",
        "SELECT",
        "UNION",
        "ALTER",
        "GRANT",
        "REVOKE",
        "SHELL",
        "XP",
        "SP",
    }
)


# ─── Result dataclass ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class ImprovePseudoResult:
    """Résultat structuré d'un appel ``improve_pseudos_chunk``.

    Statuts (``status``) :

    - ``"ok"`` : LLM a répondu, ``improved`` contient les labels validés.
    - ``"not_configured"`` : LLM local pas activé via /admin/ai-config.
    - ``"timeout"`` : LLM local a répondu trop lentement.
    - ``"error"`` : autre erreur (parse JSON, providers, etc.).

    Les ``invalid_labels`` documentent les rejets pour observabilité —
    le frontend les ignore mais peut les exposer pour debug admin.
    """

    improved: Dict[str, str] = field(default_factory=dict)
    """Map ``term → suggested_label`` (labels déjà validés et nettoyés)."""

    invalid_labels: List[Dict[str, str]] = field(default_factory=list)
    """Liste des rejets : ``[{"term": "...", "raw_label": "...", "reason": "..."}]``."""

    unprocessed: List[str] = field(default_factory=list)
    """Termes NON traités ce tour (budget continuations épuisé / aucun progrès
    LLM) — restés au libellé générique. SIGNAL ANTI DONNÉES-FAUSSES (#97/D6-F2) :
    ni dans ``improved`` ni dans ``invalid_labels``, ils seraient sinon
    silencieusement perdus et le caller afficherait « Terminé » alors qu'un
    re-run les améliorerait. Le handler le remonte en ``skipped_unprocessed``."""

    status: str = "ok"
    """``"ok" | "not_configured" | "timeout" | "error"``."""

    message: Optional[str] = None
    """Message court pour l'observabilité — JAMAIS retourné à l'user final."""


# ─── Helpers ────────────────────────────────────────────────────────────────


def validate_suggested_label(label: str) -> Tuple[bool, Optional[str]]:
    """Valide un label suggéré par le LLM local.

    Vérifications (dans l'ordre, fail-fast) :

    1. Type / non-vide
    2. Regex ``^[A-Z_]{1,30}$`` (MAJUSCULES + underscore, longueur 1-30)
    3. Blacklist anti prompt-injection (``ADMIN``, ``BYPASS``, ``EVAL``, …)

    Returns:
        ``(True, None)`` si valide, sinon ``(False, reason)`` où ``reason``
        est une chaîne courte explicative pour le log et le champ
        ``invalid_labels[].reason``.
    """
    if not isinstance(label, str) or not label:
        return False, "empty_or_non_string"
    if not _LABEL_REGEX.fullmatch(label):
        return False, "regex_mismatch"
    # Match exact OU contenant un mot blacklisté (split par "_" pour
    # capturer ADMIN_BYPASS qui contient 2 mots).
    parts = label.split("_")
    for p in parts:
        if p in _LABEL_BLACKLIST:
            return False, f"blacklisted_word_{p.lower()}"
    return True, None


async def compute_dynamic_batch_size_async() -> Tuple[int, str]:
    """Calcule le batch_size adapté au LLM local configuré.

    **Calcul purement dynamique** (2026-05-19, demande David) :

    1. Lit ``local_llm_model`` (config admin) + ``context_window`` +
       ``max_output_tokens`` du registre ``LlmModel`` (admin-éditable via
       ``/admin/ai-models``). Aucun cap arbitraire — la seule limite est
       ce que le modèle SUPPORTE réellement.

    2. Mesure dynamiquement les tokens :

       - ``prompt_overhead_tokens`` = taille du template prompt (fixe,
         mesuré chars/4 à chaque appel) sans le placeholder ``tokens_json``.
       - ``avg_input_tokens_per_item`` = estimation neutre 8 chars/terme
         (couvre la majorité des cas : ``"DUPONT"``, ``"75001"``, ``"0612..."``).
       - ``avg_output_tokens_per_item`` = longueur typique d'un item JSON
         retour ``{"term": "<term>", "label": "LABEL_FAMILLE"}``.

    3. Budget input = ``ctx - prompt_overhead - max_output``
       Budget output = ``max_output``
       batch = ``min(budget_input/per_term_in, budget_output/per_term_out)``

       Pas de safety factor, pas de hard cap, pas de min/max. Si ctx ou
       max_output sont absurdes (négatifs / 0), batch=1 (un terme à la fois).

    Returns:
        ``(batch_size, model_name)``. Si ``local_llm_model`` non configuré
        ou modèle absent du registre → ``RuntimeError`` avec message
        actionnable pour l'admin (configurer dans ``/admin/ai-models``).

    Raises:
        RuntimeError: si ``local_llm_model`` non configuré OU si le modèle
            n'a pas de ``context_window``/``max_output_tokens`` dans le
            registre. Le caller doit ``except`` proprement et afficher le
            message à l'admin.
    """
    from app.services.ai.config_service import get_ai_config_service
    from app.constants_ai import (
        get_context_window_for_model,
        get_max_tokens_for_model,
    )

    cs = get_ai_config_service()
    model_name = (await cs.get("local_llm_model")) or ""
    if not model_name:
        raise RuntimeError(
            "``local_llm_model`` non configuré dans /admin/ai-config. "
            "Renseigne le nom du modèle local (ex: ``phi3:mini``)."
        )

    ctx = get_context_window_for_model(model_name)
    max_out = get_max_tokens_for_model(model_name)
    if not ctx or ctx <= 0 or not max_out or max_out <= 0:
        raise RuntimeError(
            f"Modèle local {model_name!r} sans context_window/max_output_tokens "
            f"dans le registre. Configure ces valeurs dans /admin/ai-models "
            f"(POST /api/admin/llm/models/sync pour auto-détecter, ou saisie "
            f"manuelle)."
        )

    # Mesure dynamique du prompt overhead (template sans le placeholder).
    # Le ``{tokens_json}`` sera remplacé par un JSON ``["term1","term2",...]``
    # dont chaque terme apporte son propre budget — on retire son placeholder
    # de la mesure pour éviter de le compter 2 fois.
    template_chars = len(_PROMPT_TEMPLATE) - len("{tokens_json}")
    prompt_overhead_tokens = template_chars // _CHARS_PER_TOKEN

    # Estimation neutre 8 chars/terme. Couvre la majorité des cas Komptia
    # (« DUPONT » 6 chars, « 75001 » 5 chars, « 0612345678 » 10 chars,
    # codes comptables ≤ 5 chars). Le ratio chars/token=4 donne ~2 tokens/terme.
    # Pas de calibration par sample : la précision marginale gagnée ne
    # justifie pas la complexité (mort-code retiré 2026-05-20).
    avg_term_chars = 8
    input_tokens_per_item = (
        avg_term_chars // _CHARS_PER_TOKEN + _JSON_OVERHEAD_TOKENS_PER_INPUT_ITEM
    )
    input_tokens_per_item = max(1, input_tokens_per_item)  # min 1 pour /0

    # Tokens/terme output : on table sur term + label (LABEL_FAMILLE ~13 chars)
    # + overhead JSON.
    output_tokens_per_item = (
        avg_term_chars + 15
    ) // _CHARS_PER_TOKEN + _JSON_OVERHEAD_TOKENS_PER_OUTPUT_ITEM
    output_tokens_per_item = max(1, output_tokens_per_item)

    # Budget : tout ce que le modèle peut absorber.
    input_budget = ctx - prompt_overhead_tokens - max_out
    if input_budget <= 0:
        batch_final = 1  # ctx trop serré → un terme à la fois
    else:
        batch_by_in = input_budget // input_tokens_per_item
        batch_by_out = max_out // output_tokens_per_item
        batch_final = max(1, min(batch_by_in, batch_by_out))

    logger.debug(
        "improve_pseudo.compute_dynamic_batch_size_async: model=%s ctx=%d "
        "max_out=%d prompt_overhead=%d in_per_item=%d out_per_item=%d → batch=%d",
        model_name,
        ctx,
        max_out,
        prompt_overhead_tokens,
        input_tokens_per_item,
        output_tokens_per_item,
        batch_final,
    )
    return batch_final, model_name


# ─── Prompt LLM ─────────────────────────────────────────────────────────────


_PROMPT_TEMPLATE: str = """\
Classifie chaque valeur en label UPPERCASE (A-Z et _ uniquement, max 30 chars).

Exemples :
"DUPONT" -> "NOM_FAMILLE"
"jean@x.fr" -> "EMAIL"
"0612345678" -> "TELEPHONE"
"75001" -> "CODE_POSTAL"
"12345678901234" -> "SIRET"
"Cabinet SARL" -> "ENTREPRISE"

Réponds UNIQUEMENT en JSON valide, aucun texte autour :
{{"items":[{{"term":"<valeur exacte>","label":"<LABEL>"}}]}}

Valeurs à classifier :
{tokens_json}
"""


# ─── Fonction principale ────────────────────────────────────────────────────


def _parse_response(
    content: str, tokens_list: List[str]
) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    """Parse la réponse JSON du LLM et applique validate_suggested_label.

    Retourne ``(improved, invalid_labels)`` où :

    - ``improved`` : map ``term → label_validé`` (labels qui passent
      validate_suggested_label).
    - ``invalid_labels`` : liste des rejets pour observabilité.

    **Anti-hallucination** :

    - Ignore tout ``term`` qui n'est pas dans ``candidate_set`` (le LLM
      ne peut pas inventer de nouveaux termes).
    - Ignore tout ``label`` qui ne passe pas validate_suggested_label.

    Si le JSON est totalement invalide, retourne ``({}, [])`` — le caller
    interprétera ça comme un échec parse (status="error").
    """
    if not isinstance(content, str) or not content.strip():
        return {}, []

    # Strip markdown code fences si le LLM en ajoute (Phi-3 / Llama font ça
    # parfois malgré la consigne).
    stripped = content.strip()
    if stripped.startswith("```"):
        # Retire ```json\n…\n```
        lines = stripped.split("\n")
        if len(lines) > 2:
            stripped = "\n".join(lines[1:-1]).strip()

    # Parser tolérant (fix 2026-05-19) : si le LLM a entouré le JSON d'un
    # texte explicatif (« Here are the labels: {…} »), extrait le 1ʳᵉ objet
    # JSON via balance d'accolades. Plus permissif que ``json.loads`` direct
    # mais reste safe : l'extraction commence à la 1ʳᵉ ``{`` et finit à
    # l'``}`` correspondante (sans regex globale qui matcherait n'importe
    # quoi).
    def _extract_first_json_object(text: str) -> Optional[str]:
        start = text.find("{")
        if start < 0:
            return None
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            c = text[i]
            if escape:
                escape = False
                continue
            if c == "\\":
                escape = True
                continue
            if c == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        return None

    payload = None
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        # Retry avec extraction d'objet JSON balanced (LLM a peut-être
        # ajouté un préfixe explicatif).
        extracted = _extract_first_json_object(stripped)
        if extracted:
            try:
                payload = json.loads(extracted)
            except (json.JSONDecodeError, ValueError):
                payload = None

    # Fix 2026-05-20 — Récupération JSON tronqué :
    # qwen2.5:3b a un EOS imprévisible et peut hitter le max_output
    # tokens au milieu d'un ``{"term":"X","label":"Y"}, {"term":"Z"...``.
    # On tente de fermer le tableau ``items`` au dernier item complet
    # avant le tronquage. Best-effort, defense-in-depth — si ça rate, on
    # retombe sur payload=None (path d'erreur existant).
    if payload is None and stripped.startswith("{"):
        # Cherche la position du dernier objet d'item COMPLET dans le tableau.
        # Pattern : ``"label":"..."}`` (close-quote + close-brace) — la garantie
        # que cet item est entier (clé label posée + objet refermé).
        # On reconstruit ensuite ``...lastCompleteItem]}`` pour avoir un JSON
        # syntaxiquement valide.
        items_start = stripped.find('"items"')
        if items_start > 0:
            arr_open = stripped.find("[", items_start)
            if arr_open > 0:
                # Trouve le dernier ``}`` qui termine un item d'array
                # (= ``}`` immédiatement suivi d'une ``,`` OU rien d'utile).
                # On scanne en avant en respectant les strings (anti-faux-positifs
                # type ``"label":"FOO}BAR"``).
                last_item_end = -1
                depth = 0
                in_string = False
                escape = False
                for idx in range(arr_open + 1, len(stripped)):
                    ch = stripped[idx]
                    if escape:
                        escape = False
                        continue
                    if ch == "\\":
                        escape = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            last_item_end = idx  # ferme un item de l'array
                if last_item_end > 0:
                    repaired = stripped[: last_item_end + 1] + "]}"
                    try:
                        payload = json.loads(repaired)
                        logger.warning(
                            "improve_pseudo._parse_response: JSON tronqué "
                            "réparé (cap max_output_tokens probable) — %d items "
                            "récupérés sur les %d demandés.",
                            repaired.count('"term"'),
                            len(tokens_list),
                        )
                    except (json.JSONDecodeError, ValueError):
                        payload = None

    if payload is None:
        # Log debug tronqué — utile pour diagnostiquer les LLM locaux qui
        # produisent du texte au lieu de JSON. Pas de risque PII fort sur
        # le LOCAL (machine du user) ; on cap à 200 chars + niveau DEBUG
        # (pas INFO/WARNING qui pollueraient les logs prod).
        preview = stripped[:200].replace("\n", " ")
        logger.warning(
            "improve_pseudo._parse_response: JSON invalide (%d chars) — " "preview: %r",
            len(stripped),
            preview,
        )
        return {}, []

    candidate_set: Set[str] = set(tokens_list)
    if not isinstance(payload, dict):
        logger.warning(
            "improve_pseudo._parse_response: payload n'est pas un dict " "(type=%s) — preview: %r",
            type(payload).__name__,
            stripped[:200].replace("\n", " "),
        )
        return {}, []
    items = payload.get("items")
    if not isinstance(items, list):
        # Fallback positionnel — fix 2026-05-20 sur logs serveur :
        # les petits modèles (qwen2.5:3b, phi3:mini) ne suivent pas
        # toujours le schéma ``{"items":[{"term":..., "label":...}]}``.
        # qwen a observé répondre ``{"data": ["AMOUNT","NOM_FAMILLE",...]}``
        # aligné par position. On accepte si :
        # (a) une seule liste dans le payload a EXACTEMENT len(tokens_list)
        # (b) tous les éléments sont des labels valides
        # Anti-hallucination préservée : on ne peut pas inventer un terme,
        # juste mal le classer (le user voit et corrige).
        candidate_lists = [
            (k, v) for k, v in payload.items() if isinstance(v, list) and len(v) == len(tokens_list)
        ]
        if len(candidate_lists) == 1:
            key, labels = candidate_lists[0]
            improved_pos: Dict[str, str] = {}
            invalid_pos: List[Dict[str, str]] = []
            for i, raw in enumerate(labels):
                term = tokens_list[i]
                if term in improved_pos:
                    continue
                raw_label = str(raw) if not isinstance(raw, str) else raw
                is_valid, reason = validate_suggested_label(raw_label)
                if not is_valid or "§" in raw_label:
                    invalid_pos.append(
                        {
                            "term": term,
                            "raw_label": raw_label,
                            "reason": reason
                            or ("contains_sentinel" if "§" in raw_label else "unknown"),
                        }
                    )
                    continue
                improved_pos[term] = raw_label
            if improved_pos:
                logger.warning(
                    "improve_pseudo._parse_response: fallback positionnel "
                    "engagé (clé '%s' au lieu de 'items', %d/%d labels valides). "
                    "Le LLM (probablement un modèle 3B) ne suit pas le schéma "
                    "``items:[{term,label}]`` — mapping par position appliqué.",
                    key,
                    len(improved_pos),
                    len(tokens_list),
                )
                return improved_pos, invalid_pos
        logger.warning(
            "improve_pseudo._parse_response: clé 'items' absente ou non-list "
            "(keys=%s) et fallback positionnel inapplicable — preview: %r. "
            "Le LLM a répondu en JSON valide mais n'a pas suivi le schéma "
            'attendu {"items":[{"term":...,"label":...}]}.',
            sorted(payload.keys())[:10],
            stripped[:200].replace("\n", " "),
        )
        return {}, []

    improved: Dict[str, str] = {}
    invalid_labels: List[Dict[str, str]] = []
    # Compteurs observabilité — fix audit logs 2026-05-20 :
    # le user a vu un cas updated=0 sans diag, on tracke maintenant les
    # raisons de drop pour qu'un futur audit n'ait pas besoin de re-runner.
    dropped_not_dict = 0
    dropped_bad_types = 0
    dropped_anti_halluc = 0
    dropped_duplicate = 0
    for entry in items:
        if not isinstance(entry, dict):
            dropped_not_dict += 1
            continue
        term = entry.get("term")
        raw_label = entry.get("label")
        if not isinstance(term, str) or not isinstance(raw_label, str):
            dropped_bad_types += 1
            continue
        if term not in candidate_set:
            # Anti-hallucination : le LLM ne peut pas inventer un terme.
            dropped_anti_halluc += 1
            continue
        if term in improved:
            # Doublon dans la réponse — on garde la 1ère.
            dropped_duplicate += 1
            continue
        is_valid, reason = validate_suggested_label(raw_label)
        if not is_valid:
            invalid_labels.append(
                {
                    "term": term,
                    "raw_label": raw_label,
                    "reason": reason or "unknown",
                }
            )
            continue
        # Fix #1 (review adversariale 2026-05-19) — Defense in depth :
        # ``_LABEL_REGEX`` interdit déjà le caractère sentinelle ``§`` (hors
        # [A-Z_]), mais on assert explicitement pour qu'un futur élargissement
        # de la regex (ex: autoriser accents) ne casse pas silencieusement
        # le ``Pseudonymizer.add_mapping`` qui refuse ``§`` en fail-closed.
        if "§" in raw_label:  # noqa: PLR2004 — sentinelle §
            invalid_labels.append(
                {
                    "term": term,
                    "raw_label": raw_label,
                    "reason": "contains_sentinel",
                }
            )
            continue
        improved[term] = raw_label

    # Diagnostic warning si le LLM a répondu en JSON valide avec items[]
    # mais 0 mapping retenu — symptôme classique d'un modèle 3B qui :
    # (a) renvoie des termes légèrement modifiés (case, quotes) ne matchant
    #     pas candidate_set → dropped_anti_halluc > 0
    # (b) renvoie {"items":[]} → tous compteurs à 0
    # (c) renvoie items avec mauvaises clés → dropped_bad_types > 0
    # Sans ce log, l'admin voit "updated=0" sans savoir pourquoi.
    if items and not improved and not invalid_labels:
        logger.warning(
            "improve_pseudo._parse_response: %d items reçus du LLM mais 0 "
            "retenu (candidate_set=%d). Drops: not_dict=%d, bad_types=%d, "
            "anti_halluc=%d, duplicate=%d. Preview JSON: %r",
            len(items),
            len(candidate_set),
            dropped_not_dict,
            dropped_bad_types,
            dropped_anti_halluc,
            dropped_duplicate,
            stripped[:300].replace("\n", " "),
        )

    return improved, invalid_labels


async def improve_pseudos_chunk(
    candidate_tokens: Set[str],
    *,
    timeout_seconds: Optional[float] = None,
) -> ImprovePseudoResult:
    """Traite UN chunk de termes via le LLM local.

    Le caller (handler ou frontend) est responsable du chunking — cette
    fonction traite ce qu'on lui passe. Plus de hard cap arbitraire
    (retiré 2026-05-19) : la seule limite est ce que le modèle peut
    réellement encaisser, calculé dynamiquement dans
    :func:`compute_dynamic_batch_size_async` à partir de ``context_window``
    et ``max_output_tokens`` du registre ``LlmModel``.

    Confidentialité Niveau 3 :

    - Envoie UNIQUEMENT les termes (pas le contexte classeur/colonne).
    - Aucun log des termes en clair (anti-leak PII).
    - Le LLM local tourne sur la machine de l'user (Ollama/LM Studio) ou
      sur un réseau privé contrôlé par l'admin (TGI cluster).

    Best-effort :

    - LLM local non configuré → ``status="not_configured"``
    - Timeout → ``status="timeout"``
    - Parse JSON / erreur LLM → ``status="error"``

    Args:
        candidate_tokens: ensemble de termes à étiqueter. Le caller doit
            avoir filtré côté serveur sur ``enabled=true && pseudo_middle
            IS NULL`` (préservation des customs).
        timeout_seconds: timeout par appel LLM. Default 60s.

    Returns:
        :class:`ImprovePseudoResult` avec ``improved``, ``invalid_labels``,
        ``status``.
    """
    if not candidate_tokens:
        return ImprovePseudoResult()

    # Garde-fou précoce (review adversariale 2026-05-20) : un caller qui pose
    # ``timeout_seconds=0.0`` (ou négatif) ferait timeout tous les appels
    # instantanément avec ``status="timeout"``. ``None`` reste la sentinelle
    # "pas d'avis, lis la config admin". Refus explicite ≠ silencieux.
    # Posé AVANT ensure_providers_from_db pour fail-fast (n'init pas la BDD
    # pour rien).
    if timeout_seconds is not None and timeout_seconds <= 0:
        raise ValueError(
            f"timeout_seconds doit être > 0 (reçu {timeout_seconds!r}). "
            f"Utilise None pour déléguer à la config admin "
            f"local_llm_timeout_seconds."
        )

    # Cap dur défensif. Fix #22 (review 2026-05-19) : ne PAS tronquer
    # silencieusement — on retourne un status="error" si le caller envoie
    # Plus de hard cap arbitraire (retiré 2026-05-19). Le frontend respecte
    # le batch_size dynamique retourné par le ``/probe`` ; un dépassement
    # ferait juste timeout côté LLM, signalant correctement le bug client
    # sans rejet artificiel côté serveur. La seule limite réelle = ce que
    # le modèle peut techniquement encaisser (ctx_window + max_output_tokens).
    tokens_list = list(candidate_tokens)
    set(tokens_list)

    # Import tardif (mêmes raisons qu'auto_classify).
    try:
        from app.services.ai.llm_providers import (
            LLMRequest,
            ensure_providers_from_db,
            get_llm_manager,
        )
        from app.services.ai.llm_runtime import (
            CallProfile,
            LLMCallError,
            ModelKind,
            RetryPolicy,
            call_llm,
        )
    except ImportError as exc:
        logger.warning(
            "improve_pseudos_chunk: providers indisponibles : %s",
            exc,
        )
        return ImprovePseudoResult(
            status="error",
            message="Providers LLM indisponibles (import).",
        )

    await ensure_providers_from_db()
    manager = get_llm_manager()
    if manager.get_local_fallback() is None:
        logger.debug(
            "improve_pseudos_chunk: LLM local non configuré "
            "(/admin/ai-config → Anonymisation locale)"
        )
        return ImprovePseudoResult(status="not_configured")

    # Température + timeout lus de la config admin. Fix logs 2026-05-20 :
    # le caller ne pouvait pas surcharger ``timeout_seconds`` au-delà du
    # défaut hardcodé 60s. Sur CPU avec qwen2.5:3b et 115 termes, ça
    # timeout systématiquement (cf. ai_config default = 300s). On lit
    # la config ici pour que le bouton « Améliorer » respecte le réglage
    # admin sans nécessiter un changement de signature à chaque call-site.
    #
    # Précédence claire (refactor 2026-05-20) : caller-explicite (param
    # ``timeout_seconds`` non-None) > config admin > _DEFAULT_TIMEOUT_SECONDS.
    #
    # Avant : ``timeout_seconds: float = _DEFAULT`` + check ``== _DEFAULT``
    # comme sentinelle d'override admin. Coupling fragile : un caller qui
    # passe explicitement ``timeout_seconds=60.0`` (= valeur du défaut)
    # voyait son override IGNORÉ silencieusement au profit de la config admin.
    # Maintenant : ``Optional[float] = None`` est la sentinelle dédiée —
    # plus d'ambiguïté entre "défaut hardcodé" et "override explicite à 60s".
    local_temp = 0.0
    effective_timeout: float = (
        timeout_seconds if timeout_seconds is not None else _DEFAULT_TIMEOUT_SECONDS
    )
    try:
        from app.services.ai.config_service import get_ai_config_service

        cs = get_ai_config_service()
        raw_temp = await cs.get("local_llm_temperature")
        if raw_temp is not None:
            local_temp = float(raw_temp)
        # Lit la config admin SEULEMENT si le caller n'a pas posé d'override
        # explicite. ``None`` = "je n'ai pas d'avis, prends ce que l'admin a configuré".
        if timeout_seconds is None:
            raw_to = await cs.get("local_llm_timeout_seconds")
            if raw_to is not None:
                effective_timeout = float(raw_to)
    except Exception:  # noqa: BLE001
        pass

    # ``max_output`` lu DIRECTEMENT du registre BDD (single source of truth
    # admin-éditable, cf. ``feedback_max_tokens_must_be_dynamic.md``). Pas
    # de cap par estimation interne — David l'a répété plusieurs fois.
    try:
        from app.constants_ai import get_max_tokens_for_model

        model_max_out = get_max_tokens_for_model(manager.get_local_fallback_model() or "") or 0
    except Exception:  # noqa: BLE001
        model_max_out = 0
    if model_max_out > 0:
        max_output = model_max_out
    else:
        # Fallback estimation conservatrice (modèle inconnu — pas dans le
        # registre BDD). 15 tokens/item couvre les labels longs comme
        # ``IDENTIFIANT_BANCAIRE`` + chiffrage.
        max_output = 15 * len(tokens_list) + 100

    # Boucle de continuation (fix 2026-05-20 sur demande user) : si le LLM
    # tronque au milieu d'un JSON (cap max_output atteint, EOS imprévisible
    # des modèles 3B), on relance avec UNIQUEMENT les termes restants. Plus
    # propre que la "réparation" qui abandonne silencieusement.
    #
    # **Adaptive backoff** (fix 2026-05-22 — incident chunk 497 termes,
    # timeout 90s, 0 traités) : ``compute_dynamic_batch_size_async`` calcule
    # le batch_size sur le plafond technique du modèle (context_window +
    # max_output_tokens) sans tenir compte du temps de génération RÉEL.
    # Un qwen2.5:3b sur CPU produit ~5 tokens/s — 497 termes × 11 tokens
    # output = ~18 minutes de génération. Le timeout 90s coupe avant le
    # 1ʳᵉ item parsable. Sans adaptive, le user voyait 0/497 traités.
    # Avec l'adaptive, si un tour timeout, on divise le chunk par 4 et on
    # re-tente — ce qui converge vers la zone "le LLM tient le timeout".
    # Pas de cap initial arbitraire : on respecte le batch_size du probe
    # pour le 1ᵉʳ essai (doctrine "pas de magic number" — David 2026-05-19).
    #
    # Garde-fous :
    # - ``_MAX_CONTINUATIONS`` = 8 (anti-boucle infinie si LLM HS)
    # - Si un tour retourne 0 mappings (parse total échec) → abandon
    # - Si un tour ne fait aucun progrès (restants identiques) → abandon
    # - **Budget total = 2× effective_timeout** (fix proxy 2026-05-20) :
    #   nginx (60s) / Cloudflare (100s) couperaient sur N continuations ×
    #   300s = 40 min. On borne globalement à 2× le timeout par appel,
    #   capé à 180s. Au-delà, on retourne un résultat PARTIEL (status="ok"
    #   avec les mappings déjà obtenus) au lieu de continuer et risquer
    #   une coupure proxy invisible.
    #
    # **LIMITE CONNUE** (review adversariale 2026-05-20) : la garantie
    # "budget total" protège ENTRE tours, pas PENDANT un appel unique.
    # Si ``effective_timeout`` ≥ `_TOTAL_BUDGET_SECONDS`, le 1er call_llm
    # peut consommer tout le budget avant le check du tour 2 → le proxy
    # peut couper avant qu'on émette `status="ok"` partiel. On clamp
    # ``effective_timeout`` à la moitié du budget pour garantir 2 tours
    # minimum (le 1er ne peut pas excéder le budget).
    _MAX_CONTINUATIONS = 8
    _TOTAL_BUDGET_SECONDS = min(2.0 * effective_timeout, 180.0)
    # Clamp pour garantir au moins 2 tours dans le budget.
    effective_timeout = min(effective_timeout, _TOTAL_BUDGET_SECONDS / 2.0)
    #: Facteur de division du chunk size sur timeout. 4 (pas 2) parce que
    #: la génération LLM est ~linéaire en N tokens : un chunk de N/2 met
    #: ~T/2 mais si N est déjà énorme par rapport au timeout T, /2 ne
    #: converge pas assez vite. Avec /4, on converge en log_4(N) tours.
    _CHUNK_DIVIDE_ON_TIMEOUT = 4
    _started_at = time.monotonic()
    remaining: List[str] = list(tokens_list)
    all_improved: Dict[str, str] = {}
    all_invalid: List[Dict[str, str]] = []

    def _compute_unprocessed() -> List[str]:
        """Termes input qui n'ont fini ni dans ``all_improved`` ni dans
        ``all_invalid``. SSoT (#97/D6-F2) appelée à CHAQUE sortie ``status=ok``
        (boucle terminée OU timeout/erreur avec progrès partiel) — sinon le
        même terme « perdu » resurgit sur les chemins d'erreur partielle que
        l'adversarial a trouvés (timeout-at-floor / LLMCallError / Exception)."""
        _processed = set(all_improved.keys()) | {
            e["term"] for e in all_invalid if isinstance(e, dict) and "term" in e
        }
        return [t for t in tokens_list if t not in _processed]
    # adaptive_chunk_size = nombre de termes ENVOYÉS par tour. Démarre
    # à ``len(remaining)`` (respect du batch_size du probe) et se divise
    # sur timeout. Le ``min(adaptive_chunk_size, len(remaining))`` garantit
    # qu'on ne dépasse pas ce qu'il reste.
    adaptive_chunk_size: int = len(remaining)

    for attempt in range(_MAX_CONTINUATIONS):
        if not remaining:
            break
        # Vérifie le budget AVANT chaque nouvel appel — laisse une marge
        # pour que le call_llm en cours ne dépasse pas du proxy timeout.
        _elapsed = time.monotonic() - _started_at
        if _elapsed >= _TOTAL_BUDGET_SECONDS:
            logger.warning(
                "improve_pseudos_chunk: budget total %.0fs atteint au tour %d "
                "(%d/%d termes traités) — retour partiel pour éviter "
                "coupure proxy.",
                _TOTAL_BUDGET_SECONDS,
                attempt + 1,
                len(all_improved) + len(all_invalid),
                len(tokens_list),
            )
            break
        # Slice du remaining selon adaptive_chunk_size. Le tour traite
        # ``chunk_now`` ; ``remaining`` n'est filtré qu'après pour
        # n'enlever que ce qui a été réellement processed (improved ou
        # invalid_label). Les termes ratés (tronqués LLM, timeout) sont
        # remis en tête de file pour le tour suivant.
        chunk_now: List[str] = remaining[:adaptive_chunk_size]
        # Ajuste max_output au CHUNK courant (pas remaining entier) pour
        # ne pas demander un budget de tokens trop large quand on a
        # réduit l'adaptive_chunk_size. Sans ça, après division, on
        # demanderait toujours max_output pour N termes mais on n'en
        # envoie que N/4 → LLM pourrait halluciner du remplissage.
        #
        # **Fix D6 review adversariale 2026-05-22** : même quand le
        # registre fournit ``model_max_out`` (cap absolu plafond), on
        # ne demande pas PLUS que l'estimation conservative basée sur
        # ``len(chunk_now)``. Le registre = PLAFOND, pas valeur cible.
        # Sinon : pour un chunk réduit à 1 terme après division /4²,
        # on demandait toujours 7555 tokens (cap qwen2.5:3b) au lieu
        # des ~115 tokens réellement nécessaires → encourage le LLM
        # à halluciner du remplissage.
        estimated_output = 15 * len(chunk_now) + 100
        if model_max_out > 0:
            chunk_max_output = min(max_output, estimated_output)
        else:
            chunk_max_output = estimated_output
        prompt = _PROMPT_TEMPLATE.format(tokens_json=json.dumps(chunk_now, ensure_ascii=False))
        try:
            response = await call_llm(
                CallProfile(
                    caller="anonymizer_improve_pseudo",
                    model_kind=ModelKind.LOCAL,
                    timeout_seconds=effective_timeout,
                    retry=RetryPolicy.NONE,
                ),
                LLMRequest(
                    prompt=prompt,
                    system=(
                        "Tu classifies des valeurs en labels UPPERCASE. "
                        "Tu réponds UNIQUEMENT en JSON valide, aucun texte autour."
                    ),
                    temperature=local_temp,
                    max_tokens=chunk_max_output,
                    options={"response_format": {"type": "json_object"}},
                ),
            )
        except LLMCallError as exc:
            # Erreur réseau/timeout : adaptive backoff si on a encore
            # de la marge sur la taille du chunk. Sinon retour partiel.
            if exc.kind == "network":
                if adaptive_chunk_size > 1:
                    new_size = max(
                        1, adaptive_chunk_size // _CHUNK_DIVIDE_ON_TIMEOUT
                    )
                    # Fix D2 review adversariale 2026-05-22 : log clair
                    # avec chunk={old} → {new} (sans doublon).
                    logger.warning(
                        "improve_pseudos_chunk: timeout LLM local (%.0fs) au "
                        "tour %d — réduction adaptive chunk %d → %d pour le "
                        "tour suivant. (%d/%d termes déjà traités)",
                        effective_timeout,
                        attempt + 1,
                        adaptive_chunk_size,
                        new_size,
                        len(all_improved) + len(all_invalid),
                        len(tokens_list),
                    )
                    adaptive_chunk_size = new_size
                    # On continue la boucle — le tour suivant retentera
                    # avec le chunk réduit. ``remaining`` n'est pas
                    # modifié (les termes ratés restent en tête).
                    continue
                # Floor atteint (1) : retour partiel.
                logger.warning(
                    "improve_pseudos_chunk: timeout LLM local (%.0fs) au "
                    "tour %d, chunk déjà au floor (1 terme) — abandon. "
                    "(%d/%d termes traités au total)",
                    effective_timeout,
                    attempt + 1,
                    len(all_improved) + len(all_invalid),
                    len(tokens_list),
                )
                if all_improved or all_invalid:
                    return ImprovePseudoResult(
                        improved=all_improved,
                        invalid_labels=all_invalid,
                        unprocessed=_compute_unprocessed(),
                        status="ok",
                        message=f"Timeout sur les {len(remaining)} derniers termes — résultat partiel.",
                    )
                return ImprovePseudoResult(
                    status="timeout",
                    message=f"LLM local n'a pas répondu en {effective_timeout:.0f}s.",
                )
            logger.warning("improve_pseudos_chunk: erreur LLM local : %s", exc)
            if all_improved or all_invalid:
                return ImprovePseudoResult(
                    improved=all_improved,
                    invalid_labels=all_invalid,
                    unprocessed=_compute_unprocessed(),
                    status="ok",
                    message=f"Erreur en cours de continuation : {exc}",
                )
            return ImprovePseudoResult(
                status="error",
                message=f"Erreur LLM local : {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "improve_pseudos_chunk: erreur inattendue tour %d : %s",
                attempt + 1,
                exc.__class__.__name__,
            )
            if all_improved or all_invalid:
                return ImprovePseudoResult(
                    improved=all_improved,
                    invalid_labels=all_invalid,
                    unprocessed=_compute_unprocessed(),
                    status="ok",
                )
            return ImprovePseudoResult(
                status="error",
                message=f"Erreur inattendue : {exc.__class__.__name__}",
            )

        improved, invalid = _parse_response(response.content, chunk_now)

        # Si parse total échec → LLM est HS, arrêter
        if not improved and not invalid:
            logger.warning(
                "improve_pseudos_chunk: 0 mapping retenu au tour %d "
                "(LLM HS ou JSON corrompu) — abandon des %d restants.",
                attempt + 1,
                len(remaining),
            )
            break

        all_improved.update(improved)
        all_invalid.extend(invalid)

        # Calcul du nouveau ``remaining`` : retirer les termes processed
        # (improved OU invalidés) du chunk_now ET concaténer avec le
        # reste de ``remaining`` (au-delà de adaptive_chunk_size). Le
        # contrat : tout terme non explicitement traité (improved/invalid)
        # est remis en file d'attente — vrai pour les ratés (tronqués
        # LLM, omis par le modèle).
        #
        # **Fix D3 review adversariale 2026-05-22** : les termes
        # ``unprocessed_from_chunk`` sont placés en FIN de la file (pas
        # en tête) pour éviter qu'un terme "toxique" (qui fait crasher
        # le parsing LLM systématiquement) soit re-présenté en tête à
        # chaque tour → boucle de retentatives sur le même terme. En
        # le mettant en queue, on traite les nouveaux termes d'abord ;
        # le terme toxique sera tenté en dernier, isolé.
        processed_terms = set(improved.keys()) | {
            entry["term"] for entry in invalid if isinstance(entry, dict)
        }
        unprocessed_from_chunk = [t for t in chunk_now if t not in processed_terms]
        new_remaining = remaining[adaptive_chunk_size:] + unprocessed_from_chunk

        if not new_remaining:
            # Tous traités sur ce tour
            if attempt > 0:
                logger.info(
                    "improve_pseudos_chunk: complété en %d tours (%d termes total).",
                    attempt + 1,
                    len(tokens_list),
                )
            break

        if len(new_remaining) >= len(remaining):
            # Aucun progrès : on évite la boucle infinie
            logger.warning(
                "improve_pseudos_chunk: aucun progrès au tour %d "
                "(%d termes inchangés) — abandon.",
                attempt + 1,
                len(new_remaining),
            )
            break

        logger.info(
            "improve_pseudos_chunk: continuation %d/%d — %d traités ce tour, "
            "%d restants à traiter (adaptive_chunk_size=%d).",
            attempt + 1,
            _MAX_CONTINUATIONS,
            len(remaining) - len(new_remaining),
            len(new_remaining),
            adaptive_chunk_size,
        )
        remaining = new_remaining
    else:
        # Boucle complétée sans break : on a hit _MAX_CONTINUATIONS
        if remaining:
            logger.warning(
                "improve_pseudos_chunk: cap continuations atteint (%d tours) "
                "avec %d termes restants non traités (adaptive_chunk_size=%d).",
                _MAX_CONTINUATIONS,
                len(remaining),
                adaptive_chunk_size,
            )

    # #97/D6-F2 — termes NON traités (budget continuations épuisé / aucun
    # progrès). Même calcul SSoT que les sorties d'erreur partielle ci-dessus.
    return ImprovePseudoResult(
        improved=all_improved,
        invalid_labels=all_invalid,
        unprocessed=_compute_unprocessed(),
        status="ok",
    )
