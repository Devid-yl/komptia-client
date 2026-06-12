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

import logging
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


def _canonical_for_echo(s: str) -> str:
    """Forme canonique pour comparer un label et un terme : minuscules, accents
    retirés, et tout ce qui n'est pas ``[a-z0-9]`` supprimé (``_``, espaces,
    ponctuation). ``"Fusionne"`` et ``"FUSIONNE"`` → ``"fusionne"`` ;
    ``"Multi-source"`` et ``"MULTI_SOURCE"`` → ``"multisource"``.
    """
    s = unicodedata.normalize("NFKD", s or "")
    s = "".join(c for c in s if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _label_echoes_term(label: str, term: str) -> bool:
    """True si le ``label`` n'est qu'une RECOPIE du ``term`` au lieu d'une vraie
    catégorie sémantique.

    **Pourquoi (fix confidentialité 2026-06-09)** : un petit modèle local (3B)
    recopie souvent le terme comme « catégorie » — terme ``"extractions"`` →
    ``"1=extractions"`` → label ``"EXTRACTIONS"``. Ça passe la regex (majuscules
    valides) mais le pseudonyme ``§EXTRACTIONS_xxx§`` RÉVÈLE le terme au LLM
    cloud → ce n'est PLUS de l'anonymisation (mesuré : 44 % des pseudos d'un
    dictionnaire réel recopiaient le terme). On compare les formes canoniques
    (casse + accents + séparateurs ignorés). **Bias confidentialité** : au
    moindre recouvrement substantiel, on rejette → fallback vers le label
    opaque ``TXT``/``NUM`` (cf. ``extract._auto_pseudo_middle``).
    """
    ct = _canonical_for_echo(term)
    cl = _canonical_for_echo(label)
    if not ct or not cl:
        return False
    if ct == cl:
        return True
    # Un terme « substantiel » (≥ 3 caractères canoniques) contenu dans le label
    # — ou l'inverse — est une recopie quasi-certaine (``communes`` →
    # ``CUMUL_COMMUNES``, ``email`` → ``EMAIL``). Sous 3 car, trop de faux
    # positifs sur des catégories légitimes courtes.
    if len(ct) >= 3 and (ct in cl or cl in ct):
        return True
    return False

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
    template_chars = len(_PROMPT_TEMPLATE) - len("{numbered_values}")
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


# Refonte 2026-06-08 — prompt « matching par NUMÉRO ». Le LLM reçoit des valeurs
# NUMÉROTÉES et répond UNE LIGNE par valeur au format « numéro=CATEGORIE ». Il ne
# recopie JAMAIS la valeur → un petit modèle (3B/CPU) ne peut plus tronquer un nom
# propre rare (« BORDIER » → « BORD ») et faire échouer l'anti-hallucination par
# match exact. Le format ligne est aussi bien plus robuste que le JSON imbriqué
# pour les petits modèles : pas d'accolades à fermer, naturellement tolérant à la
# troncature (dernière ligne coupée = 1 item perdu, le reste intact).
_PROMPT_TEMPLATE: str = """\
Classe chaque valeur NUMÉROTÉE dans une catégorie en MAJUSCULES (lettres A-Z et _ uniquement, max 30 caractères).
Une catégorie est un terme qui décrit la valeur de manière générale, sans être une recopie du terme lui-même.

Réponds avec UNE LIGNE par valeur, au format exact « numéro=CATEGORIE », et RIEN d'autre.
N'écris JAMAIS la valeur elle-même — seulement son numéro et sa catégorie.

Exemple de catégories : TEXTE, NOMBRE, DATE, HEURE, DATE_HEURE, BOOLEAN, EMAIL, URL, TELEPHONE, IDENTIFIANT, CODE, DEVISE, POURCENTAGE, MESURE, NOM_COMMUN, NOM_PROPRE, VERBE, ADJECTIF, ADVERBE, PRONOM, DETERMINANT, PREPOSITION, CONJONCTION, INTERJECTION, SIGLE, ACRONYME, ABREVIATION, ACTION, ETAT, QUALITE, PROPRIETE, OBJET, PERSONNE, ORGANISATION, LIEU, EVENEMENT, TEMPS, QUANTITE, INFORMATION, COMMUNICATION, DOCUMENT, SYSTEME, PROCESSUS, RELATION, GROUPE, ROLE, ACTIVITE, RESSOURCE, PHENOMENE, CONCEPT, EMOTION, OPINION, CONDITION, RESULTAT, CAUSE, CONSEQUENCE, ANALYSE, DETECTION, IDENTIFICATION, CLASSIFICATION, VERIFICATION, VALIDATION, CONTROLE, SURVEILLANCE, ALERTE, SECURITE, RISQUE, ANOMALIE, ERREUR, QUALITE_DONNEE, STATISTIQUE, INDICATEUR, METRIQUE, VALEUR, VARIABLE, PARAMETRE, CONFIGURATION, PERFORMANCE, COMMUNICATION_NUMERIQUE, MESSAGERIE, FORMAT_FICHIER, BASE_DE_DONNEES, RESEAU, APPLICATION, MATERIEL, LOGICIEL, FINANCE, COMMERCE, SANTE, EDUCATION, TRANSPORT, ENERGIE, ENVIRONNEMENT, JURIDIQUE, ADMINISTRATION, SCIENCE, TECHNOLOGIE

Valeurs :
{numbered_values}
Réponse :
"""

# Parse une ligne de réponse « numéro<séparateur>label ». Tolérances (petits
# modèles varient le format) : préfixe de puce/gras markdown (``- ``, ``* ``,
# ``> ``, ``# ``) absorbé ; séparateurs (=, :, ., ), -, espace) ; numéro jusqu'à
# 6 chiffres (chunks > 9999 termes possibles sur gros context window). DOIT
# rester cohérent avec le format demandé dans _PROMPT_TEMPLATE.
_LINE_REGEX: re.Pattern[str] = re.compile(r"^[\s\-*>•]*#?\s*(\d{1,6})[=:.)\s-]+(.+)$")


# ─── Fonction principale ────────────────────────────────────────────────────


def _parse_response(
    content: str, tokens_list: List[str]
) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    """Parse la réponse LIGNE du LLM (« numéro=CATEGORIE ») et valide chaque label.

    Refonte 2026-06-08 — matching par NUMÉRO (index 1-based) au lieu d'une
    recopie du terme. Avant, le prompt demandait au LLM de renvoyer la valeur
    exacte (``{"items":[{"term":"<valeur>","label":...}]}``) et on matchait
    ``term in candidate_set``. Un petit modèle (3B/CPU) tronque les noms propres
    rares (« BORDIER » → « BORD ») → rejeté par l'anti-hallucination → 0 amélioré.
    Désormais le LLM ne renvoie JAMAIS la valeur, seulement son **numéro** ; le
    mapping numéro → terme se fait LOCALEMENT, donc une troncature/déformation du
    nom propre est impossible. Bonus : le format ligne est nativement tolérant au
    bruit (prose, code-fences, troncature de la dernière ligne), ce qui rend
    inutile l'ancienne logique de réparation JSON (~200 lignes supprimées).

    Retourne ``(improved, invalid_labels)`` où :

    - ``improved`` : map ``term → label_validé``.
    - ``invalid_labels`` : rejets (label invalide / sentinelle) pour observabilité.

    **Anti-hallucination par ID** : un numéro hors de ``[1, len(tokens_list)]`` =
    entrée inventée par le LLM (le terme réel n'existe pas) → ignoré.
    """
    if not isinstance(content, str) or not content.strip():
        return {}, []

    n_terms = len(tokens_list)
    improved: Dict[str, str] = {}
    invalid_labels: List[Dict[str, str]] = []
    # Compteurs d'observabilité — même intention que l'ancien parseur :
    # diagnostiquer un « 0 amélioré » sans avoir à re-runner.
    matched_lines = 0
    dropped_out_of_range = 0
    dropped_duplicate = 0

    for raw_line in content.splitlines():
        m = _LINE_REGEX.match(raw_line)
        if m is None:
            # Ligne hors-format (prose, ```fence```, ligne vide, « Réponse : ») →
            # ignorée silencieusement. C'est ce qui remplace toute la logique de
            # nettoyage JSON : le bruit ne matche simplement pas la regex.
            continue
        matched_lines += 1
        idx = int(m.group(1))  # regex garantit \d{1,4}

        # Anti-hallucination par ID : le numéro DOIT être un index 1-based valide.
        # Hors-borne = le LLM a inventé une ligne → on refuse (équivalent de
        # l'ancien ``term not in candidate_set``, mais sans dépendre d'une
        # recopie de chaîne que les petits modèles ratent).
        if idx < 1 or idx > n_terms:
            dropped_out_of_range += 1
            continue

        term = tokens_list[idx - 1]
        if term in improved:
            # Le LLM a renvoyé 2 lignes pour le même numéro — on garde la 1ʳᵉ.
            dropped_duplicate += 1
            continue

        # Normalisation tolérante AVANT validation. Un 3B sort souvent :
        #  - une glose explicative (« NOM_FAMILLE (probable) », « ENTREPRISE, SARL »)
        #    → on coupe à la 1ʳᵉ parenthèse/virgule/point-virgule pour récupérer le
        #    label utile (sinon rejeté par la regex à cause du « ( » / « , »).
        #  - du gras markdown (« **NOM** ») → on strip ``*`` et backtick en bord.
        #  - des minuscules / des espaces (« nom famille ») → upper + espaces→``_``.
        # La garde finale reste ``validate_suggested_label`` (regex ^[A-Z_]{1,30}$ +
        # blacklist anti-injection) + le check sentinelle ``§`` — aucun label
        # dangereux ne passe (la normalisation n'introduit aucun caractère
        # hors [A-Z_] : elle ne fait que couper, strip, upper et espaces→``_``).
        raw_label = re.split(r"[(,;]", m.group(2))[0].strip(" *`")
        label = re.sub(r"\s+", "_", raw_label).upper()

        is_valid, reason = validate_suggested_label(label)
        if not is_valid:
            invalid_labels.append(
                {"term": term, "raw_label": raw_label, "reason": reason or "unknown"}
            )
            continue
        # **Garde anti-recopie (fix confidentialité 2026-06-09)** : le label
        # passe la regex (majuscules valides) MAIS n'est que le terme recopié
        # (``extractions`` → ``EXTRACTIONS``). Un tel pseudo révèle la valeur au
        # cloud → on le rejette. ``term`` est traité en ``invalid_labels`` →
        # le terme garde son label opaque ``TXT``/``NUM`` (sûr) au lieu de fuiter.
        if _label_echoes_term(label, term):
            invalid_labels.append(
                {"term": term, "raw_label": raw_label, "reason": "echoes_term"}
            )
            continue
        # Defense in depth (cf. ancien fix 2026-05-19) : ``§`` est la sentinelle
        # refusée fail-closed par ``Pseudonymizer.add_mapping``. ``_LABEL_REGEX``
        # l'interdit déjà ([A-Z_] only), on re-check pour qu'un futur
        # élargissement de la regex ne casse rien en silence.
        if "§" in label:  # noqa: PLR2004 — sentinelle §
            invalid_labels.append(
                {"term": term, "raw_label": raw_label, "reason": "contains_sentinel"}
            )
            continue
        improved[term] = label

    # Diagnostic : aucune amélioration ni rejet (modèle hors-format / réponse
    # vide / que des numéros hors-borne) — symptôme d'un modèle local trop
    # faible. Sans ce log, l'admin voit « updated=0 » sans savoir pourquoi.
    if not improved and not invalid_labels:
        # Anti-leak PII (fix revue adversariale) : NE PAS logger le ``content``
        # brut du LLM. Un petit modèle hors-format peut recopier des valeurs en
        # clair dans sa réponse, et ce log se déclenche précisément dans ce cas
        # (0 ligne valide). Les compteurs suffisent au diagnostic « 0 amélioré »
        # sans exposer de PII.
        logger.warning(
            "improve_pseudo._parse_response: 0 mapping retenu "
            "(lignes_matchées=%d, hors_borne=%d, doublons=%d, termes=%d).",
            matched_lines,
            dropped_out_of_range,
            dropped_duplicate,
            n_terms,
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
        # Entrée NUMÉROTÉE (1-based) — le LLM répondra par numéro, jamais par
        # recopie de la valeur (cf. _PROMPT_TEMPLATE / _parse_response). Les
        # vraies valeurs ne quittent donc le code que vers le LLM LOCAL, et le
        # mapping numéro → terme reste 100 % côté serveur.
        # Garde déterministe anti « donnée fausse silencieuse » (fix revue
        # adversariale) : on neutralise tout retour à la ligne DANS un terme,
        # sinon il créerait 2 lignes dans le prompt → décalage de toute la
        # numérotation → label appliqué au MAUVAIS terme. Le résultat reste
        # mappé au terme ORIGINAL via l'index (chunk_now n'est pas modifié).
        numbered_values = "\n".join(
            f"{i + 1}. {t.replace(chr(10), ' ').replace(chr(13), ' ')}"
            for i, t in enumerate(chunk_now)
        )
        prompt = _PROMPT_TEMPLATE.format(numbered_values=numbered_values)
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
                        "Tu classes des valeurs numérotées en catégories "
                        "UPPERCASE. Tu réponds UNIQUEMENT par des lignes "
                        "« numéro=CATEGORIE », aucun autre texte, et tu ne "
                        "recopies jamais la valeur."
                    ),
                    temperature=local_temp,
                    max_tokens=chunk_max_output,
                    # NB : plus de ``response_format: json_object`` — on attend
                    # un format LIGNE, pas du JSON (forcer le JSON casserait le
                    # nouveau parseur et réintroduirait la fragilité d'accolades).
                ),
            )
        except LLMCallError as exc:
            # **LLM injoignable (service éteint) → FAIL-FAST** : inutile de
            # réduire le chunk ou de retenter, réduire la taille ne fait pas
            # réapparaître un Ollama arrêté. Sans ce court-circuit, les 4 tours
            # adaptatifs × (3 retries provider) = ~28 s de grind pour rien (le
            # vrai bug prod observé). On abandonne immédiatement, avec retour
            # PARTIEL si des tours précédents ont déjà produit des mappings.
            if exc.kind == "unreachable":
                logger.warning(
                    "improve_pseudos_chunk: LLM local injoignable au tour %d — "
                    "abandon immédiat (pas de réduction adaptive). (%d/%d traités)",
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
                        message="LLM local injoignable — résultat partiel.",
                    )
                # status="unreachable" DISTINCT de "error"/"timeout"/
                # "not_configured" : le service est configuré mais ÉTEINT. Le
                # frontend doit STOPPER la boucle et afficher un message
                # ACTIONNABLE (« démarre le LLM local »), pas un « Terminé : 0/N »
                # trompeur. ``unprocessed`` peuplé (fix M1) → recap honnête.
                return ImprovePseudoResult(
                    status="unreachable",
                    unprocessed=_compute_unprocessed(),
                    message=(
                        "Le LLM local est configuré mais ne répond pas "
                        "(service arrêté ?). Démarre-le puis réessaie."
                    ),
                )
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
