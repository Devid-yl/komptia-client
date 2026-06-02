"""T21 — Détection programmatique du rejet utilisateur (« non, c'est pas ça »).

Pure fonction (0 appel LLM, 0 query BDD). Analyse un message utilisateur
et retourne un dict ``{is_rejection, confidence, reason_hint, signals}``
qui sera injecté dans le contexte de l'agent IA Iris.

Le rôle de ce module est uniquement d'**identifier** le rejet. La réaction
appropriée (proposer alternatives via ``mutate_last_ir``, inspecter les
artefacts, poser une question de clarification, escalader vers
``feedback_service``) reste à la charge du LLM agent — qui dispose déjà
des outils nécessaires.

Synergies (déjà en place — réutilise, ne ré-implémente pas) :

* :func:`app.services.ai.agent_tools._handle_mutate_last_ir` — l'agent peut
  modifier l'IR du tour précédent pour repropose un SQL alternatif.
* :func:`app.services.ai.agent_tools._handle_inspect_pipeline_artifact` —
  permet de voir ``concept_resolution.top_candidates`` (T29★) pour
  envisager les alternatives métier.
* ``IrisFeedbackAPIHandler`` (``POST /api/iris/feedback``) — pour
  l'enregistrement final dans ``search_history.feedback_status``.
* ``context['_last_sql_for_delta']`` — déjà rempli avec le delta row_count
  du tour précédent (signal "cartésien probable" disponible).

Generic : aucun nom métier hardcodé. Patterns linguistiques universels FR + EN.
Le module fonctionne quelle que soit la BDD source.

Le seuil de **confidence** est calibré conservateur : on préfère un
faux négatif (l'agent traite le message comme normal) à un faux positif
(l'agent passe en mode "diagnostic rejet" alors que l'user voulait juste
préciser sa demande). Le LLM agent garde toujours la décision finale.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Seuils + bornes (constantes documentées, modifiables avec tests) ─────

# Confidence ≥ ce seuil → ``is_rejection = True``. Calibré conservateur.
REJECTION_CONFIDENCE_THRESHOLD: float = 0.55

# Cap longueur message analysé. Au-delà, on ne tente PAS de classifier
# (message long = l'user contextualise, pas un rejet net).
MAX_MESSAGE_LEN_FOR_DETECTION: int = 400

# Cap nombre de mots du message considéré "court" (rejet net typique).
# Un message ≤ N mots avec négation forte = rejet quasi-certain.
SHORT_MESSAGE_WORD_THRESHOLD: int = 8


# ─── Patterns linguistiques (regex compilées au module-level — perf) ──────
#
# Stratégie : matcher des motifs **structurels** (négation explicite + verbe
# d'évaluation négatif) plutôt qu'une liste de phrases-types. La liste de
# phrases-types se péremerait vite (FR → autre langue → autre déploiement) ;
# les motifs structurels sont plus robustes.

# Négation forte — la phrase commence par ou contient une négation directe.
# Couvre FR ("non", "c'est pas ça") + EN ("no", "not what", "wrong").
#
# Notes regex :
#   - ``['']?`` pour matcher l'apostrophe droite ASCII (``'``), l'apostrophe
#     typographique unicode (``’``), ou aucune ("cest", "nest"). On normalise
#     le texte en ``_normalize`` AVANT match, donc U+2019 → ``'`` (NFKD ne
#     décompose pas l'apostrophe typographique ; on l'attrape via la classe
#     char optionnelle pour robustesse).
#   - ``[\s,.!?]*`` pour absorber un séparateur optionnel ("non, c'est" ou
#     "non c'est" ou "non. c'est").
#   - ``\w`` Python = Unicode par défaut, donc ``\b`` fonctionne avec accents
#     (mais ``_normalize`` strip les accents → on n'a que de l'ASCII en
#     entrée du match).
_STRONG_NEGATION_RE = re.compile(
    r"\b("
    # FR — "non" autoportant ou en début de rejet
    r"non(?:[\s,.!?]+(?:c['']?est|ce[\s']?n['']?est|c['']?est[\s]+pas|pas|c|ce))?"
    # FR — "c'est faux/incorrect"
    r"|c['']?est[\s]+(?:faux|incorrect|errone)"
    # FR — "c'est (pas) X" : ça, bon, correct, exact, cela, ce que
    r"|c['']?est[\s]+(?:pas[\s]+)?(?:ca|cela|ce[\s]+que|bon|correct|exact|le[\s]+bon|la[\s]+bonne)"
    # FR — "ce n'est pas" + "ne correspond pas"
    r"|ce[\s]+n['']?est[\s]+pas" r"|ne[\s]+correspond[\s]+pas"
    # FR — "pas X" en début/milieu
    r"|pas[\s]+(?:ca|cela|ce[\s]+que|bon|correct|le[\s]+bon|la[\s]+bonne|la[\s]+bonne[\s]+\w+|le[\s]+bon[\s]+\w+|exactement[\s]+ca|exactement[\s]+cela)"
    # FR — verbes de retry
    r"|(?:reessaye|recommence|refais)"
    # EN — "that's not/wrong", "not what i wanted"
    r"|that(?:['']?s)?[\s]+(?:not|wrong)"
    r"|not[\s]+what[\s]+(?:i|we)[\s]+(?:wanted|asked|expected)"
    r"|wrong[\s]+(?:result|answer|table|column|date|period|year)"
    r"|incorrect"
    r"|try[\s]+again"
    r")\b",
    re.IGNORECASE,
)

# Négation faible — l'user pourrait être en désaccord léger ou demander une
# précision. Boost de confiance mais pas suffisant seul.
_WEAK_NEGATION_RE = re.compile(
    r"\b("
    r"pas[\s]+(?:vraiment|exactement|tout[\s]+a[\s]+fait)"
    r"|presque[\s]+mais"
    r"|c['']?est[\s]+pas[\s]+(?:tout[\s]+a[\s]+fait|exactement)"
    r"|hmm|mouais|bof"
    r"|not[\s]+(?:quite|exactly)"
    r")\b",
    re.IGNORECASE,
)


# ─── Hints sémantiques sur la raison probable du rejet ────────────────────
#
# Patterns optionnels qui suggèrent POURQUOI l'user rejette. Ces hints
# permettent à l'agent IA d'orienter sa réaction (inspecter top_candidates
# vs ajuster filtre vs proposer une autre table, etc.).

_HINT_TOO_MANY_RE = re.compile(
    r"\b(trop[ ]+de|too[ ]+many|doublons|duplicates|cart[ée]sien)\b",
    re.IGNORECASE,
)
_HINT_TOO_FEW_RE = re.compile(
    r"\b(pas[ ]+assez|trop[ ]+peu|too[ ]+few|manque[ ]+(?:de|des)|missing|incomplet)\b",
    re.IGNORECASE,
)
_HINT_WRONG_COLUMN_RE = re.compile(
    r"\b(mauvaise[ ]+colonne|wrong[ ]+column|pas[ ]+la[ ]+bonne[ ]+colonne)\b",
    re.IGNORECASE,
)
_HINT_WRONG_TABLE_RE = re.compile(
    r"\b(mauvaise[ ]+table|wrong[ ]+table|pas[ ]+la[ ]+bonne[ ]+table|autre[ ]+table)\b",
    re.IGNORECASE,
)
_HINT_WRONG_PERIOD_RE = re.compile(
    r"\b("
    r"mauvaise[ ]+(?:période|date|année|periode)|wrong[ ]+(?:date|period|year)"
    r"|pas[ ]+la[ ]+bonne[ ]+(?:période|date|année|periode)"
    r")\b",
    re.IGNORECASE,
)
_HINT_WANTED_OTHER_RE = re.compile(
    r"\b(" r"je[ ]+voulais|je[ ]+cherchais|i[ ]+wanted|i[ ]+was[ ]+looking[ ]+for|plutôt" r")\b",
    re.IGNORECASE,
)


def _normalize(text: str) -> str:
    """Lowercase + strip accents (NFKD) pour matching robust aux variations."""
    if not isinstance(text, str):
        return ""
    nfkd = unicodedata.normalize("NFKD", text)
    no_accent = "".join(c for c in nfkd if not unicodedata.combining(c))
    return no_accent.lower().strip()


def _word_count(text: str) -> int:
    return len([w for w in re.findall(r"\w+", text or "") if w])


def detect_rejection(message: str) -> dict:
    """Analyse un message utilisateur pour détecter un rejet.

    Args:
        message: le texte tel qu'envoyé par l'utilisateur (NL, FR ou EN).

    Returns:
        Dict :
        - ``is_rejection`` (bool) : True si confidence ≥ seuil.
        - ``confidence`` (float, [0, 1]) : niveau de certitude.
        - ``reason_hint`` (str | None) : un identifiant court parmi
          ``{too_many_rows, too_few_rows, wrong_column, wrong_table,
          wrong_period, wanted_other, unknown}`` — ou None si pas de
          rejet détecté.
        - ``signals`` (list[str]) : labels des patterns matchés (audit).

    Fail-safe : message None / vide / trop long → ``is_rejection=False``,
    pas de raise.

    Generic : 0 nom BDD hardcodé. Patterns purement linguistiques.
    """
    if not isinstance(message, str) or not message.strip():
        return _no_rejection_result()
    if len(message) > MAX_MESSAGE_LEN_FOR_DETECTION:
        # Message long = contextualisation/précision, pas un rejet net.
        # Le LLM agent saura traiter ça naturellement.
        return _no_rejection_result()

    normalized = _normalize(message)
    n_words = _word_count(normalized)

    confidence = 0.0
    signals: list[str] = []

    # 1. Négation forte → atteint pile le seuil seule (cf. SHORT_MESSAGE_THRESHOLD
    # qui ajoute un bonus pour les messages courts typiques).
    strong_matches = _STRONG_NEGATION_RE.findall(normalized)
    if strong_matches:
        confidence += 0.55
        signals.append("strong_negation")
        # Bonus si message court : "non c'est pas ça" en 4 mots = très net.
        if n_words <= SHORT_MESSAGE_WORD_THRESHOLD:
            confidence += 0.2
            signals.append("short_and_negative")

    # 2. Négation faible → boost mineur (insuffisant seul pour franchir le seuil)
    weak_matches = _WEAK_NEGATION_RE.findall(normalized)
    if weak_matches:
        confidence += 0.2
        signals.append("weak_negation")

    # 3. Hint "voulait autre chose" → renforce (peut faire basculer un weak
    # vers rejection détecté quand cumulé)
    if _HINT_WANTED_OTHER_RE.search(normalized):
        confidence += 0.15
        signals.append("wanted_other")

    # Cap à 1.0
    confidence = min(1.0, confidence)

    is_rejection = confidence >= REJECTION_CONFIDENCE_THRESHOLD

    # 4. Si rejet détecté, tenter d'inférer la raison probable
    reason_hint: Optional[str] = None
    if is_rejection:
        reason_hint = _infer_reason_hint(normalized)

    return {
        "is_rejection": is_rejection,
        "confidence": round(confidence, 2),
        "reason_hint": reason_hint,
        "signals": signals,
    }


def _infer_reason_hint(normalized_text: str) -> str:
    """Devine la raison probable du rejet à partir des patterns secondaires.

    Ordre de priorité : les hints les plus spécifiques d'abord (wrong_X)
    avant les hints quantitatifs (too_many, too_few).
    """
    if _HINT_WRONG_COLUMN_RE.search(normalized_text):
        return "wrong_column"
    if _HINT_WRONG_TABLE_RE.search(normalized_text):
        return "wrong_table"
    if _HINT_WRONG_PERIOD_RE.search(normalized_text):
        return "wrong_period"
    if _HINT_TOO_MANY_RE.search(normalized_text):
        return "too_many_rows"
    if _HINT_TOO_FEW_RE.search(normalized_text):
        return "too_few_rows"
    if _HINT_WANTED_OTHER_RE.search(normalized_text):
        return "wanted_other"
    return "unknown"


def _no_rejection_result() -> dict:
    return {
        "is_rejection": False,
        "confidence": 0.0,
        "reason_hint": None,
        "signals": [],
    }


def build_agent_context_hint(detection: dict, previous_search_id: Optional[int] = None) -> str:
    """Formule un hint texte à injecter dans le contexte du LLM agent.

    Le hint indique à l'agent :
    1. Qu'un rejet a été détecté programmatiquement
    2. La raison probable (si inférée)
    3. Les outils à utiliser pour réagir (déjà existants : ``mutate_last_ir``,
       ``inspect_pipeline_artifact``, ``ask_user_clarification``).
    4. La référence au search_id précédent (pour drill-down).

    Le LLM agent garde la décision finale — ce hint l'oriente seulement.
    Returns une chaîne vide si pas de rejet (caller doit alors ignorer).
    """
    if not isinstance(detection, dict) or not detection.get("is_rejection"):
        return ""

    reason = detection.get("reason_hint") or "unknown"
    confidence = detection.get("confidence", 0.0)

    lines = [
        "🔴 SIGNAL T21 — Rejet utilisateur détecté programmatiquement "
        f"(confidence={confidence}, raison probable={reason}).",
        "",
        "Réaction recommandée — n'utilise QUE les outils déjà disponibles :",
        "  • ``inspect_pipeline_artifact(run_id, phase_id)`` pour voir les "
        "alternatives ``concept_resolution.top_candidates`` (cf. T29★).",
        "  • ``mutate_last_ir`` pour proposer un IR alternatif sans refaire la "
        "pipeline complète (cf. T20).",
        "  • ``ask_user_clarification`` pour préciser l'intention métier si "
        "l'ambiguïté persiste.",
    ]

    if reason == "wrong_column":
        lines.append(
            "  → Hint : l'utilisateur dit que la COLONNE choisie est incorrecte. "
            "Examine ``top_candidates`` pour proposer une colonne alternative."
        )
    elif reason == "wrong_table":
        lines.append(
            "  → Hint : l'utilisateur dit que la TABLE choisie est incorrecte. "
            "Examine ``top_candidates`` pour proposer une entité alternative."
        )
    elif reason == "wrong_period":
        lines.append(
            "  → Hint : la PÉRIODE est incorrecte. Vérifie la résolution temporelle "
            "(le filtre WHERE sur la colonne de date)."
        )
    elif reason == "too_many_rows":
        lines.append(
            "  → Hint : trop de lignes — probable cartésien ou filtre absent. "
            "Cf. ``cartesian_warning`` dans le tool_result précédent + "
            "``_last_sql_for_delta`` pour le ratio."
        )
    elif reason == "too_few_rows":
        lines.append(
            "  → Hint : pas assez de lignes — filtre trop strict ou JOIN INNER "
            "qui élimine. Cf. ``zero_rows_diagnostic`` (T16) si applicable."
        )
    elif reason == "wanted_other":
        lines.append(
            "  → Hint : l'utilisateur attendait autre chose. Demande-lui "
            "explicitement ce qu'il cherchait via ``ask_user_clarification``."
        )

    if previous_search_id is not None:
        lines.append("")
        lines.append(
            f"  → Référence : ``search_id={previous_search_id}`` est le résultat "
            "que l'utilisateur rejette."
        )

    lines.append("")
    lines.append(
        "Ne diagnostique PAS à l'aveugle — inspecte d'abord les artefacts "
        "existants. NE crée PAS de nouveau code. NE relance PAS la pipeline "
        "complète sauf si ``mutate_last_ir`` échoue."
    )

    return "\n".join(lines)
