"""Helpers de redaction PII « best-effort » pour les sorties admin.

SSoT pour la redaction « légère » qui s'applique AVANT d'exposer du texte
utilisateur libre (question NL, SQL généré, commentaire feedback) dans une
surface admin — UI ou export CSV.

⚠️ Cette redaction est volontairement légère et générique. Elle NE remplace
PAS la pseudonymisation user-scoped via :mod:`app.services.anonymization.pseudonymizer`
(L2 — `/data-privacy`), qui nécessite un contexte user + des termes configurés
explicitement. Le but ici : bloquer les **fuites triviales** quand on ne peut
pas charger le pseudonymizer du user d'origine (cas typique de l'export CSV
admin, où l'admin n'est pas l'auteur des questions).

Axes Komptia confidentialité couverts (cumulatifs, pas remplaçants) :
- L2 (pseudonymisation /data-privacy) — non couvert ici, plug séparé.
- L3 (données décontextualisées) — partiellement : on masque les patterns PII
  les plus communs (emails, longs blocs numériques) sans toucher au contexte.
"""

from __future__ import annotations

import re
from typing import Final, Optional

# Limites par défaut — alignées avec les usages connus :
# - ``_redact_feedback_comment`` (stats_service) : 100 chars
# - Export CSV question NL : 500 chars (largement suffisant, requête médiane <200)
# - Export CSV SQL généré : 2000 chars (SELECT complexe possible)
DEFAULT_MAX_LEN: Final[int] = 100
EXPORT_QUESTION_MAX_LEN: Final[int] = 500
EXPORT_SQL_MAX_LEN: Final[int] = 2000

# #66 — marqueur de troncature ajouté quand ``truncate=True`` coupe réellement.
# Sans lui, l'admin qui lit le CSV ai_performance (ou le tooltip
# /admin/ai-performance) ne peut PAS distinguer un SQL/texte tronqué PAR
# L'EXPORT d'un SQL réellement incomplet. Ajouté APRÈS les ``max_len`` chars de
# contenu (signal de débordement, ~10 chars hors-budget).
_TRUNCATION_MARKER: Final[str] = "…[tronqué]"

# Bug 2026-05-26 (ADV-12 + ADV-15) : cap dur sur l'input AVANT le regex.
# Le pattern ``_LONG_NUMERIC_RE`` montre du backtracking modéré (167ms sur
# 10k chars d'alternance ``1-1-1-1...``) — pas catastrophique mais sur le
# path ``truncate=False`` (AT-C1 RAG storage), un input adversarial pourrait
# ralentir l'indexation. 50k chars = ~25 SQL queries d'un dump complet,
# bien au-delà de tout cas légitime (question NL ~200 chars, SQL ~2KB).
# Pre-cap = défense en profondeur même si la regex elle-même n'est pas
# une vraie ReDoS catastrophique.
#
# Naming : ``CHARS`` (pas BYTES). ``len(text)`` retourne le code point
# count, pas le byte count. Pour un input multibyte UTF-8 (emojis CJK),
# 1 char peut faire 4 bytes — donc 50k chars peut atteindre 200k bytes.
# C'est OK car la perf regex est PAR CARACTÈRE, pas par byte.
_REDACT_INPUT_MAX_CHARS: Final[int] = 50_000

# Email : pattern conservateur, accepte les caractères usuels RFC 5322 light.
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Long bloc numérique : 12+ chiffres consécutifs ou séparés par espace/tiret/point.
# Couvre : SIRET (14), IBAN (jusqu'à 34), tel international (~12-15), montants
# longs, numéros de compte. 12 = seuil tel international FR sans préfixe.
_LONG_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(r"\b(?:\d[\d \-.]*){12,}")


def redact_pii_best_effort(
    text: Optional[str],
    *,
    max_len: int = DEFAULT_MAX_LEN,
    truncate: bool = True,
) -> Optional[str]:
    """Redacte un texte user libre AVANT exposition admin OU indexation RAG.

    Politique :
    1. (optionnel) Tronque à ``max_len`` chars (en premier, pour limiter le coût
       regex). Utile pour les exports / surfaces UI où on veut un signal court.
    2. Masque les emails ``alice@x.fr`` → ``[email]``.
    3. Masque les longs blocs numériques (12+ chiffres, séparateurs autorisés)
       → ``[nombre]`` — couvre SIRET, IBAN, tels, montants longs.

    Args:
        text: Texte à redacter. ``None`` et vide pass-through (le caller
            sait quoi faire avec).
        max_len: Longueur max si ``truncate=True``. Doit être ``>= 10`` quand
            ``truncate=True`` (sinon la troncature détruit le signal sans utilité).
            Ignoré si ``truncate=False``.
        truncate: Si ``False``, ne tronque PAS — applique seulement les masques
            email/numéric. Utile pour le stockage RAG (training_store AT-C1) :
            on masque la PII mais on garde la longueur originale pour ne pas
            casser le matching recall-IDF.

    Returns:
        Texte redacté. ``None`` si entrée ``None``, vide si entrée vide.

    Raises:
        ValueError: si ``max_len < 10`` et ``truncate=True``.
    """
    if truncate and max_len < 10:
        raise ValueError(
            f"redact_pii_best_effort: max_len={max_len} trop petit (min 10). "
            "Une troncature trop agressive masque le signal sans utilité."
        )
    if not text:
        return text

    # Bug 2026-05-26 (ADV-12) : pre-cap défensif. _LONG_NUMERIC_RE a du
    # backtracking modéré sur input adversarial (alternance digit-separator).
    # Cap à 50KB borne le worst-case CPU. Au-delà = input pathologique
    # ou bug appelant — on tronque silencieusement (le regex sur la
    # première partie suffit à attraper la PII typique).
    if len(text) > _REDACT_INPUT_MAX_CHARS:
        text = text[:_REDACT_INPUT_MAX_CHARS]

    # Bug 2026-05-26 (ADV-1 CRITIQUE — adversarial review) : avant ce fix,
    # on tronquait AVANT le masquage regex. Conséquence : un email à
    # position 550 dans un texte de 600 chars avec ``max_len=500`` était
    # COUPÉ par la troncature → le regex ne matchait plus → fuite PII
    # silencieuse dans l'export CSV (AI-2) et le RAG (AT-C1).
    # Fix : masquer D'ABORD (sur le texte intégral) puis tronquer si
    # demandé. Coût CPU négligeable — les regex sont stupides face à un
    # texte de quelques KB.
    #
    # Bug 2026-05-26 (ADV-13 CRITIQUE) : ``_EMAIL_RE`` était vulnérable à
    # ReDoS catastrophique sur input avec beaucoup de ``-``/``.`` SANS ``@``
    # (50k chars de ``1-1-1...`` = 4.5s, 200k = 70s+). Le pattern
    # ``[A-Za-z0-9._%+-]+`` matchait greedy les ``-`` puis backtrackait
    # exponentiellement cherchant un ``@`` absent. Fix : short-circuit
    # via le check Python ``'@' in text`` AVANT le regex. ``in`` est
    # O(n) linear — pas de ReDoS possible.
    if "@" in text:
        out = _EMAIL_RE.sub("[email]", text)
    else:
        out = text
    out = _LONG_NUMERIC_RE.sub("[nombre]", out)
    if truncate and len(out) > max_len:
        # #66 — coupe RÉELLE : on signale. Le marqueur est AJOUTÉ APRÈS les
        # ``max_len`` caractères de CONTENU (et non dedans) : le contrat
        # « max_len chars de contenu » reste vrai, le marqueur est un pur signal
        # de débordement (~10 chars hors-budget, inoffensif pour une cellule CSV
        # ou un tooltip). Ajouté APRÈS le masquage regex → jamais re-scanné.
        out = out[:max_len] + _TRUNCATION_MARKER
    elif truncate:
        out = out[:max_len]
    return out


__all__ = [
    "DEFAULT_MAX_LEN",
    "EXPORT_QUESTION_MAX_LEN",
    "EXPORT_SQL_MAX_LEN",
    "redact_pii_best_effort",
]
