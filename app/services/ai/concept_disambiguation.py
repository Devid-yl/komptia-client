"""Concept Disambiguation — détection programmatique des ambiguïtés métier
en amont de la génération SQL.

Task #98 — REFONTE-L3 (2026-05-22). Vision « ingénierie amont, pas guard
aval » : lever les ambiguïtés sémantiques AVANT que le LLM produise du
SQL faux silencieusement.

**Problème observé run #201** (rentabilité YoY SOFIGEC PAP) :
- Phase 3 a posé 3 questions auto-soumises VIDES à l'user :
  1. « production = prix de vente ou coût interne ? »
  2. « facturation = HT ou TTC ? »
  3. « écart facturation = HT ou TTC ? » (doublon sémantique de #2)
- Aucune réponse n'a atteint l'user (parallèle Phase 3 avec
  ``auto_submit=True``).
- Conséquence : Iris a généré un SQL sur des hypothèses arbitraires
  (chiffres faux silencieusement).

**Solution amont** : détecter ces ambiguïtés par inspection DDL au
runtime, AVANT toute génération SQL. Une **batch question synchrone et
bloquante** pose les 2-3 ambiguïtés détectées une seule fois, l'user
répond, le pipeline continue avec des choix tranchés.

**Caractéristiques clés** :
1. **Générique** — aucun pattern de colonne hardcodé par BDD. La
   détection se fait par inspection des colonnes du DDL réel : si un
   concept matche N>1 colonnes candidates, il est ambigu.
2. **Déduplication cross-concept** — si « facturation totale » et
   « écart facturation » dépendent tous deux du concept ambigu
   « facturation = HT|TTC », la Q n'est posée qu'une fois (clé =
   colonne candidate, pas concept user).
3. **Pas de persistance d'apprentissage** dans ce module — décision
   2026-05-22 (« pas de nouvelle source de doc BDD »). Le RAG unique
   ``training_data`` type DOC alimentera l'apprentissage cross-runs
   quand il sera rebranché (out-of-scope ici).
4. **Pas d'intégration pipeline dans cette première itération** — ce
   module fournit l'API. L'intégration ``phase_1_2_4_disambiguate``
   dans ``scripts/pipeline.py`` viendra dans une PR suivante.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CandidateColumn:
    """Une colonne candidate pour un concept ambigu."""

    table: str
    column: str
    # ``description`` est extrait du DDL ou inféré du nom de colonne.
    # Sert à formuler la question user de façon non-technique.
    description: str = ""

    def label(self) -> str:
        """Label compact pour l'UI : ``table.column``."""
        return f"{self.table}.{self.column}"


@dataclass
class Ambiguity:
    """Une ambiguïté détectée sur un concept user.

    Plusieurs colonnes du DDL matchent le même concept → il faut
    demander à l'user laquelle utiliser.
    """

    concept: str  # le terme tel qu'il apparaît dans la query user
    candidates: list[CandidateColumn] = field(default_factory=list)
    # ``hint`` est une phrase courte qui contextualise l'ambiguïté.
    # Ex: « plusieurs colonnes "facturation" trouvées — laquelle ? »
    hint: str = ""


# Tokenisation pour matcher concept user ↔ colonne DDL.
# Sépare sur séparateurs courants : whitespace, _, -, .,
# puis ignore les casse + accents.
_TOKEN_SPLIT_RE = re.compile(r"[\s_\-\.\,\(\)\[\]'’]+")


def _normalize_token(s: str) -> str:
    """Normalise pour comparaison case-insensitive et accent-insensitive."""
    s = (s or "").strip().lower()
    # Remplacement accents courants FR (générique, pas spécifique secteur)
    replacements = {
        "à": "a", "â": "a", "ä": "a",
        "é": "e", "è": "e", "ê": "e", "ë": "e",
        "î": "i", "ï": "i",
        "ô": "o", "ö": "o",
        "ù": "u", "û": "u", "ü": "u",
        "ç": "c",
    }
    for old, new in replacements.items():
        s = s.replace(old, new)
    return s


def _tokenize(s: str) -> set[str]:
    """Découpe un texte en tokens normalisés non-vides."""
    if not s:
        return set()
    normalized = _normalize_token(s)
    parts = _TOKEN_SPLIT_RE.split(normalized)
    return {p for p in parts if p}


def _split_camel_case(name: str) -> list[str]:
    """Découpe un identifiant camelCase/PascalCase en tokens.

    Ex: ``dosNomDossier`` → ``["dos", "Nom", "Dossier"]``
    Ex: ``lfaMontant`` → ``["lfa", "Montant"]``
    """
    if not name:
        return []
    # Insère un espace avant chaque majuscule (sauf début)
    spaced = re.sub(r"(?<!^)(?=[A-Z])", " ", name)
    return [p for p in spaced.split() if p]


def _column_tokens(
    table: str, column: str, description: str = ""
) -> tuple[set[str], set[str]]:
    """Retourne (column_signals, table_signals) — séparés pour scoring.

    Adversarial fix #C1 (2026-05-22) : avant ce split, les tokens de table
    étaient mélangés avec ceux de la colonne. Conséquence : toute colonne
    d'une table dont le nom matchait le concept (ex: ``Factures`` matche
    ``facturation``) devenait candidate, peu importe le nom de colonne.
    À l'échelle réelle (50+ col/table), pollution UX massive.

    Désormais :
    - ``column_signals`` = tokens du **nom de colonne** (split camelCase) +
      tokens de la **description** DDL. Signal FORT — suffit pour qualifier
      la colonne comme candidate.
    - ``table_signals`` = tokens du **nom de table**. Signal FAIBLE —
      utilisé pour boost de pertinence mais NE SUFFIT PAS seul.

    Pourquoi exiger un match column-or-description : éviter que des dizaines
    de colonnes triviales (IDs, dates, flags) d'une table sémantiquement
    matchante remontent comme candidates.

    Filtrage ``len >= 3`` conservé pour éliminer les préfixes SGBD courts
    type ``fac``, ``dos``, ``lfa``, ``grp``, ``mis`` (3 chars typique).
    """
    column_signals: set[str] = set()
    # Nom de colonne (split camelCase, important pour SGBD à convention
    # <prefix><Nom> comme Sage Coala — le préfixe est filtré, le suffixe
    # métier est gardé)
    for piece in _split_camel_case(column):
        column_signals.add(_normalize_token(piece))
    # Description / commentaire DDL si disponible — c'est souvent le
    # signal sémantique le plus fort (« montant HT de la ligne »).
    column_signals |= _tokenize(description)
    column_signals = {t for t in column_signals if len(t) >= 3}

    table_signals: set[str] = set()
    for piece in _split_camel_case(table):
        table_signals.add(_normalize_token(piece))
    table_signals = {t for t in table_signals if len(t) >= 3}

    return column_signals, table_signals


# Longueur minimale de préfixe partagé pour qu'un match concept↔colonne
# soit jugé pertinent en mode « préfixe » (variantes morphologiques).
# 4 chars filtre les coïncidences fortuites tout en couvrant les variantes
# courantes en français (« facture » ↔ « facturation », « collabo » ↔
# « collaborateur », « rentab » ↔ « rentabilité »).
_PREFIX_MATCH_MIN_LEN = 4

# Longueur minimale pour qu'un token soit considéré comme un acronyme
# métier (HT, TTC, TVA, BIC, CRM, SAS, IBAN, etc.). À 3 chars, on exige
# match EXACT (pas préfixe partagé) pour éviter le bruit type « par » ↔
# « parent ». Adversarial fix #C2 (2026-05-22) : sans ce mode acronyme,
# tous les concepts de 3 chars étaient filtrés à tort — y compris HT/TTC
# qui sont précisément le cas Q vide du run #201.
_ACRONYM_EXACT_MATCH_MIN_LEN = 3


def _tokens_match(query_tokens: set[str], column_tokens: set[str]) -> bool:
    """True si match concept↔colonne par préfixe partagé OU acronyme exact.

    Adversarial fix #C2 (2026-05-22) — 2 modes de match :

    **Mode A — préfixe partagé** (tokens longs, ≥4 chars) :
    - exact match : ``"montant" ↔ "montant"`` ✓
    - préfixe partagé : ``"facturation" ↔ "facture"`` (``factur``, 6 chars) ✓
    - couvre les variantes morphologiques FR

    **Mode B — acronyme exact** (tokens de 3 chars) :
    - ``"HT" ↔ "ht"`` (après normalize, 2 chars — non, filtré)
    - ``"TTC" ↔ "ttc"`` ✓ (match exact, 3 chars)
    - ``"TVA" ↔ "tva"`` ✓ (idem)
    - PAS de préfixe partagé pour les 3 chars (sinon « par » ↔ « parent » bruit)

    Tokens <3 chars (« HT », « an ») restent filtrés — trop courts pour
    discriminer génériquement.
    """
    if not query_tokens or not column_tokens:
        return False
    for qt in query_tokens:
        # Acronyme exact (3 chars)
        if len(qt) == _ACRONYM_EXACT_MATCH_MIN_LEN:
            if qt in column_tokens:
                return True
            continue  # pas de préfixe pour 3 chars (bruit)
        if len(qt) < _PREFIX_MATCH_MIN_LEN:
            continue
        for ct in column_tokens:
            # Acronyme côté colonne : match exact requis
            if len(ct) == _ACRONYM_EXACT_MATCH_MIN_LEN:
                if qt == ct:
                    return True
                continue
            if len(ct) < _PREFIX_MATCH_MIN_LEN:
                continue
            # Préfixe commun : tronquer le plus long au plus court et comparer
            shorter, longer = (qt, ct) if len(qt) <= len(ct) else (ct, qt)
            if longer.startswith(shorter):
                return True
            # Préfixe partagé même si aucun n'est strictement préfixe de
            # l'autre : ex ``"collaborer" ↔ "collabo"`` partagent ``collab``
            # (6 chars) sans que l'un ne commence par l'autre.
            common_len = 0
            for a, b in zip(qt, ct):
                if a == b:
                    common_len += 1
                else:
                    break
            if common_len >= _PREFIX_MATCH_MIN_LEN:
                return True
    return False


def detect_ambiguous_concepts(
    concepts: list[str],
    schema: dict[str, list[dict[str, Any]]],
    *,
    min_candidates_for_ambiguity: int = 2,
) -> list[Ambiguity]:
    """Détecte les concepts user qui matchent N>1 colonnes du DDL.

    Args:
        concepts : liste des concepts extraits par Phase 1.1 (ex:
            ``["facturation", "rentabilité", "millésime"]``).
        schema : dict ``{table_name: [{name, description?}, ...]}``.
            Compatible avec le format ``SchemaLoader.get_table_columns()``
            et avec une forme simplifiée ``{table: [{name: ...}]}``.
        min_candidates_for_ambiguity : seuil de déclenchement (défaut 2).
            Si le concept matche 0 ou 1 colonne, pas d'ambiguïté à lever
            (0 = à dériver par formule SQL, 1 = mapping direct).

    Returns:
        Liste des ``Ambiguity`` détectées, vide si aucun concept ambigu.
        Le caller est responsable de poser la batch question à l'user
        (pas d'effet de bord ici — fonction pure).

    Doctrine GÉNÉRICITÉ : pas de pattern de colonne hardcodé par
    secteur ou SGBD. La détection se fait uniquement sur la
    correspondance lexicale (tokens) entre concept user et colonnes
    réelles du DDL chargé. Si la BDD change (autre client, autre
    SGBD), les résultats s'adaptent automatiquement.
    """
    ambiguities: list[Ambiguity] = []

    if not concepts or not schema:
        return ambiguities

    # Pré-calcul : tokens de chaque colonne (évite re-tokenize en boucle).
    # Adversarial fix #C1 : on garde 2 sets séparés (column_signals fort,
    # table_signals faible) au lieu d'un mix unique.
    column_signals_index: dict[tuple[str, str], set[str]] = {}
    column_descriptions: dict[tuple[str, str], str] = {}
    for table_name, columns in schema.items():
        if not isinstance(columns, list):
            continue
        for col in columns:
            if not isinstance(col, dict):
                continue
            col_name = col.get("name") or col.get("column_name") or ""
            if not col_name:
                continue
            desc = col.get("description") or col.get("desc") or ""
            col_signals, _table_signals = _column_tokens(table_name, col_name, desc)
            # Note adversarial #C1 : on STOCKE ``col_signals`` seul (PAS
            # le table_signals). La condition de match est désormais
            # « concept matche le NOM ou la DESCRIPTION de la colonne » —
            # le nom de table seul ne suffit plus à qualifier la colonne.
            column_signals_index[(table_name, col_name)] = col_signals
            column_descriptions[(table_name, col_name)] = desc

    if not column_signals_index:
        return ambiguities

    for concept in concepts:
        concept_tokens = _tokenize(concept)
        if not concept_tokens:
            continue

        candidates: list[CandidateColumn] = []
        seen_columns: set[tuple[str, str]] = set()  # déduplication exacte
        for (table, col), col_signals in column_signals_index.items():
            # Match : préfixe partagé ≥4 chars OU acronyme exact ≥3 chars
            # entre concept tokens et **column signals** (nom colonne
            # ou description — PAS nom de table seul). Adversarial fix
            # #C1 : évite la pollution UX par les colonnes triviales
            # (IDs, dates, flags) d'une table dont le nom matche.
            if _tokens_match(concept_tokens, col_signals):
                key = (table, col)
                if key in seen_columns:
                    continue
                seen_columns.add(key)
                candidates.append(
                    CandidateColumn(
                        table=table,
                        column=col,
                        description=column_descriptions.get(key, ""),
                    )
                )

        if len(candidates) >= min_candidates_for_ambiguity:
            ambiguities.append(
                Ambiguity(
                    concept=concept,
                    candidates=candidates,
                    hint=_default_hint(concept, candidates),
                )
            )
        elif candidates:
            logger.debug(
                "concept_disambiguation: '%s' a 1 candidate unique (%s) — "
                "pas d'ambiguïté, mapping direct",
                concept,
                candidates[0].label(),
            )
        else:
            logger.debug(
                "concept_disambiguation: '%s' a 0 candidate dans le DDL — "
                "concept à dériver par formule SQL (probable)",
                concept,
            )

    # Déduplication cross-concept : si 2 concepts user ont le même
    # ensemble de candidates, fusionne en une seule ambiguïté (la Q sera
    # posée une seule fois).
    return _dedupe_cross_concept(ambiguities)


def _dedupe_cross_concept(ambiguities: list[Ambiguity]) -> list[Ambiguity]:
    """Fusionne les ambiguïtés ayant exactement le même set de candidates.

    Cas réel run #201 : « facturation totale » et « écart facturation »
    matchent toutes deux ``[lfaMontant, montantTTC]``. La question
    « HT ou TTC ? » n'a pas à être posée 2× — on garde un seul
    ``Ambiguity`` qui liste les 2 concepts user dans son ``hint``.
    """
    if len(ambiguities) <= 1:
        return ambiguities

    by_signature: dict[frozenset[tuple[str, str]], list[Ambiguity]] = {}
    for amb in ambiguities:
        sig = frozenset((c.table, c.column) for c in amb.candidates)
        by_signature.setdefault(sig, []).append(amb)

    merged: list[Ambiguity] = []
    for sig, group in by_signature.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            # Fusion : on garde le 1er, on agrège les noms de concepts
            # dans le hint pour que l'user comprenne que sa réponse
            # s'applique à plusieurs concepts.
            base = group[0]
            concepts_str = " / ".join(a.concept for a in group)
            merged_amb = Ambiguity(
                concept=concepts_str,
                candidates=base.candidates,
                hint=_default_hint(concepts_str, base.candidates),
            )
            merged.append(merged_amb)
            logger.debug(
                "concept_disambiguation: fusion cross-concept — '%s' "
                "partagent les mêmes candidates (%d colonnes)",
                concepts_str,
                len(base.candidates),
            )

    return merged


def _default_hint(concept: str, candidates: list[CandidateColumn]) -> str:
    """Formule par défaut pour le hint d'une ambiguïté."""
    n = len(candidates)
    return (
        f"Le concept « {concept} » correspond à {n} colonne(s) candidate(s) "
        f"dans la base : "
        + ", ".join(c.label() for c in candidates)
        + ". Laquelle voulez-vous utiliser ?"
    )


def format_disambiguation_batch_question(ambiguities: list[Ambiguity]) -> Optional[str]:
    """Formate les ambiguïtés en une batch question synchrone pour user.

    Retourne ``None`` si aucune ambiguïté (le caller ne pose pas de Q).
    Sinon, retourne un bloc texte structuré qui peut être envoyé via
    ``ask_user_clarification`` ou équivalent.

    Le format est volontairement minimaliste — pas de marquage UI
    spécifique, c'est le caller qui formate pour son canal (chat,
    overlay, batch dialog).
    """
    if not ambiguities:
        return None

    lines = [
        "Avant de générer le SQL, j'ai besoin que vous leviez "
        f"{len(ambiguities)} ambiguïté(s) métier :"
    ]
    for idx, amb in enumerate(ambiguities, start=1):
        lines.append(f"\n**{idx}. « {amb.concept} »** — {amb.hint}")
        for c in amb.candidates:
            desc_suffix = f" ({c.description})" if c.description else ""
            lines.append(f"   - `{c.label()}`{desc_suffix}")
    lines.append(
        "\nMerci de répondre en indiquant pour chaque ambiguïté la colonne "
        "à utiliser. Une fois levées, ces décisions s'appliquent à toute "
        "la suite de la conversation."
    )
    return "\n".join(lines)
