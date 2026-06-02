"""Mode "exploration ouverte" — détection de question vague + axes proposés.

Quand l'utilisateur pose une question trop large (« montre-moi les données »,
« infos », « stats »), lancer la pipeline NL→SQL complète est inutile :
elle échoue Phase 1.1+1.2 (concepts vides) ou produit un SQL trop générique.

Ce module fournit :

- ``is_query_vague(query, ...)`` : détection 100 % programmatique (0 appel
  LLM) qui combine signaux structurels (longueur, lemmes vagues, lemmes
  concrets, identifiants ALL CAPS, années, noms de tables du schéma
  fourni) et signaux pipeline (``concepts_v2`` vide / single abstract,
  ``coverage.covered_below_threshold``).
- ``propose_exploration_axes(query, ...)`` : retourne 3-6 axes neutres
  (top par mesure, activité récente, totaux par période, anomalies,
  répartition par dimension, comparaisons). **Aucun nom de table ou
  concept métier n'est hardcodé** — les axes sont des patterns d'analyse
  applicables à toute BDD (règle GÉNÉRICITÉ Komptia).
- ``format_exploration_response(...)`` : payload final pour le tool
  ``start_exploration_mode``. Inclut une ``instruction_for_assistant``
  pour guider l'agent IA dans sa reformulation côté utilisateur.

Le système orchestre l'agent : il décide programmatiquement si la question
est vague, puis lui donne une micro-tâche claire (« reformule à l'user
en utilisant ces axes »). L'agent n'a aucune ambiguïté à interpréter.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Constantes — lemmes multilingues (FR + EN)
# ---------------------------------------------------------------------------

# Mots "vagues" : verbes d'affichage génériques + objets abstraits.
# Une query composée UNIQUEMENT de ces mots est qualifiée vague.
_VAGUE_LEMMAS_FR = frozenset(
    {
        "donne",
        "donnez",
        "donner",
        "montre",
        "montrez",
        "montrer",
        "affiche",
        "affichez",
        "afficher",
        "voir",
        "regarde",
        "regardez",
        "info",
        "infos",
        "information",
        "informations",
        "donnees",
        "donnee",
        "stats",
        "statistique",
        "statistiques",
        "tout",
        "tous",
        "toutes",
        "recap",
        "recapitulatif",
        "details",
        "detail",
        "resume",
        "synthese",
        "truc",
        "trucs",
        "chose",
        "choses",
        "moi",
        "les",
        "le",
        "la",
        "des",
        "du",
        "de",
        "un",
        "une",
        "mes",
        "ma",
        "mon",
        # Pronoms interrogatifs sans intent agrégatif — signalent une
        # question ouverte. Restent compatibles avec « combien »/« qui »
        # car ces lemmes vivent dans _CONCRETE_INTENT_LEMMAS (la priorité
        # va au concret quand les deux sont présents).
        "quoi",
        "que",
        "quel",
        "quelle",
        "quels",
        "quelles",
    }
)
_VAGUE_LEMMAS_EN = frozenset(
    {
        "show",
        "display",
        "view",
        "see",
        "give",
        "info",
        "infos",
        "information",
        "data",
        "stats",
        "statistics",
        "all",
        "everything",
        "summary",
        "recap",
        "details",
        "detail",
        "stuff",
        "thing",
        "things",
        "me",
        "the",
        "a",
        "an",
        "my",
        "what",
        "which",
        "whatever",
    }
)
_VAGUE_LEMMAS = _VAGUE_LEMMAS_FR | _VAGUE_LEMMAS_EN

# Lemmes "concrets" : verbes d'agrégation / opérations / comparateurs
# qui dénotent une intention analytique précise.
_CONCRETE_INTENT_LEMMAS_FR = frozenset(
    {
        "combien",
        # « compte » / « comptes » / « comptez » sont AMBIGUS en FR
        # (verbe « compter » vs substantif « compte »). « tous les comptes »
        # doit rester vague — on ne traite que les formes non ambiguës
        # comme « compter » (infinitif clair).
        "compter",
        "total",
        "totale",
        "totales",
        "totaux",
        "somme",
        "sommes",
        "moyenne",
        "moyennes",
        "max",
        "maximum",
        "min",
        "minimum",
        "top",
        "premier",
        "premiers",
        "premiere",
        "dernier",
        "derniers",
        "derniere",
        "classer",
        "classement",
        "comparer",
        "comparez",
        "comparaison",
        "depuis",
        "entre",
        "superieur",
        "inferieur",
        "egal",
        "ratio",
        "pourcentage",
        "evolution",
        "tendance",
        "trier",
        "grouper",
        "groupe",
        "filtre",
        "filtrer",
        "joindre",
        "agreger",
    }
)
_CONCRETE_INTENT_LEMMAS_EN = frozenset(
    {
        "count",
        "many",
        "much",
        "total",
        "totals",
        "sum",
        "average",
        "mean",
        "max",
        "min",
        "top",
        "first",
        "last",
        "rank",
        "ranking",
        "compare",
        "since",
        "between",
        "greater",
        "less",
        "ratio",
        "percentage",
        "trend",
        "evolution",
        "sort",
        "group",
        "filter",
        "join",
        "aggregate",
    }
)
_CONCRETE_INTENT_LEMMAS = _CONCRETE_INTENT_LEMMAS_FR | _CONCRETE_INTENT_LEMMAS_EN

# Mots-clés SQL : leur présence indique une query SQL directe (non vague,
# le user a déjà fait le travail d'analyse — appeler la pipeline ne fait
# pas sens).
_SQL_KEYWORDS = frozenset(
    {
        "select",
        "from",
        "where",
        "join",
        "inner",
        "outer",
        "left",
        "right",
        "group",
        "order",
        "having",
        "insert",
        "update",
        "delete",
        "with",
        "union",
        "case",
        "when",
        "then",
        "else",
    }
)

# Seuils — ces valeurs sont génériques (pas spécifiques à une BDD) et
# choisies pour minimiser les faux négatifs sur queries courtes vagues.
_MIN_QUERY_LENGTH = 3
_MAX_QUERY_LENGTH = 5000  # cohérent avec run_pipeline qui coupe à 5000

# Templates d'axes — 100 % neutres, aucun nom de table / colonne / métier.
# Les axes représentent des **patterns d'analyse** applicables à toute BDD.
# L'agent IA reformulera contextuellement quand il les présente à l'user.
#
# Immutables (tuple de MappingProxyType) : empêche un caller (test ou
# autre module) de muter un template par accident et de corrompre tous
# les appels suivants (Tornado tourne single-process async).
_GENERIC_AXES_TEMPLATES: tuple[MappingProxyType, ...] = tuple(
    MappingProxyType(d)
    for d in (
        {
            "kind": "top_by_metric",
            "label": "Top entités par mesure principale",
            "description": (
                "Voir les principales entrées d'une table classées par leur "
                "mesure dominante (somme, max, count)."
            ),
            "hint": (
                "Pattern : SELECT TOP N, ORDER BY <mesure> DESC sur la table "
                "principale identifiée dans le schéma."
            ),
        },
        {
            "kind": "recent_activity",
            "label": "Activité récente",
            "description": (
                "Voir les entrées récentes (jour, semaine, mois courant) dans "
                "les tables transactionnelles."
            ),
            "hint": ("Pattern : WHERE date_colonne >= DATEADD(month, -1, GETDATE())."),
        },
        {
            "kind": "totals_by_period",
            "label": "Totaux par période",
            "description": (
                "Agréger les mesures par période (jour, mois, trimestre, année) "
                "pour visualiser l'évolution."
            ),
            "hint": ("Pattern : GROUP BY YEAR(date_col), MONTH(date_col), " "SUM(<mesure>)."),
        },
        {
            "kind": "anomalies_outliers",
            "label": "Anomalies ou valeurs aberrantes",
            "description": (
                "Détecter les valeurs hors normes : montants anormalement élevés, "
                "doublons, lignes orphelines, NULL inattendus."
            ),
            "hint": (
                "Pattern : WHERE <mesure> > (SELECT 3 * AVG(<mesure>) FROM ...) "
                "ou COUNT(*) > 1 sur clé naturelle."
            ),
        },
        {
            "kind": "distribution_by_dimension",
            "label": "Répartition par dimension",
            "description": (
                "Voir la répartition d'une mesure ventilée par une dimension "
                "(catégorie, statut, type)."
            ),
            "hint": (
                "Pattern : SELECT <dimension>, SUM(<mesure>), COUNT(*) "
                "GROUP BY <dimension> ORDER BY 2 DESC."
            ),
        },
        {
            "kind": "comparisons",
            "label": "Comparaisons",
            "description": (
                "Comparer entre périodes (année N vs N-1, mois en cours vs mois "
                "précédent) ou entre entités."
            ),
            "hint": (
                "Pattern : deux sous-requêtes WHERE périodes différentes, ou "
                "self-join sur la table avec décalage temporel."
            ),
        },
    )
)

# Single source of truth pour le nombre max d'axes proposables.
# Le handler ``_handle_start_exploration_mode`` lit cette constante au
# lieu d'un littéral magique pour rester aligné avec le registre.
MAX_AXES = len(_GENERIC_AXES_TEMPLATES)
MIN_AXES = 3


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VagueDetection:
    """Résultat structuré de la détection de question vague."""

    is_vague: bool
    reason: str
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExplorationAxis:
    """Un axe d'exploration proposé à l'utilisateur.

    ``suggested_tables`` contient les premières tables du schéma fourni
    (max 3) — sert d'exemples contextuels à l'agent IA. Le label et la
    description restent neutres ; c'est l'agent qui contextualisera.
    """

    kind: str
    label: str
    description: str
    hint: str
    suggested_tables: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Helpers internes
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9_]+", re.IGNORECASE)
_YEAR_RE = re.compile(r"\b(?:19|20|21)\d{2}\b")
_UPPERCASE_ID_RE = re.compile(r"\b[A-Z][A-Z0-9_]{2,}\b")


def _normalize(text: str) -> str:
    """Lowercase + strip accents pour comparer les lemmes de manière stable."""
    if not text:
        return ""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in nfkd if not unicodedata.combining(c))


def _tokens(text: str) -> list[str]:
    """Tokenize en mots minuscules sans accents."""
    norm = _normalize(text)
    return _TOKEN_RE.findall(norm)


def _has_sql_syntax(text: str) -> bool:
    """``True`` si la query contient des mots-clés SQL (SQL direct)."""
    if not text:
        return False
    tokens = set(_tokens(text))
    return bool(tokens & _SQL_KEYWORDS)


def _has_year(text: str) -> bool:
    return bool(_YEAR_RE.search(text or ""))


def _has_uppercase_identifier(text: str) -> bool:
    """``True`` si la query contient au moins un identifier ALLCAPS (≥ 3 chars).

    Filtre les acronymes courants non-discriminants (SQL, JOIN, etc.).
    """
    if not text:
        return False
    matches = _UPPERCASE_ID_RE.findall(text)
    # Filtre les acronymes SQL communs qui pourraient passer
    common = {
        "SQL",
        "SELECT",
        "FROM",
        "WHERE",
        "JOIN",
        "GROUP",
        "ORDER",
        "AND",
        "OR",
        "NOT",
        "TOP",
        "ALL",
        "ANY",
        "NULL",
    }
    return any(m not in common for m in matches)


def _has_known_schema_table(text: str, schema_tables: Iterable[str] | None) -> bool:
    """``True`` si la query mentionne un nom de table du schéma fourni.

    Comparaison case/accent-insensitive sur les tokens.
    """
    if not schema_tables or not text:
        return False
    tokens = set(_tokens(text))
    for table in schema_tables:
        norm = _normalize(str(table))
        if norm in tokens:
            return True
        # Match aussi les noms de tables découpés par _
        for sub in norm.split("_"):
            if sub and len(sub) >= 3 and sub in tokens:
                return True
    return False


def _count_lemma_hits(tokens: list[str], lemma_set: frozenset[str]) -> int:
    return sum(1 for tok in tokens if tok in lemma_set)


# ---------------------------------------------------------------------------
# API publique — détection
# ---------------------------------------------------------------------------


def is_query_vague(
    query: str | None,
    *,
    concepts_v2: list[dict] | None = None,
    coverage: dict[str, Any] | None = None,
    schema_tables: Iterable[str] | None = None,
) -> VagueDetection:
    """Détecte si une question utilisateur est trop vague pour générer un SQL.

    Détection 100 % programmatique :
    - Cas immédiats : ``None``, vide, whitespace, trop courte → vague
    - SQL direct (mots-clés SQL) → non vague
    - Signaux concrets (année, identifier ALLCAPS, table du schéma, lemme
      concret) → tend vers non vague
    - Si ``concepts_v2`` fourni vide ou single abstract → boost vague
    - Si ``coverage.covered_below_threshold`` True → boost vague
    - Tous les tokens dans le set vague → vague
    - Query courte (≤ 3 tokens) + vague + aucun signal concret → vague

    Cette fonction est PURE (pas d'I/O, pas de LLM, déterministe).

    Args:
        query: question utilisateur en langage naturel
        concepts_v2: optionnel — sortie de la Phase 1.1 (liste de concepts
            structurés). Vide ou single mot abstrait = signal vague.
        coverage: optionnel — sortie de la Phase 1.6 coverage check.
            Champ ``covered_below_threshold`` à True = signal vague.
        schema_tables: optionnel — itérable des noms de tables du schéma
            BDD connecté. Permet d'identifier les références concrètes.

    Returns:
        ``VagueDetection`` avec ``is_vague``, ``reason`` (FR) et ``signals``
        (tuple de chaînes pour debug).
    """
    if query is None:
        return VagueDetection(True, "query est None", ("none_query",))

    cleaned = query.strip()
    if not cleaned:
        return VagueDetection(True, "query vide", ("empty_query",))

    if len(cleaned) < _MIN_QUERY_LENGTH:
        return VagueDetection(
            True,
            f"query trop courte ({len(cleaned)} char)",
            ("too_short",),
        )

    if len(cleaned) > _MAX_QUERY_LENGTH:
        # Trop longue n'est pas vague : on laisse passer (la pipeline coupe).
        return VagueDetection(
            False,
            f"query > {_MAX_QUERY_LENGTH} chars (hors scope détection)",
            ("too_long",),
        )

    # 1. SQL direct = pas vague
    if _has_sql_syntax(cleaned):
        return VagueDetection(False, "mots-clés SQL détectés", ("sql_direct",))

    signals: list[str] = []

    # 2. Signaux concrets
    has_year = _has_year(cleaned)
    has_ucid = _has_uppercase_identifier(cleaned)
    has_schema_table = _has_known_schema_table(cleaned, schema_tables)

    if has_year:
        signals.append("contains_year")
    if has_ucid:
        signals.append("contains_uppercase_id")
    if has_schema_table:
        signals.append("contains_schema_table")

    tokens = _tokens(cleaned)
    n_vague = _count_lemma_hits(tokens, _VAGUE_LEMMAS)
    n_concrete = _count_lemma_hits(tokens, _CONCRETE_INTENT_LEMMAS)

    if n_concrete:
        signals.append(f"concrete_lemma_count={n_concrete}")
    if n_vague:
        signals.append(f"vague_lemma_count={n_vague}")

    # 3. Signal concepts_v2 (Phase 1.1) — défense contre type incorrect
    if concepts_v2 is not None and isinstance(concepts_v2, list):
        if len(concepts_v2) == 0:
            signals.append("concepts_v2_empty")
        elif len(concepts_v2) == 1:
            raw_first = concepts_v2[0]
            first = raw_first if isinstance(raw_first, dict) else {}
            raw_name = first.get("name")
            name = raw_name.strip().lower() if isinstance(raw_name, str) else ""
            if name and _normalize(name) in _VAGUE_LEMMAS:
                signals.append("concepts_v2_single_abstract")

    # 4. Signal coverage (Phase 1.6)
    if coverage is not None and isinstance(coverage, dict):
        if coverage.get("covered_below_threshold") is True:
            signals.append("coverage_below_threshold")

    # Note : ``has_schema_table`` SEUL ne compte pas comme signal concret —
    # une query « tous les comptes » (où COMPTES existe dans le schéma)
    # doit rester vague tant qu'aucun lemme concret (intent agrégatif),
    # year ou identifier ALL-CAPS ne l'accompagne. Sinon le tool est
    # bypassé silencieusement sur le cas d'usage cible.
    has_concrete_signal = has_year or has_ucid or n_concrete >= 1
    if has_schema_table and not (n_concrete >= 1 or has_year or has_ucid):
        signals.append("schema_table_without_intent")

    # === Décision finale ===

    # Tous les tokens dans le set vague = forcément vague
    if tokens and all(tok in _VAGUE_LEMMAS for tok in tokens):
        return VagueDetection(
            True,
            "tous les mots sont des termes abstraits",
            tuple(signals + ["all_tokens_vague"]),
        )

    # Signal concepts_v2 explicite, sans contrepartie concrète
    if (
        "concepts_v2_empty" in signals or "concepts_v2_single_abstract" in signals
    ) and not has_concrete_signal:
        return VagueDetection(
            True,
            "concepts_v2 indique vague et aucun signal concret",
            tuple(signals),
        )

    # Coverage Phase 1.6 sous seuil, sans contrepartie concrète
    if "coverage_below_threshold" in signals and not has_concrete_signal:
        return VagueDetection(
            True,
            "coverage Phase 1.6 sous le seuil et aucun signal concret",
            tuple(signals),
        )

    # Query très courte (≤ 3 tokens), au moins un vague, aucun concret
    if len(tokens) <= 3 and n_vague >= 1 and not has_concrete_signal:
        return VagueDetection(
            True,
            f"query courte ({len(tokens)} tokens), surtout abstrait",
            tuple(signals),
        )

    return VagueDetection(False, "signaux concrets suffisants", tuple(signals))


# ---------------------------------------------------------------------------
# API publique — proposition d'axes
# ---------------------------------------------------------------------------


def propose_exploration_axes(
    query: str,
    *,
    schema_tables: Iterable[str] | None = None,
    top_n: int = 5,
) -> list[ExplorationAxis]:
    """Propose 3-6 axes d'exploration neutres face à une question vague.

    Aucun nom de table / colonne n'est hardcodé : les axes sont des
    PATTERNS d'analyse (top par mesure, agrégation par période, anomalies,
    etc.) applicables à n'importe quelle BDD source.

    Si ``schema_tables`` est fourni, on attache jusqu'à 3 noms de tables
    en ``suggested_tables`` (purement informatif, pas un filtrage métier).

    Args:
        query: question utilisateur (sert juste de contexte d'appel)
        schema_tables: optionnel — itérable des noms de tables disponibles
        top_n: nombre d'axes à retourner (clampé entre 3 et le nombre de
            templates disponibles, par défaut 6)

    Returns:
        Liste de ``ExplorationAxis``. Toujours ≥ 3 sauf si la liste de
        templates a été tronquée (cas théorique : sécurité).
    """
    try:
        n = int(top_n)
    except (TypeError, ValueError):
        n = 5
    n = max(3, min(n, len(_GENERIC_AXES_TEMPLATES)))

    tables_list: list[str] = []
    if schema_tables:
        tables_list = [str(t) for t in schema_tables if t]
    suggested = tuple(tables_list[:3])

    axes: list[ExplorationAxis] = []
    for tmpl in _GENERIC_AXES_TEMPLATES[:n]:
        axes.append(
            ExplorationAxis(
                kind=tmpl["kind"],
                label=tmpl["label"],
                description=tmpl["description"],
                hint=tmpl["hint"],
                suggested_tables=suggested,
            )
        )
    return axes


# ---------------------------------------------------------------------------
# API publique — format payload
# ---------------------------------------------------------------------------


# Instructions stables pour le LLM agent.
# Aucun markup Markdown (cross-provider safe : certains LLMs rendent
# ** ** ou les backticks littéralement). Aucune suggestion de bypass
# de la pipeline (anti defense-in-depth) : on aiguille toujours vers
# run_pipeline qui contient les couches de validation.
_INSTRUCTION_VAGUE = (
    "La question utilisateur est trop large pour générer un SQL utile. "
    "Présente à l'utilisateur les axes d'exploration ci-dessous en langage "
    "clair (3 à 5 propositions concrètes). Demande-lui d'en choisir une ou "
    "de préciser autrement. Une fois sa réponse reçue, appelle run_pipeline "
    "avec la nouvelle formulation. NE lance PAS la pipeline maintenant."
)

_INSTRUCTION_NOT_VAGUE = (
    "La question semble suffisamment concrète. Appelle run_pipeline avec "
    "la question d'origine pour validation et génération SQL."
)

# Flags structurés exposés pour les callers (tests, agents). Les chaînes
# ci-dessus sont du wording UI ; les flags ci-dessous sont l'API stable
# que les tests doivent vérifier (anti-coupling à l'i18n).
ACTION_PRESENT_AXES = "present_axes"
ACTION_RUN_PIPELINE = "run_pipeline"


def format_exploration_response(
    query: str,
    detection: VagueDetection,
    axes: list[ExplorationAxis],
) -> dict[str, Any]:
    """Format unifié pour le retour du tool ``start_exploration_mode``.

    Sérialise les dataclasses en dicts JSON-safe pour passage au LLM.
    Inclut un flag ``action`` structuré que les tests peuvent asserter
    sans coupling à la chaîne i18n ``instruction_for_assistant``.
    """
    axes_payload = [
        {
            "kind": ax.kind,
            "label": ax.label,
            "description": ax.description,
            "hint": ax.hint,
            "suggested_tables": list(ax.suggested_tables),
        }
        for ax in axes
    ]
    return {
        "is_vague": detection.is_vague,
        "reason": detection.reason,
        "signals": list(detection.signals),
        "axes": axes_payload,
        "original_query": query,
        "action": (ACTION_PRESENT_AXES if detection.is_vague else ACTION_RUN_PIPELINE),
        "instruction_for_assistant": (
            _INSTRUCTION_VAGUE if detection.is_vague else _INSTRUCTION_NOT_VAGUE
        ),
    }


__all__ = [
    "ACTION_PRESENT_AXES",
    "ACTION_RUN_PIPELINE",
    "ExplorationAxis",
    "MAX_AXES",
    "MIN_AXES",
    "VagueDetection",
    "format_exploration_response",
    "is_query_vague",
    "propose_exploration_axes",
]
