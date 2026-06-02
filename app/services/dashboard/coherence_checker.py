"""Vérificateur de cohérence pour un dashboard multi-widgets (T17).

Quand l'utilisateur compose un dashboard avec plusieurs widgets, certaines
incohérences silencieuses peuvent fausser la lecture :

- Deux widgets censés représenter la même période la filtrent en réalité
  différemment (« CA 2024 » vs « CA 2023 » côte à côte sans titre clair).
- Deux widgets filtrent la même entité métier (région, type, statut…) sur
  des valeurs différentes — le user croit voir une vue cohérente alors
  qu'il regarde deux scopes disjoints.
- Le même agrégat (``SUM(montant)``) apparaît dans plusieurs widgets avec
  des scopes de filtre différents — le total n'est pas comparable d'un
  widget à l'autre.

Ce module **détecte ces patterns** et émet des warnings structurés. Il ne
bloque rien — la décision finale revient au user. C'est l'invariant T17
qui « renforce T23 » (mode exploration ouverte) : le système se rend compte
qu'un dashboard composé peut être trompeur même quand chaque widget est
juste pris isolément.

Conformément à la règle GÉNÉRICITÉ Komptia : aucun nom de table, colonne,
secteur ou logiciel source n'est hardcodé. Le checker est agnostique :
il opère sur la structure du SQL extrait via ``filter_extractor``
(``sqlglot`` parser, dialecte ``tsql`` par défaut) et compare colonne-par-colonne.

Conformément au principe « code orchestre le LLM » : ce module est 100 %
programmatique, aucun appel LLM. Les heuristiques ``date-like`` se basent
sur le format de la valeur (ISO 8601, année 4 chiffres, fonctions de date
T-SQL), pas sur le nom de la colonne.

API publique
============

- :func:`check_dashboard_coherence` — entrée principale, fonction pure
- :class:`CoherenceWarning` — un warning structuré (frozen dataclass)
- :class:`CoherenceReport` — le rapport agrégé (frozen dataclass)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

try:
    import sqlglot
    from sqlglot import exp as sqlglot_exp

    _SQLGLOT_AVAILABLE = True
except ImportError:  # pragma: no cover - sqlglot est une dep obligatoire
    _SQLGLOT_AVAILABLE = False

from app.services.ai.filter_extractor import (
    FilterPredicate,
    extract_filters_from_sql,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

#: Kinds de warning supportés — frozen pour détecter les typos côté tests.
VALID_WARNING_KINDS = frozenset(
    {
        "filter_mismatch",
        "aggregate_scope_mismatch",
        "metric_period_mismatch",
        "unparseable_widget",
    }
)

#: Sévérités utilisées. ``info`` = signal utile, ``warning`` = action recommandée.
VALID_SEVERITIES = frozenset({"info", "warning"})

#: Cap dur sur le nombre de widgets analysés en pairwise. Au-delà, on garde
#: les ``_MAX_WIDGETS_FOR_COHERENCE`` premiers (ordre input) et on émet une
#: note dans le report. Le frontend dashboard limite déjà autour de 50 widgets.
_MAX_WIDGETS_FOR_COHERENCE = 100

#: Cap dur sur la longueur d'un SQL widget pris en compte. Au-delà, le
#: widget est marqué « unparseable » sans tentative de parse — évite que
#: ``sqlglot.parse_one`` soit appelé sur un payload pathologique (DoS CPU,
#: car le parser est synchrone et blocke la loop event Tornado).
#: 100 KiB suffit pour un SELECT complexe à 50 colonnes + CTE.
_MAX_SQL_LEN_FOR_COHERENCE = 100 * 1024

#: Fonctions d'agrégation reconnues — base canonique pour comparer les
#: scopes. Les fonctions étendues (STDDEV, VAR…) sont absentes intentionnellement
#: car non critiques pour la cohérence "SUM(CA) doit être comparable".
_AGGREGATE_FN_NAMES = frozenset({"SUM", "AVG", "COUNT", "MIN", "MAX"})

#: Patterns pour détecter une valeur "date-like" (ISO 8601, année, FR DD/MM/YYYY).
#: Utilisé UNIQUEMENT pour classer un message FR ("période" vs "filtre entité"),
#: jamais pour décider si deux filtres sont incohérents — la décision repose
#: sur la valeur exacte du prédicat.
_DATE_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\d{4}-\d{1,2}-\d{1,2}"),  # ISO 8601 YYYY-MM-DD
    re.compile(r"^\d{1,2}/\d{1,2}/\d{4}"),  # FR DD/MM/YYYY ou US MM/DD/YYYY
    re.compile(r"^(19|20)\d{2}$"),  # Année 4 chiffres 1900-2099
)

#: Fonctions T-SQL retournant une date (relatives ou statiques). Quand la
#: valeur ou la colonne d'un prédicat contient un de ces tokens, on classe
#: le filtre comme « période ».
_DATE_FUNCTION_TOKENS = frozenset(
    {
        "GETDATE",
        "GETUTCDATE",
        "SYSDATETIME",
        "DATEADD",
        "DATEDIFF",
        "CURRENT_TIMESTAMP",
        "NOW",
        "TODAY",
        "DATE",
        "YEAR",
        "MONTH",
        "DAY",
        "EXTRACT",
    }
)


# ---------------------------------------------------------------------------
# Dataclasses publiques
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoherenceWarning:
    """Un warning structuré émis par le checker.

    Frozen pour empêcher la mutation après création — un caller qui voudrait
    « patcher » une sévérité doit construire un nouveau warning.
    """

    kind: str  # ∈ VALID_WARNING_KINDS
    severity: str  # ∈ VALID_SEVERITIES
    message: str  # FR, actionnable
    affected_widget_ids: tuple[int, ...]
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "affected_widget_ids": list(self.affected_widget_ids),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class CoherenceReport:
    """Résultat agrégé du checker.

    ``widgets_analyzed`` compte les widgets effectivement analysés (≤ input
    si on a appliqué le cap). ``widgets_unparseable`` compte ceux dont le
    SQL n'a pas pu être parsé — fail-open, ils sortent silencieusement
    du périmètre des autres checks (avec un warning ``unparseable_widget``).
    """

    warnings: tuple[CoherenceWarning, ...]
    widgets_analyzed: int
    widgets_unparseable: int = 0
    widgets_capped: int = 0

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    def warnings_by_kind(self, kind: str) -> tuple[CoherenceWarning, ...]:
        return tuple(w for w in self.warnings if w.kind == kind)

    def to_dict(self) -> dict[str, Any]:
        return {
            "warnings": [w.to_dict() for w in self.warnings],
            "widgets_analyzed": self.widgets_analyzed,
            "widgets_unparseable": self.widgets_unparseable,
            "widgets_capped": self.widgets_capped,
            "has_warnings": self.has_warnings,
        }


# ---------------------------------------------------------------------------
# API publique
# ---------------------------------------------------------------------------


def check_dashboard_coherence(
    widgets: list[dict[str, Any]],
    *,
    dialect: str = "tsql",
) -> CoherenceReport:
    """Calcule les diagnostics de cohérence d'un dashboard.

    Fonction pure : pas d'I/O, pas de LLM, pas de dépendance à un schéma
    BDD particulier. Tolérante aux entrées malformées (fail-open).

    Args:
        widgets: liste de ``DashboardWidget.to_dict()``. Doit contenir au
            moins les clés ``id``, ``data_source_type``, ``data_source_config``.
            Une entrée non-dict est ignorée silencieusement (logged).
        dialect: dialecte SQL pour ``sqlglot`` (défaut ``tsql``).

    Returns:
        :class:`CoherenceReport` — toujours retourné (jamais d'exception).
        Si ``widgets`` est vide ou ne contient qu'un widget, le rapport
        n'a pas de warning (on a besoin d'au moins 2 widgets comparables).
    """
    if not isinstance(widgets, list):
        logger.warning(
            "check_dashboard_coherence: widgets non-list type=%s",
            type(widgets).__name__,
        )
        return CoherenceReport(warnings=(), widgets_analyzed=0)

    # Hard cap. Au-delà : on garde le préfixe input pour rester déterministe
    # (l'utilisateur peut réordonner les widgets pour cibler ce qui l'intéresse).
    original_len = len(widgets)
    capped = 0
    if original_len > _MAX_WIDGETS_FOR_COHERENCE:
        widgets = widgets[:_MAX_WIDGETS_FOR_COHERENCE]
        capped = original_len - _MAX_WIDGETS_FOR_COHERENCE

    sql_widgets, metric_widgets, unparseable_ids = _classify_widgets(widgets, dialect=dialect)

    warnings: list[CoherenceWarning] = []

    # Unparseable widgets — émis EN PREMIER pour que le frontend puisse les
    # surfacer même quand aucun autre check ne déclenche.
    for wid in unparseable_ids:
        warnings.append(
            CoherenceWarning(
                kind="unparseable_widget",
                severity="info",
                message=(
                    "La requête SQL du widget n'a pas pu être analysée. "
                    "La cohérence ne peut pas être vérifiée pour ce widget."
                ),
                affected_widget_ids=(wid,),
                details={"reason": "sql_parse_failed"},
            )
        )

    if len(sql_widgets) >= 2:
        warnings.extend(_check_sql_filter_coherence(sql_widgets))
        warnings.extend(_check_sql_aggregate_coherence(sql_widgets))

    if len(metric_widgets) >= 2:
        warnings.extend(_check_metric_period_coherence(metric_widgets))

    analyzed = len(sql_widgets) + len(metric_widgets)
    return CoherenceReport(
        warnings=tuple(warnings),
        widgets_analyzed=analyzed,
        widgets_unparseable=len(unparseable_ids),
        widgets_capped=capped,
    )


# ---------------------------------------------------------------------------
# Internals — classification / extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SqlWidgetSignature:
    """Vue résumée d'un widget SQL pour les checks pairwise."""

    widget_id: int
    title: str
    filters: dict[str, tuple["_FilterValue", ...]]  # col_norm → predicates
    aggregates: frozenset[tuple[str, str]]  # (col_norm, agg_fn_upper)
    has_date_filter_on: frozenset[str]  # col_norm identifiés comme "date"


@dataclass(frozen=True)
class _FilterValue:
    """Signature canonique d'un prédicat WHERE pour comparaison.

    Frozen + ``__hash__`` explicite : la signature peut entrer dans des
    ``set``/``dict`` même si ``value`` est un type non-hashable par défaut
    (liste, dict). On hash sur la représentation textuelle pour garantir
    qu'une valeur sémantiquement équivalente produit toujours la même clé.
    """

    operator: str  # =, IN, BETWEEN, >, >=, <, <=, IS NULL, IS NOT NULL, LIKE
    value: Any  # str | tuple sorted | None
    negated: bool = False

    def is_date_like(self) -> bool:
        """Retourne True si la value contient des indices de date."""
        if self.value is None:
            return False
        if isinstance(self.value, (list, tuple)):
            return any(_is_date_like_scalar(v) for v in self.value)
        return _is_date_like_scalar(self.value)

    def _stable_value_repr(self) -> str:
        """Représentation déterministe utilisée pour ``__hash__``/sort.

        ``repr`` n'est pas suffisant car ``repr(['a','b']) != repr(('a','b'))``.
        On normalise list/tuple en chaîne d'éléments triés (la canonicalisation
        IN/BETWEEN s'est déjà chargée du tri sémantique).
        """
        v = self.value
        if v is None:
            return ""
        if isinstance(v, (list, tuple)):
            return "(" + ",".join(repr(x) for x in v) + ")"
        return repr(v)

    def __hash__(self) -> int:
        return hash((self.operator, self._stable_value_repr(), self.negated))


@dataclass(frozen=True)
class _MetricWidgetSignature:
    widget_id: int
    title: str
    metric_name: str
    period_days: Optional[int]
    raw_period: Any


def _classify_widgets(
    widgets: list[dict[str, Any]],
    *,
    dialect: str,
) -> tuple[list[_SqlWidgetSignature], list[_MetricWidgetSignature], list[int]]:
    """Sépare les widgets en SQL / metric et extrait leurs signatures.

    Retourne ``(sql_sigs, metric_sigs, unparseable_ids)``.
    Les widgets dont la structure est invalide sont ignorés silencieusement,
    avec un log warning pour traçabilité.
    """
    sql_sigs: list[_SqlWidgetSignature] = []
    metric_sigs: list[_MetricWidgetSignature] = []
    unparseable_ids: list[int] = []

    for raw in widgets:
        if not isinstance(raw, dict):
            logger.warning("coherence: widget non-dict ignoré type=%s", type(raw).__name__)
            continue

        wid = _safe_int(raw.get("id"))
        if wid is None:
            logger.warning("coherence: widget sans id valide ignoré")
            continue

        title = str(raw.get("title") or "")
        source_type = str(raw.get("data_source_type") or "").lower()
        cfg = raw.get("data_source_config")
        if not isinstance(cfg, dict):
            logger.warning(
                "coherence: widget id=%s data_source_config non-dict (%s) — ignoré",
                wid,
                type(cfg).__name__,
            )
            continue

        if source_type == "sql":
            sql_text = str(cfg.get("query") or "").strip()
            if not sql_text:
                logger.warning("coherence: widget id=%s SQL vide — ignoré", wid)
                continue
            sig = _extract_sql_signature(wid, title, sql_text, dialect=dialect)
            if sig is None:
                unparseable_ids.append(wid)
                continue
            sql_sigs.append(sig)
        elif source_type == "metric":
            sig_m = _extract_metric_signature(wid, title, cfg)
            if sig_m is not None:
                metric_sigs.append(sig_m)
        else:
            # Source type inconnu — ne casse pas la coherence-check, mais on
            # log pour signaler une future extension (KPI custom, etc.).
            logger.info(
                "coherence: widget id=%s source_type inconnu '%s' — ignoré",
                wid,
                source_type,
            )

    return sql_sigs, metric_sigs, unparseable_ids


def _extract_sql_signature(
    widget_id: int,
    title: str,
    sql_text: str,
    *,
    dialect: str,
) -> Optional[_SqlWidgetSignature]:
    """Extrait filtres + agrégats d'un widget SQL. Retourne None si non parseable.

    On considère le widget "parseable" si **sqlglot.parse_one** ne lève pas.
    L'absence de WHERE ou de SELECT est valide (= signature vide), ce qui
    permet à un dashboard avec un widget « table brute » de cohabiter avec
    d'autres widgets sans déclencher de faux warning.
    """
    if not _SQLGLOT_AVAILABLE:
        return None

    # Garde-fou DoS : un SQL pathologique (généré, fuzzed) peut saturer
    # sqlglot.parse_one (CPU-bound, blocke la loop async Tornado).
    if len(sql_text) > _MAX_SQL_LEN_FOR_COHERENCE:
        logger.info(
            "coherence: widget id=%s SQL trop long (%d > %d) — marqué unparseable",
            widget_id,
            len(sql_text),
            _MAX_SQL_LEN_FOR_COHERENCE,
        )
        return None

    try:
        tree = sqlglot.parse_one(sql_text, dialect=dialect)
    except Exception:
        return None
    if tree is None:
        return None

    # Filtres — délègue à filter_extractor qui gère WHERE outer + récursion And/Or/Not.
    predicates = extract_filters_from_sql(sql_text, dialect=dialect)
    filters_by_col: dict[str, list[_FilterValue]] = {}
    date_columns: set[str] = set()
    for pred in predicates:
        col_norm = _normalize_column(pred.column)
        if not col_norm:
            continue
        fv = _filter_value_from_predicate(pred)
        filters_by_col.setdefault(col_norm, []).append(fv)
        # Détection date heuristique : si valeur date-like OU colonne fonction
        # (YEAR(<col>), MONTH(<col>)) — la « colonne » extraite est l'expression brute.
        if fv.is_date_like() or _has_date_function_token(pred.column):
            date_columns.add(col_norm)

    # Canonicalisation : tri stable pour empêcher AND a=1 AND a=2 vs a=2 AND a=1
    # de produire deux signatures différentes.
    canonical_filters: dict[str, tuple[_FilterValue, ...]] = {
        col: tuple(sorted(values, key=_filter_sort_key)) for col, values in filters_by_col.items()
    }

    # Agrégats — directement via sqlglot AST sur le SELECT outer.
    aggregates = _extract_aggregates(tree)

    return _SqlWidgetSignature(
        widget_id=widget_id,
        title=title,
        filters=canonical_filters,
        aggregates=frozenset(aggregates),
        has_date_filter_on=frozenset(date_columns),
    )


def _extract_metric_signature(
    widget_id: int,
    title: str,
    cfg: dict[str, Any],
) -> Optional[_MetricWidgetSignature]:
    """Signature d'un widget metric. Tolérant aux configs partielles."""
    metric_name = str(cfg.get("metric_name") or "").strip()
    if not metric_name:
        # Métriques sans nom : on ignore mais ne marque pas comme unparseable
        # (différent d'un SQL cassé — c'est juste mal configuré).
        logger.info("coherence: widget metric id=%s sans metric_name — ignoré", widget_id)
        return None
    raw_period = cfg.get("period")
    period_days = _normalize_metric_period(raw_period)
    return _MetricWidgetSignature(
        widget_id=widget_id,
        title=title,
        metric_name=metric_name,
        period_days=period_days,
        raw_period=raw_period,
    )


# ---------------------------------------------------------------------------
# Internals — checks
# ---------------------------------------------------------------------------


def _check_sql_filter_coherence(
    sql_widgets: list[_SqlWidgetSignature],
) -> list[CoherenceWarning]:
    """Détecte les colonnes filtrées différemment entre widgets.

    Stratégie : pour chaque colonne, recense les widgets qui la filtrent.
    Si deux widgets ou plus ont des signatures de filtre DIFFÉRENTES sur la
    même colonne, on émet un warning unique pour ce groupe. Un widget qui
    ne filtre PAS la colonne n'est pas un mismatch — il est juste absent.
    """
    # Map: col_norm → list[(widget, signature_filter_value_tuple)]
    column_groups: dict[str, list[tuple[_SqlWidgetSignature, tuple[_FilterValue, ...]]]] = {}
    for w in sql_widgets:
        for col, values in w.filters.items():
            column_groups.setdefault(col, []).append((w, values))

    warnings: list[CoherenceWarning] = []
    for col, entries in column_groups.items():
        if len(entries) < 2:
            continue
        # Deduplique par signature filter tuple.
        sig_map: dict[tuple[_FilterValue, ...], list[_SqlWidgetSignature]] = {}
        for w, sig in entries:
            sig_map.setdefault(sig, []).append(w)
        if len(sig_map) < 2:
            # Tous les widgets filtrent la même colonne avec la MÊME signature.
            continue
        # Tri stable des signatures (chaîne) pour reproductibilité tests.
        is_date_dim = any(col in w.has_date_filter_on for w, _ in entries)
        affected = tuple(sorted({w.widget_id for w, _ in entries}))
        sig_descriptions = [
            (
                _describe_filter_signature(sig),
                tuple(sorted(w.widget_id for w in ws)),
            )
            for sig, ws in sig_map.items()
        ]
        sig_descriptions.sort(key=lambda item: item[0])
        sig_text = " ; ".join(
            f"{desc} (widgets {', '.join(str(w) for w in ws)})" for desc, ws in sig_descriptions
        )
        if is_date_dim:
            message = (
                f"Les widgets filtrent la période (colonne « {col} ») différemment : "
                f"{sig_text}. Vérifiez que c'est intentionnel."
            )
        else:
            message = (
                f"Les widgets filtrent la colonne « {col} » sur des valeurs différentes : "
                f"{sig_text}. Vérifiez que c'est intentionnel."
            )
        warnings.append(
            CoherenceWarning(
                kind="filter_mismatch",
                severity="warning",
                message=message,
                affected_widget_ids=affected,
                details={
                    "column": col,
                    "is_date_dimension": is_date_dim,
                    "signatures": [
                        {"description": desc, "widget_ids": list(ws)}
                        for desc, ws in sig_descriptions
                    ],
                },
            )
        )
    return warnings


def _check_sql_aggregate_coherence(
    sql_widgets: list[_SqlWidgetSignature],
) -> list[CoherenceWarning]:
    """Détecte les mêmes agrégats (col, fn) utilisés avec des scopes différents.

    Émet un warning ``info`` (sévérité réduite par rapport à filter_mismatch)
    car ce cas peut être intentionnel (comparer SUM(CA) 2024 vs SUM(CA) 2023).
    Le user reste informé mais le check ne bloque pas.
    """
    agg_groups: dict[tuple[str, str], list[_SqlWidgetSignature]] = {}
    for w in sql_widgets:
        for agg_sig in w.aggregates:
            agg_groups.setdefault(agg_sig, []).append(w)

    warnings: list[CoherenceWarning] = []
    for (col, fn), widgets in agg_groups.items():
        if len(widgets) < 2:
            continue
        # Compare la signature filter complète (sans la colonne agrégée elle-même).
        scope_keys: dict[tuple, list[_SqlWidgetSignature]] = {}
        for w in widgets:
            key = tuple(sorted(w.filters.items()))
            scope_keys.setdefault(key, []).append(w)
        if len(scope_keys) < 2:
            continue
        affected = tuple(sorted(w.widget_id for w in widgets))
        scope_count = len(scope_keys)
        # Pour les expressions complexes (CASE/CAST/arithmétique), on n'expose
        # pas le placeholder interne ``<expr:...>`` à l'utilisateur final —
        # message plus lisible sans détail SQL.
        if col.startswith("<expr:"):
            agg_label = f"{fn} (expression complexe)"
        elif col == "*":
            agg_label = f"{fn}(*)"
        else:
            agg_label = f"{fn}({col})"
        message = (
            f"L'agrégat {agg_label} apparaît dans {len(widgets)} widgets "
            f"avec {scope_count} scopes de filtre différents. "
            f"Les totaux ne sont pas directement comparables entre ces widgets."
        )
        warnings.append(
            CoherenceWarning(
                kind="aggregate_scope_mismatch",
                severity="info",
                message=message,
                affected_widget_ids=affected,
                details={
                    "column": col,
                    "aggregate": fn,
                    "distinct_scopes": scope_count,
                },
            )
        )
    return warnings


def _check_metric_period_coherence(
    metric_widgets: list[_MetricWidgetSignature],
) -> list[CoherenceWarning]:
    """Compare les périodes des widgets metric (en jours).

    On émet un warning quand DES PÉRIODES DIFFÉRENTES coexistent ; on n'émet
    rien si tous les widgets ignorent la notion de période (period_days=None
    pour tous → la métrique est lifetime).
    """
    periods_map: dict[Optional[int], list[_MetricWidgetSignature]] = {}
    for w in metric_widgets:
        periods_map.setdefault(w.period_days, []).append(w)

    # On compare uniquement quand on a au moins 2 périodes finies différentes.
    finite_keys = [k for k in periods_map if k is not None]
    if len(finite_keys) < 2:
        return []

    affected_ids = tuple(sorted({w.widget_id for w in metric_widgets if w.period_days is not None}))
    details_periods = [
        {
            "period_days": k,
            "widget_ids": sorted(w.widget_id for w in periods_map[k]),
        }
        for k in sorted(finite_keys)
    ]
    period_summary = ", ".join(
        f"{d['period_days']}j (widgets {', '.join(str(i) for i in d['widget_ids'])})"
        for d in details_periods
    )
    message = (
        "Les widgets de métriques utilisent des périodes différentes : "
        f"{period_summary}. Vérifiez que la comparaison est intentionnelle."
    )
    return [
        CoherenceWarning(
            kind="metric_period_mismatch",
            severity="warning",
            message=message,
            affected_widget_ids=affected_ids,
            details={"periods": details_periods},
        )
    ]


# ---------------------------------------------------------------------------
# Internals — helpers
# ---------------------------------------------------------------------------


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_column(col: str) -> str:
    """Normalise un nom de colonne : strip brackets/quotes, lowercase, garde alias.

    ``[col_x]`` → ``col_x`` ; ``T.col_x`` → ``t.col_x`` ; ``"col_x"`` → ``col_x``.
    Préserve les préfixes de table car deux widgets peuvent utiliser le même
    nom de colonne sur des tables différentes (ex : ``f.code`` vs ``g.code``).

    Si la chaîne contient autre chose qu'un identifiant simple éventuellement
    qualifié (ex : ``CASE WHEN x = 1 THEN col END`` retourné par
    filter_extractor pour une expression complexe), on retourne la chaîne
    brute lowercased SANS strip — sinon deux expressions distinctes peuvent
    collision après normalisation.
    """
    if not isinstance(col, str):
        return ""
    cleaned = col.strip()
    if not cleaned:
        return ""
    # Identifiant simple ou qualifié : que des chars d'identifiant + . + brackets/quotes.
    # On accepte uniquement ces chars (lettres, chiffres, _, ., [, ], ", `, ', et espaces).
    if not re.fullmatch(r"[\w\.\[\]\"`' ]+", cleaned):
        # Expression complexe → fold simplement en lowercase compact pour préserver
        # la sémantique sans risque de collision.
        return re.sub(r"\s+", " ", cleaned).strip().lower()
    # Strip brackets/quotes — peut s'appliquer plusieurs fois pour combo.
    parts = cleaned.split(".")
    norm_parts = []
    for p in parts:
        p = p.strip()
        for q in ("[", "]", '"', "`", "'"):
            p = p.replace(q, "")
        norm_parts.append(p.strip().lower())
    return ".".join(part for part in norm_parts if part)


def _filter_value_from_predicate(pred: FilterPredicate) -> _FilterValue:
    """Convertit un FilterPredicate en signature comparable.

    Normalisations :
    - ``IN ('x')`` (1 valeur) → ``= 'x'``
    - ``IN ('a','b')`` → trie alphabétique pour neutraliser l'ordre
    - ``BETWEEN low high`` → tuple ordonné (low, high)
    """
    op = pred.operator
    val: Any = pred.value
    if op == "IN" and isinstance(val, (list, tuple)):
        if len(val) == 1:
            return _FilterValue(operator="=", value=val[0], negated=pred.negated)
        return _FilterValue(
            operator="IN",
            value=tuple(sorted(val, key=_scalar_sort_key)),
            negated=pred.negated,
        )
    if op == "BETWEEN" and isinstance(val, tuple) and len(val) == 2:
        low, high = val
        # Tuple déjà ordonné si bien parsé ; safety swap si chaînes lex inversées.
        if _scalar_sort_key(low) > _scalar_sort_key(high):
            low, high = high, low
        return _FilterValue(operator="BETWEEN", value=(low, high), negated=pred.negated)
    return _FilterValue(operator=op, value=val, negated=pred.negated)


def _filter_sort_key(fv: _FilterValue) -> tuple:
    """Clé de tri stable pour rendre l'ordre des prédicats canonique."""
    return (
        fv.operator,
        bool(fv.negated),
        _scalar_sort_key(fv.value),
    )


def _scalar_sort_key(v: Any) -> tuple:
    """Clé de tri tolérante aux types mixtes (None, str, int, float, tuple/list)."""
    if v is None:
        return (0, "")
    if isinstance(v, bool):
        return (1, str(int(v)))
    if isinstance(v, (int, float)):
        return (2, str(v))
    if isinstance(v, str):
        return (3, v)
    if isinstance(v, (list, tuple)):
        # Convertit la liste/tuple en sérialisation stable et la classe en cat 4
        return (4, ",".join(str(x) for x in v))
    return (5, str(v))


def _describe_filter_signature(sig: tuple[_FilterValue, ...]) -> str:
    """Rendu humain (FR) d'une signature filter pour le warning message."""
    if not sig:
        return "(aucun filtre)"
    parts: list[str] = []
    for fv in sig:
        if fv.operator in ("IS NULL", "IS NOT NULL"):
            parts.append(fv.operator)
            continue
        prefix = "NON " if fv.negated else ""
        if fv.operator == "IN" and isinstance(fv.value, tuple):
            joined = ", ".join(_format_scalar(v) for v in fv.value)
            parts.append(f"{prefix}IN ({joined})")
        elif fv.operator == "BETWEEN" and isinstance(fv.value, tuple) and len(fv.value) == 2:
            low, high = fv.value
            parts.append(f"{prefix}entre {_format_scalar(low)} et {_format_scalar(high)}")
        else:
            parts.append(f"{prefix}{fv.operator} {_format_scalar(fv.value)}")
    return " ET ".join(parts)


def _format_scalar(v: Any) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, str):
        return repr(v)
    return str(v)


def _is_date_like_scalar(v: Any) -> bool:
    """True si la valeur ressemble à une date / une année.

    Heuristique stricte : on ne classe PAS un entier seul comme date — sinon
    `WHERE annee_compta = 2024` et `WHERE id_compte = 2024` seraient confondus.
    On exige une chaîne au format ISO/FR ou une fonction de date.
    """
    if v is None:
        return False
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return False
        for pat in _DATE_VALUE_PATTERNS:
            if pat.match(s):
                return True
        upper = s.upper()
        return any(tok in upper for tok in _DATE_FUNCTION_TOKENS)
    return False


#: Pattern compilé une fois pour matcher les fonctions de date en frontière
#: de mot. Construit dynamiquement depuis ``_DATE_FUNCTION_TOKENS`` pour
#: éviter le drift entre la frozenset et le regex.
_DATE_FUNCTION_TOKEN_RE: re.Pattern[str] = re.compile(
    r"\b(" + "|".join(sorted(_DATE_FUNCTION_TOKENS)) + r")\s*\(",
    re.IGNORECASE,
)


def _has_date_function_token(col_raw: str) -> bool:
    """True si la « colonne » brute extraite contient une fonction de date.

    Quand le WHERE est ``WHERE YEAR(date_col) = 2024``, filter_extractor extrait
    la « colonne » comme l'expression complète (via _safe_sql). On détecte la
    fonction dans cette chaîne — utile pour classer ce filtre comme « période ».

    Utilise ``\\b`` (frontière de mot) pour ne PAS matcher ``DAY_AVERAGE(...)``
    ou ``YEAR_OVER_YEAR(...)`` qui partagent un préfixe avec ``DAY``/``YEAR``
    mais ne sont pas des fonctions de date.
    """
    if not isinstance(col_raw, str):
        return False
    return _DATE_FUNCTION_TOKEN_RE.search(col_raw) is not None


def _extract_aggregates(tree: Any) -> set[tuple[str, str]]:
    """Extrait les agrégats du SELECT outer (col_norm, fn_upper).

    Ne descend PAS dans les sous-requêtes / CTE — on s'intéresse au scope
    visible par l'utilisateur dans le widget. Les CASE WHEN imbriqués sont
    traités au mieux : si l'argument est une Column simple, on l'extrait ;
    sinon on retourne ("<expr>", fn) avec une représentation compacte.
    """
    if not _SQLGLOT_AVAILABLE:
        return set()

    select_node = _find_outer_select(tree)
    if select_node is None:
        return set()

    aggregates: set[tuple[str, str]] = set()
    for sel_expr in select_node.expressions or []:
        inner = sel_expr.this if isinstance(sel_expr, sqlglot_exp.Alias) else sel_expr
        for agg_node, fn_name in _walk_aggregates(inner):
            col = _aggregate_argument_column(agg_node)
            if col is None:
                continue
            aggregates.add((col, fn_name))
    return aggregates


def _walk_aggregates(node: Any) -> Iterable[tuple[Any, str]]:
    """Yield (node, fn_upper) pour chaque agrégat reconnu **au niveau supérieur**
    d'une expression SELECT.

    Short-circuit après le premier agrégat trouvé pour éviter le double-comptage
    avec les agrégats imbriqués (ex : ``SUM(CASE WHEN COUNT(*) > 0 THEN 1 END)``
    doit produire UN seul tuple SUM, pas SUM + COUNT). Le but du checker est de
    détecter « le même agrégat répété entre widgets » ; les agrégats internes à
    un CASE/expression ne sont pas reproductibles d'un widget à l'autre.
    """
    if node is None:
        return
    fn_name = _agg_fn_name(node)
    if fn_name is not None:
        yield (node, fn_name)
        # Short-circuit : on a l'agrégat top-level, on ne descend pas.
        return
    for sub in node.args.values() if hasattr(node, "args") else []:
        if isinstance(sub, list):
            for s in sub:
                if hasattr(s, "args"):
                    yield from _walk_aggregates(s)
        elif hasattr(sub, "args"):
            yield from _walk_aggregates(sub)


def _agg_fn_name(node: Any) -> Optional[str]:
    """Retourne SUM/AVG/COUNT/MIN/MAX si le nœud est un agrégat reconnu, None sinon.

    Restreint au **vrai** parent agrégat de sqlglot (``AggFunc``) plus les
    classes explicites ``Sum/Avg/Count/Min/Max``. Évite de classer comme
    agrégat une UDF utilisateur dont le nom commence par ``SUM`` mais qui
    n'est pas une fonction d'agrégation (cas non-déterministe sur dialecte
    cible).
    """
    if not _SQLGLOT_AVAILABLE:
        return None
    if isinstance(node, sqlglot_exp.Sum):
        return "SUM"
    if isinstance(node, sqlglot_exp.Avg):
        return "AVG"
    if isinstance(node, sqlglot_exp.Count):
        return "COUNT"
    if isinstance(node, sqlglot_exp.Min):
        return "MIN"
    if isinstance(node, sqlglot_exp.Max):
        return "MAX"
    # Fallback restreint : AggFunc explicite (vraie fonction d'agrégation
    # côté sqlglot — exclut les Func et Anonymous arbitraires).
    agg_base = getattr(sqlglot_exp, "AggFunc", None)
    if agg_base is not None and isinstance(node, agg_base):
        name = getattr(node, "name", None) or node.__class__.__name__
        upper = name.upper()
        if upper in _AGGREGATE_FN_NAMES:
            return upper
    return None


def _aggregate_argument_column(node: Any) -> Optional[str]:
    """Extrait la colonne argument d'un agrégat. ``COUNT(*)`` → ``*``."""
    if not _SQLGLOT_AVAILABLE or node is None:
        return None
    inner = node.this if hasattr(node, "this") else None
    if inner is None:
        # COUNT(*) sans this — sqlglot représente différemment selon version.
        # On considère comme COUNT(*) générique.
        return "*"
    if isinstance(inner, sqlglot_exp.Star):
        return "*"
    if isinstance(inner, sqlglot_exp.Column):
        full = inner.name or ""
        table = inner.table or ""
        composite = f"{table}.{full}" if table and full else (full or "")
        return _normalize_column(composite) if composite else None
    if isinstance(inner, sqlglot_exp.Distinct):
        # COUNT(DISTINCT col) — on cherche la colonne dans les expressions.
        for sub in inner.expressions or []:
            if isinstance(sub, sqlglot_exp.Column):
                composite = f"{sub.table}.{sub.name}" if sub.table else sub.name
                return _normalize_column(composite or "")
        return None
    # Expression complexe (CASE, arithmétique…) — on encode en SQL compact.
    try:
        compact = inner.sql(dialect="tsql").lower()
    except Exception:
        return None
    # Normalise les espaces multiples
    compact = re.sub(r"\s+", " ", compact).strip()
    return f"<expr:{compact[:80]}>" if compact else None


def _find_outer_select(parsed: Any) -> Any:
    """Trouve le SELECT outer (skip CTEs/subqueries) — copié de drilldown.py:150."""
    if not _SQLGLOT_AVAILABLE:
        return None
    if isinstance(parsed, sqlglot_exp.Select):
        return parsed
    for node in parsed.walk():
        if isinstance(node, sqlglot_exp.Select):
            parent = node.parent
            outer = True
            while parent is not None:
                if isinstance(parent, (sqlglot_exp.CTE, sqlglot_exp.Subquery)):
                    outer = False
                    break
                parent = parent.parent
            if outer:
                return node
    return parsed.find(sqlglot_exp.Select)


def _normalize_metric_period(raw: Any) -> Optional[int]:
    """Convertit une période metric en jours int.

    Accepte :
    - ``int`` ou ``float`` (déjà en jours)
    - ``"7"``, ``"7d"``, ``"30d"``, ``"4w"``, ``"3m"``, ``"1y"``
    - ``None`` → None (= « lifetime », pas de période)

    Retourne ``None`` sur format inconnu (le widget ne participe pas au check).
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return None
        return v if v > 0 else None
    if not isinstance(raw, str):
        return None
    s = raw.strip().lower()
    if not s:
        return None
    m = re.match(r"^(\d+)\s*([dwmy]?)$", s)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2) or "d"
    if n <= 0:
        return None
    multipliers = {"d": 1, "w": 7, "m": 30, "y": 365}
    return n * multipliers[unit]
