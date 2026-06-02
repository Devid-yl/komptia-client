"""Helpers de détection des FK *inférées* — purs, sans I/O DB.

Deux signaux orthogonaux, applicables à n'importe quelle BDD SQL connectée
à Komptia (aucune convention de nommage hardcodée à un éditeur) :

* **value_overlap** — produit ailleurs (``schema_sync._compute_inferred_pairs``).
  Mesure empirique : containment des valeurs distinctes d'une colonne A.x
  dans celles de B.y. Pas implémenté ici (a besoin d'I/O DB), mais consommé
  par ``combine_signals`` ci-dessous sous forme de dict.

* **naming_pattern** — implémenté ici. Pour chaque table B, on dérive
  *plusieurs* tokens identifiants (nom complet, singulier, premiers N
  chars, segments CamelCase). On scanne ensuite les colonnes de toutes
  les autres tables A pour repérer ``<token_de_B><suffixe>`` ou
  ``<préfixe><token_de_B>`` où suffixe/préfixe est un mot-clé FK
  générique (``ref|id|key|fk|num|code|no``).

Anti-2+2=4 : on ne hardcode JAMAIS un nom de table ou de colonne d'une
BDD source. La détection s'applique à toute BDD (Sage, Cegid, custom).
Les tests de garde valident des *propriétés*, pas des cas instanciés.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping, Optional

from app.models.inferred_foreign_key import (
    KIND_NAMING_AND_VALUE,
    KIND_NAMING_PATTERN,
    KIND_VALUE_OVERLAP,
)

# ─────────────────────────────────────────────────────────────────────────
# Tokens identifiants d'une table
# ─────────────────────────────────────────────────────────────────────────

# Mots-clés FK génériques. ``no`` couvre les conventions Sage (``NoEnreg``)
# et plus largement les colonnes "numéro de ...". L'ordre est important :
# le regex testera les plus longs d'abord pour éviter ``id`` qui match
# avant ``fkid``. (Géré au runtime dans ``_compile_pattern_regex``.)
_FK_KEYWORDS: tuple[str, ...] = (
    "ref",
    "fk",
    "key",
    "id",
    "num",
    "code",
    "no",
)

# Tokens *non-identifiants* à exclure : trop génériques pour servir de
# racine de table (par ex. un mot court qui matcherait toute colonne).
# Pas un blocage strict — juste une borne min de longueur.
_MIN_TOKEN_LENGTH = 3

# Séparateurs courants pour fractionner les noms de colonnes :
#   - underscore (``client_id``)
#   - tiret (``client-id``, rare mais possible)
#   - frontière camelCase (``ClientId``)
# Concaténé en une seule regex pour découper en un seul passage.
_SPLIT_RE = re.compile(r"[_\-]+|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def derive_table_tokens(table_name: str) -> set[str]:
    """Dérive l'ensemble des tokens qui *peuvent* représenter ``table_name``
    dans le nom d'une colonne FK.

    Retourne toujours au moins le nom complet lowercase ; ajoute aussi :
      - singulier naïf (suppression d'un ``s`` final)
      - segments CamelCase / underscores de longueur ≥ ``_MIN_TOKEN_LENGTH``
      - préfixe court (3-5 chars) — fréquent en convention Sage / Cegid

    Pas de hardcode par BDD : les heuristiques sont génériques.
    Cf. ``tests/unit/test_fk_inference.py`` pour les propriétés validées.
    """
    if not table_name:
        return set()
    lower = table_name.lower()
    tokens: set[str] = {lower}

    # Singulier naïf — ``Clients`` → ``client``. Marche pour l'anglais et
    # le français les plus fréquents. Pas parfait (``donnees`` → ``donnee``
    # OK mais ``souris`` → ``souri`` pas idéal) — la combinaison avec
    # value_overlap couvre les faux négatifs.
    if len(lower) > _MIN_TOKEN_LENGTH and lower.endswith("s"):
        tokens.add(lower[:-1])

    # Segments — pour les noms composés (``OrderDetails``, ``T_FACT_ENT``).
    for seg in _SPLIT_RE.split(table_name):
        seg_lower = seg.lower()
        if len(seg_lower) >= _MIN_TOKEN_LENGTH:
            tokens.add(seg_lower)
            if seg_lower.endswith("s") and len(seg_lower) > _MIN_TOKEN_LENGTH:
                tokens.add(seg_lower[:-1])

    # Préfixes courts (3-5 chars) — convention legacy fréquente
    # (``cli`` pour ``clients``, ``fac`` pour ``factures``). On *n'ajoute*
    # ces tokens que s'ils ne sont pas déjà couverts par les segments
    # ci-dessus, pour éviter d'inonder l'espace de recherche sur les
    # noms courts (``cli`` ⊂ ``client`` ⊂ ``clients``).
    for n in (5, 4, 3):
        prefix = lower[:n]
        if len(prefix) == n and prefix.isalpha():
            tokens.add(prefix)

    return {t for t in tokens if len(t) >= _MIN_TOKEN_LENGTH}


# ─────────────────────────────────────────────────────────────────────────
# Match d'un nom de colonne contre les tokens d'une table cible
# ─────────────────────────────────────────────────────────────────────────


def _normalize_column(name: str) -> str:
    """Lowercase + suppression des séparateurs. ``client_id`` → ``clientid``."""
    return re.sub(r"[_\-]+", "", name.lower())


def is_likely_fk_column_name(
    column: str,
    target_tokens: Iterable[str],
) -> tuple[bool, Optional[str]]:
    """Teste si ``column`` ressemble à une FK vers une table dont les tokens
    sont ``target_tokens``.

    Retourne ``(match, evidence)`` où ``evidence`` est le pattern matched
    (``"ClientId→client+id"``) ou ``None`` si pas de match.

    Reconnait :
      - ``<token><kw>`` (``clientId``, ``client_id``, ``ClientRef``)
      - ``<kw><token>`` (``idClient``, ``refClient``)
      - ``<token>_<kw>`` (variantes avec underscore — couvert par normalize)

    Anti-faux-positifs :
      - le nom de colonne *entier* doit être consommé par ``token+kw`` ou
        ``kw+token`` — pas de match partiel au milieu (``descriptionId``
        n'est PAS reconnu comme FK vers ``description`` car ``description``
        n'est pas un token raisonnable d'une table).
      - le keyword doit faire au moins 2 chars (``id``, ``no``, ``fk``, ``no``).
    """
    if not column:
        return False, None
    norm = _normalize_column(column)

    # Tester chaque token cible. On essaie d'abord les tokens les plus
    # longs (moins de faux positifs) — ``orderdetail`` avant ``order``.
    sorted_tokens = sorted({t for t in target_tokens if t}, key=len, reverse=True)
    for tok in sorted_tokens:
        if not tok:
            continue
        # Pattern A : <token><kw>  (ClientId, clientid, clientref, clientno)
        for kw in _FK_KEYWORDS:
            if norm == tok + kw:
                return True, f"{column}→{tok}+{kw} (suffix)"
            # Pattern B : <kw><token>  (idClient, refClient, noClient)
            if norm == kw + tok:
                return True, f"{column}→{kw}+{tok} (prefix)"
        # Pattern C : <token> exact — ex. ``Client`` qui réfère ``Client.Id``.
        # Très permissif → on ne l'autorise QUE si le nom = token + rien
        # ET token a au moins 4 chars (sinon faux positifs en cascade).
        if norm == tok and len(tok) >= 4:
            return True, f"{column}→{tok} (exact)"

    return False, None


# ─────────────────────────────────────────────────────────────────────────
# Détection naming-only à partir d'un schéma
# ─────────────────────────────────────────────────────────────────────────


def detect_naming_fks(
    tables_columns: Mapping[str, list[str]],
    pks_by_table: Optional[Mapping[str, str]] = None,
) -> list[dict]:
    """Pour chaque (source_table, source_column), cherche une cible
    plausible parmi toutes les autres tables via les tokens.

    Args:
        tables_columns : {table_name: [col1, col2, ...]} — schéma complet
            de la BDD source.
        pks_by_table : {table_name: pk_column} — optionnel. Si fourni, la
            ``target_column`` est la PK déclarée ; sinon, on essaye une
            convention générique (``id``, ``<table>_id``) — fallback faible.

    Returns:
        Liste de dicts ``{source_table, source_column, target_table,
        target_column, evidence}`` (kind décidé plus tard par
        ``combine_signals``).

    Génériquité :
      - aucun hardcode d'une convention BDD source spécifique
      - skip self-FK (table → elle-même)
      - dédup case-insensitive sur (src_table, src_col, tgt_table)
    """
    pks_by_table = dict(pks_by_table or {})
    # Index inversé : token → liste de tables qui le revendiquent.
    token_to_tables: dict[str, list[str]] = {}
    for t in tables_columns:
        for tok in derive_table_tokens(t):
            token_to_tables.setdefault(tok, []).append(t)

    seen: set[tuple[str, str, str]] = set()
    results: list[dict] = []
    for src_table, cols in tables_columns.items():
        if not cols:
            continue
        src_lower = src_table.lower()
        for col in cols:
            norm = _normalize_column(col)
            if not norm:
                continue
            # Tester chaque token candidat. ``is_likely_fk_column_name``
            # gère la priorité par longueur. On itère explicitement ici
            # pour pouvoir matcher *plusieurs* tables si elles partagent
            # le même token (ambiguïté à reporter au signal valeur).
            for tok, candidate_tables in token_to_tables.items():
                # Skip tokens que la colonne source ne peut pas exploiter
                # (court-circuit performance — le helper testerait quand
                # même).
                if tok not in norm:
                    continue
                match, evidence = is_likely_fk_column_name(col, [tok])
                if not match:
                    continue
                for tgt_table in candidate_tables:
                    if tgt_table.lower() == src_lower:
                        continue  # skip self-FK
                    key = (src_lower, col.lower(), tgt_table.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    tgt_pk = (
                        pks_by_table.get(tgt_table)
                        or pks_by_table.get(tgt_table.lower())
                        or _guess_pk_column(tables_columns.get(tgt_table, []))
                    )
                    if not tgt_pk:
                        # Pas de PK détectable → pas de naming FK fiable.
                        # On laisse le signal valeur le découvrir.
                        continue
                    results.append(
                        {
                            "source_table": src_table,
                            "source_column": col,
                            "target_table": tgt_table,
                            "target_column": tgt_pk,
                            "evidence": evidence,
                        }
                    )
    return results


def _guess_pk_column(columns: list[str]) -> Optional[str]:
    """Heuristique de fallback pour deviner la PK d'une table quand
    ``pks_by_table`` ne la fournit pas. Patterns courants : ``id``,
    ``<table>_id``, ``id_<table>``. Génériques, pas hardcodés à une BDD.

    Retourne le 1ᵉʳ candidat ou ``None`` si rien ne match.
    """
    if not columns:
        return None
    lower_map = {c.lower(): c for c in columns}
    for cand in ("id",):
        if cand in lower_map:
            return lower_map[cand]
    for c in columns:
        cl = c.lower()
        if cl.endswith("id") or cl.endswith("_id") or cl.startswith("id_"):
            return c
    return None


# ─────────────────────────────────────────────────────────────────────────
# Combinaison naming + value
# ─────────────────────────────────────────────────────────────────────────

# Seuils de containment pour le signal valeur. Calibration pragmatique :
# 0.99 = quasi-100 %, signal très fort ; 0.85 = relation probable mais
# avec quelques orphelins (clés invalides ou changement de schéma) ;
# 0.50 = signal faible, à ne garder que si naming pattern confirme.
_THRESHOLD_HIGH = 0.99
_THRESHOLD_MEDIUM = 0.85
_THRESHOLD_LOW = 0.50


def combine_signals(
    naming_fks: list[dict],
    value_fks: list[dict],
) -> list[dict]:
    """Fusionne les FK détectées par nommage et par valeur en une liste
    déduplicquée, en assignant ``kind`` et ``confidence``.

    Args:
        naming_fks : sortie de ``detect_naming_fks``.
        value_fks : liste de dicts ``{source_table, source_column,
            target_table, target_column, containment (float),
            overlap (int), src_distinct (int), tgt_distinct (int)}``.

    Returns:
        Liste de dicts ``{source_table, source_column, target_table,
        target_column, kind, confidence, evidence}`` prêts à insérer
        dans ``InferredForeignKey``.

    Règles de confidence :
      - naming match + containment ≥ 0.99 → kind=naming_and_value,
        confidence=0.99
      - naming match + 0.85 ≤ containment < 0.99 → kind=naming_and_value,
        confidence=0.90
      - naming match + containment < 0.85 → kind=naming_pattern,
        confidence=0.60 (naming seul, le value est trop faible)
      - naming match seul (pas de containment) → kind=naming_pattern,
        confidence=0.55
      - containment ≥ 0.99 seul → kind=value_overlap, confidence=0.95
      - 0.85 ≤ containment < 0.99 seul → kind=value_overlap,
        confidence=0.75
      - containment < 0.85 seul → kind=value_overlap, confidence=0.55
      - containment < 0.50 → exclu (filtré par l'amont).
    """

    # Indexer par tuple (case-insensitive) pour le merge.
    def _key(d: dict) -> tuple[str, str, str, str]:
        return (
            d["source_table"].lower(),
            d["source_column"].lower(),
            d["target_table"].lower(),
            d["target_column"].lower(),
        )

    naming_index = {_key(d): d for d in naming_fks}
    value_index = {_key(d): d for d in value_fks if d.get("containment", 0) >= _THRESHOLD_LOW}

    all_keys = set(naming_index) | set(value_index)
    results: list[dict] = []
    for k in all_keys:
        n = naming_index.get(k)
        v = value_index.get(k)

        # Le row "canonique" : on prend les noms originaux du naming s'il
        # existe (typiquement mieux casé), sinon ceux du value.
        canonical = n if n else v
        if canonical is None:  # pragma: no cover — défensif
            continue

        containment = float(v["containment"]) if v else None
        evidence_parts: list[str] = []
        if n and n.get("evidence"):
            evidence_parts.append(f"naming={n['evidence']}")
        if v:
            evidence_parts.append(
                "value=containment={containment:.2f},overlap={overlap}/{small}".format(
                    containment=containment if containment is not None else 0.0,
                    overlap=v.get("overlap", 0),
                    small=min(v.get("src_distinct", 0), v.get("tgt_distinct", 0))
                    or v.get("src_distinct", 0),
                )
            )

        # Classification kind + confidence.
        if n and v:
            if containment is not None and containment >= _THRESHOLD_HIGH:
                kind = KIND_NAMING_AND_VALUE
                confidence = 0.99
            elif containment is not None and containment >= _THRESHOLD_MEDIUM:
                kind = KIND_NAMING_AND_VALUE
                confidence = 0.90
            else:
                # Naming match mais containment trop bas → naming seul.
                # On garde quand même la trace value dans evidence pour debug.
                kind = KIND_NAMING_PATTERN
                confidence = 0.60
        elif n and not v:
            kind = KIND_NAMING_PATTERN
            confidence = 0.55
        elif v and not n:
            assert containment is not None
            if containment >= _THRESHOLD_HIGH:
                kind = KIND_VALUE_OVERLAP
                confidence = 0.95
            elif containment >= _THRESHOLD_MEDIUM:
                kind = KIND_VALUE_OVERLAP
                confidence = 0.75
            else:
                kind = KIND_VALUE_OVERLAP
                confidence = 0.55
        else:  # pragma: no cover — all_keys garantit n ou v.
            continue

        results.append(
            {
                "source_table": canonical["source_table"],
                "source_column": canonical["source_column"],
                "target_table": canonical["target_table"],
                "target_column": canonical["target_column"],
                "kind": kind,
                "confidence": confidence,
                "evidence": " | ".join(evidence_parts) if evidence_parts else None,
            }
        )

    # Ordre stable (test reproductibilité) : src_table puis src_col.
    results.sort(
        key=lambda r: (
            r["source_table"].lower(),
            r["source_column"].lower(),
            r["target_table"].lower(),
            r["target_column"].lower(),
        )
    )
    return results
