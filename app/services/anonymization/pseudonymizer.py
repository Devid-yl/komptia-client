"""Pseudonymisation bijective valeurs classeur ↔ tokens anonymes.

Complémente `anonymizer.py` (pattern-based PII: email, SIRET…). Ici on a une
approche **value-sourced** : le classeur de l'utilisateur définit l'ensemble
des valeurs à protéger (noms de clients, codes experts, codes stat métiers,
etc). On scanne ses tabs_context + sheet_content, on construit une table
bijective cleartext ↔ anonymisé, et on applique la substitution à tout
l'input du LLM et la substitution inverse à tout son output.

Garanties :
- **Bijectivité stricte** : cleartext → token → cleartext (round-trip exact).
  Collision gérée via suffixe incrémental (``§Xxx_4b3§``, ``§Xxx_4b3_2§``, …).
- **Déterministe** : même cleartext → même token, cross-session.
- **Longest-match-first** : une valeur composée (2+ mots) remplace avant
  son sous-token seul.
- **Transparent** : tokens non-trouvés passent inchangés (pas de fallback,
  pas de blocage, pas de 2+2=4).
- **Numériques & structure clairs** : int/float/parseable ne sont jamais
  anonymisés. Les noms de colonnes ne sont jamais des VALUES donc jamais
  dans la table.

Format des tokens : ``§{consonnes_et_digits}_{hash3}§`` (sentinelles
incluses). Les voyelles sont retirées, le hash md5[:3] sert de
disambiguateur. Les formats numérique/date/pourcentage ne sont pas
anonymisables — ils passent inchangés.

Usage typique :

    pseudo = Pseudonymizer()
    pseudo.build_table_from_tabs(tabs_context)
    tabs_anon = pseudo.anonymize(tabs_context)
    instruction_anon = pseudo.anonymize_text(instruction)
    # ... appel LLM ...
    result_clear = pseudo.deanonymize(result)

Portée et non-portée :
- ✅ Runtime LLM (SSoT) : instancié par `anonymize_for_llm` (proxy.py) via
  `_load_user_pseudonymizer`, lui-même branché sur TOUS les call-sites LLM
  (Iris chat/agent, copilot, rapports, schema-enrich, automation bridge…).
  La substitution forward est donc case-insensitive (la BDD source peut
  renvoyer une valeur dans une casse ≠ du terme /data-privacy configuré).
- ✅ copilot_agent : table construite via `build_user_pseudonymizer`
  (extract.py) depuis les termes /data-privacy.
- ❌ Fixtures git : protection runtime uniquement. Les fichiers JSON sur
  disque gardent leur cleartext tant que pas renommés séparément.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import unicodedata
from decimal import Decimal
from typing import Any, Dict, Iterable, List, Optional, Set

from app.services.anonymization.patterns import resolve_label

logger = logging.getLogger(__name__)

# Pattern : strings qui NE SONT PAS considérées comme business values à
# anonymiser. Couvre :
# - chaînes vides / whitespace-only
# - nombres purs (int, float) sous forme string
# - formats date/période ("2023/2024", "2024-10-15", "10/2024")
# On teste en PRIORITÉ avant d'ajouter à la table. Tout ce qui échoue
# ces règles = business value à protéger.
_PURE_NUMERIC_RE = re.compile(
    r"^-?\d+(?:[.,]\d+)?(?:[eE][-+]?\d+)?$"  # entiers, floats, scientifiques
)
_DATE_LIKE_RE = re.compile(r"^\d{1,4}[-/.]\d{1,4}(?:[-/.]\d{1,4})?$")
# Pourcentages (42%), devises (12€, $99), numéros avec thousand-sep (1,234.56)
_MONEY_OR_PERCENT_RE = re.compile(r"^-?\d+(?:[.,\s]\d+)*\s*[€$£%]?$")

# Stoplist de tokens structurels qui PASSENT le classifier numérique mais
# ne sont pas des business values à anonymiser : états, booléens, sentinelles,
# marqueurs "vide". Case-insensitive. On NE met PAS ici des codes métier —
# ceux-ci doivent être anonymisés car potentiellement identifiants.
_STRUCTURAL_STOPLIST = {
    "true",
    "false",
    "none",
    "null",
    "n/a",
    "n.a.",
    "na",
    "nan",
    "-",
    "—",
    "…",
    "...",
    "oui",
    "non",
    "yes",
    "no",
    "ok",
    "ko",  # status flags fréquents
}

# Longueur minimale d'une string pour entrer dans la table (whole OU
# sub-token). Sous ce seuil, risque élevé de substring pollution (ex: "X"
# qui remplace tous les "X" du contexte LLM). 2 chars min = compromis :
# ignore les single chars pathologiques mais garde "SA", "GB", "EC" qui
# peuvent être des codes métier légitimes. ⚠️ Le matching forward est
# case-insensitive ET whitespace-insensible (cf. _build_patterns) : un terme
# court comme "SA" matche donc aussi "sa"/"Sa". L'user choisit ses termes en
# conséquence — priorité à ZÉRO fuite PII sur le risque de sur-anonymisation
# d'un terme générique.
_MIN_ANONYMIZABLE_LENGTH = 2

# Sentinelles encadrant les tokens anonymisés. Format `§racine_hash§`.
# Pourquoi : garantit que si le LLM hallucine une string ressemblant au
# format du token SANS sentinelles, elle ne sera PAS dé-anonymisée (pas
# de corruption silencieuse de l'output user). `§` (U+00A7) est rarissime
# dans les données comptables — risque de collision ~ nul. On expose ce
# format dans le system prompt pour que le LLM conserve les sentinelles.
_SENTINEL = "§"

# Détection grossière d'un token anonymisé dans une chaîne. Utilisé par
# `coerce_to_numeric` pour décider si tenter une déanonymisation avant le
# `float()`. Volontairement permissif : matche dès qu'on voit ``§`` —
# le coût d'un `deanonymize_text` raté est bénin (retourne le string original).
_TOKEN_SHAPE_RE = re.compile(r"§[^§]*§")

# Séparateurs utilisés pour tokeniser les valeurs multi-mots (ex: label
# "NOM PRENOM - Suffixe" → tokens ["NOM", "PRENOM", "Suffixe"]). On ne
# split PAS sur `.` pour préserver les nombres et patterns comme "v1.2".
# On ne split PAS sur `:` qui peut apparaître dans des IDs métier.
_TOKENIZE_SEPARATORS_RE = re.compile(r"[\s\-/,;_]+")


def _is_numeric_literal(s: str) -> bool:
    """True si la string peut être strictement interprétée comme un nombre
    (entier, float, scientifique). Guard : on ne met JAMAIS un nombre dans
    la table. Inclut aussi les devises/pourcentages (ex: `"42%"`, `"12€"`)."""
    stripped = s.strip()
    return bool(_PURE_NUMERIC_RE.match(stripped) or _MONEY_OR_PERCENT_RE.match(stripped))


def _is_date_like(s: str) -> bool:
    """True si la string ressemble à une date/période : `2023/2024`,
    `10/2024`, `2024-10-15`. On les laisse en clair (périodes = structurelles,
    pas PII au sens du cabinet)."""
    return bool(_DATE_LIKE_RE.match(s.strip()))


def _is_empty_or_whitespace(s: str) -> bool:
    return not s or not s.strip()


def _is_structural_sentinel(s: str) -> bool:
    """True si la string est un marqueur structurel commun (true/false/null/
    n/a/etc). Ne JAMAIS les anonymiser, sinon on pollue le raisonnement
    LLM sur des status flags."""
    return s.strip().lower() in _STRUCTURAL_STOPLIST


def _make_token(
    cleartext: str,
    category: Optional[str] = None,
    suffix: Optional[int] = None,
) -> str:
    """Construit le token anonyme pour un cleartext donné.

    **Format** : ``§{LABEL}_{md5[:4]}§`` (ex: ``§EMAIL_4b3a§``,
    ``§NAME_8a2c§``, ``§TERM_a1d1§`` quand pas de catégorie).

    Les sentinelles ``§`` encadrent le token pour que la dé-anonymisation
    ne substitue QUE les tokens bien formés — une hallucination du LLM qui
    contiendrait ``EMAIL_4b3a`` sans sentinelles NE sera PAS remplacée vers
    le cleartext, donc pas de corruption silencieuse de l'output utilisateur.

    Algorithme :

    1. Résout ``LABEL`` via :func:`patterns.category_to_label` —
       ``"EMAIL"``, ``"PHONE"``, ``"IBAN"``, …, ``"TERM"`` en fallback.
       Le label ne contient JAMAIS la moindre lettre du cleartext → pas
       de leak même pour les termes sans voyelles ou purement numériques.
    2. Calcule un hash md5[:4] en base16 du cleartext → 4 chars
       reproductibles (65 536 valeurs uniques par label).
    3. Assemble ``§{LABEL}_{hash4}§``.
    4. Si `suffix` fourni (collision détectée par
       :meth:`Pseudonymizer._add_single`), append ``_{suffix}`` avant
       le sentinel final (``§EMAIL_4b3a_2§``).

    Déterministe : même ``(cleartext, category, suffix)`` → même token.

    **Rupture vs ancien format** : avant 2026-05-19, le format
    ``consonants_md5[:3]`` exposait les consonnes du cleartext et était
    désaligné de :func:`extract._auto_pseudo_middle` pour les termes sans
    voyelles (panneau affichait ``n_<md5[:8]>`` mais LLM voyait
    ``§<cleartext>_<md5[:3]>§`` = leak). Le nouveau format est uniforme
    et porte la sémantique catégorie → compréhension LLM maximisée tout
    en restant pseudo-opaque.

    Args:
        cleartext: le terme à anonymiser.
        category: catégorie BDD optionnelle (``pii_email``, ``pii_name``,
            etc.). ``None`` → label ``"TERM"``.
        suffix: index incrémental pour résoudre une collision de hash
            (gérée par :meth:`Pseudonymizer._add_single`). ``None`` au
            premier appel.

    Returns:
        Le token complet ``§...§``.
    """
    label = resolve_label(cleartext, category)
    h = hashlib.md5(cleartext.encode("utf-8")).hexdigest()[:4]
    core = f"{label}_{h}"
    if suffix is not None:
        core = f"{core}_{suffix}"
    return f"{_SENTINEL}{core}{_SENTINEL}"


def _canonical_key_runtime(value: str) -> str:
    """Clé canonique pour le matching forward case-, accent- ET
    whitespace-insensible.

    Réutilise la SSoT :func:`repository._canonical_key` (NFKD strip-accents +
    casefold, même notion d'identité que la dédup BDD) PUIS collapse les runs
    de whitespace internes — la BDD source peut renvoyer une même valeur avec
    une casse, un accent ET/OU un espacement ≠ du terme /data-privacy configuré
    (``"SOFIGEC  PAP"`` vs ``"Sofigec Pap"``, ``"CREDIT"`` vs ``"Crédit"``,
    padding CHAR de SQL Server, double espace). Ces variations sont la même
    classe de fuite PII silencieuse, traitées ensemble. Le matching reste donc
    un SUR-ensemble de l'identité BDD (plus permissif = plus protecteur).

    **SSoT** : délègue à :func:`repository._canonical_match_key` (la MÊME clé
    de match stockée en colonne ``term_canonical`` et utilisée par les lectures
    SQL scopées) — runtime et lectures DB partagent ainsi exactement la même
    notion de matching (case+accent+whitespace).

    Import paresseux pour éviter le cycle pseudonymizer ↔ extract ↔
    repository. ``sys.modules`` cache le module après le 1er appel.
    """
    from app.services.anonymization.repository import _canonical_match_key

    return _canonical_match_key(value)


def _build_accent_equivalence() -> Dict[str, str]:
    """Carte ``lettre-de-base → classe de variantes accentuées`` (casefold),
    **pour les lettres LATINES uniquement** (français/européen).

    Construite **programmatiquement** depuis les propriétés Unicode (aucune
    liste de caractères / langue hardcodée — règle GÉNÉRICITÉ ; le périmètre
    Latin est un choix de couverture pragmatique, pas une donnée métier) : on
    parcourt les plages latines (ASCII + Latin-1 Supplement + Latin
    Extended-A/B, ``0x41``..``0x24F``), on décompose chaque lettre en NFKD, on
    retire ses marques combinantes pour obtenir sa base, et on regroupe par
    base. Exemple : base ``"e"`` → ``"eèéêë…"``, base ``"c"`` → ``"cç"``,
    base ``"n"`` → ``"nñ"``.

    Seules les bases ayant **au moins une variante accentuée** sont retournées
    (sinon une lettre sans variante — ``"b"``, ``"k"`` — n'a aucun intérêt à
    devenir une classe ``[b]`` et ne ferait que grossir la regex). Les vraies
    lettres distinctes (``"æ"``, ``"ø"`` : pas de décomposition NFKD vers une
    base ASCII) ne sont **pas** fusionnées avec une autre lettre — elles
    restent littérales, ce qui est correct (``"æ"`` ≠ ``"a"``).

    La notion de base (``_strip_diacritics`` ∘ casefold) est **identique** à
    celle de :func:`repository._canonical_key`, pour que la regex de
    *détection* et l'index de *résolution* (``_forward_ci``) restent synchros :
    tout candidat matché par la classe se résout via la même clé canonique.
    """
    groups: Dict[str, set] = {}
    # 0x41='A' → 0x250 couvre ASCII + Latin-1 Supplement + Latin Extended-A/B,
    # soit l'essentiel des accents européens (français, allemand, ibérique…).
    for cp in range(0x41, 0x250):
        ch = chr(cp)
        if not ch.isalpha():
            continue
        # Base = lettre sans diacritique, casefoldée. NFKD peut produire
        # plusieurs codepoints (ligatures) → on n'accepte qu'une base d'UNE
        # lettre ASCII (ß→"ss" len 2 exclu, æ→"æ" non-ASCII exclu).
        base = "".join(
            c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)
        ).casefold()
        if len(base) != 1 or not base.isascii() or not base.isalpha():
            continue
        groups.setdefault(base, set()).add(base)
        # On n'ajoute QUE les variantes mono-codepoint : le casefold de certains
        # caractères produit plusieurs codepoints (ex: ``"İ"`` turc → ``"i̇"`` =
        # i + point combinant) qui, inséré dans une classe ``[...]``, y
        # ajouterait le point combinant comme élément parasite (matche un
        # diacritique isolé). On les écarte — leur base ``i`` garde de toute
        # façon ses vraies variantes ``ìíîï``.
        cf = ch.casefold()
        if len(cf) == 1:
            groups[base].add(cf)
    return {
        base: "".join(sorted(variants))
        for base, variants in groups.items()
        if len(variants) > 1
    }


#: Carte précalculée une fois au chargement du module (cf.
#: :func:`_build_accent_equivalence`). Lecture seule au runtime. L'assertion
#: garde contre une rupture silencieuse de la normalisation Unicode (carte vide
#: ⇒ regex non accent-insensible ⇒ fuite PII silencieuse).
_ACCENT_EQUIVALENCE: Dict[str, str] = _build_accent_equivalence()
assert _ACCENT_EQUIVALENCE, "accent equivalence map vide — normalisation Unicode cassée ?"


def _char_to_accent_class(ch: str) -> str:
    """Convertit un caractère en fragment regex accent-insensible.

    - Lettre accentuable (``"e"``, ``"é"``, ``"C"``, ``"ç"``…) → classe de
      caractères ``[eèéêë…]`` couvrant toutes les variantes de sa base. La
      casse est gérée par ``re.IGNORECASE`` au compile (la classe ne liste que
      les formes casefoldées). ``"é"`` et ``"e"`` produisent la MÊME classe.
    - Tout autre caractère (consonne sans variante, chiffre, ponctuation,
      lettre non-latine) → simplement ``re.escape(ch)`` (comportement
      historique inchangé).

    Les variantes étant des lettres (``isalpha``), elles sont sûres dans une
    classe ``[...]`` sans échappement (pas de ``]``, ``\\``, ``^``, ``-``).
    """
    base = "".join(
        c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c)
    ).casefold()
    variants = _ACCENT_EQUIVALENCE.get(base)
    if variants is not None:
        return "[" + variants + "]"
    return re.escape(ch)


class Pseudonymizer:
    """État bijectif cleartext ↔ anonymisé, construit à partir d'un classeur.

    Instance-scoped : **une par coroutine / par appel `anonymize_for_llm`**.
    Table rebâtie à chaque session — aucune persistence entre sessions.

    **NON thread-safe** (et non coroutine-safe sans précaution) : ``_forward``,
    ``_reverse``, ``_token_seen``, ``_fwd_pattern``, ``_rev_pattern`` sont
    mutés sans lock dans :meth:`_add_single` / :meth:`add_mapping`. Partager
    une instance entre 2 coroutines qui ``add_*`` en parallèle peut produire
    des patterns regex désynchronisés et des entrées orphelines. Le code
    actuel respecte le contrat en construisant une instance neuve dans
    :func:`anonymize_for_llm` (proxy.py) et en l'utilisant strictement
    dans la même closure ``restore_fn``.

    ⚠️ NE JAMAIS cacher une instance ``Pseudonymizer`` cross-user
    (collision de bijection garantie + leak cleartext via dé-anonymisation
    croisée). NE JAMAIS la cacher cross-requête même mono-user (le state
    BDD peut avoir changé entre 2 requêtes — relire la BDD à chaque appel
    via :func:`_load_user_pseudonymizer`).
    """

    def __init__(self) -> None:
        # cleartext -> token anonymisé (pour substitution input)
        self._forward: Dict[str, str] = {}
        # Index canonique (NFKC+casefold) cleartext -> token, pour la
        # substitution forward case-insensitive. Rebâti dans _build_patterns.
        self._forward_ci: Dict[str, str] = {}
        # token anonymisé -> cleartext (pour substitution output)
        self._reverse: Dict[str, str] = {}
        # Compteurs pour disambiguation en cas de collision
        self._token_seen: Set[str] = set()

        # Regex précompilées (lazy : construites après build_table)
        self._fwd_pattern: Optional[re.Pattern[str]] = None
        self._rev_pattern: Optional[re.Pattern[str]] = None

    # -- Classification helpers ------------------------------------------------

    @staticmethod
    def is_anonymizable_value(v: Any) -> bool:
        """True si `v` est une string business value à protéger.

        Règles (binaire strict — user dixit) :
        - int / float / bool / None → False (jamais anonymisé)
        - string vide ou whitespace → False
        - string de len < 2 → False (pollution substring, ex: "X")
        - string purement numérique ("123", "-45.67", "1e10", "42%") → False
        - string date-like ("2023/2024", "2024-10-15") → False
        - sentinelle structurelle ("true", "false", "null", "N/A", etc.) → False
        - autre string → True (à anonymiser)

        Remarque : on NE teste PAS si c'est "schéma" vs "data" ici — ça se
        joue au niveau du call-site (seules les VALEURS sont extraites du
        classeur pour construire la table ; les noms de colonnes ne
        passent jamais par ici).
        """
        if not isinstance(v, str):
            return False
        if _is_empty_or_whitespace(v):
            return False
        if len(v.strip()) < _MIN_ANONYMIZABLE_LENGTH:
            return False
        if _is_numeric_literal(v):
            return False
        if _is_date_like(v):
            return False
        if _is_structural_sentinel(v):
            return False
        return True

    # -- Table construction ----------------------------------------------------

    def add_value(self, cleartext: str) -> str:
        """Ajoute `cleartext` à la table (whole value uniquement) et retourne
        son token anonymisé.

        **Whole-value only** (fix 2026-04-21) : on n'ajoute PLUS les sous-tokens
        d'une valeur multi-mots. Une cellule contenant ``"Le CA et le ratio"``
        insère UN seul token pour la phrase complète — pas 5 tokens pour
        chacun des mots. Raison : les sous-tokens polluaient la table avec
        des mots de liaison français (que, les, avec, et, le, la…) qui
        apparaissent aussi dans l'instruction utilisateur, transformant
        ``"pour anne"`` en ``"§pour_xxx§ §nn_yyy§"`` sans gain de
        confidentialité (ces mots ne sont pas sensibles).

        Trade-off accepté : si l'utilisateur tape partiellement un nom
        composé (ex: ``"ACME"`` alors que le whole est ``"ACME CORP"``),
        il ne sera pas anonymisé. C'est le prix d'une instruction propre.
        La confidentialité des DONNÉES INTERNES reste intacte : chaque
        valeur non-numérique de cellule est anonymisée en tant que whole.

        Idempotent : re-appeler avec le même cleartext retourne le même token.
        Collision (2 cleartexts → même token base) : disambiguation via suffixe.
        """
        if not self.is_anonymizable_value(cleartext):
            return cleartext
        return self._add_single(cleartext)

    def _add_single(self, cleartext: str, category: Optional[str] = None) -> str:
        """Insère UN cleartext dans la table (sans tokenisation récursive).

        Utilisé en interne par add_value (whole) ET pour chaque token
        multi-mots. Classifier déjà appliqué par l'appelant.

        Collision handling : si `_make_token(cleartext, category)` produit
        un base_token déjà attribué à un AUTRE cleartext, on incrémente le
        suffix via `_make_token(cleartext, category, suffix=N)` — qui
        insère proprement le suffix AVANT la sentinelle fermante,
        garantissant que le token reste bien encadré `§…_N§`.

        Args:
            cleartext: terme à anonymiser.
            category: catégorie BDD optionnelle pour produire un label
                sémantique dans le token (``§EMAIL_4b3a§`` au lieu de
                ``§TERM_4b3a§``). ``None`` → label ``"TERM"``.
        """
        existing = self._forward.get(cleartext)
        if existing is not None:
            return existing
        token = _make_token(cleartext, category=category)
        suffix = 2
        while token in self._token_seen:
            token = _make_token(cleartext, category=category, suffix=suffix)
            suffix += 1
        self._forward[cleartext] = token
        self._reverse[token] = cleartext
        self._token_seen.add(token)
        self._fwd_pattern = None
        self._rev_pattern = None
        return token

    def add_mapping(
        self,
        term: str,
        pseudo_middle: Optional[str],
        category: Optional[str] = None,
    ) -> str:
        """Insère un mapping EXPLICITE ``term → §pseudo_middle§``.

        Mode d'usage du ``Pseudonymizer`` piloté par l'utilisateur (via
        :mod:`app.services.anonymization.extract`) : l'utilisateur choisit pour
        chaque terme de son classeur s'il souhaite l'anonymiser, et avec
        quelle chaîne sémantique. Ce point d'entrée insère la paire
        directement — **sans passer par le classifier** ``is_anonymizable_value``
        (l'utilisateur a le droit d'anonymiser un nombre, une date, ou un
        code court si c'est un identifiant dans son contexte).

        - Si ``pseudo_middle`` est ``None`` ou chaîne vide → auto-gen via
          :func:`_make_token` au format ``§{LABEL}_{md5[:4]}§`` où ``LABEL``
          est dérivé de ``category`` (``EMAIL``, ``PHONE``, …, ``TERM``).
          Idempotent sur re-appel avec le même ``term`` (et même
          ``category``, qui ne change pas l'output puisque cleartext +
          category déterminent uniquement le token).
        - Sinon → token final = ``§{pseudo_middle}§`` (la ``category`` est
          IGNORÉE quand un middle est explicitement fourni : l'utilisateur
          a choisi son propre label, on ne le surcharge pas). Le middle ne
          doit PAS contenir ``§`` (sinon on pourrait construire des tokens
          imbriqués qui cassent la regex reverse).

        Levée ``ValueError`` si :

        - ``term`` n'est pas une string non vide.
        - ``pseudo_middle`` contient un ``§`` (violation d'invariant).
        - Le token final ``§pseudo_middle§`` est déjà attribué à un AUTRE
          cleartext (collision de bijection).

        Retourne le token final (avec sentinelles) qui sera substitué dans
        les payloads envoyés au LLM.
        """
        if not isinstance(term, str) or not term:
            raise ValueError("add_mapping: term must be a non-empty string")

        # Middle vide / None → délègue à l'auto-gen catégorie-aware.
        if pseudo_middle is None or pseudo_middle == "":
            return self._add_single(term, category=category)

        if not isinstance(pseudo_middle, str):
            raise ValueError("add_mapping: pseudo_middle must be a string or None")
        if _SENTINEL in pseudo_middle:
            raise ValueError(f"add_mapping: pseudo_middle must not contain sentinel {_SENTINEL!r}")

        token = f"{_SENTINEL}{pseudo_middle}{_SENTINEL}"

        # Idempotent si le même term est re-mappé au même middle.
        existing = self._forward.get(term)
        if existing == token:
            return token

        # Collision : le token final cible déjà un AUTRE cleartext dans
        # `_reverse`. On refuse — la bijection serait cassée.
        owner = self._reverse.get(token)
        if owner is not None and owner != term:
            raise ValueError(
                f"add_mapping: token {token!r} already bound to a different term "
                f"({owner!r}) — pseudo_middle collision"
            )

        # Si `term` avait déjà un mapping auto-généré et qu'on le ré-affecte
        # à un middle custom, on nettoie l'ancien token du reverse avant de
        # poser le nouveau. Sinon le reverse garderait une entrée orpheline
        # qui pourrait dé-anonymiser à tort.
        if existing is not None and existing != token:
            self._reverse.pop(existing, None)
            self._token_seen.discard(existing)

        self._forward[term] = token
        self._reverse[token] = term
        self._token_seen.add(token)
        self._fwd_pattern = None
        self._rev_pattern = None
        return token

    def build_table_from_tabs(
        self,
        tabs_context: Optional[List[Dict[str, Any]]],
    ) -> None:
        """Scanne `tabs_context` et peuple la table avec toutes les strings
        business value rencontrées.

        Sources scannées (seulement les VALEURS, jamais les KEYS) :
        - `tab.label` (string entière, potentiellement multi-mots)
        - `tab.sheet_content[i].value` si string
        - `tab.sheet_content[i].match[k]` si string (valeurs dims)
        - `tab.col_distinct[col].values[i]` si string
        - `tab.sheet_content[i].label` si string (labels structurels de cells)

        Ne scanne PAS :
        - `tab.columns` (noms de colonnes = schéma)
        - `tab.sql` (query brute — laissée au SQL anonymizer si besoin)
        - Les KEYS des dicts (ex: `match.keys()` = noms de colonnes)
        """
        if not tabs_context:
            return
        for tab in tabs_context:
            if not isinstance(tab, dict):
                continue
            # Tab label (potentiellement multi-mots, peut contenir du PII)
            label = tab.get("label")
            if isinstance(label, str):
                self.add_value(label)
            # Sheet content cells
            for cell in tab.get("sheet_content") or []:
                if not isinstance(cell, dict):
                    continue
                val = cell.get("value")
                if isinstance(val, str):
                    self.add_value(val)
                # Labels structurels de cell (ex: "Ratio de couverture")
                cell_label = cell.get("label")
                if isinstance(cell_label, str):
                    self.add_value(cell_label)
                # Match dims (valeurs, pas keys)
                match = cell.get("match")
                if isinstance(match, dict):
                    for mv in match.values():
                        if isinstance(mv, str):
                            self.add_value(mv)
                        elif isinstance(mv, list):
                            # match en IN avec list de valeurs
                            for item in mv:
                                if isinstance(item, str):
                                    self.add_value(item)
            # col_distinct values
            col_distinct = tab.get("col_distinct")
            if isinstance(col_distinct, dict):
                for info in col_distinct.values():
                    if not isinstance(info, dict):
                        continue
                    values = info.get("values")
                    if isinstance(values, list):
                        for v in values:
                            if isinstance(v, str):
                                self.add_value(v)

    # -- Substitution ----------------------------------------------------------

    def _build_patterns(self) -> None:
        """Compile les regex fwd/rev avec longest-match-first + lookarounds.

        - `longest-match-first` : une valeur multi-mots matche avant un
          de ses sous-tokens quand les deux pourraient s'appliquer.
        - **Lookarounds** `(?<![A-Za-z0-9_])…(?![A-Za-z0-9_])` : plus sûrs
          que `\\b` pour les keys qui commencent/finissent par un non-word
          char (ex: clé avec `/` terminal). Empêche qu'un token court
          substitue à l'intérieur d'un mot plus long.
        - `re.escape` protège des méta-chars (`/`, `$`, `.`) dans les clés.

        **Pas de fallback** : si le compile échoue (ex: alternation trop
        longue), on RAISE. Zéro fallback silencieux — respect règle "fail
        loud plutôt que leak silencieux".

        Pour le REVERSE pattern : pas besoin de lookarounds — les tokens
        sont encadrés de sentinelles `§…§`, donc déjà exempts de collision
        substring. On garde une regex simple qui match `§…§` exact.
        """

        def _expand_accent(token: str) -> str:
            # Chaque lettre accentuable devient une classe ``[base+variantes]``
            # pour que la regex DÉTECTE le candidat quelle que soit la forme
            # accentuée présente dans le texte source (``"Crédit"`` config doit
            # matcher ``"CREDIT"`` Sage, et inversement). La résolution du token
            # se fait ensuite via l'index canonique ``_forward_ci`` qui partage
            # la même notion de base. cf. :func:`_char_to_accent_class`.
            return "".join(_char_to_accent_class(c) for c in token)

        def _key_to_pattern(k: str) -> str:
            # ``k.split()`` découpe sur TOUT run de whitespace (interne ET
            # bords) → on tolère le double espace, le tab, le padding CHAR de
            # SQL Server, ET on neutralise un éventuel whitespace de bord, pour
            # rester cohérent avec ``_canonical_key_runtime`` (qui strip les
            # bords via le même ``split``) — sinon la regex inclurait un espace
            # littéral de bord que l'index canonique a retiré. Chaque token est
            # ensuite étendu en classes accent-insensibles. Même classe de fuite
            # PII que la casse/accents (variation BDD↔config).
            return r"\s+".join(_expand_accent(p) for p in k.split())

        def _compile_forward(keys: List[str]) -> Optional[re.Pattern[str]]:
            if not keys:
                return None
            sorted_keys = sorted(keys, key=len, reverse=True)
            escaped = "|".join(_key_to_pattern(k) for k in sorted_keys)
            # IGNORECASE : "Sofigec Pap" configuré doit matcher "SOFIGEC PAP"
            # renvoyé par la BDD source, sinon le vrai nom fuite en clair au
            # LLM. La résolution du token passe par `_forward_ci` (index
            # canonique case+whitespace) car m.group(0) peut différer de la
            # clé par la casse ou l'espacement.
            return re.compile(
                r"(?<![A-Za-z0-9_])(?:" + escaped + r")(?![A-Za-z0-9_])",
                re.IGNORECASE,
            )

        def _compile_reverse(tokens: List[str]) -> Optional[re.Pattern[str]]:
            if not tokens:
                return None
            sorted_tokens = sorted(tokens, key=len, reverse=True)
            escaped = "|".join(re.escape(t) for t in sorted_tokens)
            # Les tokens commencent/finissent par §, donc pas d'ambiguïté
            # substring. Pattern alternation simple.
            return re.compile("(?:" + escaped + ")")

        # Index canonique pour la résolution case/accent-insensible du forward
        # (cf. _resolve_forward). First-wins sur collision canonique : les
        # termes /data-privacy sont dédupés par _canonical_key (qui retire
        # désormais les accents) côté BDD, donc collision quasi-nulle au
        # runtime ; côté classeur, deux variantes de casse/accent de la MÊME
        # valeur partagent alors un token (acceptable : même entité).
        forward_ci: Dict[str, str] = {}
        for _cleartext, _token in self._forward.items():
            forward_ci.setdefault(_canonical_key_runtime(_cleartext), _token)
        self._forward_ci = forward_ci

        self._fwd_pattern = _compile_forward(list(self._forward.keys()))
        self._rev_pattern = _compile_reverse(list(self._reverse.keys()))

    def anonymize_text(self, text: str) -> str:
        """Substitue dans `text` toutes les occurrences de valeurs en table
        par leur token anonymisé. Le texte revient inchangé si aucune
        correspondance. Le matching est case-, accent- et whitespace-insensible
        (cf. :meth:`_resolve_forward`) : la BDD source peut renvoyer une valeur
        dans une casse / un accent ≠ de ceux configurés dans /data-privacy
        (``"CREDIT"`` vs ``"Crédit"``)."""
        if not isinstance(text, str) or not text:
            return text
        if self._fwd_pattern is None:
            self._build_patterns()
        if self._fwd_pattern is None:
            return text
        return self._fwd_pattern.sub(self._resolve_forward, text)

    def _resolve_forward(self, m: "re.Match[str]") -> str:
        """Résout le token anonymisé pour un match forward.

        1. Match EXACT d'abord (`_forward`) — préserve le comportement
           historique quand la casse ET l'accent coïncident.
        2. Fallback CASE/ACCENT/WHITESPACE-INSENSIBLE via l'index canonique
           `_forward_ci` (NFKD strip-accents + casefold + collapse whitespace)
           — couvre le cas critique où la valeur Sage ("SOFIGEC  PAP",
           "CREDIT") diffère par la casse, l'accent et/ou l'espacement du terme
           configuré ("Sofigec Pap", "Crédit"). Sans ça, le vrai nom partait en
           clair au LLM.
        3. Aucun token résolu : inatteignable pour les variations
           casse/accent/whitespace (couvertes par `_forward_ci`) ; ne reste
           qu'un cas Unicode pathologique où le pattern matche là où
           NFKD+casefold diverge. FAIL-CLOSED — on RAISE (doctrine du module :
           "fail loud plutôt que leak silencieux") : le pattern a identifié une
           valeur sensible qu'on ne sait pas masquer → on REFUSE de la laisser
           partir en clair. Le caller (anonymize_for_llm) remonte l'erreur,
           comme pour un terme manquant dans `_load_user_pseudonymizer`.
        """
        matched = m.group(0)
        token = self._forward.get(matched)
        if token is not None:
            return token
        token = self._forward_ci.get(_canonical_key_runtime(matched))
        if token is not None:
            return token
        raise RuntimeError(
            "Pseudonymizer: valeur matchée sans token résolu "
            f"({matched!r}) — refus fail-closed pour éviter une fuite PII au "
            "LLM (désync pattern/table, cas Unicode non normalisable)."
        )

    def deanonymize_text(self, text: str) -> str:
        """Substitue dans `text` toutes les occurrences de tokens anonymisés
        par leur cleartext."""
        if not isinstance(text, str) or not text:
            return text
        if self._rev_pattern is None:
            self._build_patterns()
        if self._rev_pattern is None:
            return text
        return self._rev_pattern.sub(
            lambda m: self._reverse[m.group(0)],
            text,
        )

    # -- Recursive anonymize/deanonymize for structured payloads ---------------

    def anonymize(self, obj: Any) -> Any:
        """Récursion sur dict/list/tuple/set. Strings substituées via
        `anonymize_text`. Ne MODIFIE PAS les keys des dicts (= colonnes,
        champs structurels). Booléens et None inchangés.

        **Numériques (int/float)** : si leur représentation string est
        présente dans la table forward (l'utilisateur les a explicitement
        marqués à anonymiser via le panneau, ex: un numéro de téléphone,
        un SIREN, un identifiant numérique sensible), on retourne la
        substitution ``§pseudo§`` SOUS FORME DE STRING. Sinon on les
        retourne inchangés (number).

        Avantage : permet d'anonymiser les valeurs numériques sélectionnées
        par l'utilisateur (le pipeline historique ignorait tous les
        numériques, rendant impossible la protection des identifiants).
        Coût : la valeur transite alors en string dans le payload LLM —
        le LLM JSON voit ``"§CLIENT_A§"`` au lieu de ``42``. Au
        dé-anonymisation, on retombe sur une string ``"42"`` — minor
        UX issue, acceptable face au bénéfice de confidentialité.
        """
        if isinstance(obj, str):
            return self.anonymize_text(obj)
        if isinstance(obj, dict):
            return {k: self.anonymize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.anonymize(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.anonymize(v) for v in obj)
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, (int, float)):
            as_str = str(obj)
            # Lookup direct sans regex : la valeur numérique ne contient
            # aucun séparateur → elle serait soit matchée telle quelle par
            # ``anonymize_text``, soit pas du tout. ``anonymize_text``
            # marche mais on peut court-circuiter via ``_forward`` direct.
            token = self._forward.get(as_str)
            return token if token is not None else obj
        return obj

    def deanonymize(self, obj: Any) -> Any:
        """Inverse de `anonymize` : substitue tokens → cleartext récursivement."""
        if isinstance(obj, str):
            return self.deanonymize_text(obj)
        if isinstance(obj, dict):
            return {k: self.deanonymize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.deanonymize(v) for v in obj]
        if isinstance(obj, tuple):
            return tuple(self.deanonymize(v) for v in obj)
        return obj

    # -- Introspection ---------------------------------------------------------

    def __len__(self) -> int:
        """Nombre d'entrées dans la table (pour debug/metrics)."""
        return len(self._forward)

    def export_token_mapping(self) -> Dict[str, str]:
        """Retourne un dict ``{token: cleartext}`` pour restore externe.

        ⚠️ **Ne jamais loguer en clair** — contient les valeurs réelles
        de l'utilisateur. Usage prévu : caller streaming (ex: SSE provider)
        qui doit déanonymiser une réponse assemblée *après* la fin du stream
        sans pouvoir conserver l'instance Pseudonymizer (qui charge BDD).

        L'inverse (cleartext → token) est exposé via :meth:`anonymize_text`
        — pas d'export direct car la primitive métier est l'anonymisation,
        pas l'introspection cleartext.
        """
        return {token: cleartext for cleartext, token in self._forward.items()}

    def describe(self) -> Dict[str, int]:
        """Diagnostic non-identifiant : nb d'entrées, longueur min/max/avg
        des cleartext. Ne RETOURNE pas les valeurs réelles (non loggable en
        clair sans fuite)."""
        if not self._forward:
            return {"entries": 0}
        lens = [len(k) for k in self._forward.keys()]
        return {
            "entries": len(self._forward),
            "min_len": min(lens),
            "max_len": max(lens),
            "avg_len": sum(lens) // len(lens),
        }


def iter_string_values(tabs_context: Iterable[Dict[str, Any]]) -> Iterable[str]:
    """Helper itérant sur toutes les strings business value d'un tabs_context
    (utile pour tests / debug). Même règle d'extraction que
    `Pseudonymizer.build_table_from_tabs`."""
    for tab in tabs_context:
        if not isinstance(tab, dict):
            continue
        label = tab.get("label")
        if isinstance(label, str) and Pseudonymizer.is_anonymizable_value(label):
            yield label
        for cell in tab.get("sheet_content") or []:
            if not isinstance(cell, dict):
                continue
            val = cell.get("value")
            if isinstance(val, str) and Pseudonymizer.is_anonymizable_value(val):
                yield val
            cell_label = cell.get("label")
            if isinstance(cell_label, str) and Pseudonymizer.is_anonymizable_value(cell_label):
                yield cell_label
            match = cell.get("match")
            if isinstance(match, dict):
                for mv in match.values():
                    if isinstance(mv, str) and Pseudonymizer.is_anonymizable_value(mv):
                        yield mv
                    elif isinstance(mv, list):
                        for item in mv:
                            if isinstance(item, str) and Pseudonymizer.is_anonymizable_value(item):
                                yield item
        col_distinct = tab.get("col_distinct")
        if isinstance(col_distinct, dict):
            for info in col_distinct.values():
                if not isinstance(info, dict):
                    continue
                values = info.get("values")
                if isinstance(values, list):
                    for v in values:
                        if isinstance(v, str) and Pseudonymizer.is_anonymizable_value(v):
                            yield v


# ---------------------------------------------------------------------------
# Chokepoint : conversion compute-side de cellules potentiellement anonymisées
# ---------------------------------------------------------------------------
#
# Contexte du bug que ce helper corrige (audit 2026-04-27) : ``ctx.tabs_context``
# transporte les valeurs cellules en mode anonymisé tant que le run copilot est
# en cours (pour que le LLM voie des tokens cohérents). Plusieurs consommateurs
# côté MOTEUR (``_recompute_emit_tab``, ``_aggregate_core``,
# ``_evaluate_derived_formulas``, etc.) itèrent ces mêmes ``sheet_content`` et
# tentent ``float(value)`` direct. Si l'utilisateur a explicitement anonymisé
# un nombre via ``add_mapping`` (chemin documenté qui bypass ``is_anonymizable_value``),
# la valeur arrive en string ``"§515838.05_8a9§"`` → ``float()`` lève ``ValueError``
# → ``except: continue`` silencieux → la row contribue 0 au SUM, sans aucun log.
# Résultat : cellules calculées avec valeurs FAUSSES mais plausibles.
#
# Ce chokepoint :
#   1. Tente le parse direct (cas nominal : valeur déjà numérique cleartext).
#   2. Si la valeur est une string contenant une sentinelle ``§``, désanonymise
#      via le pseudonymizer fourni puis re-parse.
#   3. Si tout échoue → log WARNING détaillé + retourne ``None`` (le caller
#      doit traiter ``None`` = "row à skipper" comme avant, mais le silence est
#      brisé : le warning rend le bug VISIBLE, plus jamais silencieux).
#
# Tous les consommateurs côté moteur DOIVENT passer par ici, jamais
# ``float(sc_cell["value"])`` direct. Convention enforced par tests + grep CI.


def coerce_to_numeric(
    val: Any,
    pseudonymizer: Optional["Pseudonymizer"] = None,
    context_hint: str = "",
) -> Optional[float]:
    """Convertit une valeur de cellule en float, en gérant transparemment les
    tokens anonymisés ``§...§``.

    Args:
        val: La valeur brute de la cellule (ex: ``sc_cell.get("value")``).
        pseudonymizer: Pseudonymizer actif du run copilot, si dispo. Si ``None``
            (handler hors-copilot, test sans anon, etc.), seul le parse direct
            est tenté — un token-shape ``§...§`` retournera ``None`` + WARNING.
        context_hint: String courte décrivant le call-site (ex:
            ``"_aggregate_core col=totalMontant"``). Apparaît dans le WARNING
            pour aider à localiser le caller fuyant.

    Returns:
        ``float(val)`` si parseable (directement ou après déanonymisation),
        sinon ``None`` après avoir loggué un WARNING.

    Sémantique distinctive :
        - ``None`` en entrée → ``None`` en sortie (cellule vide, no-op silencieux).
        - ``bool`` en entrée → ``None`` (Python ``True == 1`` mais une valeur
          booléenne dans ``sheet_content`` est un signal d'erreur, on ne la
          coerce pas en 1.0 implicitement).
        - String parseable directement → ``float(string.strip())``.
        - String token (matche ``§...§``) → tente ``deanonymize_text`` puis re-parse.
        - Tout autre cas → ``None`` + WARNING.
    """
    if val is None:
        return None
    if isinstance(val, bool):
        # Python : bool est sous-classe de int (True == 1). Refus explicite —
        # une bool dans sheet_content[].value est un bug du producteur, on ne
        # le maquille pas en 1.0.
        return None
    if isinstance(val, (int, float)):
        # Contrat : ne JAMAIS renvoyer un float non-fini. ``coerce_to_numeric``
        # sert l'agrégation (``_aggregate_core`` fait ``total += numeric_val``) ;
        # un seul ``float('nan')`` empoisonnerait toute la somme silencieusement
        # (FAUSSE) et ``inf`` la rendrait infinie. Un ``nan`` peut atteindre ce
        # helper via un ``.afz.json`` (``json`` Python sérialise/relit ``NaN``
        # par défaut). int ne peut pas être non-fini ; le check ne mord que sur
        # float. Cohérent avec la branche Decimal ci-dessous (parité #149).
        f = float(val)
        return f if math.isfinite(f) else None
    if isinstance(val, Decimal):
        # Decimal = colonnes MONEY/NUMERIC/DECIMAL SQL Server (pyodbc).
        # Defense-in-depth (#147/#148) : aujourd'hui les cellules sheet_content
        # sont déjà des float (converties par _coerce_number_or_str au load
        # .afz.json), donc ce helper d'agrégation reçoit du float — mais si un
        # caller futur passe un Decimal natif, sans cette branche il tomberait
        # dans « type inattendu → None » et la cellule serait droppée de la
        # SOMME silencieusement (FAUSSE). NaN/inf filtrés : ils empoisonneraient
        # un sum() (contexte agrégation, ≠ comparaison #148).
        try:
            f = float(val)
        except (ValueError, OverflowError):
            return None
        return f if math.isfinite(f) else None
    if isinstance(val, str):
        # Cas nominal : string numérique cleartext.
        stripped = val.strip()
        try:
            f = float(stripped)
        except ValueError:
            pass
        else:
            # Contrat « jamais non-fini » : "nan"/"inf" littéral n'est pas une
            # valeur d'agrégation → on NE retourne pas, on tombe au warning→None.
            if math.isfinite(f):
                return f
        # Token-shape ? tente déanonymisation puis re-parse.
        if pseudonymizer is not None and _TOKEN_SHAPE_RE.search(stripped):
            try:
                cleartext = pseudonymizer.deanonymize_text(stripped)
            except Exception as exc:  # pragma: no cover — defensive
                logger.warning(
                    "coerce_to_numeric: deanonymize_text crashed (%s) on val=%r "
                    "context=%s — fail-loud, returning None",
                    exc,
                    stripped,
                    context_hint,
                )
                return None
            if cleartext != stripped:
                try:
                    f = float(cleartext.strip())
                except ValueError:
                    pass
                else:
                    if math.isfinite(f):
                        return f
        # Échec final : surface le bug, ne reste pas silencieux.
        logger.warning(
            "coerce_to_numeric: valeur non-parseable comme float (val=%r, "
            "context=%s). Si elle ressemble à un token §...§, vérifier que "
            "le pseudonymizer est passé au consommateur — sinon la row est "
            "skippée silencieusement et la cellule calculée est FAUSSE. "
            "Cf. audit anon-leaks 2026-04-27.",
            val,
            context_hint,
        )
        return None
    # Type inattendu (list, dict, etc.) — on ne tente rien.
    logger.warning(
        "coerce_to_numeric: type inattendu pour value (%s), context=%s",
        type(val).__name__,
        context_hint,
    )
    return None
