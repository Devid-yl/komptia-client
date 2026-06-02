"""Gestion du dictionnaire de termes à anonymiser *piloté par l'utilisateur*.

Ce module remplace le comportement historique du ``Pseudonymizer`` qui
construisait automatiquement sa table à partir de toutes les strings d'un
classeur. Le modèle actuel (v3) :

1. **Le SYSTÈME** tokenise le contenu du classeur en ``tokens`` (mot-par-mot,
   numériques inclus) via :func:`extract_terms`.
2. **L'UTILISATEUR** choisit explicitement, dans un panneau frontend, quels
   tokens doivent être anonymisés et avec quel pseudonyme « sémantique ».
3. Le résultat est persisté en **base de données locale** (table
   ``anonymization_terms``, repository async dans
   :mod:`app.services.anonymization.repository`) — une rangée par
   ``(user_id, term)``, ce qui permet le partage cross-classeur (un terme
   anonymisé dans un classeur l'est aussi dans les autres pour le même user).
4. :func:`reconcile_state` ajoute les nouveaux tokens du classeur courant au
   state complet stocké. Les termes absents du classeur courant mais présents
   en BDD SONT CONSERVÉS (ils peuvent provenir d'autres classeurs) — seul
   le job de cleanup quotidien
   (:func:`app.services.anonymization.cleanup_job.cleanup_unused_anonymization_terms_job`)
   supprime, avec la vue cross-classeur nécessaire (union de tous les
   classeurs du datastore utilisateur).
5. :func:`build_user_pseudonymizer` instancie un ``Pseudonymizer`` à partir du
   state confirmé + ``enabled`` + (optionnellement) scoped aux tokens du
   classeur courant pour économiser la regex de substitution. Le flux dans
   ``copilot_agent`` reste identique en aval (anonymize → LLM → deanonymize).

Contrat côté wire (state JSON v1) ::

    {
      "version": 1,
      "terms": {
        "<token>": {
          "pseudo": "<middle>",   // optionnel — absent ⇒ auto-généré
          "enabled": <bool>,      // anonymiser vs laisser clair
          "confirmed": <bool>     // utilisateur a tranché
        },
        ...
      }
    }

- ``<token>`` = cleartext d'un terme trouvé dans une cellule. Dedup globale
  cross-onglets et cross-classeurs pour un même user.
- ``<middle>`` = partie sémantique que l'utilisateur tape (ex: ``"CLIENT_A"``).
  Le Pseudonymizer l'encadre en ``§CLIENT_A§`` à la substitution pour garantir
  que le LLM ne confonde pas avec du langage naturel.
- ``enabled=False, confirmed=True`` = l'utilisateur a décidé de ne PAS
  anonymiser ce terme (ex: catégorie publique, label structurel). Ne trigger
  pas le gate.
- ``enabled=True, confirmed=False`` = état intermédiaire théorique ; en
  pratique le frontend ne peut pas produire cette combinaison (confirmer
  = poser ``confirmed=True`` sur l'ensemble).

**Principes de design**
-----------------------

- **Tokenizer partagé JS↔Py** : :data:`TOKEN_SPLIT_RE` doit rester STRICTEMENT
  identique à la regex ``/[^\\s,;:]+/gu`` côté ``static/js/iris-grid.js``.
  Drift = le gate backend refuse des termes que le frontend n'a pas montrés.
  Contrat exécutable dans ``tests/unit/test_anon_terms.py`` +
  fixture partagée ``tests/fixtures/anon_tokenizer_contract.json``.
- **Fail-closed** : toute anomalie (state mal formé, pending non résolu,
  pseudos en collision) retourne soit une erreur explicite à l'utilisateur,
  soit un pseudonymizer VIDE (aucune protection mais aucune corruption
  silencieuse). JAMAIS de fallback vers l'ancien comportement auto.
- **Source de vérité = BDD** (SQLCipher chiffré) : chaque requête copilot
  lit le state via le repository. Le frontend tient un CACHE local, rafraîchi
  via ``GET /api/anonymization/terms`` au boot du grid et après chaque PUT.
- **Numériques inclus** : la demande utilisateur est explicite. Un nombre
  peut être un identifiant (SIREN, téléphone, compte bancaire). Le classifier
  :func:`is_auto_decidable` pré-range les numériques courts / dates / marqueurs
  structurels avec ``confirmed=True, enabled=False`` pour réduire le bruit UX.
  L'utilisateur peut toujours enabler manuellement.

**Portée et non-portée**
------------------------

- ✅ Utilisé par ``copilot_agent`` (endpoint ``/api/iris/result-modify``).
- ✅ Utilisé par ``AnonymizationTermsAPIHandler`` (endpoints
  ``GET/PUT /api/anonymization/terms``) via le repository.
- ✅ Utilisé par le cleanup job nocturne (03:30).
- ❌ PAS utilisé par ``copilot_iris_bridge`` : quand Iris retourne des rows
  Sage inconnues du state, le bridge appelle ``Pseudonymizer.add_value()``
  en mode éphémère (auto-sentinellé). Ces valeurs vivent le temps d'UN run
  et ne fuient pas dans le state utilisateur (elles réapparaîtront au
  prochain cycle via ``extract_terms`` si elles finissent dans un tab émis).
- ❌ PAS utilisé par Iris (l'agent SQL) : sous-système distinct, propre
  stratégie de confidentialité.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import re
from typing import Any, Dict, Final, Iterable, List, Optional, Set, Tuple

from app.services.anonymization import patterns as anon_patterns
from app.services.anonymization.pseudonymizer import Pseudonymizer

logger = logging.getLogger(__name__)


# --- Constantes partagées -----------------------------------------------------

#: Regex de découpage des cellules en tokens. Chaque token = run maximal de
#: caractères qui ne sont NI whitespace NI ``,;:``. ``-`` ``.`` ``/`` ``_``
#: sont PRÉSERVÉS dans un token pour garder :
#: - les floats signés / décimaux : ``"-1.5"`` → un seul token
#: - les dates : ``"2024-10-15"`` → un seul token
#: - les compounds : ``"Client-Serveur"`` → un seul token
#: - les paths : ``"a/b/c"`` → un seul token (l'utilisateur peut choisir
#:   d'anonymiser ou non ; s'il veut séparer, il doit passer par
#:   l'interface — pas par un split pré-fait qui lui forcerait la main)
#:
#: **Whitespace explicite (BLOCKING #12 review)** : ``\s`` Python et
#: ``\s`` JS-mode ``u`` ne couvrent pas exactement les mêmes points de
#: code Unicode (cas exotiques : `` `` narrow no-break space, etc.).
#: On liste explicitement les whitespace usuels rencontrés en compta
#: (espace ASCII, tab, NL/CR, NBSP `` ``, NNBSP `` ``, line
#: separator `` ``, paragraph separator `` ``). NBSP est
#: spécialement fréquent dans les exports Excel/CSV des cabinets.
#:
#: **MIROIR OBLIGATOIRE dans ``static/js/anonymization/tokenizer.js``** —
#: la liste de chars whitespace doit être STRICTEMENT IDENTIQUE des deux
#: côtés. Si l'une bouge, l'autre DOIT bouger (sinon gate 409 cassé +
#: drift Py↔JS détecté par ``test_anon_tokenizer_js.py``).
TOKEN_SPLIT_RE = re.compile(r"[^\s    ,;:]+")

#: Taille max (chars) d'une valeur acceptée par le tokenizer. Cohérent avec
#: ``copilot_iris_bridge._MAX_ANONYMIZABLE_LEN = 500``. Au-delà on considère
#: que c'est un blob (JSON encodé, texte libre massif) — le coût regex et
#: la pertinence de l'anonymisation s'effondrent.
MAX_VALUE_LEN = 500

#: Estimation moyenne de l'empreinte BDD d'un terme d'anonymisation, en
#: octets (row ``anonymization_terms`` complète : term + pseudo + flags +
#: origins JSON + timestamps + indexes). Mesurée empiriquement 2026-05-19
#: sur dataset réel cabinet. Utilisé par :func:`get_user_term_cap` pour
#: dériver le cap dynamique depuis ``UserStorage.quota_limit``.
BYTES_PER_TERM_ESTIMATE = 200

#: Hard cap absolu, indépendant de tout quota user — anti-DoS RAM/CPU
#: garanti même si un admin met ``quota_limit`` à une valeur démesurée.
#: 5 M termes × 200 bytes ≈ 1 Go BDD/user, plafond technique.
#:
#: Garde-fou de DERNIER recours. Le cap RÉEL appliqué à chaque user est
#: calculé dynamiquement par :func:`get_user_term_cap` depuis
#: ``UserStorage.quota_limit - quota_used - db_bytes_used``, ce qui aligne
#: l'anonymisation sur la promesse "le seul cap c'est le quota disque"
#: (décision 2026-05-19).
MAX_STATE_TERMS_HARD_CAP = 5_000_000

#: Floor : un user à 99 % de quota peut quand même ajouter quelques termes
#: critiques (PII en attente de revue). Évite le "bloqué silencieusement
#: parce que ton disque est plein" qui surprend l'utilisateur.
MAX_STATE_TERMS_MIN = 1_000

#: Alias rétrocompat : utilisé par les call-sites SYNCHRONES qui ne peuvent
#: pas appeler :func:`get_user_term_cap` (qui est async). Représente le
#: plafond absolu — le cap dynamique par user, généralement plus bas,
#: s'applique dans les call-sites async via :func:`get_user_term_cap`.
MAX_STATE_TERMS = MAX_STATE_TERMS_HARD_CAP

#: Version actuelle du schéma du state. Permet une migration future sans
#: silencieusement accepter un format inconnu.
STATE_VERSION = 1

#: Longueur max d'un pseudonyme (middle) que l'utilisateur peut taper. 128
#: couvre "CLIENT_A_SOUS_SECTION_EUROPE" sans ouvrir la porte à un payload.
MAX_PSEUDO_MIDDLE_LEN = 128

#: Regex : un pseudonyme middle (pré-sentinelles) doit être non vide,
#: raisonnablement typable, et surtout NE PAS contenir le caractère ``§``
#: (réservé aux sentinelles système). On autorise large : Unicode letters,
#: digits, underscore, hyphen, espace, point. Pas besoin d'être plus strict —
#: le middle ne transite qu'entre frontend et LLM.
_PSEUDO_MIDDLE_ALLOWED = re.compile(r"^[^§]+$")

#: Regex : détection d'une valeur purement numérique (incl. pourcents, devises,
#: floats signés, notation scientifique). Déléguée depuis ``pseudonymizer``
#: pour rester cohérente — si la logique évolue côté bijection, elle évolue
#: ici aussi (seule source de vérité : la même classification).
#:
#: **Single source of truth** côté backend ET frontend : la même regex est
#: répliquée dans ``static/js/anonymization/tokenizer.js`` (constante
#: ``NUMERIC_LIKE_RE``). Toute évolution de l'une DOIT être synchronisée
#: avec l'autre — sinon le tokenizer JS sélectionne un terme que le
#: backend skipperait (ou inversement).
_NUMERIC_LIKE_RE = re.compile(r"^-?\d+(?:[.,]\d+)?(?:[eE][-+]?\d+)?\s*[€$£%]?$")


def is_numeric_like(value: str) -> bool:
    """Vrai si ``value`` est purement numérique (avec format français +
    notation scientifique + suffixe monétaire/pourcent optionnel).

    Single source of truth pour "est-ce un nombre brut" — utilisée par :

    - :func:`is_auto_decidable` (auto-décision panneau utilisateur)
    - ``handlers.anonymization.AnonymizationImprovePseudoAPIHandler``
      (skip pré-LLM des termes sans sémantique à améliorer)
    - Frontend ``static/js/anonymization/tokenizer.js`` (sélection des
      candidats côté navigateur — même regex)

    Tolère les espaces autour de ``value``. Retourne ``False`` pour les
    strings vides.
    """
    if not value:
        return False
    return bool(_NUMERIC_LIKE_RE.match(value.strip()))


#: Dates et périodes : ``"2024-10-15"``, ``"10/2024"``, ``"2023/2024"``.
_DATE_LIKE_RE = re.compile(r"^\d{1,4}[-/.]\d{1,4}(?:[-/.]\d{1,4})?$")

#: Stoplist des tokens structurels (booléens, états, marqueurs vides). Ces
#: tokens ne sont jamais sensibles — on les auto-décide "laisser clair" pour
#: éviter le bruit dans le panneau utilisateur.
_STRUCTURAL_STOPLIST = {
    "true",
    "false",
    "none",
    "null",
    "n/a",
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
    "ko",
}


# --- Pré-filtres anti-pollution (tâche #11) ----------------------------------
#
# Avant tâche #11, ``extract_terms`` proposait à l'utilisateur la totalité des
# tokens scannés dans le classeur, y compris les mots-clés SQL (``SELECT``,
# ``FROM``, ``BY``, ``WHEN``…) qui peuvent apparaître dans les libellés des
# cellules ("Group by client", "Order date") et les mots français
# grammaticaux courants ("Le", "La", "Du", "Pour"…). Résultat : panneau
# inondé de termes à trier — l'utilisateur passe à côté des vrais
# identifiants à anonymiser. Calibration empirique 2026-05-07 sur un classeur
# réel : 307 termes proposés, dont >250 parasites.
#
# La sémantique de la *tokenisation* (``_tokenize_value``) n'est PAS modifiée
# (contrat partagé JS↔Py via ``anon_tokenizer_contract.json`` préservé). Le
# filtre s'applique au niveau d'``extract_terms`` (post-tokenize) — un token
# parasite n'est simplement pas proposé comme candidat à l'anonymisation.
# Si un token est déjà entré dans le state via un autre canal (PUT explicite,
# état hérité), il reste persisté et restituable — le filtre n'efface jamais
# de l'existant.

#: Mots français grammaticaux (articles, pronoms, conjonctions, prépositions,
#: salutations) qui ne sont jamais des identifiants métier. Title-case car
#: c'est la forme produite par ``_PROPER_NOUN_PATTERN`` côté
#: ``ConfidentialityManager.sanitize_user_input`` (legacy caller).
_FR_GRAMMATICAL_TITLE = frozenset(
    {
        "Le",
        "La",
        "Les",
        "Un",
        "Une",
        "Des",
        "Du",
        "De",
        "En",
        "Au",
        "Aux",
        "Et",
        "Ou",
        "Mais",
        "Donc",
        "Or",
        "Ni",
        "Car",
        "Par",
        "Pour",
        "Sur",
        "Sous",
        "Dans",
        "Avec",
        "Sans",
        "Entre",
        "Vers",
        "Chez",
        "Dès",
        "Lors",
        "Selon",
        "Malgré",
        "Pendant",
        "Depuis",
        "Avant",
        "Après",
        "Jusqu",
        "Je",
        "Tu",
        "Il",
        "Elle",
        "Nous",
        "Vous",
        "Ils",
        "Elles",
        "On",
        "Ce",
        "Cet",
        "Cette",
        "Ces",
        "Mon",
        "Ton",
        "Son",
        "Ma",
        "Ta",
        "Sa",
        "Mes",
        "Tes",
        "Ses",
        "Notre",
        "Votre",
        "Leur",
        "Nos",
        "Vos",
        "Leurs",
        "Qui",
        "Que",
        "Quoi",
        "Dont",
        "Où",
        "Quand",
        "Comment",
        "Pourquoi",
        "Quel",
        "Quelle",
        "Quels",
        "Quelles",
        "Tout",
        "Tous",
        "Toute",
        "Toutes",
        "Bonjour",
        "Bonsoir",
        "Merci",
        "Salut",
        "Cordialement",
        "Bonne",
        "Bon",
    }
)

#: Mois, jours et lieux courants. Conservés à part car le tokenizer
#: ``extract_terms`` ne les filtre PAS (un utilisateur peut vouloir
#: anonymiser ``OCTOBRE`` ou ``France`` selon le contexte de son
#: classeur). Ils restent dans le set unifié :data:`_COMMON_FRENCH_WORDS`
#: utilisé par le détecteur de noms propres legacy (``sanitize_user_input``)
#: où l'inverse est vrai : on veut éviter qu'un mois soit pris pour un
#: nom propre dans un texte libre utilisateur.
_FR_MONTHS_DAYS_PLACES_TITLE = frozenset(
    {
        "Janvier",
        "Février",
        "Mars",
        "Avril",
        "Mai",
        "Juin",
        "Juillet",
        "Août",
        "Septembre",
        "Octobre",
        "Novembre",
        "Décembre",
        "Lundi",
        "Mardi",
        "Mercredi",
        "Jeudi",
        "Vendredi",
        "Samedi",
        "Dimanche",
        "France",
        "Paris",
        "Europe",
    }
)

#: Mots-clés T-SQL et alias courants. Title-case (forme produite par les
#: éditeurs SQL Server / Sage). Le filtre tokenizer compare en lower donc
#: ``SELECT``, ``Select``, ``select`` sont tous écartés.
_SQL_KEYWORDS_TITLE = frozenset(
    {
        # Verbes / clauses
        "Select",
        "From",
        "Where",
        "And",
        "Not",
        "Join",
        "Left",
        "Right",
        "Inner",
        "Outer",
        "Cross",
        "Full",
        "With",
        "Case",
        "When",
        "Then",
        "Else",
        "End",
        "Cast",
        "By",
        "On",
        "As",
        "In",
        "Is",
        "If",
        # Aggregats / fenêtres
        "Sum",
        "Count",
        "Avg",
        "Min",
        "Max",
        "Over",
        "Partition",
        # Tri / regroupement
        "Order",
        "Group",
        "Having",
        "Union",
        "Distinct",
        "Top",
        "Offset",
        "Fetch",
        "Asc",
        "Desc",
        # DML / DDL
        "Insert",
        "Update",
        "Delete",
        "Create",
        "Alter",
        "Drop",
        "Table",
        "View",
        "Index",
        "Into",
        "Values",
        "Set",
        # Predicats
        "Null",
        "Like",
        "Between",
        "Exists",
        "All",
        "Any",
        # Date helpers
        "Year",
        "Month",
        "Day",
        # Types
        "Varchar",
        "Int",
        "Decimal",
        "Float",
        "Char",
        "Date",
        "Datetime",
        "Bit",
        "Nvarchar",
        "Bigint",
        "Smallint",
        "Numeric",
        # Aliases
        "Dbo",
    }
)

#: **Re-export historique** : union des trois sets ci-dessus. Conservé pour
#: le caller legacy ``ConfidentialityManager.sanitize_user_input`` qui s'en
#: sert pour exclure les mots usuels de la détection de noms propres dans
#: un texte libre utilisateur. Single source of truth = ce module.
_COMMON_FRENCH_WORDS = _FR_GRAMMATICAL_TITLE | _FR_MONTHS_DAYS_PLACES_TITLE | _SQL_KEYWORDS_TITLE

#: Stoplist abaissée pour le filtre tokenizer (lookup case-insensitive). N'inclut
#: PAS les mois/jours/lieux : un utilisateur peut légitimement vouloir anonymiser
#: ``OCTOBRE`` ou ``France`` dans son classeur (ex: nom de société "France SARL").
#: Le ``_STRUCTURAL_STOPLIST`` est aussi inclus pour que les sentinelles
#: ne survivent pas au cas où elles arriveraient en majuscules.
_TOKENIZER_STOPLIST_LOWER = (
    frozenset(w.lower() for w in _FR_GRAMMATICAL_TITLE)
    | frozenset(w.lower() for w in _SQL_KEYWORDS_TITLE)
    | frozenset(_STRUCTURAL_STOPLIST)
)

#: Tokens 100% non-alphanumériques (ponctuation pure : ``--``, ``==``, ``***``,
#: ``-->``, ``.._..``…). Le tokenizer accepte ces séquences car ``-`` ``.``
#: ``/`` ``_`` sont préservés dans un token. Mais une suite de ces caractères
#: seuls n'est jamais un identifiant métier — pollution panneau garantie.
#:
#: ``[\W_]`` (et non ``\W``) car Python considère ``_`` comme un word-char :
#: sans cette extension, ``"_"`` ou ``".._.."`` resterait un "candidat".
_PUNCTUATION_ONLY_RE = re.compile(r"^[\W_]+$", re.UNICODE)


#: Caractères qui, quand ils ouvrent un token, indiquent un fragment de
#: parsing (apostrophe d'élision FR coupée du mot suivant, parenthèses de
#: code SQL non-fermées, guillemets, brackets). Ces tokens sont des
#: artefacts du tokenizer face à du texte mixte (NL + SQL + ponctuation
#: collée), pas des identifiants métier. Ex vu en prod : ``'Ajoute``
#: (apostrophe-prefix), ``(CASE``, ``(GROUP``, ``(asc/desc)`` (parenthèses).
_TOKEN_BAD_PREFIX_CHARS = frozenset({"'", "‘", "’", "(", ")", "[", "]", "{", "}", '"', "«", "»"})


def _is_pollutant_token(tok: str) -> bool:
    """``True`` si ``tok`` est un parasite à exclure du panneau utilisateur.

    Filtre **uniquement** appliqué au niveau d'``extract_terms`` (catalogue
    proposé). N'altère pas la tokenisation elle-même (``_tokenize_value``)
    qui doit rester strictement alignée avec le mirror JS.

    Critères (en cascade) :

    1. ``_PUNCTUATION_ONLY_RE`` → ponctuation pure (ex: ``"--"``, ``"==>"``).
    2. **Préfixe ponctuation suspecte** : token commençant par ``'``, ``(``,
       ``[``, ``{``, ``"``, etc. → fragment de parsing (verbe FR avec
       apostrophe d'élision coupée, code SQL collé). Vu en prod :
       ``'Ajoute``, ``(CASE``, ``(GROUP``.
    3. ``tok.lower()`` ∈ :data:`_TOKENIZER_STOPLIST_LOWER` → SQL keyword,
       mot grammatical FR ou verbe impératif (``ajoute``, ``donne-moi``…).
       Lower-case car la cellule peut produire indifféremment ``"select"``,
       ``"Select"``, ``"SELECT"``.

    Ne filtre PAS :

    - Codes courts non-keyword (ex: ``"FN"``, ``"CA"``, ``"VE"``) — peuvent
      être des identifiants métier (catégories, codes opérations).
    - Mois/jours/lieux (``"OCTOBRE"``, ``"France"``) — peuvent désigner une
      raison sociale ou un identifiant.
    - Numériques, dates, montants — gérés par :func:`is_auto_decidable`
      en aval (auto-confirmé "laisser clair").
    """
    if not isinstance(tok, str) or not tok:
        return True
    if _PUNCTUATION_ONLY_RE.match(tok):
        return True
    if tok[0] in _TOKEN_BAD_PREFIX_CHARS:
        return True
    if tok.lower() in _TOKENIZER_STOPLIST_LOWER:
        return True
    return False


# --- Classification -----------------------------------------------------------


def is_auto_decidable(token: str) -> bool:
    """Vrai si le système peut décider seul que ce token n'a PAS besoin d'une
    revue utilisateur.

    Règles (conservatrices — on préfère faire apparaître un token dans la
    liste que de le masquer silencieusement) :

    - ``len < 2`` : pollution substring (ex: ``"X"``) → auto-décide (mais
      en pratique :func:`extract_terms` ne les sort pas du tout).
    - Structural sentinel (``true``/``false``/``null``/``N/A``/…) → auto.
    - Numérique ≤ 3 digits (``"42"``, ``"123"``) → auto. Un identifiant
      métier significatif est typiquement ≥ 4 chars.
    - Date-like (``"2024-10-15"``, ``"10/2024"``, ``"2023/2024"``) → auto.
    - Numérique avec devise/pourcent (``"42%"``, ``"12€"``) → auto.

    **Ne compte PAS comme auto-décidable :**

    - Un numérique long (``"0612345678"``, ``"12345678901234"`` SIRET) →
      l'utilisateur doit trancher.
    - Un code court non-numérique (``"FN"``, ``"CA"``) → ambigu, l'utilisateur
      tranche.
    - Un mot usuel (``"Martin"``, ``"France"``) → évident mais l'utilisateur
      tranche quand même (certains mots courants peuvent être des identifiants
      métier dans leur contexte).
    """
    if not isinstance(token, str):
        return True  # Non-string : rien à anonymiser, auto-décide "rien à faire"
    stripped = token.strip()
    if not stripped or len(stripped) < 2:
        return True
    if stripped.lower() in _STRUCTURAL_STOPLIST:
        return True
    if _DATE_LIKE_RE.match(stripped):
        return True
    if _NUMERIC_LIKE_RE.match(stripped):
        # Numérique court (≤3 digits pur, hors devise/%): auto.
        # Numérique long : utilisateur décide (ex: numéro de compte).
        pure_digits = re.sub(r"[^0-9]", "", stripped)
        if 0 < len(pure_digits) <= 3:
            return True
        # Avec devise ou pourcent, même long : auto (ex: "1234567€" reste un
        # montant, pas un identifiant de contact).
        if re.search(r"[€$£%]", stripped):
            return True
        # Décimal / notation scientifique : auto (ce sont des mesures).
        if "." in stripped or "," in stripped or "e" in stripped.lower():
            return True
        # Pur numérique long (4+ digits) → NON auto-décidable : peut être
        # un numéro de téléphone, de SIREN, etc. Utilisateur tranche.
        return False
    return False


# --- Extraction des termes du classeur ---------------------------------------


#: Pattern d'un GUID/UUID formaté SQL Server (``uniqueidentifier``).
#: 8-4-4-4-12 hex digits avec tirets, case-insensitive.
#: Ex: ``018CD7BA-C610-4544-B56B-5242B8CCB4B0``. Ces IDs sont des
#: identifiants techniques internes, jamais des valeurs métier à
#: anonymiser. Sans ce filtre, le tokenizer les fragmentait en 5 tokens
#: distincts qui polluaient ``anonymization_terms`` (bug observé prod
#: 2026-05-18 : David voyait `018CD7BA-C610-4544-B56B-5242B8CCB4B0` et
#: ses fragments dans /data/privacy).
_GUID_FULL_RE = re.compile(
    r"^\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\s*$"
)


def _looks_like_binary_garbage(s: str) -> bool:
    """Heuristique : la string contient des chars **control C0 ou C1**
    qui n'apparaissent JAMAIS dans un texte légitime UTF-8.

    Critères stricts (zero-tolérance) :

    - **Control C0** (``\\x00`` à ``\\x1F``) sauf tab/LF/CR — JAMAIS dans
      du texte business (caractères de contrôle terminal/teletype).
    - **Control C1** (``\\x7F`` à ``\\x9F``) — JAMAIS dans du texte
      Unicode (réservés ISO-8859-1 pour les contrôles supplémentaires).

    Texte FR ordinaire (``"Université d'Évry"`` avec ``É=0xC9``) n'a
    AUCUN de ces chars → passe. Une string ``"\\xb6\\xcenCH@\\xd8\\xd7
    \\xe8\\x88\\xd2\\x1d\\xec'"`` contient ``\\x88`` (C1) et ``\\x1d``
    (C0) → rejetée.

    Bug observé 2026-05-18 : ces strings binaires fuyaient dans
    ``anonymization_terms`` via le hook ``scan_sql_result_terms`` quand
    SQL Server retournait des colonnes ``varbinary``/``rowversion`` —
    le decode latin-1 implicite côté ODBC produisait ces strings polluées.
    """
    if not s:
        return False
    for ch in s:
        cp = ord(ch)
        # Control C0 (< 0x20) excluant les whitespace légitimes (tab,
        # LF, CR). Un texte business n'a JAMAIS de form feed (\x0c),
        # bell (\x07), DLE (\x10), etc.
        if cp < 0x20 and cp not in (0x09, 0x0A, 0x0D):
            return True
        # Control C1 (0x7F DEL inclus + 0x80-0x9F control supp) —
        # jamais légitime dans un texte UTF-8.
        if 0x7F <= cp <= 0x9F:
            return True
    return False


def _tokenize_value(value: Any) -> List[str]:
    """Convertit une valeur quelconque en liste de tokens utilisables.

    - Non-string → ``str(value)`` (les numériques sont tokenisés aussi).
    - Chaîne > ``MAX_VALUE_LEN`` → retourne liste vide (on skippe — trop
      long pour être un identifiant utile, risque regex alternation).
    - **Skip GUID formaté SQL Server** (uniqueidentifier 8-4-4-4-12) —
      identifiant technique jamais métier. Sans ce filtre, le tokenizer
      fragmentait le GUID en 5 tokens hex polluants.
    - **Skip binaire mal-décodé** (>25% control chars) — issus typiquement
      d'un ``varbinary``/``rowversion`` SQL Server. Cf.
      :func:`_looks_like_binary_garbage`.
    - Applique :data:`TOKEN_SPLIT_RE`, drop les tokens ``len < 2``.
    """
    if value is None:
        return []
    if isinstance(value, bool):
        # bool est un int en Python — isoler avant le int-check, sinon
        # ``True`` tokeniserait en ``"True"`` et entrerait comme un terme
        # pseudo-plausible. On le traite comme un sentinel structurel.
        return []
    if isinstance(value, (int, float)):
        as_str = str(value)
    elif isinstance(value, str):
        as_str = value
    else:
        # dict / list / bytes / uuid.UUID / datetime / Decimal : ne pas
        # tokeniser récursivement ici, l'appelant descend explicitement
        # via :func:`extract_terms`. Les types binaires bruts (``bytes``,
        # ``bytearray``, ``memoryview``) sont filtrés ici par construction.
        return []
    if len(as_str) > MAX_VALUE_LEN:
        return []
    # Skip GUID/uniqueidentifier formaté SQL Server (technique, jamais métier).
    if _GUID_FULL_RE.match(as_str):
        return []
    # Skip binaire mal-décodé (varbinary/rowversion via cast/decode).
    if _looks_like_binary_garbage(as_str):
        return []
    out = []
    for match in TOKEN_SPLIT_RE.finditer(as_str):
        tok = match.group(0)
        if len(tok) >= 2:
            out.append(tok)
    return out


def _extract_from_match(match_obj: Any, out: Set[str]) -> None:
    """Ajoute à ``out`` les tokens trouvés dans un dict ``match`` de cellule.

    Seules les VALEURS (pas les clés = colonnes) sont tokenisées. Une valeur
    peut être scalaire (``{"client": "ACME"}``) ou liste (``{"mois":
    ["OCTOBRE", "NOVEMBRE"]}``).
    """
    if not isinstance(match_obj, dict):
        return
    for mv in match_obj.values():
        if isinstance(mv, list):
            for item in mv:
                out.update(_tokenize_value(item))
        else:
            out.update(_tokenize_value(mv))


def _tokenize_long_text(text: str) -> Iterable[str]:
    """Tokenise un texte libre arbitrairement long (ex: message Iris).

    Distinction avec :func:`_tokenize_value` qui rejette les valeurs ≥
    :data:`MAX_VALUE_LEN` chars in toto (cellule classeur typique ≤ 500 chars,
    au-delà = blob non pertinent à anonymiser). Un message Iris est
    naturellement long ("Donne-moi tous les clients qui ont commandé en
    octobre 2024 et qui ont payé plus de 1000€…"), il faut tokeniser sans
    capper le texte global. On cap par TOKEN individuel à la place :

    - ``len(token) < 2`` rejeté (pollution substring)
    - ``len(token) > MAX_VALUE_LEN`` rejeté (blob inline qui aurait écrasé
      un cap normal — rarissime sur un message normal, mais protège
      contre un copier-coller dump JSON sans whitespace)

    Utilise la même :data:`TOKEN_SPLIT_RE` que les classeurs : le contrat
    JS↔Py reste strictement aligné (un panneau frontend qui afficherait
    les markers d'un message Iris doit produire le même découpage).
    """
    if not isinstance(text, str) or not text:
        return
    for match in TOKEN_SPLIT_RE.finditer(text):
        tok = match.group(0)
        if 2 <= len(tok) <= MAX_VALUE_LEN:
            yield tok


def extract_terms(
    tabs_context: Optional[List[Dict[str, Any]]],
    sheet_content: Optional[List[Dict[str, Any]]] = None,
) -> Set[str]:
    """Parcourt le classeur (``tabs_context`` + ``sheet_content``) et
    retourne l'ensemble dédupliqué des tokens candidats à l'anonymisation.

    Note historique : le paramètre ``iris_messages`` a été retiré le
    2026-05-17. La tokenisation des messages Iris n'a jamais été demandée
    par l'utilisateur (cf. ``test_iris_messages_tokenisation_removed.py``).
    Source unique = CLASSEURS UNIQUEMENT.

    **Champs scannés** (lecture des VALEURS uniquement, pas des clés) :

    - Pour chaque tab :
      - ``tab.label`` (nom d'onglet)
      - ``tab.rows[i][j]`` (toutes cellules, numériques incluses)
      - ``tab.sheet_content[i].value`` (format cellule sparse)
      - ``tab.sheet_content[i].label`` (label sémantique de cellule)
      - ``tab.sheet_content[i].match`` (dict ``col → value|[values]``)
      - ``tab.col_distinct[col].values`` (valeurs distinctes de col)
      - ``tab.cellDetails["R,C"].rows[i][j]`` (drill-down : données cachées
        derrière une cellule cliquable — essentielles, sinon le LLM les
        verrait en clair quand l'utilisateur drill-down).
    - Pour ``sheet_content`` (onglet actif, structure sparse) :
      - ``entry.value`` + ``entry.label`` + ``entry.match``.

    **Champs IGNORÉS** :

    - ``sql``, ``columns``, ``col_distinct[col].type``, ``columnMetadata``
      et autres champs structurels : contiennent du schéma ou des mots-clés
      SQL, pas des données métier. Les polluer dans la liste à anonymiser
      noierait l'utilisateur dans des ``SELECT``, ``FROM``, ``col_name``.

    **Note sur la substitution** : l'anonymizer continue, LUI, à substituer
    dans les SQL / labels structurels (via ``anonymize_text``) — si un nom
    client apparaît dans une clause ``WHERE``, il sera remplacé. L'extraction
    ne décide pas de la substitution, seulement du *catalogue* des termes
    proposés à l'utilisateur.

    **Sémantique de présence (tâche #11, structurel)** : cette fonction
    retourne TOUS les tokens présents dans le classeur, **sans filtre
    anti-pollution**. Le filtre des candidats parasites (mots-clés SQL,
    grammaticaux FR, ponctuation pure) est appliqué côté
    :func:`reconcile_state` au moment de décider si un nouveau token rejoint
    le state utilisateur. Cela garantit que les call sites « présence
    physique » — :func:`app.services.anonymization.cleanup_job._active_tokens_for_user`
    (cleanup nocturne union cross-classeur),
    :func:`app.services.ai.copilot_agent` (``scope_tokens`` du
    pseudonymizer pour la substitution LLM),
    :func:`app.services.anonymization.api_service` (coverage scan) —
    voient l'union complète des tokens du classeur, sans risque de
    suppression silencieuse d'un terme déjà confirmé par l'utilisateur ni
    de fuite cleartext sur un terme historique pollutant ``enabled=True``.

    **``iris_messages`` (tâche #23)** : si fourni, chaque string est
    tokenisée via :func:`_tokenize_long_text` (mêmes :data:`TOKEN_SPLIT_RE`
    que les classeurs — contrat JS↔Py préservé) et les tokens viennent
    rejoindre l'ensemble retourné. Sert à brancher le hook
    ``agent_service.iris_main`` (un message user → reconcile_state ajoute
    les nouveaux tokens) et le provider ``_iris_message_token_provider``
    du cleanup job (rétention configurable). Pas de cap d'input total
    (un message Iris peut largement dépasser :data:`MAX_VALUE_LEN`),
    cap par token uniquement.
    """
    out: Set[str] = set()

    if tabs_context:
        for tab in tabs_context:
            if not isinstance(tab, dict):
                continue
            # Tab label
            out.update(_tokenize_value(tab.get("label")))
            # Rows (grille dense)
            rows = tab.get("rows")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, list):
                        for v in row:
                            out.update(_tokenize_value(v))
                    elif isinstance(row, dict):
                        # Format object (legacy) — itère les valeurs seulement
                        for v in row.values():
                            out.update(_tokenize_value(v))
            # sheet_content sparse embarqué dans le tab (shape list[dict])
            sc = tab.get("sheet_content")
            if isinstance(sc, list):
                for entry in sc:
                    if not isinstance(entry, dict):
                        continue
                    out.update(_tokenize_value(entry.get("value")))
                    out.update(_tokenize_value(entry.get("label")))
                    _extract_from_match(entry.get("match"), out)
            # col_distinct.values
            cd = tab.get("col_distinct")
            if isinstance(cd, dict):
                for info in cd.values():
                    if not isinstance(info, dict):
                        continue
                    values = info.get("values")
                    if isinstance(values, list):
                        for v in values:
                            out.update(_tokenize_value(v))
            # cellDetails : drill-down cellule par cellule
            cdet = tab.get("cellDetails")
            if isinstance(cdet, dict):
                for cell in cdet.values():
                    if not isinstance(cell, dict):
                        continue
                    c_rows = cell.get("rows")
                    if isinstance(c_rows, list):
                        for row in c_rows:
                            if isinstance(row, list):
                                for v in row:
                                    out.update(_tokenize_value(v))
                    # label + description d'une cellule drill-down
                    out.update(_tokenize_value(cell.get("label")))
                    out.update(_tokenize_value(cell.get("description")))
                    _extract_from_match(cell.get("match"), out)

    if sheet_content:
        for entry in sheet_content:
            if not isinstance(entry, dict):
                continue
            out.update(_tokenize_value(entry.get("value")))
            out.update(_tokenize_value(entry.get("label")))
            _extract_from_match(entry.get("match"), out)

    return out


def extract_terms_with_origin(
    tabs_context: Optional[List[Dict[str, Any]]],
    sheet_content: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Set[Optional[str]]]:
    """Variante de :func:`extract_terms` qui retourne aussi la colonne
    d'origine de chaque token (task #20 — groupement par colonne dans
    ``/data/privacy``).

    Retourne ``Dict[token, Set[col_name|None]]`` : pour chaque token, le
    set des colonnes d'origine. ``None`` signale une origine sans colonne
    associée (label d'onglet, sheet_content sans ``col``, cellDetails
    label/description).

    **Couverture origines** (sur les champs scannés par ``extract_terms``) :

    - ``tab.rows[i][j]`` (dense list) → ``tab.columns[j]`` si dispo, sinon ``None``
    - ``tab.rows[i][k]`` (dict) → key ``k``
    - ``tab.sheet_content[k].value/label`` → ``entry.col`` si dispo, sinon ``None``
    - ``tab.col_distinct[col].values`` → directement ``col`` (déjà la clé)
    - ``tab.cellDetails[..]`` → ``None`` (drill-down sans colonne stable)
    - ``tab.label`` → ``None`` (= label d'onglet, pas une colonne)
    - ``sheet_content`` (top level) → ``entry.col`` si dispo, sinon ``None``

    Choix de design : on ne traverse pas ``tab.cellDetails[X].columns`` pour
    récupérer le mapping col→drill-down. C'est rare en pratique et coûteux
    à corréler ; on accepte que les tokens de drill-down soient marqués
    ``None`` (= "origines diverses"). Le rendu frontend les groupe sous
    "Autres" ou similaire.

    Args:
        tabs_context: structure ``tabs_context`` du classeur (cf.
            :func:`extract_terms` pour le shape exact).
        sheet_content: structure ``sheet_content`` (onglet actif sparse).

    Returns:
        Dict ``{token: {col1, col2, None, ...}}``. ``None`` est une valeur
        valide dans le set, signale une origine sans colonne.
    """
    origins: Dict[str, Set[Optional[str]]] = {}

    def _add_token(token: str, col: Optional[str]) -> None:
        if not isinstance(token, str) or not token:
            return
        # Normalise col en string non-vide ou None
        col_norm: Optional[str] = None
        if col is not None and isinstance(col, (str, int)):
            col_str = str(col).strip()
            if col_str:
                col_norm = col_str[:200]  # cap raisonnable pour stockage
        if token not in origins:
            origins[token] = set()
        origins[token].add(col_norm)

    def _add_value(value: Any, col: Optional[str]) -> None:
        for tok in _tokenize_value(value):
            _add_token(tok, col)

    def _add_match(match: Any, col: Optional[str]) -> None:
        # ``match`` est un dict ``col → value|[values]`` (cf. ``_extract_from_match``).
        # Format Komptia : un ``entry.match`` représente plusieurs valeurs venant
        # de plusieurs colonnes sous-jacentes affichées en agrégat dans UNE
        # cellule. L'origine *précise* du token = ``match_col`` (la sous-colonne),
        # pas ``col`` (la cellule affichant l'agrégat). Si ``match_col`` est
        # vide/None, on retombe sur ``col`` comme meilleure approximation.
        # Fix review adversariale task #20 finding #9.
        if not isinstance(match, dict):
            return
        for match_col, match_val in match.items():
            target_col = str(match_col) if match_col else col
            if isinstance(match_val, list):
                for v in match_val:
                    _add_value(v, target_col)
            else:
                _add_value(match_val, target_col)

    if tabs_context:
        for tab in tabs_context:
            if not isinstance(tab, dict):
                continue
            # ``columns`` : liste des noms de colonnes pour les rows denses
            tab_columns = tab.get("columns")
            if not isinstance(tab_columns, list):
                tab_columns = None

            # Tab label : origine = None (label d'onglet, pas une colonne)
            _add_value(tab.get("label"), None)

            # Rows denses
            rows = tab.get("rows")
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, list):
                        for col_idx, v in enumerate(row):
                            col_name: Optional[str] = None
                            if tab_columns and 0 <= col_idx < len(tab_columns):
                                col_str = tab_columns[col_idx]
                                col_name = str(col_str) if col_str else None
                            _add_value(v, col_name)
                    elif isinstance(row, dict):
                        # Format object : la clé EST le nom de colonne
                        for k, v in row.items():
                            _add_value(v, str(k) if k else None)

            # sheet_content embedded
            sc = tab.get("sheet_content")
            if isinstance(sc, list):
                for entry in sc:
                    if not isinstance(entry, dict):
                        continue
                    entry_col = entry.get("col")
                    entry_col_name = str(entry_col) if entry_col else None
                    _add_value(entry.get("value"), entry_col_name)
                    _add_value(entry.get("label"), None)  # label = sémantique cellule
                    _add_match(entry.get("match"), entry_col_name)

            # col_distinct : la clé EST le nom de colonne
            cd = tab.get("col_distinct")
            if isinstance(cd, dict):
                for col_name, info in cd.items():
                    if not isinstance(info, dict):
                        continue
                    values = info.get("values")
                    if isinstance(values, list):
                        col_str = str(col_name) if col_name else None
                        for v in values:
                            _add_value(v, col_str)

            # cellDetails : origines = None (drill-down sans colonne stable)
            cdet = tab.get("cellDetails")
            if isinstance(cdet, dict):
                for cell in cdet.values():
                    if not isinstance(cell, dict):
                        continue
                    c_rows = cell.get("rows")
                    if isinstance(c_rows, list):
                        for row in c_rows:
                            if isinstance(row, list):
                                for v in row:
                                    _add_value(v, None)
                    _add_value(cell.get("label"), None)
                    _add_value(cell.get("description"), None)
                    _add_match(cell.get("match"), None)

    if sheet_content:
        for entry in sheet_content:
            if not isinstance(entry, dict):
                continue
            entry_col = entry.get("col")
            entry_col_name = str(entry_col) if entry_col else None
            _add_value(entry.get("value"), entry_col_name)
            _add_value(entry.get("label"), None)
            _add_match(entry.get("match"), entry_col_name)

    return origins


# --- Réconciliation state <-> classeur ---------------------------------------


# Capacité de cache : ~131 k entrées. Empreinte mémoire estimée
# **~30-65 MB** (∼300-500 B par entrée Python : 2 string args + 1 string
# return + dict overhead + LRU doubly-linked-list slot). Couvre un user
# avec 50 k termes (typique du worst-case logué 2026-05-22 à 2089 ms sur
# GET /api/anonymization/terms) avec marge pour ~2-3 users simultanés
# avant éviction LRU. Fonction PURE (term, category) → label déterministe :
# le caching n'a pas de risque de désync sémantique tant que la doctrine
# « pas d'arg supplémentaire stateful » est respectée.
#
# PII : ``term`` est PII (noms, codes métier user). Le cache RETIENT ces
# valeurs en process memory. Acceptable parce que (a) les rows ORM
# contiennent déjà ces valeurs pendant chaque GET, le cache prolonge
# seulement la durée de vie, (b) le process restart au déploiement
# nettoie tout, (c) la taille est BORNÉE par maxsize.
#
# Tests : si un test mocke ``anon_patterns.resolve_label`` ou nécessite
# une isolation stricte, appeler ``_auto_pseudo_middle.cache_clear()``
# dans la fixture setUp/teardown.
@functools.lru_cache(maxsize=131072)
def _auto_pseudo_middle(term: str, category: Optional[str] = None) -> str:
    """Construit un pseudonyme *middle* par défaut pour un terme — sans
    sentinelles (elles seront ajoutées par :meth:`Pseudonymizer._make_token`
    ou :meth:`Pseudonymizer.add_mapping`).

    **Format** : ``{LABEL}_{md5[:4]}`` où :

    - ``LABEL`` = label sémantique UPPERCASE court. Résolu dans cet ordre :

      1. **Si ``category`` connue** (``pii_email``, ``pii_name``, …) →
         label issu de :func:`patterns.category_to_label` (``"EMAIL"``,
         ``"NAME"``, ``"PHONE"``, ``"IBAN"``, ``"SIRET"``, ``"AMOUNT"``,
         ``"CODE"``…).
      2. **Sinon, distinction texte vs numérique** sur le ``term`` :

         - Si :func:`auto_classify._is_pure_numeric` (chiffres + séparateurs
           ``+-_.,/:`` + espaces) → label ``"NUM"``.
         - Sinon → label ``"TXT"``.

      Cette distinction TXT/NUM est l'invariant minimum demandé par
      l'utilisateur (mai 2026) : « si le LLM voit un terme anonymisé, qu'il
      puisse savoir si le terme en clair est du texte ou une valeur
      numérique ». Pour Iris notamment, qui génère du SQL : un placeholder
      ``§NUM_a1d1§`` indique « ici un nombre » → cellule comparable
      arithmétiquement ; un ``§TXT_4b3a§`` indique « ici du texte » →
      comparaison string / LIKE.
    - ``md5[:4]`` = 4 hex chars (65 536 valeurs uniques par label). Pour un
      utilisateur qui aurait ~100 termes dans la même catégorie, probabilité
      de collision ~7 % ; le :class:`Pseudonymizer` gère les collisions
      résiduelles via un suffixe incrémental ``_2/_3/…``.

    Exemples :

    - ``("jean@cabinet.fr", "pii_email")`` → ``"EMAIL_3f4a"``
    - ``("0612345678", "pii_phone")`` → ``"PHONE_8a2b"``
    - ``("DUPONT", "pii_name")`` → ``"NAME_4b3c"``
    - ``("DUPONT", None)`` → ``"TXT_4b3c"`` (pas de catégorie, terme texte)
    - ``("12345", "unclassified")`` → ``"NUM_a1d1"`` (pas de catégorie, numérique)
    - ``("2024-10-15", None)`` → ``"NUM_xxxx"`` (date = numérique-like)

    **Rupture vs ancien format** : avant 2026-05-19, le format
    ``consonants_md5[:3]`` (alphabétique) ou ``n_md5[:8]`` (sans voyelles)
    exposait les consonnes du terme et utilisait des hashs de longueurs
    différentes — opaque sans signal sémantique. Le nouveau format porte
    soit la catégorie sémantique (EMAIL/NAME/PHONE/IBAN/…) soit, à défaut,
    le type texte/numérique (TXT/NUM) → comprehension LLM maximisée tout
    en restant pseudo-opaque (la valeur exacte reste cachée derrière le
    hash, seul le TYPE est révélé).

    **Mirror obligatoire côté JS** : ``autoPseudoMiddle`` dans
    ``static/js/anonymization/tokenizer.js`` DOIT produire la même sortie
    pour le même couple ``(term, category)``. Le test cross-impl
    ``test_auto_pseudo_middle_cross_impl_contract`` vérifie la fixture
    ``tests/fixtures/anon_auto_pseudo_contract.json`` côté Python.

    Args:
        term: le cleartext à anonymiser.
        category: catégorie BDD optionnelle (``pii_email``, ``pii_name``,
            etc.). ``None`` ou ``"unclassified"`` → fallback TXT/NUM selon
            la nature du terme.

    Returns:
        Le middle (sans sentinelles ``§``). Chaîne vide si ``term`` est
        vide / non-string (defense in depth contre les appelants buggués).
    """
    if not isinstance(term, str) or not term:
        return ""
    label = anon_patterns.resolve_label(term, category)
    h = hashlib.md5(term.encode("utf-8")).hexdigest()[:4]
    return f"{label}_{h}"


def _default_term_entry(token: str) -> Dict[str, Any]:
    """Construit l'entrée par défaut d'un nouveau terme découvert.

    - ``enabled`` : toujours ``False`` par défaut (l'utilisateur *choisit*
      de protéger, pas l'inverse — sinon on pénalise le LLM sur chaque nouveau
      terme sans consentement).
    - ``confirmed`` : ``True`` pour les tokens auto-décidables (numériques
      courts, dates, sentinelles) — ils n'entrent pas dans la gate.
      ``False`` pour tout le reste — l'utilisateur doit trancher.
    - ``pseudo`` : absent. Le middle sera auto-généré au moment de construire
      le pseudonymizer si l'utilisateur active sans personnaliser.
    """
    return {
        "enabled": False,
        "confirmed": is_auto_decidable(token),
    }


def reconcile_state(
    current_tokens: Set[str],
    stored_state: Optional[Dict[str, Any]],
) -> Tuple[Dict[str, Any], List[str], List[str]]:
    """Aligne ``stored_state`` avec les ``current_tokens`` du classeur courant.

    **Sémantique v2 (post-fix cross-classeur)** : cette fonction est appelée
    sur UN seul classeur à la fois, mais ``stored_state`` contient tous les
    termes du user (cross-classeur via BDD). On NE DOIT PAS retirer les
    termes stockés absents du classeur courant — ils peuvent provenir d'un
    AUTRE classeur de l'utilisateur, et les retirer ici causerait une
    perte silencieuse (visible + définitive après un PUT panneau).

    Retourne ``(new_state, added_tokens, vanished_tokens)`` :

    - ``new_state`` = ``stored_state`` **normalisé** (types booléens propres,
      pseudo conservé) PLUS les tokens du classeur courant absents en BDD
      (entrent via :func:`_default_term_entry`).
    - ``added_tokens`` : liste des nouveaux tokens du classeur courant absents
      en BDD. Ces tokens sont ceux qui peuvent déclencher le gate si
      ``confirmed=False`` par défaut.
    - ``vanished_tokens`` : liste **informationnelle** (utile aux logs) des
      tokens en BDD absents du classeur courant. **PAS** supprimés du state —
      ils peuvent provenir d'autres classeurs de l'utilisateur. La suppression
      réelle est assurée par le job de cleanup périodique
      (``cleanup_unused_anonymization_terms_job``) qui a la vue cross-classeur
      nécessaire pour trancher. Nommé "vanished" et non "removed" pour que
      le caller ne présume pas d'un effet de suppression.

    Invariants préservés :

    - Un terme stocké enabled/disabled qui réapparaît dans le classeur garde
      ses flags + son pseudo.
    - Un terme stocké qui ne ré-apparaît PAS dans le classeur est CONSERVÉ
      dans le state (il vient d'un autre classeur).
    - Les tokens du classeur courant qui sont nouveaux (non-stockés) entrent
      avec les defaults (``confirmed`` selon auto-decide, ``enabled=False``).
    - **Filtre anti-pollution (tâche #11)** : un token NOUVEAU classifié
      comme parasite par :func:`_is_pollutant_token` (mot-clé SQL, mot
      grammatical FR, ponctuation pure) n'est PAS ajouté au state — il
      ne polluera pas le panneau utilisateur. **N'efface jamais les
      termes déjà persistés** : un terme historique parasite avec
      ``enabled=True`` reste dans le state et continue d'être substitué
      au LLM (la passe 1 le recopie tel quel).
    """
    stored_terms: Dict[str, Any] = {}
    if isinstance(stored_state, dict):
        st = stored_state.get("terms")
        if isinstance(st, dict):
            stored_terms = st

    new_terms: Dict[str, Any] = {}
    added: List[str] = []

    # 1. Normalise + recopie TOUS les termes stockés (cross-classeur).
    # Rationale : un terme en BDD qui n'apparaît pas dans ``current_tokens``
    # peut provenir d'un autre classeur de l'user — on ne le supprime PAS.
    # Note tâche #11 : on NE filtre PAS ici. Si l'user a explicitement
    # confirmé un terme parasite (via PUT, ou état historique), il reste.
    for tok, existing in stored_terms.items():
        if not isinstance(existing, dict) or not isinstance(tok, str) or not tok:
            continue
        # Catégorie : préférer celle stockée (auto_classify + INSERT PII),
        # sinon retomber sur la détection regex live. La regex couvre les
        # types built-in (EMAIL/PHONE/SIRET/IBAN/AMOUNT) ; pour les termes
        # non-PII typique (noms, codes), category restera None et le label
        # produit sera ``TERM`` (générique mais comprehensible pour le LLM).
        category = existing.get("category") if isinstance(existing.get("category"), str) else None
        if not category:
            category = anon_patterns.detect_pii_category(tok)
        entry: Dict[str, Any] = {
            "enabled": bool(existing.get("enabled", False)),
            "confirmed": bool(existing.get("confirmed", False)),
            # Placeholder par défaut au format ``{LABEL}_{md5[:4]}`` — porte
            # la sémantique de la catégorie au LLM (ex: ``EMAIL_4b3a``)
            # tout en restant pseudo-opaque. Affiché dans le panneau frontend
            # (input placeholder) ET utilisé par le Pseudonymizer pour
            # construire le token §…§ envoyé au LLM (cf. ``_make_token``).
            "auto_pseudo": _auto_pseudo_middle(tok, category),
        }
        pseudo = existing.get("pseudo")
        if isinstance(pseudo, str) and pseudo:
            entry["pseudo"] = pseudo
        new_terms[tok] = entry

    # 2. Ajoute les tokens du classeur courant absents en BDD — sauf
    # parasites (tâche #11). Le filtre anti-pollution s'applique au
    # *catalogue proposé* uniquement : un terme déjà persisté (passe 1)
    # n'est jamais effacé, même s'il est parasite.
    for token in current_tokens:
        if token in new_terms:
            continue  # déjà couvert par la passe 1
        if _is_pollutant_token(token):
            continue  # mot-clé SQL / grammatical FR / ponctuation pure
        entry_new = _default_term_entry(token)
        # Pour les nouveaux tokens : pas de category en BDD encore (l'INSERT
        # via repository.upsert_terms appellera ``detect_pii_category`` au
        # commit). En attendant, on précalcule la category PII regex localement
        # pour aligner l'affichage panneau dès le 1ʳᵉ scan. Si la regex ne
        # matche pas (cas typique : noms, codes), label = ``TERM``.
        category = anon_patterns.detect_pii_category(token)
        entry_new["auto_pseudo"] = _auto_pseudo_middle(token, category)
        new_terms[token] = entry_new
        added.append(token)

    # 3. ``vanished`` = informationnel (log/debug). PAS retiré du state —
    # les termes qui ne sont plus dans le classeur courant peuvent être dans
    # un AUTRE classeur du même user. Seul le cleanup quotidien (scheduler)
    # a la vue cross-classeur nécessaire pour vraiment supprimer.
    vanished = [t for t in stored_terms.keys() if t not in current_tokens]

    # Cap dur : si le classeur déborde, on tronque ET on log. Le caller doit
    # renvoyer une erreur à l'utilisateur (pas silencieux).
    if len(new_terms) > MAX_STATE_TERMS:
        logger.warning(
            "anon_terms.reconcile_state: %d tokens > MAX_STATE_TERMS=%d, "
            "truncation à la réconciliation (l'appelant doit remonter 413)",
            len(new_terms),
            MAX_STATE_TERMS,
        )
        # On garde un sous-ensemble stable (alphabétique) pour que la coupe
        # soit déterministe run-to-run.
        kept_tokens = sorted(new_terms.keys())[:MAX_STATE_TERMS]
        new_terms = {t: new_terms[t] for t in kept_tokens}

    return (
        {"version": STATE_VERSION, "terms": new_terms},
        sorted(added),
        sorted(vanished),
    )


# --- Gate checks --------------------------------------------------------------


def pending_terms(state: Dict[str, Any]) -> List[str]:
    """Liste triée des tokens en attente de revue utilisateur
    (``confirmed=False``)."""
    terms = state.get("terms") if isinstance(state, dict) else None
    if not isinstance(terms, dict):
        return []
    return sorted(
        t
        for t, entry in terms.items()
        if isinstance(entry, dict) and not bool(entry.get("confirmed", False))
    )


def has_pending_review(state: Dict[str, Any]) -> bool:
    """``True`` si au moins un terme n'a pas été confirmé.

    **C'est le gate** : appelé avant tout appel LLM côté ``copilot_agent``.
    """
    return bool(pending_terms(state))


# --- Validation du state ------------------------------------------------------


def sanitize_state(state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Retourne un state nettoyé sans entries invalides.

    Stratégie : pour chaque terme, si une violation rend l'entry
    inutilisable (pseudo invalide, enabled/confirmed non-bool), on
    strippe l'entry plutôt que de rejeter le state entier. Permet à
    l'utilisateur de continuer même si une entrée historique est
    corrompue (ex: pseudo créé par une ancienne version qui acceptait
    des caractères qu'on rejette maintenant).

    Pour ``duplicate_pseudo``, on garde le 1er terme et strippe les
    suivants — déterministe sur l'ordre dict (Python 3.7+).

    Le state retourné peut être ``{}`` si tout était invalide. C'est
    OK : l'utilisateur reverra le panneau et reflaggera.
    """
    if not isinstance(state, dict):
        return {"version": 1, "terms": {}}
    terms_in = state.get("terms")
    if not isinstance(terms_in, dict):
        return {"version": 1, "terms": {}}
    terms_out: Dict[str, Any] = {}
    seen_pseudos: Dict[str, str] = {}
    for term, entry in terms_in.items():
        if not isinstance(term, str) or not term:
            continue
        if len(term) > MAX_VALUE_LEN:
            continue
        if not isinstance(entry, dict):
            continue
        cleaned: Dict[str, Any] = {}
        # bool stricts ; non-bool → drop le champ (default False)
        for field in ("enabled", "confirmed"):
            v = entry.get(field)
            if isinstance(v, bool):
                cleaned[field] = v
        # pseudo : strict ou strippe
        pseudo = entry.get("pseudo")
        if pseudo is not None and isinstance(pseudo, str) and pseudo:
            if (
                len(pseudo) <= MAX_PSEUDO_MIDDLE_LEN
                and "§" not in pseudo
                and _PSEUDO_MIDDLE_ALLOWED.match(pseudo)
                and pseudo != term
            ):
                # check duplicate avec termes déjà retenus
                only_if_enabled = bool(cleaned.get("enabled", False))
                if only_if_enabled and pseudo in seen_pseudos:
                    pass  # collision — drop le pseudo, garde le terme
                else:
                    cleaned["pseudo"] = pseudo
                    if only_if_enabled:
                        seen_pseudos[pseudo] = term
        terms_out[term] = cleaned
    return {"version": 1, "terms": terms_out}


def validate_state(state: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Vérifie la forme d'un state utilisateur. Retourne une liste d'erreurs
    structurées (vide = OK).

    Chaque erreur = ``{"type": <code>, ...}`` avec des champs additionnels
    pour permettre au frontend de pointer précisément la ligne fautive.

    Codes d'erreur :

    - ``"invalid_shape"``     — state n'est pas un dict ou ``terms`` pas un
      dict.
    - ``"invalid_version"``   — version inconnue (future ou manquante).
    - ``"too_many_terms"``    — dépasse :data:`MAX_STATE_TERMS`.
    - ``"invalid_term_key"``  — clé non-string, vide, ou trop longue.
    - ``"invalid_term_entry"`` — valeur n'est pas un dict, ou types invalides
      pour ``enabled``/``confirmed``/``pseudo``.
    - ``"invalid_pseudo"``    — pseudo contient ``§``, est trop long, ou vide
      alors que présent.
    - ``"pseudo_equals_term"`` — pseudo identique au terme (no-op, probablement
      une erreur utilisateur).
    - ``"duplicate_pseudo"``  — deux termes différents ont le même pseudo →
      bijection impossible.
    """
    errors: List[Dict[str, Any]] = []

    if state is None:
        # None = pas de state fourni. On laisse passer (caller peut injecter
        # un state vide par défaut).
        return errors

    if not isinstance(state, dict):
        errors.append({"type": "invalid_shape", "detail": "state must be a dict"})
        return errors

    version = state.get("version")
    if version != STATE_VERSION:
        errors.append(
            {
                "type": "invalid_version",
                "expected": STATE_VERSION,
                "got": version,
            }
        )
        # On continue quand même la validation — permet de lister TOUTES
        # les erreurs d'un coup au lieu d'un seul aller-retour par champ.

    terms = state.get("terms")
    if not isinstance(terms, dict):
        errors.append({"type": "invalid_shape", "detail": "state.terms must be a dict"})
        return errors

    if len(terms) > MAX_STATE_TERMS:
        errors.append(
            {
                "type": "too_many_terms",
                "count": len(terms),
                "max": MAX_STATE_TERMS,
            }
        )
        # Hard-fail (fix review 2026-04-23) : si le cap est dépassé, on
        # refuse d'aller plus loin. Continuer validerait + tenterait l'upsert
        # sur un body potentiellement DoS. L'utilisateur reçoit une erreur
        # structurée, doit réduire sa liste.
        return errors

    # Pour détecter les pseudos en doublon on accumule (pseudo → [terms]).
    pseudo_to_terms: Dict[str, List[str]] = {}

    for term, entry in terms.items():
        if not isinstance(term, str) or not term:
            errors.append({"type": "invalid_term_key", "term": term})
            continue
        if len(term) > MAX_VALUE_LEN:
            errors.append({"type": "invalid_term_key", "term": term[:40] + "…"})
            continue
        if not isinstance(entry, dict):
            errors.append({"type": "invalid_term_entry", "term": term})
            continue
        if not isinstance(entry.get("enabled", False), bool):
            errors.append({"type": "invalid_term_entry", "term": term, "field": "enabled"})
        if not isinstance(entry.get("confirmed", False), bool):
            errors.append({"type": "invalid_term_entry", "term": term, "field": "confirmed"})

        pseudo = entry.get("pseudo")
        if pseudo is not None:
            if not isinstance(pseudo, str):
                errors.append({"type": "invalid_pseudo", "term": term, "detail": "not a string"})
                continue
            if pseudo == "":
                # Pseudo vide explicite = identique à "absent" — autorisé,
                # l'auto-gen prendra le relais. Pas d'erreur.
                continue
            if len(pseudo) > MAX_PSEUDO_MIDDLE_LEN:
                errors.append(
                    {
                        "type": "invalid_pseudo",
                        "term": term,
                        "detail": "too long",
                        "max": MAX_PSEUDO_MIDDLE_LEN,
                    }
                )
                continue
            if "§" in pseudo or not _PSEUDO_MIDDLE_ALLOWED.match(pseudo):
                errors.append(
                    {
                        "type": "invalid_pseudo",
                        "term": term,
                        "detail": "contains sentinel '§' or forbidden character",
                    }
                )
                continue
            if pseudo == term:
                errors.append(
                    {
                        "type": "pseudo_equals_term",
                        "term": term,
                        "pseudo": pseudo,
                    }
                )
                continue
            # Ne track les collisions que pour les termes qui ont `enabled=True`
            # ET un pseudo custom — les pseudos auto-générés ne collisionnent
            # pas car le hash md5[:3] disambiguë déjà.
            if bool(entry.get("enabled", False)):
                pseudo_to_terms.setdefault(pseudo, []).append(term)

    for pseudo, conflicting in pseudo_to_terms.items():
        if len(conflicting) > 1:
            errors.append(
                {
                    "type": "duplicate_pseudo",
                    "pseudo": pseudo,
                    "terms": sorted(conflicting),
                }
            )

    return errors


# --- Construction du pseudonymizer utilisateur -------------------------------


def build_user_pseudonymizer(
    state: Dict[str, Any],
    scope_tokens: Optional[Set[str]] = None,
) -> Pseudonymizer:
    """Construit un ``Pseudonymizer`` peuplé des termes ``enabled=True`` du state.

    Pour chaque terme activé :

    - Si ``pseudo`` est fourni (non vide) → ``add_mapping(term, pseudo)``
      (le Pseudonymizer encadre en ``§pseudo§``).
    - Sinon → ``add_mapping(term, None)`` qui auto-gen via l'algo historique
      (consonnes + hash md5).

    **``scope_tokens`` (optionnel)** : restreint la table du Pseudonymizer aux
    termes qui apparaissent dans ce set. Utile côté copilot_agent pour éviter
    de charger la regex de substitution avec des termes cross-classeur qui
    n'ont AUCUNE chance de matcher dans l'input courant (``tabs_context`` +
    ``sheet_content`` + ``instruction``). Gain significatif sur un user qui
    a accumulé des centaines de termes cross-classeur : la regex passe de
    O(tous les termes) à O(termes du classeur courant).

    Si ``scope_tokens`` est ``None`` (default), la table inclut TOUS les
    termes ``enabled=True`` du state — comportement utile pour les callers
    qui veulent le pseudonymizer complet (tests, inspection, ou pour couvrir
    les valeurs que ``ask_iris`` pourrait retourner dynamiquement sans passer
    par le add_value éphémère).

    **Pré-requis** : :func:`validate_state` doit avoir été appelé en amont.
    Si une collision résiduelle fait lever ``ValueError`` dans
    ``add_mapping``, on continue avec les autres termes et on log — le
    pseudonymizer retourné est potentiellement incomplet. Le caller doit
    refuser de traiter ce cas (gate backend = 400 avec erreurs structurées).
    """
    pseudo = Pseudonymizer()
    terms = state.get("terms") if isinstance(state, dict) else None
    if not isinstance(terms, dict):
        return pseudo

    for term, entry in terms.items():
        if not isinstance(entry, dict):
            continue
        if not bool(entry.get("enabled", False)):
            continue
        if not isinstance(term, str) or not term:
            continue
        # Scope filter : skip les termes qui ne peuvent pas matcher le
        # classeur courant. Ne s'applique QUE si ``scope_tokens`` non None —
        # sinon on garde le comportement complet (aucune régression test).
        if scope_tokens is not None and term not in scope_tokens:
            continue
        middle = entry.get("pseudo")
        # Catégorie : utilisée par l'auto-gen pour produire un placeholder
        # sémantique (``§EMAIL_4b3a§`` plutôt que ``§nn_4b3§``). Inutile
        # quand l'utilisateur a fourni un middle explicite (``§CLIENT_A§``).
        raw_cat = entry.get("category")
        category = raw_cat if isinstance(raw_cat, str) and raw_cat else None
        if isinstance(middle, str) and middle:
            try:
                pseudo.add_mapping(term, middle)
            except ValueError as exc:
                logger.warning(
                    "anon_terms.build_user_pseudonymizer: collision sur %s → %s (%s)",
                    term,
                    middle,
                    exc,
                )
        else:
            # Auto-gen : l'algo Pseudonymizer construit ``§{LABEL}_{hash[:4]}§``
            # avec ``LABEL`` dérivé de ``category`` via
            # :func:`patterns.category_to_label`. Unicité garantie par md5 +
            # suffixe en cas de collision hash (Pseudonymizer._add_single).
            try:
                pseudo.add_mapping(term, None, category=category)
            except ValueError as exc:
                logger.warning(
                    "anon_terms.build_user_pseudonymizer: auto-gen collision sur %s (%s)",
                    term,
                    exc,
                )
    return pseudo


# --- Utilitaires iterator (tests / debug) ------------------------------------


def iter_auto_pseudo_middles(
    terms: Iterable[str],
    categories: Optional[Dict[str, Optional[str]]] = None,
) -> Iterable[Tuple[str, str]]:
    """Helper pour tests/preview : itère (term, auto_middle) sans construire
    le pseudonymizer. Utile pour afficher les middles par défaut dans le
    panneau frontend via un endpoint séparé (si jamais on en ajoute un).

    Args:
        terms: itérable de termes (strings).
        categories: dict optionnel ``{term: category}`` pour résoudre le
            label sémantique. Un terme absent du dict retombe sur ``None``
            (label ``TERM``).
    """
    cats = categories or {}
    for t in terms:
        if isinstance(t, str) and t:
            yield (t, _auto_pseudo_middle(t, cats.get(t)))


# ---------------------------------------------------------------------------
# Dashboard scan — ajout 2026-05-20 (source="dashboard")
# ---------------------------------------------------------------------------


#: Champs textuels admin-éditables d'un dashboard scannés pour anonymisation.
#: La liste est CONTRÔLÉE : on ne scanne PAS ``data_source_config.query``
#: (SQL contient des noms techniques de tables/colonnes Sage qui ne sont
#: pas des PII utilisateur, source de bruit). On ne scanne PAS non plus
#: ``metric_name`` (valeur d'enum prédéfinie) ni ``style_config`` (hex
#: colors, dimensions). Si un futur dev veut étendre, l'ajout doit
#: explicitement traverser un champ par nom — pas de tokenisation
#: récursive aveugle.
_DASHBOARD_TEXT_FIELDS_TOP: Final[tuple[str, ...]] = (
    "name",
    "description",
    "template_description",
)

_DASHBOARD_TEXT_FIELDS_WIDGET_TOP: Final[tuple[str, ...]] = ("title",)

#: Chemins dans ``widget.data_source_config`` (JSON) à tokeniser quand
#: présents. Format : tuple de clés successives (suit l'arborescence
#: dict). Chaque entrée → ``(path_tuple, col_label_for_origin)``.
_DASHBOARD_TEXT_PATHS_WIDGET_CONFIG: Final[tuple[tuple[tuple[str, ...], str], ...]] = (
    (("render_spec", "title"), "render_spec.title"),
    (("render_spec", "x_label"), "render_spec.x_label"),
    (("render_spec", "y_label"), "render_spec.y_label"),
    (("render_spec", "insight"), "render_spec.insight"),
    # ``content`` = texte statique d'un widget data_source_type="static"
    # (notes manuelles, message annoté). Sensible par construction.
    (("content",), "content"),
)

_DASHBOARD_TEXT_FIELDS_FILTER_TOP: Final[tuple[str, ...]] = ("label",)

_DASHBOARD_TEXT_FIELDS_SCHEDULE_TOP: Final[tuple[str, ...]] = (
    "subject",
    "message",
)

#: Listes de strings dans le payload schedule à tokeniser (chaque entrée
#: est tokenisée en entier). ``recipients`` = liste d'emails destinataires
#: — PII canoniques (auto-détectées via ``upsert_terms`` pii_email).
_DASHBOARD_LIST_FIELDS_SCHEDULE: Final[tuple[str, ...]] = ("recipients",)


def _coerce_json_dict(raw: Any) -> Optional[Dict[str, Any]]:
    """Convertit un payload qui peut être dict ou string JSON en dict.

    Fail-safe : tout autre type, ou JSON invalide, retourne ``None`` —
    l'appelant doit skipper sans crash. Cas d'usage : ``data_source_config``
    stocké en TEXT (SQLite) ou JSONB (PostgreSQL), récupéré via ORM ou
    via fetchall raw — le shape final dépend du dialect.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if isinstance(parsed, dict):
            return parsed
    return None


def _walk_dict_path(d: Dict[str, Any], path: tuple[str, ...]) -> Any:
    """Récupère ``d[path[0]][path[1]]...`` ou ``None`` si chemin invalide.

    Aucune exception levée : un chemin qui rate à mi-course retourne None.
    """
    current: Any = d
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def extract_dashboard_terms_with_origin(
    dashboard: Dict[str, Any],
) -> Dict[str, Set[Optional[str]]]:
    """Tokenise les champs textuels admin-éditables d'un dashboard.

    Même contrat de retour que :func:`extract_terms_with_origin` :
    ``Dict[token, Set[col_label|None]]`` — la "col_label" identifie
    où dans le dashboard le terme a été vu (ex: ``"widget_3.title"``,
    ``"filter_2.label"``, ``"schedule_1.subject"``). L'UI
    ``/data/privacy`` réutilise le même rendu que les origines workbook
    (cf. ``privacy-page.js._subGroupByColumn``).

    **Skip systématique** :

    - ``is_template=True`` → modèle partagé, pas de PII user spécifique.
      Retourne ``{}`` direct sans parcourir.
    - ``data_source_config.query`` → SQL contient des noms techniques de
      tables/colonnes Sage (``Dossiers``, ``Factures``, ``colCodeCollabo``),
      source de bruit. Si l'admin a hardcodé une valeur dans un ``WHERE``,
      elle apparaîtra côté résultat exécuté (scan workbook normal).
    - ``metric_name`` (enum), ``style_config`` (hex/dim), ``transformation``
      (paramètres techniques).

    Args:
        dashboard: dict shape ``{id, name, description, template_description,
            is_template, widgets: [{title, data_source_config, ...}, ...],
            filters: [{label, values_config, ...}, ...],
            schedules: [{subject, message, ...}, ...]}``. ``widgets``,
            ``filters``, ``schedules`` peuvent être absents ou vides.

    Returns:
        ``{token: {col_label, ...}}``. Vide si dashboard est un template
        ou si aucun champ scanné ne contient de token.
    """
    origins: Dict[str, Set[Optional[str]]] = {}

    if not isinstance(dashboard, dict):
        return origins
    if dashboard.get("is_template"):
        return origins

    def _add_tokens(value: Any, col_label: str) -> None:
        if not isinstance(value, str) or not value:
            return
        for tok in _tokenize_long_text(value):
            # Anti-pollution (review adversariale 2026-05-20 CRITICAL #2) :
            # ``_tokenize_long_text`` ne filtre PAS les mots grammaticaux
            # français ni les keywords SQL. Sans cette garde, un widget
            # ``title = "Le suivi des dossiers"`` stockerait ``Le``,
            # ``suivi``, ``des``, ``dossiers`` — pollution massive du
            # panneau /data/privacy. Le filtre est partagé avec le path
            # workbook (utilisé dans reconcile_state) pour cohérence.
            if _is_pollutant_token(tok):
                continue
            if tok not in origins:
                origins[tok] = set()
            origins[tok].add(col_label)

    # Champs racine dashboard
    for field in _DASHBOARD_TEXT_FIELDS_TOP:
        _add_tokens(dashboard.get(field), field)

    # Widgets
    widgets = dashboard.get("widgets") or []
    if isinstance(widgets, list):
        for idx, widget in enumerate(widgets):
            if not isinstance(widget, dict):
                continue
            widget_label_prefix = f"widget_{widget.get('id', idx)}"
            for field in _DASHBOARD_TEXT_FIELDS_WIDGET_TOP:
                _add_tokens(widget.get(field), f"{widget_label_prefix}.{field}")
            cfg = _coerce_json_dict(widget.get("data_source_config"))
            if cfg is not None:
                for path, suffix in _DASHBOARD_TEXT_PATHS_WIDGET_CONFIG:
                    _add_tokens(_walk_dict_path(cfg, path), f"{widget_label_prefix}.{suffix}")

    # Filtres
    filters = dashboard.get("filters") or []
    if isinstance(filters, list):
        for idx, fltr in enumerate(filters):
            if not isinstance(fltr, dict):
                continue
            filter_label_prefix = f"filter_{fltr.get('id', idx)}"
            for field in _DASHBOARD_TEXT_FIELDS_FILTER_TOP:
                _add_tokens(fltr.get(field), f"{filter_label_prefix}.{field}")
            # Options statiques (review adversariale 2026-05-20 CRITICAL #1) :
            # Le discriminateur est ``DashboardFilter.values_source`` (colonne
            # SQL séparée, valeurs "static"/"sql"/"distinct"), PAS une clé
            # ``"source"`` à l'intérieur du JSON ``values_config``. La version
            # initiale du commit 15942fd testait ``vcfg.get("source")`` qui
            # retournait toujours None → branche morte au runtime.
            values_source = fltr.get("values_source")
            vcfg = _coerce_json_dict(fltr.get("values_config"))
            if values_source == "static" and vcfg is not None:
                opts = vcfg.get("options")
                if isinstance(opts, list):
                    for opt_idx, opt in enumerate(opts):
                        if not isinstance(opt, dict):
                            continue
                        _add_tokens(
                            opt.get("label"),
                            f"{filter_label_prefix}.options[{opt_idx}].label",
                        )
                        _add_tokens(
                            opt.get("value"),
                            f"{filter_label_prefix}.options[{opt_idx}].value",
                        )

    # Schedules (envois email planifiés)
    schedules = dashboard.get("schedules") or []
    if isinstance(schedules, list):
        for idx, sched in enumerate(schedules):
            if not isinstance(sched, dict):
                continue
            sched_label_prefix = f"schedule_{sched.get('id', idx)}"
            for field in _DASHBOARD_TEXT_FIELDS_SCHEDULE_TOP:
                _add_tokens(sched.get(field), f"{sched_label_prefix}.{field}")
            # ``recipients`` : liste d'emails (PII canoniques). Ajout
            # 2026-05-20 review adversariale HIGH #9 — sans ça les emails
            # de destinataires admin n'étaient JAMAIS dans
            # ``anonymization_terms``, alors qu'ils sont la cible naturelle
            # du système (auto-catégorisation pii_email + enabled=True).
            for list_field in _DASHBOARD_LIST_FIELDS_SCHEDULE:
                raw_list = sched.get(list_field)
                if isinstance(raw_list, list):
                    for item_idx, item in enumerate(raw_list):
                        _add_tokens(
                            item,
                            f"{sched_label_prefix}.{list_field}[{item_idx}]",
                        )

    return origins


#: Champs textuels racine d'une automation à tokeniser (admin-éditables).
_AUTOMATION_TEXT_FIELDS_TOP: Final[tuple[str, ...]] = (
    "name",
    "description",
)

#: Champs liste (emails) d'une automation à tokeniser comme PII canoniques.
_AUTOMATION_LIST_FIELDS_TOP: Final[tuple[str, ...]] = (
    "recipients",
    "notification_emails",
)

#: Champs textuels par AutomationStep à tokeniser.
_AUTOMATION_STEP_TEXT_FIELDS: Final[tuple[str, ...]] = ("name",)

#: Regex pour extraire les littéraux de chaînes SQL (entre ``'…'`` ou
#: ``"…"``). Capture le contenu, pas les quotes. Le tokenizer aval va
#: ensuite splitter ces littéraux en tokens individuels. Anti-DoS : le
#: ``.*?`` est non-greedy + cap longueur via la limite implicite du
#: ``query_text`` (Text SQLite, pas borné mais en pratique < 64KB).
_SQL_STRING_LITERAL_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")


#: GUID complet 8-4-4-4-12 (uniqueidentifier SQL Server). Module-level
#: pour partage entre scan_sql_result_terms et le cleanup provider —
#: garantit que les 2 chemins filtrent les mêmes types techniques.
_GUID_FULL_RE = re.compile(
    r"^\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\s*$"
)


def scrub_pyodbc_technical(value: Any) -> Any:
    """Remplace les valeurs techniques pyodbc/SQL Server par ``None``.

    Single source of truth pour le filtrage des types qui n'ont aucune
    sémantique métier et qui polluent ``anonymization_terms`` avec du
    bruit (varbinary, rowversion, uniqueidentifier raw ou formaté).

    Utilisée par :
    - :func:`app.services.anonymization.api_service.scan_sql_result_terms`
      au moment d'aplatir les rows en tabs_context.
    - :func:`app.services.anonymization.cleanup_job._iris_messages_token_provider`
      au moment de tokeniser les rows pour l'invariant cleanup⊆!scan.

    Si les 2 chemins divergent, l'invariant casse (cf. review adversariale
    2026-05-20 BLOCKING #1).
    """
    import uuid as _uuid

    if isinstance(value, (bytes, bytearray, memoryview)):
        return None
    if isinstance(value, _uuid.UUID):
        return None
    if isinstance(value, str) and _GUID_FULL_RE.match(value):
        return None
    return value


def extract_automation_terms_with_origin(
    automation: Dict[str, Any],
) -> Dict[str, Set[Optional[str]]]:
    """Tokenise les champs textuels admin-éditables d'une automation.

    Même contrat de retour que :func:`extract_dashboard_terms_with_origin`.
    Scopes scannés :

    - ``name``, ``description`` (racine)
    - ``recipients``, ``notification_emails`` (listes d'emails PII)
    - ``query_text`` : si ``query_type="nl"`` → tokenisé en entier ; si
      ``query_type="sql"`` → seuls les **littéraux de chaînes** (entre
      ``'…'`` ou ``"…"``) sont tokenisés. Évite de polluer
      ``anonymization_terms`` avec des noms techniques de tables/colonnes
      (``Factures``, ``cliId``…) tout en capturant les valeurs métier
      hardcodées dans un ``WHERE name='DUPONT'``.
    - ``steps[].name`` + valeurs textuelles dans ``steps[].config`` (parcours
      récursif léger, profondeur 2 max — config JSON arbitraire).

    Anti-pollution : ``_is_pollutant_token`` exclu (mots grammaticaux FR,
    keywords SQL) — cohérent avec le path dashboard/workbook.
    """
    origins: Dict[str, Set[Optional[str]]] = {}
    if not isinstance(automation, dict):
        return origins

    def _add_tokens(value: Any, col_label: str) -> None:
        if not isinstance(value, str) or not value:
            return
        for tok in _tokenize_long_text(value):
            if _is_pollutant_token(tok):
                continue
            if tok not in origins:
                origins[tok] = set()
            origins[tok].add(col_label)

    # Champs racine
    for field in _AUTOMATION_TEXT_FIELDS_TOP:
        _add_tokens(automation.get(field), field)

    # Listes emails (PII canoniques)
    for list_field in _AUTOMATION_LIST_FIELDS_TOP:
        raw_list = automation.get(list_field)
        if isinstance(raw_list, list):
            for item_idx, item in enumerate(raw_list):
                _add_tokens(item, f"{list_field}[{item_idx}]")

    # query_text : NL → tokenize entier ; SQL → littéraux seulement.
    query_text = automation.get("query_text")
    query_type = automation.get("query_type")
    if isinstance(query_text, str) and query_text:
        if query_type == "sql":
            for match in _SQL_STRING_LITERAL_RE.finditer(query_text):
                literal = match.group(1) or match.group(2) or ""
                _add_tokens(literal, "query_text.literal")
        else:
            # "nl" ou autre (placeholder) → tokenize tout le texte.
            _add_tokens(query_text, "query_text")

    # Steps : name + valeurs textuelles top-level de config.
    steps = automation.get("steps") or []
    if isinstance(steps, list):
        for step_idx, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            step_prefix = f"step_{step.get('id', step_idx)}"
            for field in _AUTOMATION_STEP_TEXT_FIELDS:
                _add_tokens(step.get(field), f"{step_prefix}.{field}")
            cfg = _coerce_json_dict(step.get("config"))
            if cfg is not None:
                # On scrute les valeurs string top-level du config (pas
                # de récursion profonde — un step.config typique fait 2-5
                # clés et n'imbrique pas de PII métier).
                for key, val in cfg.items():
                    if isinstance(val, str) and val:
                        # Si la valeur ressemble à une query SQL (clé "query"
                        # ou "sql"), on extrait uniquement les littéraux —
                        # même logique que query_text au niveau racine.
                        if key.lower() in ("query", "sql", "query_text"):
                            for match in _SQL_STRING_LITERAL_RE.finditer(val):
                                literal = match.group(1) or match.group(2) or ""
                                _add_tokens(literal, f"{step_prefix}.config.{key}.literal")
                        else:
                            _add_tokens(val, f"{step_prefix}.config.{key}")

    return origins
