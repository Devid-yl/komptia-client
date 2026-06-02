"""
Service d'anonymisation des données avant envoi aux LLMs externes.

Détecte et remplace les informations personnelles identifiables (PII)
dans les prompts envoyés à OpenAI/Anthropic. Les données anonymisées
sont restaurées dans la réponse via un mapping réversible.

Patterns détectés (12 catégories) :
- Emails
- URLs (http/https + path)
- IBAN (validé MOD-97 ISO 13616)
- Téléphones FR (préfixe +33 ou 0)
- TVA intracom FR (FR + 11 chiffres)
- NIR / Sécurité sociale FR (15 chiffres + clé 97-MOD)
- SIRET (14 chiffres validés Luhn)
- SIREN (9 chiffres validés Luhn)
- Cartes bancaires (13-19 chiffres validés Luhn)
- IPv4 (4 octets 0-255)
- Dates (jj/mm/aaaa, jj-mm-aaaa, jj.mm.aaaa, ISO 8601)
- Montants en euros

API publique :
- :func:`apply_builtin_pii` — fonction stateless qui supporte un état
  partagé (``mapping`` + ``counters``) entre appels successifs. Utilisée
  par :func:`app.services.anonymization.proxy.anonymize_for_llm` pour
  anonymiser un payload récursivement (dict / list / strings imbriquées)
  avec compteurs uniques globaux (un seul ``[EMAIL_1]`` pour le payload
  complet, jamais collision cross-string).
- :func:`detect_pii_category` — classifier strict (``fullmatch``) pour
  identifier le type d'un seul token. Utilisé à l'INSERT BDD d'un terme
  utilisateur. **Important** : restreint aux types stockables en BDD
  (cf. ``ANONYMIZATION_CATEGORIES``). Les types call-scoped seulement
  (URL/IP/NIR/DATE/VAT/CARD) retournent ``None`` ici mais sont quand
  même substitués via :func:`apply_builtin_pii`.
- :func:`detect_pii_label` — détecte le LABEL d'un terme pour l'affichage
  panneau et les pseudonymes runtime. Retourne le label étendu (EMAIL,
  URL, IP, NIR, DATE, VAT, CARD, …) ou ``None``. Non limité par le
  CHECK constraint BDD car utilisé pour le RENDU, pas pour le STORAGE.
- :func:`category_to_label` — convertit une ``category`` BDD en label
  UPPERCASE pour produire des placeholders sémantiques.
- :func:`resolve_label` — résolution complète en 3 niveaux pour
  ``_auto_pseudo_middle`` et ``_make_token`` : catégorie stockée
  prioritaire, sinon regex runtime, sinon fallback TXT/NUM.
- :class:`DataAnonymizer` + :func:`get_anonymizer` — façade orientée objet
  rétro-compatible (utilisée historiquement par ``llm_providers``).
"""

import logging
import re
from typing import Callable, Dict, FrozenSet, Optional, Tuple

logger = logging.getLogger(__name__)


def _luhn_check(digits: str) -> bool:
    """Validation Luhn pour SIRET/SIREN. ``digits`` est une chaîne de chiffres
    sans séparateur. Critical #37 review : sans Luhn, tout 14-digit séquence
    était tokenisée en SIRET (timestamps, références comptables, etc.) →
    pollution + perte d'info utilisateur.

    Algorithme : pour chaque chiffre en partant de la droite, on double
    chaque chiffre en position paire (1ʳᵉ, 3ᵉ, 5ᵉ depuis la droite). Si le
    résultat dépasse 9, on soustrait 9. La somme totale doit être ≡ 0 mod 10.
    """

    if not digits or not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Patterns PII. La CLÉ devient le label du placeholder (``[EMAIL_1]``,
# ``[URL_1]``, ``[NIR_1]``…). Ajouter une entrée ICI suffit pour que le
# nouveau type apparaisse dans les substitutions runtime — aucun branchement
# spécial dans :func:`apply_builtin_pii`. Si le pattern peut produire des
# faux positifs sur n'importe quelle chaîne structurée comme un X, fournir
# un validateur dans :data:`_PII_VALIDATORS`.
#
# **Ordre d'insertion** = ordre de priorité quand deux patterns matchent la
# MÊME longueur de chaîne (Python dict insertion-ordered + sort stable dans
# ``apply_builtin_pii``). Mettre les patterns les plus SPÉCIFIQUES avant
# les plus larges :
# - EMAIL/URL/PHONE/VAT/IBAN/AMOUNT : formats à structure unique (@, http,
#   préfixe FR, €), aucun risque de chevauchement avec les autres.
# - NIR (15 digits + clé 97) : plus long que SIRET, longest-wins automatique.
# - SIRET (14) > SIREN (9) : longest-wins automatique.
# - CARD (13-19 digits + Luhn) APRÈS SIRET/SIREN/NIR : un SIRET valide
#   passe Luhn (forcément), un SIREN aussi. Si CARD venait en premier sur
#   une longueur identique (14 chars), CARD gagnerait et un SIRET serait
#   étiqueté ``[CARD_N]``.
# - IP (broad: 4 octets) et DATE (broad: 3 nombres séparés) à la fin pour
#   ne JAMAIS rivaliser avec un PII plus structuré.
_PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}]+"),
    # IBAN ISO 13616 — code pays (2 lettres) + clé checksum (2 digits) + BBAN.
    # Le BBAN peut contenir des LETTRES (ex: IBAN FR réels avec lettre dans
    # le code compte : ``FR14 2004 1010 0505 0001 3M02 606``). La regex
    # accepte donc `[A-Z0-9]` dans le BBAN ; la validation MOD-97 dans
    # :func:`_iban_mod97_check` (qui convertit déjà ``A=10 … Z=35``) rejette
    # tout faux positif structurel. Fix 2026-05-19 : avant, regex digits-only
    # ratait ~30% des IBANs FR réels → fuite RGPD silencieuse.
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}\s?(?:[A-Z0-9]{4}\s?){5}[A-Z0-9]{1,4}\b"),
    "PHONE": re.compile(r"(?:\+33|0)\s?[1-9](?:[\s.\-]?\d{2}){4}"),
    "VAT": re.compile(r"\bFR\s?\d{2}\s?\d{9}\b"),
    "NIR": re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"),
    "SIRET": re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b"),
    "SIREN": re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b"),
    "CARD": re.compile(r"\b(?:\d[\s\-]?){12,18}\d\b"),
    "IP": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    "DATE": re.compile(r"\b(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}|\d{4}-\d{1,2}-\d{1,2})\b"),
    "AMOUNT": re.compile(r"\d{1,3}(?:[\s.]\d{3})*(?:,\d{1,2})?\s*€"),
}


def _ipv4_check(ip: str) -> bool:
    """Validation IPv4 — chaque octet doit être dans ``[0, 255]``. Élimine
    les faux positifs sur ``999.999.999.999`` ou versions logicielles."""
    if not isinstance(ip, str) or not ip:
        return False
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or len(part) > 3:
            return False
        if int(part) > 255:
            return False
    return True


def _nir_check(nir: str) -> bool:
    """Validation NIR (sécu sociale FR) — clé 97-MOD-97 sur les 13 premiers
    chiffres, comparée aux 2 derniers. Algo officiel INSEE."""
    if not isinstance(nir, str) or not nir:
        return False
    digits = "".join(c for c in nir if c.isdigit())
    if len(digits) != 15:
        return False
    try:
        body = int(digits[:13])
        key = int(digits[13:15])
    except ValueError:
        return False
    return key == 97 - (body % 97)


def _iban_mod97_check(iban: str) -> bool:
    """Validation MOD-97 ISO 13616 d'un IBAN.

    Algorithme (sans dépendance externe) :

    1. Strip whitespace + uppercase.
    2. Déplacer les 4 premiers caractères (code pays + checksum) en fin.
    3. Convertir chaque lettre en deux digits via A=10, B=11, ..., Z=35.
    4. Le grand entier obtenu doit valoir 1 modulo 97.

    Args:
        iban: chaîne IBAN candidate (espaces tolérés, casse tolérée).

    Returns:
        ``True`` si l'IBAN passe la validation MOD-97, ``False`` sinon
        (y compris en cas de format invalide ou caractère inattendu).
    """
    if not isinstance(iban, str) or not iban:
        return False
    cleaned = iban.replace(" ", "").upper()
    if len(cleaned) < 4:
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    converted_parts: list[str] = []
    for ch in rearranged:
        if ch.isdigit():
            converted_parts.append(ch)
        elif "A" <= ch <= "Z":
            # A=10, B=11, ..., Z=35
            converted_parts.append(str(ord(ch) - ord("A") + 10))
        else:
            # Caractère inattendu → IBAN invalide.
            return False
    try:
        return int("".join(converted_parts)) % 97 == 1
    except ValueError:
        return False


# Validateurs par type de PII — appliqués APRÈS regex match pour rejeter
# les faux positifs structurellement valides mais checksum-faux. Une entrée
# absente = pas de validation supplémentaire (le match regex suffit, ex:
# EMAIL/URL/PHONE/VAT/DATE/AMOUNT déjà très spécifiques par leur structure).
_PII_VALIDATORS: Dict[str, Callable[[str], bool]] = {}


def _luhn_validator(text: str) -> bool:
    """Wrapper qui extrait les chiffres puis applique Luhn. Utilisé pour
    SIRET, SIREN et CARD où les séparateurs (espace, tiret) sont tolérés
    dans la regex mais doivent être ignorés pour la checksum."""
    digits = "".join(c for c in text if c.isdigit())
    return _luhn_check(digits)


_PII_VALIDATORS.update(
    {
        "SIRET": _luhn_validator,
        "SIREN": _luhn_validator,
        "CARD": _luhn_validator,
        "IBAN": _iban_mod97_check,
        "NIR": _nir_check,
        "IP": _ipv4_check,
    }
)


# Sous-ensemble de :data:`_PII_PATTERNS` que :func:`detect_pii_category`
# accepte de retourner — limité aux catégories stockables en BDD
# (cf. ``ANONYMIZATION_CATEGORIES`` dans ``app/models/anonymization_term.py``).
# Les types supplémentaires (URL, VAT, NIR, CARD, IP, DATE) sont quand même
# DÉTECTÉS au RENDU via :func:`detect_pii_label` pour produire un placeholder
# semantique panneau (``§URL_4b3a§``) — c'est l'objectif "maximum de diversité"
# (mai 2026). Le STORAGE BDD reste limité aux 6 categories existantes en
# attendant une migration de la CHECK constraint.
_STORABLE_PII_TYPES: FrozenSet[str] = frozenset({"EMAIL", "PHONE", "SIRET", "IBAN", "AMOUNT"})


def _iter_matching_pii_types(term: str) -> Optional[str]:
    """Helper interne : itère ``_PII_PATTERNS`` dans l'ordre d'insertion et
    retourne le premier type qui matche en ``fullmatch`` + validateur OK.

    Retourne le type UPPERCASE (``"EMAIL"``, ``"URL"``, …) ou ``None``.
    """
    for pii_type, pattern in _PII_PATTERNS.items():
        if pattern.fullmatch(term) is None:
            continue
        validator = _PII_VALIDATORS.get(pii_type)
        if validator is not None and not validator(term):
            continue
        return pii_type
    return None


def detect_pii_category(term: object) -> Optional[str]:
    """Retourne la catégorie PII STOCKABLE d'un terme si elle correspond à
    un pattern built-in, sinon ``None``.

    Utilise un **match EXACT** sur le terme entier (``fullmatch``), pas un
    ``search``. Un terme métier comme ``"contact: a@b.fr"`` ne sera PAS
    catégorisé en ``pii_email`` — seul ``"a@b.fr"`` lui-même l'est. C'est
    voulu : ``anonymization_terms`` contient des tokens individuels, pas
    des chaînes libres.

    **Limité à :data:`_STORABLE_PII_TYPES`** pour respecter la CHECK
    constraint BDD ``ck_anon_term_category``. Les types call-scoped
    seulement (URL, VAT, NIR, CARD, IP, DATE) retournent ``None`` ici —
    ils sont quand même substitués via :func:`apply_builtin_pii` et leur
    label apparaît côté panneau via :func:`detect_pii_label`.

    Args:
        term: token à classifier. Tout non-string ou chaîne vide retourne
            ``None``.

    Returns:
        ``"pii_email" | "pii_phone" | "pii_siret" | "pii_iban" |
        "pii_amount" | None`` (sous-ensemble de
        :data:`_STORABLE_PII_TYPES`).
    """
    if not isinstance(term, str) or not term:
        return None
    pii_type = _iter_matching_pii_types(term)
    if pii_type is None or pii_type not in _STORABLE_PII_TYPES:
        return None
    return f"pii_{pii_type.lower()}"


def detect_pii_label(term: object) -> Optional[str]:
    """Retourne le LABEL UPPERCASE d'un terme s'il matche une regex PII
    (incluant les types call-scoped non stockables), sinon ``None``.

    À la différence de :func:`detect_pii_category`, cette fonction renvoie
    AUSSI les types non stockables en BDD : ``"URL"``, ``"VAT"``, ``"NIR"``,
    ``"CARD"``, ``"IP"``, ``"DATE"``, ``"SIREN"``. Utilisée par
    :func:`resolve_label` pour produire des placeholders panneau diversifiés
    SANS nécessiter de migration BDD (la category stockée reste
    ``"unclassified"`` mais le LABEL d'affichage devient ``"URL"`` etc.).

    Args:
        term: token à classifier.

    Returns:
        Label UPPERCASE (``"EMAIL"``, ``"URL"``, ``"NIR"``, …) ou ``None``
        si aucune regex ne matche en fullmatch + validateur.
    """
    if not isinstance(term, str) or not term:
        return None
    return _iter_matching_pii_types(term)


def resolve_label(term: str, category: Optional[str] = None) -> str:
    """Résolution centralisée du LABEL UPPERCASE pour un terme.

    **Single source of truth** utilisé à la fois par
    :func:`app.services.anonymization.extract._auto_pseudo_middle` (panneau
    /data/privacy + classeur) ET par
    :func:`app.services.anonymization.pseudonymizer._make_token` (token
    envoyé au LLM). Garantit que panneau et substitution LLM utilisent le
    même label, donc même placeholder visible.

    **3 niveaux de priorité** :

    1. **Catégorie stockée** (``category`` non vide et différente
       d'``"unclassified"``) → label via :func:`category_to_label`.
       Couvre les categories BDD existantes : ``pii_email`` → ``"EMAIL"``,
       ``pii_name`` → ``"NAME"``, ``business_code`` → ``"CODE"``, etc.
    2. **Détection regex runtime** (:func:`detect_pii_label`) → étend les
       labels possibles aux types call-scoped (``URL``, ``VAT``, ``NIR``,
       ``CARD``, ``IP``, ``DATE``, ``SIREN``) SANS migration BDD. C'est
       le « maximum de diversité » demandé : même si le terme est en
       ``unclassified`` côté BDD, si sa regex matche un URL, le panneau
       affiche ``URL_4b3a`` au lieu d'un opaque ``TXT_4b3a``.
    3. **Fallback texte/numérique** : si rien ne matche, distingue par la
       nature du terme. ``_is_pure_numeric`` (importé d'``auto_classify``)
       → ``"NUM"`` ; sinon → ``"TXT"``. C'est l'invariant minimum demandé
       par David (mai 2026) : « si le LLM voit un terme anonymisé, qu'il
       puisse savoir si le terme en clair est du texte ou une valeur
       numérique ».

    Args:
        term: cleartext à anonymiser.
        category: catégorie BDD optionnelle (``pii_email``, ``pii_name``,
            ``business_code``, ``unclassified``, …).

    Returns:
        Label UPPERCASE alphanumérique non vide (``"EMAIL"``, ``"URL"``,
        ``"NIR"``, ``"TXT"``, ``"NUM"``, …). Jamais ``None`` ni vide.
    """
    # Import local pour éviter une dépendance circulaire au boot
    # (auto_classify n'importe rien de patterns mais reste un module séparé,
    # l'import au call-time est négligeable et évite un coupling top-level).
    from app.services.anonymization.auto_classify import _is_pure_numeric

    if not isinstance(term, str) or not term:
        return "TERM"

    # Priorité 1 : catégorie stockée explicite.
    has_category = (
        isinstance(category, str)
        and category.strip()
        and category.strip().lower() != "unclassified"
    )
    if has_category:
        return category_to_label(category)

    # Priorité 2 : détection regex runtime (URL/VAT/NIR/CARD/IP/DATE/SIREN
    # + types stockables qui pourraient ne pas avoir été classés à l'insert).
    label = detect_pii_label(term)
    if label:
        return label

    # Priorité 3 : fallback TXT vs NUM selon nature du terme.
    return "NUM" if _is_pure_numeric(term) else "TXT"


def category_to_label(category: Optional[str]) -> str:
    """Convertit une ``category`` BDD en label UPPERCASE court pour
    produire des placeholders sémantiques.

    Règles (génériques — pas de dict de mapping hardcodé) :

    1. ``None``, chaîne vide ou ``"unclassified"`` → ``"TERM"`` (fallback
       neutre, comprehensible par le LLM, ne révèle aucun type).
    2. Préfixe ``"pii_"`` ou ``"business_"`` retiré, le reste passé en
       UPPERCASE et nettoyé (alphanum uniquement) :
       - ``"pii_email"`` → ``"EMAIL"``
       - ``"pii_phone"`` → ``"PHONE"``
       - ``"pii_iban"`` → ``"IBAN"``
       - ``"pii_siret"`` → ``"SIRET"``
       - ``"pii_amount"`` → ``"AMOUNT"``
       - ``"pii_name"`` → ``"NAME"``
       - ``"business_code"`` → ``"CODE"``
    3. Si le résultat est vide après nettoyage → ``"TERM"``.

    **Pas de hardcoded mapping** — la fonction reste valide si une nouvelle
    catégorie ``"pii_url"`` est ajoutée demain : elle produira ``"URL"``
    automatiquement.

    Args:
        category: valeur de la colonne ``category`` (cf.
            ``ANONYMIZATION_CATEGORIES``).

    Returns:
        Label UPPERCASE alphanumérique non vide, max ~15 chars.
    """
    if not isinstance(category, str):
        return "TERM"
    s = category.strip().lower()
    if not s or s == "unclassified":
        return "TERM"
    for prefix in ("pii_", "business_"):
        if s.startswith(prefix):
            s = s[len(prefix) :]
            break
    label = re.sub(r"[^a-zA-Z0-9]", "", s.upper())
    return label or "TERM"


def apply_builtin_pii(
    text: str,
    mapping: Optional[Dict[str, str]] = None,
    counters: Optional[Dict[str, int]] = None,
) -> Tuple[str, Dict[str, str], Dict[str, int]]:
    """Détecte et remplace les PII built-in dans ``text``.

    Cette fonction supporte un **état partagé** cross-appels via les paramètres
    ``mapping`` (token → original) et ``counters`` (par type, pour assurer
    l'unicité des indices). Elle est conçue pour être appelée plusieurs fois
    sur des fragments de payload (récursion sur dict/list) tout en garantissant
    qu'un même type PII conserve un compteur monotone global et que les
    valeurs déjà rencontrées réutilisent le même token.

    ⚠️ **NE JAMAIS partager ``mapping``/``counters`` cross-utilisateur** :
    le même placeholder (ex: ``[EMAIL_1]``) référencerait alors le PII
    d'un user pour un autre — leak cross-user à la dé-anonymisation. Un
    ``mapping`` shared est valide UNIQUEMENT pour les fragments d'un même
    payload, dans la même requête, pour le même user. La fonction
    :func:`app.services.anonymization.proxy.anonymize_for_llm` garantit
    cette isolation en créant ``mapping``/``counters`` neufs à chaque
    appel — passer par le proxy, pas appeler directement.

    Algorithme :

    1. Collecte toutes les matches des patterns PII (cf. :data:`_PII_PATTERNS`).
    2. Pour chaque type ayant un validateur dans :data:`_PII_VALIDATORS`,
       rejeter les matches qui échouent (Luhn pour SIRET/SIREN/CARD,
       MOD-97 pour IBAN, plage 0-255 pour IP, clé 97 pour NIR).
    3. Trie par longueur descendante et conserve les non-chevauchants
       (ex: NIR 15 digits > SIRET 14 digits > SIREN 9 digits).
    4. Pour chaque match retenu :

       - Si la valeur originale est déjà dans ``mapping`` (rencontre antérieure
         dans cet appel ou un appel précédent partageant l'état),
         on **réutilise** le même token (dédup).
       - Sinon, on incrémente ``counters[pii_type]`` et on alloue
         ``[<type>_<count>]``.

    5. Substitue toutes les occurrences dans ``text`` (longest-first pour
       éviter de remplacer un fragment plus court d'abord).

    Args:
        text: Texte à anonymiser.
        mapping: Dict ``{placeholder: original}`` muté en place. Si ``None``,
            un nouveau dict vide est créé (sémantique single-call, équivalent
            à :meth:`DataAnonymizer.anonymize`).
        counters: Dict ``{pii_type: count}`` muté en place. Si ``None``,
            créé vide.

    Returns:
        Tuple ``(anon_text, mapping, counters)``. Les deux derniers sont
        les **mêmes objets** que ceux passés en argument (ou les neufs si
        ``None`` initialement) — on les retourne pour faciliter le pattern
        ``text, m, c = apply_builtin_pii(...)`` en single-call.
    """
    if mapping is None:
        mapping = {}
    if counters is None:
        counters = {}

    # Index inverse pour dédup: original → token déjà alloué.
    # Reconstruit à chaque appel pour être robuste aux mutations externes
    # de ``mapping`` (le caller peut aussi y avoir injecté des tokens via
    # une autre source, ex: pseudonymizer side-channel).
    original_to_token: Dict[str, str] = {v: k for k, v in mapping.items()}

    # Collecte all matches avec spans, puis longest-wins sur chevauchements.
    # (ex: NIR 15 digits > SIRET 14 digits > SIREN 9 digits.) Les validateurs
    # checksum (Luhn/MOD-97/clé NIR/plage IP) sont appliqués AVANT la
    # résolution de chevauchement.
    all_matches: list = []
    for pii_type, pattern in _PII_PATTERNS.items():
        for match in pattern.finditer(text):
            original = match.group(0)
            validator = _PII_VALIDATORS.get(pii_type)
            if validator is not None and not validator(original):
                # Pas un vrai PII de ce type → skip (laisse cleartext OU
                # laisse une regex plus courte/différente le matcher).
                continue
            all_matches.append((match.start(), match.end(), pii_type, original))
    all_matches.sort(key=lambda m: -(m[1] - m[0]))

    taken_ranges: list = []
    new_substitutions: Dict[str, str] = {}  # original → placeholder pour ce text
    for start, end, pii_type, original in all_matches:
        if any(s < end and start < e for s, e in taken_ranges):
            continue
        taken_ranges.append((start, end))

        # Dédup global : si déjà mappé, réutiliser le token.
        existing_token = original_to_token.get(original)
        if existing_token is not None:
            new_substitutions[original] = existing_token
            continue

        count = counters.get(pii_type, 0) + 1
        counters[pii_type] = count
        placeholder = f"[{pii_type}_{count}]"
        mapping[placeholder] = original
        original_to_token[original] = placeholder
        new_substitutions[original] = placeholder

    # Substitue dans le texte (longest first pour éviter qu'un fragment court
    # ne consomme un fragment plus long avant son tour).
    result = text
    for original, placeholder in sorted(new_substitutions.items(), key=lambda x: -len(x[0])):
        result = result.replace(original, placeholder)

    if new_substitutions:
        logger.info("apply_builtin_pii: %d PII remplacées", len(new_substitutions))

    return result, mapping, counters


class DataAnonymizer:
    """Anonymise les données sensibles avant envoi aux LLMs externes.

    Façade orientée objet rétro-compatible. L'implémentation délègue à
    :func:`apply_builtin_pii` (l'algorithme est unique, la classe ne fait
    que wrapper sans persistance d'état entre appels — chaque
    :meth:`anonymize` part avec ``mapping``/``counters`` neufs).
    """

    def anonymize(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Remplace les PII détectées par des placeholders.

        Args:
            text: Texte contenant potentiellement des PII

        Returns:
            Tuple (texte_anonymisé, mapping) où mapping permet la dé-anonymisation.
            Ex: {"[EMAIL_1]": "jean@cabinet.fr", "[PHONE_1]": "01 23 45 67 89"}
        """
        anon, mapping, _counters = apply_builtin_pii(text)
        return anon, mapping

    def deanonymize(self, text: str, mapping: Dict[str, str]) -> str:
        """
        Restaure les valeurs originales dans le texte de réponse.

        Args:
            text: Texte contenant des placeholders
            mapping: Mapping placeholder → valeur originale

        Returns:
            Texte avec les valeurs restaurées
        """
        result = text
        for placeholder, original in mapping.items():
            result = result.replace(placeholder, original)
        return result


# Singleton
_anonymizer = DataAnonymizer()


def get_anonymizer() -> DataAnonymizer:
    """Retourne le singleton DataAnonymizer."""
    return _anonymizer
