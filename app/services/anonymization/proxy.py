"""Proxy d'anonymisation — point d'entrée unique pour les appels LLM.

Module **single source of truth** d'anonymisation Komptia. Compose deux
couches d'anonymisation cumulatives sur n'importe quel payload (string,
dict, list, structure imbriquée) avant envoi à un LLM cloud :

1. **Patterns PII built-in** (:func:`patterns.apply_builtin_pii`) — regex
   email, téléphone FR, SIRET, SIREN, IBAN, montants. Tokens
   ``[TYPE_N]`` (ex: ``[EMAIL_1]``). Compteurs partagés cross-strings
   pour assurer l'unicité globale dans un payload donné.
2. **Pseudonymizer user-scoped** (:func:`extract.build_user_pseudonymizer`)
   — table bijective issue de la BDD ``anonymization_terms`` filtrée sur
   ``enabled=True``. Tokens ``§…§`` (ex: ``§nn_4b3§``, ``§CLIENT_A§``).

**Ordre d'application** : PII regex en premier (défensive : capture les
emails/SIRET/etc. avant que le pseudonymizer ne fragmente leur structure),
puis pseudonymizer. Au restore, l'ordre est inversé (pseudonymizer
d'abord pour défaire ce qui a été appliqué en dernier).

**API publique** :

- :func:`anonymize_for_llm` (réexportée par
  :mod:`app.services.anonymization`) — façade unique pour anonymiser
  ``payload`` et obtenir une closure ``restore_fn`` qui sait défaire les
  deux couches sur la réponse LLM.
- :func:`get_confidentiality_prompt` — fournit le bloc « Confidentialité »
  (français, 2 formats : ``§…§`` et ``[TYPE_N]``) à injecter dans le
  system prompt par le caller. Maintenu côté proxy pour garantir un seul
  texte à jour cross-callers.

**Contrat** :

- ``user_id=None`` : appels système / batch / cron — skip pseudonymizer,
  garde la couche PII regex (defense in depth).
- BDD load fail (asyncio timeout, OperationalError) : **raise**, pas de
  fail-open silencieux (règle Komptia « doute = abstention »).
- ``context_kind`` hors whitelist : ``NotImplementedError`` fail-closed
  immédiat — un caller mal câblé ne doit JAMAIS pass-through au LLM cloud.
- ``restore_fn`` capture l'état local au moment de l'appel : pas de
  relookup BDD pendant le traitement de la réponse (cohérence pour la
  durée du round-trip LLM même si l'utilisateur modifie son state entre
  temps).

**Migration en cours** : l'API est cible des tâches #6/#7/#8 de la loop
d'implémentation anonymisation (32 call sites à migrer). La couche PII
résiduelle dans :mod:`llm_providers` sera retirée tâche #17 une fois
TOUS les call sites migrés (sinon double-anonymisation).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Final, FrozenSet, NamedTuple, Optional, Tuple

from app.services.anonymization.patterns import apply_builtin_pii
from app.services.anonymization.pseudonymizer import Pseudonymizer

logger = logging.getLogger(__name__)


# Discriminants de stratégie admis. Toute valeur hors de cet ensemble
# déclenche un :class:`NotImplementedError` fail-closed pour qu'un
# câblage prématuré ou erroné ne masque pas silencieusement l'absence
# d'anonymisation.
_VALID_CONTEXTS: Final[FrozenSet[str]] = frozenset(
    {
        "IRIS_CHAT",
        "COPILOT",
        "WIDGET_PLAN",
        "REPORT",
        "SCHEMA_ENRICH",
        "SCHEMA_ONLY",
    }
)


# Bloc « Confidentialité » unifié — un seul texte cross-context pour
# minimiser le drift et la maintenance. Format simplifié à 2 types de
# tokens (description tâche #4) :
#
# - ``§…§`` : pseudonymizer user-scoped (BDD ``anonymization_terms``)
# - ``[TYPE_N]`` : PII auto built-in (EMAIL/PHONE/SIRET/SIREN/IBAN/AMOUNT)
#
# Inspiré de :
# - ``app/services/ai/copilot_agent.py`` section "Confidentialité" (§…§)
# - ``app/services/ai/agent_roles.py`` ``CONFIDENTIALITY_INSTRUCTIONS`` (PII)
#
# Le contenu est en français car les LLM cibles répondent en français à
# l'utilisateur final ; un prompt français maintient la cohérence
# linguistique et limite le code-switching FR/EN dans les réponses.
_CONFIDENTIALITY_BLOCK: Final[str] = """## Règles de confidentialité

Certaines valeurs sensibles du contexte qui suit ont été remplacées par des **placeholders** avant envoi. Deux familles coexistent — tu les reconnaîtras à leur forme, **pas à une liste** :

1. **Placeholders utilisateur entre sentinelles `§…§`** : tokens issus du dictionnaire de termes anonymisés de l'utilisateur (noms, raisons sociales, codes métier, identifiants…). Le contenu entre sentinelles a la forme `<LABEL>_<id>` où `<LABEL>` est un mot UPPERCASE qui suggère la catégorie sémantique (ex. `§EMAIL_4b3a§`, `§NAME_8c2d§`, `§IBAN_71fa§`, `§CODE_a1c0§`, `§TERM_3f9b§`…). Un même cleartext produit toujours le même token au cours d'une réponse.

2. **Placeholders PII automatiques entre crochets `[TYPE_N]`** : tokens issus de la détection regex appliquée aux strings du contexte (ex. `[EMAIL_1]`, `[URL_2]`, `[NIR_1]`, `[DATE_3]`, `[CARD_1]`…). `TYPE` est un mot UPPERCASE qui suggère la nature de la donnée, `N` un compteur incrémental.

Tu n'as **PAS** à connaître la liste exhaustive des labels — traite tout token qui matche `§<MOT_MAJ>_<hex|alnum>§` ou `[<MOT_MAJ>_<entier>]` comme un placeholder à manipuler tel quel.

Règles strictes :

- **Préserve** intégralement sentinelles `§…§` et crochets `[…]`, ainsi que la chaîne entre eux. Ne les retire pas, ne les décompose pas, ne les traduis pas, ne change pas la casse.
- **N'invente PAS** de nouveaux placeholders (pas de `§CLIENT_B§` non fourni, pas de `[EMAIL_99]` arbitraire). Utilise UNIQUEMENT ceux qui apparaissent dans le contexte.
- **Ne devine pas** le cleartext derrière un placeholder. Le label suggère la catégorie (utile pour ton raisonnement : « `§EMAIL_4b3a§` est un email ») mais le système n'expose pas la valeur d'origine.
- Le système retraduit chaque placeholder en cleartext avant affichage à l'utilisateur. Si tu construis une phrase qui mentionne 3 personnes, place les 3 tokens distincts ; ils seront remplacés à l'envoi.
- Les nombres, dates et labels structurels (titres de colonnes, en-têtes) qui n'ont **pas** été remplacés restent en clair — ils sont structurels, pas confidentiels.
"""


# ---------------------------------------------------------------------------
# SSOT — Formats de tokens d'anonymisation produits par Komptia
# ---------------------------------------------------------------------------
# Source unique de vérité pour les formats de placeholders qu'un LLM peut
# rencontrer dans le contexte qu'on lui envoie. Cette structure est ensuite
# utilisée pour :
#   1. Générer la section pédagogique du system prompt
#      (cf. :func:`render_pii_formats_section_fr` ci-dessous)
#   2. Garder ``app/services/ai/agent_roles.py::CONFIDENTIALITY_INSTRUCTIONS``
#      synchronisée — quand un format est retiré/ajouté ici, le prompt LLM
#      l'est aussi automatiquement (refactor SSOT-6, 2026-05-21).
#
# Conserver l'ordre du tuple : il définit l'ordre d'apparition dans le prompt.
# Producteur = chemin court (module + fonction) qui produit ce format au
# runtime, utile à un dev pour tracer un placeholder inattendu.
#
# Note historique : le format ``~xxx`` (pseudonymizer legacy) est toujours
# produit par :mod:`app.services.anonymization.strategies` et
# :mod:`app.services.ai.orchestrator_models` (sample values). Tant que ces
# producteurs existent, le LLM doit savoir le manipuler.


class PIITokenFormat(NamedTuple):
    """Description d'un format de placeholder d'anonymisation.

    Champs :

    - ``key`` : identifiant interne court (utilisable comme clé/test).
    - ``shape`` : forme textuelle abstraite (``"~xxx"``, ``"§…§"``,
      ``"[TYPE_N]"``).
    - ``examples`` : exemples concrets pour ancrer le LLM (séparés par
      ``" / "`` dans le rendu).
    - ``producer`` : module producteur — sert d'identifiant SSOT au
      reviewer humain pour tracer un placeholder inattendu.
    - ``description_fr`` : phrase descriptive en français à injecter
      dans la section pédagogique.
    """

    key: str
    shape: str
    examples: str
    producer: str
    description_fr: str


PII_TOKEN_FORMATS: Final[Tuple[PIITokenFormat, ...]] = (
    PIITokenFormat(
        key="tilde_legacy",
        shape="~xxx",
        examples="~UOT / ~IA / ~DPNT",
        producer="app.services.anonymization.strategies",
        description_fr=(
            "valeurs tronquées (voyelles retirées) par le pseudonymizer legacy. "
            "Le contenu après `~` n'est PAS reconstituable, ne tente pas de deviner."
        ),
    ),
    PIITokenFormat(
        key="sentinel_user",
        shape="§LABEL_hash§",
        examples="§EMAIL_4b3a§ / §NAME_8c2d§ / §CODE_a1c0§",
        producer="app.services.anonymization.pseudonymizer",
        description_fr=(
            "tokens issus du dictionnaire user-scoped (proxy unifié). `LABEL` suggère "
            "la catégorie sémantique (NAME, EMAIL, CODE, TERM…) pour t'aider à "
            "raisonner, mais le cleartext reste opaque."
        ),
    ),
    PIITokenFormat(
        key="bracket_pii",
        shape="[TYPE_N]",
        examples="[EMAIL_1] / [PHONE_2] / [SIRET_1] / [IBAN_3]",
        producer="app.services.anonymization.patterns",
        description_fr=(
            "tokens issus de la détection regex PII automatique "
            "(EMAIL/PHONE/SIRET/SIREN/IBAN/AMOUNT/URL)."
        ),
    ),
)


def render_pii_formats_section_fr() -> str:
    """Rend la section « Échantillon anonymisé — N formats » du system prompt.

    Source de vérité : :data:`PII_TOKEN_FORMATS`. Toute modification de la
    structure (ajout/retrait/réordonnancement d'un format) se propage au
    prompt LLM automatiquement, sans toucher au texte hardcodé d'un autre
    module (refactor SSOT-6).

    Le rendu reste stable (pas de timestamp, pas de randomisation) — deux
    appels successifs sans modif de :data:`PII_TOKEN_FORMATS` produisent
    le même bytes-for-bytes texte, ce qui rend les tests de snapshot
    fiables.

    Returns:
        Section markdown FR prête à concaténer dans un system prompt.
    """
    if not PII_TOKEN_FORMATS:  # garde-fou : pas de section vide silencieuse
        raise RuntimeError(
            "PII_TOKEN_FORMATS est vide — au moins un format de placeholder doit "
            "être déclaré (sinon le LLM ne saura pas reconnaître les tokens)."
        )
    n_formats = len(PII_TOKEN_FORMATS)
    bullets = []
    for fmt in PII_TOKEN_FORMATS:
        # Forme textuelle adaptée selon le type (préfixe, sentinelle, crochets)
        if fmt.shape.startswith("~"):
            shape_label = f"Préfixe `{fmt.shape}`"
        elif fmt.shape.startswith("§"):
            shape_label = f"Sentinelles `{fmt.shape}`"
        elif fmt.shape.startswith("["):
            shape_label = f"Crochets `{fmt.shape}`"
        else:
            shape_label = f"Forme `{fmt.shape}`"
        # Reformater les exemples en code FR (séparateur virgule en français)
        examples_md = ", ".join(f"`{ex.strip()}`" for ex in fmt.examples.split("/"))
        bullets.append(f"   - **{shape_label}** (ex: {examples_md}) — {fmt.description_fr}")
    bullets_str = "\n".join(bullets)
    return (
        f"8. **Échantillon anonymisé — {n_formats} formats de placeholders possibles** : "
        f"L'échantillon que tu reçois\n"
        f"   dans `anonymized_sample` (ou tout autre contexte LLM) contient des "
        f"valeurs sensibles remplacées\n"
        f"   par des placeholders. Tu peux rencontrer {n_formats} formats — traite-les "
        f"TOUS comme des opaque\n"
        f"   tokens à manipuler tel quel :\n\n"
        f"{bullets_str}\n"
    )


def render_pii_formats_sql_hints_fr() -> str:
    """Rend la section « Valeurs anonymisées dans le SQL » dérivée de la SSOT.

    Pendant pédagogique de :func:`render_pii_formats_section_fr` pour le
    contexte SQL — explique au LLM comment quoter les tokens dans une
    requête SQL. Liste les formats depuis :data:`PII_TOKEN_FORMATS` au
    lieu de les énumérer en dur (refactor SSOT-6).
    """
    if not PII_TOKEN_FORMATS:  # pragma: no cover — déjà couvert dans helper sœur
        raise RuntimeError("PII_TOKEN_FORMATS est vide.")
    n_formats = len(PII_TOKEN_FORMATS)
    bullets = []
    for fmt in PII_TOKEN_FORMATS:
        examples_md = ", ".join(f"`{ex.strip()}`" for ex in fmt.examples.split("/"))
        bullets.append(f"- Format `{fmt.shape}` (ex: {examples_md})")
    bullets_str = "\n".join(bullets)
    return (
        f"Quand le système te fournit des **hints de correspondance** "
        f"(section \"Correspondance valeurs\nutilisateur → colonnes\"), cela "
        f"signifie que l'utilisateur a mentionné des valeurs réelles qui\n"
        f"ont été remplacées par des tokens pour la confidentialité. "
        f"Tu peux rencontrer {n_formats} formats de\n"
        f"tokens dans tes hints et tes inputs (cf. section 8 ci-dessus pour le détail) :\n\n"
        f"{bullets_str}\n"
    )


def get_confidentiality_prompt(context_kind: str) -> str:
    """Retourne le bloc « Confidentialité » à injecter dans le system prompt.

    Le bloc est unifié pour tous les ``context_kind`` valides : un seul
    texte à maintenir, garantit l'absence de drift entre callers. Le LLM
    apprend à respecter les deux formats de tokens (``§…§`` user et
    ``[TYPE_N]`` PII auto) quel que soit le contexte d'usage.

    Args:
        context_kind: discriminant — ``"IRIS_CHAT"``, ``"COPILOT"``,
            ``"WIDGET_PLAN"``, ``"REPORT"``, ``"SCHEMA_ENRICH"``,
            ``"SCHEMA_ONLY"``.

    Returns:
        Le bloc de prompt en français, ~16 lignes. Stable cross-appels.

    Raises:
        NotImplementedError: ``context_kind`` hors whitelist.
    """
    if context_kind not in _VALID_CONTEXTS:
        raise NotImplementedError(
            f"get_confidentiality_prompt: context_kind={context_kind!r} "
            f"inconnu (admis: {sorted(_VALID_CONTEXTS)})."
        )
    return _CONFIDENTIALITY_BLOCK


async def anonymize_for_llm(
    user_id: Optional[int],
    payload: Any,
    context_kind: str,
) -> Tuple[Any, Callable[[Any], Any]]:
    """Anonymise un payload avant envoi LLM cloud, retourne un restaurateur.

    Compose deux couches d'anonymisation :

    1. **PII built-in** (regex EMAIL/PHONE/SIRET/SIREN/IBAN/AMOUNT) — appliquée
       d'abord sur tous les strings du payload, avec compteurs partagés
       cross-strings (un seul ``[EMAIL_1]`` pour le payload entier).
    2. **Pseudonymizer user-scoped** (BDD ``anonymization_terms``) — appliquée
       sur le résultat. Substitue les termes ``enabled=True`` du user par
       leurs tokens ``§…§``.

    Args:
        user_id: identifiant utilisateur. ``None`` → skip pseudonymizer
            (calls système / batch). PII regex toujours appliquée.
        payload: payload à anonymiser. Types supportés : ``str``, ``int``,
            ``float``, ``bool``, ``None``, ``dict``, ``list``, ``tuple``.
            Récursion sur structures imbriquées. Les **clés** de dict ne
            sont PAS modifiées (= colonnes, métadonnées structurelles
            non confidentielles) — conséquence : si le LLM place un token
            dans une key au retour, il ne sera pas restauré (le bloc
            « Confidentialité » instruit le LLM de ne pas le faire).
        context_kind: discriminant — voir
            :func:`get_confidentiality_prompt`. Inconnu →
            ``NotImplementedError`` fail-closed.

    Précédence des couches :
        Si une valeur cleartext matche à la fois une regex PII built-in
        ET un terme user du pseudonymizer, **la PII regex gagne** (PII
        appliquée en premier consomme la valeur). Exemple : un terme
        user ``"jean@cabinet.fr"`` avec un pseudo custom ``§CLIENT_X§``
        sera quand même tokenisé en ``[EMAIL_1]`` car la regex EMAIL
        capture la chaîne complète d'abord. Conception défensive :
        les types PII auto-détectés sont les plus sensibles (RGPD).

    Round-trip numérique :
        Si l'utilisateur a explicitement marqué une **valeur numérique**
        (``42``, ``3.14``) comme à anonymiser via ``add_mapping``, le
        :class:`~Pseudonymizer` la convertit en string ``"§…§"`` au
        anonymize. À la dé-anonymisation, on retrouve une string
        ``"42"`` (pas le ``int`` original). Cf. :class:`~Pseudonymizer`
        docstring lignes 502-512 pour le compromis détaillé.

    Returns:
        Tuple ``(payload_anonymisé, restore_fn)`` où ``restore_fn(reponse)``
        ré-applique les mappings inverses (pseudonymizer + PII) sur la
        réponse LLM. Le ``restore_fn`` est une closure qui capture
        l'état local au moment de l'anonymisation — pas de relookup BDD
        au restore, garantissant la cohérence du round-trip même si
        l'utilisateur modifie son state pendant le call LLM.

    Raises:
        NotImplementedError: ``context_kind`` hors whitelist.
        Exception (sqlalchemy / async): si la lecture BDD du state user
            échoue. Pas de fail-open silencieux — le caller doit gérer
            ou remonter à l'utilisateur (règle Komptia « doute =
            abstention »).

    ⚠️ **MUST be awaited**. Coroutine async — un appel sans ``await``
    retourne un coroutine object, le payload n'est PAS modifié, et la
    couche d'anonymisation est silencieusement skippée.
    """
    if context_kind not in _VALID_CONTEXTS:
        raise NotImplementedError(
            f"anonymize_for_llm: context_kind={context_kind!r} inconnu "
            f"(admis: {sorted(_VALID_CONTEXTS)}). Fail-closed — un context "
            f"inconnu ne doit JAMAIS pass-through au LLM cloud."
        )

    # 1. Apply PII regex first (placeholders out-of-band : `[TYPE_N]`,
    #    not in scope of pseudonymizer's word-boundary regex).
    pii_mapping: Dict[str, str] = {}
    pii_counters: Dict[str, int] = {}
    payload_after_pii = _pii_anonymize_recursive(payload, pii_mapping, pii_counters)

    # 2. Load user pseudonymizer (None if no user_id, possibly empty if
    #    no enabled terms — both cases skip layer 2 cheaply).
    pseudo: Optional[Pseudonymizer] = None
    if user_id is not None:
        pseudo = await _load_user_pseudonymizer(user_id)

    # 3. Apply pseudonymizer recursively (handles all types : str, dict,
    #    list, tuple, int/float si listés explicitement par l'user).
    if pseudo is not None and len(pseudo) > 0:
        payload_anon = pseudo.anonymize(payload_after_pii)
    else:
        payload_anon = payload_after_pii

    # 4. Build restore_fn (closure captures local pseudo + pii_mapping —
    #    pas de relookup BDD pendant la durée de vie de la closure).
    def restore_fn(response: Any) -> Any:
        if response is None:
            return None
        result = response
        # Restore pseudonymizer first (sentinels `§…§`, no overlap with PII brackets `[…]`)
        if pseudo is not None and len(pseudo) > 0:
            result = pseudo.deanonymize(result)
        # Then PII placeholders
        if pii_mapping:
            result = _pii_restore_recursive(result, pii_mapping)
        return result

    logger.debug(
        "anonymize_for_llm: user=%s context=%s pii=%d pseudo_terms=%d",
        user_id,
        context_kind,
        len(pii_mapping),
        len(pseudo) if pseudo is not None else 0,
    )
    return payload_anon, restore_fn


async def _load_user_pseudonymizer(user_id: int) -> Pseudonymizer:
    """Charge un :class:`Pseudonymizer` user-scoped depuis la BDD.

    Lit le state ``anonymization_terms`` de l'utilisateur et construit un
    Pseudonymizer pré-peuplé de tous les termes ``enabled=True``. Retourne
    un Pseudonymizer **vide** si l'utilisateur n'a aucun terme actif —
    le caller skip alors la couche 2 sans effort.

    **Garde fail-closed sur perte de termes** :
    :func:`build_user_pseudonymizer` peut sauter silencieusement un terme
    en cas de collision (logué WARNING dans
    :mod:`app.services.anonymization.extract`). On compare le nombre de
    termes ``enabled=True`` du state au nombre d'entrées dans le
    pseudonymizer construit ; si moins, on raise — un terme manquant =
    cleartext qui passerait au LLM = violation de "doute = abstention".

    Args:
        user_id: identifiant user (non-None ; le caller filtre None en
            amont pour distinguer "appel système" de "user sans terme").

    Returns:
        Instance :class:`Pseudonymizer` (potentiellement vide).

    Raises:
        RuntimeError: pseudonymizer incomplet (un ou plusieurs termes
            ``enabled=True`` n'ont pas pu être chargés — typiquement
            collision de pseudo_middle entre deux termes différents).
            Le caller doit remonter à l'utilisateur ou logger l'incident.
        Exception: lecture BDD échoue (sqlalchemy timeout, OperationalError,
            etc.). Pas de fail-open silencieux — le caller décide
            (typiquement : remonter une erreur 503 à l'utilisateur).
    """
    # Imports locaux pour éviter un cycle au boot (database → models →
    # services). Le module proxy est importable très tôt dans la chaîne.
    from app.core.database import get_session
    from app.services.anonymization.extract import build_user_pseudonymizer
    from app.services.anonymization.repository import get_state_for_user

    async with get_session() as session:
        state = await get_state_for_user(session, user_id)

    pseudo = build_user_pseudonymizer(state)

    # Fail-closed : compter les termes attendus (enabled=True) et comparer
    # à la taille du pseudonymizer chargé. Une perte silencieuse signifie
    # qu'un terme va passer en cleartext au LLM — refus net.
    terms = state.get("terms") if isinstance(state, dict) else None
    if isinstance(terms, dict):
        expected_enabled = sum(
            1
            for entry in terms.values()
            if isinstance(entry, dict) and bool(entry.get("enabled", False))
        )
        if len(pseudo) < expected_enabled:
            missing = expected_enabled - len(pseudo)
            raise RuntimeError(
                f"_load_user_pseudonymizer: pseudonymizer incomplet pour "
                f"user_id={user_id} — {missing} terme(s) sur {expected_enabled} "
                f"non chargé(s) (collision pseudo_middle ou erreur silencieuse "
                f"dans extract.build_user_pseudonymizer). Refus fail-closed : "
                f"un terme manquant = cleartext qui fuiterait au LLM."
            )

    return pseudo


def _pii_anonymize_recursive(
    obj: Any,
    mapping: Dict[str, str],
    counters: Dict[str, int],
) -> Any:
    """Applique :func:`apply_builtin_pii` récursivement sur un payload.

    Les ``mapping`` et ``counters`` sont **partagés** cross-récursion —
    ainsi un email apparaissant dans deux strings différentes dans le même
    payload obtient le même token (dédup), et les compteurs PII restent
    monotones globalement (``[EMAIL_1]``, ``[EMAIL_2]``, … sans réinitialisation).

    Args:
        obj: payload — ``str``, ``dict``, ``list``, ``tuple``, ou type
            scalaire (``int``, ``float``, ``bool``, ``None``).
        mapping: dict ``{token: original}`` muté en place.
        counters: dict ``{pii_type: count}`` muté en place.

    Returns:
        Payload anonymisé (nouvelle structure, l'original n'est pas muté).
    """
    if isinstance(obj, str):
        anon, _, _ = apply_builtin_pii(obj, mapping, counters)
        return anon
    if isinstance(obj, dict):
        # Les KEYS ne sont PAS anonymisées (= colonnes / métadonnées
        # structurelles, pas confidentielles). Cohérent avec le contrat
        # Pseudonymizer.anonymize.
        return {k: _pii_anonymize_recursive(v, mapping, counters) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_pii_anonymize_recursive(v, mapping, counters) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_pii_anonymize_recursive(v, mapping, counters) for v in obj)
    # int, float, bool, None, custom objects : pass-through.
    # Les valeurs numériques explicitement marquées par l'user passent par
    # la couche pseudonymizer (qui gère la conversion via _forward[str(num)]).
    return obj


def _pii_restore_recursive(obj: Any, mapping: Dict[str, str]) -> Any:
    """Restaure les placeholders PII vers les valeurs originales, récursif.

    Réplique la logique de :meth:`DataAnonymizer.deanonymize` mais sur des
    structures imbriquées (la réponse LLM peut être structurée, ex: JSON
    parsé en dict). Substitution **longest-first** pour éviter qu'un
    placeholder court ne corrompe un placeholder long qui le contient
    comme préfixe (ex: ``[EMAIL_1]`` matché à l'intérieur de ``[EMAIL_10]``
    si on itère par insertion order au lieu de longueur — bug détecté en
    review adversariale tâche #4, qui apparaît à 10+ valeurs PII de
    même type dans un payload).

    Note sur les KEYS de dict : par symétrie avec
    :func:`_pii_anonymize_recursive`, les clés ne sont **pas** restaurées
    (elles ne sont pas anonymisées non plus). Le bloc « Confidentialité »
    instruit le LLM de ne pas placer de tokens dans des clés.

    Args:
        obj: réponse LLM — types identiques à
            :func:`_pii_anonymize_recursive`.
        mapping: dict ``{placeholder: original}`` capturé par la closure.

    Returns:
        Réponse avec placeholders PII restaurés.
    """
    # Précompute l'ordre de substitution (longest-first) une fois pour
    # toute la récursion — pas par-string. La liste résultante est
    # immuable pour la durée de l'appel.
    sorted_pairs = sorted(mapping.items(), key=lambda item: -len(item[0]))
    return _pii_restore_walk(obj, sorted_pairs)


def _pii_restore_walk(obj: Any, sorted_pairs: list) -> Any:
    """Walker récursif interne — utilise une liste pré-triée pour
    garantir que les placeholders longs (ex: ``[EMAIL_10]``) sont
    substitués AVANT les courts (ex: ``[EMAIL_1]``)."""
    if isinstance(obj, str):
        result = obj
        for placeholder, original in sorted_pairs:
            result = result.replace(placeholder, original)
        return result
    if isinstance(obj, dict):
        return {k: _pii_restore_walk(v, sorted_pairs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_pii_restore_walk(v, sorted_pairs) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_pii_restore_walk(v, sorted_pairs) for v in obj)
    return obj
