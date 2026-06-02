"""CRUD async sur ``AnonymizationTerm`` — liste des termes à anonymiser
d'un utilisateur.

Toutes les fonctions prennent une session SQLAlchemy async explicite
(fournie par ``BaseHandler.db_session()`` ou par un wrapper asyncio dans
le scheduler). Elles N'ENGAGENT PAS le commit — c'est le caller qui décide
(le context manager ``db_session()`` commit en sortie).

**Contrat** : le "state" manipulé ici respecte le schéma ``anon_terms`` v1
(cf. :mod:`app.services.anonymization.extract`) :

    {"version": 1, "terms": {<token>: {enabled, confirmed, pseudo?}}}

La BDD n'encode pas le champ ``version`` — il est ajouté à la lecture.
"""

from __future__ import annotations

import json
import logging
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import and_, case, delete, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.anonymization_term import AnonymizationTerm
from app.services.anonymization import extract as anon_terms
from app.services.anonymization import patterns as anon_patterns
from app.services.anonymization.user_id_guard import is_valid_user_id
from app.services.anonymization.locks import acquire_user_anon_lock

logger = logging.getLogger(__name__)


def _warn_invalid_user_id(fn_name: str, user_id: Any) -> None:
    """Defense-in-depth : trace un WARNING quand un ``user_id`` non-trivial
    (ni ``None`` ni ``0`` — sentinelles "vide" légitimes des accesseurs
    user-scoped) échoue :func:`is_valid_user_id` et atteint un guard fail-closed.

    Parité avec :func:`acquire_user_anon_lock` (locks.py), qui logge déjà ce
    cas. Sans ce log, un appelant qui passerait par erreur un ``bool``
    (``isinstance(True, int) is True`` → ``WHERE user_id == 1`` en SQL), une
    chaîne, ou un négatif verrait SILENCIEUSEMENT un résultat vide au lieu d'un
    signal : c'est une donnée fausse silencieuse (le pire cas — cf. doctrine
    "conséquences" #5). Le guard reste fail-closed (aucune fuite cross-user) ;
    ce helper ne fait qu'en assurer l'observabilité. ``None``/``0`` restent
    muets car ce sont des entrées attendues ("user vide / inconnu")."""
    if not is_valid_user_id(user_id) and user_id is not None and user_id != 0:
        logger.warning(
            "%s: user_id invalide (%r, type=%s) — fail-closed (résultat vide). "
            "L'appelant doit fournir un int strictement positif.",
            fn_name,
            user_id,
            type(user_id).__name__,
        )


async def get_user_term_cap(session: AsyncSession, user_id: int) -> int:
    """Cap dynamique des termes d'anonymisation pour un user, dérivé du
    quota disque admin (``UserStorage.quota_limit``).

    Aligne l'anonymisation sur la promesse Komptia "le seul cap c'est le
    quota disque" (décision 2026-05-19). Le calcul :

    1. Lit ``quota_limit`` + ``quota_used`` (fichiers) + ``db_bytes_used``
       (BDD) depuis ``UserStorage``.
    2. ``remaining = quota_limit - quota_used - db_bytes_used`` (octets
       libres avant saturation du quota).
    3. ``cap = remaining // BYTES_PER_TERM_ESTIMATE`` (estimation 200
       bytes/terme, calibrée empiriquement sur dataset cabinet).
    4. Clamp : ``[MAX_STATE_TERMS_MIN, MAX_STATE_TERMS_HARD_CAP]`` — le
       floor garantit qu'un user à 99 % de quota peut quand même ajouter
       quelques termes critiques (PII en attente de revue), le hard cap
       protège la RAM serveur si un admin met un ``quota_limit`` démesuré.

    **Fallback fail-safe** : si pas de row ``UserStorage`` (user pas encore
    tracké, cas dégradé migration), retourne ``MAX_STATE_TERMS_HARD_CAP``.
    L'absence de quota ≠ blocage user. Le hard cap reste appliqué.

    Args:
        session: session async SQLAlchemy.
        user_id: identifiant user — doit être > 0.

    Returns:
        Cap effectif (int) à appliquer pour ce user dans cette session.
    """
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("get_user_term_cap", user_id)
        return anon_terms.MAX_STATE_TERMS_MIN
    # Import tardif pour éviter cycle (``UserStorage`` → ``User`` → potentiels
    # imports de services qui importent ``repository``).
    from app.models.user_storage import UserStorage

    row = (
        await session.execute(
            select(
                UserStorage.quota_limit,
                UserStorage.quota_used,
                UserStorage.db_bytes_used,
            ).where(UserStorage.user_id == user_id)
        )
    ).first()
    if row is None:
        # User non tracké : pas de quota → applique uniquement le hard cap.
        return anon_terms.MAX_STATE_TERMS_HARD_CAP
    quota_limit = int(row[0] or 0)
    quota_used = int(row[1] or 0)
    db_bytes_used = int(row[2] or 0)
    remaining = max(0, quota_limit - quota_used - db_bytes_used)
    raw_cap = remaining // anon_terms.BYTES_PER_TERM_ESTIMATE
    # Clamp [MIN, HARD_CAP]. Le ``max(MIN, raw)`` garantit le floor —
    # même quota saturé, un user peut encore ajouter ``MIN`` termes
    # critiques (anti UX-mort).
    return max(
        anon_terms.MAX_STATE_TERMS_MIN,
        min(anon_terms.MAX_STATE_TERMS_HARD_CAP, raw_cap),
    )


#: Cap miroir de ``AnonymizationTerm.origins`` (VARCHAR(5000)). On tronque
#: alphabétiquement à la sérialisation pour rester déterministe.
_ORIGINS_MAX_LEN: int = 5000
#: Cap par champ ``classeur``/``col`` (miroir de ``AnonymizationTerm.source_ref``).
_ORIGIN_FIELD_MAX_LEN: int = 200


def _canonical_key(term: str) -> str:
    """Clé canonique pour comparer 2 termes en case-insensitive Unicode-aware.

    Normalise via NFKC (neutralise variantes Unicode NFC/NFD, ligatures) puis
    casefold (case-insensitive Unicode-aware ≠ ``lower()`` ASCII-naïf).

    Utilisée par ``upsert_terms`` (dédup intra/inter-batch) ET ``replace_state``
    (diff before/after pour les boucles audit) pour garantir que les deux
    fonctions partagent la même notion d'identité de terme — sinon le diff
    audit pense que ``"DUPONT"`` et ``"Dupont"`` sont des termes différents
    alors que la BDD les unifie via la même row (perte silencieuse du terme,
    cf. ``tests/unit/test_replace_state_case_insensitive.py``).
    """
    return unicodedata.normalize("NFKC", term).casefold()


def _sanitize_pseudo_value(pseudo: Any) -> Optional[str]:
    """Normalise un ``pseudo`` input — retourne ``None`` si invalide.

    Reproduit les 4 règles appliquées en BDD par ``upsert_terms`` (cf. branches
    de l'ancien bloc ligne 205-214 de ce module) pour fournir une **single
    source of truth** entre le path d'écriture (``upsert_terms``) et le path
    d'audit (``replace_state``). Sans ce partage, l'audit pouvait logger un
    changement de ``pseudo_middle`` qui n'avait jamais lieu en BDD (mensonge
    audit silencieux — cf. ``tests/unit/test_replace_state_pseudo_sanitize.py``).

    Règles invalides → ``None`` :

    - ``pseudo`` non-string
    - chaîne vide ``""``
    - longueur > :data:`anon_terms.MAX_PSEUDO_MIDDLE_LEN` (128)
    - contient la sentinelle ``§`` (utilisée pour les tokens de pseudonymizer
      ``§…§`` qui ne doivent pas apparaître au milieu d'un pseudo user)
    """
    if pseudo is None:
        return None
    if not isinstance(pseudo, str):
        return None
    if pseudo == "":
        return None
    if len(pseudo) > anon_terms.MAX_PSEUDO_MIDDLE_LEN:
        return None
    if "§" in pseudo:
        return None
    return pseudo


def _normalize_origin_entry(
    entry: Any,
) -> Optional[Tuple[Optional[str], Optional[str]]]:
    """Normalise un dict ``{"classeur": ..., "col": ...}`` en tuple canonique.

    Retourne ``None`` si l'entrée est invalide ou totalement vide (les deux
    champs ``None``). ``classeur``/``col`` sont strippés, cap à
    :data:`_ORIGIN_FIELD_MAX_LEN`, et les chaînes vides après strip sont
    converties en ``None`` (la sémantique "origine sans colonne" ou "scan
    sans classeur" est portée par ``None``, pas par ``""``).
    """
    if not isinstance(entry, dict):
        return None
    classeur = entry.get("classeur")
    col = entry.get("col")
    if classeur is not None:
        if not isinstance(classeur, str):
            classeur = None
        else:
            stripped = classeur.strip()
            classeur = stripped[:_ORIGIN_FIELD_MAX_LEN] if stripped else None
    if col is not None:
        if not isinstance(col, str):
            col = None
        else:
            stripped = col.strip()
            col = stripped[:_ORIGIN_FIELD_MAX_LEN] if stripped else None
    if classeur is None and col is None:
        return None
    return (classeur, col)


def _serialize_origins(
    origin_tuples: Set[Tuple[Optional[str], Optional[str]]],
) -> Optional[str]:
    """Sérialise un set d'origines en JSON déterministe.

    Tri stable : ``(classeur, col)`` lex ascendant, ``None`` en queue. On
    discrimine ``None`` via un flag entier ``(1 if v is None else 0, v or "")``
    plutôt qu'un sentinel char Unicode (un sentinel comme ``"￿"`` U+FFFF
    serait dépassé par un emoji U+1F992 ⇒ tri instable, fix finding #8 review).
    Tronquage à :data:`_ORIGINS_MAX_LEN` chars par retrait progressif depuis
    la fin (les origines alphabétiquement dernières disparaissent en premier
    — déterministe et reproductible).
    """
    if not origin_tuples:
        return None

    def _sort_key(t: Tuple[Optional[str], Optional[str]]) -> Tuple[int, str, int, str]:
        classeur, col = t
        return (
            1 if classeur is None else 0,
            classeur or "",
            1 if col is None else 0,
            col or "",
        )

    sorted_origins = sorted(origin_tuples, key=_sort_key)
    entries: List[Dict[str, Optional[str]]] = [
        {"classeur": classeur, "col": col} for classeur, col in sorted_origins
    ]
    serialized = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    while entries and len(serialized) > _ORIGINS_MAX_LEN:
        entries.pop()
        serialized = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    if not entries:
        return None
    return serialized


def _parse_origins(
    serialized: Optional[str],
) -> Set[Tuple[Optional[str], Optional[str]]]:
    """Parse un JSON sérialisé d'origines en set de tuples. Tolérant.

    Retourne un set vide si ``serialized`` est ``None``, vide, non-JSON, ou
    si le JSON décodé n'est pas une liste. Chaque entrée est passée par
    :func:`_normalize_origin_entry` pour appliquer les mêmes règles de
    validation que le path d'écriture (single source of truth).
    """
    if not serialized or not isinstance(serialized, str):
        return set()
    try:
        raw = json.loads(serialized)
    except (json.JSONDecodeError, ValueError):
        return set()
    if not isinstance(raw, list):
        return set()
    out: Set[Tuple[Optional[str], Optional[str]]] = set()
    for entry in raw:
        normalized = _normalize_origin_entry(entry)
        if normalized is not None:
            out.add(normalized)
    return out


async def get_state_for_user(
    session: AsyncSession,
    user_id: int,
    *,
    scope_tokens: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Retourne le state ``anon_terms`` v1 complet pour un utilisateur.

    Pas de filtrage — on expose tout (y compris ``confirmed=False``, qui
    déclenchera le gate côté copilot). Les termes sans ``pseudo_middle``
    sortent sans clé ``pseudo`` (l'auto-gen prendra le relais dans
    ``build_user_pseudonymizer``).

    ``scope_tokens`` (optionnel) : si fourni, restreint la lecture aux
    termes dont la clé ``term`` figure dans cette collection. Permet au
    copilot d'éviter de charger 53k termes cross-classeur quand le
    workbook courant n'en utilise que 150 (mesuré : ~660ms → ~50ms sur
    un state à 53k entries). **Ne change PAS la sémantique gate du
    copilot** : le ``vanished_tokens`` calculé par ``reconcile_state``
    devient |state-actuel| - |scope|, mais c'est de toute façon un
    informationnel (cf. ``feedback_no_decorative_i_buttons`` /
    ``project_open_findings_2026_04_30`` axe 21 — log noise quand state
    accumulé). Le pseudonymizer scope-filtré dans
    ``build_user_pseudonymizer`` continue d'enabler les bons termes.

    Important : ``scope_tokens`` est purement une optim, le caller qui
    veut un VRAI état complet (page /data/privacy, exports admin, audit)
    doit l'omettre — c'est la sémantique par défaut.

    Retourne toujours un dict valide (vide si l'utilisateur n'a rien).
    """
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("get_state_for_user", user_id)
        return {"version": anon_terms.STATE_VERSION, "terms": {}}

    # Perf (2026-05-26 Bug n°8) : pour le cas users à 90K+ termes
    # (mesuré : user_id=1 avait 92 094 termes), la requête raw SELECT *
    # prend 550ms et l'hydration ORM ajoute ~1.5s = 2,1s total. Fast-path :
    # on sélectionne UNIQUEMENT les colonnes nécessaires au state v1
    # (pas tout le row ORM) → skip l'hydration objet + réduit la mémoire
    # par 3-4x. La projection match exactement les champs construits dans
    # le dict de sortie ci-dessous — toute nouvelle clé doit être ajoutée
    # à la fois ici et au SELECT.
    stmt = select(
        AnonymizationTerm.id,
        AnonymizationTerm.term,
        AnonymizationTerm.enabled,
        AnonymizationTerm.confirmed,
        AnonymizationTerm.category,
        AnonymizationTerm.pseudo_middle,
    ).where(AnonymizationTerm.user_id == user_id)
    if scope_tokens is not None:
        # Matérialise en list pour bien borner la cardinalité. Une scope
        # vide explicite = on ne lit rien (le pseudonymizer sera vide,
        # ce qui est nominal pour un workbook sans token cleartext).
        scope_list = [t for t in scope_tokens if isinstance(t, str) and t]
        if not scope_list:
            return {"version": anon_terms.STATE_VERSION, "terms": {}}
        stmt = stmt.where(AnonymizationTerm.term.in_(scope_list))
    rows = (await session.execute(stmt)).all()
    terms: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        # Unpacking explicite — l'ordre doit matcher le SELECT ci-dessus.
        # Bypass l'hydration ORM : on accède aux colonnes par index, pas
        # par attribut. Sur 92K rows, ce changement seul fait passer la
        # boucle de ~1500ms à ~250ms (mesuré 2026-05-26).
        row_id, row_term, row_enabled, row_confirmed, row_category, row_pseudo_middle = row
        entry: Dict[str, Any] = {
            # ``id`` : permet au modal Confidentialité d'iris-grid d'appeler
            # les endpoints scopés-id (``DELETE /terms/:id``, ``GET /terms/:id/coverage``)
            # sans devoir refaire un lookup term→id. Ajouté en mai 2026 avec
            # l'alignement modal iris-grid ↔ /data/privacy. Champ tolérant
            # par les consumers existants (proxy, copilot) qui ignorent les
            # clés inconnues.
            "id": int(row_id) if row_id is not None else None,
            "enabled": bool(row_enabled),
            "confirmed": bool(row_confirmed),
            # ``category`` : exposée dans le state v1 pour que
            # :func:`extract.build_user_pseudonymizer` puisse produire un
            # placeholder sémantique (``§EMAIL_4b3a§``) au lieu d'un opaque
            # ``§nn_4b3§``. Sans cette propagation, la category de l'INSERT
            # serait perdue côté Pseudonymizer et le LLM verrait des
            # placeholders dénués de sens.
            "category": row_category if isinstance(row_category, str) and row_category else None,
            # ``auto_pseudo`` : placeholder par défaut au format
            # ``{LABEL}_{md5[:4]}`` (porte la catégorie au LLM, ex:
            # ``EMAIL_4b3a``). Exposé pour que le frontend affiche la vraie
            # valeur anonymisée dans le panneau au lieu d'un placeholder
            # "auto". N'est PAS persisté en BDD — dérivé à chaque lecture.
            "auto_pseudo": anon_terms._auto_pseudo_middle(row_term, row_category),
        }
        if row_pseudo_middle:
            entry["pseudo"] = row_pseudo_middle
        terms[row_term] = entry
    return {"version": anon_terms.STATE_VERSION, "terms": terms}


async def get_detailed_state_for_user(
    session: AsyncSession,
    user_id: int,
) -> Dict[str, Any]:
    """Retourne l'état détaillé pour la page ``/data/privacy``.

    Différence avec :func:`get_state_for_user` (qui sert le panneau iris-grid
    et n'expose qu'un sous-ensemble des champs pour la substitution
    runtime) :

    * **terms** est ici une LIST ordonnée (par ``term`` asc) plutôt qu'un
      dict — la page affiche un tableau et a besoin d'un ordre stable.
    * Chaque terme expose le ``to_dict()`` complet (id, category,
      risk_level, source, last_seen_at, …) — la page /data/privacy
      affiche ces métadonnées dans son tableau et son modal coverage.

    Pas de transformation runtime des valeurs (pas de ``§…§``, pas
    d'anonymisation côté serveur) — l'utilisateur a accès à ses propres
    termes en clair par construction (auth + ownership).

    Retourne toujours un dict valide (``{"version": 1, "terms": []}``
    pour un user vide / inconnu).
    """
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("get_detailed_state_for_user", user_id)
        return {"version": anon_terms.STATE_VERSION, "terms": []}

    stmt = (
        select(AnonymizationTerm)
        .where(AnonymizationTerm.user_id == user_id)
        .order_by(AnonymizationTerm.term.asc())
    )
    rows = (await session.scalars(stmt)).all()
    detailed: list[Dict[str, Any]] = []
    for row in rows:
        d = row.to_dict()
        d["auto_pseudo"] = anon_terms._auto_pseudo_middle(row.term, row.category)
        detailed.append(d)
    return {"version": anon_terms.STATE_VERSION, "terms": detailed}


async def upsert_terms(
    session: AsyncSession,
    user_id: int,
    terms: Dict[str, Dict[str, Any]],
    *,
    source: Optional[str] = None,
    source_ref: Optional[str] = None,
    origins_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    commit_every_n_chunks: int = 0,
) -> int:
    """Insert ou update un batch de termes pour un utilisateur.

    Utilise la contrainte unique ``(user_id, term)`` comme cible
    (``ON CONFLICT DO UPDATE``) — garantit l'idempotence et évite les
    races entre deux sessions qui synchroniseraient le même user.

    Les champs mis à jour sont ``enabled``, ``confirmed``, ``pseudo_middle``,
    ``origins``. Le timestamp ``updated_at`` est touché automatiquement
    par le ``TimestampMixin``.

    ``source`` / ``source_ref`` (optionnels) : règle de **promotion
    conditionnelle** (2026-05-19) — ``"manual"`` étant la valeur par
    défaut du modèle (fourre-tout posé par la migration historique +
    tout INSERT sans source explicite, ex. PUT panneau), on autorise
    le promote ``"manual" → autre source réelle`` quand un scan
    re-détecte le terme avec un caller-fourni ``source`` non-manual.
    Aucun downgrade ni horizontale possible (un ``"workbook"`` ne
    bascule jamais en ``"iris_message"``). Conséquences :

    - INSERT (terme inexistant) : caller-fourni utilisé, défaut
      ``"manual"`` si caller n'a rien fourni.
    - UPDATE (terme existant, ``source != "manual"``) : préservé,
      caller-fourni ignoré.
    - UPDATE (terme existant, ``source == "manual"``) : promote vers
      caller-fourni (si non-manual), sinon reste ``"manual"``.

    Implémentation : ``CASE WHEN`` dans le ``ON CONFLICT DO UPDATE``,
    donc atomique par row — pas de race entre lecture et écriture.

    ``origins_map`` (task #20, optionnel) : dict ``term →
    [{"classeur": str|None, "col": str|None}, ...]`` qui décrit les
    origines OBSERVÉES dans CE batch. À l'INSERT initial le set est
    sérialisé tel quel. À l'UPDATE le set est **mergé** avec les
    origines déjà en BDD (union de set de tuples ``(classeur, col)``),
    ce qui préserve les origines d'autres classeurs scannés
    précédemment. Cap déterministe à :data:`_ORIGINS_MAX_LEN` chars
    via tronquage alphabétique. La clé d'indexation accepte le ``term``
    original (avant remap canonique) ou la forme canonique (NFKC casefold)
    — robuste aux mismatches caller/BDD.

    Retourne le nombre de rangées affectées (insérées ou modifiées).

    **PRÉCONDITION session (task #34)** : ``session`` doit être propre
    à la coroutine appelante. :class:`AsyncSession` n'est ni thread-safe
    ni task-safe. Le verrou per-user (:func:`acquire_user_anon_lock`,
    task #23) sérialise les écritures BDD pour un user, MAIS ne protège
    PAS contre 2 coroutines qui partageraient la même ``AsyncSession``
    (anti-pattern produisant un état SQLAlchemy corrompu, indépendant
    de la sémantique anonymization). Pattern attendu : 1 requête HTTP →
    1 ``AsyncSession`` via le context manager ``db_session()`` du handler.

    ``commit_every_n_chunks`` (depuis 2026-05-22, fix
    [[project-db-locked-followup-2026-05-22]]) : si > 0, commit la session
    toutes les N chunks de :data:`CHUNK_SIZE` rows pour relâcher
    périodiquement le verrou writer SQLite. UTILE pour les batches longs
    (scan workbook 50 K termes = 500 chunks × ~50 ms = 25 s de verrou
    writer tenu sans ce paramètre, bloquant tout autre user concurrent).
    À ``0`` (défaut) le caller garde le contrôle transactionnel complet
    — adapté quand l'upsert fait partie d'une séquence atomique plus
    large (ex: ``replace_state`` qui combine upsert + DELETE + audit).
    """
    # task #38 : helper ``is_valid_user_id`` factorise les invariants
    # (exclut ``None``, ``bool``, non-int, ``<= 0``) — cf. finding #1
    # review task #35. Pattern uniforme partagé avec audit.py,
    # api_service.py et locks.py.
    if not is_valid_user_id(user_id) or not terms:
        _warn_invalid_user_id("upsert_terms", user_id)
        return 0

    # task #23 — Verrou per-user contre les races read-modify-write sur
    # ``origins``. Sans ce verrou, 2 coroutines concurrent (ex: 2 onglets
    # ouverts ou hook execute_sql en parallèle d'un scan_workbook_terms)
    # peuvent chacune SELECTer ``{A}``, fusionner avec ``{B}`` / ``{C}``,
    # puis UPDATER chacune leur set → la 2ème écrasure perd ``B`` ou ``C``
    # silencieusement. ``acquire_user_anon_lock`` est réentrant via
    # ``contextvars`` — si ``replace_state`` (parent) a déjà acquired,
    # le bloc ici est no-op safe (pas de deadlock).
    async with acquire_user_anon_lock(user_id):
        return await _upsert_terms_locked_impl(
            session,
            user_id,
            terms,
            source=source,
            source_ref=source_ref,
            origins_map=origins_map,
            commit_every_n_chunks=commit_every_n_chunks,
        )


async def _upsert_terms_locked_impl(
    session: AsyncSession,
    user_id: int,
    terms: Dict[str, Dict[str, Any]],
    *,
    source: Optional[str] = None,
    source_ref: Optional[str] = None,
    origins_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    commit_every_n_chunks: int = 0,
) -> int:
    """Implémentation de :func:`upsert_terms` à exécuter UNDER le lock
    per-user (task #23). Ne PAS appeler directement — passer par
    ``upsert_terms`` qui acquire le verrou.

    ``commit_every_n_chunks`` : cf. doc identique sur :func:`upsert_terms`.
    """
    # Filtre défensif : on ne veut PAS qu'un term invalide (trop long, non
    # string) casse le batch. ``anon_terms.validate_state`` aura déjà été
    # appelé par le handler ; ce filtre est une ceinture+bretelle.
    #
    # Dédup case-insensitive (vision DYNAMIQUE "aucun duplicate") couvre
    # 2 niveaux :
    #
    # 1. **Intra-batch** : si l'utilisateur soumet "DUPONT" et "Dupont" dans
    #    le même PUT, on garde la 1ʳᵉ forme rencontrée et on fusionne flags.
    # 2. **Inter-batch** : si une row "DUPONT" existe déjà en BDD et que
    #    l'utilisateur soumet "Dupont" dans un PUT ultérieur, on remappe
    #    "Dupont" vers le terme canonique "DUPONT" existant — l'UPSERT
    #    ON CONFLICT (user_id, term) trouvera alors la row existante et
    #    fera UPDATE. Pas de migration BDD nécessaire (le matching se fait
    #    en Python via NFKC casefold).
    #
    # NFKC + casefold partagés via ``_canonical_key`` module-level (extrait
    # pour que ``replace_state`` partage la même notion d'identité — sinon
    # le diff audit perd silencieusement un terme renommé en casse différente).

    # Charger les termes existants du user pour matching inter-batch.
    # Coût : un SELECT par appel. Pour 50K termes max c'est <100ms.
    # task #20 : on lit aussi ``origins`` pour pouvoir merger les origines
    # d'un re-scan avec les origines déjà en BDD (pas de perte d'historique).
    existing_result = await session.execute(
        select(AnonymizationTerm.term, AnonymizationTerm.origins).where(
            AnonymizationTerm.user_id == user_id
        )
    )
    existing_canonical_to_term: Dict[str, str] = {}
    existing_origins_by_canonical: Dict[str, Set[Tuple[Optional[str], Optional[str]]]] = {}
    for existing_term, existing_origins in existing_result:
        if isinstance(existing_term, str) and existing_term:
            key = _canonical_key(existing_term)
            existing_canonical_to_term[key] = existing_term
            parsed = _parse_origins(existing_origins)
            if parsed:
                existing_origins_by_canonical[key] = parsed

    seen: Dict[str, Dict[str, Any]] = {}
    values: List[Dict[str, Any]] = []
    for term, entry in terms.items():
        if not isinstance(term, str) or not term:
            continue
        if len(term) > anon_terms.MAX_VALUE_LEN:
            continue
        if not isinstance(entry, dict):
            continue
        # Sanitize via le helper module-level (single source of truth partagé
        # avec replace_state — sinon l'audit diverge de la BDD).
        pseudo = _sanitize_pseudo_value(entry.get("pseudo"))
        key = _canonical_key(term)

        # task #20 : extraire les origines AVANT le remap canonique. Le
        # caller peut indexer par le ``term`` original OU par sa forme
        # canonique (NFKC casefold) — on accepte les deux pour robustesse.
        new_origins_set: Set[Tuple[Optional[str], Optional[str]]] = set()
        if origins_map:
            raw_origins = origins_map.get(term)
            if raw_origins is None:
                raw_origins = origins_map.get(key)
            if isinstance(raw_origins, list):
                for entry_origin in raw_origins:
                    normalized = _normalize_origin_entry(entry_origin)
                    if normalized is not None:
                        new_origins_set.add(normalized)

        # Inter-batch dédup : si une row case-insensitive-équivalente existe
        # déjà en BDD, on remap le term entrant vers la forme canonique BDD.
        # L'UPSERT ON CONFLICT (user_id, term) trouvera alors la row existante
        # → UPDATE au lieu d'INSERT en doublon. Préserve le casing original
        # de la row BDD (pas de surprise UX "mon DUPONT est devenu Dupont").
        canonical_existing = existing_canonical_to_term.get(key)
        if canonical_existing is not None and canonical_existing != term:
            term = canonical_existing

        existing = seen.get(key)
        if existing is not None:
            # Fusionner avec l'occurrence précédente : OR sur les flags
            # (l'utilisateur veut activer si N'IMPORTE laquelle des
            # variantes l'était), garder le pseudo le plus précis (celui
            # déjà fixé OU le nouveau si l'ancien était None).
            existing["enabled"] = existing["enabled"] or bool(entry.get("enabled", False))
            existing["confirmed"] = existing["confirmed"] or bool(entry.get("confirmed", False))
            if existing["pseudo_middle"] is None and pseudo is not None:
                existing["pseudo_middle"] = pseudo
            # task #20 : fusionner les origines intra-batch (même token
            # vu dans 2 cols différentes d'un même scan → union).
            if new_origins_set:
                existing["_origins_set"].update(new_origins_set)
            continue
        # Détection PII auto (task #11) — appliquée UNIQUEMENT à l'INSERT
        # initial (ON CONFLICT DO UPDATE ne touche pas ``category`` / ``enabled``
        # / ``confirmed`` au-delà du set_ explicite plus bas, donc une row
        # existante avec l'user qui submit ``enabled=False`` garde son choix).
        # Si le terme matche un pattern PII built-in (email, SIRET+Luhn, IBAN,
        # téléphone FR, montant €), on force ``category="pii_<type>"``,
        # ``enabled=True``, ``confirmed=True`` — Q1 validé : un PII est
        # toujours sensible, pas d'ambiguïté, pas de gate user à l'insert.
        # NB : ``detect_pii_category`` utilise ``fullmatch`` strict — on strip
        # le terme pour éviter qu'un espace trailing (cellule Excel mal
        # formatée) fasse échouer la détection silencieusement (cf. review
        # adversariale #11 finding Q1). Le terme stocké en BDD garde sa
        # forme originale (pas de mutation cosmétique).
        pii_category = anon_patterns.detect_pii_category(term.strip())
        is_new_term = canonical_existing is None
        if is_new_term and pii_category is not None:
            record_enabled = True
            record_confirmed = True
        else:
            record_enabled = bool(entry.get("enabled", False))
            record_confirmed = bool(entry.get("confirmed", False))
        record = {
            "user_id": user_id,
            "term": term,
            "pseudo_middle": pseudo,
            "enabled": record_enabled,
            "confirmed": record_confirmed,
        }
        # category : auto-set sur PII détectées (uniquement à l'INSERT — sur
        # UPDATE on n'écrase pas la category existante).
        if is_new_term and pii_category is not None:
            record["category"] = pii_category
        # Source/source_ref : promote conditionnel ``"manual" → autre``
        # (cf. docstring upsert_terms § "Promotion source"). Pour que le
        # CASE WHEN du ``ON CONFLICT DO UPDATE`` ait une valeur exploitable
        # via ``excluded.source`` sur TOUS les rows du batch (homogène, pas
        # d'absence-de-valeur ambiguë), on force toujours une valeur dans
        # ``record["source"]``. Default modèle ``"manual"`` reproduit
        # côté Python — INSERT initial inchangé, UPDATE laisse le CASE
        # trancher.
        record["source"] = source if source is not None else "manual"
        record["source_ref"] = source_ref
        # task #20 : on stocke le set des origines NOUVELLES dans une clé
        # temporaire (préfixe ``_`` = non-DB). Le merge avec les origines
        # existantes en BDD + la sérialisation JSON sont faits en
        # post-traitement (boucle dédiée plus bas) pour garantir des
        # records homogènes côté ``sqlite_insert.values()``.
        record["_origins_set"] = set(new_origins_set)
        seen[key] = record
        values.append(record)

    if not values:
        return 0

    # Defense-in-depth : cap par batch pour éviter qu'un caller négligent
    # insère un état pathologique. Le cap est DYNAMIQUE (par user) depuis
    # 2026-05-19 : il dérive du quota disque admin via ``get_user_term_cap``
    # plutôt que d'un seuil hardcodé. Aligne l'anonymisation sur la promesse
    # Komptia "le seul cap c'est le quota disque" — un cabinet sur un plan
    # 5 Go peut anonymiser ~25 M termes ; un user à 99 % de quota reste
    # autorisé à ajouter ``MAX_STATE_TERMS_MIN`` termes critiques (PII).
    user_term_cap = await get_user_term_cap(session, user_id)
    if len(values) > user_term_cap:
        logger.warning(
            "upsert_terms: batch user=%s trop gros (%d > user_term_cap=%d, "
            "hard_cap=%d), tronqué alphabétiquement",
            user_id,
            len(values),
            user_term_cap,
            anon_terms.MAX_STATE_TERMS_HARD_CAP,
        )
        values.sort(key=lambda v: v["term"])
        values = values[:user_term_cap]

    # task #20 : finaliser les origines pour CHAQUE record (merge BDD +
    # batch puis sérialisation JSON). Le set initial est en ``_origins_set``
    # — on le retire (clé non-DB), on union avec les origines existantes
    # (parsées du JSON BDD au début), puis on stocke le JSON sérialisé dans
    # ``record["origins"]``. ``None`` si pas d'origines (rétro-compat rows
    # pré-task #20 qui restent NULL).
    for record in values:
        batch_origins: Set[Tuple[Optional[str], Optional[str]]] = record.pop("_origins_set", set())
        canonical_for_record = _canonical_key(record["term"])
        bdd_origins = existing_origins_by_canonical.get(canonical_for_record, set())
        merged = bdd_origins | batch_origins
        record["origins"] = _serialize_origins(merged)

    # Dialect-specific UPSERT (SQLite) : on cible la contrainte unique
    # ``uq_anonymization_term_user_term`` pour trancher, et on met à jour
    # les colonnes d'état. On NE touche PAS ``created_at`` (preserved),
    # ``updated_at`` sera bougé par le TimestampMixin on refresh.
    #
    # **Chunking obligatoire** : SQLite a une limite stricte sur le nombre
    # de variables dans une seule statement (``SQLITE_MAX_VARIABLE_NUMBER``,
    # défaut 999 anciens builds, 32766 récents). Avec ~14 colonnes par row
    # (user_id, term, pseudo, enabled, confirmed, category, source, source_ref,
    # usage_count, auto_proposed, risk_level, replacement_strategy, origins),
    # un batch >70 rows explose sur builds anciens.
    # Cap conservateur 100 rows/chunk : 100×14 = 1400 vars, marge confortable
    # même avec build 999. Bug 2026-05-19 : scan datastore d'un classeur
    # avec ~500 tokens uniques produisait l'erreur ``too many SQL variables``.
    CHUNK_SIZE = 100
    total_affected = 0
    chunk_index = 0
    for i in range(0, len(values), CHUNK_SIZE):
        chunk = values[i : i + CHUNK_SIZE]
        stmt = sqlite_insert(AnonymizationTerm).values(chunk)
        stmt = stmt.on_conflict_do_update(
            index_elements=["user_id", "term"],
            set_={
                "pseudo_middle": stmt.excluded.pseudo_middle,
                "enabled": stmt.excluded.enabled,
                "confirmed": stmt.excluded.confirmed,
                "origins": stmt.excluded.origins,
                # Promote conditionnel ``"manual" → autre source réelle``
                # (cf. docstring upsert_terms § "Promotion source").
                #
                # **Exception ``→ user_added``** (2026-05-19) : un caller
                # qui passe explicitement ``source="user_added"`` est par
                # définition la saisie manuelle d'un utilisateur depuis
                # le modal ``/data/privacy``. C'est un acte EXPLICITE
                # qui doit toujours gagner sur la source détectée
                # automatiquement par les scans — sans ça, un user qui
                # ré-ajoute manuellement un terme déjà scanné garderait
                # ``source="workbook"`` et serait purgé par le cleanup
                # nightly si le classeur d'origine disparaît (cf. review
                # adversariale 2026-05-19 finding #4). Pas de downgrade
                # vers ``manual`` ni d'horizontale entre les autres
                # sources (workbook ↔ iris_message reste figé).
                # Promotion ``manual → X`` autorisée SAUF vers ``sql_result``
                # qui est éphémère (= ``sql_result`` représente un terme vu
                # une fois dans un résultat Iris/preview-automation affiché à
                # l'écran ; il n'a pas de présence durable côté filesystem).
                # Falsifier la trace GDPR d'un terme saisi manuellement par
                # l'user (modal "Ajouter un terme") en le promouvant à
                # ``sql_result`` parce qu'il apparaît dans un résultat Iris
                # serait incorrect : l'intention USER d'origine était "manual"
                # (review adversariale 2026-05-19 CRITICAL #6).
                #
                # Hiérarchie de promotion (high → low durable) :
                #   user_added > workbook > sql_result > manual
                # Règles appliquées ici :
                # - existing="manual" → promote vers user_added/workbook,
                #   PAS vers sql_result.
                # - excluded="user_added" (saisie explicite via modal
                #   /data/privacy) → toujours promote.
                # - sinon → préserver l'existing (pas d'horizontale, pas
                #   de downgrade silencieux).
                "source": case(
                    (
                        and_(
                            AnonymizationTerm.source == "manual",
                            stmt.excluded.source != "sql_result",
                        ),
                        stmt.excluded.source,
                    ),
                    (
                        stmt.excluded.source == "user_added",
                        stmt.excluded.source,
                    ),
                    else_=AnonymizationTerm.source,
                ),
                "source_ref": case(
                    (
                        and_(
                            AnonymizationTerm.source == "manual",
                            stmt.excluded.source != "sql_result",
                        ),
                        stmt.excluded.source_ref,
                    ),
                    (
                        stmt.excluded.source == "user_added",
                        stmt.excluded.source_ref,
                    ),
                    else_=AnonymizationTerm.source_ref,
                ),
            },
        )
        result = await session.execute(stmt)
        total_affected += result.rowcount or 0
        chunk_index += 1
        # Commit intermédiaire : relâche le writer lock SQLite entre
        # chunks pour permettre à un autre user concurrent (scan/upload
        # parallèle) d'écrire. Sans ça, un scan de 50 K termes
        # (500 chunks × ~50 ms) tenait le verrou ~25 s en continu et
        # bloquait toutes les autres écritures de l'instance. Cf.
        # [[project-db-locked-followup-2026-05-22]].
        #
        # Coût : chaque commit fait un fsync WAL (~1 ms en
        # ``synchronous=NORMAL``). Avec ``commit_every_n_chunks=5`` on
        # ajoute 100 commits sur 500 chunks = ~100 ms d'overhead pour
        # gagner 100 fenêtres d'écriture pour les autres users.
        #
        # Skip de la sentinelle ``i + CHUNK_SIZE >= len(values)`` :
        # le dernier chunk laisse le commit final au caller (consistent
        # avec la doctrine "repository ne commit pas — c'est le caller
        # qui décide"). Sauf demande explicite ``commit_every_n_chunks
        # > 0``, comportement strictement identique à avant le fix.
        if commit_every_n_chunks > 0 and chunk_index % commit_every_n_chunks == 0:
            is_last_chunk = (i + CHUNK_SIZE) >= len(values)
            if not is_last_chunk:
                await session.commit()
    return total_affected


#: Garde anti mass-delete (incident 2026-05-20 : un PUT replace_state
#: a purgé 89785 termes sur 90135 en 13 secondes). Au-delà de ce seuil
#: ABSOLU OU si le ratio supprimé/before dépasse 50%, ``replace_state``
#: refuse l'opération avec :class:`MassDeleteRefused` — le caller doit
#: re-soumettre avec ``confirm_mass_delete=True`` pour valider explicitement.
#: Seuils conservateurs : 1000 termes c'est suffisant pour un user
#: normal (édition à la main), et 50% empêche un body partiel issu d'un
#: bug de pagination de wipe l'historique.
_MASS_DELETE_ABSOLUTE_THRESHOLD = 1000
_MASS_DELETE_RATIO_THRESHOLD = 0.5


class MassDeleteRefused(RuntimeError):
    """Levée par :func:`replace_state` quand un PUT supprimerait un nombre
    suspect de termes sans flag ``confirm_mass_delete``. Le handler HTTP
    catch ça et retourne ``409 MASS_DELETE_REFUSED`` avec un payload
    actionnable côté client (count_before, count_delete, ratio)."""

    def __init__(
        self,
        count_before: int,
        count_delete: int,
        ratio: float,
        absolute_threshold: int = _MASS_DELETE_ABSOLUTE_THRESHOLD,
        ratio_threshold: float = _MASS_DELETE_RATIO_THRESHOLD,
    ) -> None:
        self.count_before = count_before
        self.count_delete = count_delete
        self.ratio = ratio
        self.absolute_threshold = absolute_threshold
        self.ratio_threshold = ratio_threshold
        super().__init__(
            f"Mass-delete refusé : {count_delete}/{count_before} termes "
            f"({ratio:.1%}) au-dessus du seuil "
            f"({absolute_threshold} absolu / {ratio_threshold:.0%} ratio). "
            f"Le caller doit confirmer via confirm_mass_delete=True."
        )


async def replace_state(
    session: AsyncSession,
    user_id: int,
    state: Dict[str, Any],
    *,
    triggered_by: str = "user_panel",
    triggered_by_user_id: Optional[int] = None,
    confirm_mass_delete: bool = False,
) -> Dict[str, int]:
    """Remplace *tout* le state d'un user (upsert + delete des termes absents).

    Usage : ``PUT /api/anonymization/terms`` après édition utilisateur.
    L'utilisateur voit SA liste telle qu'elle est — retirer un terme du
    panneau doit le retirer effectivement de la BDD.

    Retourne un dict de stats : ``{upserted, deleted, audited}``.

    **Audit** : chaque ajout/modif/suppression produit une row dans
    ``anonymization_audit``. Le paramètre ``triggered_by`` distingue la
    source (``user_panel`` par défaut). Fail-soft : un échec audit ne
    bloque jamais l'action métier.

    **PRÉCONDITION session (task #34)** : ``session`` doit être propre
    à la coroutine appelante. Cf. :func:`upsert_terms` pour le contrat
    complet — le verrou per-user (task #23) ne protège pas contre le
    partage de session.

    **Isolation fail-closed (D6-F1)** : un ``user_id`` invalide (bool/str/0/
    négatif/None) ⇒ no-op renvoyant des stats à zéro, AVANT toute requête.
    Le verrou ``acquire_user_anon_lock`` no-op-erait sur un user_id invalide
    SANS bloquer le corps : sans ce guard explicite,
    ``replace_state(session, True, state)`` exécuterait le read-modify-write
    sur ``WHERE user_id == 1`` (``bool`` ⊂ ``int``) → écrasement des termes
    PII de l'utilisateur 1 (destruction cross-user). Parité avec
    :func:`upsert_terms` / :func:`delete_missing_terms` qui guardent déjà.
    """
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("replace_state", user_id)
        return {"upserted": 0, "deleted": 0, "audited": 0}

    # task #23 — Verrou per-user contre les races read-modify-write. Sans
    # ce verrou, un PUT panneau (replace_state) qui croise un
    # scan_workbook_terms (upsert_terms) du même user peut perdre des
    # origines ou des flags silencieusement. ``upsert_terms`` interne
    # détectera le lock déjà détenu (réentrance via ContextVar) et
    # sautera son propre acquire.
    async with acquire_user_anon_lock(user_id):
        return await _replace_state_locked_impl(
            session,
            user_id,
            state,
            triggered_by=triggered_by,
            triggered_by_user_id=triggered_by_user_id,
            confirm_mass_delete=confirm_mass_delete,
        )


async def _replace_state_locked_impl(
    session: AsyncSession,
    user_id: int,
    state: Dict[str, Any],
    *,
    triggered_by: str = "user_panel",
    triggered_by_user_id: Optional[int] = None,
    confirm_mass_delete: bool = False,
) -> Dict[str, int]:
    """Implémentation de :func:`replace_state` à exécuter UNDER le lock
    per-user (task #23)."""
    # Import local pour éviter circular import (audit utilise les models qui
    # peuvent importer des helpers depuis ce module dans certaines lectures).
    from app.services.anonymization import audit as _audit

    new_terms = (state or {}).get("terms") or {}

    # Snapshot avant : (term -> entry) pour computer le diff post-action.
    stmt = select(AnonymizationTerm).where(AnonymizationTerm.user_id == user_id)
    rows_before = (await session.scalars(stmt)).all()
    before: Dict[str, Dict[str, Any]] = {
        r.term: {
            "id": r.id,
            "enabled": bool(r.enabled),
            "confirmed": bool(r.confirmed),
            "pseudo_middle": r.pseudo_middle,
            "category": r.category,
            "risk_level": r.risk_level,
        }
        for r in rows_before
    }
    # Index canonique (NFKC casefold) pour matcher contre new_terms en
    # case-insensitive — sinon un user qui soumet "Dupont" quand "DUPONT"
    # existe en BDD verrait son terme supprimé silencieusement par la boucle
    # audit delete (qui compare brut "DUPONT" != "Dupont"). Cf. test
    # ``tests/unit/test_replace_state_case_insensitive.py``.
    before_canonical_to_term: Dict[str, str] = {_canonical_key(t): t for t in before.keys()}
    # Index canonique des termes d'entrée — dédup intra-batch (l'user soumet
    # "DUPONT" et "Dupont" dans le même PUT) avec fusion des flags via OR,
    # alignement strict avec ``upsert_terms:213-226``. Sans fusion, la boucle
    # audit itérerait 2× et produirait 2 audits INSERT distincts alors que
    # ``upsert_terms`` n'a créé qu'UNE row en BDD (audit fantôme = mensonge
    # historique RGPD).
    new_canonical_to_term: Dict[str, str] = {}
    new_canonical_to_entry: Dict[str, Dict[str, Any]] = {}
    for t, e in new_terms.items():
        if not isinstance(t, str) or not t or not isinstance(e, dict):
            continue
        ckey = _canonical_key(t)
        e_enabled = bool(e.get("enabled", False))
        e_confirmed = bool(e.get("confirmed", False))
        e_pseudo = e.get("pseudo")
        if ckey not in new_canonical_to_term:
            new_canonical_to_term[ckey] = t
            new_canonical_to_entry[ckey] = {
                "enabled": e_enabled,
                "confirmed": e_confirmed,
                "pseudo": e_pseudo,
            }
        else:
            # Fusion (OR sur flags, garder le pseudo le plus précis).
            merged = new_canonical_to_entry[ckey]
            merged["enabled"] = merged["enabled"] or e_enabled
            merged["confirmed"] = merged["confirmed"] or e_confirmed
            if merged["pseudo"] is None and e_pseudo is not None:
                merged["pseudo"] = e_pseudo

    # Garde anti mass-delete (incident 2026-05-20). On évalue le delta
    # AVANT tout write : si le PUT supprimerait > absolute_threshold ET
    # > ratio_threshold % du before, on refuse sans flag explicite. Aucun
    # UPSERT n'a tourné, aucun audit non plus → rollback "zéro effet".
    pending_delete_count = sum(
        1 for term in before if _canonical_key(term) not in new_canonical_to_term
    )
    if pending_delete_count > 0 and not confirm_mass_delete:
        count_before = len(before)
        ratio = pending_delete_count / count_before if count_before else 0.0
        if (
            pending_delete_count >= _MASS_DELETE_ABSOLUTE_THRESHOLD
            and ratio >= _MASS_DELETE_RATIO_THRESHOLD
        ):
            logger.warning(
                "replace_state user=%s: mass-delete refusé "
                "(%d/%d termes, %.1f%%). Body PUT probablement tronqué — "
                "caller doit re-soumettre avec confirm_mass_delete=True "
                "s'il s'agit d'une purge intentionnelle.",
                user_id,
                pending_delete_count,
                count_before,
                ratio * 100,
            )
            raise MassDeleteRefused(
                count_before=count_before,
                count_delete=pending_delete_count,
                ratio=ratio,
            )

    # task #23 fix finding #1 review : on appelle ``_upsert_terms_locked_impl``
    # directement plutôt que la fonction publique ``upsert_terms``. Le
    # lock per-user est déjà acquis par ``replace_state`` (parent). Avec
    # la public function, la réentrance via le set ``_held_pairs`` ferait
    # no-op le re-acquire — fonctionne mais expose un anti-pattern et
    # duplique tout overhead futur (logging, metrics, throttling) qu'on
    # ajouterait à ``upsert_terms``. L'appel direct à l'impl est l'intent
    # explicite : "je suis déjà sous le lock, exécute le corps".
    upserted = await _upsert_terms_locked_impl(session, user_id, new_terms)
    # NB : on n'exécute PAS le DELETE ici. Il doit tourner APRÈS le flush des
    # audits pour éviter une FK violation. Cf. ci-dessous.

    # Audit : 3 catégories (added, changed, removed). Bulk insert au lieu d'un
    # ``await log_audit_action(...)`` par row — chaque appel faisait un
    # ``session.flush([row])`` séparé (~1-2 ms côté SQLite WAL + sync NORMAL).
    # Pour un PUT massif (90k termes observés en prod 2026-05-20), ça produit
    # 90k+ round-trips séquentiels dans une seule transaction → 94 s de write
    # lock pendant lesquelles AUCUN autre writer ne peut écrire dans la BDD
    # (les uploads datastore se prenaient ``sqlite3.OperationalError: database
    # is locked`` en 86 s). Le bulk insert fait 1 flush pour l'ensemble.
    #
    # On accumule les rows en mémoire puis on délègue au helper privé
    # ``_bulk_insert_audits`` qui isole l'opération dans un SAVEPOINT
    # (``begin_nested``) — un échec audit ne casse pas l'action métier
    # (cohérent avec la politique fail-soft documentée dans audit.py).
    from app.models.anonymization_audit import AnonymizationAudit

    if triggered_by not in _audit.TRIGGERED_BY_VALUES:
        # Garde-fou fail-soft global : aligné sur ``log_audit_action`` qui
        # skip une row dont ``triggered_by`` est invalide. Ici on skip tout
        # le bulk plutôt que de polluer la table.
        logger.warning(
            "replace_state user=%s: triggered_by inconnu %r — bulk audit skipped",
            user_id,
            triggered_by,
        )
        audit_rows: List[AnonymizationAudit] = []
    else:
        audit_rows = []
        for ckey, merged in new_canonical_to_entry.items():
            canonical_before = before_canonical_to_term.get(ckey)
            prev = before.get(canonical_before) if canonical_before is not None else None
            # Le terme à logger : forme canonique BDD si elle existe (= la row
            # qu'upsert_terms a updaté), sinon la 1ère forme submit (= la row
            # qu'upsert_terms vient de créer).
            term = canonical_before if canonical_before is not None else new_canonical_to_term[ckey]
            # Parité stricte avec ``_upsert_terms_locked_impl`` (cf. lignes
            # 506-508 : ``if len(term) > MAX_VALUE_LEN: continue``). Pour
            # un INSERT, si le terme dépasse 500 chars il SERA REJETÉ par
            # l'upsert — créer un audit "insert" pour ce terme produirait
            # un audit fantôme (référence à une row jamais persistée).
            # Pour les UPDATE/DELETE, ``term`` vient du snapshot ``before``
            # (SELECT BDD), donc <= 500 par construction du schéma — le
            # filtre est défensif et no-op dans ces branches.
            if prev is None and len(term) > anon_terms.MAX_VALUE_LEN:
                continue
            new_enabled = merged["enabled"]
            new_confirmed = merged["confirmed"]
            if prev is None:
                # Insertion. ``anonymization_term_id`` reste None à l'INSERT
                # — cohérent avec le comportement antérieur (cf. note dans
                # test_replace_state_fk_audit_order.py:192-200).
                audit_rows.append(
                    AnonymizationAudit(
                        user_id=user_id,
                        anonymization_term_id=None,
                        term=term[:500],
                        triggered_by=triggered_by,
                        triggered_by_user_id=triggered_by_user_id,
                        action="insert",
                        enabled=new_enabled,
                        confirmed=new_confirmed,
                        changed_fields={
                            "enabled": [None, new_enabled],
                            "confirmed": [None, new_confirmed],
                        },
                    )
                )
            else:
                # Update si l'un des flags suivis a changé.
                changed: Dict[str, Any] = {}
                if prev["enabled"] != new_enabled:
                    changed["enabled"] = [prev["enabled"], new_enabled]
                if prev["confirmed"] != new_confirmed:
                    changed["confirmed"] = [prev["confirmed"], new_confirmed]
                # Sanitize via le même helper que ``upsert_terms`` pour comparer
                # ce qui sera RÉELLEMENT en BDD (pas l'input brut). Sans ça, un
                # pseudo invalide (avec §, > MAX, vide, non-str) déclencherait un
                # audit fantôme alors qu'``upsert_terms`` met silencieusement à None.
                new_pseudo = _sanitize_pseudo_value(merged.get("pseudo"))
                if new_pseudo is not None and new_pseudo != prev.get("pseudo_middle"):
                    changed["pseudo_middle"] = [prev.get("pseudo_middle"), new_pseudo]
                if changed:
                    audit_rows.append(
                        AnonymizationAudit(
                            user_id=user_id,
                            anonymization_term_id=prev["id"],
                            # Logger le terme CANONIQUE BDD (pas le submit) pour cohérence
                            # de l'historique audit : un user qui submit "DUPONT" puis
                            # "Dupont" puis "dupont" doit voir 3 updates du même terme,
                            # pas 3 audits sur 3 "termes" différents.
                            term=term[:500],
                            triggered_by=triggered_by,
                            triggered_by_user_id=triggered_by_user_id,
                            action="update",
                            enabled=new_enabled,
                            confirmed=new_confirmed,
                            changed_fields=changed,
                        )
                    )

        # Suppressions : termes présents avant mais plus dans new_terms (en
        # canonical key — un terme "DUPONT" en BDD avec un "Dupont" submit doit
        # être considéré comme UPDATE, pas DELETE+INSERT). On collecte aussi
        # les IDs à supprimer pour le DELETE chunked ci-dessous (évite la
        # boucle redondante qui re-calculait via ``keep_terms``).
        # NB : la garde anti mass-delete a déjà tourné en amont (avant le
        # UPSERT) — voir bloc ``MassDeleteRefused`` plus haut.
        delete_ids: List[int] = []
        for term, prev in before.items():
            ckey = _canonical_key(term)
            if ckey not in new_canonical_to_term:
                audit_rows.append(
                    AnonymizationAudit(
                        user_id=user_id,
                        anonymization_term_id=prev["id"],
                        term=term[:500],
                        triggered_by=triggered_by,
                        triggered_by_user_id=triggered_by_user_id,
                        action="delete",
                        enabled=prev["enabled"],
                        confirmed=prev["confirmed"],
                        changed_fields={
                            "enabled": [prev["enabled"], None],
                            "confirmed": [prev["confirmed"], None],
                        },
                    )
                )
                delete_ids.append(int(prev["id"]))

    audited = await _bulk_insert_audits(session, audit_rows, user_id)

    # DELETE après le flush des audits — le ``ondelete=SET NULL`` du modèle
    # (cf. ``anonymization_audit.py:72-89``) nullifiera l'``anonymization_term_id``
    # de TOUTES les audit rows pointant vers les termes deleted (insert/update
    # historiques + delete qu'on vient d'insérer). C'est cohérent avec la
    # doctrine "audit immuable, FK déliée du parent supprimé". Inverser cet
    # ordre (DELETE puis audit) déclenche un FK constraint failed en prod
    # (``PRAGMA foreign_keys = ON``) car l'INSERT audit pointerait vers un
    # terme inexistant — repro dans ``tests/unit/test_replace_state_fk_audit_order.py``.
    # Atomicité full : le caller wrappe via ``async with db_session()`` qui
    # commit ou rollback les audits + le DELETE ensemble. Si le DELETE crash,
    # les audits viennent d'être flush mais pas commit → rollback nettoie tout.
    #
    # DELETE par IDs (chunked) — l'ancienne implémentation passait par
    # ``delete_missing_terms`` qui faisait ``WHERE term NOT IN (?, ?, …)``
    # avec un paramètre par terme à garder. À 90k termes le driver SQLite
    # saturait ``SQLITE_MAX_VARIABLE_NUMBER`` (999 anciens builds, 32766
    # récents) — soit crash soit lenteur extrême. On a déjà les IDs des
    # termes à supprimer dans le snapshot ``before``, on les utilise
    # directement via ``_delete_terms_by_ids`` (chunké interne à 500).
    if triggered_by not in _audit.TRIGGERED_BY_VALUES:
        # Quand on a skip le bulk audit, on doit quand même calculer les IDs
        # à supprimer (le calcul était couplé à la construction des audits).
        delete_ids = [
            int(prev["id"])
            for term, prev in before.items()
            if _canonical_key(term) not in new_canonical_to_term
        ]
    deleted = await _delete_terms_by_ids(session, user_id, delete_ids)

    return {"upserted": upserted, "deleted": deleted, "audited": audited}


async def _bulk_insert_audits(
    session: AsyncSession,
    rows: List[Any],
    user_id: int,
) -> int:
    """Bulk insert d'un batch d'``AnonymizationAudit`` en un seul flush.

    Isolé dans un SAVEPOINT (``session.begin_nested``) pour préserver la
    politique fail-soft : si l'insertion bulk échoue (BDD locked, contrainte
    inattendue, etc.) on annule UNIQUEMENT les audits, sans casser la
    transaction métier (upsert + delete des termes).

    **Doctrine fail-soft préservée row-par-row** (review adversariale
    2026-05-20 finding #2) : avant le bulk, ``log_audit_action`` skip
    une row individuelle foireuse et continue le reste. Si on s'arrêtait
    à un rollback global, une seule row corrompue dans 90k perdrait
    89 999 audits valides (régression RGPD : audit immuable = histoire
    critique, pas un nice-to-have). Fallback explicite : sur exception,
    on retombe en mode "1 row = 1 flush" pour préserver le maximum
    d'audits. Ce mode reste exponentiel mais s'active UNIQUEMENT en cas
    d'incident — pas un coût quotidien.

    Retourne le nombre d'audits effectivement persistés.
    """
    if not rows:
        return 0
    try:
        async with session.begin_nested():
            session.add_all(rows)
            await session.flush()
        return len(rows)
    except Exception as exc:  # noqa: BLE001 — fallback contrôlé ci-dessous
        logger.warning(
            "replace_state user=%s: bulk audit insert échoué (%s) — "
            "fallback row-par-row pour préserver le maximum d'audits.",
            user_id,
            exc,
        )
        # Le savepoint a rollback le bulk : les ``rows`` sont sorties de
        # ``session.new``. On peut donc retenter individuellement sans
        # double-INSERT. Chaque row est tentée dans son propre savepoint
        # pour que les rows valides survivent à une row corrompue.
        persisted = 0
        for r in rows:
            try:
                async with session.begin_nested():
                    session.add(r)
                    await session.flush([r])
                persisted += 1
            except Exception as row_exc:  # noqa: BLE001
                logger.warning(
                    "replace_state user=%s: audit row perdue (%s) — " "term=%r action=%r",
                    user_id,
                    row_exc,
                    getattr(r, "term", "?"),
                    getattr(r, "action", "?"),
                )
        return persisted


async def _delete_terms_by_ids(
    session: AsyncSession,
    user_id: int,
    ids: List[int],
) -> int:
    """Supprime un set d'``AnonymizationTerm`` par IDs, chunké à 500.

    Le filtre ``user_id`` est une ceinture-bretelle (defense-in-depth) :
    un bug logique qui injecterait un ID d'un autre user ne pourrait pas
    cross-user delete. Le chunking borne le nombre de paramètres SQL par
    statement bien en-dessous de ``SQLITE_MAX_VARIABLE_NUMBER`` (999 sur
    builds anciens) — robuste indépendamment de la taille du batch.
    """
    if not ids:
        return 0
    CHUNK_SIZE = 500
    total = 0
    for i in range(0, len(ids), CHUNK_SIZE):
        chunk = ids[i : i + CHUNK_SIZE]
        stmt = delete(AnonymizationTerm).where(
            AnonymizationTerm.user_id == user_id,
            AnonymizationTerm.id.in_(chunk),
        )
        result = await session.execute(stmt)
        total += result.rowcount or 0
    return total


async def delete_missing_terms(
    session: AsyncSession,
    user_id: int,
    keep_terms: Iterable[str],
) -> int:
    """Supprime tous les termes d'un utilisateur qui NE SONT PAS dans
    ``keep_terms``.

    Deux usages :

    1. ``PUT`` du panneau — ``keep_terms`` = termes listés par l'utilisateur
       (un terme retiré du panneau doit disparaître de la BDD).
    2. Job de cleanup — ``keep_terms`` = tokens extraits des classeurs de
       l'utilisateur (un terme qui n'apparaît plus nulle part est retiré
       sans re-confirmation, comme demandé).

    Retourne le nombre de rangées supprimées.
    """
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("delete_missing_terms", user_id)
        return 0

    # set() garantit O(1) lookup, list() pour le driver SQLite qui n'aime
    # pas toujours les sets en paramètre de ``IN``.
    keep = list(set(keep_terms or []))

    if not keep:
        # Aucun terme à garder → supprimer tout pour ce user.
        stmt = delete(AnonymizationTerm).where(AnonymizationTerm.user_id == user_id)
    else:
        stmt = delete(AnonymizationTerm).where(
            AnonymizationTerm.user_id == user_id,
            AnonymizationTerm.term.notin_(keep),
        )
    result = await session.execute(stmt)
    return result.rowcount or 0


async def distinct_user_ids_with_terms(session: AsyncSession) -> list[int]:
    """Retourne la liste des ``user_id`` qui ont au moins une entrée —
    utilisé par le job de cleanup pour n'itérer que sur les users pertinents
    (skip les users sans terme, évite de scanner leur datastore pour rien)."""
    stmt = select(AnonymizationTerm.user_id).distinct()
    rows = (await session.scalars(stmt)).all()
    return [int(r) for r in rows]


async def count_terms_for_user(session: AsyncSession, user_id: int) -> int:
    """Compte les termes d'un utilisateur — pour les guards côté handler
    (refuse un PUT qui ferait exploser :data:`anon_terms.MAX_STATE_TERMS`)."""
    if not is_valid_user_id(user_id):
        _warn_invalid_user_id("count_terms_for_user", user_id)
        return 0
    from sqlalchemy import func

    stmt = select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
    return int((await session.scalar(stmt)) or 0)


async def get_term(
    session: AsyncSession,
    user_id: int,
    term: str,
) -> Optional[AnonymizationTerm]:
    """Accesseur unitaire — pour les tests et le debug."""
    if not is_valid_user_id(user_id) or not term:
        _warn_invalid_user_id("get_term", user_id)
        return None
    stmt = select(AnonymizationTerm).where(
        AnonymizationTerm.user_id == user_id,
        AnonymizationTerm.term == term,
    )
    return await session.scalar(stmt)
