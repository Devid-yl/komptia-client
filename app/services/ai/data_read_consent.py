"""Gate de consentement lecture des résultats SQL par Iris.

**Doctrine** : avant qu'Iris (free-loop agent ``agent_service`` OU pipeline
NL→SQL via ``run_pipeline``) n'envoie les résultats d'une requête SQL
exécutée au LLM cloud pour analyse, le runtime consulte la préférence
utilisateur (``user_preferences.iris_data_read_consent``) :

- ``always_allow`` → flow direct (les 2 couches d'anonymisation existantes
  appliquent toujours leur protection).
- ``ask`` (défaut) → 1 prompt par conversation. Si l'utilisateur clique
  « OUI » → consentement granté pour le reste de la conversation. Si
  « NON » → ouvre le panneau "Confidentialité — termes à anonymiser" du
  result area, pré-rempli avec les valeurs uniques des résultats. Si
  l'utilisateur coche « ne plus me redemander » → bascule en
  ``always_allow`` ou ``always_show_panel`` selon sa réponse.
- ``always_show_panel`` → ouvre systématiquement le panneau, sans prompt
  intermédiaire.

Ce module fournit :

1. :func:`get_user_consent_pref` / :func:`set_user_consent_pref` —
   accesseurs à la préférence en BDD via ``UserPreference``.
2. :func:`request_consent` — crée un Future asyncio identifié par
   ``conversation_id``, attend jusqu'à résolution ou timeout. Appelé
   depuis le free-loop d'``agent_service``.
3. :func:`resolve_consent` — résout le Future depuis le WS handler
   ``data_read_consent_response``. Idempotent : double-résolution
   silencieusement no-op (cas multi-onglet ou clic compulsif).
4. :func:`mark_conversation_consented` — track que la question a déjà
   été posée+approuvée dans cette conversation pour éviter le spam.

**Storage in-memory** : les Future et l'état "consenti" sont stockés par
``conversation_id`` dans un module-level dict. Cela suppose que le
backend Tornado est mono-process (cf. config Komptia). Si scale-out
multi-process introduit plus tard, migrer vers Redis/BDD shared.

**Timeout** : 5 minutes pour qu'un utilisateur distrait revienne sur la
question. Au-delà, le Future est annulé → le caller (agent_service)
traite ça comme un refus (lecture non autorisée).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user_preference import UserPreference

logger = logging.getLogger(__name__)


# ── Constantes ──────────────────────────────────────────────────────────

#: Clé ``user_preferences`` — DOIT matcher
#: ``app.handlers.settings.PREF_IRIS_DATA_READ_CONSENT``. Dupliquée ici
#: pour éviter une dépendance circulaire (settings importe... rien d'AI,
#: et le module AI ne doit pas importer un handler HTTP).
_PREF_KEY: str = "iris_data_read_consent"

#: Valeur par défaut si l'utilisateur n'a jamais configuré la pref.
DEFAULT_CONSENT: str = "ask"

#: Valeurs autorisées (miroir de ``settings._IRIS_CONSENT_VALUES``).
VALID_CONSENT_VALUES: frozenset[str] = frozenset({"ask", "always_allow", "always_show_panel"})

#: Timeout pour qu'un utilisateur réponde au prompt. 5 minutes : un
#: utilisateur distrait peut revenir à son onglet ; au-delà on suppose
#: qu'il a abandonné l'action — Iris reçoit "lecture refusée" et le
#: free-loop peut formuler un message d'erreur intelligible.
RESPONSE_TIMEOUT_SECONDS: float = 5 * 60.0


#: Périmètre des outils qui DOIVENT déclencher le gate de consentement.
#:
#: **Critère d'inclusion** : tout outil qui, en runtime, lit la BDD source
#: (SQL Server / Sage) et fait remonter au LLM cloud des valeurs réelles
#: — même obfusquées par ``anonymize_for_llm`` (Niveau 2 doctrine), car
#: les chiffres et dates passent en clair.
#:
#: **Single source of truth** : le gate dans ``agent_service`` lit
#: cette frozenset (via :func:`requires_consent`). Plus jamais de
#: ``tool_name == "execute_sql"`` codé en dur ailleurs.
#:
#: **Hors périmètre** (explicite) :
#:
#: - ``run_pipeline`` / ``pipeline_resume`` : le synthetic_result ne
#:   contient pas de rows (cf. ``_stream_pipeline_run_to_chat``). Le gate
#:   naturel s'applique sur le ``execute_sql`` qui exécute le ``final_sql``.
#: - ``search_schema`` / ``get_resolved_values`` / ``align_request`` :
#:   lisent uniquement la BDD locale Komptia (``ValueMapping``) qui
#:   contient des valeurs déjà tokenisées au sync. Pas de lecture SQL
#:   Server runtime.
#: - ``analyze_null_data`` : lit SQL Server mais ne retourne que des
#:   stats agrégées (counts, ratios) — pas de valeurs réelles au LLM
#:   (cf. ``NullAnalysisResult.to_dict``).
#: - ``introspect_table`` / ``get_database_schema`` : métadonnées
#:   schéma uniquement (Niveau 1 doctrine).
#: - ``test_sql`` / ``compare_query_variants`` / ``check_join_compatibility``
#:   / ``explore_join_alternatives`` : retournent uniquement des
#:   ``COUNT(*)`` (nombre, pas de rows).
#:
#: **Pour ajouter un tool** : (1) vérifier qu'il lit la BDD source ET
#: retourne des rows ou samples (chiffres compris) au LLM, (2) l'ajouter
#: ci-dessous, (3) ajouter un test de garde dans
#: ``tests/unit/test_iris_data_read_consent.py``.
CONSENT_REQUIRED_TOOLS: frozenset[str] = frozenset(
    {
        "execute_sql",
        "peek_table_data",
    }
)


def requires_consent(tool_name: str) -> bool:
    """Vrai si l'outil ``tool_name`` doit déclencher le gate de
    consentement avant que son ``tool_result`` soit transmis au LLM cloud.

    Lecture seule sur :data:`CONSENT_REQUIRED_TOOLS`. Caller doit aussi
    vérifier que le ``result`` contient effectivement des rows à
    protéger via :func:`result_has_protected_rows` — un result d'erreur
    ou sans rows ne nécessite pas de gate.
    """
    if not isinstance(tool_name, str):
        return False
    return tool_name in CONSENT_REQUIRED_TOOLS


def result_has_protected_rows(tool_result: Any) -> bool:
    """Vrai si le ``tool_result`` contient effectivement des données à
    protéger (déclencher le gate uniquement dans ce cas).

    **Critère** : ``success`` n'est pas False ET le payload contient des
    rows non vides. La métrique principale est ``row_count`` car les
    deux handlers du périmètre actuel posent cette clé :

    - ``_handle_execute_sql`` (``agent_tools.py:4561``) → ``row_count``
      et ``anonymized_sample`` (pas ``rows``).
    - ``_handle_peek_table_data`` (``agent_tools.py:5224``) → ``row_count``
      et ``rows``.

    Fallback défensif : si le handler omet ``row_count`` (régression
    future), inspecte les payloads connus (``rows``, ``anonymized_sample``,
    ``sample``) pour ne pas skip silencieusement une fuite. Préférer
    gate par excès qu'un faux négatif silencieux.

    Tout nouvel outil ajouté à :data:`CONSENT_REQUIRED_TOOLS` doit poser
    ``row_count`` dans son result, sinon ajouter sa clé de payload ici.
    """
    if not isinstance(tool_result, dict):
        return False
    if tool_result.get("success") is False:
        return False
    # Tolérer les types numériques élargis : un Decimal/string venant
    # d'un round-trip JSON (cf. ``json.dumps(default=str)`` côté
    # agent_service) doit aussi être interprété correctement, sinon le
    # gate skip silencieusement et la fuite passe — exactement le
    # scénario que la garde doit empêcher. ``isinstance(x, bool)`` est
    # explicit pour ne PAS interpréter ``True`` (qui hérite de ``int``)
    # comme "row_count=1".
    row_count_raw = tool_result.get("row_count")
    try:
        if isinstance(row_count_raw, bool):
            row_count = 0
        elif row_count_raw is None:
            row_count = 0
        else:
            row_count = int(row_count_raw)
    except (TypeError, ValueError):
        row_count = 0
    if row_count > 0:
        return True
    for key in ("rows", "anonymized_sample", "sample"):
        payload = tool_result.get(key)
        if isinstance(payload, list) and len(payload) > 0:
            return True
    return False


# ── Préférence persistée en BDD ─────────────────────────────────────────


async def get_user_consent_pref(session: AsyncSession, user_id: Optional[int]) -> str:
    """Lit la préférence consent du user. Défaut ``ask`` si absente
    ou corrompue.

    ``user_id=None`` (call sans contexte user — batch, tests) →
    ``always_allow`` : on ne peut pas gater un user qui n'existe pas,
    le système doit continuer. La couche 1 PII regex protège toujours
    indépendamment.
    """
    if user_id is None:
        logger.info(
            "data_read_consent: get_user_consent_pref user_id=None -> always_allow"
        )
        return "always_allow"

    result = await session.execute(
        select(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == _PREF_KEY,
        )
    )
    pref = result.scalar_one_or_none()
    if pref is None:
        logger.info(
            "data_read_consent: get_user_consent_pref user_id=%s key=%r -> "
            "PAS DE ROW (fallback DEFAULT_CONSENT='ask')",
            user_id,
            _PREF_KEY,
        )
        return DEFAULT_CONSENT
    if pref.value not in VALID_CONSENT_VALUES:
        logger.warning(
            "data_read_consent: get_user_consent_pref user_id=%s pref.value=%r "
            "n'est pas dans VALID_CONSENT_VALUES -> fallback DEFAULT_CONSENT='ask'",
            user_id,
            pref.value,
        )
        return DEFAULT_CONSENT
    logger.info(
        "data_read_consent: get_user_consent_pref user_id=%s -> %r",
        user_id,
        pref.value,
    )
    return pref.value


async def set_user_consent_pref(session: AsyncSession, user_id: int, value: str) -> None:
    """Persiste la préférence consent. Lève ``ValueError`` si valeur
    inadmise (defense-in-depth — l'endpoint HTTP valide déjà).

    Appelé par :
    - ``PUT /api/settings/iris-consent`` (UI déclarative).
    - Le WS handler ``data_read_consent_response`` quand l'utilisateur
      coche « ne plus me redemander » en plein flow Iris.
    """
    if value not in VALID_CONSENT_VALUES:
        raise ValueError(
            f"set_user_consent_pref: valeur '{value}' invalide. "
            f"Attendu : {sorted(VALID_CONSENT_VALUES)}."
        )

    # Pattern upsert : SELECT puis INSERT/UPDATE. Atomicité assurée par
    # la contrainte ``uq_user_preference_key`` (rollback si collision).
    result = await session.execute(
        select(UserPreference).where(
            UserPreference.user_id == user_id,
            UserPreference.key == _PREF_KEY,
        )
    )
    pref = result.scalar_one_or_none()
    if pref is None:
        session.add(
            UserPreference(
                user_id=user_id,
                key=_PREF_KEY,
                value=value,
                category="preference",
            )
        )
    else:
        pref.value = value
    # ``commit()`` est laissé au caller pour permettre la composition
    # avec d'autres opérations dans la même transaction.


# ── Gate runtime : Future + état par conversation ───────────────────────


@dataclass
class ConsentResponse:
    """Réponse de l'utilisateur au prompt de consentement.

    - ``approved=True`` : Iris peut lire les résultats. Le caller continue
      le flow normalement.
    - ``approved=False`` : refus. Selon le contexte, le caller peut soit
      ouvrir le panneau d'anonymisation (workflow standard), soit abandonner
      la lecture (si l'utilisateur ferme tout via Esc/X).
    - ``abandoned=True`` (avec ``approved=False``) : l'utilisateur a fermé
      le modal entièrement plutôt que de choisir OUI/NON — abandon de la
      requête SQL en cours. Iris reçoit un ``tool_result`` "Lecture refusée".
    - ``dont_ask_again`` (informationnel) : le caller WS gère la
      persistance de la pref. Le flux runtime ne s'en sert pas directement.
    """

    approved: bool
    abandoned: bool = False
    dont_ask_again: bool = False


#: Storage in-memory des Future en attente, keyed par ``conversation_id``.
#: Multi-conversation par user supportée (chaque conversation a son
#: propre cycle de consentement). Limité par la mémoire du process.
_pending_futures: dict[int, asyncio.Future[ConsentResponse]] = {}

#: Conversations où le consentement a déjà été granté ce run-time
#: (réponse OUI ou pref ``always_allow``). Skip le prompt pour les
#: ``execute_sql`` suivants dans la même conversation.
#:
#: Keyé par ``(user_id, conversation_id)`` plutôt que ``conversation_id``
#: seul — defense-in-depth contre une éventuelle collision si un futur
#: refactor change la stratégie d'allocation des conv_id (séquentiel
#: par user au lieu de séquentiel global). Aucune collision aujourd'hui
#: (conv_id BDD est globalement unique), mais le coût est négligeable.
#:
#: Reset au prochain démarrage du serveur (volontaire — un restart
#: lance une nouvelle session conceptuelle).
_consented_conversations: set[tuple[int, int]] = set()


def is_conversation_consented(user_id: int, conversation_id: int) -> bool:
    """Vrai si cet utilisateur a déjà donné son consentement dans cette
    conversation. Skip le prompt pour les tools suivants."""
    return (user_id, conversation_id) in _consented_conversations


def mark_conversation_consented(user_id: int, conversation_id: int) -> None:
    """Marque la conversation comme consentie pour le reste du run-time
    serveur. Idempotent. Appelé après une réponse ``approved=True``."""
    _consented_conversations.add((user_id, conversation_id))


def clear_conversation_consent(user_id: int, conversation_id: int) -> None:
    """Retire la marque de consentement (test, debug, ou changement
    explicite via /settings). Idempotent."""
    _consented_conversations.discard((user_id, conversation_id))


# ── Décision du gate (single source of truth, pure & testable) ──────────

#: Actions possibles retournées par :func:`evaluate_consent_gate`.
CONSENT_GATE_SKIP: str = "skip"  # lecture autorisée sans prompt
CONSENT_GATE_PROMPT: str = "prompt"  # demander (yield event + await réponse)


def evaluate_consent_gate(pref: str, already_consented: bool) -> str:
    """Décide l'action du gate pour UN résultat SQL protégé, à partir de la
    préférence user et de l'état de consentement de la conversation.

    **Single source of truth** de la logique de décision : le gate runtime
    dans ``agent_service`` se contente d'appliquer le verdict. Fonction pure
    et déterministe → testable sans mock du free-loop.

    Retourne :

    - :data:`CONSENT_GATE_SKIP` : lecture directe sans prompt — pref
      ``always_allow``, OU mode persistant (``ask``) déjà consenti dans la
      conversation.
    - :data:`CONSENT_GATE_PROMPT` : demander le consentement — le caller
      yield ``data_read_consent_request`` puis ``await request_consent``.

    ``always_show_panel`` retourne **TOUJOURS** ``prompt`` : il ne consulte
    jamais ``already_consented``. La doctrine du mode (cf. docstring module,
    « ouvre systématiquement le panneau ») est d'ouvrir le panneau à CHAQUE
    résultat SQL. Consulter le cache de conversation ferait que le panneau
    ne s'ouvre qu'une fois par conversation au lieu de chaque fois — bug
    observé 2026-05-30, ce verdict est la garde anti-régression.

    Valeur de ``pref`` inattendue : traitée comme ``ask`` (fail-safe — on
    demande plutôt que d'autoriser silencieusement ; ``get_user_consent_pref``
    normalise déjà les valeurs corrompues vers ``ask`` en amont).
    """
    if pref == "always_allow":
        return CONSENT_GATE_SKIP
    if pref == "always_show_panel":
        return CONSENT_GATE_PROMPT
    # ``ask`` (et tout pref inattendu, fail-safe) : 1 prompt par conversation.
    return CONSENT_GATE_SKIP if already_consented else CONSENT_GATE_PROMPT


async def request_consent(
    conversation_id: int,
    cancel_event: Optional[asyncio.Event] = None,
) -> ConsentResponse:
    """Crée un Future en attente de la réponse du user et bloque jusqu'à
    sa résolution OU le timeout OU un cancel utilisateur.

    Le caller (agent_service) doit avoir AVANT yieldé un event WebSocket
    ``data_read_consent_request`` au frontend — ce module ne gère pas la
    communication WS, seulement le rendez-vous asynchrone.

    Retourne un :class:`ConsentResponse`. Si le timeout est atteint, on
    considère que l'utilisateur a abandonné : ``approved=False`` +
    ``abandoned=True``. Si ``cancel_event`` (passé par le caller) est
    set pendant l'attente, idem (abandon) — sans cette compétition, un
    user qui clique « Stop » pendant le prompt resterait bloqué pendant
    ``RESPONSE_TIMEOUT_SECONDS``.

    Re-entrance : si un Future est déjà en attente pour cette
    ``conversation_id`` (cas pathologique : le caller a envoyé 2 prompts
    sans consommer le 1er), on annule l'ancien et installe le nouveau.
    """
    existing = _pending_futures.get(conversation_id)
    if existing is not None and not existing.done():
        logger.warning(
            "data_read_consent: Future en attente ÉCRASÉ pour conv=%s "
            "(double request_consent suspect — un nouvel execute_sql arrive "
            "avant que l'user ait répondu au précédent)",
            conversation_id,
        )
        existing.cancel()

    # ``asyncio.get_running_loop()`` au lieu de ``get_event_loop()`` —
    # ce dernier est deprecated Python 3.10+ et lèvera ``RuntimeError``
    # dans les versions futures sans loop courant. Ici on est forcément
    # dans une coroutine async, donc ``get_running_loop`` est OK.
    loop = asyncio.get_running_loop()
    future: asyncio.Future[ConsentResponse] = loop.create_future()
    _pending_futures[conversation_id] = future
    logger.info(
        "data_read_consent: Future CRÉÉ pour conv=%s (request_consent ouvert, "
        "await de la réponse user max %ss)",
        conversation_id,
        RESPONSE_TIMEOUT_SECONDS,
    )

    try:
        if cancel_event is None:
            return await asyncio.wait_for(future, timeout=RESPONSE_TIMEOUT_SECONDS)

        # Compétition Future vs cancel_event vs timeout : le premier qui
        # finit gagne. Sans ça, un user qui clique « Stop » pendant un
        # prompt en attente reste bloqué jusqu'à 5 minutes.
        cancel_task = asyncio.create_task(cancel_event.wait())
        done, pending = await asyncio.wait(
            {future, cancel_task},
            timeout=RESPONSE_TIMEOUT_SECONDS,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if future in done:
            return future.result()
        if cancel_task in done:
            logger.info(
                "data_read_consent: cancel_event set during await — traité comme abandon "
                "(conv=%s)",
                conversation_id,
            )
            return ConsentResponse(approved=False, abandoned=True)
        # ``done`` vide → asyncio.wait timeout atteint.
        logger.info(
            "data_read_consent: timeout (%.0fs) sur conv=%s — traité comme abandon",
            RESPONSE_TIMEOUT_SECONDS,
            conversation_id,
        )
        return ConsentResponse(approved=False, abandoned=True)
    except asyncio.TimeoutError:
        logger.info(
            "data_read_consent: timeout (%.0fs) sur conv=%s — traité comme abandon",
            RESPONSE_TIMEOUT_SECONDS,
            conversation_id,
        )
        return ConsentResponse(approved=False, abandoned=True)
    except asyncio.CancelledError:
        # Annulé par un autre request_consent ou par le caller — traité
        # comme abandon pour ne pas leak l'état au caller.
        return ConsentResponse(approved=False, abandoned=True)
    finally:
        # Cleanup défensif : ne JAMAIS laisser un Future résolu dans le
        # dict. Sinon une future ``request_consent(same_id)`` croirait
        # qu'il y a un Future en attente et l'écraserait par erreur.
        _popped = _pending_futures.pop(conversation_id, None)
        if _popped is not None:
            logger.info(
                "data_read_consent: Future POPPÉ pour conv=%s (request_consent "
                "terminé — done=%s cancelled=%s)",
                conversation_id,
                _popped.done(),
                _popped.cancelled(),
            )


def resolve_consent(
    user_id: int,
    conversation_id: int,
    response: ConsentResponse,
) -> bool:
    """Résout le Future en attente avec la réponse user. Idempotent :
    une 2ᵉ résolution (cas multi-onglet ou clic compulsif) est
    silencieusement no-op et retourne ``False``.

    Retourne ``True`` si la résolution a été effective (Future trouvé
    et résolu), ``False`` sinon (pas de Future en attente, ou déjà
    résolu — non-erreur, défensive).

    Si ``response.approved=True``, le module marque automatiquement la
    conversation comme consentie (clé ``(user_id, conversation_id)``)
    pour éviter de redemander dans cette conversation.

    ⚠️ Cette marque est **volontairement ignorée** par le gate en mode
    ``always_show_panel`` (cf. :func:`evaluate_consent_gate`, qui ne
    consulte jamais ``already_consented`` pour ce mode). La marque reste
    posée — ce handler ne connaît pas la pref user et marquer est
    inoffensif — mais NE PAS rebrancher ``is_conversation_consented`` dans
    une décision de gate en mode panel : cela réveillerait le bug
    2026-05-30 (panneau ouvert une seule fois au lieu de chaque résultat).
    """
    future = _pending_futures.get(conversation_id)
    if future is None or future.done():
        logger.info(
            "data_read_consent: resolve_consent no-op pour user=%s conv=%s "
            "(pas de Future en attente ou déjà résolu)",
            user_id,
            conversation_id,
        )
        return False

    if response.approved:
        mark_conversation_consented(user_id, conversation_id)
        logger.info(
            "data_read_consent: MARK conv=%s user=%s comme consentie "
            "(résolution approved=True)",
            conversation_id,
            user_id,
        )

    future.set_result(response)
    logger.info(
        "data_read_consent: resolve_consent OK conv=%s user=%s approved=%s "
        "abandoned=%s dont_ask_again=%s",
        conversation_id,
        user_id,
        response.approved,
        response.abandoned,
        response.dont_ask_again,
    )
    return True


# ── Extraction valeurs uniques d'un tool_result SQL ─────────────────────


def extract_unique_values_from_sql_result(
    tool_result: Any,
    max_values: int = 500,
) -> list[str]:
    """Extrait les valeurs uniques distinctes d'un ``tool_result`` SQL
    (format de ``_handle_execute_sql`` ou ``_handle_run_pipeline``) pour
    pré-remplir le panneau "Confidentialité — termes à anonymiser".

    **Critère de sélection** :
    - On parcourt ``tool_result.rows`` (ou ``tool_result["rows"]``).
    - Pour chaque cellule string non-vide, on collecte la valeur.
    - On exclut les valeurs purement numériques (le filtre type du
      panneau permet à l'user de les voir s'il le souhaite — mais par
      défaut on cap au signal "termes textuels potentiellement sensibles").
    - On déduplique et cap à ``max_values`` (UI : 500 valeurs suffisent ;
      au-delà le rendu virtual-list devient lent).

    Retourne une liste ordonnée (insertion order — Python 3.7+) pour un
    affichage stable.

    ⚠️ Volontairement défensif : un ``tool_result`` mal formé (clés
    manquantes, types inattendus) retourne ``[]`` sans lever — le caller
    décide de la suite (panneau vide → user sait qu'il n'y a rien à
    configurer, soit Iris lit, soit user annule).
    """
    if not isinstance(tool_result, dict):
        return []

    rows = tool_result.get("rows")
    if not isinstance(rows, list):
        # Format alternatif possible : tool_result["sample"] ou autre.
        # Best-effort : essayer ``sample`` qui est utilisé par certains
        # handlers (introspect_table notamment).
        rows = tool_result.get("sample")
        if not isinstance(rows, list):
            return []

    unique: dict[str, None] = {}  # ordered set via dict keys
    for row in rows:
        if not isinstance(row, dict):
            continue
        for cell_value in row.values():
            if not isinstance(cell_value, str):
                continue
            stripped = cell_value.strip()
            if not stripped:
                continue
            if stripped in unique:
                continue
            # Cap dur sur la longueur d'une valeur (anti-injection visuelle
            # + cohérence avec MAX_VALUE_LEN du tokenizer Komptia).
            if len(stripped) > 500:
                continue
            unique[stripped] = None
            if len(unique) >= max_values:
                return list(unique.keys())

    return list(unique.keys())
