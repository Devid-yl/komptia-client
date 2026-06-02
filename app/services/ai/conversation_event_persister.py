"""Persister des événements WebSocket d'une conversation Iris.

Source de vérité pour le replay au refresh : chaque event yieldé par
``IrisAgent.run()`` est persisté dans ``conversation_events`` avant d'être
envoyé au client. Au refresh, le frontend rejoue cette séquence via le MÊME
dispatcher que le live → DOM strictement IDENTIQUE.

Décision design (APEX 2026-05-09 — Solution B) :

- **Pas de whitelist d'event types**. On persiste TOUT (sauf ``cancelled``
  qui n'a aucun rendu DOM dans le frontend). Trim de payload = divergence
  garantie au refresh, donc interdit. Le coût BDD est géré par le TTL de
  ``db_retention.py``.
- **Persistance synchrone in-order** : ``SequentialEventPersister.persist``
  attribue un ``seq`` monotone sous lock per-conv et await l'INSERT BDD
  avant que le caller n'envoie l'event au client WS. Garantit qu'aucun
  event reçu côté frontend n'est absent de la BDD au refresh (= pas de
  divergence silencieuse).
- **Idempotence** : ``UNIQUE(conversation_id, turn_index, seq)`` côté table.
  Si un retry envoie le même event, l'INSERT échoue silencieusement (catché
  ici). Aucun doublon possible au refresh.

Contraintes :
- Generic — aucun event_type Iris-spécifique hardcodé. Toute évolution du
  flux d'events live (nouveau type, nouveau payload) est automatiquement
  prise en charge.
"""

from __future__ import annotations

import asyncio
import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.database import get_session
from app.models.conversation import ConversationEvent
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Events transients : non persistés en BDD (pas de row ``ConversationEvent``)
# MAIS quand même envoyés au client WS (signal logger, barre de progression
# live, modal consent ouvert). C'est l'union des deux propriétés "pas durable
# au refresh" + "doit être vu par le browser en live".
#
# **SSoT — IMPORTANT** : ``app/handlers/iris.py:_run_agent`` importe cette
# frozenset pour décider quels events transmettre au WS quand
# ``persist_event`` retourne ``False``. Si tu ajoutes un type ici :
# (a) il sera AUTOMATIQUEMENT envoyé au WS sans toucher iris.py, mais
# (b) il NE sera PAS persisté → vérifie que (1) le frontend a un handler
# pour ce type côté ``static/js/iris.js``, et (2) que l'event n'a pas
# besoin de survivre au refresh (sinon il faut le persister, pas le
# rendre transient).
#
# **Régression historique** : avant 2026-05-26, ``iris.py`` hardcodait
# ``("cancelled",)`` côté skip-WS-on-persist-failed → ``context_progress``
# et ``data_read_consent_request`` arrivaient dans la frozenset mais étaient
# silencieusement skippés côté iris.py → modals consent jamais affichés,
# barre de progression figée. Fix : SSoT via cette frozenset publique.
TRANSIENT_EVENT_TYPES = frozenset(
    {
        # ``cancelled`` : signal logger côté frontend (cf. iris.js case
        # ``cancelled``). Pas de DOM à reconstruire au refresh.
        "cancelled",
        # ``context_progress`` est émis APRÈS chaque tour LLM par
        # ``agent_service.py`` pour que la barre #contextWindowIndicator
        # avance dynamiquement pendant qu'Iris tool-calle. Pas d'état à
        # restaurer au refresh (l'event ``done`` final pose la valeur
        # finale dans la même conv) → ne pas polluer F_CONVERSATION_EVENT
        # avec N rows par tour.
        "context_progress",
        # ``data_read_consent_request`` est un prompt LIVE qui attend une
        # réponse user via ``data_read_consent_response`` (WS). Le Future
        # côté ``data_read_consent._pending_futures`` est in-memory : dès
        # que le browser refresh / reconnect, le Future est popped et la
        # réponse user arrive trop tard (no-op silencieux). Replayer cet
        # event au boot fait ré-afficher un modal orphelin qui ne peut
        # PLUS être résolu côté backend — l'user clique OUI, la pref se
        # bascule en ``always_allow`` mais ``mark_conversation_consented``
        # n'est pas appelé → au prochain execute_sql dans cette conv, le
        # gate re-lit pref + mark + skip OK, MAIS le replay re-fait le
        # cycle. Bug 2026-05-22 : enfer infini de modals que la pref ne
        # peut pas casser. Solution : ne pas persister ces events.
        # L'effet métier (pref persisted, conv marked) survit déjà via
        # ``user_preferences`` (durable BDD) + ``_consented_conversations``
        # (reset acceptable au restart serveur).
        "data_read_consent_request",
    }
)

# Champs à STRIP du payload AVANT persistance pour éviter de stocker en clair
# des données confidentielles client (rows SQL Server, contenu de fichier
# uploadé, etc.). Cf. CLAUDE.md confidentialité Niveau 4 + adversarial
# review CRITICAL #10. Le frontend reconstruit ces champs au replay depuis
# ``IRIS_CONFIG.conversationMessages`` (qui a sa propre persistance via
# ``ConversationMessage.tool_result`` — déjà existante AVANT cette table).
#
# Les events stockent toujours les MÉTADONNÉES (columns, row_count, sql)
# et un flag ``_rows_stripped: true`` pour indiquer au frontend qu'il doit
# faire le merge depuis savedMessages.
#
# ⚠️ NOTE PII (cf. adversarial review 2026-05-10 CRITICAL #7) :
# Le type ``user_message`` (WAL ajouté par ``iris.py:_run_agent``) contient
# le ``content`` brut du message utilisateur — qui peut nommer des entités,
# personnes ou montants confidentiels. C'est le même contenu que celui
# déjà stocké depuis toujours dans ``ConversationMessage.content`` (role=USER),
# donc pas une régression de surface PII. La rétention RGPD est gérée :
# (a) ``cleanup_conversation_events`` (TTL 30j par défaut, env
# ``CONVERSATION_EVENTS_RETENTION_DAYS``), (b) cascade DELETE depuis
# ``Conversation`` pour le droit à l'oubli individuel.
_PAYLOAD_FIELDS_TO_STRIP_BY_TYPE: dict[str, tuple[str, ...]] = {
    "sql_results": ("rows",),
    "tool": ("rows",),  # tool messages avec sql_data.rows
}


def _strip_confidential_fields(event: dict) -> dict:
    """Retourne une copie de l'event avec les champs confidentiels retirés.

    Generic — pas de connaissance du contenu, juste des noms de champs par
    type d'event (whitelist). Le DOM affichera les rows réelles via
    ``conversationMessages`` qui ont leur propre cycle de persistance.
    """
    event_type = event.get("type")
    fields = _PAYLOAD_FIELDS_TO_STRIP_BY_TYPE.get(event_type or "")
    if not fields:
        return event  # rien à strip pour ce type
    stripped = dict(event)  # shallow copy
    removed_any = False
    for field in fields:
        if field in stripped:
            del stripped[field]
            removed_any = True
    if removed_any:
        stripped["_rows_stripped"] = True
    return stripped


def _serialize_payload(event: dict) -> str:
    """Serialise le dict event en JSON. Fail-safe : si serialisation échoue
    (objets non-JSON), retourne un placeholder explicite plutôt que de
    crasher le streaming.
    """
    try:
        return json.dumps(event, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.warning(
            "ConversationEvent: payload serialization failed for type=%s: %s",
            event.get("type"),
            e,
        )
        return json.dumps(
            {
                "type": event.get("type", "unknown"),
                "_serialize_error": str(e)[:200],
            }
        )


async def persist_event(
    conversation_id: int,
    turn_index: int,
    seq: int,
    event: dict,
) -> bool:
    """Persiste un event en BDD. Idempotent via UNIQUE constraint.

    Returns:
        True si l'INSERT a réussi (ou échoué via UNIQUE — idempotent),
        False si une erreur inattendue est survenue.
    """
    if not isinstance(event, dict):
        return False
    event_type = event.get("type")
    if not isinstance(event_type, str) or not event_type:
        return False
    if event_type in TRANSIENT_EVENT_TYPES:
        return False  # silently skipped — c'est volontaire (caller WS DOIT
        # quand même envoyer au client : cf. iris.py qui importe
        # TRANSIENT_EVENT_TYPES pour gater son ``continue`` skip-WS).

    # Strip confidential fields BEFORE serialization (rows SQL).
    safe_event = _strip_confidential_fields(event)
    payload_json = _serialize_payload(safe_event)
    try:
        async with get_session() as session:
            row = ConversationEvent(
                conversation_id=conversation_id,
                turn_index=turn_index,
                seq=seq,
                event_type=event_type[:64],  # tronque au cap String(64)
                payload=payload_json,
            )
            session.add(row)
            try:
                await session.commit()
            except IntegrityError as err:
                # Distinguer UNIQUE (idempotent OK) vs FK violation (vrai bug).
                # Pattern : ``app/handlers/admin.py:_integrity_error_to_business``
                # qui parse ``err.orig`` brut (le format varie entre dialectes
                # mais nom de constraint reste). Cf. adversarial review CRITICAL #11.
                await session.rollback()
                orig_msg = str(getattr(err, "orig", err)).lower()
                is_unique = (
                    "uq_conversation_events_conv_turn_seq" in orig_msg
                    or "unique constraint" in orig_msg
                    or "duplicate key" in orig_msg
                )
                is_fk = "foreign key" in orig_msg or "foreign_key" in orig_msg
                if is_unique:
                    # Idempotent : event déjà persisté (retry, double-write).
                    logger.debug(
                        "ConversationEvent: skipped duplicate "
                        "(conv=%s, turn=%s, seq=%s, type=%s)",
                        conversation_id,
                        turn_index,
                        seq,
                        event_type,
                    )
                    return True
                if is_fk:
                    # Conv parente n'existe plus (delete concurrent) — on
                    # log error pour visibilité, return False pour que le
                    # caller skip _safe_write (atomicité).
                    logger.error(
                        "ConversationEvent: FK violation (conv=%s probably deleted)",
                        conversation_id,
                    )
                    return False
                # Autre IntegrityError — propager pour ne pas masquer un
                # vrai bug schéma (ex: NOT NULL violation, CHECK).
                logger.error(
                    "ConversationEvent: unknown IntegrityError (conv=%s, " "type=%s): %s",
                    conversation_id,
                    event_type,
                    orig_msg[:200],
                )
                return False
        return True
    except Exception as exc:  # noqa: BLE001 — fail-soft pour ne pas crasher le streaming
        logger.warning(
            "ConversationEvent: persist failed (conv=%s, seq=%s, type=%s): %s",
            conversation_id,
            seq,
            event_type,
            exc,
        )
        return False


# Locks par conv_id pour sérialiser les writes d'un même tour ET la lecture
# de ``max(seq)`` AVANT le 1er insert d'un tour (anti-race seq).
#
# **Pattern Guard lock** repris de ``app/services/ai/pipeline_runner.py:88-98``
# (``_USER_START_LOCKS`` / ``_get_user_start_lock``). Sans le Guard, deux
# coroutines first-touch sur le même conv_id créeraient deux ``Lock()``
# différents (race ``.get()`` puis assign), défaisant l'exclusion mutuelle.
# Cf. adversarial review BLOCKING #2/#3 du fix initial.
_CONV_LOCKS: dict[int, asyncio.Lock] = {}
_CONV_LOCKS_GUARD = asyncio.Lock()


async def _get_lock_for_conversation(conversation_id: int) -> asyncio.Lock:
    """Retourne le lock per-conv en garantissant qu'UN SEUL ``asyncio.Lock``
    existe pour un même ``conversation_id``, même sous concurrence first-touch.

    Note volume : pour 100 users actifs simultanés sur 100 conv différentes,
    le dict garde 100 locks en mémoire (~1 KB chacun). Pas de purge active —
    le process est généralement reload avant accumulation problématique.
    """
    async with _CONV_LOCKS_GUARD:
        lock = _CONV_LOCKS.get(conversation_id)
        if lock is None:
            lock = asyncio.Lock()
            _CONV_LOCKS[conversation_id] = lock
    return lock


class SequentialEventPersister:
    """Helper stateful pour persister les events d'UN tour dans l'ordre.

    Le caller (``IrisWebSocketHandler._run_agent``) instancie une fois par
    tour, puis appelle ``persist(event)`` pour chaque event yieldé par
    l'agent. Le seq est calculé en interne (monotone par instance), pas
    de race possible avec les tours antérieurs (chaque instance lit
    ``get_max_seq_for_conversation`` UNE fois au boot et incrémente en
    mémoire ensuite).

    Cf. adversarial review BLOCKING #2 (race seq) + ÉLEVÉ #5
    (persistance pas atomique). En passant à ``await`` synchrone,
    on a la garantie que l'event est persisté AVANT que l'envoi WS au
    client ait lieu — pas de cas où le client voit un event que la BDD
    n'a pas (= divergence au refresh).
    """

    __slots__ = ("conversation_id", "turn_index", "_seq")

    def __init__(self, conversation_id: int, turn_index: int, start_seq: int):
        self.conversation_id = conversation_id
        self.turn_index = turn_index
        self._seq = int(start_seq)

    @classmethod
    async def open(cls, conversation_id: int, turn_index: int) -> "SequentialEventPersister":
        """Factory : lit ``max(seq)`` actuel sous le lock per-conv pour
        garantir qu'AUCUN autre persister ne va lire la même valeur en
        parallèle (sinon 2 tours concurrents génèrent des seq qui collisionnent
        et les INSERTs perdants tombent silencieusement sur ``IntegrityError``).
        Cf. adversarial review BLOCKING #2 du fix initial.
        """
        lock = await _get_lock_for_conversation(conversation_id)
        async with lock:
            start = await get_max_seq_for_conversation(conversation_id)
        return cls(conversation_id, turn_index, start)

    async def persist(self, event: dict) -> bool:
        """Persiste un event sous le lock conv_id. Synchrone (await).

        Garantit que la BDD a vu l'event avant le retour. Le caller peut
        envoyer au client juste après en sécurité — aucune divergence
        silencieuse au refresh n'est possible.

        **Task #15 (M2, 2026-05-22)** — mute ``event["_seq"]`` avec le
        numéro monotone attribué par CE persister AVANT l'INSERT BDD. Le
        caller (handler WS) envoie ensuite l'event muté au client qui peut
        l'utiliser pour :
          - dedup au reconnect mid-stream (event reçu 2x avec même _seq)
          - détection trous (delta N+2 reçu sans N+1)
          - pagination de reprise via ``get_events_for_conversation(after_seq=X)``

        Mutation in-place car les events yieldés par l'agent sont des dicts
        FRAIS à chaque yield (pas de réutilisation downstream). Mutation
        ANTÉRIEURE à l'INSERT pour que le `_seq` soit aussi dans le payload
        persisté en BDD (rétrocompat replay).
        """
        if not isinstance(event, dict) or not event.get("type"):
            return False
        lock = await _get_lock_for_conversation(self.conversation_id)
        async with lock:
            self._seq += 1
            assigned_seq = self._seq
            # **Fix CRITICAL #3+#4 adversarial session 19 (2026-05-22)** :
            # persist BDD AVANT mutation event["_seq"], pour deux raisons :
            #
            # (1) Si persist BDD échoue (IntegrityError, BDD down), on
            #     rollback ``self._seq`` ET on NE mute PAS le dict. Sinon
            #     gap permanent dans la séquence du reste du turn + dict
            #     muté avec _seq fantôme qui peut leak en log.
            #
            # (2) Le payload BDD persisté ne contient PAS `_seq` (la colonne
            #     ``seq`` est la SSOT côté BDD, le `_seq` du dict ne sert
            #     qu'au transport WS). Évite duplication + bug de replay
            #     futur où `_seq` ancien serait réinjecté.
            try:
                ok = await persist_event(
                    self.conversation_id, self.turn_index, assigned_seq, event
                )
            except Exception:
                # Rollback compteur — le prochain persist reprendra le seq
                # qu'on vient de tenter (idempotent côté BDD via UNIQUE).
                self._seq -= 1
                raise
            if not ok:
                # persist_event a retourné False (échec silencieux) :
                # rollback aussi pour éviter le gap permanent.
                self._seq -= 1
                return False
            # Persist OK — mute APRÈS pour que le client voit le seq.
            event["_seq"] = assigned_seq
            return True


async def get_events_for_conversation(
    conversation_id: int,
    after_seq: int = 0,
) -> list[dict]:
    """Retourne les events d'une conversation triés par ``seq`` ASC.

    Args:
        conversation_id : conversation cible
        after_seq : retourne uniquement les events avec ``seq > after_seq``.
                    Permet la pagination / fetch incrémental côté admin UI.
                    Default 0 = tous.

    Format : list de dicts ``{seq, turn_index, event_type, payload (str JSON),
    created_at}``. Le frontend fait ``JSON.parse(payload)`` pour reconstruire
    le dict event original avant de le passer au dispatcher.
    """
    async with get_session() as session:
        stmt = (
            select(ConversationEvent)
            .where(ConversationEvent.conversation_id == conversation_id)
            .where(ConversationEvent.seq > after_seq)
            .order_by(ConversationEvent.seq.asc())
        )
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
    return [
        {
            "seq": r.seq,
            "turn_index": r.turn_index,
            "event_type": r.event_type,
            "payload": r.payload,
            "created_at": (r.created_at.isoformat() if r.created_at is not None else None),
        }
        for r in rows
    ]


async def get_max_seq_for_conversation(conversation_id: int) -> int:
    """Retourne le ``seq`` maximum stocké pour la conversation, ou 0 si vide.

    Utilisé par le handler WS au début d'un nouveau tour pour connaître le
    point de départ du compteur ``seq`` (monotone par conversation, pas
    par tour — assure l'ordre absolu cross-tour si jamais il y a un
    chevauchement).
    """
    from sqlalchemy import func as sql_func

    async with get_session() as session:
        stmt = select(sql_func.max(ConversationEvent.seq)).where(
            ConversationEvent.conversation_id == conversation_id
        )
        result = await session.execute(stmt)
        max_seq = result.scalar()
    return int(max_seq or 0)


async def get_max_turn_index_for_conversation(conversation_id: int) -> int:
    """Retourne le ``turn_index`` maximum, ou 0 si conversation vide.

    Utilisé pour calculer le ``turn_index`` du nouveau tour : ``max + 1``.
    """
    from sqlalchemy import func as sql_func

    async with get_session() as session:
        stmt = select(sql_func.max(ConversationEvent.turn_index)).where(
            ConversationEvent.conversation_id == conversation_id
        )
        result = await session.execute(stmt)
        max_turn = result.scalar()
    return int(max_turn or 0)
