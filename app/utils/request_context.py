"""Contexte de requête propagé via ``contextvars`` + helpers PII-safe.

Permet de logger ``request_id`` et ``user_id`` dans les services SANS
ajouter ces paramètres à toutes les signatures. ``BaseHandler.prepare()``
pose le contexte ; les services ``logger.X("msg", extra=current_log_extra())``
le récupèrent automatiquement.

Pourquoi ``contextvars`` plutôt qu'une variable globale ou un argument
explicite :
* ``contextvars`` est isolé par task asyncio — pas de fuite cross-request
  même sous charge concurrente.
* Pas besoin de plumber ``request_id=`` dans toutes les signatures de
  service (~50 méthodes), ce qui pollue l'API métier sans bénéfice.
* Test-friendly : ``set_request_context()`` dans un fixture isole
  chaque test.

Usage côté handler::

    class MyHandler(BaseHandler):
        async def prepare(self):
            super().prepare()
            set_request_context(
                request_id=self.request_id,
                user_id=self.current_user.id if self.current_user else None,
            )

Usage côté service::

    from app.utils.request_context import current_log_extra
    logger.info("Contact créé", extra=current_log_extra())
    # → JSON inclut request_id + user_id automatiquement.
"""

from __future__ import annotations

import hashlib
import logging
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

_log = logging.getLogger(__name__)


def _restore_value(
    var: ContextVar[Any],
    value: Any,
    *,
    where: str,
) -> None:
    """Restaure ``var`` à ``value`` de manière fail-safe.

    Remplace l'ancien pattern ``var.reset(token)`` (Token-based) qui
    levait ``ValueError("Token was created in a different Context")``
    sur chaque appel LLM streamé. Cause racine identifiée 2026-05-22 :
    ``IrisAgent._iterate_with_cancel`` (``agent_service.py``) wrappe
    chaque ``stream.__anext__()`` dans ``asyncio.create_task()``, qui
    crée à chaque chunk une *copie* du Context. Le ``Token`` produit
    par ``var.set(...)`` au ``__enter__`` (Task T1) ne peut pas être
    ``reset()`` au ``__exit__`` (Task T_N) — ``Token.reset`` est lié
    au Context exact qui l'a créé.

    Le caller capture la valeur courante via ``var.get()`` AVANT le
    ``var.set(new_value)`` du ``__enter__``, et passe cette
    **previous value** ici en sortie. ``var.set`` opère dans le
    Context courant peu importe lequel — pas de restriction
    Token-Context. Pattern *capture-previous-value* propre, robuste
    aux switches d'async-generator + ``create_task(__anext__)``.

    **Garantie d'isolation cross-coroutine** (cf. adversarial review
    2026-05-10 CRITICAL #4) : la previous value capturée au
    ``__enter__`` était la valeur LÉGITIME du Context à ce moment.
    En la restaurant en sortie, on garantit qu'aucune valeur posée
    par notre with-block ne fuite vers la coroutine suivante. Si la
    previous value était elle-même héritée d'un caller parent, elle
    reste héritée — c'est sémantiquement correct.

    Le ``try/except`` est défensif pour des cas pathologiques (mocks
    de test, ``ContextVar`` custom mal-implémenté). En condition
    normale, ``var.set(value)`` ne peut pas lever.
    """
    try:
        var.set(value)
    except Exception as exc:  # noqa: BLE001 — vraiment fail-safe
        # Pas d'``extra=current_log_extra()`` : le contexte est précisément
        # ce qui est en train d'être nettoyé, on évite la récursion.
        _log.warning(
            "ContextVar restore failed (%s): %s — previous value possibly lost",
            where,
            exc,
        )


# ContextVar par task asyncio. ``""`` = pas de contexte (logs hors requête,
# ex: scheduler, scripts admin) — on n'écrit rien dans les logs structurés.
_request_id: ContextVar[str] = ContextVar("komptia_request_id", default="")
_user_id: ContextVar[int | None] = ContextVar("komptia_user_id", default=None)

# Contexte LLM — propagé jusqu'au hook ``llm_call_tracker`` pour le
# breakdown "consommation par feature". ``caller`` = origine sémantique
# de l'appel LLM (``iris_main``, ``schema_sync``, ``copilot_cell``, etc.),
# ``conversation_id`` = grouping (UUID conv Iris ou batch sync).
# Default ``""`` / ``None`` = appel sans contexte (legacy, probe Ollama,
# script standalone) — le hook accepte et logue avec caller=NULL.
_caller: ContextVar[str] = ContextVar("komptia_llm_caller", default="")
_conversation_id: ContextVar[str | None] = ContextVar("komptia_llm_conversation_id", default=None)


def set_request_context(*, request_id: str = "", user_id: int | None = None) -> None:
    """Pose le contexte pour la task asyncio courante.

    Appelé par ``BaseHandler.prepare()`` qui pose le contexte au début
    de chaque requête HTTP et le réinitialise via ``reset_request_context()``
    en ``on_finish``.

    .. warning::
       **Pour tout scope bornable (block ``try/finally``, coroutine,
       message handler WebSocket), utiliser :func:`request_scope` à la
       place.** ``set_request_context`` n'a pas de mécanisme de reset
       automatique — il fuiterait sur la coroutine suivante traitée
       dans le même IOLoop, ce qui est précisément le bug que ``request_scope``
       résout pour les WS handlers (cf. ``IrisWebSocketHandler._run_agent``).
    """
    _request_id.set(request_id)
    _user_id.set(user_id)


def reset_request_context() -> None:
    """Efface le contexte (à appeler dans la cleanup d'un test, sinon
    fuite entre tests dans le même event-loop)."""
    _request_id.set("")
    _user_id.set(None)
    _caller.set("")
    _conversation_id.set(None)


def current_request_id() -> str:
    """Retourne le request_id courant ou ``""`` si hors requête."""
    return _request_id.get()


def current_user_id() -> int | None:
    """Retourne le user_id courant ou ``None`` si hors requête / anonyme."""
    return _user_id.get()


def current_caller() -> str:
    """Retourne le ``caller`` LLM courant (``""`` si non posé)."""
    return _caller.get()


def current_conversation_id() -> str | None:
    """Retourne le ``conversation_id`` LLM courant (``None`` si non posé)."""
    return _conversation_id.get()


@contextmanager
def request_scope(
    *,
    request_id: str = "",
    user_id: int | None = None,
) -> Iterator[None]:
    """Pose le contexte de requête pour la durée d'un bloc, **token-based**.

    Variante propre de :func:`set_request_context` : utilise le ``Token``
    retourné par ``ContextVar.set`` pour restaurer la valeur précédente
    en sortie. Indispensable pour les **WebSocket handlers** où plusieurs
    connexions partagent l'IOLoop : sans ce reset, le ``user_id`` posé par
    une connexion fuiterait sur les ``on_message`` d'une autre connexion
    qui suit dans la même boucle (les ContextVars sont task-locales mais
    Tornado dispatche les messages dans la task de l'IOLoop).

    Usage::

        async def _handle_send_message(self, payload):
            with request_scope(
                user_id=self.current_user.id,
                request_id=str(uuid.uuid4()),
            ):
                await agent.run(...)
                # current_user_id() retourne self.current_user.id ici et
                # dans toutes les coroutines descendantes (call_llm, hook
                # llm_call_tracker, etc.)

    Préfère ce CM à ``set_request_context()`` partout où le scope est
    bornable — ``set_request_context()`` reste utile pour les
    ``BaseHandler.prepare()`` HTTP où le reset est fait en
    ``on_finish``.

    Validation : ``user_id`` doit être ``None`` (anonyme/legacy) ou un
    entier strictement positif. Refuse les ``bool`` (qui sont des ``int``
    en Python — ``isinstance(True, int)`` retourne ``True``) et les
    valeurs négatives, qui ne correspondent à aucun ``users.id`` valide
    et indiquent un bug du caller.
    """
    if user_id is not None and (
        isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0
    ):
        raise ValueError(f"request_scope: user_id invalide ({user_id!r}) — attendu None ou int>0")
    # Pattern capture-previous-value : on lit la valeur courante AVANT de
    # poser la nôtre, puis on restaure en sortie via ``_restore_value``.
    # Robuste aux switches de Context (async-generators + ``create_task``
    # autour de ``__anext__``) — cf. docstring de ``_restore_value``.
    prev_request_id = _request_id.get()
    prev_user_id = _user_id.get()
    _request_id.set(request_id)
    _user_id.set(user_id)
    try:
        yield
    finally:
        _restore_value(_request_id, prev_request_id, where="request_scope.request_id")
        _restore_value(_user_id, prev_user_id, where="request_scope.user_id")


@contextmanager
def llm_call_context(
    *,
    caller: str,
    conversation_id: str | None = None,
) -> Iterator[None]:
    """Pose le contexte LLM pour la durée d'un bloc.

    Usage::

        with llm_call_context(caller="schema_sync", conversation_id=run_id):
            await manager.generate(request)

    À la sortie du bloc, restaure les valeurs précédentes (pas de fuite
    entre features qui pourraient s'enchaîner dans une même requête).
    Préfère ce context manager à ``set_request_context`` pour le LLM —
    il est scoped, donc safe en présence de tâches concurrentes.

    ``caller`` est obligatoire (vide non-accepté) pour forcer l'attribution
    correcte. Tous les sites d'appel LLM doivent fournir un caller
    sémantique précis (cf. liste dans ``llm_call_tracker``).
    """
    if not caller:
        raise ValueError("caller cannot be empty — use a semantic name")
    # Pattern capture-previous-value (cf. ``_restore_value`` pour le détail).
    # Indispensable ici : ``llm_call_context`` enveloppe la boucle de
    # streaming d'Iris (``stream_llm_with_tools`` dans ``llm_runtime.py``),
    # consommée via ``IrisAgent._iterate_with_cancel`` qui wrappe chaque
    # ``stream.__anext__()`` dans ``asyncio.create_task()``. Chaque chunk
    # vit dans un Context distinct ; un ``Token.reset()`` au ``__exit__``
    # serait quasi-systématiquement rejeté (warning à chaque LLM streamé).
    prev_caller = _caller.get()
    prev_conversation_id = _conversation_id.get()
    _caller.set(caller)
    _conversation_id.set(conversation_id)
    try:
        yield
    finally:
        _restore_value(_caller, prev_caller, where="llm_call_context.caller")
        _restore_value(
            _conversation_id,
            prev_conversation_id,
            where="llm_call_context.conversation_id",
        )


def current_log_extra(**overrides: Any) -> dict[str, Any]:
    """Construit un dict ``extra={}`` pour ``logger.X(..., extra=...)``.

    N'inclut que les valeurs non-vides (évite de polluer le JSON avec
    ``"request_id": ""`` partout). Les ``overrides`` sont fusionnés
    par-dessus — utile pour ajouter des champs métier (``contact_id``,
    ``operation``, etc.).
    """
    extra: dict[str, Any] = {}
    rid = _request_id.get()
    if rid:
        extra["request_id"] = rid
    uid = _user_id.get()
    if uid is not None:
        extra["user_id"] = uid
    extra.update(overrides)
    return extra


def hash_pii(value: str | None, *, length: int = 12) -> str:
    """Hash court (BLAKE2b) d'une valeur PII pour traçabilité audit RGPD-safe.

    Usage : remplacer ``deleted_email=user@example.com`` (PII clair, RGPD
    incompatible avec rétention 30j logs) par
    ``deleted_email_hash=hash_pii(email)`` qui permet la corrélation entre
    événements (le même email a été créé puis supprimé) sans stocker la
    valeur en clair. La rétention longue ne devient plus un problème
    article 17 RGPD.

    BLAKE2b > SHA-256 ici : plus rapide, et l'option ``digest_size`` permet
    un hash court natif (pas de troncature manuelle qui réduit l'entropie).
    """
    if not value:
        return ""
    h = hashlib.blake2b(value.encode("utf-8"), digest_size=max(4, length // 2))
    return h.hexdigest()
