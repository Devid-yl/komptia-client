"""
T20 — Store in-memory de l'IR par conversation pour permettre les mutations
multi-tour (cf. ``ir_mutator``).

**Volatile** : reset au restart serveur. Si l'agent demande une mutation
mais le store est vide, le handler ``mutate_last_ir`` renvoie une erreur
``NO_PREVIOUS_IR`` actionnable — l'agent relance alors ``run_pipeline``.

**Isolation cross-user** : clé = ``(user_id, conversation_id)``. Aucune
fuite possible entre utilisateurs car la clé inclut ``user_id`` ; un
``get(user_X, conv_Z)`` n'atteint jamais la valeur posée par
``set(user_Y, conv_Z)``.

**Thread-safe** : un ``asyncio.Lock`` par clé pour les mutations, un
``_meta_lock`` global pour les opérations sur les structures internes
(``_data``, ``_locks``). LRU eviction au-delà de
``DEFAULT_MAX_ENTRIES``.

**Pas de persistance disque** : le run.json reste la source de vérité
en cas de besoin (l'agent peut le rappeler via ``inspect_pipeline_artifact``).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from typing import Any, Optional, TypedDict

logger = logging.getLogger(__name__)

DEFAULT_MAX_ENTRIES: int = 200


class IRBundle(TypedDict, total=False):
    """Bundle stocké par conversation : tout ce qu'il faut pour recomposer
    un SQL à partir d'une mutation de l'IR."""

    ir: dict
    concept_resolution: dict
    fk_lookup: dict
    source_run_id: int
    query_nl: str
    created_at: float  # unix epoch ; posé automatiquement par ``set`` si absent


_StoreKey = tuple[int, int]  # (user_id, conversation_id)


class ConversationIRStore:
    """Singleton in-memory ``{(user_id, conversation_id): IRBundle}`` avec
    LRU eviction et locks par clé.

    L'instance est créée paresseusement via ``get_ir_store()``. Les tests
    peuvent appeler ``reset_for_tests()`` pour repartir d'un état propre.
    """

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError(f"max_entries doit être int > 0, got {max_entries!r}")
        self._max = max_entries
        self._data: "OrderedDict[_StoreKey, IRBundle]" = OrderedDict()
        self._locks: dict[_StoreKey, asyncio.Lock] = {}
        # Protège _data et _locks (lectures + structure).
        self._meta_lock = asyncio.Lock()

    @staticmethod
    def _validate_keys(user_id: Any, conversation_id: Any) -> Optional[_StoreKey]:
        """Valide et normalise une paire (user_id, conversation_id).

        Returns:
            La paire (int, int) si valide, sinon ``None``. Les callers
            qui veulent un échec dur doivent vérifier eux-mêmes.
        """
        if isinstance(user_id, bool) or not isinstance(user_id, int):
            return None
        if user_id <= 0:
            return None
        if isinstance(conversation_id, bool) or not isinstance(conversation_id, int):
            return None
        if conversation_id <= 0:
            return None
        return (user_id, conversation_id)

    async def _get_key_lock(self, key: _StoreKey) -> asyncio.Lock:
        """Récupère (ou crée) le lock pour une clé.

        Thread-safe via ``_meta_lock``. Le lock est conservé en mémoire
        tant que la clé existe dans ``_data`` ; il est purgé lors de
        l'éviction LRU ou d'un ``clear`` explicite.
        """
        async with self._meta_lock:
            if key not in self._locks:
                self._locks[key] = asyncio.Lock()
            return self._locks[key]

    async def set(
        self,
        user_id: int,
        conversation_id: int,
        bundle: IRBundle,
    ) -> None:
        """Stocke (ou écrase) l'IRBundle pour ``(user_id, conversation_id)``.

        Raises:
            ValueError : clé invalide ou bundle manquant.
        """
        key = self._validate_keys(user_id, conversation_id)
        if key is None:
            raise ValueError(
                f"clé invalide: user_id={user_id!r}, conversation_id={conversation_id!r}"
            )
        if not isinstance(bundle, dict):
            raise ValueError(f"bundle doit être un dict, got {type(bundle).__name__}")
        if "ir" not in bundle or not isinstance(bundle["ir"], dict):
            raise ValueError("bundle invalide (manque 'ir' ou ir non-dict)")

        lock = await self._get_key_lock(key)
        async with lock:
            async with self._meta_lock:
                # Copie défensive — l'appelant ne doit pas pouvoir muter
                # le bundle stocké après coup.
                bundle_with_ts: IRBundle = dict(bundle)  # type: ignore[assignment]
                bundle_with_ts.setdefault("created_at", time.time())
                self._data[key] = bundle_with_ts
                self._data.move_to_end(key)
                # LRU eviction (cap strict).
                while len(self._data) > self._max:
                    evicted_key, _ = self._data.popitem(last=False)
                    self._locks.pop(evicted_key, None)
                    logger.debug(
                        "ConversationIRStore: evicted LRU key=%s (cap=%d)",
                        evicted_key,
                        self._max,
                    )

    async def get(
        self,
        user_id: int,
        conversation_id: int,
    ) -> Optional[IRBundle]:
        """Récupère le bundle pour ``(user_id, conversation_id)``.

        Touch LRU side-effect : la clé devient la plus récente.

        Returns:
            ``None`` si clé invalide ou absente.
        """
        key = self._validate_keys(user_id, conversation_id)
        if key is None:
            return None
        async with self._meta_lock:
            bundle = self._data.get(key)
            if bundle is not None:
                self._data.move_to_end(key)
            return bundle

    async def clear(self, user_id: int, conversation_id: int) -> bool:
        """Supprime l'entrée pour ``(user_id, conversation_id)``.

        Returns:
            True si l'entrée existait et a été supprimée, False sinon.
        """
        key = self._validate_keys(user_id, conversation_id)
        if key is None:
            return False
        async with self._meta_lock:
            existed = key in self._data
            self._data.pop(key, None)
            self._locks.pop(key, None)
            return existed

    async def update_ir(
        self,
        user_id: int,
        conversation_id: int,
        new_ir: dict,
    ) -> bool:
        """Update juste le champ ``ir`` d'un bundle existant (idempotent).

        Le ``concept_resolution`` et le ``fk_lookup`` sont conservés —
        cf. mutate_last_ir qui re-utilise la résolution précédente.

        Returns:
            False si pas de bundle existant pour cette clé.
        """
        key = self._validate_keys(user_id, conversation_id)
        if key is None:
            return False
        if not isinstance(new_ir, dict):
            raise ValueError(f"new_ir doit être dict, got {type(new_ir).__name__}")
        lock = await self._get_key_lock(key)
        async with lock:
            async with self._meta_lock:
                existing = self._data.get(key)
                if existing is None:
                    return False
                existing["ir"] = new_ir
                existing["created_at"] = time.time()  # bump pour LRU
                self._data.move_to_end(key)
                return True

    async def atomic_mutate(
        self,
        user_id: int,
        conversation_id: int,
        mutator,
    ):
        """Acquiert le lock par clé pour TOUTE la durée d'une opération
        read-modify-write.

        Anti race TOCTOU : entre ``get`` et ``update_ir``, le bundle ne peut
        PAS être muté par un autre call dans la même conversation.

        Args:
            user_id, conversation_id : clé d'isolation.
            mutator : ``async callable(bundle: IRBundle | None) -> Any``.
                      Si ``bundle is None`` (pas de bundle stocké), le
                      mutator est tout de même appelé pour décider du
                      comportement (par ex. retourner une erreur).
                      Si le mutator retourne un dict ``{"new_ir": dict}``,
                      le bundle est mis à jour AVANT release lock.
                      Tout autre type de retour est passé tel quel au caller.

        Returns:
            La valeur retournée par ``mutator``.

        Raises:
            ValueError : clé invalide.
            Toute exception levée par ``mutator`` est propagée APRÈS release
            du lock — le bundle n'est pas modifié dans ce cas.
        """
        key = self._validate_keys(user_id, conversation_id)
        if key is None:
            raise ValueError(
                f"clé invalide: user_id={user_id!r}, " f"conversation_id={conversation_id!r}"
            )
        lock = await self._get_key_lock(key)
        async with lock:
            # Lecture sous lock — pas de move_to_end ici (le caller décide
            # via le retour s'il y a un update).
            async with self._meta_lock:
                bundle = self._data.get(key)
                # Copie défensive — le mutator peut deep-copier l'IR sans
                # impacter le store ; mais s'il modifie le bundle en place
                # par accident, on serait pollué. ``mutator`` reçoit donc
                # le bundle réel — TODO: dict(bundle) pour shallow safety,
                # mais le mutator n'est attendu que de READ.
            try:
                result = await mutator(bundle)
            except Exception:
                raise
            # Si le mutator retourne {"new_ir": ...}, on persiste avant
            # release lock. Aucun autre call ne peut intervenir.
            if isinstance(result, dict) and isinstance(result.get("new_ir"), dict):
                async with self._meta_lock:
                    existing = self._data.get(key)
                    if existing is not None:
                        existing["ir"] = result["new_ir"]
                        existing["created_at"] = time.time()
                        self._data.move_to_end(key)
            return result

    def size(self) -> int:
        """Nombre d'entrées en cache (lecture non-bloquante)."""
        return len(self._data)

    @property
    def max_entries(self) -> int:
        return self._max


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton: Optional[ConversationIRStore] = None


def get_ir_store() -> ConversationIRStore:
    """Retourne le singleton (créé paresseusement à la 1re utilisation)."""
    global _singleton
    if _singleton is None:
        _singleton = ConversationIRStore()
    return _singleton


def reset_for_tests() -> None:
    """Reset le singleton — à utiliser UNIQUEMENT depuis les tests unitaires
    pour garantir l'isolation entre cas (un test ne doit pas hériter de
    l'état d'un précédent)."""
    global _singleton
    _singleton = None
