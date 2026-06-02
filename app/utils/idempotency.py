"""Garde d'idempotence en mémoire pour les opérations sensibles aux doublons.

Pourquoi
--------
L'envoi d'emails aux contacts/clients est une opération où un **doublon** est
visible et embarrassant (le client reçoit deux fois le même rapport). Le
double-clic sur un onglet est déjà bloqué côté client (bouton désactivé), mais
deux cas résiduels restent : (1) deux onglets ouverts qui soumettent le même
envoi, (2) un retry réseau alors que le serveur avait déjà réussi (la réponse
s'est perdue). Cette garde dédoublonne ces requêtes RAPPROCHÉES côté serveur.

Conception
----------
* **Single-process** (cf. ``app/main.py``) → un dict en mémoire + lock suffit
  (pas besoin d'un store partagé type Redis).
* **TTL court** (~60 s) : on ne dédoublonne que les requêtes rapprochées. Un
  renvoi *délibéré* du même contenu plus tard repasse normalement.
* **``release`` sur échec** : on réserve la clé AVANT l'envoi, mais si l'envoi
  ÉCHOUE on la libère — sinon un premier envoi raté bloquerait à tort le retry
  légitime de l'utilisateur.
* **Transparent** : l'appelant répond explicitement « non renvoyé (doublon) »,
  jamais un faux succès silencieux.

Cette garde NE conserve PAS le résultat du premier envoi : sur doublon, on
renvoie un statut « déjà effectué » plutôt que de rejouer/retourner l'ancienne
réponse. C'est suffisant pour l'UX (anti-doublon) et évite la complexité d'un
cache de résultats + coordination d'attente.
"""

from __future__ import annotations

import hashlib
import threading
import time
import weakref
from typing import Iterable

#: TTL par défaut — fenêtre pendant laquelle deux envois identiques sont
#: considérés comme un doublon. Couvre un double-submit / retry réseau, pas un
#: renvoi délibéré ultérieur.
DEFAULT_IDEMPOTENCY_TTL_SECONDS: float = 60.0


def make_idempotency_key(
    *,
    kind: str,
    user_id: int,
    subject: str,
    body: str,
    recipient_ids: Iterable[int],
) -> str:
    """Clé déterministe d'un envoi : même contenu + mêmes destinataires + même
    user (+ même ``kind``) ⇒ même clé.

    ``kind`` préfixe la clé pour éviter toute collision entre endpoints
    distincts (ex. ``"report_email"`` vs ``"contact_email"``). ``recipient_ids``
    est trié pour être insensible à l'ordre. ``\\x00`` sépare les champs pour
    qu'une frontière déplacée ne produise pas la même clé (ex. subject="ab",
    body="c" ≠ subject="a", body="bc").
    """
    h = hashlib.sha256()
    for part in (kind, str(user_id), subject or "", body or ""):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    # ``str(i)`` AVANT ``sorted`` : robuste à un mélange de types (sinon
    # ``sorted([1, "a"])`` lève TypeError). Les call-sites valident les IDs en
    # amont, mais le helper ne doit jamais planter sur un input inattendu.
    h.update(",".join(sorted(str(i) for i in recipient_ids)).encode("utf-8"))
    return h.hexdigest()


class IdempotencyGuard:
    """Garde TTL en mémoire, thread-safe. Voir le docstring du module."""

    #: Registre FAIBLE des instances pour un cleanup global périodique
    #: (cf. ``cleanup_all`` + ``app/main.py``). Même pattern que ``RateLimiter``.
    _instances: "weakref.WeakSet[IdempotencyGuard]" = weakref.WeakSet()

    def __init__(self, ttl_seconds: float = DEFAULT_IDEMPOTENCY_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()
        IdempotencyGuard._instances.add(self)

    def claim(self, key: str) -> bool:
        """Réserve ``key``. Atomique.

        Returns:
            ``True`` si la clé vient d'être réservée (1er passage → procéder).
            ``False`` si elle était déjà réservée dans la fenêtre TTL
            (doublon → l'appelant doit bloquer l'envoi).
        """
        now = time.time()
        with self._lock:
            ts = self._seen.get(key)
            if ts is not None and (now - ts) < self._ttl:
                return False
            self._seen[key] = now
            return True

    def release(self, key: str) -> None:
        """Libère ``key`` — à appeler si l'envoi a ÉCHOUÉ, pour autoriser un
        retry immédiat (sinon le 1er échec bloquerait le 2e essai légitime)."""
        with self._lock:
            self._seen.pop(key, None)

    def cleanup(self) -> int:
        """Purge les clés expirées. Retourne le nombre de clés supprimées."""
        now = time.time()
        with self._lock:
            stale = [k for k, ts in self._seen.items() if (now - ts) >= self._ttl]
            for k in stale:
                del self._seen[k]
        return len(stale)

    @classmethod
    def cleanup_all(cls) -> int:
        """Purge toutes les instances enregistrées (croissance bornée, axe 21).
        Appelé périodiquement au runtime (cf. ``app/main.py``)."""
        total = 0
        for inst in list(cls._instances):
            total += inst.cleanup()
        return total


#: Singleton partagé par les endpoints d'envoi d'email user-initiated
#: (``/api/reports/send-email`` et ``/api/contacts/send-email``).
email_send_guard = IdempotencyGuard()
