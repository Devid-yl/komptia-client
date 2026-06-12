"""Décompression gzip robuste et bornée — SINGLE SOURCE OF TRUTH (décode EN RAM).

SSoT pour décompresser un blob gzip ``.afz.json`` ENTIÈREMENT EN MÉMOIRE :
upload datastore (gzip navigateur ``CompressionStream``) et lecture classeur
(``classeur.reader.decode_afz_bytes`` → web UI, automation, copilot, scan
anonymisation, cleanup). Avant cette consolidation, la logique était dupliquée
dans ``datastore._gunzip_with_cap`` et ré-implémentée à coups de
``gzip.decompress`` dans ``classeur.reader`` et ``automation.workbook_loader`` —
avec des robustesses et des caps divergents.

⚠️ PÉRIMÈTRE — exception délibérée : le TÉLÉCHARGEMENT NORMAL en STREAMING
(``datastore.py``) ne passe PAS par ici. Il lit un fichier serveur (membre gzip
unique, propre → la fragilité octets-de-queue ne l'atteint pas) et le STREAME
chunk par chunk vers le client (``gzip.open``) avec la contrainte « poser le
status 413 AVANT le 1ᵉʳ flush » — un pattern d'I/O différent (sortie réseau, pas
un ``bytes`` en RAM) qui justifie de rester séparé. Sa borne reste la même SSoT
que partout : le quota de stockage admin (plus aucun cap hardcodé). Le download
ANONYMISÉ, lui, re-matérialise le JSON → il passe désormais par ``decode_afz_bytes``
(donc par ici).

Deux exigences que ``gzip.GzipFile`` / ``gzip.decompress`` ne satisfont PAS :

1. **Tolérance aux octets de queue.** ``GzipFile`` lit le 1ᵉʳ membre gzip PUIS
   tente d'en parser un second ; le moindre octet résiduel après le membre
   (padding ``CompressionStream`` selon le navigateur, artefact chunked d'un
   proxy/nginx, marqueur de troncature) déclenche ``BadGzipFile`` « Not a
   gzipped file » APRÈS avoir pourtant décompressé toutes les vraies données —
   un classeur parfaitement valide était alors rejeté. ``decompressobj(wbits=31)``
   s'arrête proprement au marqueur de fin du 1ᵉʳ membre et range le résidu dans
   ``unused_data`` SANS lever ; on l'ignore (les producteurs n'émettent qu'UN
   membre, le reste est du bruit de transport).

2. **Borne RAM anti zip-bomb.** ``gzip.decompress`` charge tout en mémoire sans
   plafond : un petit gzip malicieux « explose » en gigaoctets et OOM-kill le
   conteneur. On décompresse en streaming avec un cap dur sur la sortie.

On rejette en revanche fermement un flux TRONQUÉ (marqueur de fin jamais
atteint) : renvoyer un préfixe décompressé silencieusement serait une perte de
données invisible — pire qu'un crash.
"""

from __future__ import annotations

import io
import zlib

_GZIP_MAGIC: bytes = b"\x1f\x8b"
#: Taille de sortie par itération de décompression (borne le pic mémoire d'un
#: chunk intermédiaire ; sans rapport avec le cap total ``max_bytes``).
_GUNZIP_CHUNK: int = 256 * 1024


class GunzipError(ValueError):
    """Base — échec de décompression gzip.

    Sous-classe ``ValueError`` pour rester rétrocompatible avec les callers
    historiques qui attrapaient ``ValueError``, tout en permettant aux nouveaux
    de distinguer la CAUSE (trop gros vs corrompu) par ``isinstance`` — message
    utilisateur et log diffèrent selon le cas.
    """


class GunzipTooLargeError(GunzipError):
    """Le flux décompressé dépasse le plafond anti zip-bomb (cap RAM)."""


class GunzipCorruptError(GunzipError):
    """Flux gzip illisible : en-tête invalide, tronqué, ou données corrompues."""


def gunzip_first_member(data: bytes, max_bytes: int) -> bytes:
    """Décompresse le PREMIER membre gzip de ``data``, tolérant aux octets de queue.

    Args:
        data: octets commençant (idéalement) par les magic bytes gzip.
        max_bytes: plafond dur sur la taille DÉCOMPRESSÉE (anti zip-bomb).

    Returns:
        Les octets décompressés du 1ᵉʳ membre gzip. Tout résidu après le membre
        est ignoré.

    Raises:
        GunzipTooLargeError: la sortie dépasse ``max_bytes``.
        GunzipCorruptError: pas d'en-tête gzip, flux tronqué, ou corrompu.
    """
    if data[:2] != _GZIP_MAGIC:
        raise GunzipCorruptError("en-tête gzip absent")

    out = io.BytesIO()
    total = 0
    buf = data
    # wbits=31 = 16 (wrapper gzip) + 15 (fenêtre max) → décode UN membre gzip.
    decomp = zlib.decompressobj(wbits=31)
    try:
        while True:
            part = decomp.decompress(buf, _GUNZIP_CHUNK)
            # Entrée non consommée (sortie plafonnée à _GUNZIP_CHUNK) → reboucle.
            # ``unused_data`` (résidu APRÈS le membre) reste ignoré.
            buf = decomp.unconsumed_tail
            if part:
                total += len(part)
                if total > max_bytes:
                    raise GunzipTooLargeError("flux décompressé trop volumineux")
                out.write(part)
            if decomp.eof:
                break  # 1ᵉʳ membre complet — octets de queue ignorés
            if not part and not buf:
                break  # entrée épuisée sans marqueur de fin → tronqué (cf. ci-dessous)
        tail = decomp.flush()
        if tail:
            total += len(tail)
            if total > max_bytes:
                raise GunzipTooLargeError("flux décompressé trop volumineux")
            out.write(tail)
        if not decomp.eof:
            raise GunzipCorruptError("flux gzip tronqué (marqueur de fin manquant)")
    except GunzipError:
        raise
    except (zlib.error, OSError, EOFError, MemoryError) as exc:
        # zlib.error n'est PAS une OSError ; MemoryError survient près du cap.
        # On normalise pour que les callers aient des types stables à attraper.
        raise GunzipCorruptError(f"{type(exc).__name__}: {exc}") from exc
    return out.getvalue()


def is_gzip_magic(data: bytes) -> bool:
    """True si ``data`` commence par les magic bytes gzip (``0x1f 0x8b``)."""
    return len(data) >= 2 and data[:2] == _GZIP_MAGIC
