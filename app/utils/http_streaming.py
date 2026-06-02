"""Streaming de fichiers vers une réponse Tornado sans explosion mémoire.

Trois appelants (``reports.py``, ``datastore.py``, ``automations.py``) avaient
dupliqué la même boucle read/write — drift garanti (un qui flush, un qui non,
chunk sizes divergents). Une seule implémentation canonique réduit le risque
et concentre les fixes (anti-CRLF sur filename, ``Referrer-Policy`` sur
télécharge\u00admement de tokens) à une classe utilitaire.

Garanties
---------
* **Event loop non bloqué** — ouverture/lecture/fermeture passent par
  ``asyncio.to_thread`` ; pas d'appel bloquant sur le loop Tornado.
* **Streaming constant** — borne mémoire du handler = ``chunk_size`` (par
  défaut 64 KiB), indépendamment de la taille du fichier servi.
* **Flush après chaque chunk** — évite l'accumulation côté client si le
  réseau est lent (``write_buffer`` Tornado plafonne autrement).
* **Fermeture fail-safe** — le ``finally`` ferme même si le client coupe la
  connexion (``WriteError`` Tornado).

Pourquoi ne pas utiliser ``aiofiles`` directement ? La dépendance n'est
pas dans le lockfile du projet. ``asyncio.to_thread`` est suffisamment
performant pour les volumes attendus (PDF < 50 Mo, XLSX < 50 Mo) et évite
une dep externe. Si l'app ingère un jour des volumes > 500 Mo, revisiter.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Final
from urllib.parse import quote

from app.utils.validators import assert_no_crlf

if TYPE_CHECKING:  # évite le cycle d'import (handlers → utils → handlers)
    from app.handlers.base import BaseHandler

#: Taille d'un chunk de streaming. 64 KiB aligne sur la page TCP usuelle
#: (MTU 1500 × ~43 paquets) et garde la latence perçue faible sur les
#: connexions lentes (client reçoit le premier octet en < 100 ms).
DEFAULT_CHUNK_BYTES: Final[int] = 64 * 1024


async def stream_file_to_handler(
    handler: BaseHandler,
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_BYTES,
) -> None:
    """Stream ``file_path`` sur la réponse HTTP de ``handler`` par chunks.

    Appelle ``handler.write()`` + ``handler.flush()`` pour chaque chunk.
    **Le caller doit poser les headers (Content-Type, Content-Disposition,
    Content-Length) AVANT d'appeler cette fonction**, et appeler
    ``handler.finish()`` après retour.

    La fonction ne fait aucun check de chemin : le caller est responsable de
    valider ``file_path`` contre le path traversal (``Path.resolve()`` +
    ``is_relative_to`` sur le base_dir autorisé). Ajouter une validation
    ici doublonnerait la garde des services (``report_storage.get_file_path``,
    ``datastore._safe_path``) et créerait de la confusion sur "qui valide".
    """
    file_handle = await asyncio.to_thread(open, file_path, "rb")
    try:
        while True:
            chunk = await asyncio.to_thread(file_handle.read, chunk_size)
            if not chunk:
                return
            handler.write(chunk)
            await handler.flush()
    finally:
        await asyncio.to_thread(file_handle.close)


def sanitize_download_filename(file_name: str) -> str:
    """Encode un nom de fichier pour ``Content-Disposition`` (RFC 6266).

    * ``assert_no_crlf`` — défense-in-depth contre la response splitting
      (CWE-93). Le caller borne déjà les noms ; on double-check au point
      d'émission.
    * ``quote`` — percent-encoding pour gérer les caractères unicode
      (accents, émojis) sans casser le header ASCII.

    SSoT du téléchargement sûr : tout handler qui sert un fichier passe par
    cette fonction (``reports.py`` la ré-exporte sous son ancien nom privé
    pour rétro-compat de ses call-sites et tests).
    """
    assert_no_crlf(file_name, "file_name")
    return quote(file_name)


def set_download_security_headers(
    handler: BaseHandler,
    content_type: str,
    filename: str,
    *,
    inline: bool = False,
    content_length: int | None = None,
) -> None:
    """Pose les headers de téléchargement sûrs (Content-Type, Disposition, Referrer-Policy).

    Invariant transverse : **tous** les téléchargements de l'app (rapports,
    guides d'aide, futurs exports) passent par ici pour garantir la même
    posture sécurité — un nouvel endpoint de download qui pose ses headers
    « à la main » serait une régression silencieuse de ces garanties.

    * ``Referrer-Policy: no-referrer`` — si le fichier est affiché inline et
      contient un lien externe, sans ce header le navigateur fuiterait
      l'URL courante (qui peut contenir un ID ou un token de partage).
    * ``X-Content-Type-Options: nosniff`` — bloque le MIME sniffing
      navigateur, évite qu'un fichier malicieux soit interprété comme HTML.
    """
    handler.set_header("Content-Type", content_type)
    handler.set_header("Referrer-Policy", "no-referrer")
    handler.set_header("X-Content-Type-Options", "nosniff")

    safe_filename = sanitize_download_filename(filename)
    disposition = "inline" if inline else "attachment"
    handler.set_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{safe_filename}")
    if content_length is not None:
        handler.set_header("Content-Length", content_length)
