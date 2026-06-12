"""Initialisation du package Komptia.

Configure OpenSSL pour autoriser TLS 1.0/1.1 quand la configuration legacy
est présente dans ``config/openssl_legacy.cnf``. Nécessaire pour les anciens
serveurs SQL Server (type Sage Coala) qui n'exposent pas TLS 1.2+.

Mécanisme à DEUX étages (le second depuis 2026-06-11) :

1. **Env** : ``OPENSSL_CONF`` est posé vers le fichier legacy. Suffisant
   uniquement si AUCUNE libcrypto n'est encore initialisée — or l'init est
   déclenchée par le premier ``import hashlib`` du process (donc par
   sqlalchemy, pytest et la quasi-totalité des libs), PAS seulement par
   ``pyodbc``. « Importer ``app`` en tête » ne suffit donc que pour un
   entry point vraiment propre (``app.main``).
2. **Reload à chaud** : ``_reload_openssl_config_in_process`` recharge la
   config (``CONF_modules_load_file``) dans les libcrypto DÉJÀ chargées du
   process. Rend l'ordre des imports indifférent : pytest, scripts
   standalone et workers qui importent ``app`` tardivement obtiennent
   quand même le TLS legacy pour Sage.

Règles de non-surprise :

- ``OPENSSL_CONF`` déjà défini dans l'environnement → respecté tel quel,
  ET aucun reload (on ne ré-applique jamais une conf qu'on n'a pas posée).
  ⚠️ Conséquence pour l'ops : une conf custom posée dans ``os.environ``
  APRÈS l'init de libcrypto n'est jamais relue par OpenSSL — poser
  ``OPENSSL_CONF`` dans l'environnement du process AVANT le lancement de
  Python (Dockerfile, systemd, shell), jamais depuis le code.
- Fichier legacy absent → aucune modification, aucun reload.
- L'ancien ``RuntimeWarning`` « pyodbc déjà importé » subsiste dans
  ``_configure_openssl_legacy`` à titre de diagnostic, mais le cas qu'il
  décrit est désormais couvert par le reload (étage 2).
- Le bootstrap suppose un import de ``app`` mono-thread (cas normal des
  entry points). Ne pas importer ``app`` paresseusement depuis un thread
  d'un process déjà multi-threadé qui fait du TLS : le reload muterait la
  config globale pendant des handshakes en cours.

⚠️ Effet de bord SÉCURITÉ (périmètre ÉLARGI par l'étage 2) : l'activation
baisse le niveau OpenSSL pour l'ensemble du process (``SECLEVEL=0`` +
``MinProtocol=TLSv1``) — y compris, depuis le reload, pour pytest, les
scripts standalone et tout worker important ``app``, pas seulement les
entry points prod. Le vrai vecteur de risque n'est pas TLS 1.0 (réservé de
fait au serveur Sage qui le réclame) mais **SECLEVEL=0** : il réautorise
ciphers et certificats faibles sur TOUTES les connexions sortantes
(Anthropic API, SMTP) si un MITM les propose. Risque accepté en
connaissance de cause (réseau cabinet, endpoints connus). À terme, isoler
la connexion Sage dans un worker dédié avec ``OPENSSL_CONF`` scopé — seule
vraie correction — ou migrer le serveur source vers TLS 1.2+.
"""

from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path

_OPENSSL_ENV = "OPENSSL_CONF"
_OPENSSL_LEGACY_DIR = "config"
_OPENSSL_LEGACY_FILENAME = "openssl_legacy.cnf"


def _configure_openssl_legacy(
    project_root: Path | None = None,
    *,
    respect_existing: bool = True,
) -> Path | None:
    """Pointe ``OPENSSL_CONF`` vers la config TLS legacy si applicable.

    Retourne le chemin appliqué, ou ``None`` quand aucune modification n'a
    été faite (env déjà défini / fichier absent). Le retour permet aux
    tests et aux diagnostics de vérifier sans inspecter ``os.environ``.

    Args:
        project_root: racine du projet où chercher ``config/openssl_legacy.cnf``.
            Par défaut, le parent du dossier ``app/``. Exposé pour les tests.
        respect_existing: si ``True`` (défaut), ne remplace pas une valeur
            déjà présente dans l'environnement — critique en production pour
            ne pas downgrade une config ops durcie.
    """
    if respect_existing and _OPENSSL_ENV in os.environ:
        return None

    root = project_root if project_root is not None else Path(__file__).resolve().parent.parent
    config_path = root / _OPENSSL_LEGACY_DIR / _OPENSSL_LEGACY_FILENAME
    if not config_path.is_file():
        return None

    if "pyodbc" in sys.modules:
        warnings.warn(
            f"pyodbc importé avant la configuration {_OPENSSL_ENV} : "
            "OpenSSL est déjà initialisé pour le process, la config legacy "
            "ne sera pas relue. Importer le package 'app' avant tout import "
            "de pyodbc pour garantir l'ordre.",
            RuntimeWarning,
            stacklevel=2,
        )

    os.environ[_OPENSSL_ENV] = str(config_path)
    return config_path


def _iter_loaded_libcrypto_paths() -> list[str]:
    """Chemins des libcrypto OpenSSL DÉJÀ chargées dans le process.

    macOS : énumération des images dyld. Linux : ``/proc/self/maps``.
    Windows : liste vide (le driver SQL Server y utilise SChannel, la
    config OpenSSL est sans objet). La LibreSSL système macOS
    (``/usr/lib/libcrypto*``) est exclue : elle n'est pas celle du driver
    ODBC, et son ``CONF_modules_load_file`` répond -1 (observé) — c'est
    elle que ``ctypes.CDLL(None)`` résout en premier, d'où l'énumération
    explicite plutôt qu'un lookup global de symbole.

    Best-effort strict : toute erreur → liste vide (le fallback env
    ``OPENSSL_CONF`` reste posé pour les libcrypto pas encore chargées).
    """
    paths: list[str] = []
    try:
        if sys.platform == "darwin":
            import ctypes

            dyld = ctypes.CDLL(None)
            dyld._dyld_image_count.restype = ctypes.c_uint32
            dyld._dyld_get_image_name.restype = ctypes.c_char_p
            dyld._dyld_get_image_name.argtypes = [ctypes.c_uint32]
            for i in range(dyld._dyld_image_count()):
                raw = dyld._dyld_get_image_name(i)
                if not raw:
                    continue
                name = raw.decode("utf-8", "replace")
                if "libcrypto" in os.path.basename(name) and not name.startswith("/usr/lib/"):
                    paths.append(name)
        elif sys.platform.startswith("linux"):
            # Pas d'exclusion /usr/lib ici — sur Linux la libcrypto système
            # y vit légitimement (ex. /usr/lib/x86_64-linux-gnu/), contrai-
            # rement à macOS où /usr/lib/ = LibreSSL Apple à écarter.
            with open("/proc/self/maps", encoding="utf-8", errors="replace") as maps:
                for line in maps:
                    # Format : addr perms offset dev inode  pathname — le
                    # pathname est le 6e champ et PEUT contenir des espaces
                    # (maps ne les échappe pas) : split(maxsplit=5), jamais
                    # rsplit (review adversariale 2026-06-11, MOYEN).
                    fields = line.split(maxsplit=5)
                    if len(fields) < 6:
                        continue
                    candidate = fields[5].strip()
                    if candidate.endswith(" (deleted)"):
                        candidate = candidate[: -len(" (deleted)")]
                    if candidate.startswith("/") and "libcrypto" in os.path.basename(candidate):
                        paths.append(candidate)
    except Exception:  # noqa: BLE001 — diagnostic best-effort, jamais bloquant
        return []
    # Dédup en préservant l'ordre de chargement.
    return list(dict.fromkeys(paths))


def _reload_openssl_config_in_process(config_path: Path) -> bool:
    """Applique la config TLS legacy aux libcrypto DÉJÀ initialisées.

    Pourquoi (2026-06-11) : OpenSSL ne lit ``OPENSSL_CONF`` qu'UNE fois,
    à l'initialisation de libcrypto — déclenchée par le premier
    ``import hashlib`` du process (donc par sqlalchemy, pytest et la
    quasi-totalité des libs), PAS seulement par pyodbc. Poser l'env dans
    ``_configure_openssl_legacy`` ne suffit donc que si ``app`` est le
    tout premier import du process : sous pytest ou dans un script qui
    importe sqlalchemy d'abord, la config legacy n'était jamais appliquée
    et toute connexion Sage échouait ``SSL routines::unsupported
    protocol`` (diagnostiqué par bissection : ``import hashlib`` avant
    ``app`` suffit à reproduire).

    ``CONF_modules_load_file(path, NULL, 0)`` recharge la config à chaud :
    la section ``system_default_sect`` (MinProtocol/CipherString) est
    relue et s'applique aux ``SSL_CTX`` créés ENSUITE — dont celui du
    driver msodbcsql au prochain connect (vérifié empiriquement :
    hashlib préchargé + reload → connexion Sage OK).

    Retourne ``True`` si au moins une libcrypto a accepté la config.
    Ne lève jamais : un échec laisse le comportement d'avant (env posé,
    warning ci-dessous pour la visibilité). Même portée process-wide que
    le mécanisme env documenté en tête de module (SECLEVEL=0 global).
    """
    import ctypes

    loaded_paths = _iter_loaded_libcrypto_paths()
    applied = False
    for lib_path in loaded_paths:
        try:
            lib = ctypes.CDLL(lib_path)
            load_file = lib.CONF_modules_load_file
            load_file.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong]
            load_file.restype = ctypes.c_int
            if load_file(str(config_path).encode(), None, 0) == 1:
                applied = True
            else:
                # rc != 1 laisse l'erreur sur la stack thread-locale
                # OpenSSL : on la purge pour ne pas léguer une erreur
                # orpheline au premier handshake du process (review
                # adversariale 2026-06-11, FAIBLE). Best-effort : le
                # symbole peut manquer selon le build.
                try:
                    lib.ERR_clear_error()
                except AttributeError:
                    pass
        except (OSError, AttributeError):
            continue
    if loaded_paths and not applied:
        warnings.warn(
            "libcrypto déjà chargée mais le rechargement de la config TLS "
            f"legacy ({config_path}) a échoué sur : {loaded_paths}. Les "
            "connexions Sage TLS 1.0/1.1 échoueront probablement "
            "(« unsupported protocol »).",
            RuntimeWarning,
            stacklevel=2,
        )
    return applied


_applied_legacy_conf = _configure_openssl_legacy()
if _applied_legacy_conf is not None:
    # Couvre le cas « libcrypto initialisée avant app » (pytest, scripts
    # important sqlalchemy/hashlib en premier). No-op si rien n'est encore
    # chargé : l'env posé ci-dessus s'appliquera à l'init normale.
    _reload_openssl_config_in_process(_applied_legacy_conf)
