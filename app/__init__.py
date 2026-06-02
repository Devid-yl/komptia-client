"""Initialisation du package Komptia.

Configure OpenSSL pour autoriser TLS 1.0/1.1 quand la configuration legacy
est présente dans ``config/openssl_legacy.cnf``. Nécessaire pour les anciens
serveurs SQL Server (type Sage Coala) qui n'exposent pas TLS 1.2+.

La configuration doit être posée AVANT tout import de ``pyodbc`` : la placer
dans le ``__init__.py`` du package garantit qu'elle précède tout import
depuis ``app.*``. Tout autre entry point (script standalone, script
utilitaire) doit importer ``app`` en tête avant tout import de ``pyodbc``.

Règles de non-surprise :

- ``OPENSSL_CONF`` déjà défini dans l'environnement → respecté tel quel.
  Permet aux opérateurs (Docker, CI, durcissement custom) d'imposer leur
  propre configuration sans être silencieusement écrasés.
- Fichier legacy absent → aucune modification de l'environnement.
- ``pyodbc`` déjà importé au moment de l'appel → ``RuntimeWarning`` :
  OpenSSL est déjà initialisé pour le process, la nouvelle config ne sera
  pas relue pour les connexions ouvertes.

Effet de bord important : l'activation baisse le niveau de sécurité OpenSSL
pour l'ensemble du process Python (``SECLEVEL=0`` + ``MinProtocol=TLSv1``),
pas uniquement pour ``pyodbc``. Les appels HTTPS sortants (Anthropic API,
SMTP, etc.) héritent du même niveau. À terme, préférer un worker dédié
pour la connexion Sage ou la migration du serveur source vers TLS 1.2+.
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


_configure_openssl_legacy()
