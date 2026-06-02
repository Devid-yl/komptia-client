"""Garde d'identité de déploiement (#8, zone 1) — anti-corruption multi-instance.

Risque : deux déploiements Komptia qui partageraient PAR ERREUR la même BDD
locale (volume copié, montage croisé) corromperaient silencieusement les
singletons mono-déploiement (``tenant_setup_progress``, ``feature_flags``).

Mécanisme : au 1er boot, on enregistre dans le volume de données un identifiant
dérivé de la **source SQL Server** configurée (``hash(host:port:database)``).
Aux boots suivants :
- identité absente → on enregistre l'identité courante (1er boot), OK ;
- identité enregistrée == courante → OK ;
- divergence → la BDD locale a été initialisée pour une AUTRE source → soit BDD
  partagée par erreur (corruption), soit reconfiguration légitime de la source.
  **Fail-closed** : on lève :class:`DeploymentIdentityError` (refus boot), SAUF
  override explicite ``KOMPTIA_ALLOW_DEPLOYMENT_REASSIGN`` (changement voulu).

Les erreurs d'I/O sur le fichier d'identité sont **fail-safe** (loggées, non
bloquantes) : un hoquet FS ne doit pas empêcher le boot. Seule une divergence
CONFIRMÉE refuse le boot.

Le câblage au boot (qui propage la refus) est une étape séparée — ce module ne
fait que la logique, pure et testable.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

logger = logging.getLogger("komptia." + __name__)

#: Fichier (dans le volume de données) portant l'identité du déploiement.
_IDENTITY_FILENAME = ".deployment_id"
#: Env d'override : autorise la ré-assignation d'identité (reconfiguration source voulue).
_OVERRIDE_ENV = "KOMPTIA_ALLOW_DEPLOYMENT_REASSIGN"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


class DeploymentIdentityError(RuntimeError):
    """La BDD locale appartient à un autre déploiement (source SQL différente)."""


def compute_deployment_id() -> str:
    """Identifiant court (BLAKE2b 16o) dérivé de la source SQL configurée.

    Générique : dérive uniquement de ``host:port:database`` de la config courante
    (zéro nom hardcodé). Une source non configurée donne un id stable (sur les
    valeurs vides) — non bloquant en soi (la divergence ne se déclenche qu'entre
    deux sources REMPLIES différentes).
    """
    from app.config import config

    raw = f"{config.sage.host}:{config.sage.port}:{config.sage.database}".strip().lower()
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=16).hexdigest()


def _identity_path() -> Path:
    from app.config import config

    return Path(config.data_dir) / _IDENTITY_FILENAME


def _override_active() -> bool:
    return os.getenv(_OVERRIDE_ENV, "").strip().lower() in _TRUTHY


def verify_deployment_identity() -> None:
    """Vérifie/enregistre l'identité de déploiement. **Fail-closed sur divergence.**

    Raises:
        DeploymentIdentityError: identité enregistrée != courante, sans override.
    """
    current = compute_deployment_id()
    path = _identity_path()

    try:
        existing = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
    except OSError as exc:  # fail-safe : un FS capricieux ne bloque pas le boot
        logger.warning("Identité déploiement : lecture impossible (%s) — check ignoré", exc)
        return

    if not existing:
        _write_identity(path, current, first=True)
        return

    if existing == current:
        return

    if _override_active():
        logger.warning(
            "Identité de déploiement RÉ-ASSIGNÉE via %s (source SQL changée, "
            "reconfiguration acceptée). Ancien=%s → nouveau=%s.",
            _OVERRIDE_ENV,
            existing,
            current,
        )
        _write_identity(path, current, first=False)
        return

    raise DeploymentIdentityError(
        f"La BDD locale a été initialisée pour une AUTRE source SQL Server "
        f"(identité {existing} != courante {current}). Cause probable : volume/BDD "
        f"partagé par erreur entre deux déploiements (RISQUE DE CORRUPTION), ou "
        f"reconfiguration légitime de la source. Si le changement est VOULU, "
        f"relancer avec {_OVERRIDE_ENV}=1 pour ré-assigner l'identité ; sinon, "
        f"vérifier que CHAQUE déploiement a son PROPRE volume de données."
    )


def _write_identity(path: Path, value: str, *, first: bool) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        if first:
            logger.info("Identité de déploiement enregistrée (1er boot).")
    except OSError as exc:  # fail-safe : non bloquant
        logger.warning("Identité déploiement : écriture impossible (%s) — non bloquant", exc)
