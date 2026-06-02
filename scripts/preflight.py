#!/usr/bin/env python3
"""Préflight : valide statiquement la config de déploiement AVANT de démarrer l'app.

But (todo consolidation déploiement #12) : attraper les erreurs de config
(``.env`` / ``config.yaml``) tout de suite, là où l'opérateur peut corriger,
plutôt que de les découvrir en testant l'app une fois démarrée.

Réutilise EXACTEMENT les checks statiques de
``app.services.diagnostics.startup_check`` (SSoT — aucune logique dupliquée) :
seuls les checks « sans I/O » (lecture ``config`` / ``os.environ``) sont
exécutables hors application. Les vérifications réseau/BDD (Sage, LLM, SMTP,
schéma) ne sont PAS faites ici — elles restent dans ``startup_check`` au boot
et dans ``/health`` (elles nécessitent l'app + la BDD chiffrée ouvertes).

Usage : ``python -m scripts.preflight``  (à câbler dans le first-run de
déploiement — cf. todo #5). Code de sortie ≠ 0 si au moins une ERREUR, pour
bloquer une chaîne make/CI avant le build/boot.
"""

from __future__ import annotations

import asyncio
import sys

# Checks statiques (lecture config/env, AUCUNE I/O) partagés avec
# ``startup_check`` — réutilisés tels quels (single source of truth).
from app.services.diagnostics import (
    _check_debug_off,
    _check_environment_coherence,
    _check_scheduler_enabled,
    _check_ws_origins,
)

#: Sous-ensemble « statique » de startup_check (pas de BDD/réseau requis).
#: Volontairement explicite : ``sqlite``/``admin_seeded``/``sage_config``/
#: ``llm_config``/``schema_loaded`` font de l'I/O et n'ont leur place qu'APRÈS
#: le boot (startup_check complet), pas dans un préflight pré-démarrage.
_STATIC_CHECKS = [
    ("environment_coherence", _check_environment_coherence),
    ("ws_origins", _check_ws_origins),
    ("debug_off", _check_debug_off),
    ("scheduler_enabled", _check_scheduler_enabled),
]

_ICON = {"ok": "OK  ", "warning": "WARN", "error": "ERR "}


async def _run() -> int:
    """Exécute les checks statiques, imprime un rapport, retourne le code de sortie."""
    errors = 0
    warnings = 0
    print("=== Komptia preflight — validation config avant démarrage ===")
    for name, fn in _STATIC_CHECKS:
        try:
            result = await fn()
        except Exception as exc:  # noqa: BLE001 — un check ne doit pas crasher le préflight
            result = {
                "status": "error",
                "detail": f"check '{name}' a échoué : {exc.__class__.__name__}",
            }
        status = result.get("status", "ok")
        line = f"[{_ICON.get(status, status)}] {name}"
        if result.get("detail"):
            line += f" — {result['detail']}"
        print(line)
        if status != "ok" and result.get("fix"):
            print(f"        -> FIX: {result['fix']}")
        if status == "error":
            errors += 1
        elif status == "warning":
            warnings += 1

    print(f"=> {errors} ERREUR(s), {warnings} avertissement(s).")
    if errors:
        print("=> Démarrage déconseillé : corriger les ERREUR(s) dans .env / config.yaml.")
    print("=> Vérifs réseau (Sage/LLM/SMTP) + schéma BDD : APRÈS le boot (/health, startup_check).")
    return 1 if errors else 0


def main() -> None:
    """Point d'entrée CLI : exit ≠ 0 si une erreur de config est détectée."""
    sys.exit(asyncio.run(_run()))


if __name__ == "__main__":
    main()
