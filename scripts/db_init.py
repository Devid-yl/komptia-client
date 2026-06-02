"""Initialise la base de données locale (tables + migrations idempotentes).

Exécution : ``python -m scripts.db_init`` (cf. ``make db-init``).

Pourquoi un module dédié plutôt qu'un ``python -c "..."`` dans le Makefile :
``init_database`` est ``async``. Un ``python -c "from app.core.database
import init_database; init_database()"`` lèverait ``RuntimeWarning``
("coroutine was never awaited") sans rien faire — bug silencieux qui était
masqué par l'ancien Makefile (qui appelait un ``init_db`` inexistant).

Le script est fail-fast : toute erreur fait remonter un code de sortie
non nul à ``make`` afin que la chaîne d'init s'arrête.
"""

from __future__ import annotations

import asyncio
import sys

from app.core.database import close_database, init_database
from app.utils.logger import AppLogger, get_logger

# ── Codes de sortie distincts (ADV-M32) ─────────────────────────────────
# Avant : ``except Exception → sys.exit(1)`` masquait toutes les erreurs
# sous le code 1. L'admin ne savait pas s'il s'agissait d'un import error,
# d'un permission denied, ou d'un schema mismatch. Codes différenciés :
#
#   1 = erreur générique (catch-all)
#   2 = permission / I/O (PermissionError, OSError sur fichier BDD)
#   3 = schema / SQLAlchemy (ProgrammingError, OperationalError SQL)
#   4 = import error (Python broken, deps manquantes)
#
# ``make`` reçoit le code et peut afficher un message d'aide adapté.

_EXIT_GENERIC = 1
_EXIT_IO = 2
_EXIT_SCHEMA = 3
_EXIT_IMPORT = 4


async def _run() -> None:
    """Crée tables + applique les migrations incrémentales idempotentes.

    ``init_database`` planifie une task fire-and-forget
    (``litellm_autosync_at_boot``) qui détient sa propre connexion aiosqlite.
    Sans teardown, ``asyncio.run`` ferme la boucle alors que cette task est
    encore en vol : la connexion est ensuite collectée par le GC sur une
    boucle morte → ``call_soon_threadsafe`` échoue dans le worker thread
    aiosqlite → ``Exception in thread Thread-N (_connection_worker_thread)``.
    ``close_database`` (idempotent) annule et draine les boot tasks PUIS
    dispose l'engine — le même chemin de teardown que l'app.

    Le ``finally`` couvre le cas nominal (init réussie → engine + boot task
    publiés → à drainer). Si ``init_database`` échoue AVANT de publier l'engine
    global (erreur ``create_all`` / migration), ``close_database`` est un no-op
    (``_engine is None``) — et c'est correct : la task de boot n'a pas encore
    été planifiée, il n'y a rien à nettoyer. Le teardown est lui-même
    encapsulé pour ne JAMAIS masquer l'exception d'init : sinon les codes de
    sortie différenciés de ``main`` (schema/IO/import) seraient corrompus si
    ``dispose`` levait à son tour.
    """
    try:
        await init_database()
    finally:
        try:
            await close_database()
        except Exception:  # noqa: BLE001 — cleanup best-effort, ne masque pas l'erreur primaire
            get_logger(__name__).warning(
                "Teardown BDD post-init échoué (non bloquant)", exc_info=True
            )


def main() -> None:
    """Point d'entrée CLI."""
    AppLogger.setup("INFO")
    logger = get_logger(__name__)
    try:
        asyncio.run(_run())
    except ImportError as exc:
        logger.critical("Import error — dépendances Python manquantes ?", exc_info=True)
        sys.stderr.write(f"❌ Import error: {exc}\n")
        sys.exit(_EXIT_IMPORT)
    except (PermissionError, OSError) as exc:
        logger.critical("Erreur I/O sur le fichier BDD", exc_info=True)
        sys.stderr.write(f"❌ I/O error: {exc.__class__.__name__}: {exc}\n")
        sys.exit(_EXIT_IO)
    except Exception as exc:  # noqa: BLE001 — fail-fast pour la chaîne make
        # On essaie de différencier SQLAlchemy errors (schema) des autres.
        try:
            from sqlalchemy.exc import SQLAlchemyError

            if isinstance(exc, SQLAlchemyError):
                logger.critical("Erreur schema SQLAlchemy", exc_info=True)
                sys.stderr.write(f"❌ Schema error: {exc.__class__.__name__}\n")
                sys.exit(_EXIT_SCHEMA)
        except ImportError:
            pass
        logger.critical("Initialisation BDD échouée", exc_info=True)
        sys.stderr.write(f"❌ {exc.__class__.__name__}: {exc}\n")
        sys.exit(_EXIT_GENERIC)
    logger.info("Base de données initialisée (tables + migrations OK)")


if __name__ == "__main__":
    main()
