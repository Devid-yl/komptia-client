"""Sérialisation JSON tolérante aux types Python non-JSON — SSoT.

Incident 2026-06-12 : une exécution d'automatisation RÉUSSIE (SQL → Excel →
email envoyé) a été requalifiée en ÉCHEC parce que l'INSERT du journal
``F_STEP_EXECUTION`` plantait — ``step_output`` embarquait des ``datetime``
venus de SQL Server (pyodbc) et l'engine SQLAlchemy n'avait AUCUN
``json_serializer`` (le ``json.dumps`` par défaut refuse ``datetime``).

Ce module fournit LE sérialiseur JSON des colonnes ``JSON`` SQLAlchemy
(branché via ``json_serializer=`` sur les 3 points de création d'engine de
``app/core/database.py`` — engine principal, engines async de jobs planifiés
``make_async_engine``, engines sync ``make_sync_engine``). Tout type
non-JSON devient une représentation SÛRE au lieu d'un crash.

Choix de représentation (journal/observabilité — pas une source de vérité
métier, qui elle reste dans les workbooks/exports) :
- ``datetime``/``date``/``time`` → ISO 8601 (lisible, triable, réversible) ;
- ``Decimal`` → ``float`` : on RESTE un nombre côté JSON (une string
  casserait silencieusement tout lecteur qui agrège) — perte de précision
  acceptable pour un journal ;
- ``bytes`` → décodage UTF-8 avec remplacement (jamais de crash) ;
- ``set``/``frozenset``/``tuple`` → liste ;
- fallback → ``str(o)`` (UUID, Path, Enum hors str-Enum, timedelta, etc.).
"""

from __future__ import annotations

import json
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any


def json_default(value: Any) -> Any:
    """Handler ``default=`` : convertit un type non-JSON en équivalent sûr."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, (set, frozenset, tuple)):
        return list(value)
    return str(value)


def dumps_safe(obj: Any, **kwargs: Any) -> str:
    """``json.dumps`` qui ne lève JAMAIS ``TypeError`` sur un type exotique.

    ``ensure_ascii=False`` : les libellés français (étape « Convertir en
    Excel/CSV »…) restent lisibles dans la BDD au lieu d'échappements ``\\uXXXX``.
    """
    kwargs.setdefault("default", json_default)
    kwargs.setdefault("ensure_ascii", False)
    return json.dumps(obj, **kwargs)
