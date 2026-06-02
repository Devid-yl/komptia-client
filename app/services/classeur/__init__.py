"""Service partagé de lecture/manipulation des classeurs Komptia (.afz.json).

Factorise les helpers qui étaient dans app.handlers.reports pour que iris,
datastore et reports partagent le même code de lecture des classeurs.
"""

from app.services.classeur.reader import (
    MAX_CLASSEUR_SIZE,
    extract_source_data,
    list_classeurs_sync,
    read_classeur,
    read_tab_data,
    rows_to_dicts,
)

__all__ = [
    "MAX_CLASSEUR_SIZE",
    "extract_source_data",
    "list_classeurs_sync",
    "read_classeur",
    "read_tab_data",
    "rows_to_dicts",
]
