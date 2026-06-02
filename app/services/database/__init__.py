"""
Services de base de données
- sage_connector: Connexion SQL Server (base source)
- query_executor: Exécution sécurisée de requêtes

Note: L'import de sage_connector nécessite pyodbc et unixodbc.
      Si non disponibles, les fonctions Sage seront désactivées.
"""

# Import conditionnel pour éviter les erreurs si pyodbc n'est pas installé
try:
    from app.services.database.sage_connector import (  # noqa: F401
        SageConnector,
        QueryResult,
        get_sage_connector,
        close_sage_connector,
        sage_connection,
        _reset_sage_connector,
        init_sage_from_db_config,
        switch_sage_mode,
        get_current_sage_mode,
        PYODBC_AVAILABLE,
    )
    from app.services.database.query_executor import (  # noqa: F401
        QueryExecutor,
        get_query_executor,
    )

    __all__ = [
        "SageConnector",
        "QueryResult",
        "get_sage_connector",
        "close_sage_connector",
        "sage_connection",
        "_reset_sage_connector",
        "init_sage_from_db_config",
        "switch_sage_mode",
        "get_current_sage_mode",
        "QueryExecutor",
        "get_query_executor",
        "PYODBC_AVAILABLE",
    ]
except ImportError:
    # pyodbc non disponible - fonctions Sage désactivées
    PYODBC_AVAILABLE = False

    __all__ = ["PYODBC_AVAILABLE"]
