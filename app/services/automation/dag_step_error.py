"""Helper pour formater proprement les erreurs des steps DAG.

**P3.1 (audit 2026-05-26)** — Single source of truth pour transformer une
exception SQL (typiquement ``pyodbc.Error``, ``QueryError``, ``SageConnectionError``)
en chaîne courte et lisible stockée dans ``StepExecution.error_message``.

Avant ce helper, ``error_message=str(exc)`` posait ``str(pyodbc.Error)`` qui
donne ``"('42S22', '[Microsoft][ODBC Driver 17 for SQL Server][SQL Server]
Invalid column name CODE_TIERS (207) (SQLExecDirectW)')"`` — l'agrégation
``_aggregate_step_errors`` tronquait ce blob à 120 chars → l'UI affichait
``« step_X » : ('42S22', '[Microsoft][ODBC Driver 17 for SQL Server][SQL...``
sans révéler ni la colonne fautive ni le contexte.

Maintenant : ``[42S22] Invalid column name CODE_TIERS`` — court, actionnable,
préserve SQLSTATE pour le filtrage admin.
"""

from __future__ import annotations

import re
from typing import Optional


_PYODBC_SERVER_MSG_RE = re.compile(r"\[SQL Server\]\s*(.+?)(?:\s*\(\d+\))", re.DOTALL)
_PYODBC_SERVER_MSG_FALLBACK_RE = re.compile(r"\[SQL Server\]\s*(.+)", re.DOTALL)


def _extract_sql_server_message(raw: str) -> Optional[str]:
    """Extrait le message [SQL Server] depuis une chaîne ODBC verbeux.

    Les drivers ODBC chaînent souvent plusieurs préfixes :
    ``[Microsoft][ODBC Driver 17 for SQL Server][SQL Server]<message réel>``.
    Cette fonction garde uniquement le ``<message réel>``.
    """
    if not raw:
        return None
    matches = _PYODBC_SERVER_MSG_RE.findall(raw)
    if matches:
        cleaned = " | ".join(m.strip() for m in matches if m.strip())
        if cleaned:
            return cleaned
    fallback = _PYODBC_SERVER_MSG_FALLBACK_RE.search(raw)
    if fallback:
        # Retire les suffixes type "(SQLExecDirectW)" ou "(SQL...)".
        msg = re.sub(r"\s*\(SQL\w+\)\s*$", "", fallback.group(1)).strip()
        return msg or None
    return None


def format_step_error_message(exc: BaseException, *, max_len: int = 300) -> str:
    """Sérialise une exception step en chaîne courte ``"[SQLSTATE] message"``.

    Cas couverts :

    - **pyodbc.Error** (signature ``args=(sqlstate, raw)``) : ``"[42S22] Invalid
      column name 'CODE_TIERS'"`` (extrait propre).
    - **KomptiaError contenant déjà ``[SQLSTATE]``** (depuis P1.1 audit
      2026-05-26) : ``str(exc)`` propagé tel quel (déjà formaté correctement
      par ``sage_connector._format_pyodbc_error``).
    - **Autres exceptions** : ``f"{type(exc).__name__}: {str(exc)}"`` tronqué.

    Args:
        exc: l'exception step à formater.
        max_len: longueur maximale du message retourné (défaut 300).

    Returns:
        Chaîne courte stockable en BDD et lisible dans
        :func:`AutomationExecutor._aggregate_step_errors`.
    """
    if exc is None:
        return "erreur inconnue"

    raw = str(exc).strip()
    if not raw:
        return type(exc).__name__

    # Cas 1 : exception type pyodbc avec args=(sqlstate, message)
    args = getattr(exc, "args", None)
    if args and len(args) >= 2 and isinstance(args[0], str):
        candidate_state = args[0].upper()
        if re.match(r"^[A-Z0-9]{5}$", candidate_state):
            server_msg = _extract_sql_server_message(str(args[1]))
            if not server_msg:
                server_msg = str(args[1])[:max_len]
            formatted = f"[{candidate_state}] {server_msg}"
            return formatted[:max_len]

    # Cas 2 : str(exc) contient déjà ``[SQLSTATE] ...`` (P1.1 sage_connector)
    if re.search(r"\[[A-Z0-9]{5}\]", raw):
        return raw[:max_len]

    # Cas 3 : autres exceptions (RuntimeError, ValueError, etc.)
    type_name = type(exc).__name__
    if raw.startswith(type_name):
        return raw[:max_len]
    return f"{type_name}: {raw}"[:max_len]
