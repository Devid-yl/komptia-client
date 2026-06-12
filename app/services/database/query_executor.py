"""
Service d'exécution de requêtes
Couche d'abstraction pour exécuter des requêtes sur Sage
"""

import re
import asyncio
from typing import Any, Dict, Optional, Tuple

try:
    import pyodbc
except ImportError:
    pyodbc = None  # type: ignore

from app.core import clock
from app.services.database.sage_connector import SageConnector, QueryResult, get_sage_connector
from app.utils.logger import get_logger
from app.utils.sql_scan import STRIP_COMMENTS_MAX_SQL_LEN
from app.core.exceptions import QueryError, ValidationError

logger = get_logger(__name__)


class QueryExecutor:
    """
    Service pour exécuter des requêtes SQL de manière sécurisée

    Features:
    - Validation des requêtes
    - Ajout automatique de TOP/LIMIT
    - Formatage des résultats
    - Logging et métriques
    """

    # Mots-clés SQL interdits (modifications)
    FORBIDDEN_KEYWORDS = [
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "TRUNCATE",
        "ALTER",
        "CREATE",
        "EXEC",
        "EXECUTE",
        "GRANT",
        "REVOKE",
        "DENY",
        "BACKUP",
        "RESTORE",
        "SHUTDOWN",
    ]

    # Tables système à exclure (regex word-boundary patterns)
    _SYSTEM_TABLE_RE = re.compile(
        r"\b(?:sys|INFORMATION_SCHEMA|master|tempdb|msdb)\.",
        re.IGNORECASE,
    )

    def __init__(self, connector: SageConnector = None):
        """
        Args:
            connector: Connecteur Sage **explicitement injecté** (tests,
                scripts ad-hoc). Si None, on relit dynamiquement le singleton
                global via ``get_sage_connector()`` à chaque accès — ce qui
                permet de respecter un ``switch_sage_mode()`` runtime
                (sqlserver ↔ sqlite) sans laisser le QueryExecutor pointer
                sur l'ancien connecteur.
        """
        self._connector_explicit = connector

    @property
    def connector(self) -> SageConnector:
        """Retourne le connecteur courant.

        Si un connecteur explicite a été injecté (tests), on le retourne tel
        quel. Sinon on relit le singleton global à chaque accès — pas de
        cache. Indispensable pour que le switch sqlserver→sqlite via
        ``switch_sage_mode`` soit immédiatement visible par les automations
        et autres consommateurs (cf. incident 2026-05-08 : auto crashait
        avec login_timeout SQL Server alors que mode sqlite actif, parce
        que le QueryExecutor avait cache l'ancien SageConnector).
        """
        if self._connector_explicit is not None:
            return self._connector_explicit
        return get_sage_connector()

    def validate_query(self, query: str) -> Tuple[bool, Optional[str]]:
        """
        Valide qu'une requête est sûre à exécuter

        Args:
            query: Requête SQL à valider

        Returns:
            (is_valid, error_message)
        """
        # Anti-DoS : reject les SQL > STRIP_COMMENTS_MAX_SQL_LEN char AVANT
        # tout strip/regex. Cap aligné sur strip_all_sql_comments (1 MB)
        # qui sert déjà de défense anti-DoS côté sage_connector — single
        # source of truth (axe 7 CLAUDE.md). Sans ce check, un attaquant
        # authentifié peut faire scanner O(n) plusieurs regex DOTALL sur
        # un SQL géant et bloquer un worker Tornado.
        if len(query) > STRIP_COMMENTS_MAX_SQL_LEN:
            return False, "Requête SQL trop volumineuse"

        # Retirer les commentaires SQL en début de requête (le LLM en ajoute souvent)
        cleaned = query.strip()
        while cleaned.startswith("--"):
            newline_pos = cleaned.find("\n")
            if newline_pos == -1:
                cleaned = ""
                break
            cleaned = cleaned[newline_pos + 1 :].strip()
        # Retirer aussi les commentaires bloc /* ... */
        while cleaned.startswith("/*"):
            end_pos = cleaned.find("*/")
            if end_pos == -1:
                cleaned = ""
                break
            cleaned = cleaned[end_pos + 2 :].strip()

        if not cleaned:
            return False, "Requête SQL vide"

        # Keyword scanning sur le SQL complet (y compris commentaires mid-query)
        # pour bloquer même les tentatives cachées dans des commentaires bloc.
        # Le startswith check utilise la version sans commentaires de tête.
        query_upper = query.upper()

        # Doit commencer par SELECT ou WITH (CTE)
        cleaned_upper = cleaned.upper()
        if not (cleaned_upper.startswith("SELECT") or cleaned_upper.startswith("WITH")):
            return False, "Seules les requêtes SELECT sont autorisées"

        # Rejet des requêtes multi-statement. FORBIDDEN_KEYWORDS ne couvre
        # ni WAITFOR (DoS worker), ni USE (context switch), ni SET (isolation
        # level → dirty reads), ni DECLARE (state injection), ni DBCC (admin
        # metadata) — donc `SELECT 1; <attaque>` passait. Strip strings/
        # commentaires/identifiers délimités (`[...]`) AVANT le scan pour
        # éviter les faux positifs sur un `;` inoffensif dans un string
        # literal ou un commentaire. La regex exige du non-whitespace après
        # le `;`, ce qui tolère le `;` terminal standard SQL.
        # Source : Finding 1779338000-01 (multi-statement bypass).
        query_for_semi = self._strip_sql_noise(query_upper)
        if re.search(r";\s*\S", query_for_semi):
            return False, "Une seule requête à la fois (multi-statement interdit)"

        # Vérifier les mots-clés interdits
        for keyword in self.FORBIDDEN_KEYWORDS:
            # Chercher le mot-clé comme mot complet avec limite de mots
            if re.search(rf"\b{keyword}\b", query_upper):
                return False, f"Mot-clé interdit: {keyword}"

        # Vérifier l'accès aux tables système (word-boundary regex, not substring)
        sys_match = self._SYSTEM_TABLE_RE.search(query)
        if sys_match:
            return False, f"Accès aux tables système interdit: {sys_match.group()}"

        # SELECT INTO check robuste — fix bypass (task #15, 2026-05-21) :
        # (1) Substring INSERT : l'ancien `'INSERT' not in query_upper` était
        #     court-circuité par les identifiants type 'INSERT_DATE' (colonne,
        #     alias) car _ est un word char → \bINSERT\b ne matche pas.
        # (2) Tokenization brute split() : `'INTO/*c*/NewTable'` produit le
        #     token 'INTO/*C*/NEWTABLE' → words.index('INTO') ValueError →
        #     bypass silencieux.
        # (3) Phase examine task #15 : la version initiale exigeait
        #     `.*?\bFROM\b` APRÈS le target → bypass trivial sur
        #     `SELECT 1 INTO #tmp`, `SELECT 1 INTO @var`,
        #     `SELECT 1 INTO ##global` (T-SQL : SELECT INTO crée une table
        #     temp / table-variable même sans clause FROM). On retire le
        #     `.*?\bFROM\b` final pour bloquer ces formes.
        # SQL Server ignore commentaires, string literals et identifiers
        # délimités (`[col]`) AVANT le parse, donc `_strip_sql_noise` les
        # neutralise. La regex word-bound sur SELECT…INTO {target} remplace
        # la tokenization fragile par un check unique.
        query_for_into = self._strip_sql_noise(query_upper)
        if re.search(
            r"\bSELECT\b.*?\bINTO\b\s+\S+",
            query_for_into,
            re.DOTALL,
        ):
            return False, "SELECT INTO n'est pas autorisé"

        return True, None

    def add_row_limit(self, query: str, max_rows: int) -> str:
        """
        Ajoute une limite de lignes si absente

        Pour les requêtes CTE (WITH ... SELECT), le TOP est ajouté
        sur le SELECT principal (hors CTE), pas sur le SELECT interne.

        Args:
            query: Requête SQL
            max_rows: Nombre max de lignes

        Returns:
            Requête avec TOP ajouté si nécessaire
        """
        # CRITIQUE : lstrip pour que les positions trouvées dans query_upper
        # correspondent aux positions dans query. Sans ça, un SQL qui commence
        # par "\n" (courant avec Claude) fait que find("SELECT") dans le strippé
        # renvoie 0, mais query[:6] inclut le "\n" et coupe le "T" de SELECT —
        # produit "\nSELEC TOP 1 T ..." (rejeté par SQL Server ET par le guard
        # SELECT du sage_connector en cascade).
        query = query.lstrip()
        query_upper = query.upper()

        # Si TOP est déjà présent (word boundary check — not substring),
        # ne pas modifier. Substring "TOP " matches inside DESKTOP, LAPTOP etc.
        if re.search(r"\bTOP\s*[\s(]", query_upper):
            return query

        # Pour les CTE (WITH ... AS (...) SELECT ...),
        # trouver le SELECT principal à profondeur 0 de parenthèses
        if query_upper.startswith("WITH"):
            select_pos = self._find_outer_select(query_upper)
        else:
            select_pos = query_upper.find("SELECT")

        if select_pos != -1:
            # Gérer SELECT DISTINCT
            after_select = query_upper[select_pos + 6 :].strip()
            if after_select.startswith("DISTINCT"):
                insert_pos = select_pos + 6 + query_upper[select_pos + 6 :].find("DISTINCT") + 8
            else:
                insert_pos = select_pos + 6

            # Insérer TOP (sur la requête originale, pas query_upper)
            query = query[:insert_pos] + f" TOP {max_rows} " + query[insert_pos:]

        return query

    @staticmethod
    def _strip_sql_noise(query_upper: str) -> str:
        """Strip string literals + commentaires bloc/ligne d'un SQL.

        SQL Server (et les autres moteurs) ignorent commentaires et strings
        AVANT le parse, ET les commentaires sont des séparateurs de tokens
        (`/*c*/` ≡ espace). Pour la détection SELECT…INTO…FROM côté Python,
        on doit donc reproduire ces deux invariants :

        1. Les strings sont **opaques** : un `/*` ou `--` qui apparaît dans
           un string literal n'est PAS un délimiteur de commentaire (bypass
           D/E review adversariale task #15). On strip les strings d'abord
           pour les neutraliser AVANT de scanner les commentaires.
        2. Les commentaires sont **remplacés par un espace**, pas supprimés :
           `INTO/*c*/NewTable` ≡ `INTO NewTable`, pas `INTONewTable`.
           Sinon la regex `\\bINTO\\b\\s+\\S+` rate la séparation des tokens.

        La regex string `'(?:[^']|'')*'` gère l'escape SQL standard `''`
        (apostrophe doublée). Pas de `"..."` (réservé aux identifiers
        SQL Server). Les strings non fermées (SQL malformé) ne matchent pas
        — le validator les voit telles quelles et le pattern INTO peut
        match ou non selon le contenu ; SQL Server rejettera le SQL avant
        exécution de toute façon.
        """
        # 1) Neutraliser les string literals (opaques pour le parser SQL).
        out = re.sub(r"'(?:[^']|'')*'", " '' ", query_upper)
        # 2) Strip block comments — remplacé par espace pour préserver les
        # frontières de tokens (sémantique SQL standard).
        out = re.sub(r"/\*.*?\*/", " ", out, flags=re.DOTALL)
        # 3) Strip line comments jusqu'à fin de ligne (idem espace).
        out = re.sub(r"--[^\n]*", " ", out)
        # 4) Strip T-SQL delimited identifiers `[col]` (et "col" si jamais).
        # SQL Server traite `[...]` comme un identifier opaque — son
        # contenu n'a aucune sémantique de mot-clé. Sans ce strip, un alias
        # comme `[Mode INTO Direct]` déclencherait un faux positif
        # SELECT INTO. (Phase examine task #15, 2026-05-21.)
        out = re.sub(r"\[[^\]]*\]", " '' ", out)
        return out

    @staticmethod
    def _find_outer_select(query_upper: str) -> int:
        """
        Trouve la position du SELECT principal (profondeur 0)
        dans une requête CTE.

        Parcourt le SQL en suivant la profondeur des parenthèses.
        Le SELECT principal est le premier SELECT trouvé à profondeur 0
        APRÈS le mot-clé WITH initial.
        """
        depth = 0
        i = 0
        length = len(query_upper)
        # Passer le mot WITH initial
        i = 4  # len("WITH")

        while i < length:
            ch = query_upper[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and query_upper[i : i + 6] == "SELECT":
                # Vérifier que c'est un mot complet (pas dans un identifiant)
                before_ok = i == 0 or not query_upper[i - 1].isalnum()
                after_ok = i + 6 >= length or not query_upper[i + 6].isalnum()
                if before_ok and after_ok:
                    return i
            i += 1

        # Fallback: premier SELECT trouvé
        return query_upper.find("SELECT")

    async def execute(
        self,
        query: str,
        params: Tuple[Any, ...] = None,
        max_rows: Optional[int] = None,
        add_limit: bool = True,
        timeout: Optional[int] = None,
        user: Any = None,
        *,
        rls_source: str = "query_executor",
        require_user: bool = False,
        cancel_event: Optional["asyncio.Event"] = None,
    ) -> QueryResult:
        """
        Exécute une requête SQL de manière sécurisée.

        Args:
            query: Requête SQL
            params: Paramètres (pour requêtes paramétrées)
            max_rows: Limite de lignes. ``None`` (défaut) = utiliser
                le cap admin configuré dans ``/admin/database``
                (``DatabaseConnection.max_rows``, propagé au connector).
                Un int explicite → le connector applique
                ``min(caller, admin)``. La doctrine Komptia : l'admin
                est l'UNIQUE source de vérité du plafond global ;
                hardcoder un cap caller ignore cette config et casse
                l'asymétrie /iris vs /datastore (incident 2026-05-20).
            add_limit: Ajouter TOP automatiquement
            timeout: Timeout d'exécution (wall-clock) en secondes. ``None``
                (défaut) = utiliser le timeout admin configuré dans
                ``/admin/database`` (``DatabaseConnection.timeout``, propagé
                au connector via ``_reload_sage_connector``). Un int explicite
                l'emporte (ex: pré-vol rapide qui doit échouer vite). Même
                doctrine "admin = UNIQUE source de vérité" que ``max_rows`` :
                hardcoder 30s ici ignorait silencieusement la config admin
                (incident dashboard 2026-06-08 : widget tué à 30s alors que
                l'admin avait configuré 120s).
            user: Utilisateur authentifié pour application RLS. Cas :
                - User réel → enforcement appliqué (filter+check) si ON
                - ``enforcer.SYSTEM_USER`` → bypass explicite (sync, jobs)
                - ``None`` → bypass legacy (logué WARNING si enforcement ON)
            rls_source: Étiquette pour log "qui appelle" (debug propagation
                manquante de user).
            require_user: Si ``True``, ``user=None`` lève
                ``DataAccessDeniedError`` au lieu du bypass legacy. Opt-in pour
                les sources user-facing (dashboards) où l'absence de user = un
                oubli de propagation (= fuite RLS), pas un appel système. Défaut
                ``False`` → comportement legacy inchangé pour scripts/sync.

        Returns:
            QueryResult avec les résultats

        Raises:
            ValidationError: Si la requête est invalide
            QueryError: Si l'exécution échoue
            DataAccessDeniedError: Si l'enforcement RLS refuse la requête
        """
        # Validation (always validate)
        is_valid, error = self.validate_query(query)
        if not is_valid:
            raise ValidationError(error)

        # ── Application RLS centralisée ──
        # Toute SQL exécutée par cet executor passe par l'enforcer. Couvre
        # les call-sites présents et futurs (saved queries, dashboards,
        # automations, tools agent…). Voir ``enforcer.enforce_for_executor``.
        try:
            from app.services.data_access import enforcer as _data_access_enforcer

            # Fail-closed opt-in : une source user-facing (dashboards) qui arrive
            # avec ``user=None`` = oubli de propagation du contexte → l'executor
            # ferait un bypass legacy de l'enforcement (données Sage NON filtrées).
            # On refuse explicitement. Les sources système/scripts gardent
            # ``require_user=False`` → comportement legacy inchangé.
            if require_user and user is None:
                raise _data_access_enforcer.DataAccessDeniedError(
                    f"Contexte utilisateur requis pour cette requête (source: {rls_source})."
                )

            query = await _data_access_enforcer.enforce_for_executor(query, user, source=rls_source)
        except _data_access_enforcer.DataAccessDeniedError:
            # Propager tel quel : le caller (handler/tool) doit la mapper
            # en réponse JSON / message utilisateur.
            raise

        # Résolution effective du cap : ``None`` → cap admin du connector.
        # Doctrine Komptia (David 2026-05-20) : l'admin est l'UNIQUE
        # source de vérité du plafond global. Pas de hard cap applicatif,
        # pas de fallback caché — si l'admin configure 10M, on respecte ;
        # s'il configure 0, on respecte aussi (et le résultat sera vide,
        # ce qui est sa décision). Aucun double cap, aucune "défense
        # en profondeur" qui masque la config admin.
        #
        # ``getattr`` défensif uniquement pour les tests mockant le
        # connector sans ``max_rows`` — retombe sur 10000 (le défaut de
        # ``DatabaseConnection.max_rows``, pas un cap applicatif).
        if max_rows is not None:
            effective_max_rows = max_rows
        elif hasattr(self.connector, "max_rows") and self.connector.max_rows is not None:
            effective_max_rows = self.connector.max_rows
        else:
            # Connector sans attribut (tests). Fallback aligné sur le défaut
            # de ``DatabaseConnection.max_rows`` (relevé 1000→10000 le
            # 2026-05-29). Ce n'est PAS un cap applicatif — l'admin reste
            # l'unique source de vérité via /admin/database.
            effective_max_rows = 10000

        # ── Résolution du timeout (MÊME doctrine "admin = source unique" que
        # ``max_rows`` ci-dessus). ``None`` (défaut) → timeout configuré par
        # l'admin sur ``/admin/database`` (``DatabaseConnection.timeout``,
        # propagé au connector via ``_reload_sage_connector``). S'il met 120s,
        # on attend 120s. Hardcoder 30s ici ignorait SILENCIEUSEMENT la config
        # admin — incident dashboard 2026-06-08 : le widget (et tous les autres
        # call-sites qui ne passent pas ``timeout``) était tué à 30s alors que
        # l'admin avait configuré 120s.
        #
        # ``isinstance(... > 0)`` défensif : connector mocké sans ``timeout``
        # (tests, ``getattr`` → None), valeur corrompue (0/négatif/non-numérique)
        # → fallback 30 (le défaut PARTAGÉ de ``SageConfig.timeout`` et
        # ``DatabaseConnection.timeout`` — borné 1..600 par check constraint BDD).
        # Ce n'est PAS un cap applicatif : un int admin valide est toujours
        # respecté tel quel. Un timeout 0/non-int passé à ``asyncio.wait_for``
        # planterait (échec instantané / TypeError) = donnée fausse silencieuse.
        if timeout is not None:
            effective_timeout = timeout
        else:
            _connector_timeout = getattr(self.connector, "timeout", None)
            # ``not isinstance(bool)`` : en Python ``isinstance(True, int)`` est
            # vrai → sans cette exclusion, un ``connector.timeout = True`` corrompu
            # passerait la garde et donnerait ``wait_for(timeout=True)`` = 1s
            # silencieux (la donnée fausse que la garde prétend justement écarter).
            effective_timeout = (
                _connector_timeout
                if isinstance(_connector_timeout, (int, float))
                and not isinstance(_connector_timeout, bool)
                and _connector_timeout > 0
                else 30
            )

        # Ajouter limite (TOP N) si demandé.
        if add_limit:
            query = self.add_row_limit(query, effective_max_rows)

        # Exécuter — on passe ``max_rows`` (peut être None) au connector
        # qui appliquera son propre ``min(caller, self.max_rows)``. Si
        # ``max_rows=None``, le connector utilise pleinement son admin cap.
        start_time = clock.now()

        try:
            # Task #9 (2026-05-22) — propage cancel_event au connector pour
            # qu'il puisse appeler cursor.cancel() (SQLCancel) côté Sage si
            # l'user clique Stop. Sans ce forward, le `asyncio.wait_for`
            # timeout fonctionne mais un cancel volontaire user ne propage
            # PAS vers le thread d'exec — pyodbc continue ses 30s+.
            #
            # **DETTE TECHNIQUE BLOCKING #1 adversarial session 18** :
            # le ``asyncio.wait_for(..., timeout=timeout)`` ci-dessous
            # cancel la coroutine ``connector.execute`` côté Python sur
            # timeout, MAIS le thread sous-jacent (``loop.run_in_executor``)
            # n'est PAS cancellable côté thread → cursor reste vivant,
            # connection occupée, sémaphore relâché à tort. Le cancel_event
            # côté user fonctionne (Stop UI), mais le timeout serveur fuit.
            # Fix futur : retirer asyncio.wait_for + utiliser cancel_event
            # interne au connector pour le timeout aussi (via asyncio.Event
            # + threading.Timer). Hors scope cette session (refactor étendu).
            result = await asyncio.wait_for(
                self.connector.execute(query, params, max_rows, cancel_event=cancel_event),
                timeout=effective_timeout,
            )

            total_time = (clock.now() - start_time).total_seconds() * 1000

            logger.info(
                "Query executed successfully",
                extra={
                    "rows": result.row_count,
                    "time_ms": total_time,
                    "query_preview": query[:100],
                },
            )

            return result

        except asyncio.TimeoutError:
            logger.error("Query timeout after %ds", effective_timeout, extra={"query": query[:200]})
            raise QueryError(f"Requête dépassée: timeout après {effective_timeout} secondes")
        except (pyodbc.Error, OSError, ConnectionError):
            logger.error("Query failed", extra={"query": query[:200]}, exc_info=True)
            raise

    async def execute_for_ai(
        self,
        query: str,
        max_rows: Optional[int] = None,
        user: Any = None,
        *,
        rls_source: str = "execute_for_ai",
    ) -> Dict[str, Any]:
        """
        Exécute une requête et formate pour l'IA.

        ``max_rows=None`` (défaut) : utilise le cap admin
        (``DatabaseConnection.max_rows``). Cf. :meth:`execute` pour la
        doctrine complète.

        ``user`` : voir :meth:`execute`. Idem sentinel ``SYSTEM_USER`` pour
        bypass système, ``None`` pour legacy.

        Retourne un dict avec:
        - success: bool
        - columns: liste des colonnes
        - data: liste de dicts
        - row_count: nombre de lignes
        - execution_time_ms: temps d'exécution
        - error: message d'erreur si échec
        """
        try:
            result = await self.execute(query, max_rows=max_rows, user=user, rls_source=rls_source)

            return {
                "success": True,
                "columns": result.columns,
                "data": result.to_dicts(),
                "row_count": result.row_count,
                "execution_time_ms": result.execution_time_ms,
                # A8-F1 — propager le flag AUTORITATIF du connector (basé sur le
                # cap EFFECTIF ``min(caller, DatabaseConnection.max_rows)``).
                # Sans ça, un caller (ex: datastore SQL execute) ne pouvait pas
                # savoir que le connector avait tronqué au cap admin → il croyait
                # voir TOUTES les lignes (données fausses silencieuses). Même
                # classe que A7-C6 (preview) / A3-F1 (export CSV).
                "truncated": bool(getattr(result, "truncated", False)),
                "error": None,
            }
        except ValidationError as e:
            return {
                "success": False,
                "columns": [],
                "data": [],
                "row_count": 0,
                "execution_time_ms": 0,
                "error": f"Validation: {str(e)}",
            }
        except QueryError as e:
            return {
                "success": False,
                "columns": [],
                "data": [],
                "row_count": 0,
                "execution_time_ms": 0,
                "error": f"Exécution: {str(e)}",
            }
        except Exception as exc:
            # Catch DataAccessDeniedError (sa hiérarchie : Exception) avant
            # le log « unexpected » : on veut un message explicite à l'IA.
            from app.services.data_access.enforcer import DataAccessDeniedError

            if isinstance(exc, DataAccessDeniedError):
                return {
                    "success": False,
                    "columns": [],
                    "data": [],
                    "row_count": 0,
                    "execution_time_ms": 0,
                    "error": exc.user_message,
                    "blocked_by": "data_access_rule",
                }
            # Log full exception for debugging.
            # P1.2 (audit 2026-05-26) : auparavant le message client était
            # « Erreur système inattendue. Contactez l'administrateur. » sans
            # ``str(exc)`` ; Iris (qui consomme ce dict via ``execute_sql`` /
            # datastore) ne pouvait pas auto-corriger faute de contexte.
            # Désormais on propage ``type(exc).__name__`` + ``str(exc)`` borné
            # à 500 chars. La sanitization PII / IP / noms internes reste la
            # responsabilité du caller (``sanitize_sql_server_error_message``
            # appliqué par ``app/handlers/datastore.py:2097`` côté admin et
            # par ``agent_tools._handle_execute_sql`` côté Iris).
            logger.error("execute_for_ai: unexpected error", exc_info=True)
            exc_detail = str(exc).strip()[:500] or type(exc).__name__
            return {
                "success": False,
                "columns": [],
                "data": [],
                "row_count": 0,
                "execution_time_ms": 0,
                "error": f"Erreur système ({type(exc).__name__}) : {exc_detail}",
            }


# Instance globale
_query_executor: Optional[QueryExecutor] = None


def get_query_executor() -> QueryExecutor:
    """Retourne l'instance globale du QueryExecutor"""
    global _query_executor
    if _query_executor is None:
        _query_executor = QueryExecutor()
    return _query_executor


# Export
__all__ = [
    "QueryExecutor",
    "get_query_executor",
]
