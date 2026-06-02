"""Messages d'erreur génériques pour le mode "invisible".

**Invariant fondamental** : en mode invisible, aucun message d'erreur retourné
à un utilisateur final ne doit révéler l'existence d'une table ou d'une
colonne à laquelle il n'a pas accès. Sinon la confidentialité fuit par le
canal "erreur" (l'utilisateur déduit qu'un objet existe parce qu'on lui
dit qu'il "n'a pas accès" plutôt que "n'existe pas").

**Stratégie** : tous les messages sont **ambigus volontairement** —
"n'existe pas OU vous n'y avez pas accès". L'utilisateur ne peut pas
distinguer les deux cas, donc ne peut rien déduire.

**Exception admin** : si le toggle ``verbose_errors_for_admin`` est actif
(par défaut OFF en prod), un admin reçoit le message verbeux avec le nom
réel pour pouvoir débugger. Le toggle n'est jamais exposé aux non-admins.

**Note** : les logs serveur internes (``logger.warning``, etc.) restent
verbeux avec les vrais noms — c'est intentionnel pour l'opérateur, et
ces logs ne sont jamais retournés au user final.

Voir :mod:`app.services.data_access.enforcer` pour les call-sites qui
utilisent ces messages.
"""

from __future__ import annotations

import enum
import re
from typing import Any, Literal, Optional, TypedDict


class GenericMessageKind(enum.Enum):
    """Catégories de refus pour lesquelles on a un template générique.

    Le call-site choisit la catégorie ; ce module garantit qu'aucun
    nom métier ne s'échappera. Si une nouvelle catégorie est nécessaire,
    l'ajouter ici plutôt que de construire un message ad-hoc côté caller.
    """

    #: Table référencée pas dans la vue visible
    TABLE_NOT_VISIBLE = "table_not_visible"
    #: Colonne référencée pas dans la vue visible
    COLUMN_NOT_VISIBLE = "column_not_visible"
    #: SELECT * sur table avec column-deny actif
    WILDCARD_BLOCKED = "wildcard_blocked"
    #: User non authentifié dans un path qui le requiert
    AUTH_REQUIRED = "auth_required"
    #: SQL non parsable + règles d'accès actives → fail-closed
    UNPARSEABLE_SQL = "unparseable_sql"
    #: Échec interne d'application des row filters → fail-closed
    ROW_FILTER_FAILURE = "row_filter_failure"
    #: Erreur SQL Server "Invalid object/column name" — re-sanitizée
    #: avant remontée au user/LLM pour ne pas révéler le nom métier
    #: que SQL Server avait mis dans le message d'erreur.
    SQL_INVALID_NAME = "sql_invalid_name"


#: Templates fixes. **NE JAMAIS** y insérer un nom de table/colonne via
#: format string — cela briserait l'invariant invisible. Si le besoin
#: existe, créer un nouveau ``GenericMessageKind`` avec un template
#: générique adapté.
_GENERIC_TEMPLATES: dict[GenericMessageKind, str] = {
    GenericMessageKind.TABLE_NOT_VISIBLE: (
        "L'objet demandé n'existe pas ou vous n'y avez pas accès. "
        "Vérifiez l'orthographe ou contactez votre administrateur."
    ),
    GenericMessageKind.COLUMN_NOT_VISIBLE: (
        "Un champ demandé n'existe pas ou vous n'y avez pas accès. "
        "Vérifiez l'orthographe ou contactez votre administrateur."
    ),
    GenericMessageKind.WILDCARD_BLOCKED: (
        "L'usage de `SELECT *` n'est pas autorisé sur cette requête. "
        "Listez explicitement les champs que vous souhaitez consulter."
    ),
    GenericMessageKind.AUTH_REQUIRED: ("Authentification requise pour exécuter cette requête."),
    GenericMessageKind.UNPARSEABLE_SQL: (
        "Cette requête n'a pas pu être analysée pour vérifier vos droits "
        "d'accès. Reformulez-la ou contactez votre administrateur."
    ),
    GenericMessageKind.ROW_FILTER_FAILURE: (
        "Une erreur interne a empêché l'application de vos droits d'accès "
        "à cette requête. Contactez votre administrateur."
    ),
    GenericMessageKind.SQL_INVALID_NAME: (
        "La requête fait référence à un objet ou un champ qui n'existe pas "
        "ou auquel vous n'avez pas accès. Vérifiez l'orthographe ou "
        "contactez votre administrateur."
    ),
}


#: Patterns SQL Server (EN + FR) typiques pour les erreurs "Invalid name".
#: Quand un de ces patterns matche un message d'erreur, on sanitize la
#: chaîne entière avant remontée au user/LLM si l'user a des restrictions
#: actives — sinon SQL Server révélerait le nom métier dans la string
#: ``Invalid object name 'F_SALAIRES'``.
_SQL_INVALID_NAME_RE = re.compile(
    r"Invalid\s+(?:object|column)\s+name"
    r"|Le\s+nom\s+d'?objet\s+'[^']+'\s+n'est\s+pas\s+valide"
    r"|Nom\s+de\s+colonne\s+'[^']+'\s+non\s+valide",
    re.IGNORECASE,
)


async def sanitize_sql_server_error_message(
    error_msg: str,
    user: Any,
) -> str:
    """Sanitize un message d'erreur SQL Server pour respecter le mode invisible.

    SQL Server renvoie des messages du type ``Invalid object name 'F_SECRET'``
    qui contiennent le **vrai nom** de l'objet inexistant ou non accessible.
    Si l'user a des règles ``deny`` actives, ce message **leak** : il révèle
    à l'user (et au LLM qui peut le voir) que ``F_SECRET`` existe peut-être.

    **Comportement** :

    - Si ``error_msg`` ne matche pas un pattern "Invalid name" → retourné
      tel quel (l'erreur n'est pas un canal de fuite).
    - Si user n'a pas de restrictions (admin, enforcement off, no rules) →
      retourné tel quel.
    - Sinon → remplacé entièrement par le message générique
      :attr:`GenericMessageKind.SQL_INVALID_NAME`.

    L'approche "remplacement total" est conservative (potentiellement
    aggressive sur les vrais typos), mais c'est la seule sûre :
    une substitution partielle pourrait laisser fuiter d'autres
    informations en place. Le caller logue le message original côté
    serveur pour debug admin.

    Args:
        error_msg: message brut remonté par pyodbc / SQL Server.
        user: l'utilisateur courant (objet User ou ``None``).

    Returns:
        Message d'erreur soit inchangé, soit sanitizé.
    """
    if not error_msg or not isinstance(error_msg, str):
        return error_msg or ""

    if not _SQL_INVALID_NAME_RE.search(error_msg):
        return error_msg  # Pas un pattern à risque, laisse passer.

    # Si user None → on est dans un path système. On laisse passer
    # (les logs admin verront le vrai message).
    if user is None:
        return error_msg

    # Import lazy pour éviter circular dep (error_messages est consommé
    # par visible_schema indirectement).
    try:
        from app.services.data_access.visible_schema import (
            build_user_schema_view,
        )

        view = await build_user_schema_view(user)
    except Exception:
        # Si on n'arrive pas à construire la vue, fail-closed sur le
        # sanitize : on remplace par générique plutôt que de laisser
        # passer.
        return _GENERIC_TEMPLATES[GenericMessageKind.SQL_INVALID_NAME]

    if not view.has_restrictions:
        return error_msg

    return _GENERIC_TEMPLATES[GenericMessageKind.SQL_INVALID_NAME]


# ---------------------------------------------------------------------------
# Phase 3.3 — garde-fou runtime pré-envoi LLM
# ---------------------------------------------------------------------------


class InvisibleLeakError(Exception):
    """Levée par :func:`assert_safe_llm_prompt` quand un nom interdit
    est détecté dans un prompt sur le point d'être envoyé à un LLM.

    Ne devrait JAMAIS être levée si les filtrages amont (Phase 4.x et 5.x)
    sont correctement branchés — c'est le dernier filet de sécurité.
    Quand elle se déclenche : log CRITICAL côté serveur + abort de l'appel
    LLM. Le caller décide quoi répondre à l'user (typiquement message
    générique via :func:`make_generic_message`).
    """


async def assert_safe_llm_prompt(
    prompt_text: str,
    user: Any,
    *,
    context_label: str = "llm_call",
) -> None:
    """Scanne un prompt LLM avant envoi pour détecter une fuite invisible.

    **Usage** : à appeler par les call-sites LLM critiques juste avant
    ``call_llm(...)``. Si l'invariant invisible est respecté en amont,
    cette fonction ne lève jamais. Si elle lève, il y a un bug dans le
    filtrage amont (Phase 4.x / 5.x).

    **Stratégie** :

    - Si user est ``None`` / admin / pas de restrictions → no-op
      (rien à protéger)
    - Sinon : scanne le prompt pour les noms de tables interdites de
      l'user. Si match → lève :class:`InvisibleLeakError` + log CRITICAL.

    **Limites** :

    - Le scan se fait sur ``visible_tables`` (l'union connue) — les
      tables hors inventaire ne sont pas surveillées. C'est cohérent
      avec le reste de l'architecture (fail-closed via parse).
    - Le scan ne couvre PAS les colonnes denied : il faudrait connaître
      l'union des noms de colonnes interdites, ce qui n'est pas
      matérialisé V0. Affiné Phase 6 si nécessaire.

    Args:
        prompt_text: le texte du prompt (system + user concaténés).
        user: l'utilisateur courant.
        context_label: identifiant du call-site pour les logs (ex:
            "iris_one_shot", "result_assistant_modify").

    Raises:
        InvisibleLeakError: si un nom de table interdite apparaît dans
            le prompt.
    """
    if not prompt_text or not isinstance(prompt_text, str):
        return
    if user is None:
        return  # path système, pas concerné

    # **#112 fail-safe partiel** : try-each indépendant. Si view crash
    # mais rules OK → check sur rules atomiques (sans closure). Si rules
    # crash mais view OK → check sur closure. Les 2 KO → return (legacy).
    view = None
    rules = None
    try:
        from app.services.data_access.visible_schema import (
            build_user_schema_view,
        )

        view = await build_user_schema_view(user)
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "assert_safe_llm_prompt[%s]: build_user_schema_view failed "
            "— fallback sur rules.denied_tables (closure dégradée)",
            context_label,
        )

    # Court-circuit : view chargée + no restrictions → bypass.
    if view is not None and not view.has_restrictions:
        return

    try:
        from app.services.data_access.enforcer import load_rules_for_user

        rules = await load_rules_for_user(user.id)
    except Exception:
        import logging

        logging.getLogger(__name__).warning(
            "assert_safe_llm_prompt[%s]: load_rules_for_user failed "
            "— fallback sur view.denied_tables_with_closure",
            context_label,
        )

    # Construire denied_names à partir de ce qui a réussi.
    denied_atomic = frozenset(rules.denied_tables) if rules is not None else frozenset()
    denied_closure = frozenset(view.denied_tables_with_closure) if view is not None else frozenset()
    denied_names = denied_atomic | denied_closure
    if not denied_names:
        return  # rien à surveiller (ou les 2 lookups ont fail)

    if contains_protected_name(prompt_text, denied_tables=denied_names):
        import logging

        logger = logging.getLogger(__name__)
        # Log CRITICAL côté serveur — c'est un VRAI bug, il faut une alerte.
        logger.critical(
            "INVISIBLE LEAK DETECTED [%s] user=%s prompt contient un nom "
            "denied. Filtrage Phase 4.x/5.x à investiguer. Abort du call LLM.",
            context_label,
            getattr(user, "id", "?"),
        )
        raise InvisibleLeakError(
            f"Prompt LLM contient un nom de table interdite pour user "
            f"#{getattr(user, 'id', '?')}. Filtrage amont défaillant."
        )


def make_generic_message(
    kind: GenericMessageKind,
    *,
    verbose_blocking_table: Optional[str] = None,
    verbose_blocking_column: Optional[str] = None,
    verbose_for_admin: bool = False,
) -> str:
    """Retourne un message d'erreur générique sûr pour l'invariant invisible.

    Le message par défaut **ne mentionne aucun nom** de table/colonne
    métier. Il est volontairement ambigu pour empêcher l'utilisateur de
    déduire l'existence d'un objet.

    Args:
        kind: catégorie de refus (voir :class:`GenericMessageKind`).
        verbose_blocking_table: nom réel de la table qui a bloqué — utilisé
            **uniquement** si ``verbose_for_admin`` est True.
        verbose_blocking_column: nom réel de la colonne — idem.
        verbose_for_admin: si True ET que le caller a vérifié que le
            destinataire est admin, retourne un message verbeux avec les
            vrais noms pour faciliter le debug. **Le caller est
            responsable** de la vérification ``user.is_admin`` —
            ce module ne le fait pas.

    Returns:
        Message UTF-8 en français, prêt à mettre dans une réponse JSON
        ou un message LLM.

    **Anti-patterns à éviter** :

    - Concaténer le nom de table au message générique côté caller —
      reviendrait à briser l'invariant.
    - Logger le message générique côté serveur — préférer logger le
      message verbeux (vrai nom) pour l'opérateur.
    """
    template = _GENERIC_TEMPLATES.get(kind)
    if template is None:
        # Catégorie inconnue : fallback ultra-générique, fail-safe.
        return "L'accès à cette ressource est restreint. Contactez votre " "administrateur."

    if verbose_for_admin and (verbose_blocking_table or verbose_blocking_column):
        # Mode debug admin : on accole les vrais noms entre crochets après
        # le template. Le format ``[debug: table=X, column=Y]`` est facile
        # à grep côté ops et clairement marqué comme info admin-only.
        parts = []
        if verbose_blocking_table:
            parts.append(f"table={verbose_blocking_table}")
        if verbose_blocking_column:
            parts.append(f"column={verbose_blocking_column}")
        return f"{template} [debug admin: {', '.join(parts)}]"

    return template


#: Placeholder utilisé par :func:`scrub_text_for_user` pour remplacer un
#: nom interdit. Choisi pour être visuellement distinct (les `[…]` indiquent
#: clairement qu'un contenu a été masqué) sans révéler la nature du contenu.
_SCRUB_PLACEHOLDER: str = "[…]"


async def scrub_text_for_user(
    text: str,
    user: Any,
    *,
    context_label: str = "conversation_history",
) -> str:
    """**Phase 2.5.quater (#97)** — Scrubbe un texte pour retirer les noms
    de tables/colonnes interdites pour ``user``.

    **Usage principal** : filtrage de l'historique conversationnel à
    chaque chargement (``agent_service._load_conversation_history``). Si
    l'admin a posé un ``deny F_SALAIRES`` AUJOURD'HUI alors que l'user
    a fait des queries SUR ``F_SALAIRES`` la semaine dernière, les
    anciens messages assistant contiennent encore le nom. Sans cette
    fonction, le LLM les voit dans le contexte et peut les re-mentionner
    dans ses réponses → leak du nom alors qu'il devrait être invisible.

    **Stratégie** :

    - User None / admin / sans restrictions → retourne ``text`` inchangé
      (no-op rapide, pas d'allocation).
    - Sinon : pour chaque nom denied de l'user, remplace toutes les
      occurrences (case-insensitive, word boundary) par
      :data:`_SCRUB_PLACEHOLDER`.
    - Log INFO avec ``context_label`` + nombre de remplacements si match
      (pour audit ; le nom réel reste côté serveur, pas dans le log
      user-facing).

    **Fail-safe** : si le chargement de view ou rules échoue, retourne
    le texte inchangé + log WARNING. C'est moins safe qu'un fail-closed
    mais préserve la conversation user (mieux qu'un texte vide).

    Args:
        text: texte à scrubber (peut être vide).
        user: utilisateur courant (objet ou stub avec ``id``/``role``).
        context_label: identifiant du caller pour les logs.

    Returns:
        Texte scrubé, ou texte original si rien à scrubber / erreur.

    **Différence avec `contains_protected_name`** : detect → retourne
    bool ; scrub → retourne texte modifié + log. Utilisation
    complémentaire.

    **Limitation V1** : ne scrubbe QUE les ``denied_tables``. Les
    ``denied_columns`` n'apparaissent pas seules dans l'historique
    typique (le LLM utilise ``table.col``). Affinable Phase 6 si
    nécessaire.
    """
    if not text or not isinstance(text, str):
        return text or ""
    if user is None:
        return text

    # **Phase 2.5.bis.bis follow-up (#112)** — Fail-safe partiel.
    # Avant : si view OU rules crash → return text sans scrub (bypass
    # silencieux complet). Risque : si la BDD a un hoquet temporaire,
    # on désactive TOUT le scrub mode invisible → leak silencieux.
    #
    # Maintenant : try-each indépendant. Si view crash mais rules OK,
    # on scrub sur ``rules.denied_tables`` (sans closure). Si rules
    # crash mais view OK, on scrub sur ``view.denied_tables_with_closure``.
    # Les 2 crashs → return text (comportement legacy de dernier recours).
    view = None
    rules = None
    import logging as _logging

    _logger = _logging.getLogger(__name__)

    try:
        from app.services.data_access.visible_schema import (
            build_user_schema_view,
        )

        view = await build_user_schema_view(user)
    except Exception:
        _logger.warning(
            "scrub_text_for_user[%s]: build_user_schema_view failed "
            "— fallback sur rules.denied_tables (closure dégradée)",
            context_label,
        )

    # Court-circuit ADMIN / enforcement off / no rules : uniquement si
    # view chargée ET sans restrictions. Sinon on tente quand même rules.
    if view is not None and not view.has_restrictions:
        return text

    try:
        from app.services.data_access.enforcer import load_rules_for_user

        rules = await load_rules_for_user(user.id)
    except Exception:
        _logger.warning(
            "scrub_text_for_user[%s]: load_rules_for_user failed "
            "— fallback sur view.denied_tables_with_closure",
            context_label,
        )

    # **#112 fail-safe partiel** : construit denied_names à partir de
    # ce qui a réussi. Si les 2 lookups ont échoué → frozenset vide
    # (équivalent à return text).
    denied_atomic = frozenset(rules.denied_tables) if rules is not None else frozenset()
    denied_closure = frozenset(view.denied_tables_with_closure) if view is not None else frozenset()
    denied_names = list(denied_atomic | denied_closure)

    if not denied_names:
        return text  # rien à scrubber (ou les 2 lookups ont fail)

    # Tri par longueur décroissante pour éviter qu'un nom court ``F_X`` ne
    # scrub UN PRÉFIXE de ``F_XSALAIRES`` avant qu'on ait scrub ce dernier.
    # Avec word boundary `\b`, cette pathologie est limitée mais le tri
    # ajoute robustesse à coût zéro.
    sorted_names = sorted(denied_names, key=len, reverse=True)

    scrubbed = text
    total_replacements = 0
    for name in sorted_names:
        if not name:
            continue
        # `\b` = word boundary (avant + après le nom). `re.escape` pour
        # protéger contre les caractères regex spéciaux dans les noms
        # (typiquement zéro mais defense-in-depth). `re.IGNORECASE` car
        # SQL Server est case-insensitive sur les identifiants.
        pattern = r"\b" + re.escape(name) + r"\b"
        new_scrubbed, n_replaced = re.subn(
            pattern, _SCRUB_PLACEHOLDER, scrubbed, flags=re.IGNORECASE
        )
        if n_replaced > 0:
            scrubbed = new_scrubbed
            total_replacements += n_replaced

    if total_replacements > 0:
        import logging

        logging.getLogger(__name__).info(
            "scrub_text_for_user[%s]: %d remplacement(s) effectué(s) pour "
            "user_id=%s (mode invisible historique)",
            context_label,
            total_replacements,
            getattr(user, "id", "?"),
        )

    return scrubbed


class DataAccessLeakDetectedError(Exception):
    """**Phase 2.5.bis.bis fix BLOCKING #1 review** — Levée quand un
    output LLM (SQL généré, JSON structuré, etc.) contient un nom de
    table/colonne denied.

    **Différence avec :class:`InvisibleLeakError`** :

    - :class:`InvisibleLeakError` = leak détecté **côté prompt entrée**
      (bug de filtrage amont, codé en dur côté serveur).
    - :class:`DataAccessLeakDetectedError` = leak détecté **côté output
      LLM** (hallucination du LLM ; ce n'est PAS un bug code, c'est le
      LLM qui produit un nom plausible qui se trouve être denied).

    **Propagation attendue** : les callers user-facing (copilot bridge,
    handlers HTTP) catchent cette exception et propagent
    ``blocked_by="data_access_rule"`` au consumer, déclenchant ainsi
    le comportement ``DATA_ACCESS_GUIDANCE`` côté prompt copilot
    (pas de retry, suggestion contact admin, etc.).

    Attributs :
        user_message : message générique mode-invisible adapté à
            l'utilisateur final (sans révéler le nom détecté).
    """

    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


async def assert_safe_llm_response(
    response_text: str,
    user: Any,
    *,
    context_label: str = "llm_response_output",
    strict_when_no_user: bool = False,
) -> Optional[str]:
    """**Phase 2.5.bis.bis (#102)** — Variante de :func:`scrub_text_for_user`
    pour les cas où **un scrub partiel casserait la sémantique** du texte
    (SQL hallucié, JSON structuré, etc.).

    Au lieu de remplacer le nom denied par ``[…]`` (ce qui produirait
    un SQL invalide ou un JSON mal formé), cette fonction **détecte** la
    présence et **retourne un message d'erreur générique** pour le caller
    qui décide de fail-closed (refuser l'output, demander reformulation).

    **Usage typique** : ``iris_oneshot.transform_sql_via_llm`` qui ne
    peut pas retourner un SQL scrubé partiellement (casserait l'exec ET
    l'affichage drilldown).

    **Différence avec `assert_safe_llm_prompt`** :

    - ``assert_safe_llm_prompt`` est pour les **PROMPTS d'entrée** au LLM
      (vérifier que le filtrage amont a marché). Lève
      :class:`InvisibleLeakError` si fuite (cas BUG côté serveur).
    - ``assert_safe_llm_response`` est pour les **RÉPONSES de sortie** du
      LLM (vérifier que le LLM n'a pas halluciné un nom denied). Retourne
      un message d'erreur générique au lieu de raise (cas LLM normal,
      pas un bug du code).

    **Différence avec `scrub_text_for_user`** :

    - ``scrub_text_for_user`` REMPLACE le nom par ``[…]`` (OK pour
      narratifs, KO pour SQL/JSON structurés).
    - ``assert_safe_llm_response`` DÉTECTE et retourne un message (OK
      pour fail-closed sur structures fragiles).

    Args:
        response_text: la réponse LLM à vérifier.
        user: utilisateur courant.
        context_label: identifiant du caller pour les logs.

    Returns:
        ``None`` si la réponse est sûre (peut être retournée au caller).
        Une string de message d'erreur générique si une fuite est
        détectée (caller doit fail-closed).

    **Fail-safe** : si l'enforcement check échoue (BDD down, etc.),
    retourne ``None`` (laisse passer) avec log WARNING — préférer
    ne pas casser un flow par un check qui ne peut pas vérifier.
    """
    if not response_text or not isinstance(response_text, str):
        return None
    if user is None:
        # **Phase 2.5.bis.bis follow-up (#113) — fail-closed sur user=None
        # en contexte user-facing.** Sans cette option, un bug de
        # propagation (caller user-facing qui oublie de passer ``user=``)
        # passait silencieusement → leak potentiel. Les callers
        # user-facing connus (iris_oneshot, vanna, copilot_agent,
        # result_assistant._call_llm_anon, widget_planner._llm_common,
        # report_analyzer, report_planner) passent désormais
        # ``strict_when_no_user=True`` → on retourne le message générique
        # qui force le caller à raise DataAccessLeakDetectedError.
        if strict_when_no_user:
            import logging

            logging.getLogger(__name__).warning(
                "assert_safe_llm_response[%s]: user=None en contexte "
                "user-facing strict → fail-closed (bug de propagation user= "
                "côté caller à investiguer)",
                context_label,
            )
            return (
                "Erreur interne : contexte utilisateur manquant pour "
                "le contrôle d'accès aux données. Réessayez après "
                "rafraîchissement, ou contactez votre administrateur."
            )
        return None

    try:
        from app.services.data_access.visible_schema import (
            build_user_schema_view,
        )

        view = await build_user_schema_view(user)
    except Exception:
        # **#112 fail-safe partiel** : view crash → fallback sur rules
        # uniquement (sans closure transitive). Avant : return None
        # bypass complet.
        import logging

        logging.getLogger(__name__).warning(
            "assert_safe_llm_response[%s]: build_user_schema_view failed "
            "— fallback sur rules.denied_tables (closure dégradée)",
            context_label,
        )
        view = None

    # Court-circuit court ADMIN / enforcement off / no rules : uniquement
    # si view chargée ET sans restrictions. Sinon on tente quand même rules.
    if view is not None and not view.has_restrictions:
        return None

    rules = None
    try:
        from app.services.data_access.enforcer import load_rules_for_user

        # **Phase 2.5.bis.bis follow-up (#114) — Investigation conclue.**
        # L'union ``rules.denied_tables ∪ view.denied_tables_with_closure``
        # n'est PAS un doublon sémantique : c'est une **protection
        # defense-in-depth** contre la fenêtre de désync cache 60s.
        rules = await load_rules_for_user(user.id)
    except Exception:
        # **#112** : rules crash → fallback sur view uniquement (closure).
        import logging

        logging.getLogger(__name__).warning(
            "assert_safe_llm_response[%s]: load_rules_for_user failed "
            "— fallback sur view.denied_tables_with_closure",
            context_label,
        )

    # **#112 fail-safe partiel** : construit denied_names à partir de
    # ce qui a réussi. Les 2 lookups KO → return None (legacy).
    denied_atomic = frozenset(rules.denied_tables) if rules is not None else frozenset()
    denied_closure = frozenset(view.denied_tables_with_closure) if view is not None else frozenset()
    denied_names = denied_atomic | denied_closure
    if not denied_names:
        return None

    if not denied_names:
        return None

    if contains_protected_name(response_text, denied_tables=denied_names):
        import logging

        logger = logging.getLogger(__name__)
        # Log CRITICAL côté serveur — c'est soit une hallucination
        # (rare mais à monitorer), soit un bug de filtrage amont.
        logger.critical(
            "INVISIBLE LEAK in LLM response [%s] user=%s — output contient "
            "un nom denied. Fail-closed activé.",
            context_label,
            getattr(user, "id", "?"),
        )
        return (
            "Cette opération s'appuie sur des données auxquelles vous "
            "n'avez pas accès avec votre profil actuel. Contactez votre "
            "administrateur Komptia si vous pensez devoir y avoir accès, "
            "ou reformulez votre demande différemment."
        )

    return None


async def assert_safe_llm_blocks(
    content_blocks: list,
    user: Any,
    *,
    restore_fn: Optional[Any] = None,
    context_label: str = "llm_blocks",
    strict_when_no_user: bool = False,
) -> Optional[str]:
    """**Phase 2.5.bis.6 follow-up (#116)** — Helper réutilisable pour
    le check fail-closed sur une liste de ``content_blocks`` Anthropic
    (``[{type: text|thinking|tool_use, ...}]``).

    Refactor pur — consolide le pattern dupliqué dans 3 modules :
    ``copilot_agent.run_copilot_agent``,
    ``report_planner_agent.run_report_agent``,
    ``widget_planner_agent.run_widget_planner_agent``.

    Le helper fait :

    1. Concat des blocks ``text`` et ``thinking`` en une string.
    2. Concat des blocks ``tool_use.input`` via ``json.dumps`` (fix
       CRITIQUE adversarial #106 — un LLM peut halluciner un nom denied
       dans les arguments d'un tool, pas seulement dans un text block).
    3. Restore PII/pseudo via ``restore_fn`` si fourni (sinon scan
       direct sur le raw).
    4. Appel à :func:`assert_safe_llm_response` qui retourne :
       - ``None`` si OK
       - Une string générique si leak détecté

    Args:
        content_blocks: liste de blocks Anthropic
            (``[{type, text|input, ...}]``).
        user: utilisateur courant (``None`` pour contextes système).
        restore_fn: callable optionnel ``(str) -> str`` ou ``(Any) -> Any``
            qui dé-anonymise le content. Si crash, fallback sur le raw
            avec log WARNING.
        context_label: identifiant du caller pour les logs.
        strict_when_no_user: si ``True``, ``user=None`` retourne un
            message d'erreur (defense-in-depth #113).

    Returns:
        ``None`` si la liste est sûre. Une string générique si leak
        détecté (le caller doit raise ``DataAccessLeakDetectedError``).
    """
    if not content_blocks:
        return None

    # 1. Concat des blocks text + thinking.
    try:
        text_concat = "\n".join(
            b.get("text", "")
            for b in content_blocks
            if isinstance(b, dict)
            and b.get("type") in ("text", "thinking")
            and isinstance(b.get("text"), str)
        )
    except Exception:  # noqa: BLE001 — defensive (content malformé)
        text_concat = ""

    # 2. Concat des blocks tool_use.input via json.dumps.
    try:
        import json as _json

        tool_use_concat = "\n".join(
            _json.dumps(b.get("input"), ensure_ascii=False, default=str)
            for b in content_blocks
            if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("input") is not None
        )
        if tool_use_concat:
            text_concat = (text_concat + "\n" + tool_use_concat) if text_concat else tool_use_concat
    except Exception:  # noqa: BLE001
        pass

    if not text_concat:
        return None

    # 3. Restore PII/pseudo si fourni.
    if restore_fn is not None:
        try:
            cleartext_for_check = restore_fn(text_concat)
            if not isinstance(cleartext_for_check, str):
                cleartext_for_check = text_concat
        except Exception:  # noqa: BLE001
            import logging

            logging.getLogger(__name__).warning(
                "assert_safe_llm_blocks[%s]: restore_fn a crashé — "
                "check tourne sur pseudos (potential miss)",
                context_label,
                exc_info=True,
            )
            cleartext_for_check = text_concat
    else:
        cleartext_for_check = text_concat

    # 4. Appel à assert_safe_llm_response (qui handle user=None + strict).
    return await assert_safe_llm_response(
        cleartext_for_check,
        user,
        context_label=context_label,
        strict_when_no_user=strict_when_no_user,
    )


async def scrub_llm_blocks_for_user(
    content_blocks: list,
    user: Any,
    *,
    context_label: str = "llm_response",
) -> list:
    """**Phase 2.5.bis (#95)** — Scrubbe les noms denied dans une liste
    de ``content_blocks`` au format Anthropic Messages API.

    **Usage** : à appeler juste avant de renvoyer la réponse LLM au
    consumer (websocket, persistance BDD, tool result, etc.). Filet
    déterministe contre l'**hallucination** : un LLM qui invente un nom
    plausible (`F_SALAIRES`, `F_PERSONNEL`, etc.) qui se trouve être
    denied pour cet user → leak via la réponse.

    Format attendu de ``content_blocks`` (Anthropic) :

    .. code-block:: python

        [
            {"type": "text", "text": "..."},
            {"type": "tool_use", "id": "...", "name": "...", "input": {...}},
            {"type": "thinking", "thinking": "..."},  # extended thinking
        ]

    Seuls les ``text`` et ``thinking`` blocks sont scrubés. Les
    ``tool_use`` ne sont PAS touchés (leur ``input`` peut contenir des
    SQL valides côté serveur — c'est l'enforcer RLS qui filtre à
    l'exécution, pas ce scrub).

    **Différence avec `scrub_text_for_user`** : ce wrapper structure-aware
    parcourt la liste de blocks. La fonction texte (`scrub_text_for_user`)
    fait le vrai travail sur le contenu.

    **Fail-safe** : si la liste est mal formée ou si le scrub texte
    lève, retourne ``content_blocks`` inchangée + log WARNING.

    Args:
        content_blocks: liste de dicts au format Anthropic.
        user: utilisateur courant (objet avec ``id``/``role``).
        context_label: identifiant du caller pour les logs.

    Returns:
        Liste de dicts, structurellement identique, avec les textes
        scrubés. Mutation **non-destructive** : on copie les dicts modifiés
        pour ne pas muter le cache caller.
    """
    if not content_blocks or not isinstance(content_blocks, list):
        return content_blocks
    if user is None:
        return content_blocks

    out: list = []
    for block in content_blocks:
        if not isinstance(block, dict):
            out.append(block)
            continue
        btype = block.get("type")
        if btype == "text":
            text = block.get("text", "")
            scrubbed = await scrub_text_for_user(text, user, context_label=context_label)
            if scrubbed != text:
                # Copie pour ne pas muter le cache caller
                new_block = dict(block)
                new_block["text"] = scrubbed
                out.append(new_block)
            else:
                out.append(block)
        elif btype == "thinking":
            # Extended thinking côté Anthropic — le user peut le voir
            # dans certaines UIs. Scrubber par cohérence.
            thinking = block.get("thinking", "")
            scrubbed = await scrub_text_for_user(
                thinking, user, context_label=f"{context_label}_thinking"
            )
            if scrubbed != thinking:
                new_block = dict(block)
                new_block["thinking"] = scrubbed
                out.append(new_block)
            else:
                out.append(block)
        else:
            # tool_use, tool_result, image, etc. — non touchés.
            # Les ``tool_use.input`` peuvent contenir des SQL qui
            # référencent des tables interdites, c'est l'enforcer RLS
            # qui les bloque à l'exécution. Scrubber le ``input`` ici
            # casserait des SQL valides côté serveur (le mode invisible
            # s'applique au LLM, pas à l'enforcer interne).
            out.append(block)
    return out


async def scrub_llm_response_for_user(
    response: Any,
    user: Any,
    *,
    context_label: str = "llm_response",
) -> Any:
    """Wrapper haut-niveau — scrub la ``.content`` d'une réponse LLM.

    **⚠️ SCOPE LIMITÉ — adversarial review session 17 (2026-05-22)**

    Ce helper est utile UNIQUEMENT pour les contextes :
      - SANS proxy d'anonymisation amont (pas de ``§…§`` dans la réponse)
      - où ``.content`` est déjà en cleartext lisible
      - où une mutation partielle (``[…]``) ne casse pas la sémantique
        (narratif uniquement, JAMAIS SQL ou JSON structuré)

    **NE PAS UTILISER** dans ces cas :
      1. Contenu encore anonymisé par le proxy (``§…§`` / ``[TYPE_N]``) :
         le scrub cherche les vrais noms BDD, ne matchera RIEN → NO-OP.
         → Utiliser ``assert_safe_llm_response`` ou ``assert_safe_llm_blocks``
         APRÈS le ``restore_fn`` (pattern ``report_planner_agent.py:639``).
      2. Avant un autre garde-fou ``assert_safe_*`` (fail-closed) :
         le scrub masquerait les leaks que l'assert devait raise.
         → Choisir UN seul garde-fou, préférer le strict fail-closed.
      3. Sur du SQL / JSON structuré : le placeholder ``[…]`` casse la
         syntaxe (caller crash au parse).
         → Utiliser ``assert_safe_llm_response`` + raise.

    **Cas d'usage VALIDES** : agent narratif sans proxy d'anonymisation,
    réponse texte pure destinée à l'UI / persistance message history,
    contexte system batch sans user-scoped pseudonymizer.

    **Mutation NON-destructive** : retourne la response telle quelle si :
      - ``user`` est ``None`` (no-op rapide, fail-safe)
      - ``response`` ou ``response.content`` est ``None`` / vide
      - le scrub ne change rien

    Sinon, mute ``response.content`` en place avec le contenu scrubé.

    **Auto-dispatch sur la shape** :
      - ``str`` → :func:`scrub_text_for_user`
      - ``list`` → :func:`scrub_llm_blocks_for_user`
      - autre → no-op + log debug

    Args:
        response: objet LLM avec attribut ``.content`` (str ou list).
        user: utilisateur courant (objet avec ``id``/``role``).
        context_label: identifiant du caller pour les logs d'audit.

    Returns:
        Le même ``response`` (muté ou inchangé).
    """
    if response is None or user is None:
        return response
    content = getattr(response, "content", None)
    if not content:
        return response

    try:
        if isinstance(content, str):
            scrubbed = await scrub_text_for_user(content, user, context_label=context_label)
            if scrubbed != content:
                response.content = scrubbed
        elif isinstance(content, list):
            scrubbed_blocks = await scrub_llm_blocks_for_user(
                content, user, context_label=context_label
            )
            # ``scrub_llm_blocks_for_user`` retourne déjà une nouvelle liste
            # si modification. Comparaison structurelle pour éviter une mutation
            # inutile (et son cache invalidation côté caller).
            if scrubbed_blocks is not content:
                response.content = scrubbed_blocks
        else:
            import logging as _logging

            _logging.getLogger(__name__).debug(
                "scrub_llm_response_for_user: type inattendu %s (context=%s) — no-op",
                type(content).__name__,
                context_label,
            )
    except Exception:  # noqa: BLE001 — fail-safe, on ne casse jamais le caller
        import logging as _logging

        _logging.getLogger(__name__).warning(
            "scrub_llm_response_for_user: scrub a levé (context=%s) — réponse inchangée",
            context_label,
            exc_info=True,
        )

    return response


#: **Phase 2.5.bis.bis follow-up (#111)** — Regex pour neutraliser les
#: commentaires SQL inline qui peuvent servir de bypass au scan
#: word-boundary de :func:`contains_protected_name`.
#:
#: Sans ce strip, un LLM (hallucination ou prompt-injection) pouvait
#: écrire ``F_SECRE/*x*/T`` ou ``F_SECRET-- comment``. Le regex
#: ``\bF_SECRET\b`` ne match pas car les tokens sont séparés par un
#: commentaire ; mais l'utilisateur lit le rendu (la plupart des UI
#: rendent les commentaires sous forme grise ou invisible) et peut
#: reconstituer ``F_SECRET``.
_SQL_COMMENT_BLOCK_RE: re.Pattern[str] = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_COMMENT_LINE_RE: re.Pattern[str] = re.compile(r"--[^\n]*")


def _strip_sql_comments(text: str, replacement: str = " ") -> str:
    """Retire les commentaires SQL ``/* ... */`` et ``-- ...`` du texte.

    ``replacement`` :

    - ``" "`` (défaut) : préserve la séparation des tokens. Bon pour
      éviter le bypass ``EXEC/*x*/AS USER='admin'`` qui devient
      ``EXEC AS USER='admin'`` (match).
    - ``""`` : colle les tokens (cas attaque où l'utilisateur lit le
      rendu **sans** les commentaires invisibles → reconstitue le mot
      complet). Bon pour ``F_/*x*/SECRET`` → ``F_SECRET`` (match).

    Retourne le texte original si compilation regex impossible (input
    pathologique).
    """
    if not isinstance(text, str) or not text:
        return text or ""
    try:
        out = _SQL_COMMENT_BLOCK_RE.sub(replacement, text)
        out = _SQL_COMMENT_LINE_RE.sub(replacement, out)
        return out
    except re.error:
        return text


def contains_protected_name(
    text: str,
    denied_tables: frozenset[str],
    denied_columns_flat: frozenset[str] = frozenset(),
) -> bool:
    """Détecte si un texte (prompt LLM, message d'erreur, etc.) contient
    un nom de table/colonne interdit, **en mot entier**.

    Utilisé par le garde-fou runtime (Phase 3.3 / 2.5.bis.bis) pour
    détecter une fuite. Comparaison **insensible à la casse**, **word
    boundary** (`\\b...\\b`) — pas de match partiel pour éviter les
    faux positifs cataclysmiques sur des substrings communes.

    **Phase 2.5.bis.bis fix CRITICAL #2 review** : avant ce fix, la
    fonction utilisait ``name in upper`` brutal → ``F_X`` matchait
    ``MY_F_XYZ``, ``USERS`` matchait ``USERS_ROLES``,
    ``F_DOSSIER`` matchait ``T_F_DOSSIER_HISTO``. Violation explicite
    de la règle GÉNÉRICITÉ du CLAUDE.md (le code applicatif ne doit
    JAMAIS supposer une convention de naming spécifique à une BDD).
    Le fix utilise ``\\b...\\b`` cohérent avec :func:`scrub_text_for_user`.

    Args:
        text: le texte à scanner.
        denied_tables: noms de tables interdites (en majuscules).
        denied_columns_flat: noms de colonnes interdites aplatis
            (toutes les colonnes denied pour ce user, peu importe la table).

    Returns:
        True si AU MOINS un nom interdit apparaît comme **mot entier**
        (insensible à la casse) dans le texte.

    Note : reste conservative — un faux positif (fail-closed) reste
    préférable à un faux négatif (leak). Mais avec word boundary, les
    faux positifs sont limités aux vrais homonymes structurels (ex:
    une colonne qui s'appelle exactement comme une table interdite).
    """
    if not text:
        return False
    # **Phase 2.5.bis.bis follow-up (#111)** — Scan AUSSI sur des variantes
    # stripées des commentaires SQL, pour empêcher les bypass via
    # commentaires inline. Cas couverts :
    #
    # - ``F_SECRE/*x*/T`` → l'utilisateur lit ``F_SECRET`` quand les
    #   commentaires sont rendus invisibles dans la grille SQL
    # - ``F_SECRET-- comment\nFROM x`` → le ``--`` masque la suite
    # - ``F_/*joiner*/SECRET`` → reconstitution avec strip-join
    #
    # 3 passages : texte brut, espace-substitué, strippé sans remplacement.
    variants = [text]
    stripped_space = _strip_sql_comments(text, replacement=" ")
    if stripped_space != text:
        variants.append(stripped_space)
    stripped_join = _strip_sql_comments(text, replacement="")
    if stripped_join != text and stripped_join != stripped_space:
        variants.append(stripped_join)

    for variant in variants:
        for name in denied_tables:
            if not name:
                continue
            pattern = r"\b" + re.escape(name) + r"\b"
            if re.search(pattern, variant, flags=re.IGNORECASE):
                return True
        for name in denied_columns_flat:
            if not name:
                continue
            pattern = r"\b" + re.escape(name) + r"\b"
            if re.search(pattern, variant, flags=re.IGNORECASE):
                return True
    return False


# ---------------------------------------------------------------------------
# P2.1 — Single source of truth pour transformer une exception SQL en payload
# client structuré (audit 2026-05-26).
# ---------------------------------------------------------------------------
#
# Contexte : avant 2026-05-26, **6 implémentations divergentes** sérialisaient
# les erreurs SQL Server vers le client :
#   - iris.py::_classify_agent_error (chat Iris)
#   - datastore.py (non-admin SQL exec)
#   - drilldown.py (3 sites : multi-CTE, single, cell-detail)
#   - automation/executor.py (top-level catch)
#   - agent_tools._handle_execute_sql (Iris tool)
# Chacune masquait l'erreur différemment ("Une erreur inattendue", "référence
# invalide", "Cette sous-requête n'a pas pu être exécutée", etc.) → l'admin et
# Iris perdaient toute capacité de diagnostic.
#
# Ce helper centralise la sérialisation. Les call-sites appellent
# ``sanitize_sql_for_client(exc, user, audience=...)`` et reçoivent un dict
# structuré (message, sqlstate, category, detail_for_admin). Migration des
# call-sites prévue par P2.2 à P2.6.

ClientAudience = Literal["admin", "user", "llm"]


class SqlErrorPayload(TypedDict):
    """Payload structuré retourné par :func:`sanitize_sql_for_client`.

    - ``message`` : message FR actionnable adapté à l'audience.
    - ``sqlstate`` : code SQLSTATE ANSI (5 chars) si extractable depuis l'exception.
    - ``category`` : famille d'erreur — ``syntax``, ``referential``, ``type``,
      ``timeout``, ``permission``, ``connection``, ``unknown``.
    - ``detail_for_admin`` : ``str(exc)`` brut, présent **uniquement** si
      ``audience == "admin"``. Sinon ``None``. Ne JAMAIS exposer ce champ au
      user final ou au LLM.
    """

    message: str
    sqlstate: Optional[str]
    category: str
    detail_for_admin: Optional[str]


#: SQLSTATE → catégorie. Basé sur ISO/IEC 9075 + extensions SQL Server / ODBC.
#: Non exhaustif — le fallback par préfixe couvre les SQLSTATE inconnus.
_SQLSTATE_CATEGORY_MAP: dict[str, str] = {
    # Connexion (classe 08)
    "08001": "connection",
    "08003": "connection",
    "08004": "connection",
    "08006": "connection",
    "08007": "connection",
    "08S01": "connection",
    # Authentification (classe 28)
    "28000": "permission",
    # Syntax / generic 42
    "42000": "syntax",
    # Référentiel (objets, contraintes)
    "42S02": "referential",
    "42S22": "referential",
    "42S12": "referential",
    "42S11": "referential",
    "42S21": "referential",
    "23000": "referential",
    # Types / cast (classe 22)
    "22001": "type",
    "22003": "type",
    "22007": "type",
    "22008": "type",
    "22012": "type",
    "22018": "type",
    "22019": "type",
    "22025": "type",
    # Timeout / verrouillage
    "HYT00": "timeout",
    "HYT01": "timeout",
    "40001": "timeout",
    # Permission (PG-style)
    "42501": "permission",
}


#: Hints FR par catégorie destinés à l'utilisateur final. Texte volontairement
#: actionnable (« vérifie ceci », « fais cela ») plutôt que descriptif.
_USER_HINTS_BY_CATEGORY: dict[str, str] = {
    "syntax": (
        "La requête contient une erreur de syntaxe SQL. "
        "Vérifiez les mots-clés, la ponctuation et les guillemets."
    ),
    "referential": (
        "La requête référence une table, une colonne ou un objet qui n'existe pas, "
        "ou auquel vous n'avez pas accès. Vérifiez l'orthographe ou contactez "
        "votre administrateur."
    ),
    "type": (
        "Une valeur ne correspond pas au type de données attendu (nombre, date, texte). "
        "Vérifiez les conversions et les formats utilisés."
    ),
    "timeout": (
        "La requête a dépassé le délai d'exécution. Réessayez ou ajoutez un filtre "
        "pour réduire le volume scanné."
    ),
    "permission": (
        "Les identifiants ou autorisations sur la base source sont incorrects. "
        "Contactez votre administrateur."
    ),
    "connection": (
        "La base de données source est temporairement indisponible. "
        "Si le problème persiste, contactez votre administrateur."
    ),
    "deployment": (
        "Le serveur Komptia n'est pas correctement configuré pour parler à la "
        "base de données source (pilote ODBC manquant). Ce n'est ni un problème "
        "de réseau ni d'identifiants : contactez votre administrateur système."
    ),
    "unknown": (
        "La base de données a renvoyé une erreur que nous n'avons pas pu classer. "
        "Contactez votre administrateur si le problème persiste."
    ),
}


_SQLSTATE_RE = re.compile(r"^[A-Z0-9]{5}$")


def _extract_sqlstate(exc: BaseException) -> Optional[str]:
    """Extrait le SQLSTATE depuis une exception type pyodbc (args[0] = state).

    Duck-typed : ne dépend pas de ``pyodbc`` (qui est conditionnellement importé
    et absent en environnement test). Reconnaît tout ``exc.args[0]`` qui ressemble
    à un SQLSTATE (5 chars alphanumérique majuscule).

    Returns:
        SQLSTATE upper-case (ex: ``"42S22"``) ou ``None`` si non extractable.
    """
    args = getattr(exc, "args", None)
    if not args:
        return None
    candidate = args[0]
    if not isinstance(candidate, str):
        return None
    candidate_up = candidate.upper()
    if _SQLSTATE_RE.match(candidate_up):
        return candidate_up
    return None


def _categorize_sql_error(sqlstate: Optional[str], raw_message: str) -> str:
    """Mappe (SQLSTATE, message) → catégorie.

    Stratégie :

    1. SQLSTATE exact dans :data:`_SQLSTATE_CATEGORY_MAP` → catégorie.
    2. Préfixe 2-chars du SQLSTATE → fallback ISO/IEC 9075
       (08=connection, 22=type, 28=permission, 40=timeout, 42=referential, HY=timeout).
    3. Heuristique keyword sur ``raw_message`` (en l'absence de SQLSTATE).
    4. Fallback ``"unknown"``.
    """
    if sqlstate:
        cat = _SQLSTATE_CATEGORY_MAP.get(sqlstate)
        if cat:
            return cat
        prefix = sqlstate[:2]
        if prefix == "08":
            return "connection"
        if prefix == "22":
            return "type"
        if prefix == "28":
            return "permission"
        if prefix == "40":
            return "timeout"
        if prefix == "42":
            return "referential" if sqlstate != "42000" else "syntax"
        if prefix == "HY":
            return "timeout"
    if not raw_message:
        return "unknown"
    lower = raw_message.lower()
    # Ordre important : checks les plus spécifiques d'abord.
    # Faute de DÉPLOIEMENT (pilote ODBC SQL Server absent du serveur applicatif) :
    # à détecter AVANT tout le reste car le message contient « réseau » (dans
    # « ce n'est PAS un problème réseau ») qui pourrait sinon induire en erreur.
    # Couvre le chemin string-sérialisé (le chemin exception est court-circuité
    # par isinstance(SageDriverMissingError) dans sanitize_sql_for_client). Les
    # marqueurs proviennent des messages SSoT de discover_sage_odbc_driver().
    if (
        "aucun driver odbc" in lower
        or "le module python pyodbc n'est pas disponible" in lower
    ):
        return "deployment"
    if "timeout" in lower or "delai" in lower or "expired" in lower:
        return "timeout"
    if "deadlock" in lower or "lock request" in lower:
        return "timeout"
    if (
        "invalid object name" in lower
        or "invalid column name" in lower
        or "n'est pas valide" in lower
    ):
        return "referential"
    if "constraint" in lower or "foreign key" in lower or "primary key" in lower:
        return "referential"
    if "login failed" in lower or "permission denied" in lower or "access denied" in lower:
        return "permission"
    if "incorrect syntax" in lower or "syntax error" in lower:
        return "syntax"
    if "conversion failed" in lower or "cannot convert" in lower or "arithmetic overflow" in lower:
        return "type"
    if (
        "communication link failure" in lower
        or "tcp provider" in lower
        or "cannot open database" in lower
        or "connection refused" in lower
        or "network-related" in lower
    ):
        return "connection"
    return "unknown"


def _truncate(text: str, limit: int = 500) -> str:
    """Tronque ``text`` à ``limit`` chars en ajoutant ``…`` si tronqué."""
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


async def sanitize_sql_for_client(
    exc_or_message: Any,
    user: Any,
    *,
    audience: ClientAudience = "user",
) -> SqlErrorPayload:
    """Sérialise une erreur SQL en payload structuré pour le client.

    **Single source of truth** (P2.1, audit 2026-05-26) : ce helper remplace
    6 implémentations divergentes (iris.py, datastore.py, drilldown.py x3,
    automation/executor.py, agent_tools._handle_execute_sql).

    Args:
        exc_or_message: soit une exception (``QueryError``, ``SageConnectionError``,
            ``pyodbc.Error``, etc.), soit une chaîne déjà sérialisée par un
            layer inférieur (typiquement ``execute_for_ai`` qui retourne
            ``{"error": "Exécution: [42S22] ..."}``). ``None`` accepté.
            Le SQLSTATE est extrait depuis ``exc.args[0]`` pour une exception,
            ou via regex ``\\[XXXXX\\]`` pour une string.
        user: l'utilisateur courant. Sert à :
            - décider de la sanitization PII via
              :func:`sanitize_sql_server_error_message` (mode invisible).
            - ``user=None`` est accepté (contexte système) — la sanitization
              passe en transparent.
        audience: cible du message :
            - ``"admin"`` : message verbeux + ``detail_for_admin`` = raw.
              Pour pages /admin et logs.
            - ``"user"`` : hint catégoriel FR (+ détail court sanitizé pour
              les catégories referential/type/syntax). Pour user final.
            - ``"llm"`` : message structuré sanitizé pour permettre l'auto-correction
              Iris. Inclut SQLSTATE et un détail court sanitizé.

    Returns:
        :class:`SqlErrorPayload` (TypedDict) :

        .. code-block:: python

            {
                "message": "La requête référence une table... Vérifiez l'orthographe.",
                "sqlstate": "42S02",
                "category": "referential",
                "detail_for_admin": None,  # ou str(exc) si audience=admin
            }

    **Garanties** :

    - Aucune exception ne remonte depuis ce helper (try/except global).
    - Le raw brut n'est JAMAIS exposé si ``audience != "admin"``.
    - PII / noms denied sont scrubés via :func:`sanitize_sql_server_error_message`
      pour ``audience in ("user", "llm")``.

    **Exemples d'usage** :

    .. code-block:: python

        # Handler HTTP user final
        payload = await sanitize_sql_for_client(exc, self.current_user, audience="user")
        self.write_json({"success": False, "error": payload["message"], "category": payload["category"]})

        # Datastore (chaîne déjà sérialisée par execute_for_ai)
        payload = await sanitize_sql_for_client(result["error"], user, audience="user")

        # Tool Iris (LLM input)
        payload = await sanitize_sql_for_client(exc, user, audience="llm")
        return {"success": False, "error": payload["message"], "sqlstate": payload["sqlstate"]}

        # Page admin /executions
        payload = await sanitize_sql_for_client(exc, current_user, audience="admin")
        # payload["detail_for_admin"] contient le str(exc) complet pour debug
    """
    raw_message = ""
    sqlstate: Optional[str] = None
    category = "unknown"
    try:
        if exc_or_message is None:
            pass  # garde les defaults
        elif isinstance(exc_or_message, str):
            raw_message = exc_or_message.strip()
            # Extrait SQLSTATE depuis un préfixe ``[XXXXX]`` n'importe où dans
            # la string (les call-sites peuvent ajouter des préfixes type
            # « Exécution: ... » comme dans ``execute_for_ai``).
            match = re.search(r"\[([A-Z0-9]{5})\]", raw_message)
            if match:
                sqlstate = match.group(1).upper()
            category = _categorize_sql_error(sqlstate, raw_message)
        elif isinstance(exc_or_message, BaseException):
            raw_message = str(exc_or_message).strip()
            sqlstate = _extract_sqlstate(exc_or_message)
            # Court-circuit déterministe : un driver ODBC absent est une faute de
            # DÉPLOIEMENT (serveur applicatif Komptia), pas une erreur SQL ni
            # réseau. On la classe explicitement pour ne PAS retomber en
            # « unknown »/« connection » et perdre le diagnostic actionnable sur
            # le chemin Iris/datastore/drilldown (cf. incident driver manquant).
            from app.core.exceptions import SageDriverMissingError

            if isinstance(exc_or_message, SageDriverMissingError):
                category = "deployment"
            else:
                category = _categorize_sql_error(sqlstate, raw_message)
        else:
            # Type inattendu : on coerce en str (defensive)
            raw_message = str(exc_or_message).strip()
            category = _categorize_sql_error(None, raw_message)
    except Exception:  # noqa: BLE001 — defensive : never crash the error path
        # Fallback ultime : on perd l'info mais on ne casse pas le caller.
        if isinstance(exc_or_message, BaseException):
            raw_message = type(exc_or_message).__name__
        else:
            raw_message = "unknown"
        sqlstate = None
        category = "unknown"

    # Sanitization PII : remplace les "Invalid object name 'X'" si user a
    # des règles deny actives. Pour audience=admin on garde le raw.
    sanitized_msg = raw_message
    if audience != "admin" and raw_message:
        try:
            sanitized_msg = await sanitize_sql_server_error_message(raw_message, user)
        except Exception:  # noqa: BLE001 — fail-closed sur la sanitization
            # Si la sanitization plante, on ne laisse PAS passer le raw au
            # user/LLM — on retombe sur un message générique mode-invisible.
            sanitized_msg = _GENERIC_TEMPLATES[GenericMessageKind.SQL_INVALID_NAME]

    hint = _USER_HINTS_BY_CATEGORY.get(category, _USER_HINTS_BY_CATEGORY["unknown"])

    if audience == "admin":
        # Admin voit tout (catégorie + SQLSTATE + raw).
        if sqlstate:
            message = f"[{sqlstate}] {_truncate(raw_message)}"
        elif raw_message:
            message = f"[{category}] {_truncate(raw_message)}"
        else:
            message = f"[{category}] (aucun détail)"
        return SqlErrorPayload(
            message=message,
            sqlstate=sqlstate,
            category=category,
            detail_for_admin=_truncate(raw_message, limit=2000),
        )

    if audience == "llm":
        # LLM voit le détail sanitizé + SQLSTATE pour auto-corriger.
        # Pas de detail_for_admin (le LLM n'est pas admin).
        prefix = f"[{sqlstate}] " if sqlstate else f"[{category.upper()}] "
        # Inclure raw sanitized si présent, sinon juste le hint catégoriel.
        if sanitized_msg:
            body = _truncate(sanitized_msg, limit=400)
            message = f"{prefix}{body}"
        else:
            message = f"{prefix}{hint}"
        return SqlErrorPayload(
            message=message,
            sqlstate=sqlstate,
            category=category,
            detail_for_admin=None,
        )

    # audience == "user" : hint FR catégoriel + détail court pour les
    # catégories actionnables (referential/type/syntax). Pour les autres
    # (connection/timeout/permission/unknown), juste le hint.
    if sanitized_msg and category in ("referential", "type", "syntax") and len(sanitized_msg) < 200:
        message = f"{hint} Détail : {sanitized_msg}"
    else:
        message = hint
    return SqlErrorPayload(
        message=message,
        sqlstate=sqlstate,
        category=category,
        detail_for_admin=None,
    )
