"""Diff structuré entre une question validée passée et la demande courante.

Inspiré de la philosophie ``copilot_agent`` : le système fait le travail
déterministe (re-scoring, extraction de scope, comparaison de tokens), le
LLM reçoit une micro-tâche d'édition au lieu de devoir tout reconstruire.

Pourquoi ce module existe
-------------------------

Quand une nouvelle conversation Iris démarre avec un SQL validé en mémoire
RAG (déjà-vu), le code historique injectait soit :

* un score figé pris au tour 1 puis cappé au journal (« non re-scoré, ne
  l'utilise pas aveuglément »),
* un message générique « adapte ce SQL si nécessaire ».

Le LLM, face à un signal aussi flou, choisissait la sécurité et
reconstruisait depuis zéro. Le run #15-17 du 2026-04-28 a illustré le
coût concret : 10+ tool calls et clarifications redondantes alors que
3 modifications triviales sur le SQL validé suffisaient.

Ce module fournit aux call-sites :

1. ``freshly_score_pair`` : ré-évalue la similarité entre le message
   courant et la question validée avec la même métrique (recall-IDF) que
   le RAG initial. Plus de score périmé du tour 1.
2. ``compute_question_diff`` : extrait des deux questions et du SQL
   validé un dict structuré ``{kept, dropped, added, scope}`` exploitable
   directement comme micro-tâche d'édition.
3. ``format_diff_block`` : sérialise le diff en bloc Markdown à injecter
   dans le system prompt — wording adapté au score frais (applicable /
   proche / écart).

Aucune liste hardcodée de mots-clés métier. Le scope provient d'un parser
SQL générique (``filter_extractor.extract_sql_scope``) et la tokenisation
de la même chaîne ``SimpleTextSearch.tokenize`` que le RAG. Branchable
quel que soit le secteur ou la BDD connectée.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.ai.training_store import SimpleTextSearch

# Seuil sous lequel un SQL validé re-scoré n'est PAS injecté. La paire
# est considérée trop éloignée du message courant pour servir de base.
# Au-dessus, on injecte le SQL avec le diff : c'est au LLM (avec le diff
# en hint) de décider s'il copie/adapte.
FRESH_REUSE_MIN_SCORE = 0.50

# Seuil de "quasi-identité" : au-dessus, le wording du prompt insiste
# fort sur "adapter minimalement, ne pas reconstruire".
#
# Calibré à 0.70 sur la base du recall-IDF : la métrique pénalise la
# variation morphologique normale (« exercice » vs « exercices »), les
# politesses (« bonjour ») et les verbes de demande (« donner »,
# « peux ») qui sont structurellement absents d'une question validée
# antérieure. Deux questions vraiment quasi-identiques selon la
# perception utilisateur sortent typiquement à 0.70-0.80, pas 0.95.
# Au-dessus de 0.70, l'adaptation minimale est la bonne stratégie.
FRESH_STRICT_MIN_SCORE = 0.70


@dataclass
class QuestionDiff:
    """Résultat structuré d'un diff question↔question + SQL validé.

    Tous les champs sont optionnels — un diff vide reste valide (cas
    "questions identiques, rien à changer"). Les valeurs sont données en
    français lisible, pas en tokens bruts (sauf ``new_terms_unscoped``).
    """

    fresh_score: float = 0.0
    """Score de similarité re-calculé sur le message courant (recall-IDF)."""

    scope_kept: List[str] = field(default_factory=list)
    """Filtres du SQL validé que l'utilisateur courant re-mentionne."""

    scope_unmentioned: List[str] = field(default_factory=list)
    """Filtres du SQL validé que l'utilisateur courant ne mentionne PAS.

    Indice fort qu'ils peuvent être à retirer (« je ne l'ai pas demandé »).
    Mais le LLM décide — un utilisateur qui dit « la même chose pour
    2025 » sous-entend de garder les filtres.
    """

    new_terms_unscoped: List[str] = field(default_factory=list)
    """Tokens présents dans le message courant ET absents du scope validé.

    Candidats à de nouveaux filtres / valeurs / périodes. Filtré par
    ``_TOKEN_RELEVANCE_PRED`` pour éliminer le bruit (politesse, verbes
    génériques) — voir doc ci-dessous.
    """

    validated_question: str = ""
    """La question initiale ayant produit le SQL validé (rappel)."""

    validated_sql: str = ""
    """Le SQL validé lui-même."""


# Liste complémentaire de ``SimpleTextSearch.STOP_WORDS`` : les
# tokens passent déjà par ``tokenize`` qui filtre les stopwords
# basiques (le, la, de, du, et, ou, the, is, …) et drop les tokens
# de longueur ≤ 1. On ajoute ici les politesses et verbes de
# demande typiques d'une question utilisateur, qui ne sont pas
# dans ``STOP_WORDS`` parce que cette liste est conçue pour le
# RAG (matching de DDL / documentation), pas pour un diff
# question↔question.
#
# Liste générique : pas de mots-clés métier. Si une langue autre
# que le français devient nécessaire, étendre cette liste plutôt
# que dupliquer toute la logique.
_NOISE_TOKENS = frozenset(
    {
        # politesse / formules d'entrée
        "bonjour",
        "merci",
        "stp",
        "svp",
        # verbes auxiliaires de demande
        "peux",
        "pourrais",
        "pourriez",
        "veux",
        "voudrais",
        "donne",
        "donnes",
        "donner",
        "donnez",
        "fais",
        "faire",
        "trouve",
        "trouver",
        "expliquer",
        "explique",
        "voir",
        "savoir",
        "vais",
        "voulais",
        # interrogation / liaison
        "pourquoi",
        "comment",
        "que",
        "qu",
        "ce",
        "ca",
        "cela",
        "tu",
        "vous",
        "moi",
        "lui",
        "leur",
        "leurs",
        # quantifieurs / connecteurs ne couverts par STOP_WORDS
        "uniquement",
        "seulement",
        "juste",
        "toujours",
        "jamais",
        "puis",
        "ensuite",
        "alors",
        "ainsi",
        "chaque",
    }
)


def _is_relevant_token(token: str) -> bool:
    """Filtre le bruit des tokens pour le diff.

    Un token « pertinent » pour signaler un changement de filtre est :

    * un nombre / année / code numérique (« 2025 », « 70610000 »),
    * un code court alphanumérique de 3+ chars (« TVA », « BIC »,
      « EUR ») — utile sur les BDD non-Sage où les codes sont
      typiquement à 3 lettres,
    * un mot de 4+ chars qui n'est pas du bruit (politesse, verbe
      de demande).

    Pas de liste blanche métier — tout ce qui n'est PAS dans la liste
    noire ``_NOISE_TOKENS`` ET satisfait la règle de longueur passe.
    Le seuil à 3 (au lieu de 4) capture les acronymes courts comme
    « TVA » qui ne contiennent pas de chiffre mais sont des valeurs
    métier légitimes.
    """
    if not token:
        return False
    t = token.lower()
    if t in _NOISE_TOKENS:
        return False
    # Nombres / années / codes numériques : toujours pertinents
    if any(c.isdigit() for c in t):
        return True
    # Codes courts (3 chars) ou mots longs (4+) qui ne sont pas du bruit
    if len(t) >= 3:
        return True
    return False


def _normalize_scope_value(val: Any) -> str:
    """Normalise une valeur de scope SQL en string adapté au diff.

    Cas spéciaux :

    * ``70610000.0`` (float entier sortant de sqlglot/Decimal) →
      ``'70610000'`` pour éviter que la tokenisation produise
      ``{"70610000", "0"}`` et casse la comparaison ``issubset`` avec
      le message utilisateur (qui n'écrit jamais ``.0``).
    * ``True`` / ``False`` / ``None`` → string par défaut.
    * Strings → renvoyés tels quels (le ``str()`` est gardé pour la
      robustesse).
    """
    if val is None:
        return ""
    if isinstance(val, float) and val.is_integer():
        return str(int(val))
    return str(val)


def freshly_score_pair(
    current_message: str,
    validated_question: str,
    corpus_questions: Optional[List[str]] = None,
) -> float:
    """Re-score la similarité ``current_message`` ↔ ``validated_question``.

    Utilise la même métrique que le RAG initial (``compute_query_recall_idf``)
    pour rester cohérent. Le score est dans ``[0, 1]`` :

    * ``1.0`` : tous les tokens discriminants du message courant sont
      présents dans la question validée (couverture parfaite),
    * ``0.0`` : aucun mot discriminant en commun.

    ``corpus_questions`` permet de fournir d'autres questions du même
    corpus pour calibrer l'IDF (token rare → poids fort). Si ``None``, on
    utilise un corpus minimal (les 2 questions seules) — l'IDF est alors
    moins discriminant mais le score reste utilisable comme signal
    relatif. En production, le caller fournira un sample du store.

    Retourne ``0.0`` sur entrée invalide (questions vides) — fail-safe :
    pas d'injection RAG plutôt qu'une injection sur score erroné.
    """
    if not current_message or not validated_question:
        return 0.0
    if not isinstance(current_message, str) or not isinstance(validated_question, str):
        return 0.0

    query_tokens = SimpleTextSearch.tokenize(current_message)
    if not query_tokens:
        return 0.0

    doc_tokens = SimpleTextSearch.tokenize(validated_question)
    documents = [doc_tokens]

    # Corpus minimal si non fourni : la question elle-même + le message.
    # Donne un IDF stable (DF=1 partout, valeurs égales) qui revient à
    # une couverture brute. C'est un fallback acceptable — un caller
    # consciencieux fournira un vrai corpus.
    if corpus_questions:
        for q in corpus_questions:
            if isinstance(q, str) and q and q != validated_question:
                documents.append(SimpleTextSearch.tokenize(q))

    scores = SimpleTextSearch.compute_query_recall_idf(query_tokens, documents)
    if not scores:
        return 0.0
    # Premier score = couverture entre query et la question validée.
    return float(scores[0])


def compute_question_diff(
    old_question: str,
    new_message: str,
    old_sql: Optional[str] = None,
    fresh_score: Optional[float] = None,
) -> QuestionDiff:
    """Diff structuré entre l'ancienne question (validée) et la nouvelle.

    Trois axes :

    1. **Scope SQL** : extrait via ``filter_extractor.extract_sql_scope``
       les couples ``{col: [vals]}`` du WHERE du SQL validé. Pour chaque
       valeur scope, on regarde si elle est re-mentionnée dans le message
       courant (= "kept") ou pas (= "scope_unmentioned" → candidat à
       retrait).

    2. **Termes nouveaux** : tokens du message courant qui n'apparaissent
       ni dans le scope validé ni dans la question validée → candidats à
       de nouveaux filtres / colonnes / périodes.

    3. **Score frais** : pré-calculé via ``freshly_score_pair`` ou
       fourni en paramètre. Sert au caller à choisir le wording du
       prompt (applicable / proche / écart).

    Tout est optionnel — un diff vide est valide. Pas de hardcode de
    mots-clés métier : la pertinence d'un token est testée par
    ``_is_relevant_token`` (longueur, présence de chiffres, exclusion
    d'une liste noire de mots vides français).
    """
    if fresh_score is None:
        fresh_score = freshly_score_pair(new_message, old_question)

    diff = QuestionDiff(
        fresh_score=fresh_score,
        validated_question=old_question or "",
        validated_sql=old_sql or "",
    )

    if not new_message or not isinstance(new_message, str):
        return diff

    new_tokens = set(SimpleTextSearch.tokenize(new_message))
    old_tokens = set(SimpleTextSearch.tokenize(old_question or ""))

    # ── 1. Scope SQL : ce qui est filtré dans le SQL validé ──
    scope: Dict[str, List[Any]] = {}
    if old_sql and isinstance(old_sql, str):
        try:
            from app.services.ai.filter_extractor import extract_sql_scope

            extracted = extract_sql_scope(old_sql)
            if isinstance(extracted, dict):
                scope = extracted
        except Exception:
            # Parsing SQL cassé / sqlglot indisponible : pas de scope.
            # On retombe sur le diff de tokens uniquement.
            scope = {}

    # Pour chaque (col, vals), vérifier si l'utilisateur courant
    # re-mentionne la valeur. Trois cas :
    #
    # (a) Valeur SIMPLE (mono-token, ex: « 70610000 ») → match strict
    #     sur la présence du token dans le message.
    # (b) Valeur MULTI-MOTS (ex: « DOSSIER_A PAP », « EXPERT COMPTABLE »)
    #     → on accepte « kept » dès lors qu'au moins un token
    #     distinctif est présent OU que la valeur entière apparaît en
    #     substring dans le message (cas où l'utilisateur copie-colle).
    #     C'est un compromis : exiger TOUS les tokens (issubset) crée
    #     des faux-négatifs (l'utilisateur tape « DOSSIER_A » sans le
    #     « PAP » qui est un suffixe d'antenne) ; n'exiger qu'un seul
    #     produirait des faux-positifs (un token générique partagé).
    #     L'addition du substring-match couvre les copies-collés.
    # (c) Valeur tokenisée VIDE (1 char, pure ponctuation) → on
    #     retombe sur substring lower-case.
    new_message_lower = (new_message or "").lower()
    for col, vals in scope.items():
        for val in vals:
            val_str = _normalize_scope_value(val)
            if not val_str:
                continue
            val_tokens = set(SimpleTextSearch.tokenize(val_str))
            if not val_tokens:
                if val_str.lower() in new_message_lower:
                    diff.scope_kept.append(f"{col} = {val_str}")
                else:
                    diff.scope_unmentioned.append(f"{col} = {val_str}")
                continue

            full_token_match = val_tokens.issubset(new_tokens)
            substring_match = len(val_str) >= 3 and val_str.lower() in new_message_lower
            partial_token_match = len(val_tokens) > 1 and bool(val_tokens & new_tokens)

            if full_token_match or substring_match or partial_token_match:
                diff.scope_kept.append(f"{col} = {val_str}")
            else:
                diff.scope_unmentioned.append(f"{col} = {val_str}")

    # ── 2. Termes nouveaux dans le message courant ──
    # Tokens du message courant qui ne sont :
    # - ni dans la question validée (sinon ce n'est pas "nouveau"),
    # - ni dans une valeur du scope (déjà couvert par scope_kept),
    # - ni un token "bruit" (politesse / verbe générique).
    scope_value_tokens: set[str] = set()
    for vals in scope.values():
        for val in vals:
            scope_value_tokens.update(SimpleTextSearch.tokenize(_normalize_scope_value(val)))

    candidates = new_tokens - old_tokens - scope_value_tokens
    diff.new_terms_unscoped = sorted(t for t in candidates if _is_relevant_token(t))

    return diff


def format_diff_block(diff: QuestionDiff) -> str:
    """Sérialise un ``QuestionDiff`` en bloc Markdown pour le system prompt.

    Wording adapté au score (les seuils numériques exacts sont lus
    dynamiquement depuis les constantes — pas de pourcentages hardcodés
    dans le texte) :

    * ≥ ``FRESH_STRICT_MIN_SCORE`` : « SQL validé applicable — adapte
      minimalement ». Insiste sur la conservation de la structure.
    * ≥ ``FRESH_REUSE_MIN_SCORE`` : « SQL validé proche — vérifie les
      écarts ». Plus prudent, demande au LLM de cocher chaque
      différence.
    * < ``FRESH_REUSE_MIN_SCORE`` : ne devrait pas arriver (le caller
      doit avoir filtré avant), mais on retourne quand même un bloc
      défensif « à utiliser comme inspiration uniquement ».

    Les listes ``scope_kept`` et ``scope_unmentioned`` sont rendues
    seulement si elles sont non vides — pas de "Aucun" ou "N/A" qui
    pollueraient le prompt.

    Le bloc est conçu pour être concaténé dans le system prompt après
    le bloc déjà-vu existant (``format_prefetch_for_prompt``) ou en
    remplacement du bloc fallback "non re-scoré".
    """
    s = float(diff.fresh_score or 0)
    _strict_pct = int(round(FRESH_STRICT_MIN_SCORE * 100))

    if s >= FRESH_STRICT_MIN_SCORE:
        header = "## ⚡ SQL VALIDÉ APPLICABLE — Adapte, ne reconstruis pas"
        intro = (
            f"Score de similarité re-calculé sur ta demande courante : "
            f"**{s:.0%}** (≥ {_strict_pct}% = quasi-identique). "
            "Le SQL ci-dessous est ta base. Modifie UNIQUEMENT ce que la "
            "section « différences détectées » signale."
        )
    elif s >= FRESH_REUSE_MIN_SCORE:
        header = "## 💡 SQL VALIDÉ PROCHE — Vérifie chaque écart"
        intro = (
            f"Score de similarité re-calculé sur ta demande courante : "
            f"**{s:.0%}**. Le SQL ci-dessous est un point de départ "
            "valable. Examine chaque écart signalé avant d'adapter — "
            "un écart non traité peut casser la sémantique."
        )
    else:
        # Cas défensif : caller aurait dû filtrer, on dégrade
        # gracieusement.
        header = "## 📎 SQL VALIDÉ ÉLOIGNÉ — Inspiration seulement"
        intro = (
            f"Score de similarité re-calculé : **{s:.0%}** (faible). "
            "Le SQL ci-dessous porte sur une question DIFFÉRENTE — "
            "consulte-le comme exemple de patterns sur la BDD, mais "
            "RECONSTRUIS ta requête depuis zéro pour la demande courante."
        )

    lines: List[str] = [
        "",
        "",
        header,
        "",
        intro,
        "",
    ]

    # Différences détectées : c'est le cœur de la micro-tâche d'édition.
    has_changes = diff.scope_kept or diff.scope_unmentioned or diff.new_terms_unscoped

    if has_changes:
        lines.append("### Différences détectées entre la question validée et ta demande courante")
        lines.append("")

        if diff.scope_kept:
            lines.append(
                "**Filtres du SQL validé que l'utilisateur RE-MENTIONNE** "
                "(à conserver tels quels) :"
            )
            for item in diff.scope_kept:
                lines.append(f"- ✅ `{item}`")
            lines.append("")

        if diff.scope_unmentioned:
            lines.append(
                "**Filtres du SQL validé que l'utilisateur NE MENTIONNE PAS** "
                "(candidats à retirer — sauf si la formulation sous-entend "
                "« la même chose pour … ») :"
            )
            for item in diff.scope_unmentioned:
                lines.append(f"- ⚠️ `{item}`")
            lines.append("")

        if diff.new_terms_unscoped:
            terms_str = ", ".join(f"`{t}`" for t in diff.new_terms_unscoped)
            lines.append(
                "**Termes du message courant ABSENTS du SQL validé** "
                "(candidats à de nouveaux filtres / colonnes / périodes) :"
            )
            lines.append(f"- 🆕 {terms_str}")
            lines.append("")
    else:
        lines.append("### Aucune différence structurelle détectée")
        lines.append("")
        lines.append(
            "Les filtres du SQL validé semblent tous ré-applicables et "
            "aucun terme nouveau n'a été identifié. Si la demande est "
            "réellement identique, exécute directement le SQL validé. "
            "Sinon, vérifie qu'aucune nuance ne t'a échappé."
        )
        lines.append("")

    # Garde-fous : rappel des règles d'adaptation à utiliser comme
    # check-list mentale, sans répéter ce qui est déjà dans le prompt
    # principal. Concis car le bloc déjà-vu en amont a déjà couvert le
    # « comment l'utiliser » détaillé.
    lines.append("### Tâche")
    lines.append("")
    lines.append(
        "Produis le SQL adapté en partant du SQL validé. Pour chaque "
        "différence ci-dessus, applique l'édition correspondante. Ne "
        "touche pas aux JOINs, CTE, fonctions T-SQL — ils encodent la "
        "logique métier validée."
    )
    lines.append("")

    return "\n".join(lines)


__all__ = [
    "FRESH_REUSE_MIN_SCORE",
    "FRESH_STRICT_MIN_SCORE",
    "QuestionDiff",
    "compute_question_diff",
    "format_diff_block",
    "freshly_score_pair",
]
