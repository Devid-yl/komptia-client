"""
Base de connaissances auto-alimentée pour l'agent Iris.

Construit par-dessus TrainingStore pour donner à l'agent une connaissance
approfondie de la base source : schémas, sens métier des colonnes,
exemples de requêtes validés par les utilisateurs.

L'agent peut :
- Interroger la base pour construire son contexte système
- Enregistrer de nouveaux insights sur les tables/colonnes
- Apprendre depuis les retours positifs des utilisateurs
- Consulter tout ce qui est connu sur une table précise
"""

import logging
import re
import time
from typing import Any, Optional

from app.constants_ai import DISTINCT_VALUES_MAX_DISPLAY, VISIBLE_TABLES_LIMIT
from app.services.ai.training_store import TrainingStore, get_training_store

logger = logging.getLogger(__name__)


async def get_concept_glossary_mappings(concepts: list[str]) -> dict[str, list[dict]]:
    """Lecteur runtime du ``ConceptGlossary`` (glossaire appris par feedback ✅).

    Tâche #13 (2026-06-10) : la table était ÉCRITE
    (``_persist_concept_resolutions_on_validate``) mais jamais RELUE — la boucle
    « demander une fois → apprendre → rejouer » restait ouverte. Ce lecteur la
    referme : pour chaque concept (normalisé ``lower()``), renvoie les mappings
    (table, colonne) déjà validés, triés par ``(usage_count, confidence)`` desc,
    pour qu'``align_request`` applique une désambiguïsation passée sans redemander.

    GLOBAL (mono-déploiement, pas d'isolation cross-user — cf. modèle).
    Fail-closed : toute erreur → ``{}`` (ne casse jamais le flow d'alignement).

    Returns:
        ``{concept_lower: [{"table","column","value_type","confidence",
        "usage_count"}, ...]}`` — vide si aucun concept appris.
    """
    if not concepts:
        return {}
    normed = {(c or "").strip().lower() for c in concepts if c and c.strip()}
    if not normed:
        return {}
    try:
        from sqlalchemy import select as _select

        from app.core.database import get_session
        from app.models.concept_glossary import ConceptGlossary

        out: dict[str, list[dict]] = {}
        async with get_session() as session:
            rows = (
                (
                    await session.execute(
                        _select(ConceptGlossary).where(
                            ConceptGlossary.concept.in_(list(normed))
                        )
                    )
                )
                .scalars()
                .all()
            )
        for r in rows:
            out.setdefault(r.concept, []).append(
                {
                    "table": r.table_name,
                    "column": r.column_name,
                    "value_type": r.value_type,
                    "confidence": r.confidence,
                    "usage_count": r.usage_count,
                }
            )
        for key in out:
            out[key].sort(key=lambda m: (m["usage_count"], m["confidence"]), reverse=True)
        return out
    except Exception as exc:  # fail-closed
        logger.warning("get_concept_glossary_mappings a échoué (fail-closed): %s", exc)
        return {}


# Cache TTL pour le catalogue de tables (en secondes)
_TABLE_CATALOGUE_TTL = 300  # 5 minutes

# Mots-clés pour la détection des retours utilisateurs (feedback)
_POSITIVE_KEYWORDS = frozenset(
    {
        "good",
        "correct",
        "valid",
        "positive",
        "oui",
        "yes",
        "ok",
        "parfait",
        "exact",
        "super",
        "bravo",
        "nickel",
        "✅",
    }
)

_ADJUST_KEYWORDS = frozenset({"🔄", "adjust", "ajuster", "à ajuster", "presque", "pas tout à fait"})


class AgentKnowledge:
    """
    Surcouche sémantique du TrainingStore pour l'agent Iris.

    Fournit :
    - Assemblage du contexte RAG formaté pour le prompt système
    - Enregistrement structuré d'insights sur les tables
    - Apprentissage depuis les retours utilisateurs
    - Vue synthétique d'une table ou de la couverture globale
    """

    def __init__(self) -> None:
        # Lazy-load : le singleton n'est résolu qu'au premier appel effectif
        self._store: Optional[TrainingStore] = None
        # Cache du catalogue de tables
        self._table_catalogue_cache: Optional[str] = None
        self._table_catalogue_time: float = 0

    @property
    def store(self) -> TrainingStore:
        if self._store is None:
            self._store = get_training_store()
        return self._store

    async def _get_table_catalogue(self, user: Any = None) -> str:
        """Retourne le catalogue des tables formaté, avec cache TTL 5min.

        Appelé à la construction du contexte RAG pour empêcher le LLM
        d'inventer des noms de tables.

        Optimisation : au lieu de lister les 790+ tables (qui consomme ~3K tokens
        dans le system prompt), ne liste que les tables documentées (enrichies).
        Les autres sont accessibles via `get_database_schema` ou `search_documentation`.

        ``user`` (optionnel) : si fourni ET que l'enforcement
        ``data_access_enforcement_enabled`` est ON ET que l'user a des règles
        deny actives, les tables interdites sont retirées du catalogue
        exposé au LLM (defense-in-depth — Iris ne peut pas mentionner une
        table qu'il ne voit pas). Le cache TTL reste global (sans user) :
        on lit le cache, puis on filtre la copie à retourner.
        """
        now = time.monotonic()
        cached_text: Optional[str] = None
        if (
            self._table_catalogue_cache
            and (now - self._table_catalogue_time) < _TABLE_CATALOGUE_TTL
        ):
            cached_text = self._table_catalogue_cache
            # Pas de user → cache hit direct.
            if user is None:
                return cached_text
            # Avec user, on doit refaire la liste filtrée — on relit la BDD
            # (peu coûteux car ``get_all_table_names`` est lui-même cacheable
            # côté store). Alternative : stocker la liste brute en cache
            # et formatter à la sortie. V2.

        try:
            # Phase α.4.B : propager user pour filtrage à la source.
            all_names = await self.store.get_all_table_names(user=user)
        except Exception as exc:
            logger.warning("Impossible de charger le catalogue de tables: %s", exc)
            return ""

        if not all_names:
            return ""

        # Séparer les tables documentées (enrichies) des tables brutes
        try:
            documented_names = await self.store.get_documented_table_names(user=user)
        except Exception:
            documented_names = set()

        documented = sorted(n for n in all_names if n in documented_names)
        undocumented_count = len(all_names) - len(documented)

        # ── Defense-in-depth : filtrer selon UserSchemaView (mode invisible) ──
        # Source unique de vérité : ``build_user_schema_view`` (Phase 0/4
        # du refactor). Plus strict que le legacy ``filter_table_catalogue``
        # — retire aussi les objets dérivés (vues/fonctions/synonymes qui
        # dépendent de tables interdites) une fois la Phase 1 en place.
        # NOTE : pas de filtrage si user None (call-sites legacy / tests).
        if user is not None:
            try:
                from app.services.data_access.llm_context import filter_to_visible
                from app.services.data_access.visible_schema import (
                    build_user_schema_view,
                )

                view = await build_user_schema_view(user)
                if view.has_restrictions:
                    documented = filter_to_visible(view, documented)
                    # Pour les undocumented, on filtre sur la liste complète
                    # puis on recompute le compte (le LLM ne saura pas qu'il
                    # y avait plus de tables — invariant invisible).
                    all_filtered = filter_to_visible(view, list(all_names))
                    undocumented_count = len(all_filtered) - len(documented)
                    if undocumented_count < 0:
                        undocumented_count = 0
            except Exception as exc:
                # Fail-open ICI sur le filtrage du contexte LLM uniquement :
                # on garde le catalogue complet. La protection runtime
                # (execute_sql RLS check) reste en place et bloquera quand
                # même les requêtes sur tables interdites.
                logger.warning(
                    "data_access: catalogue filter via view failed (LLM may "
                    "see denied tables, but runtime block remains): %s",
                    exc,
                )

        # Construire un catalogue compact : tables documentées listées,
        # les autres résumées par leur nombre (le LLM peut les chercher à la demande)
        parts = [
            "### CATALOGUE DES TABLES DISPONIBLES",
            "**RÈGLE** : Utilise UNIQUEMENT les tables connues dans tes requêtes SQL. "
            "N'invente PAS de nom de table. Utilise `search_documentation` ou "
            "`get_database_schema` pour trouver la bonne table.",
        ]
        if documented:
            parts.append(
                f"\n**Tables documentées** ({len(documented)}) :\n" + ", ".join(documented)
            )
        if undocumented_count > 0:
            parts.append(
                f"\n**{undocumented_count} tables supplémentaires** disponibles "
                "(non encore documentées). Utilise `get_database_schema` pour les explorer."
            )

        text = "\n".join(parts) + "\n"

        # Ne mettre en cache QUE le catalogue global (sans filtrage user).
        # Le catalogue user-specific est recalculé à chaque appel : peu
        # coûteux car les listes sont en mémoire (TTL 5min côté store).
        if user is None:
            self._table_catalogue_cache = text
            self._table_catalogue_time = now
        return text

    def invalidate_table_catalogue(self) -> None:
        """Invalide le cache du catalogue (à appeler après un schema sync)."""
        self._table_catalogue_cache = None
        self._table_catalogue_time = 0

    @staticmethod
    def _build_enriched_ddl_block(table_name: str, ddl_content: str, enrichment: dict) -> str:
        """
        Construit un bloc DDL enrichi avec rôle, colonnes annotées (type, FK, rôle, stats).

        Format cible :
            -- TABLE: TABLE_EXAMPLE (~45000 lignes)
            -- Rôle: Table principale avec données de référence
            -- Colonnes:
            --   id_column (varchar(17), PK) — Identifiant unique | 1250 distinct, 0% NULL
            --   category_id (int, FK→TABLE_REF.category_id) — Catégorie | 5 distinct, 12% NULL
            CREATE TABLE dbo.TABLE_EXAMPLE (...)
        """
        row_count = enrichment.get("row_count", 0)
        selection_reason = enrichment.get("_selection_reason", "")

        # Détecter si c'est une VUE (pas une TABLE)
        is_view = bool(
            re.search(r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\b", ddl_content, re.IGNORECASE)
        )

        kind = "VUE" if is_view else "TABLE"
        header = f"-- {kind}: {table_name}"
        if row_count:
            header += f" (~{row_count} lignes)"
        if selection_reason:
            header += f" [{selection_reason}]"
        lines = [header]

        if is_view:
            lines.append(
                "-- ⚠️ Ceci est une VUE — les noms après AS sont des ALIAS CALCULÉS, "
                "PAS des colonnes réelles. Utilise les colonnes des TABLES sources."
            )

        table_role = enrichment.get("table_role")
        if table_role:
            lines.append(f"-- Rôle: {table_role}")

        column_roles = enrichment.get("column_roles", {})
        column_values = enrichment.get("column_values", {})
        column_stats = enrichment.get("column_stats", {})
        relations = enrichment.get("relations", [])

        # Construire un index FK par colonne depuis les relations
        # Format relation content: "FK sortante: TABLE.col → col → PARENT. Constraint: ..."
        fk_by_column: dict[str, str] = {}
        reverse_fk_tables: list[str] = []  # Tables qui référencent celle-ci
        for rel in relations:
            content = rel.get("content", "") if isinstance(rel, dict) else str(rel)
            cat = rel.get("category", "") if isinstance(rel, dict) else ""

            fk_matches = re.findall(r"(\w+)\s*→\s*(\w+)", content)
            if fk_matches and "→" in cat:
                # relation:PARENT→CHILD — FK sortante
                cat_parts = cat.replace("relation:", "").split("→")
                if len(cat_parts) == 2:
                    parent_table = cat_parts[0]
                    for child_col, parent_col in fk_matches:
                        fk_by_column[child_col.lower()] = f"FK→{parent_table}.{parent_col}"
            elif "←" in cat:
                # relation:TABLE←REF — FK entrante : qui référence cette table ?
                cat_parts = cat.replace("relation:", "").split("←")
                if len(cat_parts) == 2:
                    reverse_fk_tables.append(cat_parts[1])

        # Extraire les types depuis le DDL — TOUJOURS, même sans enrichissement
        # Gère les identifiants entre crochets [ColumnName] (SQL Server)
        col_types: dict[str, str] = {}
        _SQL_TYPE_PATTERN = re.compile(
            r"^\s+\[?(\w+)\]?\s+((?:N?VARCHAR|N?CHAR|N?TEXT|"
            r"TINY|SMALL)?INT|BIGINT|FLOAT|NUMERIC|DECIMAL|"
            r"DATETIME2?|SMALLDATETIME|DATETIMEOFFSET|DATE|TIME|"
            r"BIT|MONEY|SMALLMONEY|REAL|IMAGE|"
            r"N?VARCHAR|N?CHAR|N?TEXT|"
            r"VARBINARY|BINARY|UNIQUEIDENTIFIER|XML|"
            r"TIMESTAMP|ROWVERSION|SQL_VARIANT|HIERARCHYID|"
            r"GEOGRAPHY|GEOMETRY)"
            r"(?:\(\d+(?:,\s*\d+)?\)|\(MAX\))?",
            re.MULTILINE | re.IGNORECASE,
        )
        # Indexer les types par clé lowercase — garantit la fusion DDL↔enrichment
        # même si le DDL a camelCase et l'enrichment UPPER
        col_types: dict[str, str] = {}  # lowercase_name → type
        col_original_name: dict[str, str] = {}  # lowercase → original (pour l'affichage)
        for m in _SQL_TYPE_PATTERN.finditer(ddl_content):
            name = m.group(1)
            col_types[name.lower()] = m.group(2).lower()
            col_original_name[name.lower()] = name

        # PK : pré-normalisé en lowercase
        pk_cols: set[str] = set()
        pk_match = re.search(r"PRIMARY\s+KEY\s*\(([^)]+)\)", ddl_content, re.IGNORECASE)
        if pk_match:
            pk_cols = {c.strip().strip("[]").lower() for c in pk_match.group(1).split(",")}

        # TOUJOURS afficher le bloc colonnes — même sans enrichissement sémantique,
        # les types + PK + FK sont essentiels pour que le LLM génère du SQL correct
        lines.append("-- Colonnes:")

        # Normaliser TOUTES les clés enrichment en lowercase pour fusion fiable
        roles_lc = {k.lower(): v for k, v in column_roles.items()}
        values_lc = {k.lower(): v for k, v in column_values.items()}
        stats_lc = {k.lower(): v for k, v in column_stats.items()}
        # fk_by_column est déjà en lowercase (normalisé à l'extraction)

        # Fusionner toutes les colonnes connues (types DDL + enrichment) — clés lowercase
        all_cols_lc = list(
            dict.fromkeys(
                list(col_types.keys())
                + [k.lower() for k in column_roles]
                + [k.lower() for k in column_values]
                + [k.lower() for k in column_stats]
            )
        )

        has_enrichment = bool(column_roles or column_values or column_stats)

        for col_lc in all_cols_lc[:30]:  # Limiter à 30 colonnes affichées
            # Nom d'affichage : original du DDL si possible, sinon la clé enrichment
            display_name = col_original_name.get(col_lc, col_lc)

            # Type
            type_str = col_types.get(col_lc, "")

            # Annotations (PK, FK)
            annotations = []
            if col_lc in pk_cols:
                annotations.append("PK")
            fk_ref = fk_by_column.get(col_lc)
            if fk_ref:
                annotations.append(fk_ref)

            # Construire la partie type+annotations
            type_parts = []
            if type_str:
                type_parts.append(type_str)
            type_parts.extend(annotations)
            type_info = f" ({', '.join(type_parts)})" if type_parts else ""

            # Rôle sémantique
            role = roles_lc.get(col_lc, "")
            if role:
                role_str = f" — {role}"
            elif has_enrichment:
                # Signaler uniquement si l'enrichissement existe (sinon c'est du bruit)
                role_str = " — [sémantique non documentée, ne pas deviner]"
            else:
                role_str = ""

            # Stats colonnes (cardinalité, % NULL)
            # NOTE: min/max exclus volontairement (confidentialité — données réelles)
            stats = stats_lc.get(col_lc, {})
            stats_str = ""
            if stats:
                parts = []
                # Supporter les deux formats de clés (sage_connector + legacy)
                # Note: pas de `or` car 0 est une valeur valide (falsy mais pas None)
                distinct = stats.get("distinct")
                if distinct is None:
                    distinct = stats.get("distinct_count")
                if distinct is not None:
                    parts.append(f"{distinct} distinct")
                null_pct = stats.get("null_pct")
                if null_pct is None:
                    null_pct = stats.get("null_percent")
                if null_pct is not None:
                    parts.append(f"{null_pct}% NULL")
                if parts:
                    stats_str = f" | {', '.join(parts)}"

            # Valeurs distinctes anonymisées — TOUJOURS les afficher si disponibles
            # C'est crucial pour que le LLM identifie les bonnes valeurs
            # (ex: quand l'utilisateur saisit une forme abrégée, il faut
            # pouvoir remonter à la valeur exacte stockée en BDD).
            values = values_lc.get(col_lc, [])
            if values:
                displayed = values[:DISTINCT_VALUES_MAX_DISPLAY]
                vals = ", ".join(
                    f'"{v}"' if not v.replace(".", "").replace("-", "").isdigit() else v
                    for v in displayed
                )
                suffix = f" +{len(values) - len(displayed)}" if len(values) > len(displayed) else ""
                stats_str += f" | Ex: {vals}{suffix}"

            lines.append(f"--   {display_name}{type_info}{role_str}{stats_str}")

        # Afficher les reverse FK (tables qui référencent celle-ci)
        if reverse_fk_tables:
            lines.append(f"-- Référencée par: {', '.join(reverse_fk_tables)}")

        # Ajouter le DDL brut pour référence
        lines.append(ddl_content)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Contexte RAG pour le prompt système de l'agent
    # ------------------------------------------------------------------

    async def get_knowledge_for_context(
        self,
        question: str,
        max_items: int = 10,
        *,
        user: Any = None,
    ) -> str:
        """
        Construit une section "Base de connaissances" prête à insérer dans
        le prompt système de l'agent.

        Combine (par ordre d'importance) :
        1. DDL des tables pertinentes (schémas)
        2. Documentation métier associée (sens des colonnes, règles)
        3. Exemples question/SQL validés (few-shot)

        Args:
            question: Question posée par l'utilisateur en langage naturel.
            max_items: Nombre maximum d'éléments récupérés par catégorie.
            user: optionnel — propagé aux appels training_store pour mode
                invisible (Phase α.4.B). Sans user, comportement legacy.

        Returns:
            Bloc de texte formaté, vide si aucune donnée trouvée.
        """
        # Phase α.4.B : propager user aux 3 appels training_store.
        ddl_items = await self.store.get_related_ddl(question, n_results=max_items, user=user)
        doc_items = await self.store.get_related_documentation(question, n_results=max_items)
        sql_items = await self.store.get_similar_question_sql(
            question, n_results=max_items, user=user
        )

        if not ddl_items and not doc_items and not sql_items:
            return ""

        from app.config import get_source_db_label

        db_label = get_source_db_label()
        sections: list[str] = [f"### Base de connaissances {db_label}\n"]

        if ddl_items:
            sections.append("#### Schémas de tables pertinents")
            for item in ddl_items:
                table = item.get("table_name") or "table"
                sections.append(f"-- {table}\n{item['content']}")
            sections.append("")

        if doc_items:
            sections.append("#### Documentation métier")
            for item in doc_items:
                category = item.get("category") or "général"
                sections.append(f"[{category}]\n{item['content']}")
            sections.append("")

        if sql_items:
            sections.append("#### Exemples de requêtes validées")
            for item in sql_items:
                q = item.get("question", "").strip()
                sql = item.get("sql", "").strip()
                if q and sql:
                    sections.append(f"-- Question : {q}\n{sql}")
            sections.append("")

        return "\n".join(sections)

    async def get_knowledge_with_sources(
        self,
        question: str,
        max_items: int = 10,
        *,
        user: Any = None,
    ) -> tuple[str, list[dict]]:
        """
        Comme get_knowledge_for_context mais retourne aussi les sources RAG.

        Combine (par ordre d'importance) :
        1. DDL des tables pertinentes (schémas)
        2. Documentation métier associée (sens des colonnes, règles)
        3. Exemples question/SQL validés (few-shot)

        Args:
            question: Question posée par l'utilisateur en langage naturel.
            max_items: Nombre maximum d'éléments récupérés par catégorie.
            user: optionnel — propagé aux appels training_store pour mode
                invisible (Phase α.4.B). Sans user, comportement legacy.

        Returns:
            Tuple (formatted_context, sources) où sources est une liste de
            dicts décrivant chaque source RAG utilisée.
        """
        store = self.store
        sources: list[dict] = []

        # Extraction directe des tables mentionnées (priorité aux matches
        # exacts)
        table_pattern = re.compile(r"\b([A-Z][A-Z0-9]*_[A-Z0-9_]+)\b")
        mentioned_tables = list(set(table_pattern.findall(question.upper())))

        # DDL: d'abord les tables mentionnées, puis TF-IDF
        ddl_items = []
        if mentioned_tables:
            # Phase α.4.B : propager user.
            exact_ddl = await store.get_ddl_by_table_names(mentioned_tables, n_results=5, user=user)
            for item in exact_ddl:
                ddl_items.append(item)
                sources.append(
                    {
                        "type": "ddl",
                        "table": item.get("table_name", ""),
                        "match": "exact",
                    }
                )

        tfidf_ddl = await store.get_related_ddl(question, n_results=max_items, user=user)
        seen_tables = {item.get("table_name", "").upper() for item in ddl_items}
        for item in tfidf_ddl:
            tname = item.get("table_name", "").upper()
            if tname not in seen_tables and len(ddl_items) < max_items:
                ddl_items.append(item)
                seen_tables.add(tname)
                sources.append(
                    {
                        "type": "ddl",
                        "table": item.get("table_name", ""),
                        "match": "tfidf",
                        "score": round(item.get("score", 0), 2),
                    }
                )

        # Documentation (get_related_documentation pas encore patchée — task #86)
        doc_items = await store.get_related_documentation(question, n_results=max_items)
        for item in doc_items[:max_items]:
            sources.append(
                {
                    "type": "documentation",
                    "category": item.get("category", ""),
                    "score": round(item.get("score", 0), 2),
                }
            )

        # Exemples question-SQL
        # Phase α.4.B : propager user.
        example_items = await store.get_similar_question_sql(
            question, n_results=max_items, user=user
        )
        for item in example_items[:max_items]:
            q_text = item.get("question", "")
            q_display = q_text[:80] + "..." if len(q_text) > 80 else q_text
            sources.append(
                {
                    "type": "example",
                    "question": q_display,
                    "score": round(item.get("score", 0), 2),
                }
            )

        # Format context (same format as get_knowledge_for_context)
        parts = []

        # Catalogue des tables (empêche le LLM d'inventer des noms)
        catalogue = await self._get_table_catalogue()
        if catalogue:
            parts.append(catalogue)

        if ddl_items:
            from app.config import get_source_db_label

            db_label = get_source_db_label()
            parts.append(f"### Base de connaissances {db_label}\n")
            parts.append("#### Schémas de tables pertinents")
            for item in ddl_items:
                table = item.get("table_name") or "table"
                parts.append(f"-- {table}\n{item['content']}")
            parts.append("")

        if doc_items:
            parts.append("#### Documentation métier")
            for item in doc_items[:max_items]:
                category = item.get("category") or "général"
                parts.append(f"[{category}]\n{item['content']}")
            parts.append("")

        if example_items:
            parts.append("#### Exemples de requêtes validées")
            for item in example_items[:max_items]:
                q = item.get("question", "").strip()
                sql = item.get("sql", "").strip()
                if q and sql:
                    parts.append(f"-- Question : {q}\n{sql}")
            parts.append("")

        return "\n".join(parts), sources

    async def get_enriched_context(
        self,
        question: str,
        max_items: int = 10,
        *,
        user: Any = None,
    ) -> tuple[str, list[dict], dict]:
        """
        Comme get_knowledge_with_sources mais inclut les rôles sémantiques,
        les alias métier résolus, les grappes de tables, et calcule un
        score de confiance enrichi.

        Args:
            question: Question utilisateur en NL.
            max_items: nombre max d'items RAG par catégorie.
            user: optionnel — propagé aux appels training_store pour mode
                invisible (Phase α.4.B). Sans user, comportement legacy.

        Returns:
            Tuple (formatted_context, sources, confidence_info) où confidence_info
            contient schema_coverage, knowledge_gaps, overall_confidence.
        """
        store = self.store
        sources: list[dict] = []

        # --- Phase 0 : Résoudre les alias métier ---
        # Avant même le TF-IDF, chercher si la question contient des termes
        # métier connus (ex: "dépenses" → Production.proPrixRevientTotal)
        alias_matches = await store.resolve_aliases(question)
        alias_tables: list[str] = []
        alias_context_parts: list[str] = []
        for match in alias_matches:
            if match.get("table"):
                alias_tables.append(match["table"])
                sources.append(
                    {
                        "type": "alias",
                        "alias": match["alias"],
                        "table": match["table"],
                        "column": match.get("column"),
                    }
                )
                alias_context_parts.append(f'- "{match["alias"]}" → {match.get("description", "")}')

        # --- Phase 0b : Découverte de tables via ValueMapping ---
        # Chercher dans l'index des valeurs réelles si le message de l'utilisateur
        # contient des mots qui correspondent à des valeurs en BDD.
        # Ex: "VALEUR_X" → trouvé dans TABLE_EXAMPLE.name_column → ajouter TABLE_EXAMPLE.
        value_tables: list[str] = []
        try:
            from app.services.ai.value_resolver import get_value_resolver

            resolver = get_value_resolver()
            value_discoveries = await resolver.discover_tables_from_message(question)
            seen_value_upper = {t.upper() for t in alias_tables}
            for disc in value_discoveries:
                tname = disc["table"].upper()
                if tname not in seen_value_upper:
                    seen_value_upper.add(tname)
                    value_tables.append(disc["table"])
                    sources.append(
                        {
                            "type": "value_match",
                            "table": disc["table"],
                            "column": disc["column"],
                            "matched_word": disc["matched_word"],
                        }
                    )
        except Exception as vm_err:
            logger.debug("Value-based table discovery skipped: %s", vm_err)

        # --- Phase 0c : Recherche dans la documentation stockée (TF-IDF) ---
        # Cherche dans column_values, table_role et join_pattern pour identifier
        # les tables pertinentes :
        # column_values:  "DUPONT" → column_values:Dossiers.dosNomDossier → Dossiers
        # table_role:     "expert comptable" → table_role:DossierSuppl → DossierSuppl
        # join_pattern:   "chiffre affaires expert" → join_pattern:FACTURES+DOSSIERSUPPL
        #                 → ajoute TOUTES les tables du pattern (Factures + DossierSuppl)
        try:
            value_docs = await store.get_related_documentation(question, n_results=5)
            already_upper = {t.upper() for t in alias_tables + value_tables}
            for vdoc in value_docs:
                score = vdoc.get("score", 0)
                cat = vdoc.get("category", "")

                # column_values:TABLE.COLUMN — seuil standard
                if cat.startswith("column_values:") and score >= 0.15:
                    parts = cat.split(":", 1)[1].split(".", 1)
                    if parts:
                        tbl = parts[0]
                        if tbl.upper() not in already_upper:
                            already_upper.add(tbl.upper())
                            value_tables.append(tbl)
                            sources.append(
                                {
                                    "type": "column_value_match",
                                    "table": tbl,
                                    "category": cat,
                                    "score": round(score, 2),
                                }
                            )

                # table_role:TABLE — seuil plus élevé (docs plus larges)
                elif cat.startswith("table_role:") and score >= 0.20:
                    tbl = cat.split(":", 1)[1]
                    if tbl.upper() not in already_upper:
                        already_upper.add(tbl.upper())
                        value_tables.append(tbl)
                        sources.append(
                            {
                                "type": "table_role_match",
                                "table": tbl,
                                "category": cat,
                                "score": round(score, 2),
                            }
                        )

                # join_pattern:TABLE1+TABLE2+... — ajoute TOUTES les tables du pattern
                # C'est la doc la plus précieuse : un chemin de jointure validé ✅
                elif cat.startswith("join_pattern:") and score >= 0.20:
                    jp_tables = cat.split(":", 1)[1].split("+")
                    for tbl in jp_tables:
                        if tbl and tbl not in already_upper:
                            already_upper.add(tbl)
                            value_tables.append(tbl)
                            sources.append(
                                {
                                    "type": "join_pattern_match",
                                    "table": tbl,
                                    "category": cat,
                                    "score": round(score, 2),
                                }
                            )

        except Exception as cv_err:
            logger.debug("Column value search skipped: %s", cv_err)

        # Extract table names mentioned in the question + alias-discovered + value-discovered
        table_pattern = re.compile(r"\b([A-Z][A-Z0-9]*_[A-Z0-9_]+)\b")
        mentioned_tables = list(
            set(table_pattern.findall(question.upper()) + alias_tables + value_tables)
        )

        # Get DDL with enrichment
        ddl_items = []
        enrichment_data = {}

        if mentioned_tables:
            # Phase α.4.B : propager user.
            exact_ddl = await store.get_ddl_by_table_names(mentioned_tables, n_results=5, user=user)
            for item in exact_ddl:
                ddl_items.append(item)
                sources.append(
                    {"type": "ddl", "table": item.get("table_name", ""), "match": "exact"}
                )

            # Get semantic enrichment for mentioned tables.
            # **Phase α.1.bis (#86)** — méthode patchée pour accepter `user=`
            # et filtrer les tables denied (defense-in-depth — le caller a
            # normalement déjà filtré, mais on ré-applique ici à la source).
            enrichment_data = await store.get_enrichment_for_tables(mentioned_tables, user=user)

        # TF-IDF DDL search
        tfidf_ddl = await store.get_related_ddl(question, n_results=max_items, user=user)
        seen_tables = {item.get("table_name", "").upper() for item in ddl_items}
        tfidf_table_names = []
        for item in tfidf_ddl:
            tname = item.get("table_name", "").upper()
            if tname not in seen_tables and len(ddl_items) < max_items:
                ddl_items.append(item)
                seen_tables.add(tname)
                tfidf_table_names.append(tname)
                sources.append(
                    {
                        "type": "ddl",
                        "table": item.get("table_name", ""),
                        "match": "tfidf",
                        "score": round(item.get("score", 0), 2),
                    }
                )

        # Get enrichment for TF-IDF discovered tables too
        if tfidf_table_names:
            extra_enrichment = await store.get_enrichment_for_tables(tfidf_table_names, user=user)
            enrichment_data.update(extra_enrichment)

        # --- Phase 3 : FK expansion — ajouter les tables liées par FK ---
        # Pour que le LLM puisse construire les JOINs, il doit connaître
        # la structure des tables référencées par FK.
        if seen_tables and len(ddl_items) < VISIBLE_TABLES_LIMIT:
            try:
                fk_linked = await store.get_fk_linked_tables(list(seen_tables))
                # Ne garder que les tables pas encore dans le contexte,
                # dans la limite du budget global VISIBLE_TABLES_LIMIT.
                new_fk_tables = [t for t in fk_linked if t not in seen_tables]
                slots_left = VISIBLE_TABLES_LIMIT - len(ddl_items)
                new_fk_tables = new_fk_tables[: max(0, slots_left)]

                if new_fk_tables:
                    # Phase α.4.B : propager user.
                    fk_ddl = await store.get_ddl_by_table_names(
                        new_fk_tables, n_results=len(new_fk_tables), user=user
                    )
                    for item in fk_ddl:
                        tname = item.get("table_name", "").upper()
                        if tname not in seen_tables:
                            ddl_items.append(item)
                            seen_tables.add(tname)
                            sources.append(
                                {
                                    "type": "ddl",
                                    "table": item.get("table_name", ""),
                                    "match": "fk_linked",
                                }
                            )

                    # Enrichment pour les tables FK ajoutées
                    fk_enrichment = await store.get_enrichment_for_tables(new_fk_tables, user=user)
                    enrichment_data.update(fk_enrichment)

                    fk_added = sum(
                        1 for item in fk_ddl if item.get("table_name", "").upper() in seen_tables
                    )
                    logger.info(
                        "FK expansion: %d tables liées ajoutées au contexte",
                        fk_added,
                    )
            except Exception as fk_err:
                logger.debug("FK expansion skipped: %s", fk_err)

        # Documentation
        doc_items = await store.get_related_documentation(question, n_results=max_items)
        for item in doc_items[:max_items]:
            sources.append(
                {
                    "type": "documentation",
                    "category": item.get("category", ""),
                    "score": round(item.get("score", 0), 2),
                }
            )

        # Examples — Phase α.4.B : propager user.
        example_items = await store.get_similar_question_sql(
            question, n_results=max_items, user=user
        )
        for item in example_items[:max_items]:
            q_text = item.get("question", "")
            q_display = q_text[:80] + "..." if len(q_text) > 80 else q_text
            sources.append(
                {
                    "type": "example",
                    "question": q_display,
                    "score": round(item.get("score", 0), 2),
                }
            )

        # --- Classer les tables par pertinence pour guider le LLM ---
        # Les tables mentionnées explicitement ou trouvées par alias sont les plus pertinentes,
        # suivies par TF-IDF, puis FK (contexte de jointure).
        table_relevance: dict[str, str] = {}  # table_upper → raison
        for s in sources:
            tname = s.get("table", "").upper()
            if not tname:
                continue
            match_type = s.get("match", s.get("type", ""))
            # Ne garder que la raison la plus forte
            if tname not in table_relevance:
                if match_type in ("exact", "alias", "value_match"):
                    table_relevance[tname] = "mentionnée dans la question"
                elif match_type == "tfidf":
                    table_relevance[tname] = "pertinence sémantique"
                elif match_type == "fk_linked":
                    table_relevance[tname] = "liée par FK (contexte JOIN)"

        # Build formatted context WITH enrichment
        parts = []

        # --- Catalogue des tables (empêche le LLM d'inventer des noms) ---
        catalogue = await self._get_table_catalogue()
        if catalogue:
            parts.append(catalogue)

        # --- Alias métier résolus (en premier pour que l'agent les voie tout de suite) ---
        if alias_context_parts:
            parts.append("### Termes métier reconnus dans votre question\n")
            for acp in alias_context_parts:
                parts.append(acp)
            parts.append("")

        if ddl_items:
            from app.config import get_source_db_label

            db_label = get_source_db_label()
            parts.append(f"### Base de connaissances {db_label}\n")
            parts.append("#### Schémas de tables pertinents")

            # Collecter les grappes à afficher
            cluster_docs_seen: set = set()

            # Trier les DDL : tables mentionnées/alias d'abord, puis TF-IDF, puis FK
            relevance_order = {
                "mentionnée dans la question": 0,
                "pertinence sémantique": 1,
                "liée par FK (contexte JOIN)": 2,
            }

            def ddl_sort_key(item: dict) -> int:
                tname = (item.get("table_name") or "").upper()
                reason = table_relevance.get(tname, "")
                return relevance_order.get(reason, 3)

            ddl_items_sorted = sorted(ddl_items, key=ddl_sort_key)

            for item in ddl_items_sorted:
                table = item.get("table_name") or "table"
                table_upper = table.upper()
                enrich = enrichment_data.get(table_upper, {})

                # Ajouter la raison de sélection pour guider le LLM
                reason = table_relevance.get(table_upper)
                if reason:
                    enrich = {**enrich, "_selection_reason": reason}

                # Construire le bloc enrichi inline
                enriched_block = self._build_enriched_ddl_block(table, item["content"], enrich)
                parts.append(enriched_block)

                # Ajouter la grappe de la table si disponible
                if table_upper not in cluster_docs_seen:
                    cluster_doc = await store.get_cluster_documentation(table_upper)
                    if cluster_doc:
                        parts.append(f"-- Grappe: {cluster_doc}")
                        cluster_docs_seen.add(table_upper)
            parts.append("")

        # --- Carte de jointures (FK) — résumé consolidé des relations ---
        # Extraire TOUTES les FK des enrichments et les présenter en une section claire.
        # Le LLM voit d'un coup d'œil comment joindre les tables.
        join_map_lines: list[str] = []
        seen_fk_pairs: set[str] = set()
        for table_upper, enrich in enrichment_data.items():
            for rel in enrich.get("relations", []):
                content = rel.get("content", "") if isinstance(rel, dict) else str(rel)
                cat = rel.get("category", "") if isinstance(rel, dict) else ""
                # Extraire les mappings col → col
                fk_matches = re.findall(r"(\w+)\s*→\s*(\w+)", content)
                if not fk_matches:
                    continue
                # Identifier la direction
                if "→" in cat:
                    # relation:PARENT→CHILD — FK sortante
                    cat_parts = cat.replace("relation:", "").split("→")
                    if len(cat_parts) == 2:
                        parent_table = cat_parts[0]
                        child_table = cat_parts[1]
                        for child_col, parent_col in fk_matches:
                            pair_key = f"{child_table}.{child_col}→{parent_table}.{parent_col}"
                            if pair_key not in seen_fk_pairs:
                                seen_fk_pairs.add(pair_key)
                                join_map_lines.append(
                                    f"  {child_table}.{child_col} → {parent_table}.{parent_col}"
                                )
                elif "←" in cat:
                    cat_parts = cat.replace("relation:", "").split("←")
                    if len(cat_parts) == 2:
                        this_table = cat_parts[0]
                        ref_table = cat_parts[1]
                        for ref_col, this_col in fk_matches:
                            pair_key = f"{ref_table}.{ref_col}→{this_table}.{this_col}"
                            if pair_key not in seen_fk_pairs:
                                seen_fk_pairs.add(pair_key)
                                join_map_lines.append(
                                    f"  {ref_table}.{ref_col} → {this_table}.{this_col}"
                                )

        if join_map_lines:
            parts.append("#### Carte de jointures (FK)")
            parts.append(
                "-- Relations entre les tables ci-dessus. "
                "Utilise UNIQUEMENT ces FK pour tes JOINs."
            )
            for line in sorted(join_map_lines):
                parts.append(line)
            parts.append("")

        if doc_items:
            # Filtrer les docs qui sont déjà incluses inline dans les blocs DDL enrichis
            # pour éviter les doublons qui gaspillent du contexte
            filtered_docs = []
            for item in doc_items[:max_items]:
                cat = item.get("category") or "général"
                if cat.startswith(
                    (
                        "table_role:",
                        "column_role:",
                        "relation:",
                        "alias:",
                        "cluster:",
                        "cluster_member:",
                        "column_values:",
                        "table_stats:",
                    )
                ):
                    continue
                filtered_docs.append(item)

            if filtered_docs:
                parts.append("#### Documentation métier")
                for item in filtered_docs:
                    cat = item.get("category") or "général"
                    parts.append(f"[{cat}]\n{item['content']}")
                parts.append("")

        if example_items:
            parts.append("#### Exemples de requêtes validées")
            for item in example_items[:max_items]:
                q = item.get("question", "").strip()
                sql = item.get("sql", "").strip()
                if q and sql:
                    parts.append(f"-- Question : {q}\n{sql}")
            parts.append("")

        # Calculate confidence scores
        all_tables = list(seen_tables)
        gaps = await store.detect_knowledge_gaps(all_tables)

        schema_coverage = gaps.get("schema_coverage", 0.0)
        example_relevance = max((item.get("score", 0) for item in example_items[:3]), default=0.0)

        overall_confidence = (
            schema_coverage * 0.5
            + (1.0 if not gaps.get("has_gaps") else 0.5) * 0.3
            + min(example_relevance * 2, 1.0) * 0.2
        )

        # Extraire les relations FK structurées depuis l'enrichissement
        fk_relations = []
        for tname, enrich in enrichment_data.items():
            for rel in enrich.get("relations", []):
                cat = rel.get("category", "") if isinstance(rel, dict) else ""
                content = rel.get("content", "") if isinstance(rel, dict) else str(rel)
                if "→" in cat:
                    cat_parts = cat.replace("relation:", "").split("→")
                    if len(cat_parts) == 2:
                        fk_matches = re.findall(r"(\w+)\s*→\s*(\w+)", content)
                        nullable = "nullable" in content.lower() or "NULL" in content
                        hint = ""
                        hint_match = re.search(r"join_hint:\s*(\w+)", content)
                        if hint_match:
                            hint = hint_match.group(1)
                        for child_col, parent_col in fk_matches:
                            fk_relations.append(
                                {
                                    "source_table": tname,
                                    "target_table": cat_parts[0],
                                    "source_column": child_col,
                                    "target_column": parent_col,
                                    "nullable": nullable,
                                    "join_hint": hint,
                                }
                            )

        confidence_info = {
            "schema_coverage": round(schema_coverage, 2),
            "example_relevance": round(example_relevance, 3),
            "overall_confidence": round(overall_confidence, 2),
            "knowledge_gaps": gaps.get("missing_table_roles", []),
            "has_gaps": gaps.get("has_gaps", False),
            # Données exposées pour l'orchestrateur (enrichissement + relations)
            "enrichment_data": enrichment_data,
            "fk_relations": fk_relations,
            "ddl_tables": list(seen_tables),
        }

        # Ajouter un résumé de confiance visible par le LLM pour qu'il ajuste son comportement
        if confidence_info["has_gaps"]:
            missing = confidence_info["knowledge_gaps"][:5]
            parts.append(
                "### État des connaissances\n"
                f"Couverture schéma: {confidence_info['schema_coverage']:.0%}. "
                f"Tables sans documentation: {', '.join(missing)}.\n"
                "**Si tu manques d'information sur ces tables, utilise `introspect_table` "
                "ou `search_documentation` avant de générer du SQL.**\n"
            )

        formatted_context = "\n".join(parts)

        # Garde-fou : limiter la taille du contexte (max ~50K chars ≈ ~12K tokens)
        MAX_CONTEXT_CHARS = 50_000
        if len(formatted_context) > MAX_CONTEXT_CHARS:
            logger.warning(
                "Contexte RAG trop volumineux (%d chars > %d), troncature par sections",
                len(formatted_context),
                MAX_CONTEXT_CHARS,
            )
            # Troncature intelligente par sections DDL : on retire les tables
            # FK-linked (les moins pertinentes) en partant de la fin.
            # Chaque table est séparée par "-- TABLE:" ou "-- VUE:".
            sections = re.split(r"(?=^-- (?:TABLE|VUE): )", formatted_context, flags=re.MULTILINE)
            trimmed_parts = []
            total_chars = 0
            for section in sections:
                if total_chars + len(section) > MAX_CONTEXT_CHARS:
                    break
                trimmed_parts.append(section)
                total_chars += len(section)
            formatted_context = "".join(trimmed_parts)
            if total_chars < len(formatted_context):
                formatted_context += (
                    "\n\n-- [Contexte tronqué — utilise `introspect_table` "
                    "pour les tables manquantes]\n"
                )

        return formatted_context, sources, confidence_info

    # ------------------------------------------------------------------
    # Enregistrement de nouveaux insights
    # ------------------------------------------------------------------

    async def learn(
        self,
        table_name: str,
        insight: str,
        source: str = "agent",
        user_id: Optional[int] = None,
    ) -> None:
        """
        Mémorise un insight métier sur une table ou une colonne.

        L'insight est stocké comme documentation avec la catégorie
        "knowledge:{table_name}" pour rester isolé et facilement retrouvable.

        Args:
            table_name: Nom de la table concernée (ex: "TABLE_EXAMPLE").
            insight: Texte décrivant le sens métier (ex: "id_column est l'identifiant
                     unique, name_column est le nom complet de l'enregistrement").
            source: Origine de l'insight ("agent", "user", "manual", …).
            user_id: Identifiant de l'utilisateur à l'origine, le cas échéant.

        Example:
            await knowledge.learn(
                "TABLE_EXAMPLE",
                "id_column est l'identifiant unique, name_column est le nom complet.",
                source="agent",
            )
        """
        if not table_name or not table_name.strip():
            raise ValueError("table_name ne peut pas être vide")
        if not insight or not insight.strip():
            raise ValueError("insight ne peut pas être vide")

        category = f"knowledge:{table_name.strip().upper()}"
        doc = f"[{table_name.upper()}] {insight.strip()}"

        await self.store.add_documentation(
            doc=doc,
            category=category,
            tags=[table_name.upper(), "knowledge", source],
            source=source,
            user_id=user_id,
        )
        logger.info("Nouvel insight enregistré pour %s (source=%s)", table_name, source)

    # ------------------------------------------------------------------
    # Apprentissage depuis les retours utilisateurs
    # ------------------------------------------------------------------

    async def learn_from_feedback(
        self,
        question: str,
        sql: str,
        feedback: str,
        user_id: Optional[int] = None,
        is_admin: bool = False,
    ) -> None:
        """
        Traite un retour utilisateur sur une paire question/SQL.

        - Retour positif ("good", "correct", "valid", "oui", "yes", "ok",
          "parfait", "exact") → stocke la paire dans le TrainingStore avec
          un score qualité de 1.0. Modération admin/user (axe 14 + promesse
          d'onboarding /admin/ai-training « arrive en attente d'approbation ») :
          ``pending_review = not is_admin`` — un 👍 d'admin est auto-approuvé
          (l'admin EST le modérateur), un 👍 de non-admin part EN ATTENTE
          d'approbation. Évite qu'un non-admin injecte des paires approuvées
          dans le RAG global partagé (isolation axe 18).
        - Retour négatif → journalise uniquement, ne stocke pas.

        Args:
            question: Question en langage naturel d'origine.
            sql: Requête SQL générée par l'agent.
            feedback: Retour de l'utilisateur (mot-clé ou phrase).
            user_id: Identifiant de l'utilisateur.
            is_admin: True si le feedback émane d'un admin → paire auto-approuvée.
                Défaut False = fail-closed (paire en attente d'approbation admin).
        """
        if not question or not sql:
            logger.warning("learn_from_feedback : question ou sql vide, ignoré")
            return

        feedback_lower = feedback.strip().lower()
        is_positive = any(kw in feedback_lower for kw in _POSITIVE_KEYWORDS)
        is_adjust = any(kw in feedback_lower for kw in _ADJUST_KEYWORDS)

        if is_adjust:
            # "🔄 À ajuster" — stocker la paire Q/SQL avec quality_score=0.8
            # Le SQL est proche mais pas parfait — attendre validation finale
            # pour les rôles sémantiques (pas de génération ici)
            try:
                await self.store.add_question_sql(
                    question=question,
                    sql=sql,
                    quality_score=0.8,
                    source="feedback_adjust",
                    user_id=user_id,
                    pending_review=True,
                )
                logger.info(
                    "Feedback 🔄 stocké comme paire Q/SQL (score=0.8, user_id=%s): %.60s…",
                    user_id,
                    question,
                )
            except ValueError as exc:
                logger.warning("Feedback 🔄 ignoré, SQL refusé: %s", exc)
            except Exception as exc:
                logger.warning("Impossible de stocker le feedback 🔄: %s", exc)
            # Aussi stocker comme règle de correction pour mémoire
            try:
                await self.store.add_correction_rule(
                    question_pattern=question,
                    bad_sql=sql,
                    good_sql="",
                    error_type="user_adjust",
                    explanation=f"Feedback utilisateur : {feedback[:200]}",
                    user_id=user_id,
                    pending_review=not is_admin,
                )
            except Exception:
                pass
        elif is_positive:
            try:
                # Modération : admin → auto-approuvé ; non-admin → en attente
                # d'approbation (cf. docstring + onboarding /admin/ai-training).
                await self.store.add_question_sql(
                    question=question,
                    sql=sql,
                    quality_score=1.0,
                    source="feedback",
                    user_id=user_id,
                    pending_review=not is_admin,
                )
                logger.info(
                    "Paire Q/SQL apprise depuis feedback positif "
                    "(user_id=%s, is_admin=%s, pending_review=%s): %.60s…",
                    user_id,
                    is_admin,
                    not is_admin,
                    question,
                )

                # Extract table names from SQL and generate roles
                try:
                    from app.services.ai.agent_tools import _extract_real_tables_from_sql

                    extracted_tables = list(_extract_real_tables_from_sql(sql))
                    if extracted_tables:
                        await self._generate_roles_from_validated_query(
                            question=question,
                            sql=sql,
                            tables=extracted_tables,
                            user_id=user_id,
                            is_admin=is_admin,
                        )
                except Exception as role_err:
                    logger.warning("Role generation from feedback failed: %s", role_err)

            except ValueError as exc:
                # SQL contenant des opérations interdites — on ne stocke pas
                logger.warning("Feedback ignoré, SQL refusé par le validateur: %s", exc)
        else:
            # Stocker le feedback négatif comme règle de correction potentielle
            # (pattern MAGIC: apprendre des erreurs pour ne pas les répéter)
            try:
                await self.store.add_correction_rule(
                    question_pattern=question,
                    bad_sql=sql,
                    good_sql="",  # Pas de correction connue encore
                    error_type="negative_feedback",
                    explanation=f"Feedback négatif: {feedback[:200]}",
                    user_id=user_id,
                    pending_review=not is_admin,
                )
                logger.info(
                    "Feedback négatif stocké comme règle de correction (user_id=%s): %.60s…",
                    user_id,
                    question,
                )
            except Exception as exc:
                logger.warning("Impossible de stocker le feedback négatif: %s", exc)

    async def learn_from_conversation_feedback(
        self,
        conversation_id: int,
        feedback: str,
        is_admin: bool = False,
        message_id: Optional[int] = None,
    ) -> None:
        """
        Apprend depuis le feedback d'une conversation.

        Cherche le **dernier tool utile** au feedback :

        1. ``run_pipeline`` en priorité : contexte le plus riche (run_id qui
           pointe vers ``PipelineRun.output_dir/run.json`` avec query +
           final_sql + ``concept_resolution`` data-driven Phase 2.5).
        2. ``execute_sql`` en fallback : pour les queries simples résolues
           directement par l'agent sans passer par la pipeline complète.

        Dans les deux cas appelle ``learn_from_feedback`` (qui écrit le couple
        Q/SQL dans ``training_data`` selon le type de feedback).

        En plus, sur feedback positif d'un run pipeline : persiste les
        résolutions concept→colonne validées dans ``concept_glossary``
        (global, partagé entre toutes les conversations) via ``_persist_concept_resolutions_on_validate``.

        Args:
            conversation_id: ID de la conversation à analyser.
            feedback: Retour de l'utilisateur ("positive" / "adjust" /
                "negative" — cf. ``_POSITIVE_KEYWORDS`` / ``_ADJUST_KEYWORDS``).
            is_admin: True si le feedback émane d'un admin → paires Q/SQL
                auto-approuvées ; sinon en attente d'approbation (fail-closed).
            message_id: D4 (L1O2) — id du message assistant ciblé par le feedback.
                Si fourni, la résolution question/tool est BORNÉE à ``created_at <=``
                celui du message ciblé → on apprend la paire Q/SQL du BON tour
                (cas d'un vote sur un tour ANCIEN au replay). ``None`` (live /
                auto-feedback / legacy) → dernier tour de la conv (comportement
                historique, correct car le dernier message EST le bon).
        """
        from sqlalchemy import select, desc
        from app.core.database import get_session
        from app.models.conversation import (
            Conversation,
            ConversationMessage,
            MessageRole,
        )

        try:
            async with get_session() as session:
                # Récupérer l'owner de la conversation (FK ownership pour les
                # appels aval qui ont besoin d'un user_id, et pour le check
                # cross-user sur PipelineRun).
                conv = await session.get(Conversation, conversation_id)
                owner_user_id = conv.user_id if conv is not None else None

                # Trouver le dernier message utilisateur — en EXCLUANT les
                # déclencheurs de la carte auto-feedback (« C'est bon ! », etc.).
                # Race fix (review adversariale du snapshot 20b8902) :
                # ``sendAutoFeedback`` POST ce feedback PUIS ``ws.send`` le message
                # déclencheur ; si ce message USER est persisté AVANT ce SELECT,
                # sans exclusion il serait pris pour LA question apprise (au lieu de
                # la vraie question d'origine). On exclut donc les valeurs de la
                # triade SSoT ``AUTO_FEEDBACK_OPTIONS`` → fix DÉTERMINISTE,
                # indépendant du timing JS (POST vs ws.send).
                from app.constants import AUTO_FEEDBACK_OPTIONS

                # D4 — borne du tour ciblé par l'``id`` du message (PAS ``created_at``).
                # Les messages d'un même tour PARTAGENT le ``created_at`` (func.now()
                # au flush, résolution seconde — cf. conversation.py:173-181 / base.py) ;
                # seul l'``id`` auto-incrémenté est strictement monotone = ordre
                # d'insertion réel. Borner par ``id <= target_id`` isole donc le tour
                # de façon tie-free (le message assistant FINAL du tour a le plus grand
                # ``id`` du tour ; le tour suivant a des ``id`` strictement plus grands),
                # là où ``created_at <=`` laisserait passer le user du tour suivant en
                # cas d'égalité de seconde → mauvaise paire Q/SQL apprise (Q5). Le tri
                # ajoute ``desc(id)`` en tiebreaker déterministe. ``id`` absent /
                # introuvable / hors-conv → borne None = comportement historique.
                target_id = None
                if message_id is not None:
                    target = await session.get(ConversationMessage, message_id)
                    if target is not None and target.conversation_id == conversation_id:
                        target_id = target.id  # == message_id (lookup par PK)

                _auto_fb_triggers = [opt["value"] for opt in AUTO_FEEDBACK_OPTIONS]
                _user_stmt = select(ConversationMessage).where(
                    ConversationMessage.conversation_id == conversation_id,
                    ConversationMessage.role == MessageRole.USER,
                    ConversationMessage.content.notin_(_auto_fb_triggers),
                )
                if target_id is not None:
                    _user_stmt = _user_stmt.where(ConversationMessage.id <= target_id)
                user_msg = await session.execute(
                    _user_stmt.order_by(
                        desc(ConversationMessage.created_at), desc(ConversationMessage.id)
                    ).limit(1)
                )
                user_msg = user_msg.scalar_one_or_none()

                if user_msg is None or not user_msg.content:
                    return

                # Chercher le dernier tool « informatif » pour le feedback.
                # Priorité : run_pipeline (contexte le plus riche) > execute_sql.
                _pipeline_stmt = select(ConversationMessage).where(
                    ConversationMessage.conversation_id == conversation_id,
                    ConversationMessage.role == MessageRole.TOOL,
                    ConversationMessage.tool_name == "run_pipeline",
                )
                if target_id is not None:
                    _pipeline_stmt = _pipeline_stmt.where(ConversationMessage.id <= target_id)
                pipeline_msg = await session.execute(
                    _pipeline_stmt.order_by(
                        desc(ConversationMessage.created_at), desc(ConversationMessage.id)
                    ).limit(1)
                )
                pipeline_msg = pipeline_msg.scalar_one_or_none()

                _exec_stmt = select(ConversationMessage).where(
                    ConversationMessage.conversation_id == conversation_id,
                    ConversationMessage.role == MessageRole.TOOL,
                    ConversationMessage.tool_name == "execute_sql",
                )
                if target_id is not None:
                    _exec_stmt = _exec_stmt.where(ConversationMessage.id <= target_id)
                exec_sql_msg = await session.execute(
                    _exec_stmt.order_by(
                        desc(ConversationMessage.created_at), desc(ConversationMessage.id)
                    ).limit(1)
                )
                exec_sql_msg = exec_sql_msg.scalar_one_or_none()

            # Décider lequel des deux est le plus récent (donc le plus
            # probablement lié au feedback). On compare par ``id`` (monotone,
            # tie-free) et non ``created_at`` (égal au sein d'un tour → départage
            # non déterministe).
            chosen_msg = None
            if pipeline_msg and exec_sql_msg:
                if pipeline_msg.id >= exec_sql_msg.id:
                    chosen_msg = pipeline_msg
                else:
                    chosen_msg = exec_sql_msg
            else:
                chosen_msg = pipeline_msg or exec_sql_msg

            if chosen_msg is None:
                return

            import json

            if chosen_msg.tool_name == "run_pipeline":
                # Cas pipeline : extraire run_id du tool_result, charger le
                # PipelineRun (avec ownership check), lire query + final_sql
                # depuis BDD et concept_resolution depuis run.json snapshot.
                try:
                    tool_result_raw = json.loads(chosen_msg.tool_result or "{}")
                except (json.JSONDecodeError, TypeError):
                    # CRITICAL C8 adversarial review : ne plus silently skip,
                    # logger explicitement pour qu'un admin puisse tracer un
                    # tool_result mal-formé (signal d'un bug amont dans le bus
                    # pipeline → agent_service).
                    logger.warning(
                        "learn_from_conversation_feedback: tool_result for "
                        "run_pipeline (msg_id=%s) is malformed JSON — skip",
                        chosen_msg.id,
                    )
                    return
                run_id = tool_result_raw.get("run_id")
                if not isinstance(run_id, int):
                    logger.warning(
                        "learn_from_conversation_feedback: tool_result for "
                        "run_pipeline (msg_id=%s) missing 'run_id' (got %r) "
                        "— skip apprentissage",
                        chosen_msg.id,
                        run_id,
                    )
                    return
                await self._learn_from_pipeline_run(
                    run_id=run_id,
                    user_id=owner_user_id,
                    question=user_msg.content,
                    feedback=feedback,
                    is_admin=is_admin,
                )
            else:
                # Cas execute_sql : comportement historique. SQL extrait du
                # tool_input. Pas de concept_resolution à persister (la
                # pipeline n'a pas tourné).
                try:
                    tool_input = json.loads(chosen_msg.tool_input or "{}")
                except (json.JSONDecodeError, TypeError):
                    tool_input = {}
                sql = tool_input.get("sql", "")
                if sql:
                    await self.learn_from_feedback(
                        question=user_msg.content,
                        sql=sql,
                        feedback=feedback,
                        user_id=owner_user_id,
                        is_admin=is_admin,
                    )
        except Exception as exc:
            logger.warning("learn_from_conversation_feedback failed: %s", exc)

    async def _learn_from_pipeline_run(
        self,
        run_id: int,
        user_id: Optional[int],
        question: str,
        feedback: str,
        is_admin: bool = False,
    ) -> None:
        """Apprend depuis un ``PipelineRun`` validé par feedback.

        Charge le ``PipelineRun`` (avec ownership check ``user_id`` cross-user),
        lit ``final_sql`` BDD + ``concept_resolution`` depuis ``run.json``
        snapshot, appelle ``learn_from_feedback`` (training_data) et — sur
        feedback positif — ``_persist_concept_resolutions_on_validate``
        (concept_glossary global, partagé entre toutes les conversations).

        Fail-safe : tout échec (FK manquante, snapshot absent / corrompu,
        ownership KO) est loggé warning et ne crashe pas le caller.
        """
        from app.core.database import get_session
        from app.models.pipeline_run import PipelineRun

        try:
            async with get_session() as session:
                run = await session.get(PipelineRun, run_id)
                if run is None:
                    logger.warning("_learn_from_pipeline_run: run_id=%s not found", run_id)
                    return
                # Ownership cross-user FAIL-CLOSED (BLOCKING fix adversarial
                # review #77) : si on ne connaît pas l'identité du caller
                # (user_id is None) OU si le caller n'est pas l'owner du run,
                # on refuse. Auparavant : `if user_id is not None and ...`
                # → fail-open quand user_id=None. CLAUDE.md doctrine fail-closed.
                if user_id is None or run.user_id != user_id:
                    logger.warning(
                        "_learn_from_pipeline_run: ownership refused "
                        "(run.user_id=%s, feedback user_id=%s)",
                        run.user_id,
                        user_id,
                    )
                    return
                final_sql = run.final_sql or ""
                output_dir = run.output_dir or ""

            # final_sql doit exister (sinon le run n'a pas abouti — rien à
            # apprendre côté Q/SQL ; on ne tente même pas le glossaire).
            if not final_sql:
                logger.info(
                    "_learn_from_pipeline_run: run_id=%s a pas de final_sql "
                    "(run non abouti) — pas d'apprentissage",
                    run_id,
                )
                return

            # 1) Couple Q/SQL → training_data via le pipeline d'apprentissage
            # existant (idempotent, validation SQL incluse).
            await self.learn_from_feedback(
                question=question,
                sql=final_sql,
                feedback=feedback,
                user_id=user_id,
                is_admin=is_admin,
            )

            # 2) Sur feedback positif uniquement, persister les résolutions
            # concept→colonne data-driven Phase 2.5 dans concept_glossary.
            # Les feedbacks 🔄 / ❌ ne valident pas le mapping → on n'écrit
            # rien (sinon on polluerait le glossaire avec des mappings douteux).
            feedback_lower = (feedback or "").strip().lower()
            is_positive = any(kw in feedback_lower for kw in _POSITIVE_KEYWORDS)
            if not is_positive:
                return

            concept_resolution = self._read_concept_resolution_from_snapshot(output_dir)
            if not concept_resolution:
                logger.info(
                    "_learn_from_pipeline_run: pas de concept_resolution "
                    "exploitable pour run_id=%s — glossaire non alimenté",
                    run_id,
                )
                return

            await self._persist_concept_resolutions_on_validate(
                concept_resolution=concept_resolution,
                user_id=user_id,
                is_admin=is_admin,
            )
        except Exception as exc:
            logger.warning("_learn_from_pipeline_run failed (run_id=%s): %s", run_id, exc)

    @staticmethod
    def _read_concept_resolution_from_snapshot(output_dir: str) -> Optional[dict]:
        """Lit ``concept_resolution`` depuis ``<output_dir>/run.json``.

        Le snapshot du run pipeline persiste l'état complet — y compris la
        résolution Phase 2.5. Format attendu (ce que ``PipelineState.save()``
        écrit) :

            {
                "concept_resolution": {
                    "concept_resolution": {
                        "<concept>": {
                            "best": {"table": "...", "col": "...",
                                     "value_type": "...", ...},
                            "top_candidates": [...],
                            "low_confidence": bool,
                            "requires_disambiguation": bool,
                            ...
                        }, ...
                    }, ...
                }
            }

        Retourne le dict interne `{concept: {best, ...}}` ou ``None`` si
        snapshot absent / illisible / structure inattendue.

        Sécurité : cap de taille fichier (50 MB) pour éviter d'OOM sur les
        runs volumineux. Aligné avec la doctrine IRIS-L3 du fix
        ``inspect_pipeline_artifact`` (10 MB de base + marge pour les
        snapshots les plus gros — cf. run #4 = 65 MB observé).
        """
        if not output_dir:
            return None
        try:
            from pathlib import Path
            import json as _json

            run_json = Path(output_dir) / "run.json"
            if not run_json.exists():
                return None
            # Cap de sécurité : refuser les snapshots > 80 MB (les runs
            # observés vont jusqu'à 65 MB). Au-delà, on n'alimente pas le
            # glossaire — la pipeline a produit un état dégénéré.
            size_mb = run_json.stat().st_size / (1024 * 1024)
            if size_mb > 80:
                logger.warning(
                    "_read_concept_resolution_from_snapshot: %s trop gros "
                    "(%.1f MB), skip glossaire",
                    run_json,
                    size_mb,
                )
                return None
            data = _json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        cr_outer = data.get("concept_resolution")
        if not isinstance(cr_outer, dict):
            return None
        # Le snapshot stocke parfois sous la clé "concept_resolution" interne
        # (cf. Phase 2.5 output format), parfois en flat. On tolère les deux.
        cr_inner = cr_outer.get("concept_resolution")
        if isinstance(cr_inner, dict):
            return cr_inner
        return cr_outer if cr_outer else None

    async def _persist_concept_resolutions_on_validate(
        self,
        concept_resolution: dict,
        user_id: Optional[int],
        is_admin: bool = False,
    ) -> None:
        """Upsert les ``best`` mappings concept→(table, col) dans
        ``concept_glossary`` (table globale partagée entre toutes les conversations).

        Pour chaque concept résolu (``best`` non vide et exploitable :
        table + col non-vides), on fait un UPSERT sur la clé unique
        (concept_lower, table, col) :

        - Existe → ``usage_count += 1``, refresh ``updated_at``, raffraîchit
          ``confidence`` et ``value_type`` si le run apporte des données
          plus à jour.
        - N'existe pas → INSERT avec ``usage_count=1``, ``source=
          "feedback_validate"``, ``created_by=user_id``.

        Fail-soft : un seul concept qui échoue ne bloque pas les autres
        (log warning, continue).
        """
        if not isinstance(concept_resolution, dict) or not concept_resolution:
            return

        # Cohérence modération 2026-05-31 (review adversariale du snapshot
        # 20b8902) : le ``concept_glossary`` est GLOBAL (partagé entre tous les
        # users). Comme la paire Q/SQL — gatée ``pending_review=not is_admin``
        # dans ``learn_from_feedback`` —, seules les validations ADMIN doivent
        # alimenter ce glossaire partagé. Un non-admin ne doit pas y injecter ses
        # mappings concept→(table, col) (isolation axe 18). La table n'a pas
        # encore de lecteur runtime, mais l'écriture Q/SQL au-dessus était déjà
        # gatée et pas celle-ci : on ferme l'asymétrie en amont.
        if not is_admin:
            logger.debug(
                "concept_glossary : écriture non-admin ignorée (user_id=%s) — "
                "seules les validations admin alimentent le glossaire global",
                user_id,
            )
            return

        from app.core.database import get_session
        from app.models.concept_glossary import ConceptGlossary

        # Préparer les triplets exploitables hors session (évite I/O lourdes
        # dans la transaction si la BDD est sous pression).
        triplets: list[dict] = []
        for concept_raw, entry in concept_resolution.items():
            if not isinstance(entry, dict):
                continue
            best = entry.get("best")
            if not isinstance(best, dict):
                continue
            table = best.get("table")
            col = best.get("col")
            if not isinstance(table, str) or not table.strip():
                continue
            if not isinstance(col, str) or not col.strip():
                continue
            concept_key = str(concept_raw).strip().lower()
            if not concept_key:
                continue
            # CRITICAL C5 adversarial review : utiliser le `confidence_score`
            # réel calculé par Phase 2.5 (`_compute_phase_2_5_confidence` —
            # pipeline.py:3144) plutôt qu'un binaire 0.7/1.0 qui écraserait
            # toute la finesse. Score retourné en [0,100] (cf. Phase 2.5)
            # → normaliser en [0,1].
            confidence: float = 1.0
            raw_conf = entry.get("confidence_score")
            if isinstance(raw_conf, (int, float)):
                if raw_conf > 1.0:
                    # Score Phase 2.5 sur [0,100] → ramener à [0,1]
                    confidence = max(0.0, min(1.0, raw_conf / 100.0))
                else:
                    # Déjà sur [0,1] (ou < 1 par hasard) → clamper
                    confidence = max(0.0, min(1.0, float(raw_conf)))
            elif entry.get("low_confidence"):
                # Fallback : si Phase 2.5 ne fournit pas confidence_score
                # mais expose le flag low_confidence, on dégrade modestement.
                confidence = 0.7
            triplets.append(
                {
                    "concept": concept_key,
                    "table_name": table.strip(),
                    "column_name": col.strip(),
                    "value_type": (best.get("value_type") or None),
                    "is_derived": bool(entry.get("is_derived", False)),
                    "confidence": confidence,
                }
            )

        if not triplets:
            return

        # BLOCKING fix #77 adversarial review : utiliser INSERT ... ON CONFLICT
        # DO UPDATE pour upsert atomique (SQLite + PostgreSQL natif). Évite la
        # race condition SELECT-then-INSERT qui produit IntegrityError sur
        # concurrence (deux ✅ simultanés sur le même triplet → la 2e Insert
        # crashe et tue la transaction parente). Avec on_conflict, c'est
        # idempotent par construction.
        from sqlalchemy import func
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        try:
            async with get_session() as session:
                for tri in triplets:
                    try:
                        stmt = sqlite_insert(ConceptGlossary).values(
                            concept=tri["concept"],
                            table_name=tri["table_name"],
                            column_name=tri["column_name"],
                            value_type=tri["value_type"],
                            is_derived=tri["is_derived"],
                            confidence=tri["confidence"],
                            source="feedback_validate",
                            usage_count=1,
                            created_by=user_id,
                        )
                        # ON CONFLICT (concept, table_name, column_name) → incrémente
                        # usage_count, prend max(confidence) pour ne pas dégrader,
                        # raffraîchit value_type uniquement si actuellement NULL.
                        stmt = stmt.on_conflict_do_update(
                            index_elements=["concept", "table_name", "column_name"],
                            set_={
                                "usage_count": ConceptGlossary.usage_count + 1,
                                "confidence": func.max(
                                    ConceptGlossary.confidence, stmt.excluded.confidence
                                ),
                                "value_type": func.coalesce(
                                    ConceptGlossary.value_type, stmt.excluded.value_type
                                ),
                            },
                        )
                        await session.execute(stmt)
                    except Exception as inner_exc:
                        logger.warning(
                            "concept_glossary upsert failed (concept=%s): %s",
                            tri["concept"],
                            inner_exc,
                        )
                        # Pas de rollback — l'opération atomique ON CONFLICT
                        # ne devrait pas raise (l'index unique est respecté
                        # nativement). Si elle raise, c'est une autre erreur
                        # (FK invalide, type mismatch) — on log et continue.
                await session.commit()
                logger.info(
                    "concept_glossary : %d mapping(s) upsertés (user_id=%s)",
                    len(triplets),
                    user_id,
                )
        except Exception as exc:
            logger.warning("_persist_concept_resolutions_on_validate failed: %s", exc)

    async def _generate_roles_from_validated_query(
        self,
        question: str,
        sql: str,
        tables: list[str],
        *,
        user_id: Optional[int] = None,
        is_admin: bool = False,
    ) -> None:
        """Generate/update table roles, column roles, AND join patterns from a validated query.

        Called ONLY on positive feedback (✅). This is the ONLY place where
        LLM is called to generate semantic knowledge — never during sync.

        Generates 3 types of documentation:
        - table_role:TABLE — Description métier de la table dans ce contexte
        - column_role:TABLE.COLUMN — Rôle métier des colonnes clés
        - join_pattern:TABLE1+TABLE2+... — Chemins de jointure avec contexte métier
          (ex: "Pour obtenir l'expert comptable : DossierSuppl → Collaborateurs")

        Modération (review snapshot 20b8902) : ces rôles sont écrits dans le RAG
        DOCUMENTATION GLOBAL (categories ``table_role:``/``column_role:``/
        ``join_pattern:``), servi à TOUS et NON filtré par ``pending_review`` au
        read (``get_related_ddl_with_roles``, ``get_documented_table_names``…).
        Seules les validations ADMIN doivent donc l'alimenter — cohérent avec le
        gating Q/SQL (``pending_review=not is_admin``) et ``concept_glossary``
        (``is_admin``). Un non-admin est skippé AVANT l'appel LLM (ferme le gap
        d'isolation axe 18 ET économise le coût LLM)."""
        if not is_admin:
            logger.debug(
                "Génération de rôles ignorée (feedback non-admin, user_id=%s) — "
                "seules les validations admin alimentent le RAG de rôles global.",
                user_id,
            )
            return
        try:
            from app.services.anonymization import anonymize_for_llm
            from app.services.anonymization.proxy import get_confidentiality_prompt
            from app.services.ai.llm_providers import LLMRequest
            from app.services.ai.llm_runtime import CallProfile, ModelKind, call_llm

            prompt = (
                f'L\'utilisateur a demandé : "{question}"\n'
                f"La requête SQL validée est :\n{sql}\n\n"
                f"Tables impliquées : {', '.join(tables)}\n\n"
                "Analyse cette requête validée et génère 3 types de connaissances "
                "métier en JSON :\n\n"
                "1. **table_roles** : Pour chaque table, décris son rôle métier "
                "EN CONTEXTE de cette requête (pas juste 'table de facturation', "
                "mais 'Contient les factures avec lien vers les groupes/dossiers "
                "via facNoEnregGrp et facNoEnregDos').\n\n"
                "2. **column_roles** : Pour les colonnes CLÉS seulement (FK, "
                "filtres, agrégations), décris leur rôle métier.\n\n"
                "3. **join_patterns** : Décris chaque chemin de jointure utilisé "
                "avec le CONTEXTE MÉTIER (pourquoi cette jointure, quel besoin "
                "elle remplit). Inclus les colonnes de jointure exactes.\n\n"
                "Format JSON :\n"
                '{{"table_roles": {{"TABLE": "description contextuelle"}}, '
                '"column_roles": {{"TABLE.COLUMN": "rôle métier"}}, '
                '"join_patterns": ['
                '{{"description": "Pour obtenir X, joindre A et B via ...", '
                '"tables": ["A", "B"], '
                '"joins": "A.col1 = B.col2", '
                '"business_context": "pourquoi cette jointure est nécessaire"}}'
                "]}}"
            )

            # Proxy d'anonymisation : couche PII regex sur le ``prompt``
            # + pseudonymizer user-scoped si ``user_id`` fourni. La
            # ``question`` provient de l'utilisateur (peut citer des
            # emails/SIRET/IBAN ou des termes que l'utilisateur a marqués
            # confidentiels via /anonymization). ``SCHEMA_ENRICH`` car
            # le LLM produit de la documentation structurelle (rôles
            # métier de tables/colonnes/jointures). ``user_id`` provient
            # du caller (``learn_from_conversation_feedback`` extrait
            # ``user_id`` du conversation owner) — fail-safe ``None``
            # si caller ne thread pas (PII regex seule).
            prompt_anon, restore_fn = await anonymize_for_llm(user_id, prompt, "SCHEMA_ENRICH")
            system_with_block = (
                get_confidentiality_prompt("SCHEMA_ENRICH")
                + "\n\n"
                + (
                    "Tu es un analyste de BDD spécialisé en comptabilité. "
                    "Génère des descriptions de rôle métier RICHES et CONTEXTUELLES "
                    "qui permettront à un futur agent SQL de retrouver ces tables "
                    "quand un utilisateur posera une question similaire. "
                    "Utilise des termes métier (chiffre d'affaires, expert comptable, "
                    "exercice, code statistique, etc.). Réponds UNIQUEMENT en JSON."
                )
            )

            response = await call_llm(
                CallProfile(
                    caller="agent_knowledge",
                    model_kind=ModelKind.UTILITY,
                    max_tokens_soft=2048,
                ),
                LLMRequest(
                    prompt=prompt_anon,
                    system=system_with_block,
                    temperature=0.1,
                ),
            )

            import json

            # Parse JSON ENCORE anonymisé puis restaure la STRUCTURE
            # (cf. EPIC E4 — restore-then-parse-JSON fragile aux PII
            # contenant `"`/`\`/`\n`). Les tokens `[TYPE_N]` ne contiennent
            # pas de chars JSON-spéciaux donc le parse est sûr.
            text = response.content.strip()
            # Strip markdown code blocks
            md = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if md:
                text = md.group(1).strip()
            data_anon = json.loads(text)
            data = restore_fn(data_anon)
            if not isinstance(data, dict):
                data = {}

            stored_count = 0

            # Store table roles
            for table, role in data.get("table_roles", {}).items():
                await self.store.add_documentation(
                    doc=role,
                    category=f"table_role:{table}",
                    tags=[table, "table_role", "feedback_generated"],
                    source="feedback_role_gen",
                )
                stored_count += 1

            # Store column roles
            for table_col, role in data.get("column_roles", {}).items():
                await self.store.add_documentation(
                    doc=role,
                    category=f"column_role:{table_col}",
                    tags=["column_role", "feedback_generated"],
                    source="feedback_role_gen",
                )
                stored_count += 1

            # Store join patterns — the key addition
            for jp in data.get("join_patterns", []):
                desc = jp.get("description", "")
                joins = jp.get("joins", "")
                biz = jp.get("business_context", "")
                jp_tables = jp.get("tables", [])
                if desc and jp_tables:
                    # Document riche et cherchable par TF-IDF
                    doc = f"{desc}\nJointures: {joins}"
                    if biz:
                        doc += f"\nContexte métier: {biz}"

                    # Catégorie = tables triées pour dédup
                    cat_key = "+".join(sorted(t.upper() for t in jp_tables))
                    await self.store.add_documentation(
                        doc=doc,
                        category=f"join_pattern:{cat_key}",
                        tags=jp_tables + ["join_pattern", "feedback_generated"],
                        source="feedback_role_gen",
                    )
                    stored_count += 1

            logger.info(
                "Feedback learning: %d docs generated (roles + join patterns) for tables: %s",
                stored_count,
                tables,
            )
        except Exception as e:
            logger.warning("Role generation from feedback failed: %s", e)

    async def get_correction_context(self, error_message: str, sql: str) -> str:
        """
        Récupère les règles de correction pertinentes pour une erreur SQL.

        Cherche dans le training_store les corrections passées similaires
        (pattern MAGIC) pour guider la correction automatique.

        Args:
            error_message: Message d'erreur SQL Server
            sql: Requête SQL qui a échoué

        Returns:
            Bloc de texte avec les règles de correction pertinentes, ou vide.
        """
        try:
            rules = await self.store.get_correction_rules(
                question=error_message,
                error_type="",
                n_results=3,
            )
        except Exception as exc:
            logger.warning("Impossible de charger les règles de correction: %s", exc)
            return ""

        if not rules:
            return ""

        parts = ["### Règles de correction apprises (situations similaires passées)\n"]
        for rule in rules:
            category = rule.get("category", "")
            # #18f (triage caps 2026-06-10) — le content des règles est
            # structuré : une coupe muette à 300 chars laissait le LLM
            # lire une règle amputée comme si elle était complète.
            _raw_content = rule.get("content", "")
            content = _raw_content[:300]
            if len(_raw_content) > 300:
                content += " […règle tronquée]"
            # Extraire le type d'erreur depuis la catégorie (format: "correction:type")
            error_type = category.split(":", 1)[1] if ":" in category else category
            parts.append(f"- **Type** : {error_type}")
            if content:
                parts.append(f"  Contexte : {content}")
            parts.append("")

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Vue détaillée d'une table
    # ------------------------------------------------------------------

    async def get_table_knowledge(
        self,
        table_name: str,
        *,
        user: Any = None,
    ) -> str:
        """
        Restitue tout ce que le système sait sur une table précise.

        Agrège : DDL, documentation métier (toutes catégories), exemples
        de requêtes contenant le nom de la table.

        Args:
            table_name: Nom exact de la table (ex: "TABLE_EXAMPLE").
            user: optionnel — propagé pour mode invisible (Phase α.4.B).

        Returns:
            Bloc de texte formaté, ou message indiquant l'absence de données.
        """
        if not table_name or not table_name.strip():
            return "Nom de table manquant."

        name_upper = table_name.strip().upper()

        # Phase α.4.B : propager user (ddl + similar_question_sql).
        # get_related_documentation pas encore patchée (task #86).
        ddl_items = await self.store.get_ddl_by_table_names([name_upper], n_results=1, user=user)
        doc_items = await self.store.get_related_documentation(name_upper, n_results=20)
        sql_items = await self.store.get_similar_question_sql(name_upper, n_results=10, user=user)

        # Filtrer les docs strictement liées à cette table
        table_docs = [
            d
            for d in doc_items
            if name_upper in (d.get("content") or "").upper()
            or name_upper in (d.get("category") or "").upper()
        ]

        # Filtrer les exemples SQL mentionnant la table
        table_sqls = [
            s
            for s in sql_items
            if name_upper in (s.get("sql") or "").upper()
            or name_upper in (s.get("question") or "").upper()
        ]

        if not ddl_items and not table_docs and not table_sqls:
            return f"Aucune connaissance enregistrée pour la table {name_upper}."

        sections: list[str] = [f"### Connaissances sur {name_upper}\n"]

        if ddl_items:
            sections.append("#### Schéma (DDL)")
            sections.append(ddl_items[0]["content"])
            sections.append("")

        if table_docs:
            sections.append("#### Documentation métier")
            for doc in table_docs:
                category = doc.get("category") or "général"
                sections.append(f"[{category}]\n{doc['content']}")
            sections.append("")

        if table_sqls:
            sections.append("#### Exemples de requêtes")
            for item in table_sqls:
                q = (item.get("question") or "").strip()
                sql = (item.get("sql") or "").strip()
                if q and sql:
                    sections.append(f"-- Question : {q}\n{sql}")
            sections.append("")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Readiness report
    # ------------------------------------------------------------------

    async def get_readiness_report(self) -> dict:
        """
        Évalue si Iris est prête à répondre aux questions SQL.

        Returns:
            Dict avec :
            - ready (bool): True si readiness_score >= 30
            - readiness_score (float): 0-100
            - stats: détail des métriques
            - message: message humain décrivant l'état
        """
        stats = await self.store.get_readiness_stats()
        score = stats["readiness_score"]
        ready = score >= 30

        if score >= 70:
            message = (
                f"Base de connaissances solide ({score:.0f}%). "
                f"{stats['total_tables']} tables connues, "
                f"{stats['tables_with_roles']} avec description sémantique, "
                f"{stats['aliases_count']} alias métier."
            )
        elif score >= 30:
            message = (
                f"Base de connaissances partielle ({score:.0f}%). "
                f"{stats['total_tables']} tables DDL mais seulement "
                f"{stats['tables_with_roles']} avec description sémantique. "
                "L'enrichissement complet améliorerait la précision des réponses."
            )
        else:
            message = (
                f"Base de connaissances insuffisante ({score:.0f}%). "
                f"Seulement {stats['total_tables']} tables DDL, "
                f"{stats['tables_with_roles']} enrichies sémantiquement. "
                "Un enrichissement complet est NÉCESSAIRE avant de répondre aux questions SQL."
            )

        return {
            "ready": ready,
            "readiness_score": score,
            "stats": stats,
            "message": message,
        }

    # ------------------------------------------------------------------
    # Résumé global de la couverture de connaissances
    # ------------------------------------------------------------------

    async def get_full_knowledge_summary(self, *, user: Any = None) -> str:
        """
        Retourne un résumé synthétique de la base de connaissances.

        Inclut : nombre de tables connues, nombre de docs, nombre d'exemples
        Q/SQL, et les 10 tables les plus consultées (usage_count).

        Args:
            user: optionnel — propagé pour mode invisible (Phase α.4.B).
                Note : ``get_stats()`` reste sans filtre car son output
                est agrégé (compteurs) sans noms de tables.

        Returns:
            Bloc de texte lisible par un humain ou insérable dans un prompt.
        """
        stats = await self.store.get_stats()
        # Phase α.4.B : propager user (la liste de tables retournée DOIT
        # être filtrée pour le mode invisible).
        table_names = await self.store.get_all_table_names(user=user)

        n_tables = stats.get("tables_count", 0)
        n_views = stats.get("views_count", 0)
        n_docs = stats.get("documentation_count", 0)
        n_pairs = stats.get("question_sql_count", 0)

        # Identifier les tables les plus utilisées via une recherche par table
        # (on utilise get_ddl_by_table_names pour obtenir les usage_count)
        top_tables: list[str] = []
        if table_names:
            # Récupérer les DDL avec usage_count pour trier
            from sqlalchemy import select, desc
            from app.models.training_data import TrainingData, TrainingDataType
            from app.core.database import get_session

            async with get_session() as session:
                result = await session.execute(
                    select(TrainingData.table_name, TrainingData.usage_count)
                    .where(
                        TrainingData.data_type == TrainingDataType.DDL,
                        TrainingData.is_active.is_(True),
                        TrainingData.table_name.isnot(None),
                    )
                    .order_by(desc(TrainingData.usage_count))
                    .limit(10)
                )
                rows = result.fetchall()
                top_tables = [f"{row[0]} (utilisée {row[1]} fois)" for row in rows if row[1] > 0]

        lines: list[str] = [
            "### Résumé de la base de connaissances Iris",
            "",
            f"- Tables connues (DDL)  : {n_tables}",
            f"- Vues connues (DDL)    : {n_views}",
            f"- Docs métier           : {n_docs}",
            f"- Exemples Q/SQL        : {n_pairs}",
            f"- Total entrées actives : {stats.get('total', 0)}",
            "",
        ]

        if table_names:
            lines.append(f"Tables disponibles ({len(table_names)}) :")
            lines.append(", ".join(table_names[:50]))
            if len(table_names) > 50:
                lines.append(f"  … et {len(table_names) - 50} autres")
            lines.append("")

        if top_tables:
            lines.append("Tables les plus consultées :")
            for entry in top_tables:
                lines.append(f"  - {entry}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Orchestrator helpers (used by orchestrator_tools.py)
    # ------------------------------------------------------------------

    async def build_fk_graph(self) -> dict[str, list[dict]]:
        """
        Build a bidirectional FK graph from stored documentation.

        Returns:
            dict[str, list[dict]]: {TABLE_UPPER: [{target, src_col, tgt_col, nullable, direction}]}
        """
        import json as _json

        graph: dict[str, list[dict]] = {}
        docs = await self.store.get_related_documentation("fk:", n_results=500)

        for doc in docs:
            category = doc.get("category", "")
            content = doc.get("content", "")

            if not category.startswith("fk:"):
                continue

            try:
                fk_data = _json.loads(content) if content.startswith("{") else {}
            except (_json.JSONDecodeError, TypeError):
                fk_data = {}

            if not fk_data:
                # Try parsing structured text
                continue

            src_table = fk_data.get("source_table", "").upper()
            tgt_table = fk_data.get("target_table", "").upper()
            src_col = fk_data.get("source_column", "")
            tgt_col = fk_data.get("target_column", "")
            nullable = fk_data.get("nullable", True)

            if not (src_table and tgt_table and src_col and tgt_col):
                continue

            # Outgoing: src → tgt
            graph.setdefault(src_table, []).append(
                {
                    "target": tgt_table,
                    "src_col": src_col,
                    "tgt_col": tgt_col,
                    "nullable": nullable,
                    "direction": "outgoing",
                }
            )

            # Incoming: tgt ← src (reverse direction for bidirectional search)
            graph.setdefault(tgt_table, []).append(
                {
                    "target": src_table,
                    "src_col": tgt_col,
                    "tgt_col": src_col,
                    "nullable": nullable,
                    "direction": "incoming",
                }
            )

        logger.info(
            "FK graph built: %d tables, %d edges", len(graph), sum(len(v) for v in graph.values())
        )
        return graph

    async def get_table_detail(
        self,
        table_name: str,
        *,
        user: Any = None,
    ) -> dict:
        """
        Get structured details for a single table (DDL, FK, stats, values, role).

        Used by the orchestrator to provide detailed table context to the LLM
        during Phase 2 concept verification.

        Args:
            table_name: Nom de la table cible.
            user: optionnel — propagé pour mode invisible (Phase α.4.B).

        Returns:
            dict with keys: ddl, fk_outgoing, fk_incoming, column_stats, column_values,
                           role, row_count, pk_columns, indexes
        """
        import json as _json

        name_upper = table_name.strip().upper()
        result: dict = {
            "name": name_upper,
            "ddl": "",
            "fk_outgoing": [],
            "fk_incoming": [],
            "column_stats": {},
            "column_values": {},
            "role": "",
            "row_count": 0,
            "pk_columns": [],
            "indexes": [],
        }

        # DDL — Phase α.4.B : propager user.
        ddl_items = await self.store.get_ddl_by_table_names([name_upper], n_results=1, user=user)
        if ddl_items:
            result["ddl"] = ddl_items[0].get("content", "")

        # All related docs
        docs = await self.store.get_related_documentation(name_upper, n_results=50)

        for doc in docs:
            category = (doc.get("category") or "").lower()
            content = doc.get("content", "")

            # FK relations
            if category.startswith("fk:"):
                try:
                    fk = _json.loads(content) if content.startswith("{") else {}
                except (_json.JSONDecodeError, TypeError):
                    fk = {}
                if fk:
                    direction = fk.get("direction", "sortante")
                    if direction == "sortante" or fk.get("source_table", "").upper() == name_upper:
                        result["fk_outgoing"].append(fk)
                    else:
                        result["fk_incoming"].append(fk)

            # Column stats
            elif category.startswith("column_stats:"):
                try:
                    stats = _json.loads(content) if content.startswith("{") else {}
                except (_json.JSONDecodeError, TypeError):
                    stats = {}
                if stats:
                    result["column_stats"].update(stats)

            # Column values (real values — pseudonymizer runtime applies if
            # configured in /data-privacy ``anonymization_terms``).
            elif category.startswith("column_values:"):
                try:
                    values = _json.loads(content) if content.startswith("{") else {}
                except (_json.JSONDecodeError, TypeError):
                    values = {}
                if values:
                    result["column_values"].update(values)

            # Table role
            elif category.startswith("table_role:"):
                if name_upper in category.upper():
                    result["role"] = content

            # Cardinality
            elif category.startswith("cardinality:"):
                try:
                    card = _json.loads(content) if content.startswith("{") else {}
                except (_json.JSONDecodeError, TypeError):
                    card = {}
                result["row_count"] = card.get("row_count", 0)

        return result

    async def get_column_sample_values(self, table_name: str, column_name: str) -> list[str]:
        """Get sample real values for a specific column.

        Returns max 15 non-null real values from stored ``column_values`` docs.
        Pseudonymization for LLM consumption is applied at the boundary by the
        Pseudonymizer when the term is configured in /data-privacy.
        """
        import json as _json

        name_upper = table_name.strip().upper()
        col_upper = column_name.strip().upper()

        docs = await self.store.get_related_documentation(
            f"column_values:{name_upper}", n_results=5
        )

        for doc in docs:
            category = doc.get("category") or ""
            if name_upper not in category.upper():
                continue

            content = doc.get("content", "")
            try:
                values_dict = _json.loads(content) if content.startswith("{") else {}
            except (_json.JSONDecodeError, TypeError):
                continue

            # Search for column (case-insensitive)
            for key, vals in values_dict.items():
                if key.upper() == col_upper and isinstance(vals, list):
                    return [str(v) for v in vals if v is not None][:15]

        return []


# ------------------------------------------------------------------
# Singleton module-level
# ------------------------------------------------------------------

_agent_knowledge: Optional[AgentKnowledge] = None


def get_agent_knowledge() -> AgentKnowledge:
    """Retourne le singleton AgentKnowledge (instanciation paresseuse)."""
    global _agent_knowledge
    if _agent_knowledge is None:
        _agent_knowledge = AgentKnowledge()
    return _agent_knowledge
