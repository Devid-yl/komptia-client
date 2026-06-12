"""
Service de résolution des valeurs utilisateur vers les colonnes SQL.

Quand l'utilisateur mentionne une valeur réelle (ex: "DUPONT") qui a été
anonymisée en ~DPNT par sanitize_user_input(), ce service cherche dans
l'index ValueMapping pour trouver la table/colonne correspondante.

Le LLM reçoit un "hint de colonne" (sans la valeur réelle) pour savoir
OÙ utiliser le token dans le SQL. Le serveur substitue ensuite
le token par la vraie valeur via requête paramétrisée.

Sécurité : les valeurs réelles ne quittent JAMAIS le serveur.
"""

import re
from typing import Optional

from sqlalchemy import select, func

from app.core.database import get_session
from app.models.value_mapping import ValueMapping
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Mots-outils francais (filtre pour discover_tables_from_message)
_FRENCH_STOP_WORDS = frozenset(
    {
        "les",
        "des",
        "une",
        "pour",
        "dans",
        "avec",
        "sans",
        "sur",
        "sous",
        "que",
        "qui",
        "est",
        "sont",
        "pas",
        "plus",
        "tous",
        "tout",
        "mon",
        "ton",
        "son",
        "mes",
        "tes",
        "ses",
        "nos",
        "vos",
        "leur",
        "mais",
        "donc",
        "car",
        "par",
        "entre",
        "chez",
        "vers",
        "quand",
        "comment",
        "pourquoi",
        "cette",
        "ces",
        "aux",
        "aussi",
        "très",
        "bien",
        "fait",
        "faire",
        "être",
        "avoir",
        "montre",
        "donne",
        "liste",
        "affiche",
        "combien",
        "quel",
        "quelle",
        "quels",
        "quelles",
        "moi",
        "toi",
    }
)


class ValueResolver:
    """Résout les tokens anonymisés (~TOKEN) vers les colonnes SQL correspondantes."""

    async def resolve_placeholders(self, pii_mapping: dict[str, str]) -> dict[str, list[dict]]:
        """
        Pour chaque token ~xxx dans le mapping, chercher dans ValueMapping
        les correspondances possibles (table/colonne).

        Args:
            pii_mapping: {token: valeur_originale} retourné par sanitize_user_input()
                         Les tokens ~xxx sont des noms propres anonymisés.
                         Les tokens [EMAIL_X] etc. sont des PII (ignorés ici).

        Returns:
            Dict {token: [{"table": str, "column": str, "value_type": str}]}
            Vide si aucune correspondance trouvée.
        """
        if not pii_mapping:
            return {}

        # Filtrer : ne résoudre que les ~TOKEN (pas [EMAIL_1], [PHONE_1], etc.)
        nom_placeholders = {k: v for k, v in pii_mapping.items() if k.startswith("~")}
        if not nom_placeholders:
            return {}

        resolved: dict[str, list[dict]] = {}

        try:
            async with get_session() as session:
                for placeholder, real_value in nom_placeholders.items():
                    real_lower = real_value.strip().lower()
                    if not real_lower:
                        continue

                    # Recherche exacte (case-insensitive via real_value_lower)
                    stmt = (
                        select(
                            ValueMapping.table_name,
                            ValueMapping.column_name,
                            ValueMapping.value_type,
                        )
                        .where(ValueMapping.real_value_lower == real_lower)
                        .distinct()
                    )
                    rows = (await session.execute(stmt)).all()

                    if rows:
                        resolved[placeholder] = [
                            {
                                "table": r.table_name,
                                "column": r.column_name,
                                "value_type": r.value_type,
                            }
                            for r in rows
                        ]

                    if not rows:
                        # Recherche partielle (LIKE %valeur%)
                        # Echapper les caracteres LIKE speciaux pour eviter l'injection
                        escaped = (
                            real_lower.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                        )
                        stmt_like = (
                            select(
                                ValueMapping.table_name,
                                ValueMapping.column_name,
                                ValueMapping.value_type,
                            )
                            .where(ValueMapping.real_value_lower.like(f"%{escaped}%", escape="\\"))
                            .distinct()
                            .limit(10)
                        )
                        rows_like = (await session.execute(stmt_like)).all()
                        if rows_like:
                            resolved[placeholder] = [
                                {
                                    "table": r.table_name,
                                    "column": r.column_name,
                                    "value_type": r.value_type,
                                }
                                for r in rows_like
                            ]

        except Exception as e:
            logger.warning("ValueResolver error: %s", e, exc_info=True)

        # ── Fallback Sage pour les valeurs non trouvées dans le ValueMapping ──
        # Le ValueMapping ne contient qu'un échantillon. Si une valeur n'y est pas,
        # on la cherche directement dans la BDD source via INFORMATION_SCHEMA + requête live.
        # Ça résout le problème d'une valeur rare qui n'a pas été échantillonnée au sync.
        unresolved = {k: v for k, v in nom_placeholders.items() if k not in resolved}
        if unresolved:
            try:
                from app.services.database.sage_connector import (
                    get_sage_connector,
                    PYODBC_AVAILABLE,
                )

                if PYODBC_AVAILABLE:
                    connector = get_sage_connector()
                    for placeholder, real_value in unresolved.items():
                        # Chercher la valeur dans les colonnes varchar/nvarchar
                        # de toutes les tables principales (pas Temp*)
                        # TOP 100 (cohérent avec max_rows=100 ci-dessous) et
                        # PAS TOP 5 : avec 5, seules les 5 premières tables (ordre
                        # alphabétique) sont candidates. Si la valeur user vit dans
                        # une table plus loin, le placeholder reste NON résolu en
                        # SILENCE → Iris filtre sur une colonne devinée → 0 ligne ou
                        # résultats faux sans erreur visible (donnée fausse
                        # silencieuse). On élargit le pool de candidats.
                        search_sql = """
                            SELECT TOP 100 t.TABLE_NAME, c.COLUMN_NAME
                            FROM INFORMATION_SCHEMA.COLUMNS c
                            JOIN INFORMATION_SCHEMA.TABLES t
                                ON c.TABLE_NAME = t.TABLE_NAME
                            WHERE t.TABLE_TYPE = 'BASE TABLE'
                                AND c.DATA_TYPE IN ('varchar', 'nvarchar')
                                AND c.CHARACTER_MAXIMUM_LENGTH >= ?
                                AND t.TABLE_NAME NOT LIKE 'Temp%'
                                AND t.TABLE_NAME NOT LIKE 'Z_%'
                            ORDER BY t.TABLE_NAME
                        """
                        # Ne pas exécuter si la valeur est trop courte
                        if len(real_value.strip()) < 3:
                            continue
                        try:
                            # bypass_admin_cap=True : ce sondage INFORMATION_SCHEMA
                            # est un INTERNAL de pré-vol (jamais montré à l'user),
                            # comme schema_sync / db_config_service. Sans le bypass,
                            # le cap UX /admin/database (min(100, max_rows)) re-rétréci
                            # EN SILENCE le pool de candidats qu'on vient d'élargir à
                            # 100 → on retombe sur le bug d'origine (placeholder non
                            # résolu si la table sort tard). #18f review (verdict #18).
                            col_result = await connector.execute(
                                search_sql,
                                (len(real_value),),
                                max_rows=100,
                                bypass_admin_cap=True,
                            )
                            # Pour chaque table/colonne candidate, chercher la valeur.
                            # On itère TOUTES les candidates retournées (≤100, borné
                            # par le TOP 100 SQL) au lieu d'un sous-cap [:20] : la
                            # boucle s'arrête (break) au premier match, donc le coût
                            # plein n'est payé que si la valeur est introuvable.
                            for row in col_result.rows:
                                tbl, col = row[0], row[1]
                                try:
                                    check_sql = f"SELECT TOP 1 1 FROM [{tbl}] " f"WHERE [{col}] = ?"
                                    check_result = await connector.execute(
                                        check_sql, (real_value.strip(),), max_rows=1
                                    )
                                    if check_result.rows:
                                        if placeholder not in resolved:
                                            resolved[placeholder] = []
                                        resolved[placeholder].append(
                                            {
                                                "table": tbl,
                                                "column": col,
                                                "value_type": "exact_match_live",
                                            }
                                        )
                                        # Aussi chercher les AUTRES colonnes clés du même row
                                        # pour donner au LLM les codes associés
                                        try:
                                            row_sql = (
                                                f"SELECT TOP 1 * FROM [{tbl}] " f"WHERE [{col}] = ?"
                                            )
                                            row_result = await connector.execute(
                                                row_sql, (real_value.strip(),), max_rows=1
                                            )
                                            if row_result.rows and row_result.columns:
                                                row_data = dict(
                                                    zip(row_result.columns, row_result.rows[0])
                                                )
                                                # Chercher les colonnes "Code" ou "ID" associées
                                                related_codes = {}
                                                for c_name, c_val in row_data.items():
                                                    if (
                                                        c_name != col
                                                        and c_val is not None
                                                        and isinstance(c_val, str)
                                                        and len(c_val) <= 50
                                                        and (
                                                            "code" in c_name.lower()
                                                            or "entite" in c_name.lower()
                                                            or "groupe" in c_name.lower()
                                                        )
                                                    ):
                                                        related_codes[c_name] = c_val
                                                if related_codes:
                                                    resolved[placeholder][-1][
                                                        "related_codes"
                                                    ] = related_codes
                                        except Exception:
                                            pass  # Non-bloquant
                                        break  # Trouvé dans cette table, pas besoin de continuer
                                except Exception:
                                    continue
                        except Exception as sage_err:
                            logger.debug("Live value search failed: %s", sage_err)
            except Exception as fb_err:
                logger.debug("Sage fallback for value resolution failed: %s", fb_err)

        if resolved:
            logger.info(
                "ValueResolver: %d/%d placeholders résolus",
                len(resolved),
                len(nom_placeholders),
            )

        return resolved

    def build_column_hints(
        self,
        resolved: dict[str, list[dict]],
        all_placeholders: dict[str, str] | None = None,
    ) -> str:
        """
        Construit un bloc texte à injecter dans le system prompt du LLM.

        Indique au LLM QUELLE colonne utiliser pour chaque token ~xxx,
        SANS révéler la valeur réelle.

        Args:
            resolved: Résultat de resolve_placeholders()
            all_placeholders: mapping {token: valeur} d'origine (pii_mapping).
                Si fourni, on calcule les tokens ~xxx cherchés mais NON résolus
                et on les SIGNALE LOUD au LLM. Sans ce signal, un token non
                localisé pousserait Iris à filtrer sur une colonne devinée →
                0 ligne ou résultats faux SANS erreur visible (doctrine
                « donnée fausse silencieuse »). La garde d'effet doit vivre au
                bout de la chaîne, ici, dans le payload réellement consommé.

        Returns:
            Texte à ajouter au system prompt (vide si rien à résoudre NI à signaler)
        """
        # Tokens ~xxx présents dans l'input user mais que la résolution n'a pas
        # rattachés à une colonne. (Les [EMAIL_x], [PHONE_x]… ne sont pas des
        # candidats — resolve_placeholders ne traite que les ~xxx.)
        unresolved_tokens: list[str] = []
        if all_placeholders:
            unresolved_tokens = [
                tok
                for tok in all_placeholders
                if tok.startswith("~") and tok not in resolved
            ]

        if not resolved and not unresolved_tokens:
            return ""

        lines: list[str] = []

        if resolved:
            lines.extend(
                [
                    "\n\n## Correspondance valeurs utilisateur → colonnes",
                    "",
                    "L'utilisateur a mentionné des valeurs que le serveur a anonymisées "
                    "(tokens ~xxx). Voici les colonnes correspondantes :",
                    "",
                ]
            )

            for placeholder, matches in resolved.items():
                if len(matches) == 1:
                    m = matches[0]
                    lines.append(
                        f"- **`{placeholder}`** → colonne `{m['column']}` "
                        f"de la table `{m['table']}` (type: {m['value_type']})"
                    )
                    # Ajouter les codes associés si disponibles
                    if m.get("related_codes"):
                        for rc_col, rc_val in m["related_codes"].items():
                            lines.append(
                                f"  - Code associé : `{m['table']}.{rc_col}` = `'{rc_val}'`"
                            )
                else:
                    # Plusieurs correspondances possibles
                    lines.append(f"- **`{placeholder}`** → correspondances multiples :")
                    for m in matches:
                        hint = f"  - `{m['table']}.{m['column']}` (type: {m['value_type']})"
                        if m.get("related_codes"):
                            codes = ", ".join(
                                f"`{c}` = `'{v}'`" for c, v in m["related_codes"].items()
                            )
                            hint += f" — codes associés : {codes}"
                        lines.append(hint)

            # Construire un exemple à partir du premier token résolu
            example_token = next(iter(resolved))
            lines.extend(
                [
                    "",
                    f"**REGLE** : Utilise directement le token anonymisé (ex: `{example_token}`) "
                    "dans tes requêtes SQL comme valeur de filtre. "
                    f"Exemple : `WHERE colonne = '{example_token}'`. "
                    "Le serveur substituera automatiquement la vraie valeur via requête "
                    "paramétrisée. Ne tente PAS de deviner ou d'écrire la valeur réelle.",
                ]
            )

        if unresolved_tokens:
            # Garde d'EFFET (pas juste de présence) : le warning est dans le
            # payload consommé par le LLM, donc il agit vraiment sur sa décision.
            lines.extend(
                [
                    "\n\n## ⚠ Valeurs utilisateur NON localisées",
                    "",
                    "Les tokens suivants correspondent à des valeurs citées par "
                    "l'utilisateur que le serveur n'a PAS pu rattacher à une colonne "
                    "(recherche limitée dans le cache ValueMapping + BDD source) :",
                    "",
                ]
            )
            for tok in unresolved_tokens:
                lines.append(
                    f"- **`{tok}`** : valeur non localisée (recherche limitée) — "
                    "vérifie la colonne cible AVANT de filtrer dessus. Si tu n'es pas "
                    "certain de la colonne, demande à l'utilisateur plutôt que de "
                    "deviner : un filtre sur la mauvaise colonne renvoie 0 ligne ou "
                    "des résultats faux SANS erreur visible."
                )

        return "\n".join(lines)

    async def discover_tables_from_message(self, message: str) -> list[dict]:
        """
        Cherche dans ValueMapping les mots du message utilisateur pour identifier
        les tables/colonnes pertinentes SANS envoyer de valeurs au LLM.

        Utilisé par le RAG pour booster la sélection de tables :
        si l'utilisateur dit une valeur, on découvre quelle table est pertinente.

        Args:
            message: Message brut de l'utilisateur (avant sanitisation)

        Returns:
            Liste de dicts {"table": str, "column": str, "matched_word": str}
            représentant les tables découvertes via les valeurs.
        """
        if not message or len(message) < 2:
            return []

        # Extraire les mots significatifs du message (>=4 chars, pas des mots courants)
        # Minimum 4 chars pour éviter "code", "nom", "type" qui matchent partout
        words = re.findall(r"\b[A-Za-zÀ-ÿ0-9]{4,}\b", message)
        if not words:
            return []

        # Mots métier courants qui existent comme valeurs dans beaucoup de tables
        # mais n'identifient pas UNE table spécifique
        _VALUE_NOISE = {
            "code",
            "compte",
            "nombre",
            "montant",
            "date",
            "type",
            "numero",
            "ligne",
            "total",
            "dossier",
            "expert",
            "comptable",
            "chiffre",
            "affaires",
            "facture",
            "exercice",
            "groupe",
            "mission",
            "statistique",
            "entite",
            "signataire",
            "collaborateur",
        }
        candidates = [
            w
            for w in words
            if w.lower() not in _FRENCH_STOP_WORDS and w.lower() not in _VALUE_NOISE
        ]
        if not candidates:
            return []

        # Batch query: chercher tous les mots en une seule requete
        candidate_lowers = list({w.lower() for w in candidates})
        # Map lower → original word pour le champ matched_word
        lower_to_word = {}
        for w in candidates:
            wl = w.lower()
            if wl not in lower_to_word:
                lower_to_word[wl] = w

        discovered: list[dict] = []
        seen_tables: set[str] = set()  # Dédup par TABLE (pas table.column)
        _MAX_DISCOVERED = 10  # Max tables découvertes

        try:
            async with get_session() as session:
                stmt = (
                    select(
                        ValueMapping.table_name,
                        ValueMapping.column_name,
                        ValueMapping.real_value_lower,
                    )
                    .where(ValueMapping.real_value_lower.in_(candidate_lowers))
                    .distinct()
                )
                rows = (await session.execute(stmt)).all()

                for r in rows:
                    tname_upper = r.table_name.upper()
                    if tname_upper not in seen_tables:
                        seen_tables.add(tname_upper)
                        discovered.append(
                            {
                                "table": r.table_name,
                                "column": r.column_name,
                                "matched_word": lower_to_word.get(
                                    r.real_value_lower, r.real_value_lower
                                ),
                            }
                        )
                        if len(discovered) >= _MAX_DISCOVERED:
                            break

        except Exception as e:
            logger.warning("discover_tables_from_message error: %s", e, exc_info=True)

        if discovered:
            logger.info(
                "ValueResolver: %d tables découvertes via valeurs dans le message",
                len(discovered),
            )

        return discovered

    async def count_mappings(self) -> int:
        """Retourne le nombre total de mappings stockés."""
        try:
            async with get_session() as session:
                stmt = select(func.count(ValueMapping.id))
                result = await session.execute(stmt)
                return result.scalar_one()
        except Exception:
            logger.error("count_mappings failed", exc_info=True)
            return 0


# Singleton
_resolver: Optional[ValueResolver] = None


def get_value_resolver() -> ValueResolver:
    """Retourne le singleton ValueResolver."""
    global _resolver
    if _resolver is None:
        _resolver = ValueResolver()
    return _resolver
