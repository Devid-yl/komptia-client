"""
ConfidentialityManager — anonymisation user-driven legacy + helpers actifs.

Ce module reste **actif en production** : il héberge plusieurs méthodes
encore appelées par ``llm_report_planner``, ``widget_planner.pipeline``,
``agent_tools._restore_for_user_safe`` et 9 sites dans ``agent_service``.
La nouvelle façade unifiée :func:`anonymize_for_llm` (proxy) est la cible
pour tout *nouveau* call site, mais ConfidentialityManager n'est pas du
code mort.

Méthodes ACTIVES (ne pas supprimer) :

- :meth:`ConfidentialityManager.sanitize_user_input` — anonymise le texte
  utilisateur avant LLM (PII regex + noms propres ↔ ``anonymization_terms``
  + neutralisation prompt injection). Caller : ``llm_report_planner``,
  ``widget_planner.pipeline``.
- :meth:`ConfidentialityManager.restore_response` — réinjecte le mapping
  inverse dans la réponse LLM. Caller : tous les flows qui appellent
  ``sanitize_user_input``.
- :meth:`ConfidentialityManager.restore_anonymized_values` — résout les
  tokens ``~xxx`` legacy via lookup ``anonymization_terms`` (BDD). Caller :
  ``agent_tools._restore_for_user_safe`` + ``agent_service``.
- :meth:`ConfidentialityManager.substitute_sql_placeholders` — remplace
  les tokens dans le SQL par des paramètres ODBC ``?`` (sécurité).
- :meth:`ConfidentialityManager.anonymize_dataset_for_llm` — tokenisation
  bidirectionnelle tabulaire. Caller : ``llm_report_planner``.
- :meth:`ConfidentialityManager.anonymize_widget_payload` — tokenisation
  d'un payload widget (table/chart/kpi). Caller : ``widget_planner.pipeline``.

Méthode TRANSITOIRE (orphan en prod, gardée comme compat shim) :

- :meth:`ConfidentialityManager.filter_tool_results` — pass-through depuis
  tâche #5. Plus aucun caller dans ``agent_service`` (#6 l'a retiré du
  dispatch loop). Conservée pour les tests legacy ; à supprimer dans
  une prochaine session de cleanup orphan.

Helpers module-level CONSERVÉS pour les méthodes actives ci-dessus :

- :func:`_obfuscate_date` — utilisé par ``anonymize_dataset_for_llm`` et
  ``anonymize_widget_payload`` (truncation année-mois).
- :func:`_is_date_value`, :func:`_is_numeric` — classification de valeurs.
- :meth:`ConfidentialityManager._generate_anon_token` — fallback de
  génération de token quand ``ValueMapping`` n'a pas de forme anonymisée.

**État post-tâche #5 (lossy purge complète)** : supprimés ``obfuscate_for_peek``
(Niveau 2 lossy), ``decontextualize`` et ``anonymize_string`` (orphans
YAGNI), helper ``_obfuscate_string`` ainsi que ``_obfuscate_value`` /
``_obfuscate_row`` côté ``agent_tools.py``.

**Pour tout NOUVEAU call site** (à partir de tâche #5) : cibler
:func:`app.services.anonymization.proxy.anonymize_for_llm`. Tâches #7/#8
migreront les call sites legacy ci-dessus vers le proxy.

---

Niveaux de protection branchés en production :

    Niveau 1 — Pass-through : schéma BDD, documentation (non sensible)
    Niveau 4 — Métadonnées uniquement (``execute_sql`` : le LLM voit
               row_count, columns, anonymized_sample — pas les vraies rows)

Détection PII regex déléguée à
:mod:`app.services.anonymization.patterns` (anciennement
``app.services.ai.anonymizer``).
"""

import logging
import os
import re
from decimal import Decimal
from typing import Any

from app.services.anonymization.extract import _COMMON_FRENCH_WORDS
from app.services.anonymization.patterns import get_anonymizer

logger = logging.getLogger(__name__)

# ``_COMMON_FRENCH_WORDS`` est désormais maintenu dans
# :mod:`app.services.anonymization.extract` (single source of truth depuis
# tâche #11). Re-exporté ici pour les callers historiques. Le set inclut
# articles/pronoms/conjonctions FR + mois + jours + lieux + salutations +
# mots-clés T-SQL — utile à
# :meth:`ConfidentialityManager.sanitize_user_input` qui exclut ces formes
# de la détection de noms propres dans un texte libre utilisateur.

# Pattern pour détecter les noms propres heuristiques :
# - Title Case : mot commençant par une majuscule (ex: nom de personne)
# - ALL CAPS : mot entièrement en majuscules (ex: code d'entité/groupe)
# Pas en début de phrase (pas précédé de . ou début de texte)
_PROPER_NOUN_PATTERN = re.compile(
    r"(?<![.!?\n])\s("
    r"[A-ZÀÂÄÉÈÊËÎÏÔÖÙÛÜÇ][a-zàâäéèêëîïôöùûüç]{2,}"  # Title Case (≥3 chars)
    r"|"
    r"[A-ZÀÂÄÉÈÊËÎÏÔÖÙÛÜÇ]{3,}"  # ALL CAPS (≥3 chars, évite "OK", "TV")
    r")"
)


def _obfuscate_date(value: Any) -> str | None:
    """
    Réduit une date à son année-mois, supprimant le jour.

    Accepte les objets date/datetime Python et les chaînes ISO 8601.
    Retourne None si le format n'est pas reconnu.

    NOTE (anon-impl-loop #5) : conservé transitoirement — utilisé par
    :meth:`ConfidentialityManager.anonymize_dataset_for_llm` et
    :meth:`anonymize_widget_payload`. À supprimer dès que ces deux
    méthodes auront migré vers le proxy unifié (tâches #7/#8).
    """
    # Objet date/datetime Python
    if hasattr(value, "year") and hasattr(value, "month"):
        return f"{value.year}-{value.month:02d}"

    # Chaîne ISO : "2024-03-15", "2024-03-15T10:30:00", etc.
    if isinstance(value, str):
        match = re.match(r"^(\d{4}-\d{2})", value)
        if match:
            return match.group(1)

    return None


def _is_date_value(value: Any) -> bool:
    """Détecte si une valeur est de type date (objet ou chaîne ISO)."""
    if hasattr(value, "year") and hasattr(value, "month"):
        return True
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}", value):
        return True
    return False


def _is_numeric(value: Any) -> bool:
    """Vérifie si une valeur est un nombre (int, float, Decimal)."""
    return isinstance(value, (int, float, Decimal))


class ConfidentialityManager:
    """
    Stratégie de confidentialité legacy — en cours de migration vers
    :func:`app.services.anonymization.proxy.anonymize_for_llm`.

    Niveaux encore branchés :

    - Niveau 1 : Pass-through (``filter_tool_results``) — données non sensibles
    - Niveau 4 : Métadonnées uniquement (``execute_sql``) — l'IA voit juste les stats

    Pour anonymisation bidirectionnelle d'un payload LLM, le **point d'entrée
    cible** est :func:`anonymize_for_llm` (proxy). Les méthodes
    ``sanitize_user_input`` / ``anonymize_dataset_for_llm`` /
    ``anonymize_widget_payload`` sont conservées pour les call sites legacy
    (llm_report_planner, widget_planner) tant que tâches #7/#8 ne les ont
    pas migrés.

    Usage legacy (à éviter pour de nouveaux call sites) :

        manager = get_confidentiality_manager()
        sanitized, mapping = await manager.sanitize_user_input(user_text)
        response = await call_llm(sanitized)
        final = manager.restore_response(response, mapping)
    """

    def __init__(self) -> None:
        """Initialize the confidentiality manager with a random anonymization salt."""
        self._anonymization_salt = os.urandom(16).hex()

    def anonymize_dataset_for_llm(
        self,
        rows: list[dict],
        columns: list[str],
        label: str | None = None,
        shared_used_tokens: set[str] | None = None,
        shared_value_to_token: dict[str, str] | None = None,
    ) -> tuple[list[dict], str | None, dict[str, str]]:
        """
        Anonymisation bidirectionnelle pour données tabulaires destinées au LLM.

        Méthode RÉVERSIBLE (contrairement à l'ancienne obfuscation lossy retirée
        tâche #5) : produit des tokens ~xxx *uniques* pour chaque valeur distincte
        et renvoie un mapping inverse permettant de restaurer les vraies valeurs
        via `restore_response`.

        Règles appliquées cellule par cellule :
        - Chaînes > 3 chars : tokenisées (~xxx, unique par valeur distincte)
        - Chaînes ≤ 3 chars : préservées (codes non identifiants type "VE", "HT")
        - Dates : tronquées à année-mois
        - Nombres (int/float/Decimal) : préservés à l'identique
        - NULL : préservés

        Collisions : si deux valeurs produisent le même token, on ajoute un suffixe
        _2, _3, … pour garantir l'unicité (obligatoire pour la réversibilité).

        État partagé : pour anonymiser plusieurs datasets au sein d'un même appel
        LLM, passer les mêmes `shared_used_tokens` et `shared_value_to_token` à
        chaque invocation. Cela évite que deux valeurs avec un préfixe commun
        (ex: "Foobar" dataset 1 et "Foobaz" dataset 2) produisent le même token
        localement, ce qui écraserait silencieusement un mapping au merge.

        Usage typique (un seul dataset) :
            anon_rows, anon_label, mapping = cm.anonymize_dataset_for_llm(rows, cols, label)
            restored_text = cm.restore_response(llm_text, mapping)

        Usage multi-dataset partageant l'allocateur :
            used = set()
            v2t = {}
            merged = {}
            for ds in datasets:
                ar, al, m = cm.anonymize_dataset_for_llm(
                    ds.rows, ds.cols, label=ds.label,
                    shared_used_tokens=used, shared_value_to_token=v2t,
                )
                merged.update(m)

        Args:
            rows: Lignes brutes (liste de dicts)
            columns: Colonnes à traiter (les clés hors scope sont préservées)
            label: Label optionnel du dataset (ex: libellé du regroupement) — tokenisé si > 3 chars
            shared_used_tokens: Set partagé entre appels pour garantir l'unicité globale
            shared_value_to_token: Dict partagé pour dédupliquer les valeurs identiques
                entre datasets (même valeur ⇒ même token ⇒ mapping cohérent au merge)

        Returns:
            Tuple (anon_rows, anon_label, mapping) où
            mapping = {token: valeur_originale} à passer à restore_response().
        """
        mapping: dict[str, str] = {}
        value_to_token: dict[str, str] = (
            shared_value_to_token if shared_value_to_token is not None else {}
        )
        used_tokens: set[str] = shared_used_tokens if shared_used_tokens is not None else set()

        def _token_for(real_value: str) -> str:
            """Return a unique ~token for a real string value (dedup + collision-proof)."""
            cached = value_to_token.get(real_value)
            if cached is not None:
                # Une valeur déjà tokenisée dans un dataset précédent : réutilise
                # le même token ET propage le mapping (sinon merged_mapping ignore
                # ce token pour ce dataset).
                mapping[cached] = real_value
                return cached
            base = f"~{self._generate_anon_token(real_value)}"
            token = base
            suffix = 2
            while token in used_tokens:
                token = f"{base}_{suffix}"
                suffix += 1
            used_tokens.add(token)
            mapping[token] = real_value
            value_to_token[real_value] = token
            return token

        def _transform_cell(value: Any) -> Any:
            if value is None:
                return None
            if _is_numeric(value):
                return value
            if _is_date_value(value):
                return _obfuscate_date(value)
            if isinstance(value, str):
                if len(value) <= 3:
                    return value
                return _token_for(value)
            # Fallback : stringify then tokenize if long enough
            s = str(value)
            if len(s) <= 3:
                return s
            return _token_for(s)

        anon_rows: list[dict] = []
        for row in rows:
            anon_row: dict = {}
            for col in columns:
                anon_row[col] = _transform_cell(row.get(col))
            # Préserver les clés hors scope (colonnes non listées : passthrough)
            for key in row:
                if key not in columns:
                    anon_row[key] = row[key]
            anon_rows.append(anon_row)

        # Label : tokenisé si c'est une chaîne > 3 chars (il peut contenir un nom propre)
        anon_label: str | None
        if label is None:
            anon_label = None
        elif isinstance(label, str) and len(label) > 3:
            anon_label = _token_for(label)
        else:
            anon_label = label if isinstance(label, str) else None

        logger.debug(
            "anonymize_dataset_for_llm: %d lignes, %d tokens distincts",
            len(rows),
            len(mapping),
        )
        return anon_rows, anon_label, mapping

    def anonymize_widget_payload(
        self,
        shape: dict[str, Any],
        shared_used_tokens: set[str] | None = None,
        shared_value_to_token: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        """Anonymise un payload widget (table/chart/kpi) destiné au LLM Designer.

        Principe : on tokenise les VALEURS de données (labels de chart, cellules
        de table, label de kpi) mais on préserve les MÉTADONNÉES STRUCTURELLES
        (type, columns, dataset.label qui est le nom de la métrique). Les noms
        de colonnes sont du schema (niveau 1 confidentialité).

        Règles par shape :
        - table : cellules des rows tokenisées, columns préservées
        - chart : labels (catégories) tokenisées, datasets.label (métriques)
          préservé, data (nombres) préservé
        - kpi   : label tokenisé, value préservé
        - autre : tentative générique (preserve keys connues, tokenise strings)

        Args:
            shape: dict shape produit par `_trim_for_designer` / `apply_transformation`
            shared_used_tokens / shared_value_to_token: permettent de partager
                l'allocateur avec d'autres appels (user_hint, autres widgets…)
                pour éviter les collisions silencieuses lors du merge des mappings.

        Returns:
            (anon_shape, mapping) où mapping = {token: real_value} à passer à
            `restore_response`.
        """
        mapping: dict[str, str] = {}
        value_to_token: dict[str, str] = (
            shared_value_to_token if shared_value_to_token is not None else {}
        )
        used_tokens: set[str] = shared_used_tokens if shared_used_tokens is not None else set()

        def _token_for(real_value: str) -> str:
            cached = value_to_token.get(real_value)
            if cached is not None:
                mapping[cached] = real_value
                return cached
            base = f"~{self._generate_anon_token(real_value)}"
            token = base
            suffix = 2
            while token in used_tokens:
                token = f"{base}_{suffix}"
                suffix += 1
            used_tokens.add(token)
            mapping[token] = real_value
            value_to_token[real_value] = token
            return token

        def _transform_value(v: Any) -> Any:
            if v is None or isinstance(v, bool):
                return v
            if _is_numeric(v):
                return v
            if _is_date_value(v):
                return _obfuscate_date(v)
            if isinstance(v, str):
                return v if len(v) <= 3 else _token_for(v)
            # Fallback : stringify non-scalaire
            s = str(v)
            return s if len(s) <= 3 else _token_for(s)

        if not isinstance(shape, dict):
            return shape, mapping

        result: dict[str, Any] = {**shape}
        shape_type = shape.get("type")

        if shape_type == "table":
            raw_rows = shape.get("rows")
            if isinstance(raw_rows, list):
                result["rows"] = [
                    (
                        [_transform_value(cell) for cell in row]
                        if isinstance(row, list)
                        else _transform_value(row)
                    )
                    for row in raw_rows
                ]
        elif shape_type == "chart":
            raw_labels = shape.get("labels")
            if isinstance(raw_labels, list):
                result["labels"] = [_transform_value(lbl) for lbl in raw_labels]
            raw_datasets = shape.get("datasets")
            if isinstance(raw_datasets, list):
                new_datasets: list[Any] = []
                for ds in raw_datasets:
                    if not isinstance(ds, dict):
                        # Item malformé (ex: str direct) : tokeniser pour fail-closed
                        new_datasets.append(_transform_value(ds))
                        continue
                    new_ds = {**ds}
                    # dataset.label : en 1D c'est un nom de métrique ("total"),
                    # en 2D (groupby_2d, top_n_2d, time_series_multi) c'est une
                    # VALEUR de série (ex: nom client "DUPONT"). On tokenise
                    # systématiquement > 3 chars — les métriques techniques
                    # comme "CA", "HT" sont préservées par la règle ≤ 3 chars.
                    if "label" in new_ds:
                        new_ds["label"] = _transform_value(new_ds.get("label"))
                    data = ds.get("data")
                    if isinstance(data, list):
                        new_ds["data"] = [
                            _transform_value(d) if isinstance(d, str) else d for d in data
                        ]
                    new_datasets.append(new_ds)
                result["datasets"] = new_datasets
        elif shape_type == "kpi":
            # value peut être un nombre ou une chaîne (scalar_from_column sur
            # colonne non-numérique). Si str > 3 chars, tokeniser impératif.
            if "value" in shape:
                v = shape.get("value")
                result["value"] = _transform_value(v) if isinstance(v, str) else v
            if "label" in shape:
                result["label"] = _transform_value(shape.get("label"))
            if "subtitle" in shape:
                result["subtitle"] = _transform_value(shape.get("subtitle"))
        else:
            # Shape inconnue : fail-closed — parcourt récursivement et tokenise
            # tout string > 3 chars (défensif contre les futures transformations
            # non anticipées ou shapes malformés).
            def _recursive_anonymize(obj: Any) -> Any:
                if obj is None or isinstance(obj, (int, float, bool)):
                    return obj
                if isinstance(obj, str):
                    return _transform_value(obj)
                if isinstance(obj, dict):
                    return {k: _recursive_anonymize(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_recursive_anonymize(i) for i in obj]
                return _transform_value(obj)

            for key, value in shape.items():
                if key == "type":
                    continue  # préserve le discriminant
                result[key] = _recursive_anonymize(value)

        logger.debug(
            "anonymize_widget_payload: type=%s, %d tokens alloués",
            shape_type,
            len(mapping),
        )
        return result, mapping

    async def sanitize_user_input(
        self, text: str, user_id: int | None = None
    ) -> tuple[str, dict[str, str]]:
        """
        Niveau 1+ : Nettoyage du texte utilisateur avant envoi au LLM.

        ``user_id`` (depuis 2026-05-22) restreint le lookup ``anonymization_terms``
        au user courant. Sans ``user_id``, la passe 2 (noms propres) utilise
        uniquement le fallback ``_generate_anon_token`` (jamais de pseudo
        d'un autre user appliqué).

        Trois passes successives :
        1. Anonymisation PII via DataAnonymizer (emails, téléphones, SIRET, IBAN, etc.)
           → remplacés par [EMAIL_1], [PHONE_1], etc.
        2. Détection heuristique des noms propres (mots en majuscule non courants)
           → remplacés par des tokens ~xxx (lookup dans ValueMapping ou fallback
             par obfuscation). Le LLM voit ~DPNT au lieu de "DUPONT".
        3. Neutralisation des tentatives de prompt injection.

        Le mapping retourné permet de restaurer les valeurs originales dans la
        réponse du LLM via restore_response().

        Args:
            text: Texte brut de l'utilisateur

        Returns:
            Tuple (texte_sanitisé, mapping) où mapping = {token: valeur_originale}
            Les tokens PII sont de la forme [EMAIL_1], les noms propres ~xxx.
        """
        anonymizer = get_anonymizer()

        # Passe 1 : PII regex (emails, téléphones, SIRET, IBAN, montants)
        sanitized, pii_mapping = anonymizer.anonymize(text)

        # Passe 2 : Noms propres → tokens ~xxx via ValueMapping
        proper_noun_mapping: dict[str, str] = {}
        used_tokens: set[str] = set()  # Pour garantir l'unicité

        # Collecter d'abord tous les noms propres détectés
        detected_nouns: list[tuple[str, re.Match]] = []
        for match in _PROPER_NOUN_PATTERN.finditer(sanitized):
            word = match.group(1)
            # Ignorer les mots courants français (insensible à la casse)
            if word.title() in _COMMON_FRENCH_WORDS or word in _COMMON_FRENCH_WORDS:
                continue
            # Ignorer si déjà un placeholder PII
            if word.startswith("[") and word.endswith("]"):
                continue
            detected_nouns.append((word, match))

        if detected_nouns:
            # Lookup batch dans anonymization_terms du user (depuis 2026-05-22)
            vm_lookup = await self._lookup_anonymized_forms(
                [word for word, _ in detected_nouns], user_id=user_id
            )

            # Construire le mapping et remplacer dans le texte
            # On remplace de droite à gauche pour ne pas décaler les positions
            replacements: list[tuple[int, int, str, str]] = []  # (start, end, token, word)

            from app.services.anonymization.repository import _canonical_match_key

            for word, match in detected_nouns:
                # Lookup via la clé CANONIQUE (case + accent + whitespace) —
                # même notion que ``_lookup_anonymized_forms`` (qui clé son dict
                # sur ``term_canonical``).
                anon_form = vm_lookup.get(_canonical_match_key(word))
                if anon_form:
                    token = f"~{anon_form.replace(' ', '_')}"
                else:
                    # Fallback : obfuscation locale (retirer les voyelles)
                    token = f"~{self._generate_anon_token(word)}"

                # Garantir l'unicité du token
                base_token = token
                suffix = 2
                while token in used_tokens:
                    token = f"{base_token}_{suffix}"
                    suffix += 1
                used_tokens.add(token)

                proper_noun_mapping[token] = word
                # Position dans le texte : le match.group(0) contient l'espace + le mot
                word_start = match.start(1)
                word_end = match.end(1)
                replacements.append((word_start, word_end, token, word))

            # Remplacer de droite à gauche
            replacements.sort(key=lambda r: r[0], reverse=True)
            for start, end, token, _word in replacements:
                sanitized = sanitized[:start] + token + sanitized[end:]

        # Fusionner les deux mappings (PII d'abord, noms propres ensuite)
        combined_mapping = {**pii_mapping, **proper_noun_mapping}

        if proper_noun_mapping:
            logger.info(
                "sanitize_user_input: %d PII + %d noms propres masqués (tokens: %s)",
                len(pii_mapping),
                len(proper_noun_mapping),
                list(proper_noun_mapping.keys()),
            )

        # Passe 3 : Détection de tentatives de prompt injection
        sanitized = self._neutralize_injection_attempts(sanitized)

        return sanitized, combined_mapping

    async def _lookup_anonymized_forms(
        self, words: list[str], user_id: int | None = None
    ) -> dict[str, str]:
        """Cherche des pseudos configurés dans ``anonymization_terms`` pour
        ``user_id`` UNIQUEMENT (la table est strictement user-scoped via
        UniqueConstraint(user_id, term)).

        /data-privacy est la seule source de vérité depuis 2026-05-22 — on lit
        donc directement les termes configurés (``enabled=True`` + pseudo non
        vide). Sans ``user_id``, le lookup est skip (fail-safe vs. fuite
        cross-user — voir review adversariale).

        Match CANONIQUE (case + accent insensible) via la colonne
        ``term_canonical`` (NFKD strip-accents + casefold, cf.
        ``repository._canonical_key``) depuis 2026-06-09. Avant, le match
        ``func.lower(term) IN (...)`` ne couvrait que l'ASCII et ratait les
        accents : ``"Crédit"`` configuré n'était pas retrouvé pour ``"CREDIT"``
        → le pseudo CONFIGURÉ n'était pas appliqué (le mot restait masqué via
        le fallback ``_generate_anon_token``, mais pas avec le pseudo choisi).
        Le caller fait son lookup avec la MÊME clé ``_canonical_key(word)``.

        Returns:
            Dict ``{term_canonical: pseudo}`` pour les mots ayant un pseudo
            configuré par ce user. Vide si ``user_id`` est None ou si la BDD est
            down (fail-silent local — le caller voit le mot original, jamais une
            fuite involontaire vers un pseudo d'un autre user).
        """
        if not words or user_id is None:
            return {}

        try:
            from app.core.database import get_session
            from app.models.anonymization_term import AnonymizationTerm
            from app.services.anonymization.repository import _canonical_match_key
            from sqlalchemy import select

            # Match CANONIQUE (case + accent + whitespace insensible) via
            # ``term_canonical`` (cf. caveat ci-dessus, corrigé 2026-06-09). Le
            # caller fait le lookup avec la MÊME clé ``_canonical_match_key``.
            # On filtre les clés vides (token dégénéré sans contenu canonique).
            canon_words = list(
                {
                    k
                    for w in words
                    if isinstance(w, str) and w
                    for k in (_canonical_match_key(w),)
                    if k
                }
            )
            if not canon_words:
                return {}

            async with get_session() as session:
                stmt = (
                    select(
                        AnonymizationTerm.term_canonical.label("term_canon"),
                        AnonymizationTerm.pseudo_middle,
                    )
                    .where(
                        AnonymizationTerm.user_id == user_id,
                        AnonymizationTerm.term_canonical.in_(canon_words),
                        AnonymizationTerm.enabled.is_(True),
                        AnonymizationTerm.pseudo_middle.isnot(None),
                        AnonymizationTerm.pseudo_middle != "",
                    )
                    # ORDER BY id : si plusieurs rows partagent une canonical
                    # (variantes casse/accent legacy avec pseudos différents),
                    # le dict ci-dessous garde le DERNIER → gagnant DÉTERMINISTE
                    # (plus grand id) au lieu d'un ordre BDD arbitraire. cf.
                    # review migration findings #7/#14.
                    .order_by(AnonymizationTerm.id)
                )
                result = await session.execute(stmt)
                return {row.term_canon: row.pseudo_middle for row in result}
        except Exception as e:
            logger.debug("anonymization_terms lookup failed: %s", e)
            return {}

    @staticmethod
    def _generate_anon_token(word: str) -> str:
        """
        Génère un token anonymisé pour un mot non trouvé dans ValueMapping.
        Retire les voyelles pour garder un pattern reconnaissable.
        Ex: "DUPONT" → "DPNT", "Sofigec" → "Sfgc"
        """
        if not word or len(word) < 2:
            return word[:1] + "." if word else "x"

        vowels = set("aeiouyAEIOUY")
        result = []
        for i, ch in enumerate(word):
            if ch == " ":
                result.append("_")
            elif ch.isalpha() and ch in vowels and i > 0:
                continue
            else:
                result.append(ch)

        anonymized = "".join(result)

        # Si rien n'a été retiré (ex: "BCDG"), garder 1 char sur 2
        if len(anonymized) == len(word) and len(word) > 4:
            anonymized = word[::2]

        if not anonymized or len(anonymized) < 2:
            anonymized = word[0] + "."

        return anonymized

    # Patterns de prompt injection courants (case-insensitive)
    _INJECTION_PATTERNS = re.compile(
        r"(?i)"
        r"("
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|prompts?)"
        r"|forget\s+(everything|all|your)\s+(instructions?|rules?|training)"
        r"|you\s+are\s+now\s+(a|an|my)\s+"
        r"|new\s+instructions?:\s*"
        r"|system\s*:\s*"
        r"|<\s*/?system\s*>"
        r"|override\s+(safety|security|instructions?|rules?)"
        r"|bypass\s+(security|filter|protection|rules?)"
        r"|jailbreak"
        r"|do\s+not\s+follow\s+(your|the)\s+(rules?|instructions?)"
        r"|act\s+as\s+if\s+you\s+(have\s+no|don[''']t\s+have)\s+(rules?|restrictions?)"
        r")"
    )

    def _neutralize_injection_attempts(self, text: str) -> str:
        """
        Détecte et neutralise les séquences de prompt injection.

        Stratégie : encadrer les séquences suspectes avec des marqueurs
        qui signalent au LLM que c'est du texte utilisateur (pas une instruction).
        """
        matches = list(self._INJECTION_PATTERNS.finditer(text))
        if not matches:
            return text

        logger.warning(
            "⚠️ Tentative de prompt injection détectée: %d pattern(s) — %s",
            len(matches),
            [m.group(0)[:40] for m in matches],
        )

        # Neutraliser en encadrant les séquences suspectes
        result = self._INJECTION_PATTERNS.sub(
            r"[USER_TEXT: \1]",
            text,
        )
        return result

    def restore_response(self, text: str, mapping: dict[str, str]) -> str:
        """
        Restaure les valeurs originales dans la réponse du LLM.

        Inverse de sanitize_user_input : remplace tous les tokens
        (~TOKEN, [EMAIL_1], etc.) par leurs valeurs d'origine.

        Args:
            text: Réponse du LLM contenant des tokens anonymisés
            mapping: Mapping {token: valeur_originale} retourné par sanitize_user_input

        Returns:
            Texte avec toutes les valeurs restaurées
        """
        result = text
        # Longest-first : un token court (``~DPNT``) peut être un PRÉFIXE d'un
        # token de collision (``~DPNT_2``) — ``_generate_anon_token`` est
        # non-injectif et désambiguïse par suffixe ``_N``. Sans tri, le replace
        # du token court corromp le long (``~DPNT_2`` → ``DUPONT_2`` au lieu de
        # ``DUPOONT``) = valeur restituée FAUSSE et plausible à l'utilisateur,
        # silencieuse. Aligné sur ``proxy.py::_pii_restore_recursive``. Les
        # tokens PII ``[TYPE_N]`` sont auto-délimités par ``]`` (pas de
        # collision de préfixe) ; le tri ne leur nuit pas.
        for placeholder in sorted(mapping, key=len, reverse=True):
            result = result.replace(placeholder, mapping[placeholder])
        return result

    async def restore_anonymized_values(
        self, text: str, user_id: int | None = None
    ) -> str:
        """Traduit les tokens ``~xxx`` (legacy ``sanitize_user_input``) en
        valeurs réelles dans le texte destiné à l'utilisateur ``user_id``.

        Depuis 2026-05-22, le reverse lookup se fait via ``anonymization_terms``
        (/data-privacy = seule source). Les tokens viennent de
        ``sanitize_user_input.passe 2`` qui utilise les pseudos du user
        courant. Sans ``user_id`` (callers legacy), on retourne le texte
        inchangé (fail-safe vs. fuite cross-user — la table est strictement
        user-scoped par design).
        """
        import re

        from app.core.database import get_session
        from app.models.anonymization_term import AnonymizationTerm
        from sqlalchemy import select

        tilde_pattern = re.compile(r"~[A-Za-z0-9_.]{2,}")
        tokens = set(tilde_pattern.findall(text))

        if not tokens or user_id is None:
            return text

        # Le format token ``~PSEUDO`` correspond à un ``pseudo_middle`` après
        # remplacement d'espaces par ``_`` côté ``sanitize_user_input``. On
        # reverse : enlever ``~`` et remplacer ``_`` par espace pour matcher
        # le ``pseudo_middle`` stocké.
        try:
            stripped = {t: t[1:].replace("_", " ") for t in tokens}
            lookup_values = list(stripped.values())

            async with get_session() as session:
                stmt = select(
                    AnonymizationTerm.pseudo_middle,
                    AnonymizationTerm.term,
                ).where(
                    AnonymizationTerm.user_id == user_id,
                    AnonymizationTerm.pseudo_middle.in_(lookup_values),
                    AnonymizationTerm.enabled.is_(True),
                )
                result = await session.execute(stmt)
                db_map = {row.pseudo_middle: row.term for row in result}

            mappings: dict[str, str] = {}
            for token, stripped_val in stripped.items():
                if stripped_val in db_map:
                    mappings[token] = db_map[stripped_val]
        except Exception:
            return text

        if not mappings:
            return text

        for anon, real in mappings.items():
            escaped = re.escape(anon)
            text = re.sub(rf"(?<!\w){escaped}(?!\w)", real, text)

        return text

    @staticmethod
    def substitute_sql_placeholders(sql: str, pii_mapping: dict[str, str]) -> tuple[str, list]:
        """
        Remplace les tokens anonymisés (~TOKEN, [EMAIL_X], etc.) dans le SQL
        par des paramètres ODBC (?).

        Sécurité :
        - Seuls les tokens QUOTÉS sont acceptés ('...token...')
        - Les tokens non-quotés sont REJETÉS (risque d'injection SQL)
        - TOUTES les occurrences d'un token sont remplacées (pas juste la première)
        - Les paramètres ODBC (?) empêchent l'injection SQL

        Cas gérés :
        - WHERE col = '~DPNT'      → WHERE col = ?  (param: 'DUPONT')
        - WHERE col LIKE '%~DPNT%' → WHERE col LIKE ? (param: '%DUPONT%')
        - WHERE col IN ('~DPNT')   → WHERE col IN (?) (param: 'DUPONT')

        Args:
            sql: Requête SQL avec tokens anonymisés
            pii_mapping: {token: valeur_originale}

        Returns:
            (sql_paramétrisé, params_list)
            Si aucun token trouvé, retourne (sql_original, [])
        """
        if not pii_mapping or not isinstance(pii_mapping, dict):
            return sql, []

        import re as _re
        import logging as _logging

        _logger = _logging.getLogger(__name__)

        # Phase 1 : parcourir les littéraux QUOTÉS une seule fois. Pour chacun qui
        # contient ≥1 placeholder, restaurer TOUS les placeholders présents
        # LONGEST-FIRST (collision-safe) puis émettre UNE substitution → UN ``?``.
        #
        # Avant ce correctif (#146), on bouclait PAR placeholder avec un pattern
        # ``'…<placeholder>…'``. Conséquences :
        #  - Collision : un token substring d'un autre (``~DPNT`` ⊂ ``~DPNT_2``)
        #    matchait AUSSI le littéral de l'autre → la même position enregistrée
        #    2× avec une valeur fausse (``DUPONT_2`` au lieu de ``DUPOONT``).
        #  - Plusieurs tokens dans un même littéral (``'~A et ~B'``) → littéral
        #    enregistré 1× par token.
        # Dans les deux cas : nb de ``?`` ≠ nb de params → crash ODBC (mismatch
        # de paramètres), OU filtre WHERE faux. Le parcours PAR LITTÉRAL règle les
        # deux : 1 littéral = 1 ``?`` = 1 param, restauration interne longest-first
        # (même doctrine que :meth:`restore_response`).
        sorted_placeholders = sorted((p for p in pii_mapping if p), key=len, reverse=True)
        substitutions: list[tuple[int, int, str]] = []
        quoted_found: set[str] = set()

        for m in _re.finditer(r"'([^']*)'", sql):
            inner = m.group(1)
            present = [p for p in sorted_placeholders if p in inner]
            if not present:
                continue
            param_value = inner
            for p in present:  # longest-first → pas de corruption de collision
                param_value = param_value.replace(p, pii_mapping[p])
            quoted_found.update(present)
            substitutions.append((m.start(), m.end() - m.start(), param_value))

        # Sécurité : un placeholder présent dans le SQL mais JAMAIS dans un
        # littéral quoté → non substitué (laissé tel quel) + warning (risque
        # d'injection si le LLM l'a mis sans quotes).
        for placeholder in pii_mapping:
            if placeholder and placeholder in sql and placeholder not in quoted_found:
                _logger.warning(
                    "Placeholder %s trouvé NON-QUOTÉ dans le SQL — ignoré "
                    "(risque d'injection). Le LLM doit utiliser des quotes : "
                    "WHERE col = '%s'",
                    placeholder,
                    placeholder,
                )

        if not substitutions:
            return sql, []

        # Phase 2 : Substituer en ordre inverse (pour ne pas décaler les positions)
        substitutions.sort(key=lambda s: s[0], reverse=True)
        result_sql = sql
        params_reversed: list[str] = []

        for pos, length, param_value in substitutions:
            result_sql = result_sql[:pos] + "?" + result_sql[pos + length :]
            params_reversed.append(param_value)

        # Remettre les params dans l'ordre du SQL (on a inséré en reverse)
        params = list(reversed(params_reversed))

        return result_sql, params

    def filter_tool_results(self, tool_name: str, raw_result: Any) -> dict:
        """
        Pass-through legacy. Tous les outils retournent leur dict tel quel —
        l'anonymisation des données utilisateur est désormais traitée en
        amont par :func:`anonymize_for_llm` (proxy unifié) au niveau des
        tool handlers (cf. :func:`agent_tools._handle_execute_sql` /
        :func:`_handle_peek_table_data`). La couche lossy historique
        ``obfuscate_for_peek`` a été retirée tâche #5.

        Cette méthode est conservée comme garde de compatibilité tant que
        des tests legacy l'invoquent ; aucun call site prod ne l'utilise
        depuis tâche #6.

        Args:
            tool_name: Nom de l'outil ayant produit le résultat
            raw_result: Résultat brut de l'outil

        Returns:
            ``raw_result`` tel quel si dict, sinon ``{"_raw": str(raw_result)}``.
        """
        # Defense-in-depth : si raw_result n'est pas un dict, on l'encapsule
        # (les outils retournent normalement un dict, mais un bug pourrait envoyer autre chose).
        if not isinstance(raw_result, dict):
            logger.warning(
                "filter_tool_results[%s]: raw_result n'est pas un dict, pass-through", tool_name
            )
            return {"_raw": str(raw_result)}

        logger.debug("filter_tool_results[%s]: pass-through legacy", tool_name)
        return raw_result


# Singleton module-level
_confidentiality_manager: ConfidentialityManager | None = None


def get_confidentiality_manager() -> ConfidentialityManager:
    """Retourne le singleton ConfidentialityManager (création paresseuse)."""
    global _confidentiality_manager
    if _confidentiality_manager is None:
        _confidentiality_manager = ConfidentialityManager()
        logger.info("ConfidentialityManager initialisé")
    return _confidentiality_manager
