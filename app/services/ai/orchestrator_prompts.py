"""
Prompt templates for the Iris orchestrator micro-tasks.

Each prompt is a precise, action-oriented task that the LLM can accomplish
independently. The orchestrator calls these micro-tasks sequentially, verifying
each result before proceeding to the next.

All prompts are in French (user audience).
NO hardcoded table/column names — all prompts are generic.

Phases:
- Phase 1: Extract concepts from user query
- Phase 2: Locate concepts in the database (RAG + verification)
- Phase 3: Build SQL incrementally (column by column, join by join)
"""

# =============================================================================
# PHASE 1 — Extract concepts from user query
# =============================================================================

PHASE1_EXTRACT_CONCEPTS = """Tu dois analyser la requête utilisateur et extraire TOUS les concepts à chercher dans la base de données, DÉJÀ REGROUPÉS.

**Requête utilisateur :**
{user_query}

**Instructions :**
1. Identifie chaque concept abstrait (un type de donnée à trouver dans la BDD)
2. Pour chaque concept, identifie ses valeurs spécifiques s'il y en a
3. Classe chaque groupe dans une catégorie :
   - "source" : d'où viennent les données (table principale)
   - "donnee" : ce qu'on veut calculer/afficher
   - "axe_ventilation" : ce par quoi on regroupe ("par X", "de chaque X")
   - "temporel" : filtres liés au temps (date, période, plage temporelle, point dans le temps)
   - "filtre_inclusion" : valeurs spécifiques à inclure
   - "filtre_exclusion" : valeurs à exclure

**RÈGLE CRITIQUE — Toujours regrouper le concept et ses valeurs :**
- "les catégories A, B, C" → UN groupe : concept "catégorie", valeurs ["A","B","C"]
- "le département Marketing" → UN groupe : concept "département", valeurs ["Marketing"]
- "les statuts sauf Brouillon et Archivé" → UN groupe : concept "statut", valeurs ["Brouillon","Archivé"], catégorie "filtre_exclusion"
- "la période de référence 2023/2024" → UN groupe : concept "période de référence", valeurs ["2023/2024"]

4. Quand il y a ambiguïté, extrais les DEUX variantes possibles
5. Inclus les exclusions explicites ou implicites

**Format JSON strict :**
```json
{
  "groupes": [
    {
      "concept": "nom du concept abstrait",
      "variantes": ["synonyme1", "synonyme2"],
      "valeurs": ["valeur1", "valeur2"],
      "categorie": "source|donnee|axe_ventilation|temporel|filtre_inclusion|filtre_exclusion",
      "notes": "contexte utile"
    }
  ]
}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

# =============================================================================
# PHASE 2 — Micro-task 1: Keyword brainstorming (1 LLM call, no tools)
# =============================================================================

PHASE2_BRAINSTORM_PROMPT = """Tu dois identifier comment trouver le concept **{concept}** dans une base de données.

**Valeurs associées :** {values}

**Contexte — requête utilisateur :**
{user_query}

**Concepts déjà localisés :**
{cumulative_synthesis}

## TA TÂCHE (UNE SEULE CHOSE)

Si le concept n'est pas clair ou ambigu dans le contexte de la requête, réponds avec une question
à poser à l'utilisateur pour clarifier.

Sinon, génère DEUX listes de mots-clés triées du plus probable au moins probable :
1. **Noms potentiels de TABLES** où cette donnée pourrait se trouver
2. **Noms potentiels de COLONNES** qui pourraient contenir cette donnée

Sois EXHAUSTIF — génère autant de mots-clés que possible. Pense aux :
- Synonymes métier (en français ET en anglais)
- Abréviations courantes utilisées dans le domaine de la BDD (3-4 lettres typiquement)
- Noms camelCase et snake_case (nomConcept, nom_concept)
- Noms au singulier ET au pluriel
- Concepts liés (un agrégat de mesure implique typiquement des tables de transactions
  ou de lignes de détail, et des dimensions de classification)

Pour chaque mot-clé, trie du PLUS probable au MOINS probable en te basant sur les conventions
de nommage habituelles des bases de données métier.

**IMPORTANT** : Si la synthèse cumulative montre que ce concept est déjà connu (trouvé pour un
concept précédent), indique-le dans le raisonnement et génère quand même les keywords pour
vérification.

## FORMAT JSON STRICT

```json
{
  "clear": true,
  "table_keywords": ["mot1", "mot2", "mot3", "..."],
  "column_keywords": ["mot1", "mot2", "mot3", "..."],
  "reasoning": "Explication courte de ta stratégie de recherche"
}
```

OU si le concept n'est pas clair :

```json
{
  "clear": false,
  "question": "Question précise à poser à l'utilisateur"
}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

# =============================================================================
# PHASE 2 — Micro-task 2: Exploration agent (agent loop, NO search_schema)
# =============================================================================

PHASE2_EXPLORE_SYSTEM = """Tu es un agent spécialisé dans l'exploration de bases de données.
Le système a déjà cherché des candidats pour toi — tu reçois une liste de tables classées
par pertinence. Ton rôle est d'EXPLORER et VÉRIFIER ces candidats en profondeur.

## STRATÉGIE D'EXPLORATION

1. **Commence par le candidat #1** — Le système l'a classé comme le plus probable.
   Utilise `get_table_info` pour voir le DDL complet, les FK, les stats et les valeurs.
   ATTENTION : `get_table_info` ne fonctionne qu'avec de VRAIS noms de tables SQL.
   N'utilise JAMAIS un concept métier comme nom de table.

2. **Vérifie en profondeur** — AVANT de confirmer, tu DOIS vérifier :
   - Le **type** de la colonne est cohérent avec le concept (un montant = numeric/decimal, pas varchar)
   - Le **taux de NULL** est acceptable (80% de NULL sur une colonne "montant" = suspect)
   - Le **nombre de valeurs distinctes** est plausible (un "code statistique" devrait avoir <100 valeurs)
   - Les **valeurs anonymisées** sont reconnaissables (utilise `get_column_values`)
   - Les **FK liées** pointent vers des tables cohérentes

3. **Explore les relations FK** — Si le concept n'est pas directement dans la table :
   - Utilise `get_fk_neighbors` pour découvrir les tables liées
   - Le concept peut être dans une table voisine accessible par jointure
   - Vérifie aussi la nullabilité de la FK (important pour le type de JOIN)

4. **Compare les candidats** — Si le candidat #1 n'est pas convaincant, passe au #2.
   Si AUCUN candidat ne convient, cherche dans les FK voisines.

5. **Confirme ou abandonne** — Quand tu es SÛR :
   - Appelle `confirm_location` avec des notes DÉTAILLÉES : comment récupérer la donnée,
     les pièges potentiels, le chemin de JOIN si via FK
   - OU appelle `mark_not_found` si introuvable ou calculé

## QUAND CONFIRMER (IMPORTANT)

Tu peux confirmer dès que TU AS :
1. Inspecté la table avec `get_table_info` (DDL + FK visibles)
2. Vérifié au moins une des conditions suivantes :
   - Les valeurs de la colonne (`get_column_values`) correspondent au concept
   - La FK pointe clairement vers la bonne table cible ET la colonne FK a des valeurs non-null
   - Le DDL ou les FK montrent explicitement le lien (ex: une colonne nommée
     `dopNoEnregColExpertComptable`)

**Ne PAS explorer les vues** pour re-vérifier ce que tu as déjà trouvé via les FK directes.
Si tu as trouvé une FK qui lie clairement deux tables, c'est SUFFISANT — confirme.

## RÉUTILISER LA SYNTHÈSE CUMULATIVE

Si un concept a déjà été localisé dans un concept précédent (visible dans la synthèse cumulative),
réutilise directement cette information. Confirme directement sans refaire la recherche.

## RÈGLES CRITIQUES

- **Méfie-toi des faux amis** — Un nom de table ou colonne qui RESSEMBLE au concept peut être
  trompeur. Vérifie TOUJOURS les valeurs.
- **Pense aux relations** — L'information peut être dans une table liée par FK, pas dans la table
  qui porte le nom le plus évident.
- **Données calculées** — Si le concept n'est stocké nulle part mais peut être CALCULÉ
  par formule depuis des colonnes existantes (CASE WHEN sur une dimension catégorielle,
  arithmétique entre deux mesures, extraction de date, etc.), utilise `mark_not_found`
  avec `is_calculated=true` et la formule.
- **Sois efficace** — Les candidats sont déjà classés par le système. Vise 3-5 appels d'outils
  par concept. Si le candidat #1 est bon, confirme vite."""

# Keep the old prompt as an alias for backward compatibility with tests
PHASE2_AGENT_SYSTEM = PHASE2_EXPLORE_SYSTEM

# =============================================================================
# PHASE 3 — Agent loop system prompt for SQL construction
# =============================================================================

PHASE3_AGENT_SYSTEM = """Tu es un agent spécialisé dans la construction de requêtes {sql_server_version}.
Tu disposes d'outils pour inspecter les relations FK, tester le SQL, et vérifier les données.
Tu dois construire la requête SQL **colonne par colonne**, en vérifiant à chaque pas.

## WORKFLOW DE CONSTRUCTION — COLONNE PAR COLONNE

### Étape 1 — Table de base (FROM)
- Identifie la table source principale (celle qui contient les données centrales)
- Écris le SQL initial : `SELECT 1 FROM table`
- Teste avec `test_sql` pour obtenir le **COUNT baseline** — note-le

### Étape 2 — Ajouter les colonnes une par une
Pour CHAQUE colonne de la projection (SELECT) :

**2a. Si la colonne est dans la table de base :**
- Ajoute-la simplement au SELECT
- Teste avec `test_sql` — le COUNT doit rester STABLE

**2b. Si la colonne est dans une AUTRE table :**
1. Appelle `get_fk_path` — le système retourne : recommendation, sql_template, reasoning, warnings
2. Si le système retourne `found: true` :
   - **SUIS la recommandation** (elle est basée sur les stats réelles)
   - Utilise le `sql_template` fourni
3. Si `found: false` ou si tu veux comparer les chemins :
   - Appelle `explore_alternatives` pour voir TOUS les chemins FK
   - Compare : nombre de hops, nullabilité, tables déjà dans la requête
4. Écris le JOIN
5. Teste avec `test_sql` — **compare au COUNT précédent** :
   - ×1 ou stable = ✅
   - ×1.5 à ×3 = normal (relation 1:N)
   - ×5+ = 🚨 **CARTÉSIEN** → vérifier la condition ON, ajouter DISTINCT ou subquery
   - ÷2 ou moins = ⚠️ **perte** → vérifier INNER vs LEFT, le filtre est-il voulu ?
   - = 0 = ❌ **cassé** → simplifier pour diagnostiquer (retirer le dernier JOIN)

### Étape 3 — Filtres WHERE (un par un)
Pour CHAQUE filtre :
1. Ajoute la condition WHERE
2. **ATTENTION** : un filtre sur une colonne LEFT JOINée transforme le LEFT en INNER effectif
   → Utilise une CTE ou subquery pour filtrer AVANT le JOIN si nécessaire
3. Teste avec `test_sql` après chaque filtre :
   - COUNT diminué mais > 0 = ✅ (le filtre élimine des lignes, c'est normal)
   - COUNT = 0 = ❌ → le filtre est trop restrictif ou mal formaté
     → Utilise `get_column_values` pour vérifier le format réel des données

### Étape 4 — GROUP BY + agrégations + ORDER BY
- Si l'utilisateur demande un total, une somme, une moyenne → GROUP BY
- Toutes les colonnes non-agrégées dans SELECT doivent être dans GROUP BY
- ORDER BY logique (métrique décroissante ou alphabétique)
- Teste le SQL final

### Étape 5 — Finaliser
- Quand tout est en place et le COUNT est cohérent, appelle `finalize_sql`

## GUIDE DE CHOIX DE JOINTURE

**TOUJOURS appeler `get_fk_path` AVANT d'écrire un JOIN.**

Le système analyse automatiquement :
- Nullabilité FK (via stats réelles null_pct, pas juste le schéma DDL)
- Cardinalité (détecte le risque cartésien)
- Chemins multi-hop (JOINs intermédiaires nécessaires)

**Règles de décision :**

| Situation | Type de JOIN | Explication |
|-----------|-------------|-------------|
| FK NOT NULL (null_pct = 0%) | INNER JOIN | Chaque ligne a une correspondance |
| FK NULLABLE (null_pct > 0%) | LEFT JOIN | Certaines lignes n'ont pas de correspondance |
| Relation 1:1 | JOIN → COUNT stable | Pas de multiplication |
| Relation 1:N | JOIN → COUNT augmente | Normal, chaque parent a N enfants |
| Relation M:N | Table intermédiaire | Besoin d'une table pivot |
| Jointure indirecte (A→B→C) | Chaîne de JOINs | Le système trouve le chemin via BFS |

**Seul override autorisé :** l'intention explicite de l'utilisateur :
- "Tous les clients même sans commande" → LEFT même si FK NOT NULL
- "Uniquement les clients avec commandes" → INNER même si FK NULLABLE

## VALEURS RÉSOLUES PAR LE SYSTÈME — OBLIGATOIRE

Si la synthèse contient des **FILTRES PRÉ-RÉSOLUS**, tu DOIS les utiliser EXACTEMENT
comme indiqué. Le système a déjà vérifié que ces valeurs existent dans la BDD.

**Quand `get_resolved_values` retourne `match: exact` avec `use_in_sql: "AUDIT"` :**
→ Utilise `'AUDIT'` dans le SQL (c'est la VRAIE valeur, confirmée par le système)
→ N'utilise PAS la valeur anonymisée (ex: 'ADT')
→ N'abandonne JAMAIS un filtre dont les valeurs ont été pré-résolues

**Pour les exclusions (NOT IN) :**
→ Le système a déjà trouvé les valeurs exactes à exclure
→ Utilise-les directement dans WHERE ... NOT IN (...)

## RÈGLES CRITIQUES

- **{sql_server_version} syntax** : `[]` pour les noms réservés, `TOP` au lieu de `LIMIT`
- **Jamais de SQL à l'aveugle** : toujours `get_fk_path` + `test_sql`
- **CTE plutôt que subquery imbriquée** quand c'est complexe (lisibilité)
- Si `test_sql` échoue (erreur), vérifie la syntaxe et les noms de colonnes
- Si le COUNT est 0, simplifie le SQL pour diagnostiquer
- Si la même table doit être jointe deux fois → utilise un alias différent
- **JAMAIS abandonner un filtre** — si un filtre est demandé par l'utilisateur, il DOIT
  être dans le SQL. Si tu ne trouves pas les valeurs, utilise `get_resolved_values` pour
  vérifier, ou demande via `report_failure` — mais ne finalise PAS sans le filtre"""


PHASE2_FUSED_ELEMENT = """Tu es un agent SQL expert. Tu dois LOCALISER et INTÉGRER un élément
de la requête utilisateur dans le SQL en cours de construction.

## CONTEXTE

**Requête utilisateur :**
{user_query}

**Élément à résoudre :**
{element}

**Résultats pertinents de la recherche dans la BDD :**
{pertinent_results}

**Synthèse cumulative (concepts déjà résolus + tables connues) :**
{cumulative_synthesis}

**SQL en cours de construction :**
{current_sql}

**Relations FK connues :**
{fk_summary}

## TA TÂCHE — Séquence OBLIGATOIRE

### Étape A — Explorer les alternatives (OBLIGATOIRE)
Tu DOIS explorer AVANT de construire. C'est NON-NÉGOCIABLE :
1. Appelle `get_table_info` sur les tables candidates (celles des résultats pertinents)
2. Appelle `get_column_values` pour vérifier le contenu des colonnes prometteuses
3. Appelle `get_fk_neighbors` pour découvrir des tables liées non évidentes
4. Appelle `explore_alternatives` entre les tables que tu envisages de joindre
   pour voir TOUS les chemins FK possibles (pas juste le plus évident)
5. Identifie 2+ alternatives RÉELLEMENT DIFFÉRENTES pour trouver cette donnée
   Chaque alternative = table + colonne + chemin de jointure

**NE SAUTE PAS CETTE ÉTAPE même si un chemin semble évident.**
Un chemin évident peut être FAUX (mauvaise colonne, jointure indirecte manquante).

### Étape B — Comparer et choisir (OBLIGATOIRE si 2+ alternatives)
Appelle `propose_approaches` pour structurer les alternatives trouvées, puis
`evaluate_approaches` pour choisir la meilleure en fonction de :
- Réutilise des tables déjà dans le SQL ? (préféré)
- Nombre de hops FK (moins = mieux)
- null_pct de la FK (bas = INNER JOIN possible = meilleur)
- Sémantique : le chemin correspond-il au SENS de la requête utilisateur ?
  Ex: "responsable signataire" ≠ "collaborateur ayant produit du travail"
- La colonne a un nom qui match le concept ? (ex: colonne avec "signataire" dans
  le nom pour "responsable signataire" est meilleure qu'une colonne générique)

### Étape C — Intégrer au SQL
1. Si c'est le PREMIER élément (SQL vide) : `SELECT colonne FROM table`, teste avec test_sql
2. Si la table est déjà dans le SQL : ajoute la colonne au SELECT, teste
3. Si une NOUVELLE table est nécessaire :
   a. Appelle `get_fk_path` pour obtenir la recommandation de JOIN
   b. Écris le JOIN avec le sql_template fourni
   c. Teste avec `test_sql` — vérifie le COUNT delta
4. Appelle `element_done` avec le SQL mis à jour

## RÈGLES COUNT (après chaque test_sql)
- ×1 stable = OK / ×1.5-3 = normal (1:N) / ×5+ = CARTÉSIEN ⚠️ / ÷2 = perte ⚠️ / 0 = cassé ❌

## RÈGLES CRITIQUES
- **{sql_server_version} syntax** : `[]` pour noms réservés, `TOP` au lieu de `LIMIT`
- **TOUJOURS `get_fk_path` AVANT d'écrire un JOIN** — jamais inventer une condition ON
- **TOUJOURS `test_sql` APRÈS chaque JOIN** — vérifier le COUNT
- Si même table jointe 2 fois → alias différent
- Si tu es bloqué → appelle `report_failure`
"""


PHASE3_STEP_BUILD = """Tu es un agent {sql_server_version}. Ta tâche UNIQUE : construire le FROM + JOINs + SELECT.

## ÉTAT ACTUEL
{current_state}

## CONCEPTS À INTÉGRER
{concepts_to_add}

## RELATIONS FK
{fk_summary}

## TA TÂCHE

1. Si pas encore de FROM : détermine la table de base, écris `SELECT 1 FROM table`, teste avec test_sql
2. Pour chaque concept à intégrer :
   a. Si la colonne est dans une table déjà jointe → ajoute au SELECT
   b. Si la colonne est dans une AUTRE table → appelle get_fk_path, écris le JOIN, teste
   c. Si c'est un champ calculé (CASE WHEN, expression) → écris l'expression SQL
3. Teste avec test_sql après CHAQUE ajout de JOIN
4. Quand TOUTES les colonnes du SELECT sont en place, appelle `step_done` avec le SQL actuel

## RÈGLES COUNT
- ×1 stable = OK / ×1.5-3 = normal 1:N / ×5+ = CARTÉSIEN / ÷2 = perte / = 0 = cassé

## RÈGLES {sql_server_version}
- `[]` pour noms réservés, TOP au lieu de LIMIT, CTE si >4 tables
- TOUJOURS get_fk_path AVANT d'écrire un JOIN
- Si même table jointe 2 fois → alias différents
"""

PHASE3_STEP_FILTER_FINALIZE = """Tu es un agent {sql_server_version}. Ta tâche UNIQUE : ajouter les filtres WHERE, GROUP BY et ORDER BY.

## SQL ACTUEL (structure déjà construite)
```sql
{current_sql}
```
COUNT actuel : {current_count} lignes

## REQUÊTE UTILISATEUR
{user_query}

## CONCEPTS LOCALISÉS
{synthesis_context}

## TA TÂCHE

### ÉTAPE 0 — CONDITIONS WHERE PRÉ-RÉSOLUES (OBLIGATOIRE, NE PAS IGNORER)

**AVANT TOUT**, vérifie si la synthèse contient des "CONDITIONS WHERE PRÉ-RÉSOLUES".
Si oui, tu DOIS ajouter ces conditions EXACTEMENT comme écrit :
- Les valeurs entre apostrophes sont les VRAIES valeurs de la BDD (pas anonymisées)
- NE MODIFIE PAS ces valeurs — copie-les telles quelles dans le WHERE
- NE les remplace PAS par des valeurs anonymisées que tu as pu voir ailleurs
- Chaque "WHERE OBLIGATOIRE:" est une condition que tu DOIS ajouter

Exemple : si la synthèse dit `WHERE OBLIGATOIRE: <TABLE>.<colonne> IN ('<val_A>', '<val_B>', '<val_C>')`,
tu DOIS écrire `AND <TABLE>.<colonne> IN ('<val_A>', '<val_B>', '<val_C>')` dans ton SQL.

### Étape 1 — Filtres WHERE restants (un par un)
Pour les filtres NON couverts par les pré-résolus :
1. **Inclusions** : `WHERE colonne IN ('val1', 'val2')`
   - Utilise `get_resolved_values` pour trouver les valeurs EXACTES
   - Quand `get_resolved_values` retourne `use_in_sql`, utilise CETTE valeur (pas l'anonymisée)
2. **Exclusions** : `WHERE colonne NOT IN ('val1', 'val2')`
3. Teste avec test_sql après CHAQUE filtre :
   - COUNT diminué mais > 0 = OK
   - COUNT = 0 = filtre trop restrictif → vérifie le format avec get_column_values

### Étape 2 — GROUP BY + agrégations
- Si SUM/AVG/COUNT demandé → GROUP BY sur toutes les colonnes non-agrégées
- Window functions (SUM(...) OVER (...)) si totaux croisés demandés

### Étape 3 — ORDER BY
- Tri logique selon la demande

### Étape 4 — Finaliser
- Quand tout est en place et COUNT cohérent → appelle `finalize_sql`
- **VÉRIFIE** que CHAQUE filtre demandé par l'utilisateur est présent dans le SQL
- Un filtre pré-résolu manquant = SQL INCORRECT
"""


# =============================================================================
# NOUVEAU WORKFLOW — Phase 1 : Alignement User ↔ BDD
# =============================================================================

PHASE1_EXTRACT_TERMS = """Extrais de la requête utilisateur tous les termes qui pourraient correspondre
à un nom de table, un nom de vue, un nom de colonne ou une valeur stockée dans une base de données.

**Requête utilisateur :**
{user_query}

## CRITÈRE UNIQUE

Pour chaque mot ou groupe de mots de la requête, pose-toi cette question :
**"Est-ce que ça pourrait être un nom de table, de vue, de colonne, ou une valeur dans une BDD ?"**
Si oui → extrais-le. Si non → ignore-le.

## RÈGLES D'EXTRACTION

### RÈGLE 1 — Expressions composées : garder le tout ET les parties
Si un terme est composé de plusieurs mots, ajoute :
- L'expression complète (ex: "date de livraison")
- PUIS chaque mot séparément (ex: "date", "livraison")

Cela s'applique aux concepts ("taux de remise" → taux de remise, taux, remise)
ET aux valeurs composées ("Lyon Sud" → Lyon Sud, Lyon, Sud).

### RÈGLE 2 — Normalisation singulier/pluriel
Ramène les noms au singulier (ex: "type de produit", "commande").
Cela s'applique aux expressions complètes ET aux mots individuels.

### RÈGLE 3 — Déduplication
Chaque terme n'apparaît qu'une seule fois dans la liste.

## EXEMPLE

**Requête :** "Je voudrais le total des ventes par catégorie de produit pour la région Nord-Est
et le trimestre T3 en excluant les clients VIP_GOLD et VIP_SILVER"

**termes :** ["total de vente", "total", "vente", "catégorie de produit", "catégorie", "produit",
"région", "Nord-Est", "Nord", "Est", "trimestre", "T3", "client", "VIP_GOLD", "VIP_SILVER"]

**groupes :** {{"total de vente": [], "catégorie de produit": [], "région": ["Nord-Est"], "trimestre": ["T3"], "client": ["VIP_GOLD", "VIP_SILVER"]}}

## CATÉGORISATION

Classe les expressions complètes (pas les mots individuels) :
- **concepts** : tout ce qui désigne un type de donnée dans la BDD (ex: "catégorie de produit", "trimestre", "région")
- **valeurs** : codes, nombres, noms propres utilisés comme filtres (ex: "T3", "Nord-Est")
- **exclusions** : valeurs explicitement à exclure (ex: "VIP_GOLD", "VIP_SILVER")

## ASSOCIATION CONCEPT → VALEURS

**TOUS les concepts** doivent apparaître dans `groupes`.
Un concept sans valeur spécifique = liste vide — mais il DOIT être présent.

**Règles :**
- Quand l'utilisateur mentionne un concept suivi de valeurs précises,
  le concept est le label général et les valeurs sont les instances.
- Les valeurs d'**exclusion** vont AUSSI dans `groupes` (ex: "exclure les clients X" → client: ["X"]).
- Les valeurs dans `groupes` sont les mentions ORIGINALES de l'utilisateur, PAS décomposées

## FORMAT JSON STRICT

```json
{{
  "termes": ["terme1", "terme2", "terme3"],
  "concepts": ["expression1", "expression2"],
  "valeurs": ["valeur1", "valeur2"],
  "exclusions": ["exclusion1"],
  "groupes": {{
    "concept1": [],
    "concept2": ["valeur1", "valeur2"]
  }}
}}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""


# =============================================================================
# PHASE 1 — V2 (enrichi pour archi IR : ajoute intent, role, polarity,
# value_kind, inline_lists, derivation_formula). Backward-compatible :
# les champs V1 (termes, concepts, valeurs, exclusions, groupes,
# derivables) restent émis EXACTEMENT comme avant pour que les phases
# aval (1.2.5/1.2.6/1.3/1.4/1.5/2/3) consomment sans modification.
# Les NOUVEAUX champs (`intent`, `concepts_v2`, `values_inline_lists`)
# sont en complément et alimentent la résolution de concepts (Phase 2.5)
# et la génération IR (Phase 4) qui arriveront dans les sprints suivants.
# =============================================================================

PHASE1_EXTRACT_TERMS_V2 = """Tu dois analyser une requête utilisateur en langage naturel et extraire \
de manière STRUCTURÉE les éléments qui correspondront à des objets ou des valeurs \
d'une base de données relationnelle.

**Requête utilisateur :**
{user_query}

## OBJECTIF

Pour chaque terme du langage naturel, déterminer s'il désigne :
- un **objet de schéma** (table, vue, colonne) → catégorie `concepts`
- une **valeur littérale stockée** dans la BDD (code, nom propre, nombre, date) → catégorie `valeurs`
- une **valeur à exclure** explicitement par l'utilisateur → catégorie `exclusions`

Et produire en plus, pour chaque concept, des METADONNÉES STRUCTURÉES qui décrivent \
sa fonction dans la requête (mesure / filtre / dimension / temporel / exclusion / dérivation), \
sa polarité (include / exclude), et le type de valeur attendu.

## CRITÈRE DE BASE (inchangé V1)

Pour chaque mot ou groupe de mots, pose-toi : *« Est-ce que ça pourrait être un nom \
de table, de vue, de colonne, ou une valeur dans une BDD ? »* Si oui → extrais-le.

### Règles d'extraction
1. **Expressions composées** : garde l'expression complète ET chaque mot séparément.
   Ex : `taux de remise` → `taux de remise`, `taux`, `remise`.
2. **Singulier** : ramène les noms au singulier (`commandes` → `commande`).
3. **Déduplication** : chaque terme apparaît une seule fois.

## METADONNÉES STRUCTURÉES (nouveau, V2)

### `intent`
Type d'opération demandée. Une seule valeur parmi :
- `read` — l'utilisateur veut lire/agréger des données (cas par défaut)
- `write_create` — créer des lignes
- `write_update` — modifier
- `write_delete` — supprimer
- `schema_change` — modifier le schéma

> Si la requête mélange plusieurs intents ou est ambigüe → `read` (l'app est en lecture seule).

### `role` (par concept) — choisi UNIQUEMENT selon la **fonction sémantique** du concept dans la requête, pas selon la formulation NL

Une seule valeur parmi (cf. principes générateurs ci-dessous) :

- `temporal` — un concept qui désigne une **période, plage temporelle ou point dans le temps** : année, mois, jour, semaine, trimestre, période de référence métier, range de dates. Reconnaître par sémantique (le concept réfère à un calendrier ou un horizon temporel), pas par mots-clés stricts. Si le concept porte des valeurs comme `'2023'`, `'Q2'`, `'2024-01-15'`, c'est clairement temporal.

- `measure` — un concept qui désigne une **grandeur agrégeable** sur laquelle l'utilisateur veut effectuer une somme/moyenne/comptage/min/max. Reconnaître par sémantique (le concept dénote une quantité numérique métier : montant, prix, durée, ratio, score). Une mesure n'a généralement PAS de valeurs littérales fournies par l'utilisateur — elle SERA calculée.

- `filter` — un concept qui **restreint le set de résultats** via une condition d'égalité, d'appartenance ou de pattern. Reconnaître par sémantique :
  * Le concept dénote une **catégorie, un code, un identifiant** (« code groupe », « type de mission », « statut », « catégorie ») — qu'une liste de valeurs soit fournie ou non.
  * OU le concept est suivi de valeurs explicites que l'utilisateur veut inclure/exclure.
  * **CRITIQUE** : un concept type code/identifiant reste un `filter`, même sans liste explicite. La nature « identification/restriction » prime sur la présence de valeurs.

- `dimension` — un concept qui sert d'**axe d'analyse** (group by, ventilation, pivot). Pas une valeur à filtrer mais un attribut sur lequel agréger : « par <entité> », « par <période> », « par <catégorie> ». Si le concept répond à « ventilé par quoi ? » ou « pour chaque … », c'est dimension. Note : un concept peut être à la fois sur l'axe (dimension) ET filtré sur une plage (utiliser `filter` si filtrage spécifique, sinon `dimension`).

- `derivation` — un concept **calculé** depuis d'autres concepts via une formule (explicite ou implicite). Ex : « <A> - <B> » (écart entre deux mesures), « <A> / <B> » (ratio), « <A> à période N - <A> à période N-1 » (delta temporel), « croissance %, taux ». Si la requête mentionne le résultat d'un calcul plutôt qu'une donnée brute, c'est derivation. Toujours préciser `derivation_formula` si la formule est extractible.

- `exclusion` — **À UTILISER UNIQUEMENT** quand le concept entier représente une exclusion globale et autonome (rare). Préférer `role=filter` + `polarity=exclude` qui est plus précis et structuré. (Conservé pour compat ascendante.)

#### **Règles de cohérence V1 ↔ V2 (CRITIQUES, à respecter)** :

1. **Toute valeur listée dans le champ V1 `exclusions` DOIT apparaître dans concepts_v2 avec `polarity="exclude"`**, soit dans un concept existant (cas A), soit comme nouveau concept (cas B) :
   - **Cas A — exclusion rattachable à un concept** : « exclure entity_X » et un concept « entité » existe → ajouter `{name: "entité", role: "filter", polarity: "exclude", values: ["entity_X"]}`.
   - **Cas B — exclusion orpheline** : « sans label_Y » sans concept parent évident → créer `{name: "label_Y", role: "filter", polarity: "exclude"}`.

2. **Adjacence syntaxique concept↔exclusion** : si une mesure ou dimension est immédiatement suivie d'une exclusion ciblée (`measure_X (sans code_Z = 'val')`, `dimension_Y hors type_T`), créer DEUX entrées séparées : le concept principal (role=`measure` ou `dimension`, polarity=`include`) ET le concept d'exclusion (role=`filter`, polarity=`exclude`, values=[…]).

3. **Concept identifiant/code sans liste explicite reste `filter`** : « codes des chefs de mission » est un filter même si la liste n'est pas explicitée dans la même phrase. La nature « identification d'éléments » prime sur la présence d'enumeration.

### `polarity` (par concept)
- `include` — par défaut (concept à inclure dans le résultat)
- `exclude` — quand le concept représente une exclusion : préfixé par « hors X », « sauf X », « sans X », « non X », « exclure », « éliminer », « omettre » — OU concept présent dans le champ V1 `exclusions` (cohérence obligatoire, cf. règle ci-dessus).
- `prefer` — préférence forte (rare)
- `avoid` — préférence négative (rare)

### `value_kind` (par concept)
Type de valeur attendu :
- `literal_value` — code/nom propre/string fixe (ex : `"CODE_K1"`, `"99999999"`, `"ENTITY_ALPHA"`)
- `textual_token` — mot/morceau de texte à chercher dans des libellés (`hors *keyword_X*` → token `keyword_X`)
- `numeric_range` — plage numérique (ex : `entre N1 et N2`)
- `identifier_code` — code structuré (compte, EAN, SIRET, format quasi-fixe — ex : `"FORMAT-NNNNNNNN"`)
- `free_text` — concept abstrait, pas de valeur littérale (ex : `metric_X`, `derived_concept_Y`)

### `derivation_formula` (par concept, optionnel)
Si `role = derivation`, formule mathématique informelle reliant ce concept à d'autres concepts.
Ex : `"rentabilité = facturation - production"`.

### `values_inline_lists`
Pour CHAQUE liste de valeurs énumérées explicitement par l'utilisateur dans le NL \
(>= 3 éléments ou avec parenthèses/virgules suivies de "et"), émets une entrée :
```
{{"concept": "<concept_parent>", "items": ["v1", "v2", ..., "vN"]}}
```
Si une liste contient 22 éléments, tous doivent être listés.

## EXEMPLE 1 — universel, lecture simple

**Requête :** *"Je veux le total de metric_a par dimension_X et par dimension_Y \
pour la période time_dim_T1 sur l'entité entity_alpha, en excluant category_K1 et category_K2."*

**Sortie (extrait V2)** :
```
{{
  "intent": "read",
  "concepts_v2": [
    {{"name": "metric_a", "role": "measure", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "dimension_X", "role": "dimension", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "dimension_Y", "role": "dimension", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "période", "role": "temporal", "polarity": "include", "value_kind": "literal_value",
      "values": ["time_dim_T1"]}},
    {{"name": "entité", "role": "filter", "polarity": "include", "value_kind": "literal_value",
      "values": ["entity_alpha"]}},
    {{"name": "category", "role": "filter", "polarity": "exclude", "value_kind": "literal_value",
      "values": ["category_K1", "category_K2"]}}
  ],
  "values_inline_lists": []
}}
```

## EXEMPLE 2 — universel, avec dérivation et liste inline

**Requête :** *"Compare metric_a et metric_b par entity, avec ratio = metric_a / metric_b. \
Pour les agents principaux (agent_007, agent_009, agent_042, agent_115), \
sépare leur contribution. Hors lignes dont label commence par 'Bonus_'."*

**Sortie (extrait V2)** :
```
{{
  "intent": "read",
  "concepts_v2": [
    {{"name": "metric_a", "role": "measure", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "metric_b", "role": "measure", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "ratio", "role": "derivation", "polarity": "include", "value_kind": "free_text",
      "derivation_formula": "ratio = metric_a / metric_b"}},
    {{"name": "entity", "role": "dimension", "polarity": "include", "value_kind": "free_text"}},
    {{"name": "agent_principal", "role": "filter", "polarity": "include", "value_kind": "literal_value",
      "values": ["agent_007", "agent_009", "agent_042", "agent_115"]}},
    {{"name": "exclusion_label", "role": "filter", "polarity": "exclude", "value_kind": "textual_token",
      "values": ["Bonus_"]}}
  ],
  "values_inline_lists": [
    {{"concept": "agent_principal", "items": ["agent_007", "agent_009", "agent_042", "agent_115"]}}
  ]
}}
```

> **Note importante** : ces 2 exemples utilisent des noms 100% neutres (`metric_a`, `entity_alpha`, \
`time_dim_T1`, `category_K1`, etc.) pour ne pas biaiser ton extraction selon un domaine métier précis. \
Applique la MÊME logique structurelle quel que soit le domaine de la vraie requête utilisateur.

## FORMAT JSON DE SORTIE — STRICT

```json
{{
  "intent": "read",
  "termes": ["terme1", "terme2", "..."],
  "concepts": ["expression1", "expression2"],
  "valeurs": ["valeur1", "valeur2"],
  "exclusions": ["exclusion1"],
  "groupes": {{
    "concept1": [],
    "concept2": ["valeur1", "valeur2"]
  }},
  "derivables": {{
    "concept_dérivé": ["concept_source_1", "concept_source_2"]
  }},
  "concepts_v2": [
    {{
      "name": "<concept_name (= une des entrées de `concepts`)>",
      "role": "measure|filter|dimension|temporal|exclusion|derivation",
      "polarity": "include|exclude|prefer|avoid",
      "value_kind": "literal_value|textual_token|numeric_range|identifier_code|free_text",
      "values": [],
      "derivation_formula": null
    }}
  ],
  "values_inline_lists": [
    {{"concept": "<concept_name>", "items": ["v1", "v2", "..."]}}
  ]
}}
```

### Règles de cohérence
- Tout `name` dans `concepts_v2` doit être présent dans `concepts`.
- `values` dans `concepts_v2[i]` = `groupes[name]` (donnée dupliquée pour ergonomie).
- Si `polarity = exclude`, le concept doit aussi figurer dans `exclusions`.
- Si `role = derivation`, `derivables[name]` doit être renseigné ET `derivation_formula` non null.
- `intent = "read"` par défaut (l'application est read-only sur la BDD source).
- `values_inline_lists` ne contient QUE les listes ≥ 3 éléments énumérés explicitement par l'utilisateur.
- Si la demande utilisateur contient des valeurs numériques comme des nombres ou des dates il faut que tu partes du principe que ces valeurs peuvent avoir plusieurs types candidats (peu importe la façon dont l'utilisateur a écrit les valeurs numériques)

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

PHASE1_EXPAND_TERMS = """Pour chaque terme conceptuel de la liste, génère des mots clés liés au terme qui
aurait pu être utilisé dans un nom de table, un nom de vue ou un nom de colonne qui permettrait d'obtenir ce concept dans une BDD SQL Server.

**Requête utilisateur :**
{user_query}

**Termes extraits :**
{listo}

**Catégories :**
{categories}

## CRITÈRE UNIQUE

Pour chaque terme, pose-toi ces deux questions :
1. **"Quels mots-clés liés à ce terme pourraient contenu être dans un nom de table, de vue ou de colonne ?"**
2. **"Si ce concept n'existe pas tel quel dans la BDD, à partir de quelles données brutes
   pourrait-on le calculer ou le construire ?"**

Pense aux synonymes métier, aux traductions, aux abréviations,
mais aussi aux données sources nécessaires pour produire ce concept.

## RÈGLES

- Ne génère des variantes que pour les CONCEPTS (pas pour les valeurs littérales, codes ou nombres)
- Max 20 variantes par concept
- Ne répète pas les termes déjà dans la liste

## FORMAT JSON STRICT

```json
{{
  "expansions": {{
    "terme_concept_1": ["variante1", "variante2", "variante3"],
    "terme_concept_2": ["variante1", "variante2"]
  }}
}}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

PHASE1_EXPAND_TERMS_REPHRASE = """Pour chaque terme conceptuel de la liste, imagine comment quelqu'un
parlerait de ce concept SANS utiliser le terme exact. Génère les mots-clés issus de ces reformulations.

**Requête utilisateur :**
{user_query}

**Termes extraits :**
{listo}

**Catégories :**
{categories}

## CRITÈRE UNIQUE

Pour chaque terme, pose-toi ces deux questions :
1. **"Si quelqu'un ne connaissait pas ce mot, comment décrirait-il ce concept ?"**
2. **"Quelles données brutes faudrait-il combiner pour obtenir ce concept ?"**

## RÈGLES

- Ne génère des variantes que pour les CONCEPTS (pas pour les valeurs littérales, codes ou nombres)
- **Grande diversité obligatoire** : chaque terme doit apporter un angle vraiment différent.
- Ne répète pas les termes déjà dans la liste

## FORMAT JSON STRICT

```json
{{
  "expansions": {{
    "terme_concept_1": ["variante1", "variante2", "variante3"],
    "terme_concept_2": ["variante1", "variante2"]
  }}
}}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

PHASE1_ALIGNMENT_SYSTEM = """Tu es un agent qui vérifie que la demande d'un utilisateur et le contenu
d'une base de données sont compatibles. Le système a cherché les termes de la requête dans la BDD
et te donne les résultats. Tu as des outils pour approfondir.

## CONTEXTE UTILISATEUR

L'utilisateur ne connaît PAS la structure de la BDD. Il ne sait pas quelles tables existent,
comment les données sont stockées, ni dans quel format. Il décrit ce qu'il veut en langage
naturel, parfois avec les mauvais mots. Ton rôle est de faire le pont entre son intention et
la réalité de la BDD.

## TON OBJECTIF — ALIGNEMENT À 100%

Pour CHAQUE concept de la demande, tu dois vérifier :

1. **Trouvé ou constructible ?** — Le concept est soit stocké directement dans une colonne,
   soit constructible à partir d'autres données de la BDD (calcul, agrégation, combinaison).
   Si NI l'UN NI L'AUTRE après exploration → explore avec les outils si tu as une piste, sinon discute du problème avec l'utilisateur.
   IMPORTANT : "pas trouvé" ne veut PAS dire "n'existe pas". L'utilisateur s'est peut-être
   trompé dans sa demande.

2. **Non-ambigu ?** — S'il y a PLUSIEURS candidats pour le même concept,
   c'est une ambiguïté. Pose une question pour clarifier.

3. **Cohérent ?** — Le format des données trouvées correspond-il à ce que l'utilisateur attend ?
   Si la BDD stocke un concept d'une façon que l'utilisateur ne soupçonne probablement pas,
   signale-le dans les notes du candidat (la Phase 2 s'en servira).

Aligne TOUS les concepts avant de confirmer. Un seul concept mal aligné = requête SQL fausse.

## TON WORKFLOW

1. **Analyse les résultats de recherche** — ils couvrent tables, vues, colonnes ET valeurs
2. **Pour chaque concept**, identifie TOUS les candidats plausibles (pas juste le meilleur)
3. **Si un concept n'a pas de résultat évident et que tu as une piste** :
   a. Utilise `search_schema` pour chercher avec des termes différents
   b. Utilise `get_fk_neighbors` pour explorer les tables voisines
   c. Utilise `get_table_info` pour inspecter une table en profondeur
4. **Si un concept est ambigu** (plusieurs interprétations plausibles) → pose une question
5. **Si un concept est introuvable** → demande à l'utilisateur de le
   décrire autrement (il s'est peut-être trompé dans sa demande)
6. **Quand TOUT est aligné** → appelle `confirm_alignment` avec TOUS les candidats par concept

## QUAND POSER UNE QUESTION

Pose une question quand :
- Un concept n'a **aucun résultat** → "Je n'ai rien trouvé sur X dans la base de données, vous êtes sûr que cette information est présente ?"
- Un concept a **plusieurs interprétations très différentes** → "Voici A, voici B, vous voulez A ou B ?"
- L'utilisateur fait une **hypothèse implicite** qui pourrait être fausse → clarifier

Ne pose PAS de question quand :
- Tu as plusieurs candidats mais qui pointent tous vers la même donnée (juste des chemins différents)
- L'ambiguïté peut être résolue par la Phase 2 (choix technique, pas métier)

Les questions portent sur le SENS MÉTIER (ce que l'utilisateur veut), JAMAIS sur la structure
technique de la BDD (tables, colonnes, jointures = ta responsabilité).

## EXPLORATION DES FK — OBLIGATOIRE

Quand tu inspectes une table avec `get_table_info`, vérifie les FK ENTRANTES (tables enfants).
Les données détaillées sont souvent dans des tables enfants, pas dans la table parent.
Ne déclare JAMAIS un concept introuvable sans avoir exploré les voisins FK.

## OUTILS DISPONIBLES

- `get_table_info(table_name)` — DDL complet, FK, stats, valeurs anonymisées
- `get_column_values(table_name, column_name)` — Valeurs anonymisées d'une colonne
- `search_schema(term)` — Cherche un terme dans TOUTE la BDD (tables, vues, colonnes, valeurs)
- `get_fk_neighbors(table_name)` — Liste les tables liées par FK (sortantes ET entrantes)
- `get_discussion_history(n_last)` — Historique des échanges précédents
- `confirm_alignment(elements)` — TERMINAL : confirme l'alignement
- `ask_user_clarification(question, options)` — TERMINAL : pose une question à l'utilisateur

## VALEURS ANONYMISÉES

Les valeurs dans les résultats sont ANONYMISÉES (voyelles retirées, etc.).
C'est NORMAL. Si un résultat de type VALEUR a un match "exact" ou "contains", c'est que la VRAIE valeur
correspond — fais confiance au système de recherche.

## RÔLES POSSIBLES
- "donnee_a_calculer" : ce qu'on veut calculer/afficher (SUM, COUNT, etc.)
- "source" : la table principale d'où viennent les données
- "axe_ventilation" : ce par quoi on regroupe (GROUP BY)
- "filtre_inclusion" : valeurs à inclure (WHERE IN)
- "filtre_exclusion" : valeurs à exclure (WHERE NOT IN / NOT LIKE)
- "temporel" : filtre lié au temps
- "jointure" : table nécessaire pour relier d'autres tables

## RÉSOLUTION DES FILTRES D'EXCLUSION

Quand l'utilisateur dit qu'il ne veut pas quelque chose, utilise `get_resolved_values` pour trouver
TOUTES les valeurs exactes à exclure.

## DONNÉES DIRECTES ET DONNÉES CONSTRUITES

Un concept demandé par l'utilisateur peut être :
- **Direct** — stocké tel quel dans une colonne (ex: un nom, un code, une date)
- **Construit** — obtenu en combinant/calculant à partir d'autres données de la BDD

Ne cherche PAS uniquement une colonne qui porte le nom du concept.
Vérifie aussi si les **données brutes nécessaires** pour le construire existent.
Si le concept est construit, note-le avec `is_calculated: true` et décris la logique.

## COLLECTE LARGE

Quand tu appelles `confirm_alignment`, inclus pour chaque concept TOUS les candidats trouvés,
même les moins probables. C'est la Phase 2 qui triera. Ne choisis PAS le meilleur —
donne-les TOUS avec des notes sur chaque chemin.

## RÈGLES CRITIQUES

- COLLECTER tous les candidats par concept, pas confirmer un seul
- EXPLORER les FK voisines avant de conclure qu'un concept est introuvable
- Les questions portent sur l'INTENTION de l'utilisateur, JAMAIS sur la technique
- Les OPTIONS des questions doivent être ancrées sur des données RÉELLES trouvées
- Si un historique de discussion est fourni, ne redemande PAS ce qui a déjà été clarifié
- Cherche dans les VUES aussi (colonnes calculées qui n'existent pas dans les tables)"""

# Ancien prompt gardé comme alias (backward compat pour les tests)
PHASE1_ALIGNMENT_CHECK = PHASE1_ALIGNMENT_SYSTEM


# ── Phase 1 bis : Reformulation après clarification ────────────────

PHASE1_REFORMULATE_QUERY = """Tu es un reformulateur de requêtes. L'utilisateur a fait une demande
initiale, puis a fourni des précisions dans une discussion.

**Requête originale :**
{original_query}

**Historique des échanges (clarifications) :**
{discussion_summary}

**Dernière précision de l'utilisateur :**
{user_clarification}

## TA TÂCHE

Produis UNE requête reformulée qui fusionne la demande originale avec TOUTES les précisions.
La requête reformulée doit être :
- Autonome (compréhensible sans l'historique)
- Plus claire et plus précise que l'originale
- Fidèle à l'intention de l'utilisateur

Retourne un JSON :
{{"requete_reformulee": "la requête reformulée complète"}}"""


# =============================================================================
# NOUVEAU WORKFLOW — Phase 2 : Construction SQL par élément
# =============================================================================

PHASE2_PLAN_ELEMENTS = """Tu es un architecte SQL. Tu dois planifier la construction d'une requête
SQL étape par étape.

**Requête utilisateur :**
{user_query}

**Éléments identifiés (résultat de l'alignement) :**
{pertinent_results}

**Relations FK connues :**
{fk_summary}

## TA TÂCHE

Crée un plan ORDONNÉ des éléments à traiter. L'ordre est crucial :
1. D'abord la SOURCE (table principale + colonne de base)
2. Ensuite les DONNÉES À CALCULER (SUM, COUNT, etc.)
3. Puis les AXES DE VENTILATION (GROUP BY) — en priorité ceux dans la même table
4. Puis les FILTRES (WHERE) — en priorité ceux dans des tables déjà présentes
5. En dernier les éléments nécessitant des JOINs complexes

Pour chaque élément, indique :
- Ce qu'il faut ajouter au SQL (SELECT, FROM, JOIN, WHERE, GROUP BY)
- La table source identifiée
- Si un JOIN est nécessaire (et vers quelle table)

## FORMAT JSON STRICT

```json
{{
  "plan": [
    {{
      "order": 1,
      "concept": "nom du concept",
      "role": "source|donnee_a_calculer|axe_ventilation|filtre_inclusion|filtre_exclusion|temporel",
      "sql_part": "FROM|SELECT|JOIN|WHERE|GROUP_BY|ORDER_BY",
      "table": "NomTable",
      "column": "nomColonne",
      "needs_join": false,
      "join_target": "",
      "notes": "détails"
    }}
  ]
}}
```

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

PHASE2_RESOLVE_ELEMENT = """Tu es un agent SQL expert. Tu dois résoudre UN élément de la requête
et construire/étendre le SQL correspondant.

## CONTEXTE

**Requête utilisateur :**
{user_query}

**Élément à résoudre :**
{element}

**Résultats pertinents de la recherche dans la BDD :**
{pertinent_results}

**Synthèse cumulative (concepts déjà résolus + tables connues + jointures) :**
{cumulative_synthesis}

**SQL en cours de construction :**
{current_sql}

**Relations FK connues :**
{fk_summary}

## TA TÂCHE — Séquence OBLIGATOIRE

### Étape A — Proposer des approches (OBLIGATOIRE)
Appelle TOUJOURS `propose_approaches` en premier :
- Identifie 2-5 façons différentes de résoudre cet élément
- Pour chaque approche : quelle(s) table(s), colonne(s), méthode (direct, join, subquery, case_when)
- Les approches doivent être RÉELLEMENT différentes (pas des variantes mineures)

### Étape B — Tester les approches
Pour chaque approche proposée :
- Utilise `get_table_info` pour vérifier les tables candidates
- Utilise `explore_alternatives` / `get_fk_path` pour les JOINs
- Utilise `test_sql` si tu peux déjà construire un SQL partiel
- Note les résultats (COUNT, nullabilité, nombre de hops)

### Étape C — Choisir la meilleure (OBLIGATOIRE)
Appelle `evaluate_approaches` pour choisir :
- Préfère les approches qui réutilisent des tables déjà dans le SQL
- Préfère les chemins avec moins de hops
- Préfère les chemins où les FK ont un null_pct bas (JOIN plus propre)
- Si deux approches sont équivalentes, préfère la plus simple

### Étape D — Construire le SQL
- Si c'est le premier élément : crée le SELECT ... FROM ...
- Si c'est un ajout : étends le SQL existant avec le nouveau JOIN/colonne/filtre
- Après chaque modification, appelle `test_sql` pour vérifier le COUNT
- Si le COUNT est anormal (×5+ = cartésien, ÷2 = perte, 0 = cassé), corrige

### Étape E — Finaliser l'élément
- Quand le SQL est correct pour cet élément, appelle `finalize_element`

## RÈGLES CRITIQUES

- **{sql_server_version} syntax** : `[]` pour les noms réservés, `TOP` au lieu de `LIMIT`
- **TOUJOURS `get_fk_path` AVANT d'écrire un JOIN** — ne jamais inventer une condition
- **TOUJOURS `test_sql` APRÈS chaque modification** — vérifier le COUNT
- Si une même table doit être jointe deux fois → alias différent
- Si un filtre porte sur une table LEFT JOINée → considérer CTE ou déplacer le filtre
- Les join_pattern: extraits des vues montrent comment les devs originaux font les jointures
"""
