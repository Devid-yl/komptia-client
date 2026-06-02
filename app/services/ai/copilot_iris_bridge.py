"""Bridge copilot_agent ↔ Iris — expose un appel direct `ask_iris()` qui valide
et exécute un SQL proposé par le copilot_agent, sans passer par le handler
WebSocket ni par l'orchestrator streaming complet.

Architecture : le copilot_agent (manipulateur de classeur) n'a pas les
capacités SQL d'Iris (validation schéma, exécution Sage, introspection
INFORMATION_SCHEMA). Plutôt que de dupliquer cette infra, on compose
directement les 3 fonctions clés d'Iris pour construire un tool
`ask_iris(task, draft_sql, execute=True)`.

Workflow :
1. Le LLM du copilot propose un ``draft_sql`` (il voit les SQL existants via
   ``list_tabs`` et peut en dériver des variantes).
2. ``ask_iris`` valide le SQL contre le schéma BDD réel
   (``_validate_sql_columns`` → INFORMATION_SCHEMA).
3. Si ``execute=True``, exécute via ``QueryExecutor`` (même exécuteur que
   le reste de Komptia, max_rows + timeout standards).
4. Retourne un dict structuré : ``{sql, columns, rows, row_count, errors,
   warnings}``. Le copilot_agent décide ensuite l'usage (créer un onglet,
   stocker dans ``cellDetails.sql``, faire un calcul ponctuel).

Design choices :
- ``draft_sql`` est **requis** : force le LLM à proposer, Iris relit.
  Évite l'aller-retour "devine ce que je veux" qui explose le contexte.
- Pas de génération SQL from scratch ici : si le LLM veut construire un SQL
  from task, il compose lui-même depuis les ``list_tabs`` existants et
  passe le draft. Le bridge = relecteur + exécuteur, pas générateur.
- Pas de streaming : on retourne un résultat unique (cohérent avec le
  tool-loop du copilot qui veut des résultats synchrones par tool_use).
- Anonymisation : les tokens ``§…§`` dans ``draft_sql`` sont désanonymisés
  AVANT validation (schéma BDD en clair), et les ``rows`` retournées sont
  re-anonymisées pour que le LLM ne voie que des tokens (cohérent avec le
  reste du copilot_agent).

Fail-safe :
- Schema non synchronisé → error claire, pas de cold-start sync 600s.
- Timeout exécution (30s) → error, pas d'exception propagée.
- SQL invalide → dict error avec suggestions (INFORMATION_SCHEMA).
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Nombre de lignes exécutées en mode dry-run (execute=False). Suffisant pour
# détecter les erreurs runtime que la validation statique rate (division par
# zéro dans CASE, CAST invalide, JOIN sur colonne nullable) sans tirer un
# volume de données qui solliciterait Sage inutilement. Les rows lues en
# dry-run sont JETÉES — seul une exception levée par l'executor remonte.
_DRY_RUN_ROW_LIMIT = 5

# Toute string Sage plus longue que ce seuil est traitée comme non-anonymisable
# et envoyée tronquée au LLM. Borne la taille des alternations regex du
# pseudonymizer (évite la pathologie O(N²) + OOM sur une valeur Sage binaire
# castée en str). 500 char reste largement au-dessus de n'importe quel nom
# d'entité plausible.
_MAX_ANONYMIZABLE_LEN = 500

# Matche une valeur qui EST elle-même déjà un token `§…§` complet. Ces
# valeurs ne doivent PAS entrer dans la table du pseudonymizer (elles
# créeraient des tokens pour un token, ou rentreraient en collision avec un
# token existant — confusion d'identité côté sortie).
_TOKEN_SHAPE_RE = re.compile(r"^§[^§]+§$")


def _cache_key(task: str, sql_cleartext: str, max_rows: int) -> str:
    """Hash stable de ``(task, sql_cleartext, max_rows)`` pour clé de cache.

    On normalise les espaces du SQL pour que "SELECT  *" et "SELECT * " hit
    le même cache (sinon chaque variation d'espace ferait un miss). On fait
    pareil pour ``task`` (le LLM peut être appelé avec des variations
    cosmétiques de la même consigne).

    Case-sensitive volontairement : le LLM peut varier les alias mais pas le
    SQL de fond, et une variation de casse peut cacher une différence
    sémantique (ex: nom de colonne SQL Server sensible selon collation).

    ``task`` participe à la clé car la transformation LLM dépend de la
    consigne — deux ``task`` différents pour le même ``draft_sql`` doivent
    produire des résultats indépendants en cache.
    """
    normalized_sql = " ".join(sql_cleartext.split())
    normalized_task = " ".join((task or "").split())
    h = hashlib.sha256(
        f"{normalized_task}||{normalized_sql}||{max_rows}".encode("utf-8")
    ).hexdigest()
    return h[:16]


async def ask_iris(
    task: str,
    draft_sql: str,
    execute: bool = True,
    max_rows: int = 1000,
    pseudonymizer: Any = None,
    cache: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    user_id: Optional[int] = None,
    user: Any = None,
) -> Dict[str, Any]:
    """Transforme via LLM (si ``task`` non-vide), valide et exécute un SQL.

    Pipeline :

    0. **Transformation LLM one-shot** — si ``task`` est non-vide, délègue à
       ``iris_oneshot.transform_sql_via_llm`` pour appliquer la consigne
       sur ``draft_sql`` (ex: "fais la même chose mais groupé par mois",
       "ajoute toutes les colonnes en projection"). Le SQL transformé devient
       le nouveau ``draft_sql`` qui passe par le reste du pipeline.

       Cette étape rend ``ask_iris`` cohérente avec son contrat tel que
       décrit dans le system prompt du copilot : *"Iris (agent SQL connecté
       à la BDD) adapte le SQL au schéma réel"*. Sans cette étape, le
       copilot était obligé de désobéir à la consigne *"Ne fabrique jamais
       le SQL final toi-même"* pour produire le résultat attendu.

       Si ``task`` est vide ou whitespace-only, l'étape 0 est skippée
       (back-compat : on valide+exécute le ``draft_sql`` tel quel).

    1. Désanonymisation (si pseudonymizer fourni).
    2. Check fraîcheur du schéma BDD.
    3. Validation contre INFORMATION_SCHEMA.
    4. Dry-run ou exécution complète.
    5. Ré-anonymisation des rows retournées.

    Args:
        task: Consigne en langage naturel décrivant la transformation à
            appliquer sur ``draft_sql``. Si non-vide, déclenche un appel
            LLM one-shot. Si vide, ``draft_sql`` est validé/exécuté tel quel.
        draft_sql: SQL proposé. PEUT contenir des tokens ``§…§`` si
            ``pseudonymizer`` est fourni (seront résolus avant validation
            et exécution). Si transformation LLM activée, le LLM voit le
            SQL dans la même forme (tokenisé ou en clair).
        execute: Si True, exécute le SQL sur Sage après validation. Si False,
            retourne uniquement le résultat de validation (sql final, erreurs).
            Utile pour sonder le schéma sans taper la BDD.
        max_rows: Plafond de lignes retournées (protection runaway query).
        pseudonymizer: Instance ``Pseudonymizer`` du run copilot actif. Si
            fournie, désanonymise ``draft_sql`` avant exécution et ré-anonymise
            les ``rows`` retournées. ``None`` = passage direct en clair.
            **Rôle** : protection caller-side du SQL en input/output (avant
            validation/exécution Sage et avant ré-affichage côté LLM).
        cache: Dict partagé entre appels ``ask_iris`` du même run copilot.
            Si fourni, un SQL déjà exécuté dans ce run est servi depuis le
            cache (zéro round-trip Sage, zéro re-tokenisation). Scope =
            1 run copilot (pas persistent inter-sessions).
        user_id: Identifiant utilisateur — **distinct de ``pseudonymizer``**.
            Threadé jusqu'à ``transform_sql_via_llm`` pour que le proxy
            d'anonymisation charge le pseudonymizer user-scoped + applique
            la couche PII regex sur le payload envoyé au LLM cloud (tâche
            #20 du loop d'anonymisation). ``None`` = appel système (PII
            regex appliquée, pas de pseudonymizer user). **Les deux peuvent
            être fournis simultanément** : ``pseudonymizer`` protège le
            SQL côté caller (validation/exécution + rendu), ``user_id``
            alimente le proxy LLM (transformation IA). Si le copilot a
            un pseudonymizer actif, fournir AUSSI ``user_id`` pour
            cohérence proxy↔caller.
        user: Objet ORM ``User`` complet — **distinct de ``user_id``**.
            Propage le contexte d'enforcement à ``query_executor.execute``
            pour activer le Row-Level-Security du module ``data_access``
            (filtrage par tables/colonnes/lignes autorisées selon les
            permissions du rôle). Sans ce paramètre, ``enforcer`` logue
            un WARNING ``RLS skip`` et la requête traverse sans filtrage
            (fail-OPEN historique pour callers legacy). À fournir
            systématiquement quand le caller a accès à l'objet user :
            ne pas se contenter de ``user_id``, car le RLS doit
            inspecter ``user.role`` / ``user.scopes`` (charge ORM).
            ``None`` = caller système / pas de user (RLS skip explicite).

    Returns:
        ``{
            "sql": str,                        # SQL final (après validation/normalisation)
            "validated": bool,                 # True si schéma OK
            "executed": bool,                  # True si requête tapée sur Sage
            "columns": list[str] | None,       # colonnes du résultat (si executed)
            "rows": list[list] | None,         # lignes (ré-anonymisées si pseudo)
            "row_count": int | None,
            "execution_time_ms": float | None,
            "errors": list[str],               # non-fatal = warnings, fatal = validation/exec échoue
            "schema_suggestions": dict | None, # si validation KO : colonnes proches trouvées
        }``
    """
    # **Phase 2.5.ter fix BLOCKING #2 review** — champ ``success`` aligné
    # sur le contrat documenté dans le prompt copilot ``DATA_ACCESS_GUIDANCE``
    # (cf. agent_roles.py). Le prompt promet `{"success": false, "blocked_by":
    # "data_access_rule", "error": ...}` — sans ce champ, le matching côté
    # LLM échoue silencieusement. ``success=True`` par défaut, basculé à
    # ``False`` sur tout early-return d'erreur.
    result: Dict[str, Any] = {
        "success": True,
        "sql": draft_sql,
        "validated": False,
        "executed": False,
        "cached": False,
        "columns": None,
        "rows": None,
        "row_count": None,
        "execution_time_ms": None,
        "errors": [],
        "schema_suggestions": None,
    }

    if not isinstance(draft_sql, str) or not draft_sql.strip():
        result["success"] = False
        result["errors"].append("draft_sql requis et non-vide")
        return result

    # 0. Transformation LLM one-shot (auto si ``task`` non-vide). Le LLM
    #    voit le SQL dans la forme reçue (tokenisé si pseudonymizer actif,
    #    sinon en clair) et retourne un SQL dans la même forme. La
    #    désanonymisation pour validation/exécution est faite à l'étape 1
    #    ci-dessous, sur le SQL transformé.
    #
    #    Back-compat : ``task`` vide ⇒ pipeline historique inchangé (skip).
    #    Le copilot_agent passe systématiquement une ``task`` non-vide — il
    #    bénéficie donc maintenant de la transformation LLM, ce qui le rend
    #    cohérent avec son system prompt qui promet *"Iris adapte le SQL"*.
    if isinstance(task, str) and task.strip():
        from app.services.ai.iris_oneshot import transform_sql_via_llm as _transform
        from app.services.data_access.error_messages import (
            DataAccessLeakDetectedError,
        )

        try:
            new_sql, llm_errors = await _transform(task, draft_sql, user_id=user_id)
        except DataAccessLeakDetectedError as leak_exc:
            # Phase 2.5.bis.bis fix BLOCKING #1 review — propage le
            # marker structuré ``blocked_by="data_access_rule"`` pour
            # que le copilot LLM déclenche ``DATA_ACCESS_GUIDANCE``
            # (pas de retry, suggestion contact admin). Sans ce marker,
            # le LLM voit juste status:error opaque et peut générer un
            # ``emit_tab(sql=...)`` avec un nom denied → leak via
            # ``.afz.json``.
            logger.info(
                "ask_iris: refus data_access sur SQL halluciné LLM — "
                "marker blocked_by propagé au consumer (mode invisible)"
            )
            result["success"] = False
            result["errors"].append(leak_exc.user_message)
            result["blocked_by"] = "data_access_rule"
            return result

        if llm_errors:
            result["errors"].extend(llm_errors)
            return result
        if not isinstance(new_sql, str) or not new_sql.strip():
            result["errors"].append("La transformation LLM a échoué (réponse vide).")
            return result
        draft_sql = new_sql
        result["sql"] = draft_sql

    # 1. Désanonymisation du draft_sql si le copilot est en mode pseudonymisé.
    #    Le schéma BDD (INFORMATION_SCHEMA, colonnes réelles) est en clair,
    #    donc les tokens `§…§` doivent être résolus avant d'arriver aux
    #    requêtes de validation / exécution.
    sql_cleartext = draft_sql
    if pseudonymizer is not None:
        try:
            sql_cleartext = pseudonymizer.deanonymize_text(draft_sql)
        except Exception:
            # Pas de ``str(exc)`` user-facing : peut leaker la table interne
            # du pseudonymizer.
            logger.warning("ask_iris: échec déanonymisation draft_sql", exc_info=True)
            result["errors"].append("Échec de la désanonymisation du SQL (voir logs serveur).")
            return result

    # 2. Check de fraîcheur du schéma — on refuse si training_store vide,
    #    plutôt que de déclencher un cold-start sync (600s) qui bloquerait le
    #    tool-loop du copilot. Si le check LUI-MÊME lève (training_store KO),
    #    on remonte l'erreur réelle au lieu de la masquer : une cause
    #    d'infra cassée ne doit pas se transformer en "validation SQL faux
    #    positif" plus bas dans le pipeline.
    from app.services.ai.training_store import get_training_store

    store = get_training_store()
    has_ddl = await store.has_any_ddl()
    if not has_ddl:
        result["errors"].append(
            "Schéma BDD pas encore synchronisé — impossible de valider le SQL. "
            "Lance /admin/ai-config puis re-essaie."
        )
        return result

    # 3. Validation contre INFORMATION_SCHEMA (tables/colonnes réelles).
    # **Phase 2.5.ter fix BLOCKING #3 review** : on passe ``user=user``
    # pour que ``_validate_sql_columns`` applique le filtre RLS sur les
    # introspections INFORMATION_SCHEMA. Sans ce param, le validate path
    # bypass le mode invisible (un user denied sur F_SALAIRES voit ses
    # colonnes lors du validate, le `validated=True` reste exposé au LLM
    # alors que l'exec ultérieure va échouer).
    try:
        from app.services.ai.agent_tools import _validate_sql_columns

        validation_err = await _validate_sql_columns(sql_cleartext, user=user)
    except Exception:
        logger.exception("ask_iris: _validate_sql_columns a levé")
        result["success"] = False
        result["errors"].append("Erreur interne lors de la validation du SQL (voir logs serveur).")
        return result

    if validation_err is not None:
        err_msg = validation_err.get("error") or "Validation schéma échouée"
        result["success"] = False
        result["errors"].append(err_msg)
        suggestions = validation_err.get("suggestions")
        if suggestions:
            result["schema_suggestions"] = suggestions
        return result

    result["validated"] = True
    result["sql"] = sql_cleartext

    from app.services.database.query_executor import get_query_executor
    from app.services.data_access.enforcer import DataAccessDeniedError

    executor = get_query_executor()

    # 4a. Dry-run (execute=False) : exécute TOP 5 pour attraper les erreurs
    #     runtime que la validation statique rate (divisions zéro dans CASE,
    #     CAST invalides, contraintes NULL). Les rows lues sont JETÉES — on
    #     retourne seulement validated=True + erreurs éventuelles.
    #
    # Contrat de QueryExecutor.execute() : succès → return QueryResult ;
    # erreur → raise (ValidationError, QueryError, asyncio.TimeoutError,
    # **DataAccessDeniedError** pour les refus RLS).
    if not execute:
        try:
            await executor.execute(
                sql_cleartext,
                max_rows=_DRY_RUN_ROW_LIMIT,
                add_limit=True,
                timeout=30,
                user=user,
                rls_source="copilot_iris_bridge.ask_iris.dry_run",
            )
        except DataAccessDeniedError as exc:
            # Phase 2.5.ter fix BLOCKING #3 review — symétrie avec le
            # path execute. Sans ce catch, le dry-run RLS denied
            # remontait comme "Dry-run Sage en échec" opaque (perte
            # du marker, leak potentiel via /api/expand-columns).
            logger.info(
                "ask_iris (dry_run): refus data_access — reason=%s",
                exc.reason or "(n/a)",
            )
            result["success"] = False
            result["errors"].append(exc.user_message)
            result["blocked_by"] = "data_access_rule"
            return result
        except Exception:
            # Pas de ``str(exc)`` user-facing : peut leaker un fragment de
            # SQL ou un détail d'execution plan.
            logger.warning("ask_iris: dry-run a échoué", exc_info=True)
            result["success"] = False
            result["errors"].append("Dry-run Sage en échec (voir logs serveur).")
        return result

    # 4b. Cache hit ? On réutilise un résultat déjà exécuté dans ce run.
    #     Le cache est indexé par (sql_cleartext, max_rows) — si le LLM
    #     appelle 2× avec exactement le même SQL, aucun round-trip Sage.
    ckey = _cache_key(task or "", sql_cleartext, max_rows) if cache is not None else None
    if cache is not None and ckey in cache:
        cached_entry = cache[ckey]
        # Clone pour isoler les mutations (le LLM pourrait modifier result
        # côté appelant, on ne veut pas corrompre le cache).
        result.update(
            {
                "executed": True,
                "cached": True,
                "columns": list(cached_entry["columns"]),
                "rows": [list(r) for r in cached_entry["rows"]],
                "row_count": cached_entry["row_count"],
                "execution_time_ms": cached_entry["execution_time_ms"],
            }
        )
        return result

    # 4c. Exécution complète.
    # Contrat : succès → return QueryResult ; erreur → raise. Pas de
    # .success/.error à tester en post-call.
    #
    # **Phase 2.5.ter (#96) — Fix BLOCKING review** : on intercepte
    # explicitement ``DataAccessDeniedError`` AVANT le catch générique.
    # Sinon, le LLM copilot reçoit le refus RLS sous forme d'erreur
    # opaque ``"Exécution Sage en échec"`` et peut :
    # (a) re-tenter avec une variation du SQL → gaspillage tokens + bypass
    #     tentative bloquée silencieusement par l'enforcer
    # (b) générer un ``emit_tab(sql=...)`` qui contient le nom de la table
    #     denied → leak du nom métier dans le ``.afz.json`` du classeur
    # (c) inventer une raison ("la table n'existe pas") → leak indirect
    #
    # Avec le marker structuré ``blocked_by: data_access_rule``, le bloc
    # ``DATA_ACCESS_GUIDANCE`` du prompt copilot (cf. Phase 2.5 / #76)
    # déclenche le bon comportement : pas de retry, message générique
    # « contactez votre administrateur », pas de mention du nom bloqué.
    # ``DataAccessDeniedError`` est déjà importé plus haut (path dry-run).
    try:
        query_result = await executor.execute(
            sql_cleartext,
            max_rows=max_rows,
            add_limit=True,
            timeout=30,
            user=user,
            rls_source="copilot_iris_bridge.ask_iris",
        )
    except DataAccessDeniedError as exc:
        # Le ``user_message`` est déjà générique mode-invisible
        # (ne mentionne pas le nom de table — cf. Phase 3.1).
        logger.info(
            "ask_iris: refus data_access (mode invisible) — reason=%s",
            exc.reason or "(n/a)",
        )
        result["success"] = False
        result["errors"].append(exc.user_message)
        result["blocked_by"] = "data_access_rule"
        return result
    except Exception:
        # Pas de ``str(exc)`` user-facing : peut leaker fragment SQL.
        logger.warning("ask_iris: exécution SQL a échoué", exc_info=True)
        result["success"] = False
        result["errors"].append("Exécution Sage en échec (voir logs serveur).")
        return result

    # 5. Pack du résultat + ré-anonymisation si besoin.
    columns: List[str] = list(query_result.columns or [])
    rows_raw: List[List[Any]] = [list(row) for row in (query_result.rows or [])]

    if pseudonymizer is not None:
        # Ré-anonymise chaque valeur string. Les valeurs RETOURNÉES PAR SAGE
        # peuvent être absentes de la table bâtie depuis tabs_context (la BDD
        # sait des noms de clients que le classeur n'affiche pas encore). Si
        # on se contentait d'`anonymize_text`, les nouvelles valeurs
        # partiraient cleartext vers le LLM — fuite.
        #
        # Stratégie 2-pass pour borner le coût regex rebuild :
        #   1. Passe 1 : collecter les nouvelles valeurs uniques et les
        #      `add_value` en lot (chaque add_value invalide les patterns
        #      compilés ; regrouper évite N rebuilds sur une même session).
        #   2. Passe 2 : un seul `anonymize_text` par cellule string (rebuild
        #      des patterns une seule fois, à la première invocation).
        #
        # Filtres en entrée :
        #   - `len(v) > _MAX_ANONYMIZABLE_LEN` → tronqué, non tokenisé (borne
        #     la taille des alternations regex).
        #   - `v` matche `§…§` seul → SKIP (c'est un token, pas un cleartext ;
        #     le ré-ajouter créerait une collision / double-encoding).
        #
        # Fail-CLOSED : si la ré-anonymisation lève, on NE retourne PAS les
        # rows cleartext au LLM. L'erreur remonte comme fatale.
        try:
            # Passe 1 : déduplique les candidats, add_value en lot.
            seen: set = set()
            for row in rows_raw:
                for v in row:
                    if not isinstance(v, str):
                        continue
                    if len(v) > _MAX_ANONYMIZABLE_LEN:
                        continue
                    if _TOKEN_SHAPE_RE.match(v):
                        continue
                    if v in seen:
                        continue
                    seen.add(v)
                    pseudonymizer.add_value(v)

            # Passe 2 : transcrit chaque row.
            rows_anon = []
            for row in rows_raw:
                new_row = []
                for v in row:
                    if isinstance(v, str):
                        if len(v) > _MAX_ANONYMIZABLE_LEN:
                            # Tronqué : on perd la tokenisation pour cette
                            # valeur, mais on évite l'explosion regex. La
                            # sentinelle préfixe signale au LLM que la vraie
                            # valeur était trop longue.
                            new_row.append(f"[TOO_LONG:{len(v)}c]")
                        elif _TOKEN_SHAPE_RE.match(v):
                            # Token-shape : on laisse tel quel (le LLM verra
                            # un token inconnu de sa table, ce qui est OK —
                            # les deanonymize_text ultérieurs le laisseront
                            # intact, pas de corruption).
                            new_row.append(v)
                        else:
                            new_row.append(pseudonymizer.anonymize_text(v))
                    else:
                        new_row.append(v)
                rows_anon.append(new_row)
            rows_raw = rows_anon
        except Exception as exc:
            logger.exception("ask_iris: ré-anonymisation rows a échoué")
            result["errors"].append(
                f"Re-anonymisation rows a échoué — rows non retournées pour "
                f"préserver la confidentialité : {exc}"
            )
            # Fail-closed : pas de rows, pas d'exécution reconnue comme réussie.
            return result

    result["executed"] = True
    result["columns"] = columns
    result["rows"] = rows_raw
    result["row_count"] = query_result.row_count
    result["execution_time_ms"] = query_result.execution_time_ms

    # Stocke dans le cache pour les futurs appels du même run. On cache les
    # rows DÉJÀ ré-anonymisées — si le LLM hit le cache, il reçoit directement
    # des tokens `§…§` sans re-tokenisation, cohérent avec l'appel initial.
    if cache is not None and ckey is not None:
        cache[ckey] = {
            "columns": columns,
            "rows": rows_raw,
            "row_count": query_result.row_count,
            "execution_time_ms": query_result.execution_time_ms,
        }

    logger.info(
        "ask_iris: task=%r rows=%d cols=%d time_ms=%.0f",
        (task or "")[:80] if isinstance(task, str) else "",
        len(rows_raw),
        len(columns),
        query_result.execution_time_ms or 0,
    )
    return result
