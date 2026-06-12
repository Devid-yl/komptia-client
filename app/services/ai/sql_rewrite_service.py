"""Feature #7 task #7c (2026-05-26) — Service de réécriture LLM des SQL
stockés quand le serveur SQL Server connecté change de version.

Pipeline d'utilisation :
1. ``schema_sync._detect_and_store_server_version`` détecte un downgrade
   (cf. ``compute_capability_delta``).
2. ``find_active_pairs_affected_by_capabilities`` retourne les paires
   Q/SQL qui utilisent les capabilities cassées.
3. **Pour chaque paire**, ce service est appelé : 1 appel LLM via
   ``LLMManager`` (modèle dynamique de ``/admin/ai-config``, JAMAIS
   hardcoded), produit un nouveau SQL compatible.
4. Dry-run du nouveau SQL sur Sage (réutilise le dry-run de Bug n°4).
5. Retour : ``success / needs_human_review / failed`` avec audit info.

Doctrine
--------
* **Source unique** : modèle = ``LLMManager.default_model_name`` (BDD).
* **Pas de fallback Ollama** : ``FallbackPolicy.NONE`` — la réécriture
  de paires validées est une opération à enjeu (« données fausses
  silencieuses 100× pire qu'une indisponibilité »). Si le primary
  cloud est down, on laisse les paires non réécrites et on remontera
  un warning admin — c'est OK car les paires originales restent
  accessibles (juste cassées sur le nouveau serveur, ce qui est déjà
  protégé par les garde-fous compat-level downstream).
* **Dry-run obligatoire** : on ne persiste JAMAIS un SQL réécrit qui
  n'a pas tourné. Si le LLM produit un SQL syntaxiquement plausible
  mais qui crash, ``needs_human_review=True`` — la paire est marquée
  pour validation admin mais PAS auto-activée.
* **Output isolé** : ce service ne touche PAS la BDD. Le caller
  (task #7d) décide de persister, marquer pending_review, audit log, etc.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import List, Optional

from app.constants_ai import clamped_max_tokens

logger = logging.getLogger(__name__)


# Budget output max pour le SQL réécrit. Le SQL d'origine fait
# typiquement < 8K chars ; le réécrit fait à peu près la même taille
# (souvent un peu plus à cause des alternatives compat-friendly comme
# ``STUFF + FOR XML PATH`` qui sont verbeuses). 8K tokens = ~30K chars,
# bordée généreuse. ``clamped_max_tokens`` ramène au cap réel du modèle
# actif (jamais de littéral hardcoded — cf. feedback_max_tokens_must_be_dynamic).
_REWRITE_MAX_OUTPUT_TOKENS_SOFT = 8000

# Timeout par appel LLM. La réécriture est une op asynchrone batch
# (la sync schéma attend la fin), pas user-facing → budget large
# acceptable. Évite les rewrites bâclées sur réseau lent.
_DEFAULT_REWRITE_TIMEOUT_SECONDS = 60.0


@dataclass
class RewriteResult:
    """Résultat d'une réécriture SQL par le LLM.

    Trois états mutuellement exclusifs :
    * ``success=True`` : le LLM a produit un SQL qui passe le dry-run
      sur Sage. ``new_sql`` est le SQL à persister.
    * ``needs_human_review=True`` : le LLM a produit un SQL mais le
      dry-run échoue (ou rien d'utilisable). Le caller doit marquer
      ``pending_review=True`` et garder l'ancien SQL en backup.
    * ``success=False`` ET ``needs_human_review=False`` : échec dur
      (LLM down, timeout, output vide). Aucune action sur la paire —
      elle reste avec son SQL original (qui cassera sur le nouveau
      serveur, mais la garde compat-level downstream le bloquera).
    """

    success: bool
    new_sql: Optional[str]
    error: Optional[str]
    dry_run_passed: bool
    model_used: Optional[str]
    duration_seconds: float
    needs_human_review: bool


def _strip_markdown_sql_block(content: str) -> str:
    """Strip ```sql ... ``` markdown wrapper si présent.

    Le LLM peut retourner ``"```sql\\nSELECT ...\\n```"`` ou ``"SELECT ..."``
    selon l'humeur. On normalise au SQL pur.
    """
    if not content:
        return ""
    # Strip ```sql ... ``` ou ``` ... ```
    m = re.search(r"```(?:sql)?\s*\n?(.*?)\n?```", content, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return content.strip()


def _build_rewrite_prompt(
    old_sql: str,
    old_label: str,
    new_label: str,
    broken_capabilities: List[str],
) -> tuple[str, str]:
    """Construit (system, user) prompt pour le LLM rewrite.

    Système : rôle expert SQL Server, contrat de réécriture clair.
    User : SQL ancien + contexte versions + capabilities cassées.
    Format de sortie strict : SQL pur (pas markdown, pas explications).
    """
    capabilities_str = ", ".join(f"``{c}``" for c in broken_capabilities)

    system = (
        "Tu es un expert SQL Server. Ta mission est de réécrire un SQL "
        "qui fonctionnait sur une ancienne version du serveur pour qu'il "
        "fonctionne sur la nouvelle version, qui ne supporte plus certaines "
        "fonctions/syntaxes.\n\n"
        "RÈGLES STRICTES :\n"
        "1. Préserve EXACTEMENT la sémantique métier du SQL d'origine "
        "(même tables, mêmes filtres, même résultat attendu).\n"
        "2. Remplace UNIQUEMENT les capabilities cassées par des "
        "équivalents compat-friendly (ex: STRING_AGG WITHIN GROUP → "
        "STUFF + FOR XML PATH, TRIM → LTRIM(RTRIM(...))).\n"
        "3. Ne change PAS les noms de tables/colonnes/alias, sauf si "
        "strictement nécessaire au remplacement de la capability.\n"
        "4. N'ajoute PAS de commentaires explicatifs dans le SQL.\n"
        "5. Output : SQL PUR exclusivement (pas de ```sql, pas de prose, "
        "pas d'explication). Le caller parsera directement ta réponse "
        "comme du SQL à exécuter.\n"
        "6. Si la réécriture est impossible (capability sans équivalent "
        "compat-friendly réaliste), réponds avec UN SEUL mot : "
        "``IMPOSSIBLE``."
    )

    user = (
        f"L'ancien serveur était : {old_label}\n"
        f"Le nouveau serveur est : {new_label}\n"
        f"Capabilities qui ne fonctionnent plus : {capabilities_str}\n\n"
        f"SQL à réécrire :\n```sql\n{old_sql}\n```\n\n"
        f"Réécris ce SQL pour qu'il tourne sur {new_label}. "
        f"Output : SQL pur uniquement."
    )

    return system, user


async def rewrite_sql_for_new_server(
    old_sql: str,
    old_label: str,
    new_label: str,
    broken_capabilities: List[str],
    *,
    timeout: float = _DEFAULT_REWRITE_TIMEOUT_SECONDS,
    user_id: Optional[int] = None,
) -> RewriteResult:
    """Demande au LLM de réécrire un SQL pour qu'il tourne sur la nouvelle
    version du serveur SQL Server, puis dry-run le résultat sur Sage.

    Args:
        old_sql: SQL d'origine (qui marchait sur ``old_label``).
        old_label: Ex: "SQL Server 2019".
        new_label: Ex: "SQL Server 2014".
        broken_capabilities: Ex: ["STRING_AGG", "STRING_AGG_WITHIN_GROUP"].
        timeout: Timeout par appel LLM (secondes). Défaut 60s.

    Returns:
        ``RewriteResult`` détaillé (cf. docstring de la dataclass).

    Doctrine :
        * Modèle = ``LLMManager.default_model_name`` (BDD, dynamique).
          AUCUN hardcode de model name dans cette fonction.
        * ``max_tokens`` = ``clamped_max_tokens(soft_limit, model)`` pour
          respecter le cap réel du modèle actif.
        * ``FallbackPolicy.NONE`` : pas de retombée sur LLM local
          (données sacrées, cf. P1 #14).
    """
    if not old_sql or not old_sql.strip():
        return RewriteResult(
            success=False,
            new_sql=None,
            error="empty_old_sql",
            dry_run_passed=False,
            model_used=None,
            duration_seconds=0.0,
            needs_human_review=False,
        )
    if not broken_capabilities:
        # No-op : si rien n'est cassé, pas besoin de réécrire.
        return RewriteResult(
            success=True,
            new_sql=old_sql,
            error=None,
            dry_run_passed=True,
            model_used=None,
            duration_seconds=0.0,
            needs_human_review=False,
        )

    # Imports tardifs : évite le cycle d'import au boot du module.
    # ``fallback_policy`` est un string sur l'API ``LLMManager.generate``
    # (cf. llm_providers.py:4377) — "none" désactive le fallback Ollama.
    from app.services.ai.llm_providers import (
        LLMRequest,
        get_llm_manager,
    )

    manager = get_llm_manager()
    model_name = manager.default_model_name
    if not model_name:
        return RewriteResult(
            success=False,
            new_sql=None,
            error="no_default_model_configured",
            dry_run_passed=False,
            model_used=None,
            duration_seconds=0.0,
            needs_human_review=False,
        )

    system, user_prompt = _build_rewrite_prompt(old_sql, old_label, new_label, broken_capabilities)
    max_tokens = clamped_max_tokens(_REWRITE_MAX_OUTPUT_TOKENS_SOFT, model_name)

    start_ts = time.perf_counter()
    try:
        response = await manager.generate(
            LLMRequest(
                prompt=user_prompt,
                system=system,
                model=model_name,
                # Temperature volontairement omise : laisse l'admin
                # config /admin/ai-config trancher (cf. doctrine
                # feedback_no_double_cap — pas de double cap).
                max_tokens=max_tokens,
                # Couche 2 — pseudonymise les termes /data-privacy de
                # l'ancien SQL (peut contenir des littéraux WHERE) avant envoi.
                user_id=user_id,
            ),
            fallback_policy="none",
        )
    except Exception as exc:  # noqa: BLE001 — toute erreur LLM = échec safe
        duration = time.perf_counter() - start_ts
        logger.warning(
            "Feature #7 rewrite — appel LLM échoué (%s) : %s",
            type(exc).__name__,
            exc,
        )
        return RewriteResult(
            success=False,
            new_sql=None,
            error=f"llm_call_failed: {type(exc).__name__}: {exc}",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=False,
        )

    duration = time.perf_counter() - start_ts
    raw_content = (response.content or "").strip()

    # Cas spécial : le LLM a explicitement dit qu'il ne pouvait pas
    # réécrire. On respecte sa décision et on flag pour review humaine.
    if raw_content.upper() == "IMPOSSIBLE":
        logger.info(
            "Feature #7 rewrite — LLM a déclaré IMPOSSIBLE pour les "
            "capabilities %s. Paire à reviewer manuellement.",
            broken_capabilities,
        )
        return RewriteResult(
            success=False,
            new_sql=None,
            error="llm_declared_impossible",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=True,
        )

    new_sql = _strip_markdown_sql_block(raw_content)
    if not new_sql:
        return RewriteResult(
            success=False,
            new_sql=None,
            error="llm_returned_empty",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=False,
        )

    # Garde anti-empoisonnement : un rewrite ne doit JAMAIS introduire une
    # opération dangereuse (write/DDL) dans le RAG. check_sql_dangerous est la
    # SSoT partagée avec add_question_sql. Si dangereux → review humaine, on ne
    # persiste pas (success=False). Import tardif (cohérent avec les autres).
    from app.services.ai.sql_validator import check_sql_dangerous

    found_dangerous = check_sql_dangerous(new_sql)
    if found_dangerous:
        logger.warning(
            "Feature #7 rewrite — SQL réécrit contient des opérations "
            "interdites (%s). Marqué needs_human_review.",
            ", ".join(found_dangerous),
        )
        return RewriteResult(
            success=False,
            new_sql=new_sql,
            error=f"dangerous_sql: {', '.join(found_dangerous)}",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=True,
        )

    # Dry-run sur Sage pour valider que le LLM a produit quelque chose
    # qui tourne réellement. Réutilise le même pattern que Bug n°4
    # (validation à l'insertion) : execute avec max_rows=1, add_limit=True.
    # Si crash → needs_human_review (LLM a produit du SQL plausible mais
    # sémantiquement / syntaxiquement faux).
    #
    # Pas de ``timeout=`` explicite : le coût est déjà borné par ``max_rows=1``
    # (TOP 1, aucun gros résultat ramené). On hérite donc du timeout admin
    # (``connector.timeout``). Un hardcode court (ex: 15s) rejetait à tort un
    # SQL valide sur une Sage lente où l'admin a délibérément configuré plus —
    # même bug de double-cap que l'incident dashboard 2026-06-08.
    from app.core.exceptions import QueryError, ValidationError
    from app.services.database.query_executor import get_query_executor

    try:
        executor = get_query_executor()
        await executor.execute(
            new_sql,
            max_rows=1,
            add_limit=True,
            rls_source="feature_7_rewrite_dryrun",
        )
        # Dry-run OK : on retourne le nouveau SQL prêt à persister.
        logger.info(
            "Feature #7 rewrite — paire réécrite avec succès " "(model=%s, %.1fs, capabilities=%s)",
            model_name,
            duration,
            broken_capabilities,
        )
        return RewriteResult(
            success=True,
            new_sql=new_sql,
            error=None,
            dry_run_passed=True,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=False,
        )
    except (QueryError, ValidationError) as exc:
        logger.warning(
            "Feature #7 rewrite — dry-run du SQL réécrit échoué (%s) : "
            "%s. Marqué needs_human_review.",
            type(exc).__name__,
            str(exc)[:200],
        )
        return RewriteResult(
            success=False,
            new_sql=new_sql,  # garder le SQL pour review admin
            error=f"dry_run_failed: {type(exc).__name__}: {str(exc)[:200]}",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=True,
        )
    except Exception as exc:  # noqa: BLE001 — defense in depth
        logger.warning(
            "Feature #7 rewrite — dry-run a levé une exception inattendue "
            "(%s) : %s. Marqué needs_human_review.",
            type(exc).__name__,
            str(exc)[:200],
        )
        return RewriteResult(
            success=False,
            new_sql=new_sql,
            error=f"dry_run_exception: {type(exc).__name__}: {str(exc)[:200]}",
            dry_run_passed=False,
            model_used=model_name,
            duration_seconds=duration,
            needs_human_review=True,
        )
