"""Tools DAG-aware exclusivement disponibles pour le step ``iris`` en automation.

Task #10 P4.1 + Task #11 P4.2 — Tools que l'agent Iris utilise UNIQUEMENT
quand il tourne dans un step d'automatisation backend (``source="automation"``).
Bloqués en mode page/widget par la whitelist
``AUTOMATION_TOOL_CLASSIFICATION`` (cf. ``agent_tools.py``).

6 tools :

**DAG state (#10)** :
- ``set_run_variable(name, value)`` — écrit une variable dans le state du
  run DAG, interpolable par les steps aval via ``{{<step_name>.<name>}}``
  (mécanisme ``workflow_engine.resolve_template_variables`` existant —
  cf. Task #14).
- ``get_run_variable(name)`` — lit une variable écrite par un step amont.
- ``get_step_output(step_id, kind="workbook")`` — lit l'output d'un step
  amont (workbook produit par extract_sql, etc.) — sera utile quand Iris
  doit analyser les données d'un step précédent.

**Control-flow (#11)** :
- ``route_to(edge_ids)`` — active sélectivement les edges sortants du step
  Iris (les autres descendants sont skipped). Préparation pour routing
  conditionnel (Task #15 différée v2).
- ``skip_steps(step_ids)`` — marque des steps aval comme skipped
  (couverture MVP v1 selon décision P0 Q2).
- ``abort_run(reason, severity="error")`` — arrête l'automation entière
  avec raison tracée (cf. ``IrisAutomationResult.aborted``).

**Mécanisme** : les handlers mutent ``context`` (dict shared agent_service)
via des clés ``_automation_*``. Le ``iris_automation_bridge`` lit ces clés
après le run pour construire le ``IrisAutomationResult`` final.

**Sécurité** :
- Pas de propagation cross-runs (chaque run a son propre ``context`` dict).
- Validation : skip_steps refuse les IDs hors-DAG (à valider runtime —
  pour l'instant, validation faite par le DAG executor avant exécution).
- abort_run est terminal (le runtime quitte la free-loop comme ``done``).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schémas JSON Schema (déclarations IRIS_TOOLS)
# ---------------------------------------------------------------------------

AUTOMATION_DAG_TOOLS: List[Dict[str, Any]] = [
    # ── DAG state (Task #10) ──────────────────────────────────────────
    {
        "name": "set_run_variable",
        "description": (
            "[automation only] Écris une variable dans le state du run DAG. "
            "La variable sera accessible par les steps aval via "
            "``{{<nom_de_ton_step>.<name>}}`` dans leur configuration "
            "(SQL, sujet mail, etc.). Exemple : ``set_run_variable(\"verdict\", "
            "\"OUI\")`` puis un step email aval peut interpoler "
            "``{{iris_decider.verdict}}`` dans son sujet. "
            "Utilise des noms snake_case courts (verdict, period_start, "
            "recipients_csv, target_tab, etc.)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nom de la variable (snake_case). Max 60 chars.",
                },
                "value": {
                    "description": (
                        "Valeur à stocker (string, number, boolean ou objet "
                        "JSON sérialisable). Cap 4KB sérialisé."
                    ),
                },
            },
            "required": ["name", "value"],
        },
    },
    {
        "name": "get_run_variable",
        "description": (
            "[automation only] Lis une variable écrite par toi-même ou par "
            "un step amont. Retourne ``{found: bool, value: any}``. Si la "
            "variable n'existe pas, ``found=false`` — ne plante pas."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Nom de la variable à lire.",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "get_step_output",
        "description": (
            "[automation only] Lis l'output d'un step amont (par ID ou nom). "
            "Retourne le workbook produit (avec tabs/columns/rows) ou les "
            "métadonnées du fichier (pour les steps qui produisent un "
            "fichier comme report/export). Utile quand tu dois analyser les "
            "résultats d'un step précédent avant de décider."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "step_id": {
                    "type": "integer",
                    "description": "ID numérique du step amont.",
                },
                "kind": {
                    "type": "string",
                    "enum": ["workbook", "file", "any"],
                    "default": "any",
                    "description": (
                        "Type d'output attendu : ``workbook`` (.afz.json), "
                        "``file`` (PDF, Excel, CSV), ou ``any`` (laisse "
                        "l'outil détecter)."
                    ),
                },
            },
            "required": ["step_id"],
        },
    },
    # ── Control-flow (Task #11) ───────────────────────────────────────
    {
        "name": "route_to",
        "description": (
            "🚧 [DIFFÉRÉ v2 — NO-OP en v1, ne PAS l'utiliser] Le routing conditionnel "
            "sur edges (`selective_edges_to_activate`) n'est PAS encore implémenté "
            "côté DAG executor (décision P0 Q2 — MVP avec `skip_steps` seul). "
            "Si tu veux router conditionnellement, utilise `skip_steps([step_ids "
            "que tu ne veux pas exécuter], 'raison')` pour désactiver des branches "
            "entières. L'appel à `route_to` est tracé mais n'a AUCUN effet sur le "
            "DAG runtime."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "edge_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Liste des IDs d'edges (no-op v1).",
                },
            },
            "required": ["edge_ids"],
        },
    },
    {
        "name": "skip_steps",
        "description": (
            "[automation only] Marque explicitement des steps aval comme "
            "``skipped`` (ils ne s'exécuteront pas). Utile pour : skip envoi "
            "mail si rien à signaler, skip rapport si données vides, etc. "
            "Les step_ids doivent être DESCENDANTS topologiques du step Iris "
            "courant (pas un step ancêtre ou parallèle indépendant)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "step_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "IDs des steps aval à skipper.",
                },
                "reason": {
                    "type": "string",
                    "description": (
                        "Raison courte du skip (tracée pour audit + UX). "
                        "Ex: « Aucune anomalie détectée »."
                    ),
                },
            },
            "required": ["step_ids", "reason"],
        },
    },
    {
        "name": "abort_run",
        "description": (
            "[automation only] Arrête l'automation entière avec raison tracée. "
            "Utilise ce tool quand tu détectes une condition incompatible avec "
            "la poursuite (données corrompues, écart > threshold critique, "
            "user désactivé en cours de run, etc.). Préfère ``done`` quand "
            "tu peux décider sans avoir besoin d'arrêter tout. Préfère "
            "``skip_steps`` quand seuls quelques steps aval n'ont plus de sens. "
            "``abort_run`` = stop net du DAG entier."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": (
                        "Raison claire et factuelle (visible UI + audit). "
                        "Ex: « Somme sous-totaux ≠ total : 12450 vs 12500 »."
                    ),
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "warn", "error"],
                    "default": "error",
                    "description": (
                        "Sévérité de l'abort. ``error`` (défaut) marque le run "
                        "failed. ``warn`` log un warning mais marque success. "
                        "``info`` purement informationnel."
                    ),
                },
            },
            "required": ["reason"],
        },
    },
]


# ---------------------------------------------------------------------------
# Constantes internes (caps pour ne pas exploser context shared)
# ---------------------------------------------------------------------------

_MAX_VARIABLE_NAME_LEN: int = 60
_MAX_VARIABLE_VALUE_BYTES: int = 4 * 1024  # 4KB sérialisé JSON
_MAX_REASON_LEN: int = 500


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _ensure_automation_context(context: Dict) -> None:
    """Initialise les clés ``_automation_*`` dans le context shared si absentes.

    Idempotent — peut être appelé plusieurs fois sans réinitialiser les
    données déjà présentes.
    """
    context.setdefault("_automation_run_variables", {})
    context.setdefault("_automation_route_to_edges", None)  # None = défaut (tous activés)
    context.setdefault("_automation_skip_steps", [])
    context.setdefault("_automation_skip_reasons", {})
    context.setdefault("_automation_abort", None)  # None = pas d'abort, ou dict {reason, severity}


def _is_automation_context(context: Dict, user: Any) -> bool:
    """Garde-fou : ces tools ne doivent s'exécuter QUE en mode automation.

    En théorie la whitelist ``AUTOMATION_TOOL_CLASSIFICATION`` bloque déjà
    l'appel en mode page/widget (ces tools ne sont jamais exposés au LLM
    hors automation). Mais défense en profondeur : si pour une raison X
    un handler est appelé hors automation, on refuse explicitement.

    Détection : le contexte automation est posé par ``iris_automation_bridge``
    via la clé ``_automation_mode = True``.
    """
    return bool(context.get("_automation_mode") is True)


async def _handle_set_run_variable(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Écrit une variable dans le state du run DAG."""
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "set_run_variable n'est disponible qu'en mode automation.",
        }

    name = (tool_input.get("name") or "").strip()
    if not name:
        return {"success": False, "error": "Le paramètre `name` est requis."}
    if len(name) > _MAX_VARIABLE_NAME_LEN:
        return {
            "success": False,
            "error": f"Nom trop long ({len(name)} > {_MAX_VARIABLE_NAME_LEN} chars).",
        }

    # Cap valeur sérialisée pour éviter explosion context shared
    import json

    try:
        serialized = json.dumps(tool_input.get("value"), default=str)
    except (TypeError, ValueError) as exc:
        return {
            "success": False,
            "error": f"Valeur non sérialisable JSON : {exc}",
        }
    if len(serialized) > _MAX_VARIABLE_VALUE_BYTES:
        return {
            "success": False,
            "error": (
                f"Valeur trop grande ({len(serialized)} > "
                f"{_MAX_VARIABLE_VALUE_BYTES} bytes JSON). Synthétisez "
                "ou stockez juste la décision (pas les données brutes)."
            ),
        }

    _ensure_automation_context(context)
    # Fix MINOR #12 (adversarial 2026-05-27) : stocker la version JSON
    # roundtrip-safe pour éviter qu'un type non-sérialisable (datetime,
    # set, custom) écrit en mémoire crash au step aval qui sérialise.
    # On a déjà vérifié `json.dumps(...)` plus haut → ré-importer pour
    # garantir la roundtrip-safety au stockage.
    import json as _json

    safe_value = _json.loads(serialized)
    context["_automation_run_variables"][name] = safe_value
    return {
        "success": True,
        "name": name,
        "message": f"Variable `{name}` écrite ({len(serialized)} bytes).",
    }


async def _handle_get_run_variable(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Lit une variable du state du run DAG."""
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "get_run_variable n'est disponible qu'en mode automation.",
        }

    name = (tool_input.get("name") or "").strip()
    if not name:
        return {"success": False, "error": "Le paramètre `name` est requis."}

    _ensure_automation_context(context)
    # Lecture combinée : variables écrites par Iris + variables fournies en
    # entrée par le bridge (DAGRunContext.variables des steps amont, posées
    # par iris_automation_bridge via _automation_upstream_variables).
    iris_vars = context.get("_automation_run_variables", {})
    upstream_vars = context.get("_automation_upstream_variables", {})
    if name in iris_vars:
        return {"success": True, "found": True, "value": iris_vars[name], "source": "iris"}
    if name in upstream_vars:
        return {
            "success": True,
            "found": True,
            "value": upstream_vars[name],
            "source": "upstream",
        }
    return {"success": True, "found": False, "value": None}


async def _handle_get_step_output(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Lit l'output d'un step amont (posé par le bridge avant agent.run).

    Task #29 (CRITIQUE sécu) : le payload retourné au LLM est ANONYMISÉ via
    `anonymize_for_llm` (couche PII regex + Pseudonymizer user-scoped).
    Sinon : fuite directe de données Sage vers le LLM cloud quand Iris
    en automation lit un workbook produit par un step extract_sql amont
    contenant noms clients / montants / SIRET / etc.
    """
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "get_step_output n'est disponible qu'en mode automation.",
        }

    step_id = tool_input.get("step_id")
    if not isinstance(step_id, int):
        return {"success": False, "error": "Le paramètre `step_id` doit être un entier."}

    kind = tool_input.get("kind", "any")
    if kind not in ("workbook", "file", "any"):
        return {
            "success": False,
            "error": f"`kind` invalide ({kind!r}). Valeurs : workbook/file/any.",
        }

    # Le bridge dépose les outputs amont dans context["_automation_step_outputs"]
    # (dict step_id → {kind, payload}). Si pas posé → step non trouvé.
    step_outputs = context.get("_automation_step_outputs", {})
    if step_id not in step_outputs:
        return {
            "success": False,
            "found": False,
            "error": (
                f"Step {step_id} non disponible en entrée. Vérifiez que ce step "
                "est bien parent topologique du step Iris dans le DAG."
            ),
        }

    entry = step_outputs[step_id]
    actual_kind = entry.get("kind")
    if kind != "any" and actual_kind != kind:
        return {
            "success": False,
            "found": True,
            "error": (
                f"Step {step_id} a produit `{actual_kind}` mais tu as demandé `{kind}`."
            ),
        }

    # Task #29 — Anonymisation CRITIQUE avant retour au LLM
    # Fix MAJOR #8 (adversarial 2026-05-27) : fail-CLOSED si user_id absent.
    # Sans user_id, `anonymize_for_llm` skip le pseudonymizer user-scoped
    # → les noms clients/comptes mappés dans /data-privacy partent en CLEAR
    # vers le LLM cloud. On REFUSE plutôt que retourner en mode degraded.
    payload = entry.get("payload")
    user_id_for_anon = getattr(user, "id", None)
    if payload is not None and not isinstance(user_id_for_anon, int):
        return {
            "success": False,
            "found": True,
            "error": (
                "Anonymisation impossible : user_id non valide ou absent. "
                "Sans user_id, le pseudonymizer user-scoped ne peut pas "
                "tokeniser les termes confidentiels du cabinet → refus "
                "défense en profondeur (sécurité > disponibilité)."
            ),
        }
    if payload is not None:
        try:
            from app.services.anonymization import anonymize_for_llm

            # Anonymise récursivement (dict/list/str/numeric). PII regex
            # (email/SIRET/IBAN/montant) toujours appliquée. Pseudonymizer
            # user-scoped en plus si user_id valide. Token sortant : `[EMAIL_N]`
            # pour PII regex, `§…§` pour pseudos user-scoped.
            anonymized_payload, _restore_fn = await anonymize_for_llm(
                user_id_for_anon, payload, "IRIS_CHAT"
            )
            payload = anonymized_payload
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:  # noqa: BLE001
            # Fail-CLOSED : si l'anonymisation crash, on REFUSE de retourner
            # les données brutes (sécurité prime sur disponibilité). Iris
            # verra l'erreur et pourra abort_run proprement.
            logger.error(
                "get_step_output: anonymize_for_llm a crash — REFUS de retour brut "
                "(défense en profondeur fuite PII)",
                exc_info=True,
            )
            return {
                "success": False,
                "found": True,
                "error": (
                    "Échec anonymisation du payload step amont. Données non "
                    "retournées (sécurité). Réessayez ou contactez l'admin."
                ),
            }

    return {
        "success": True,
        "found": True,
        "step_id": step_id,
        "kind": actual_kind,
        "payload": payload,
    }


async def _handle_route_to(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Active sélectivement les edges sortants du step Iris."""
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "route_to n'est disponible qu'en mode automation.",
        }

    edge_ids = tool_input.get("edge_ids")
    if not isinstance(edge_ids, list) or not all(isinstance(e, int) for e in edge_ids):
        return {
            "success": False,
            "error": "`edge_ids` doit être une liste d'entiers (IDs d'edges).",
        }

    _ensure_automation_context(context)
    context["_automation_route_to_edges"] = list(edge_ids)
    return {
        "success": True,
        "activated_edges": edge_ids,
        "message": f"{len(edge_ids)} edge(s) activé(s) sélectivement.",
    }


async def _handle_skip_steps(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Marque des steps aval comme skipped (avec raison tracée).

    Fix CRIT #5 (adversarial 2026-05-27) : validation runtime que les
    step_ids sont bien DESCENDANTS topologiques du step Iris courant.
    Sans cette validation, Iris (qui peut halluciner) peut corrompre
    le state DAG en skippant des ancêtres / steps parallèles / steps
    d'autres automations.

    Le bridge dépose dans ``context["_automation_allowed_skip_targets"]``
    la liste des step_ids descendants topologiques pré-calculée (set).
    Si non posée → fail-closed (refuse tout skip).
    """
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "skip_steps n'est disponible qu'en mode automation.",
        }

    step_ids = tool_input.get("step_ids")
    if not isinstance(step_ids, list) or not all(isinstance(s, int) for s in step_ids):
        return {
            "success": False,
            "error": "`step_ids` doit être une liste d'entiers.",
        }

    reason = (tool_input.get("reason") or "").strip()
    if not reason:
        return {
            "success": False,
            "error": "Le paramètre `reason` est requis (tracé pour audit).",
        }
    if len(reason) > _MAX_REASON_LEN:
        reason = reason[: _MAX_REASON_LEN - 1].rstrip() + "…"

    # Fix CRIT #5 — Validation descendants topologiques. Si le bridge n'a
    # pas posé la liste des cibles autorisées, on REFUSE (fail-closed).
    allowed_targets = context.get("_automation_allowed_skip_targets")
    if allowed_targets is None:
        return {
            "success": False,
            "error": (
                "Skip refusé : le bridge n'a pas exposé la liste des steps "
                "aval autorisés (fail-closed défense en profondeur)."
            ),
        }
    if not isinstance(allowed_targets, (set, frozenset, list, tuple)):
        return {
            "success": False,
            "error": "Skip refusé : config interne corrompue (allowed_targets type).",
        }
    allowed_set = set(allowed_targets)
    invalid = [s for s in step_ids if s not in allowed_set]
    if invalid:
        return {
            "success": False,
            "error": (
                f"Skip refusé : step_ids {invalid} ne sont PAS des descendants "
                "topologiques du step Iris courant. Tu ne peux skipper que "
                f"parmi : {sorted(allowed_set)[:20]}{'…' if len(allowed_set) > 20 else ''}."
            ),
        }

    _ensure_automation_context(context)
    # Merge avec skips précédents (Iris peut appeler skip_steps plusieurs fois)
    existing = set(context["_automation_skip_steps"])
    existing.update(step_ids)
    context["_automation_skip_steps"] = sorted(existing)
    for sid in step_ids:
        context["_automation_skip_reasons"][sid] = reason
    return {
        "success": True,
        "skipped": step_ids,
        "reason": reason,
        "message": f"{len(step_ids)} step(s) marqué(s) skipped.",
    }


async def _handle_abort_run(
    tool_input: Dict[str, Any], user: Any, context: Dict
) -> Dict[str, Any]:
    """Arrête l'automation avec raison + sévérité (terminal)."""
    if not _is_automation_context(context, user):
        return {
            "success": False,
            "error": "abort_run n'est disponible qu'en mode automation.",
        }

    reason = (tool_input.get("reason") or "").strip()
    if not reason:
        return {
            "success": False,
            "error": "Le paramètre `reason` est requis.",
        }
    if len(reason) > _MAX_REASON_LEN:
        reason = reason[: _MAX_REASON_LEN - 1].rstrip() + "…"

    severity = tool_input.get("severity", "error")
    if severity not in ("info", "warn", "error"):
        severity = "error"

    _ensure_automation_context(context)
    context["_automation_abort"] = {"reason": reason, "severity": severity}
    # Aussi : signaler terminal_kind=abandon pour que le runtime sorte de la
    # boucle (même mécanisme que ``_handle_abandon``).
    context["_terminal_kind"] = "abandon"
    context["_terminal_summary"] = reason
    return {
        "success": True,
        "aborted": True,
        "reason": reason,
        "severity": severity,
        "message": "Automation arrêtée.",
    }


# ---------------------------------------------------------------------------
# Mapping handlers (export pour intégration agent_tools._TOOL_HANDLERS)
# ---------------------------------------------------------------------------

AUTOMATION_DAG_TOOL_HANDLERS: Dict[str, Any] = {
    "set_run_variable": _handle_set_run_variable,
    "get_run_variable": _handle_get_run_variable,
    "get_step_output": _handle_get_step_output,
    "route_to": _handle_route_to,
    "skip_steps": _handle_skip_steps,
    "abort_run": _handle_abort_run,
}


# Liste des noms exposée pour les filtres role / classification
AUTOMATION_DAG_TOOL_NAMES: set = set(AUTOMATION_DAG_TOOL_HANDLERS.keys())
