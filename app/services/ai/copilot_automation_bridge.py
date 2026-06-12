"""
Bridge automation ↔ copilot_agent (Phase 3e).

Le step type ``format_copilot`` du DAG d'automatisation appelle le
``run_copilot_agent`` interactif (concu pour le frontend iris-grid) pour
appliquer une transformation de classeur decrite en langage naturel.

Ce module expose une facade simple
``format_workbook_for_automation(workbook, instruction, user_id, tab_index=0)``
qui :
1. Convertit le format workbook automation (rows = list[dict]) au format
   ``tabs_context`` attendu par run_copilot_agent.
2. Forwarde ``user_id`` pour que le **gate d'anonymisation** reste actif —
   c'est volontaire : si l'utilisateur a des termes non confirmes dans
   ``anonymization_terms``, le step echoue avec un message clair l'invitant
   a aller dans /iris pour confirmer. Pas de bypass "trusted server-side".
3. Recupere le ``terminal_result`` (type ``emit_tab``), reconvertit les
   rows liste-de-listes → liste-de-dicts, et reconstruit un workbook au
   format automation.
4. Gere les erreurs (ANON_PENDING_REVIEW, abandon, error generique) en
   levant ``CopilotAutomationError`` avec un message lisible pour
   l'utilisateur dans le panel de l'execution.

Securite :
* Le gate d'anonymisation est preserve (CWE-200 information exposure
  via LLM cloud non-controle).
* Aucune execution de Python sandboxe ici — c'est ``run_copilot_agent``
  qui orchestre les tools internes (``run_python``, ``emit_via_code``,
  ``ask_iris``) avec leurs propres protections (AST whitelist,
  schema validation, etc.).
* Les ``error_message`` provenant de l'agent ne sont JAMAIS retournes
  bruts au DAG executor : ``_safe_error_message`` les nettoie.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


class CopilotAutomationError(Exception):
    """Erreur consommable par le DAG executor (message utilisateur safe)."""


def _safe_error_message(raw: Any, *, max_length: int = 300) -> str:
    """Sanitise un message d'erreur du copilot avant exposition (CWE-209).

    Le LLM, le provider Anthropic et le sandbox Python peuvent tous
    inclure dans leurs erreurs : chemins serveur (Unix/Windows), API
    keys (sk-ant-…, Bearer …), credentials inline (password=…), IPs
    privees (10.x, 192.168.x). Defense-in-depth : strip tout ca avant
    affichage dans le panel de l'execution (lu par tout admin avec
    acces aux logs/UI).
    """
    if raw is None:
        return "erreur inconnue"
    text = str(raw)
    # Chemins absolus Unix
    text = re.sub(r"/(Users|home|var|etc|tmp|root|opt)/[^\s'\"]+", "<path>", text)
    # Chemins absolus Windows
    text = re.sub(r"\b[A-Za-z]:\\[\w\\.\-]+", "<path>", text)
    # API keys / tokens / credentials inline (password=, token=, api_key=, etc.)
    text = re.sub(
        r"\b(sk-ant-\S+|sk-[a-zA-Z0-9_-]{20,}|Bearer\s+\S+)",
        "<redacted>",
        text,
    )
    text = re.sub(
        r"(password|pwd|token|secret|api[-_]?key)\s*=\s*[^;\s'\"]+",
        r"\1=***",
        text,
        flags=re.IGNORECASE,
    )
    # IPs privees (RFC1918) — utile pour ne pas leaker la topologie
    text = re.sub(
        r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
        "<ip>",
        text,
    )
    if len(text) > max_length:
        text = text[: max_length - 1].rstrip() + "…"
    return text or "erreur inconnue"


# _MAX_ROWS_TO_LLM supprimé 2026-05-27 (décision P0 Q9 doctrine user "SSoT
# admin OU pas de limite"). Pas de SSoT directe pour le cap rows→LLM : le
# LLM cape lui-même via son ``context_window`` (registre BDD LlmModel).
# Si l'user veut limiter, il pré-filtre en amont via une étape SQL/format.


def _rows_to_sheet_content(
    rows: list, columns: list, *, max_rows: Optional[int] = None
) -> tuple[list, bool]:
    """Convertit les rows automation (list[dict]) en sheet_content sparse
    (list[{row, col, value}], 1-based) attendu par le copilot.

    Retourne ``(sheet_content, truncated_bool)``. Les cellules vides
    (None ou string vide) sont omises (format sparse). Si ``max_rows`` est
    fourni et que rows depasse, on tronque et signale via le booleen. Si
    ``max_rows`` est ``None`` (defaut), aucune troncature — le LLM cape
    lui-même via son context_window.
    """
    truncated = max_rows is not None and len(rows) > max_rows
    rows_to_send = rows[:max_rows] if max_rows is not None else rows
    sheet: list = []
    for r_idx, row in enumerate(rows_to_send):
        if not isinstance(row, dict):
            continue
        for col in columns:
            val = row.get(col)
            if val is None or val == "":
                continue  # sparse : skip empty
            sheet.append(
                {
                    "row": r_idx + 1,  # 1-based (convention copilot)
                    "col": col,
                    "value": val,
                }
            )
    return sheet, truncated


def _automation_workbook_to_tabs_context(
    workbook: Dict[str, Any],
    active_index: int,
    *,
    max_rows_per_tab: Optional[int] = None,
) -> tuple[list, list, dict]:
    """Convertit le workbook automation au format ``tabs_context`` + sheet_content.

    Le copilot a besoin de DEUX choses :
    * un ``tabs_context`` (list de meta + sheet_content par tab non-actif)
    * un ``sheet_content`` top-level pour le tab ACTIF

    Cette fonction prepare les deux. Pour chaque tab, on convertit ``rows``
    en cellules sparse via ``_rows_to_sheet_content`` et on cap a
    ``max_rows_per_tab`` lignes (garde-fou contre un workbook geant qui
    exploserait le contexte LLM).

    Retourne ``(tabs_context, active_sheet_content, truncation_info)`` ou
    truncation_info est ``{tab_label: rows_total}`` pour les tabs tronques.
    """
    tabs = workbook.get("tabs") or []
    out: list = []
    active_sheet: list = []
    truncation_info: dict = {}
    for i, tab in enumerate(tabs):
        if not isinstance(tab, dict):
            continue
        rows = tab.get("rows") or []
        columns = list(tab.get("columns") or [])
        sheet, truncated = _rows_to_sheet_content(rows, columns, max_rows=max_rows_per_tab)
        if truncated:
            truncation_info[tab.get("label", f"Onglet {i + 1}")] = len(rows)

        is_active = i == active_index
        tab_ctx = {
            "index": i,
            "label": tab.get("label", f"Onglet {i + 1}"),
            "columns": columns,
            "row_count": len(rows),  # vrai total (pas le tronque)
            "is_active": is_active,
            "sql": tab.get("sql"),
            "col_distinct": {},
        }
        # Pour les tabs non-actifs, on attache `sheet_content` directement
        # au tab. Pour l'actif, on l'expose top-level (convention copilot).
        if not is_active:
            tab_ctx["sheet_content"] = sheet
        else:
            active_sheet = sheet
        out.append(tab_ctx)
    return out, active_sheet, truncation_info


def _copilot_terminal_to_workbook(
    terminal_result: Dict[str, Any],
    *,
    fallback_label: str,
) -> tuple[Dict[str, Any], int]:
    """Recupere le ``tab`` final du copilot et reconstruit un workbook auto.

    Les ``rows`` du copilot sont au format liste-de-listes (aligne sur
    ``columns``). On les transforme en liste-de-dicts pour le format
    workbook.

    **Difference critique avec ``rows_to_workbook``** : on PRESERVE
    ``columns`` venu du copilot meme si ``rows`` est vide (filtre total).
    Sinon le step suivant recoit `columns=[]` et plante avec un message
    obscur. On retourne aussi le compte de rows malformees ignorees pour
    audit (CWE : "donnees fausses sans erreur visible").

    Retourne ``(workbook, n_skipped_rows)``.
    """
    tab = terminal_result.get("tab") or {}
    columns = list(tab.get("columns") or [])
    raw_rows = tab.get("rows") or []
    label = tab.get("label") or fallback_label

    rows_as_dicts: list = []
    n_skipped = 0
    for row in raw_rows:
        if isinstance(row, dict):
            rows_as_dicts.append(row)
        elif isinstance(row, (list, tuple)):
            rows_as_dicts.append(dict(zip(columns, row)))
        else:
            n_skipped += 1

    # Construction directe : preserve `columns` meme si rows vide.
    workbook = {
        "version": 1,
        "app": "komptia",
        "tabs": [
            {
                "label": label,
                "columns": columns,
                "rows": rows_as_dicts,
                "totalRowCount": len(rows_as_dicts),
            }
        ],
        "warnings": [],
    }
    return workbook, n_skipped


async def format_workbook_for_automation(
    workbook: Dict[str, Any],
    instruction: str,
    *,
    user_id: Optional[int],
    user: Any = None,
    tab_index: int = 0,
    max_rows: Optional[int] = None,
    max_rows_to_llm: Optional[int] = None,
) -> Dict[str, Any]:
    """Applique une transformation copilot a un workbook d'automation.

    Pipeline :
    1. Convertit ``rows`` (list[dict]) en ``sheet_content`` sparse
       (cells [{row, col, value}] 1-based) — c'est le format que le
       copilot attend pour ``read_tab_rows`` ET pour le gate
       d'anonymisation (``extract_terms`` scanne sheet_content/rows).
    2. Cap a ``max_rows_to_llm`` cellules par tab pour ne pas exploser
       le contexte LLM (200k tokens chez Anthropic). Au-dela on tronque
       avec warning explicite.
    3. Appelle ``run_copilot_agent`` (gate anonymisation actif via
       ``user_id`` qui pointe la table ``anonymization_terms``).
    4. Reconvertit le terminal emit_tab en workbook automation.
    5. PRESERVE les autres onglets du workbook input (transformation
       1-tab → 1-tab + autres tabs intacts) avec warning si remplaces.

    Args:
        workbook: Workbook automation ``{tabs: [{label, columns, rows, sql?}]}``.
        instruction: Instruction en langage naturel.
        user_id: Id du proprietaire — REQUIS (>0) pour activer le gate.
        user: Objet ORM ``User`` complet (optionnel). Propage le contexte RLS
            data_access jusqu'a ``executor.execute`` quand le copilot invoque
            ``ask_iris`` / ``modify_tab_sql``. Sans user, l'enforcer logue
            ``RLS skip`` (fail-OPEN historique). Le caller (automation
            executor) doit le fournir si dispo : ``user_id`` seul ne suffit
            pas (l'enforcer a besoin de ``user.role``/``user.scopes``).
        tab_index: Onglet a transformer (default 0).
        max_rows: Plafond strict d'entree (defense memoire BDD).
        max_rows_to_llm: Cap d'envoi au LLM (defense contexte tokens).

    Returns:
        Workbook automation post-transformation.

    Leve ``CopilotAutomationError`` sur :
        - instruction vide
        - workbook vide / tab_index hors-bornes
        - user_id absent ou invalide (gate d'anonymisation impossible)
        - depassement max_rows
        - ANON_PENDING_REVIEW
        - erreur copilot generique / abandon / type terminal non-supporte
    """
    from app.services.ai.copilot_agent import run_copilot_agent

    instruction = (instruction or "").strip()
    if not instruction:
        raise CopilotAutomationError(
            "Instruction vide : decrivez en quelques mots la transformation a appliquer."
        )

    # Validation explicite user_id (CWE-285) : le gate d'anonymisation
    # cote run_copilot_agent depend de user_id pour lire les termes
    # confirmes depuis la BDD. Sans user_id valide, le gate fonctionne
    # quand meme (fail-closed sur state vide) mais l'audit log attribue
    # l'action a "user 0" ce qui complique l'investigation. On refuse
    # explicitement.
    if not isinstance(user_id, int) or user_id <= 0:
        raise CopilotAutomationError(
            "user_id automation invalide ; impossible d'appliquer le gate "
            "d'anonymisation. Verifiez que l'automation a un proprietaire."
        )

    tabs = (workbook or {}).get("tabs") or []
    if not tabs:
        raise CopilotAutomationError(
            "Aucun onglet a transformer : verifiez que l'etape precedente "
            "produit bien un classeur."
        )
    if not (0 <= tab_index < len(tabs)):
        raise CopilotAutomationError(
            f"tab_index hors-bornes : {tab_index} (le classeur a {len(tabs)} onglets)."
        )

    # NOTE : la materialisation des SQL tabs (re-exec via QueryExecutor pour
    # hydrater rows quand le classeur arrive avec des onglets SQL non
    # materialises — cas load_workbook ou format_copilot precedent) est faite
    # par le caller (executor.py adapter format_copilot). Le bridge reste pur
    # pour rester unit-testable sans BDD ni Sage. Si un caller oublie la
    # materialisation, le copilot transformera du vide silencieusement.

    active_tab = tabs[tab_index]
    active_label = active_tab.get("label", f"Onglet {tab_index + 1}")
    active_columns = list(active_tab.get("columns") or [])
    active_row_count = len(active_tab.get("rows") or [])
    active_sql = active_tab.get("sql") or ""

    if max_rows is not None and active_row_count > max_rows:
        raise CopilotAutomationError(
            f"Trop de lignes a transformer ({active_row_count} > {max_rows}). "
            "Pre-filtrez avec une etape filter_rows ou augmentez max_rows."
        )

    # Conversion rows → sheet_content (sparse, avec cap LLM).
    tabs_context, active_sheet, truncation_info = _automation_workbook_to_tabs_context(
        workbook, tab_index, max_rows_per_tab=max_rows_to_llm
    )

    logger.info(
        "format_copilot start (user_id=%s, tab=%s, rows=%d, cells_to_llm=%d, instr_len=%d)",
        user_id,
        active_label,
        active_row_count,
        len(active_sheet),
        len(instruction),
    )

    try:
        result = await run_copilot_agent(
            sql=active_sql,
            instruction=instruction,
            columns=active_columns,
            display_state=None,
            tabs_context=tabs_context,
            sheet_content=active_sheet,  # Phase 3e: vraies donnees passees
            sheet_context=None,
            is_auto_fill=False,
            run_id="",
            user_id=user_id,
            anonymization_state=None,  # source = BDD via user_id
            copilot_memory="",
            user=user,
        )
    except (KeyboardInterrupt, SystemExit):
        # Ne JAMAIS catch ces exceptions critiques (BLE001 best practice).
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("format_copilot run_copilot_agent crash", exc_info=True)
        # `from None` casse la chaine __cause__ pour eviter qu'un caller
        # qui logue exc.__cause__ ne fasse fuir le path absolu / token /
        # credential (le sanitize ne nettoie que le message visible).
        # Le traceback complet reste dans logger.error ci-dessus pour debug.
        raise CopilotAutomationError(
            f"Erreur d'execution copilot : {_safe_error_message(exc)}"
        ) from None

    if not isinstance(result, dict):
        raise CopilotAutomationError(f"Reponse copilot inattendue (type={type(result).__name__}).")

    # --- Cas 1 : gate anonymisation bloque ---
    err_code = result.get("error_code")
    if err_code == "ANON_PENDING_REVIEW":
        # Page de validation : /data/privacy (pas /iris — corrige
        # message historique 2026-05-08 qui pointait sur l'ancienne
        # page admin retiree). L'utilisateur peut valider en bulk
        # par categorie / par source.
        raise CopilotAutomationError(
            "Termes confidentiels a valider avant d'utiliser le copilot IA. "
            "Ouvrez /data/privacy, confirmez les termes detectes (validation "
            "possible en lot), puis relancez l'automatisation."
        )

    # --- Cas 2 : erreur generique ---
    if "error" in result:
        raise CopilotAutomationError(f"Copilot : {_safe_error_message(result.get('error'))}")

    # --- Cas 3 : abandon explicite ---
    terminal_kind = result.get("type") or result.get("terminal_kind") or "<absent>"
    if terminal_kind == "abandon":
        reason = result.get("reason") or result.get("message") or "raison non precisee"
        raise CopilotAutomationError(f"Copilot a abandonne : {_safe_error_message(reason)}")

    # --- Cas 4 : terminal `done` multi-actions (emits + modifications) ---
    # Le copilot peut terminer en mode `done` avec plusieurs actions :
    # cf. copilot_tools.py:2824. Format : {type: "done", emits: [...],
    # modifications: [...], summary: ""}. Pour un step `format_copilot`
    # d'automation, on attend UN onglet transformé final → on prend le
    # DERNIER emit DE TYPE ``emit_tab`` (l'ordre reflète la chronologie
    # des actions LLM, le dernier emit_tab est l'état final voulu pour
    # cet onglet). Les autres types (``modify_tab_sql``, ``patch_tab``,
    # ``rename_tab``, ``delete_tab``, ``emit_via_code``) ne produisent
    # PAS un onglet complet — ils modifient un existant — donc pas
    # éligibles comme sortie de format_copilot.
    # Décision David 2026-05-08 : ne plus rejeter `done`.
    if terminal_kind == "done":
        all_emits = result.get("emits") or []
        # Filtrer aux emit_tab uniquement — un modify_tab_sql/patch_tab/etc.
        # ne fournit pas la structure ``tab`` complète attendue par
        # ``_copilot_terminal_to_workbook``.
        emit_tab_emits = [
            e for e in all_emits if isinstance(e, dict) and e.get("type") == "emit_tab"
        ]
        if not emit_tab_emits:
            non_emit_types = sorted(
                {
                    e.get("type", "?")
                    for e in all_emits
                    if isinstance(e, dict) and e.get("type") != "emit_tab"
                }
            )
            detail = f" (types produits : {', '.join(non_emit_types)})" if non_emit_types else ""
            raise CopilotAutomationError(
                "Copilot a termine en mode 'done' sans aucun emit_tab"
                + detail
                + ". Le step format_copilot a besoin d'un onglet COMPLET "
                "(emit_tab) — les actions de modification (modify_tab_sql, "
                "patch_tab, rename_tab) ne produisent pas un onglet "
                "autonome. Reformulez l'instruction pour produire un "
                "onglet complet (par exemple : « recrée l'onglet X avec "
                "le SQL Y et toutes ses colonnes »)."
            )
        # Le dernier emit_tab reflète l'état final voulu. On promeut son
        # contenu au niveau racine pour rester compat avec
        # `_copilot_terminal_to_workbook` qui lit `result['tab']`.
        last_emit = emit_tab_emits[-1]
        result = {**last_emit, "type": "emit_tab"}
        terminal_kind = "emit_tab"
        if len(all_emits) > 1:
            logger.info(
                "format_copilot: copilot a emis %d actions, on retient le "
                "dernier emit_tab (%d emit_tab sur %d actions ; les autres "
                "sont des modifications/etapes intermediaires).",
                len(all_emits),
                len(emit_tab_emits),
                len(all_emits),
            )

    # --- Cas 5 : terminal != emit_tab (patch_tab/rename_tab/etc.) ---
    if terminal_kind != "emit_tab":
        raise CopilotAutomationError(
            f"Copilot a produit un type terminal non-supporte : '{terminal_kind}'. "
            "Reformulez l'instruction pour produire un onglet complet."
        )

    if "tab" not in result:
        raise CopilotAutomationError("Copilot : tab manquant dans la reponse.")

    transformed_tab_workbook, n_skipped = _copilot_terminal_to_workbook(
        result, fallback_label=active_label
    )

    # Preserver les autres onglets du workbook input. La transformation
    # est 1-tab → 1-tab : les autres tabs ne doivent PAS disparaitre
    # silencieusement (CWE: donnees fausses sans erreur visible).
    transformed_tab = transformed_tab_workbook["tabs"][0]
    output_workbook = {
        "version": 1,
        "app": "komptia",
        "tabs": [],
        "warnings": [],
    }
    for i, tab in enumerate(tabs):
        if i == tab_index:
            output_workbook["tabs"].append(transformed_tab)
        else:
            output_workbook["tabs"].append(tab)

    # Warnings : truncation, multi-tab, rows malformees, metrics.
    if truncation_info:
        for label, total in truncation_info.items():
            output_workbook["warnings"].append(
                f"format_copilot : '{label}' tronque a {max_rows_to_llm}/{total} "
                "lignes envoyees au LLM (contexte token cap). Pre-filtrez avec "
                "filter_rows pour garantir la couverture complete."
            )
    if n_skipped > 0:
        output_workbook["warnings"].append(
            f"format_copilot : {n_skipped} ligne(s) malformee(s) ignoree(s) "
            "dans la sortie copilot."
        )

    # **Garde workbook vide (fix 2026-06-10, consequences.md axe 5)** : un
    # onglet transforme avec columns non vides mais rows=[] (« filtre
    # total » : aucune ligne ne matche) traversait le DAG comme un SUCCES —
    # les steps suivants (rapport PDF, export, email) operaient sur du vide
    # sans aucun signal. Doctrine :
    #  * TOUS les onglets sortants vides → erreur explicite (le DAG n'a
    #    plus AUCUNE donnee a traiter, continuer n'a pas de sens) ;
    #  * onglet transforme vide mais d'autres onglets ont des donnees →
    #    warning structure dans le rapport d'execution (SSoT
    #    output_workbook["warnings"], surface par l'executor).
    transformed_rows_count = len(transformed_tab.get("rows") or [])
    all_tabs_empty = all(
        not (t.get("rows") or []) for t in output_workbook["tabs"] if isinstance(t, dict)
    )
    if transformed_rows_count == 0 and all_tabs_empty:
        raise CopilotAutomationError(
            f"format_copilot : l'onglet transforme '{active_label}' est VIDE "
            "(0 ligne — l'instruction a probablement filtre toutes les lignes) "
            "et aucun autre onglet du classeur ne contient de donnees. "
            "Execution interrompue plutot que de produire un rapport/export vide. "
            "Verifiez l'instruction de transformation ou les donnees sources."
        )
    if transformed_rows_count == 0:
        output_workbook["warnings"].append(
            f"format_copilot : l'onglet transforme '{active_label}' est VIDE "
            "(0 ligne apres transformation — filtre total ?). Les steps "
            "suivants opereront sur les autres onglets ; verifiez que c'est "
            "intentionnel."
        )

    metrics = result.get("metrics") or {}
    # Gate sur metrics non-vide : sinon le warning ne contient que des "?"
    # qui pollue l'UI sans information utile (le copilot peut ne pas
    # remonter de metrics dans certains chemins terminaux precoces).
    if metrics:
        output_workbook["warnings"].append(
            f"copilot metrics: turns={metrics.get('turns', '?')}, "
            f"tokens_in={metrics.get('tokens_in', '?')}, "
            f"tokens_out={metrics.get('tokens_out', '?')}"
        )

    logger.info(
        "format_copilot end (user_id=%s, tab=%s, rows_out=%d, turns=%s, skipped=%d)",
        user_id,
        active_label,
        len(transformed_tab.get("rows", [])),
        metrics.get("turns"),
        n_skipped,
    )

    return output_workbook
