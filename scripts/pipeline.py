#!/usr/bin/env python3
"""Pipeline NL→SQL monolithique — orchestrateur unique de toutes les phases.

Avant ce fichier : `run_pipeline.py` lançait 8 sous-scripts en subprocess
(`test_pipeline_extract.py`, `llm_filter_entities.py`, `llm_curate_terms.py`,
`test_pipeline_search.py`, `test_pipeline_v2.py`, `llm_rerank_per_concept.py`,
`llm_generate_sql.py`, `llm_diagnose_and_retry.py`). Chaque phase écrivait
des fichiers intermédiaires (`extracted_terms.txt`, `search_results_test*.txt`,
`<concept>.json` × 20, `dropped_entities.json`, `user_qa_session.json`, etc.)
juste pour transporter l'état entre subprocess.

Maintenant : 1 seul process Python, 8 phases en fonctions, état partagé en
mémoire (`PipelineState`), 2 fichiers d'output (`outputs/run.json` snapshot
+ `outputs/run.sql` SQL final). Plus de timeout subprocess (Phase 4 appelle
Phase 3 directement), plus de re-imports (sqlglot/anthropic chargés 1 fois),
plus de race conditions cross-process sur user_qa_session.json.

Usage minimal :
    python scripts/pipeline.py "Donne-moi le CA par expert ..."

Options :
    --block-all-views          # mode test : drop TOUTES les vues (Phase 1.2.5)
    --max-probes N             # cap sur les sous-requêtes Phase 4 (défaut 15)
    --max-qa-loops N           # max Q/A loops par concept (filter+curate)
    --only-phase PHASE         # exécute UNE phase (1.1-1.2 / 1.2.5 / 1.2.6 /
                               #   1.3-1.4 / 1.5 / 2 / 3 / 4), lit run.json amont
    --resume                   # reprend après dernière phase complétée dans run.json
    --no-clean                 # ne wipe pas run.json avant le run
    --db PATH                  # BDD source (défaut data/sage_copy.db)
    --debug-traces             # écrit les traces LLM brutes dans outputs/_debug_traces/
    --top-n N                  # Phase 3, nb de tables shortlistées par concept
    --concept STR              # filtre une seule concept en debug (curate, rerank)
    --dry-run                  # imprime les prompts sans appeler le LLM

État du refactor : TOUTES les 8 phases sont converties et branchées dans
`_execute_phase`. Les anciens scripts qui faisaient l'orchestration en
subprocess ont été archivés vers `_trash/`. Plus aucun subprocess
inter-phase. Plus de timeout artificiel (Phase 4 → Phase 3 = appel Python
direct).

Phases converties :
- ✅ 1.1+1.2 — extract + expand (réécriture complète)
- ✅ 1.2.5 — filter (réécriture complète)
- ✅ 1.2.6 — curate (réécriture complète)
- ✅ 1.3+1.4 — search (réécriture complète)
- ✅ 1.5 — scoring + FK subgraph (HYBRIDE : patche globals de
  `scripts.test_pipeline_v2` + tmpdir, appelle `v2.main()` in-process —
  évite de réécrire 2156 lignes de logique scoring)
- ✅ 2 — rerank LLM (réécriture complète)
- ✅ 3 — generate SQL (HYBRIDE : `scripts.llm_generate_sql.main()`
  in-process avec --no-trigger-phase4 forcé — l'orchestrateur décide)
- ✅ 4 — compose SQL via IR composer Python pur (mode IR — défaut depuis
  todo #7, 2026-05-26) OU mode legacy SQL libre par LLM (DEPRECATED,
  cf. ``phase_4_compose_sql``). PAS de boucle diagnose+retry intégrée
  dans la pipeline elle-même — le mécanisme historique
  ``llm_diagnose_and_retry.main()`` a été archivé dans
  ``_trash/dev_artifacts/old_subprocess_pipeline_2026_05_05/``.

  **Le retry effectif vit côté runtime agent** (cf.
  ``agent_service.py`` + ``sql_error_taxonomy.py``) : le tool
  ``run_pipeline`` génère le SQL, l'agent appelle ``execute_sql``,
  et en cas d'erreur SQL Server, ré-appelle ``run_pipeline`` avec
  hint d'erreur. Cap retry géré par turn budget de l'agent (10+).

  **Reste à faire (todo #8 partiel)** : pour les usages CLI standalone
  de pipeline.py (sans agent), un retry intégré pourrait améliorer la
  convergence sans intervention manuelle. Hors scope MVP — agent
  retry couvre 99% des usages prod.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import json
import logging
import math
import os
import re
import sqlite3
import sys
import textwrap
import time
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Logger module-level. Réutilisé par les phases pour info/warning/exception
# au lieu de l'inline ``logging.getLogger(__name__)`` répété.
logger = logging.getLogger(__name__)

# ── Paths centralisés ────────────────────────────────────────────────

# Chemin du **mirror SQLite local de la BDD source externe**. C'est un
# artefact de DÉVELOPPEMENT uniquement : il permet de tourner les probes
# Phase 3 sans accès au SQL Server live (utile quand on bosse hors VPN
# / hors site client). EN PRODUCTION, ce fichier N'EXISTE PAS — les
# probes vont toutes au SQL Server live via le connecteur. Le nom
# ``sage_copy.db`` est un héritage du 1er client (Sage Coala) ; côté
# code applicatif, on devrait considérer ce fichier comme un dev tool,
# pas comme une promesse fonctionnelle.
#
# Configurable via la variable d'environnement ``KOMPTIA_DB_PATH`` pour
# qu'un dev puisse pointer vers son propre fichier ``.db`` (ex: export
# d'une autre instance Sage pour reproduire un bug). Ne change rien
# en prod (le code mirror n'est jamais activé).
#
# TODO avant prod (cf. task GFP-G5) : retirer le param ``use_sage`` du
# tool ``run_pipeline`` (visible LLM), retirer le code de routing
# mirror vs live (mort en prod), retirer ce fichier.
DEFAULT_DB_PATH = Path(
    os.environ.get(
        "KOMPTIA_DB_PATH",
        str(ROOT / "data" / "sage_copy.db"),
    )
)
# Alias backward-compat pour les callers historiques. À supprimer en même
# temps que le mirror SQLite (cf. TODO ci-dessus, avant prod).
SAGE_DB = DEFAULT_DB_PATH
KOMPTIA_DB = ROOT / "data" / "komptia.db"
OUT_DIR = ROOT / "outputs"
RUN_JSON = OUT_DIR / "run.json"
RUN_SQL = OUT_DIR / "run.sql"
RUN_MD = OUT_DIR / "run.md"
DEBUG_TRACES_DIR = OUT_DIR / "_debug_traces"


@dataclass(frozen=True, slots=True)
class _RunPaths:
    """Chemins effectifs d'un run (override possible via ``output_dir``).

    ``run_pipeline()`` et ``_resolve_run_paths()`` utilisent ce dataclass
    pour propager les chemins de sortie. Quand ``output_dir`` est ``None``
    (cas CLI standalone), les chemins défaut globaux (``RUN_JSON``,
    ``RUN_SQL``, ``RUN_MD``, ``DEBUG_TRACES_DIR``) sont utilisés —
    rétro-compat 100%. Quand ``output_dir`` est fourni (cas runtime
    Komptia / Iris), un dossier dédié héberge les artefacts pour permettre
    le multi-users et l'historique par run.
    """

    output_dir: Path
    run_json: Path
    run_sql: Path
    run_md: Path
    debug_traces: Path


def _resolve_run_paths(output_dir: Path | None) -> _RunPaths:
    """Calcule les chemins effectifs depuis un ``output_dir`` optionnel.

    - ``None`` → chemins globaux (CLI legacy).
    - ``Path`` → un sous-dossier dédié, créé à la demande.
    """

    if output_dir is None:
        return _RunPaths(
            output_dir=OUT_DIR,
            run_json=RUN_JSON,
            run_sql=RUN_SQL,
            run_md=RUN_MD,
            debug_traces=DEBUG_TRACES_DIR,
        )
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    return _RunPaths(
        output_dir=output_dir,
        run_json=output_dir / "run.json",
        run_sql=output_dir / "run.sql",
        run_md=output_dir / "run.md",
        debug_traces=output_dir / "_debug_traces",
    )


# ── Cancel event ContextVar ────────────────────────────────────────
#
# Posé par ``run_pipeline()`` quand un ``cancel_event`` est passé en kwarg
# (mode runtime Iris). Les phases longues (Phase 3 probes parallèles,
# boucle Q/A) appellent ``_check_cancel_or_raise()`` aux points
# d'interruption pour quitter rapidement sans attendre la fin de la
# phase courante.
#
# Mode CLI : pas de cancel_event posé, helper retourne sans rien faire.

import contextvars as _contextvars

_pipeline_cancel_event: _contextvars.ContextVar[asyncio.Event | None] = _contextvars.ContextVar(
    "_pipeline_cancel_event", default=None
)

# Identité de l'utilisateur propriétaire du run (Iris). Posé par
# ``run_pipeline`` et lu par ``call_llm`` / phase_4 pour appliquer la COUCHE 2
# (pseudonymizer user-scoped /data-privacy) sur la phrase NL brute envoyée au
# LLM cloud — sinon un nom de client tapé par l'utilisateur partirait en clair.
# ``None`` en mode CLI standalone (pas d'identité) → couche 1 PII seule (aucune
# régression). Même pattern que ``_pipeline_cancel_event`` (évite de threader
# user_id dans toutes les signatures de phases). Per-task : pas de fuite
# inter-run (chaque run = task asyncio avec son propre contexte).
_pipeline_user_id: _contextvars.ContextVar[int | None] = _contextvars.ContextVar(
    "_pipeline_user_id", default=None
)


def _check_cancel_or_raise() -> None:
    """Lève ``asyncio.CancelledError`` si le cancel_event courant est set.

    À appeler aux points d'interruption (entre 2 probes, entre 2 LLM
    calls parallèles). No-op si pas de cancel_event posé (mode CLI).
    """

    ev = _pipeline_cancel_event.get()
    if ev is not None and ev.is_set():
        raise asyncio.CancelledError("pipeline cancel_event triggered")


# ── Lock cross-coroutine pour Phase 1.5 ────────────────────────────
#
# La Phase 1.5 (``phase_1_5_scoring_fk``) patche des globals module-level
# (SRC, DB, DST_MAIN, DST_ANNEX, _DROPPED_ENTITIES_FILE, _CURATE_DIR) +
# ``sys.argv`` pour réutiliser le code legacy ``_p15_main_legacy()`` inliné
# depuis ``test_pipeline_v2.py``. Sans sérialisation, deux runs simultanés
# (deux users Iris) corrompraient mutuellement leurs résultats.
#
# Solution intermédiaire : un ``asyncio.Lock`` module-level sérialise les
# entrées dans Phase 1.5. Le refactor profond (paramétriser
# ``_p15_main_legacy()``) reste à faire (TODO Lot 4 ultérieur).
_PHASE_1_5_LOCK: asyncio.Lock | None = None


def _get_phase_1_5_lock() -> asyncio.Lock:
    """Retourne le lock Phase 1.5, init lazy (un seul event loop).

    Init lazy car ``asyncio.Lock()`` doit être créé dans un event loop
    actif (sinon ``DeprecationWarning`` Python 3.10+).
    """

    global _PHASE_1_5_LOCK
    if _PHASE_1_5_LOCK is None:
        _PHASE_1_5_LOCK = asyncio.Lock()
    return _PHASE_1_5_LOCK


# =====================================================================
# CONFIG — lecture ai_config (modèle + clé API) depuis la BDD admin
# (anciennement scripts/_pipeline_lib.py — fusionné 2026-05-05)
# =====================================================================


def _read_ai_config_value(key: str) -> str | None:
    """Lit une clé brute depuis `ai_config`. Retourne None si absente."""
    if not KOMPTIA_DB.exists():
        raise SystemExit(f"❌ {KOMPTIA_DB} introuvable")
    conn = sqlite3.connect(str(KOMPTIA_DB))
    try:
        row = conn.execute(
            "SELECT value FROM ai_config WHERE key = ?",
            (key,),
        ).fetchone()
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    raw = row[0]
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw if isinstance(raw, str) else None
    if parsed is None:
        # JSON "null" → None. Sinon caller pense avoir une valeur (le string
        # "null") et tombe dans des erreurs obscures (ex: Fernet InvalidToken
        # sur api_key="null").
        return None
    if isinstance(parsed, str):
        return parsed
    return raw


def get_configured_model() -> str:
    """Retourne le modèle LLM configuré dans `/admin/ai-config`.

    Single source of truth. Fail-fast si la config est absente — refuse
    les fallbacks silencieux qui masquent un état incohérent.
    """
    model = _read_ai_config_value("primary_model")
    if not model:
        raise SystemExit(
            "❌ Aucun modèle configuré dans ai_config.primary_model. "
            "Va sur http://127.0.0.1:8888/admin/ai-config et choisis un modèle."
        )
    return model


def get_api_key() -> str:
    """Retourne la clé API déchiffrée depuis `ai_config.api_key`."""
    raw = _read_ai_config_value("api_key")
    if not raw:
        raise SystemExit("❌ ai_config.api_key absent")
    from app.services.ai.config_service import decrypt_api_key

    return decrypt_api_key(raw)


# =====================================================================
# IO — helpers accent-insensible + parsers de extracted_terms.txt
# =====================================================================


def strip_accents(s: str | None) -> str:
    if not s:
        return ""
    return "".join(c for c in unicodedata.normalize("NFD", s) if not unicodedata.combining(c))


def build_unacc_index(cache_keys) -> dict[str, list[str]]:
    """`unaccented → [original_keys]` index. Tolère collisions."""
    out: dict[str, list[str]] = {}
    for k in cache_keys:
        out.setdefault(strip_accents(k), []).append(k)
    return out


def lookup_cache_keys(search_key: str, unacc_index: dict[str, list[str]]) -> list[str]:
    """Retourne les clés cache matchant search_key accent-insensible."""
    return unacc_index.get(strip_accents(search_key), [])


def parents_match_concept(parents, concept: str) -> bool:
    """`concept ∈ parents` accent-insensible."""
    c_unacc = strip_accents(concept.lower())
    return any(strip_accents(p.lower()) == c_unacc for p in parents)


_LISTO_LINE_RE = re.compile(r"^\s*\d+\.\s+(.+?)\s+\[(extract|expand <- (.+))\]\s*$")
_CONCEPT_HEADER_RE = re.compile(r"^  ([\w' \-éèêëàâîïùûüôœç]+):\s*$")
_TOTAL_LIST_RE = re.compile(r"^    TOTAL \(\d+\): (\[.*\])\s*$")


def parse_user_query(text: str) -> str:
    """Récupère la requête utilisateur depuis `**Requête utilisateur :**`."""
    m = re.search(r"\*\*Requête utilisateur :\*\*\s*\n", text)
    if not m:
        return "(requête introuvable)"
    rest = text[m.end() :]
    lines: list[str] = []
    for ln in rest.splitlines():
        if not ln.strip():
            break
        lines.append(ln.rstrip())
    joined = " ".join(line.strip() for line in lines).strip()
    return joined if joined else "(requête introuvable)"


def parse_concept_values(text: str) -> dict[str, list[str]]:
    """Parse STRUCTURE CONCEPT → VALEURS."""
    result: dict[str, list[str]] = {}
    in_block = False
    for line in text.splitlines():
        if "STRUCTURE CONCEPT → VALEURS" in line:
            in_block = True
            continue
        if not in_block:
            continue
        if not line.strip() or line.startswith("=") or line.startswith("---"):
            if result:
                break
            continue
        stripped = line.strip()
        if " -> " in stripped:
            concept, vals_str = stripped.split(" -> ", 1)
            result[concept.strip()] = [v.strip() for v in vals_str.split(",") if v.strip()]
        else:
            result[stripped] = []
    return result


def parse_derivables(text: str) -> dict[str, list[str]]:
    """Parse STRUCTURE CONCEPT DÉRIVABLES."""
    result: dict[str, list[str]] = {}
    in_block = False
    for line in text.splitlines():
        if "STRUCTURE CONCEPT DÉRIVABLES" in line:
            in_block = True
            continue
        if not in_block:
            continue
        if not line.strip() or line.startswith("=") or line.startswith("---"):
            if result:
                break
            continue
        stripped = line.strip()
        if " <- " not in stripped:
            continue
        concept, sources_str = stripped.split(" <- ", 1)
        result[concept.strip()] = [s.strip() for s in sources_str.split(",") if s.strip()]
    return result


def parse_termes_phase11(text: str) -> list[str]:
    """Parse `TERMES PHASE 1.1 (N) :` (concepts + valeurs + parts)."""
    result: list[str] = []
    in_block = False
    for line in text.splitlines():
        if line.startswith("TERMES PHASE 1.1"):
            in_block = True
            continue
        if not in_block:
            continue
        stripped = line.strip()
        if not stripped:
            if result:
                break
            continue
        if stripped.startswith("- "):
            result.append(stripped[2:].strip())
        elif stripped.startswith("=") or stripped.startswith("---"):
            break
    return result


def parse_extracted_terms_from_recap(text: str) -> dict[str, list[str]]:
    """Parse `RÉCAPITULATIF DES 3 PASSES PAR CONCEPT` → {concept: [TOTAL]}."""
    result: dict[str, list[str]] = {}
    lines = text.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if "RÉCAPITULATIF DES 3 PASSES PAR CONCEPT" in ln:
            start = i
            break
    if start is None:
        return result
    current = None
    for i in range(start, len(lines)):
        ln = lines[i]
        if ln.startswith("=") and i > start + 2:
            break
        m_c = _CONCEPT_HEADER_RE.match(ln)
        if m_c:
            current = m_c.group(1).strip()
            continue
        if current:
            m_t = _TOTAL_LIST_RE.match(ln)
            if m_t:
                try:
                    parsed = ast.literal_eval(m_t.group(1))
                    if isinstance(parsed, list):
                        result[current] = [str(t) for t in parsed]
                except (SyntaxError, ValueError):
                    pass
                current = None
    return result


def parse_listo(text: str) -> tuple[list[str], dict[str, set[str]]]:
    """Parse `LISTO FINALE` → (full_listo, term_origins)."""
    full_listo: list[str] = []
    term_origins: dict[str, set[str]] = {}
    in_block = False
    for ln in text.splitlines():
        if "LISTO FINALE" in ln and "termes" in ln:
            in_block = True
            continue
        if not in_block:
            continue
        if not ln.strip():
            if full_listo:
                break
            continue
        m = _LISTO_LINE_RE.match(ln)
        if not m:
            continue
        term = m.group(1).strip()
        full_listo.append(term)
        kind = m.group(2)
        if kind.startswith("expand"):
            parents = [p.strip() for p in m.group(3).split(",") if p.strip()]
            term_origins[term] = set(parents)
    return full_listo, term_origins


def parse_routing_combo(combo: str) -> set[str]:
    """`[T,V,C,VC,Val]` → {'T','V','C','VC','Val'}."""
    inner = combo.strip().strip("[]")
    return {p.strip() for p in inner.split(",") if p.strip()}


# Dimensions du JSON curate vers les noms internes (aligné avec orchestrator_search.py).
ROUTING_DIM_TO_INTERNAL = {
    "T": "table",
    "V": "view",
    "C": "column",
    "VC": "view_column",
    "Val": "value",
}


def load_curate_routing(curate_dir: Path) -> dict[str, set[str]]:
    """Lit `outputs/llm_curate/<concept>.json` → {concept: {dim_internal}}.

    Fail-explicit : un JSON corrompu ou un mode autre que "routing" est
    skippé AVEC warning stdout. Pas de fail-open silencieux.
    """
    if not curate_dir.exists():
        return {}
    routing: dict[str, set[str]] = {}
    skipped: list[str] = []
    for jf in sorted(curate_dir.glob("*.json")):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            skipped.append(f"{jf.name}: {type(e).__name__}: {e}")
            continue
        mode = data.get("mode")
        if mode != "routing":
            skipped.append(f"{jf.name}: mode={mode!r} (pas de routing)")
            continue
        concept = data.get("concept")
        if not concept:
            skipped.append(f"{jf.name}: champ 'concept' manquant")
            continue
        allowed: set[str] = set()
        for combo, _terms in (data.get("routing") or {}).items():
            for dim_short in parse_routing_combo(combo):
                internal = ROUTING_DIM_TO_INTERNAL.get(dim_short)
                if internal:
                    allowed.add(internal)
        routing[concept] = allowed
    if skipped:
        print(
            f"⚠️  load_curate_routing : {len(skipped)} fichier(s) skippé(s) "
            f"(filtre dim désactivé pour ces concepts) :"
        )
        for s in skipped:
            print(f"     - {s}")
    return routing


# =====================================================================
# LLM — wrapper Anthropic + parsing JSON + slug
# =====================================================================


async def call_llm(
    system: str,
    user: str,
    *,
    model_id: str,
    api_key: str,
    caller: str,
    max_tokens: int = 4000,
    temperature: float = 0.0,
    cache_prefix: str | None = None,
) -> str:
    """Appel LLM. Wrapper minimal — strip()ed.

    Si un ``LLMManager`` global est initialisé (cas runtime Komptia, ex :
    pipeline lancée depuis Iris), on délègue au manager pour respecter le
    provider configuré dynamiquement (cf. CLAUDE.md « Architecture LLM
    dynamique »). Fallback sur ``AnthropicProvider`` direct si le manager
    n'est pas accessible (cas CLI standalone : ``python scripts/pipeline.py``
    sans le serveur Komptia chargé).

    Args:
        system        : system prompt (cache automatique côté provider).
        user          : user prompt — partie variable.
        cache_prefix  : préfixe stable du user prompt à mettre en cache.
        model_id      : ignoré si LLMManager dispo (le manager utilise
                        ``default_model_name`` configuré via /admin/ai-config).
                        Utilisé en mode CLI fallback.
        caller        : nom sémantique de la phase (ex. ``pipeline_p4_compose``)
                        pour attribuer l'appel dans ``AIPerformanceLog.caller``
                        et le faire apparaître sous son nom dans
                        ``/admin/api-usage`` au lieu de ``(non attribué)``.
    """
    from app.utils.request_context import llm_call_context

    # Tentative LLMManager global (runtime Komptia)
    try:
        from app.services.ai.llm_providers import LLMRequest, get_llm_manager

        manager = get_llm_manager()
    except Exception:  # noqa: BLE001
        manager = None

    if manager is not None and getattr(manager, "default_model_name", None):
        try:
            from app.services.ai.llm_providers import LLMRequest

            with llm_call_context(caller=caller):
                resp = await manager.generate(
                    LLMRequest(
                        prompt=user,
                        system=system,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        model=manager.default_model_name,
                        prompt_cache_prefix=cache_prefix,
                        user_id=_pipeline_user_id.get(),
                    )
                )
            return resp.content.strip()
        except Exception:  # noqa: BLE001 — on log et fallback Anthropic direct
            logging.getLogger(__name__).exception(
                "call_llm: LLMManager.generate échoué — fallback AnthropicProvider"
            )

    # Fallback CLI / manager indisponible : Anthropic direct (rétro-compat)
    from app.services.ai.llm_providers import AnthropicProvider, LLMRequest

    provider = AnthropicProvider(api_key=api_key)
    with llm_call_context(caller=caller):
        resp = await provider.generate(
            LLMRequest(
                prompt=user,
                system=system,
                temperature=temperature,
                max_tokens=max_tokens,
                model=model_id,
                prompt_cache_prefix=cache_prefix,
                user_id=_pipeline_user_id.get(),
            )
        )
    return resp.content.strip()


_FENCE_HEAD = re.compile(r"^\s*```(?:json)?\s*\n?")
_FENCE_TAIL = re.compile(r"\n?```\s*$")


def _strip_json_fences(raw: str) -> str:
    cleaned = _FENCE_HEAD.sub("", raw)
    cleaned = _FENCE_TAIL.sub("", cleaned)
    return cleaned


def parse_llm_json(raw: str) -> dict | None:
    """Strip fences + json.loads + isinstance(dict). None si KO (strict)."""
    data, _ = parse_llm_json_with_error(raw)
    return data


def parse_llm_json_with_error(raw: str) -> tuple[dict | None, str | None]:
    """Variante avec message d'erreur. (data, None) ou (None, "raison")."""
    cleaned = _strip_json_fences(raw)
    try:
        parsed = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as e:
        return None, f"JSON parse échoué : {e}"
    if not isinstance(parsed, dict):
        return None, (
            f"JSON parsé mais pas un objet (type={type(parsed).__name__}, "
            f"valeur={parsed!r:.80})"
        )
    return parsed, None


_SLUG_NON_WORD = re.compile(r"[^\w]+")


def slug_from_concept(concept: str) -> str:
    """`code groupe` → `code_groupe`. Accent-sensitive, déterministe.

    NE PAS modifier la formule sans plan de migration des fichiers
    `outputs/llm_*/{slug}.json` existants.
    """
    return _SLUG_NON_WORD.sub("_", concept.lower()).strip("_")


# ── État pipeline transporté entre phases (en mémoire) ───────────────


@dataclass
class PipelineState:
    """Snapshot complet d'un run de pipeline.

    Sérialisé après chaque phase dans `outputs/run.json` pour permettre
    `--resume` après crash. Chaque phase mute UN champ et appelle
    `save()` pour persister. Les phases aval lisent les champs amont
    qu'elles consomment.

    Conventions :
    - Aucun champ n'est obligatoire — None signifie "phase pas encore
      exécutée" (utilisé par `--resume` pour détecter le point de reprise).
    - Les phases ne se passent JAMAIS d'état via fichier — uniquement via
      ce dataclass. Le seul fichier produit est `run.json` (snapshot
      complet) + `run.sql` (résultat final humain) + traces debug
      optionnelles si `debug_traces=True`.
    """

    # Inputs
    query: str = ""
    started_at: float = field(default_factory=time.time)

    # Phase 1.1+1.2 — extract + expand
    extracted: dict | None = None  # {termes, concepts, valeurs, exclusions,
    #  groupes, derivables, full_listo,
    #  term_origins, trace_text}

    # Phase 1.2.4 — concept disambiguation (task #98 REFONTE-L3, 2026-05-22).
    # Détecte par inspection DDL les concepts user matchant N>1 colonnes
    # candidates → ambigus. Pose Q user synchrone amont (intégration Q
    # user via ``pipeline_ask_user_bridge`` à venir dans une PR suivante —
    # pour l'instant, détection seule + log, sans bloquer la pipeline).
    # Format : {ambiguities: [{concept, candidates, hint}, ...],
    #           answers: {concept: chosen_label, ...},
    #           batch_question: str | None, trace_text: str}
    disambiguated: dict | None = None

    # Phase 1.2.5 — filter
    filtered: dict | None = None  # {dropped_tables, dropped_views, qa_session, trace_text}

    # Phase 1.2.6 — curate
    curated: dict | None = None  # {per_concept: {mode, routing, terms, ...}, trace_text}

    # Phase 1.3+1.4 — search
    search: dict | None = None  # {results: {concept: {term: matches}}, search_text}

    # Phase 1.5 — scoring FK
    scored: dict | None = None  # {entities, fk_subgraph, v2_text, v2_annex_text}

    # Phase 2 — rerank LLM
    reranks: dict | None = None  # {per_concept: {ranking_top, rejected_or_low}}

    # Phase 3 — concept fact sheets (parallel, 1 LLM par concept + probes exécutées)
    factsheets: dict | None = (
        None  # {per_concept: {concept: {probes, interpretation, raw_response, ...}},
    )
    #  formatted_block, system_prompt, prompts_per_concept}

    # Phase 4 — SQL composer (1 LLM, fiches → SQL final exécutable)
    sql_final: dict | None = (
        None  # {sql, raw_response, system_prompt, user_prompt, formatted_factsheets}
    )

    # Phase 2.5 (mode=ir) — concept resolution data-driven (utilisée par
    # `phase_4_compose_ir` quand --mode=ir). En mode legacy, reste à None.
    concept_resolution: dict | None = None  # {concept_resolution, trace_text, stats}

    # Final (le SQL réellement exécutable — vient de Phase 4)
    final_sql: str | None = None

    # Telemetry
    phase_durations: dict[str, float] = field(default_factory=dict)

    def save(self, path: Path = RUN_JSON) -> None:
        """Sérialise l'état complet dans run.json (écriture atomique).

        Atomic write via tmp + os.replace : évite que `--resume` lise un
        run.json tronqué si le process est tué en plein write_text() (cas
        observé en pratique : SIGKILL OOM, crash interpréteur). Avant le
        fix, run.json partiel → json.JSONDecodeError au prochain --resume,
        utilisateur bloqué.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_text(
                json.dumps(asdict(self), indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            os.replace(tmp, path)
        except OSError as e:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"PipelineState.save() échoué pour {path} : {e}") from e

    @classmethod
    def load(cls, path: Path = RUN_JSON) -> "PipelineState":
        if not path.exists():
            raise SystemExit(f"❌ {path} introuvable (--resume sans run préalable ?)")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)

    def last_completed_phase(self) -> str | None:
        """Retourne le dernier ID de phase complétée (pour --resume)."""
        last: str | None = None
        for phase_id, attr, _label in PHASES_ORDER:
            if getattr(self, attr) is None:
                break  # première phase non complétée — stop
            last = phase_id
        return last


# Ordre canonique des phases : (id, attribut_state, label).
# tuple immutable au lieu de list — empêche un test ou import malveillant
# de muter l'ordre via PHASES_ORDER.append() (impacterait tous les runs
# suivants dans le même process Python).
PHASES_ORDER: tuple[tuple[str, str, str], ...] = (
    ("1.1-1.2", "extracted", "Phase 1.1+1.2 — Extract + Expand"),
    (
        "1.2.4",
        "disambiguated",
        "Phase 1.2.4 — Concept Disambiguation (détection ambiguïtés DDL)",
    ),
    ("1.2.5", "filtered", "Phase 1.2.5 — Filter entités"),
    ("1.2.6", "curated", "Phase 1.2.6 — Curate routing"),
    ("1.3-1.4", "search", "Phase 1.3+1.4 — Search BDD"),
    ("1.5", "scored", "Phase 1.5 — Scoring + FK subgraph"),
    ("2", "reranks", "Phase 2 — Rerank LLM"),
    ("3", "factsheets", "Phase 3 — Concept Fact Sheets (probes par concept)"),
    ("4", "sql_final", "Phase 4 — SQL Composer (final)"),
)


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.1+1.2 — Extract + Expand termes (✅ converti)
# ─────────────────────────────────────────────────────────────────────


def _parse_extract_pass(raw: str, listo_set: set[str]) -> dict[str, list[str]]:
    """Parse tolérant d'une passe EXPAND (Phase 1.2) : extrait les variantes de
    termes du JSON LLM, en ignorant celles déjà connues (``listo_set``).

    P1 #11(b) — dégradation gracieuse : une passe dont le JSON est malformé (LLM
    tronqué/bavard) ne doit PAS crasher tout l'extract amont. EXPAND est un
    ENRICHISSEMENT (variantes de termes) ; une passe ratée = 0 nouveau terme
    (retourne ``{}``), pas un échec fatal.

    Helper module-level testable (review snapshot 20b8902, finding 5) : avant,
    cette logique était une closure ``_parse_pass`` non-importable, testée
    seulement par grep statique + une réplique ``_tolerant_parse`` susceptible de
    diverger du vrai code."""
    m2 = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
    raw_clean = m2.group(1).strip() if m2 else raw
    try:
        data = json.loads(raw_clean)
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        print(
            f"  ⚠ Phase 1.2 EXPAND : passe ignorée (JSON malformé : "
            f"{type(exc).__name__}) — 0 terme ajouté pour cette passe.",
            flush=True,
        )
        return {}
    if not isinstance(data, dict):
        print(
            "  ⚠ Phase 1.2 EXPAND : passe ignorée (réponse JSON non-objet) "
            "— 0 terme ajouté pour cette passe.",
            flush=True,
        )
        return {}
    result: dict[str, list[str]] = {}
    for concept, variants in data.get("expansions", {}).items():
        if isinstance(variants, list):
            result[concept] = [
                str(v).strip()
                for v in variants
                if v and str(v).strip() and str(v).strip() not in listo_set
            ]
    return result


async def phase_1_1_1_2_extract(
    query: str,
    *,
    model_id: str,
    api_key: str,
    debug_traces: bool = False,
    additional_context: str | None = None,
) -> dict:
    """Phase 1.1 (EXTRACT) + Phase 1.2 (EXPAND, 3 passes chaînées).

    Inputs :
        query : la requête utilisateur en NL.

    Output (dict) :
        - termes        : list[str] — termes Phase 1.1 brute (concepts + valeurs)
        - concepts      : list[str]
        - valeurs       : list[str]
        - exclusions    : list[str]
        - groupes       : dict[str, list[str]] — concept → [valeurs]
        - derivables    : dict[str, list[str]] — concept_dérivé → [concepts source]
        - full_listo    : list[str] — listo complète (Phase 1.1 + expansions)
        - term_origins  : dict[str, list[str]] — terme expansé → [concepts parents]
        - trace_text    : str — trace LLM lisible (équivalent ancien
                          extracted_terms.txt, écrit sur disque seulement
                          si debug_traces=True).

    Préserve le format du fichier `extracted_terms.txt` historique pour
    permettre la migration progressive — les phases aval qui le consomment
    (curate, search) reçoivent `trace_text` dans leur état.

    Lève `RuntimeError` sur échec LLM ou parse JSON KO.
    """
    from app.core.database import init_database

    await init_database()

    from app.services.ai.orchestrator_prompts import (
        PHASE1_EXPAND_TERMS,
        PHASE1_EXPAND_TERMS_REPHRASE,
        PHASE1_EXTRACT_TERMS_V2,
    )

    out: list[str] = []  # buffer pour le trace_text human-readable
    # Liste structurée des appels LLM — exposée dans le dict retourné pour
    # que _render_run_markdown puisse les afficher en sections <details>.
    llm_calls: list[dict] = []
    print(f"→ Modèle LLM : {model_id} (depuis ai_config.primary_model)", flush=True)

    # === PHASE 1.1 — EXTRACT (V2 enrichi : intent, role, polarity, value_kind,
    # inline_lists, derivation_formula). Backward-compatible : émet aussi tous
    # les champs V1 (termes, concepts, valeurs, exclusions, groupes,
    # derivables) que les phases aval consomment. Cf. PHASE1_EXTRACT_TERMS_V2
    # docstring dans orchestrator_prompts.py.
    system1 = (
        "Tu es un expert en extraction de termes de recherche. "
        "Réponds UNIQUEMENT en JSON valide."
    )

    # Injection d'un bloc de contexte temporel métier RETIRÉE le 2026-05-22
    # (task #90). Le bloc supposait une « période de référence » configurable
    # côté admin et présentait un vocabulaire spécifique à un secteur, ce qui
    # biaisait le LLM Phase 1.1 vers un domaine particulier en violation du
    # contrat de généricité Komptia (« toute entreprise utilisant une base
    # SQL Server »). Le LLM dispose déjà de la date du jour via le system
    # prompt de l'agent Iris en amont — il déduit le reste depuis la BDD
    # elle-même (colonnes temporelles + samples).
    prompt1 = (
        PHASE1_EXTRACT_TERMS_V2.replace("{user_query}", query).replace("{{", "{").replace("}}", "}")
    )

    # Task #93 PR3 (2026-05-21) — ADD-only : si Iris a fourni un contexte
    # complémentaire via le tool ``run_pipeline(additional_context=...)``,
    # on l'ajoute en suffixe au user prompt Phase 1.1 sous une section
    # dédiée. Placement EN FIN du prompt (pas au début) pour que la query
    # NL user reste la source de vérité primaire — le contexte additionnel
    # est de l'information complémentaire que Iris a observée via ses tools
    # (search_schema, déjà-vu RAG, etc.), pas une reformulation. Aucune
    # transformation appliquée (passé verbatim, sauf le strip de base).
    _add_ctx = (additional_context or "").strip()
    if _add_ctx:
        prompt1 = (
            prompt1
            + "\n\n# Contexte complémentaire (fourni par l'agent Iris — pas par "
            + "l'utilisateur)\n\n"
            + "Cette section contient des informations que l'agent Iris a observées "
            + "via ses tools (RAG sur historique des conversations validées, "
            + "introspection schéma, etc.) et qu'il juge utiles à ton routage. "
            + "Traite-la comme un INDICE qui complète la query, jamais comme une "
            + "instruction qui la remplace. La query utilisateur ci-dessus reste "
            + "la source de vérité primaire.\n\n"
            + _add_ctx
        )

    out.append("=" * 100)
    out.append("PHASE 1.1 — EXTRACT TERMS")
    out.append("=" * 100)
    out.append("\nSYSTEM MESSAGE :")
    out.append(system1)
    out.append("\nPROMPT :")
    out.append(prompt1)

    t0 = time.time()
    print("→ Phase 1.1: EXTRACT en cours...", flush=True)
    # Budget output : la version V2 demande ~30-40% de tokens en plus que
    # V1 (champs concepts_v2 + values_inline_lists). On passe par
    # `clamped_max_tokens` pour respecter le contrat dynamique CLAUDE.md
    # (« JAMAIS de magic number `max_tokens=<int>` dans une call-site »)
    # et garantir qu'on ne dépasse jamais le cap du modèle cible.
    from app.constants_ai import clamped_max_tokens

    raw1 = await call_llm(
        system1,
        prompt1,
        model_id=model_id,
        api_key=api_key,
        caller="pipeline_p11_extract",
        max_tokens=clamped_max_tokens(5000, model_name=model_id),
    )
    t1 = time.time()
    llm_calls.append(
        {
            "label": "Phase 1.1 — EXTRACT",
            "system_prompt": system1,
            "user_prompt": prompt1,
            "raw_response": raw1,
            "duration_sec": round(t1 - t0, 2),
            "temperature": 0.0,
        }
    )
    out.append(f"\nRÉPONSE BRUTE ({t1 - t0:.1f}s) :")
    out.append(raw1)

    # Parsing : strip markdown fences puis json.loads.
    m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw1, re.DOTALL)
    raw1_cleaned = m.group(1).strip() if m else raw1
    data1 = parse_llm_json(raw1_cleaned)
    if data1 is None:
        # Fallback : tenter un parse direct avec json.loads (parse_llm_json
        # rejette les non-dict comme None — ici on accepte tout dict).
        try:
            data1 = json.loads(raw1_cleaned)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Phase 1.1 — JSON parse échoué : {e}") from e
        if not isinstance(data1, dict):
            raise RuntimeError(
                f"Phase 1.1 — JSON parsé mais pas un dict (type={type(data1).__name__})"
            )

    termes = data1.get("termes", [])
    out.append(f"\nJSON PARSÉ ({len(termes)} termes) :")
    out.append(json.dumps(data1, indent=2, ensure_ascii=False))

    # Compléter `groupes` avec tous les concepts (sécurité si LLM en oublie).
    groupes_llm = data1.get("groupes", {}) or {}
    for c in data1.get("concepts", []):
        if c not in groupes_llm:
            groupes_llm[c] = []
    data1["groupes"] = groupes_llm

    # Concepts DÉRIVABLES — filtrage de robustesse contre hallucinations LLM.
    derivables_llm = data1.get("derivables", {}) or {}
    valid_concepts = set(groupes_llm.keys())
    cleaned: dict[str, list[str]] = {}
    for derived, sources in derivables_llm.items():
        if not isinstance(derived, str) or derived not in valid_concepts:
            continue
        if not isinstance(sources, list):
            continue
        valid_sources = [
            s for s in sources if isinstance(s, str) and s in valid_concepts and s != derived
        ]
        if valid_sources:
            cleaned[derived] = valid_sources
    derivables_llm = cleaned
    data1["derivables"] = derivables_llm

    # === V2 ENRICHED FIELDS — validation + normalisation défensive ===
    # Le prompt V2 demande {intent, concepts_v2, values_inline_lists}. Si le
    # LLM les omet ou produit du contenu invalide, on les **reconstruit**
    # depuis les champs V1 (concepts, groupes, exclusions, derivables) avec
    # des valeurs neutres pour `role`/`polarity`/`value_kind`. Aucune phase
    # aval ne plante : Phase 1.6 (couverture) et Phase 2.5 (resolution future)
    # consomment cette structure normalisée. Les warnings sont loggés pour
    # ajuster le prompt si nécessaire.
    _ROLE_VALUES = {"measure", "filter", "dimension", "temporal", "exclusion", "derivation"}
    _POLARITY_VALUES = {"include", "exclude", "prefer", "avoid"}
    _VALUE_KIND_VALUES = {
        "literal_value",
        "textual_token",
        "numeric_range",
        "identifier_code",
        "free_text",
    }
    _INTENT_VALUES = {"read", "write_create", "write_update", "write_delete", "schema_change"}

    intent_raw = data1.get("intent", "read")
    intent_warnings: list[str] = []
    if intent_raw not in _INTENT_VALUES:
        intent_warnings.append(f"intent='{intent_raw}' non reconnu, fallback='read'")
        intent_raw = "read"
    if intent_raw != "read":
        # L'app est read-only sur la BDD source — refuser tout intent ≠ read.
        # Cette levée est volontaire (cf. design : intent ≠ read = fail-fast,
        # pas de side-effect runtime).
        raise RuntimeError(
            f"Phase 1 — intent='{intent_raw}' refusé. "
            f"L'application est read-only sur la BDD source. "
            f"Reformule la requête en lecture."
        )
    data1["intent"] = intent_raw

    # concepts_v2 — normalisation + reconstruction défensive si absent/invalide.
    concepts_set = set(data1.get("concepts", []) or [])
    exclusions_set = set(data1.get("exclusions", []) or [])
    derivables_set = set(derivables_llm.keys())
    raw_v2 = data1.get("concepts_v2", []) or []
    concepts_v2_clean: list[dict] = []
    seen_v2_names: set[str] = set()
    v2_warnings: list[str] = []

    for entry in raw_v2:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or name not in concepts_set:
            v2_warnings.append(
                f"concepts_v2 entrée ignorée (name absent ou hors `concepts`): {entry!r}"
            )
            continue
        if name in seen_v2_names:
            continue
        role = entry.get("role")
        # `partial_reconstruction` flag : passe à True si l'un des
        # champs (role/polarity/value_kind) est manquant ou invalide
        # côté LLM et qu'on doit le re-deriver depuis V1. Visible côté
        # phases aval pour qu'elles puissent décider si elles veulent
        # se fier à cette entrée ou demander confirmation.
        partial_reconstruction = False
        if role not in _ROLE_VALUES:
            partial_reconstruction = True
            if name in derivables_set:
                role = "derivation"
            elif name in exclusions_set:
                # Adversarial fix #80 BLOCKING 2 — la nouvelle doctrine
                # Phase 1.1 (prompt 2026-05-21) préfère `role="filter" +
                # polarity="exclude"` au déprécié `role="exclusion"`. Le
                # fallback Python aligne sur cette doctrine pour ne pas
                # contredire le prompt. `"exclusion"` reste valide dans
                # `_ROLE_VALUES` pour la rétrocompat des anciens runs.
                role = "filter"
            elif groupes_llm.get(name) or []:
                role = "filter"
            else:
                role = "dimension"
        polarity = entry.get("polarity")
        if polarity not in _POLARITY_VALUES:
            partial_reconstruction = True
            # Cohérence : si l'entrée vient des exclusions V1 (`name in
            # exclusions_set`) OU si le rôle legacy `"exclusion"` était
            # sauvegardé en BDD (vieux runs), forcer `polarity="exclude"`.
            polarity = "exclude" if name in exclusions_set or role == "exclusion" else "include"
        value_kind = entry.get("value_kind")
        if value_kind not in _VALUE_KIND_VALUES:
            partial_reconstruction = True
            value_kind = "literal_value" if (groupes_llm.get(name) or []) else "free_text"
        values = entry.get("values")
        if not isinstance(values, list):
            values = list(groupes_llm.get(name, []))
        else:
            values = [str(v) for v in values if isinstance(v, (str, int, float))]
        derivation_formula = entry.get("derivation_formula")
        if not isinstance(derivation_formula, str):
            derivation_formula = None
        concepts_v2_clean.append(
            {
                "name": name,
                "role": role,
                "polarity": polarity,
                "value_kind": value_kind,
                "values": values,
                "derivation_formula": derivation_formula,
                "_reconstructed": "partial" if partial_reconstruction else None,
            }
        )
        seen_v2_names.add(name)

    # Reconstruction TOTALE : si le LLM a omis un concept entier de
    # `concepts_v2`, on l'ajoute avec des défauts neutres dérivés de
    # V1. **Marqué `_reconstructed: "full"` explicitement** pour que les
    # phases aval (Phase 2.5+) sachent que ce role/polarity/value_kind
    # n'a JAMAIS été validé par un LLM. Cf. adversarial review : un
    # fallback caché violerait le contrat user.
    for c in data1.get("concepts", []) or []:
        if c in seen_v2_names:
            continue
        v2_warnings.append(f"concepts_v2 reconstruit (full) pour concept omis: '{c}'")
        is_excl = c in exclusions_set
        is_deriv = c in derivables_set
        if is_deriv:
            role = "derivation"
        elif is_excl:
            role = "exclusion"
        elif groupes_llm.get(c) or []:
            role = "filter"
        else:
            role = "dimension"
        concepts_v2_clean.append(
            {
                "name": c,
                "role": role,
                "polarity": "exclude" if is_excl else "include",
                "value_kind": "literal_value" if (groupes_llm.get(c) or []) else "free_text",
                "values": list(groupes_llm.get(c, [])),
                "derivation_formula": None,
                "_reconstructed": "full",
            }
        )
    data1["concepts_v2"] = concepts_v2_clean

    # values_inline_lists — normalisation.
    raw_inline = data1.get("values_inline_lists", []) or []
    inline_clean: list[dict] = []
    for entry in raw_inline:
        if not isinstance(entry, dict):
            continue
        cname = entry.get("concept")
        items = entry.get("items")
        if not isinstance(cname, str) or not isinstance(items, list):
            continue
        items_clean = [
            str(i).strip() for i in items if isinstance(i, (str, int, float)) and str(i).strip()
        ]
        # Seuil ≥ 3 conformément au prompt V2.
        if len(items_clean) >= 3:
            inline_clean.append({"concept": cname, "items": items_clean})
    data1["values_inline_lists"] = inline_clean

    # Trace lisible des nouveautés V2 + warnings (si déclenchés).
    out.append(f"\nINTENT (V2) : {intent_raw}")
    if concepts_v2_clean:
        out.append(f"\nCONCEPTS_V2 ({len(concepts_v2_clean)}) :")
        for c2 in concepts_v2_clean:
            extras = []
            if c2["values"]:
                extras.append(f"values={c2['values']}")
            if c2["derivation_formula"]:
                extras.append(f"derivation={c2['derivation_formula']!r}")
            out.append(
                f"  - {c2['name']} | role={c2['role']} polarity={c2['polarity']} "
                f"value_kind={c2['value_kind']}" + (" | " + " | ".join(extras) if extras else "")
            )
    if inline_clean:
        out.append(f"\nVALUES_INLINE_LISTS ({len(inline_clean)}) :")
        for il in inline_clean:
            out.append(
                f"  - {il['concept']} : {len(il['items'])} items "
                f"({', '.join(il['items'][:5])}{'...' if len(il['items']) > 5 else ''})"
            )
    if v2_warnings or intent_warnings:
        out.append(f"\nV2 WARNINGS ({len(v2_warnings) + len(intent_warnings)}) :")
        for w in intent_warnings + v2_warnings:
            out.append(f"  - {w}")

    # Émission EXPLICITE de la liste `termes` Phase 1.1 brute (consommée
    # par les parsers _pipeline_lib.parse_termes_phase11 dans les phases aval
    # qui lisent encore le format texte).
    if termes:
        out.append(f"\nTERMES PHASE 1.1 ({len(termes)}) :")
        for t in termes:
            out.append(f"  - {t}")
    if groupes_llm:
        out.append(f"\nSTRUCTURE CONCEPT → VALEURS ({len(groupes_llm)} concepts) :")
        for concept, values in sorted(groupes_llm.items()):
            if values:
                out.append(f"  {concept} -> {', '.join(values)}")
            else:
                out.append(f"  {concept}")
    if derivables_llm:
        out.append(f"\nSTRUCTURE CONCEPT DÉRIVABLES ({len(derivables_llm)} concepts) :")
        out.append(
            "  (concepts calculables par formule SQL depuis d'autres concepts — "
            "PAS de recherche de table dédiée pour ceux-là)"
        )
        for concept, sources in sorted(derivables_llm.items()):
            out.append(f"  {concept} <- {', '.join(sources)}")
    out.append("")

    # === PHASE 1.2 — EXPAND (3 chained passes) ===
    cat_lines = []
    for cat in ("concepts", "valeurs", "exclusions"):
        items = data1.get(cat, []) or []
        if items:
            cat_lines.append(f"- {cat}: {', '.join(items)}")
    categories_str = "\n".join(cat_lines) if cat_lines else "(non catégorisés)"

    system2 = (
        "Tu es un expert en nommage de bases de données SQL Server. "
        "Réponds UNIQUEMENT en JSON valide."
    )
    base_prompt = (
        PHASE1_EXPAND_TERMS.replace("{user_query}", query)
        .replace("{listo}", "\n".join(sorted(termes)))
        .replace("{categories}", categories_str)
        .replace("{{", "{")
        .replace("}}", "}")
    )
    listo_set = set(termes)

    out.append("=" * 100)
    out.append("PHASE 1.2 — EXPAND TERMS (3 passes chaînées)")
    out.append("=" * 100)
    out.append("\nSYSTEM MESSAGE :")
    out.append(system2)

    async def _do_pass(prompt: str, temp: float) -> str:
        return await call_llm(
            system2,
            prompt,
            model_id=model_id,
            api_key=api_key,
            caller="pipeline_p12_expand",
            max_tokens=3000,
            temperature=temp,
        )

    def _parse_pass(raw: str) -> dict[str, list[str]]:
        # Délègue au helper module-level testable (review snapshot 20b8902,
        # finding 5) : la logique de parse tolérant était une closure
        # non-importable, testée seulement par grep + une réplique divergente.
        return _parse_extract_pass(raw, listo_set)

    def _collect_terms(pass_data: dict[str, list[str]]) -> set[str]:
        terms: set[str] = set()
        for variants in pass_data.values():
            terms.update(variants)
        return terms

    def _format_already_found(accumulated: dict[str, list[str]]) -> str:
        return "\n".join(
            f"  - {concept}: {', '.join(accumulated[concept])}" for concept in sorted(accumulated)
        )

    # PASS 1
    out.append("\n--- PASS 1 (temperature=0.0) ---")
    out.append("\nPROMPT :")
    out.append(base_prompt)
    t_p1 = time.time()
    print("→ Phase 1.2: EXPAND pass 1 (temp=0.0)...", flush=True)
    raw_p1 = await _do_pass(base_prompt, 0.0)
    t_p1e = time.time()
    llm_calls.append(
        {
            "label": "Phase 1.2 — EXPAND pass 1 (literal, temp=0.0)",
            "system_prompt": system2,
            "user_prompt": base_prompt,
            "raw_response": raw_p1,
            "duration_sec": round(t_p1e - t_p1, 2),
            "temperature": 0.0,
        }
    )
    pass1 = _parse_pass(raw_p1)
    pass1_terms = _collect_terms(pass1)
    out.append(f"\nRÉPONSE BRUTE ({t_p1e - t_p1:.1f}s) :")
    out.append(raw_p1)
    out.append(f"\nTERMES PASS 1 ({len(pass1_terms)}) :")
    for concept, variants in sorted(pass1.items()):
        out.append(f"  {concept}: {variants}")

    # PASS 2 — rephrase, temp 0.3
    rephrase_prompt = (
        PHASE1_EXPAND_TERMS_REPHRASE.replace("{user_query}", query)
        .replace("{listo}", "\n".join(sorted(termes)))
        .replace("{categories}", categories_str)
        .replace("{{", "{")
        .replace("}}", "}")
    )
    already_p1 = (
        "\n\n**Termes DÉJÀ trouvés (NE PAS RÉPÉTER) :**\n" f"{_format_already_found(pass1)}"
    )
    out.append("\n--- PASS 2 (temperature=0.3) — ANGLE: REFORMULATION ---")
    out.append("\nPROMPT (différent de pass 1) :")
    out.append(rephrase_prompt + already_p1)
    t_p2 = time.time()
    print(f"→ Phase 1.2: EXPAND pass 2 (temp=0.3, rephrase)... [{t_p1e - t_p1:.1f}s]", flush=True)
    raw_p2 = await _do_pass(rephrase_prompt + already_p1, 0.3)
    t_p2e = time.time()
    llm_calls.append(
        {
            "label": "Phase 1.2 — EXPAND pass 2 (rephrase, temp=0.3)",
            "system_prompt": system2,
            "user_prompt": rephrase_prompt + already_p1,
            "raw_response": raw_p2,
            "duration_sec": round(t_p2e - t_p2, 2),
            "temperature": 0.3,
        }
    )
    pass2 = _parse_pass(raw_p2)
    pass2_terms = _collect_terms(pass2)
    out.append(f"\nRÉPONSE BRUTE ({t_p2e - t_p2:.1f}s) :")
    out.append(raw_p2)
    out.append(f"\nTERMES PASS 2 — NOUVEAUX ({len(pass2_terms)}) :")
    for concept, variants in sorted(pass2.items()):
        out.append(f"  {concept}: {variants}")

    # PASS 3 — innovate, temp 0.6
    accumulated: dict[str, list[str]] = {}
    for p in (pass1, pass2):
        for concept, variants in p.items():
            accumulated.setdefault(concept, []).extend(variants)
    innovate_suffix = (
        "\n\n**IMPORTANT — Voici les termes DÉJÀ trouvés par concept. "
        "NE LES RÉPÈTE PAS. Pour CHAQUE concept, trouve des termes DIFFÉRENTS "
        "que les passes précédentes ont ratés :**\n"
        f"{_format_already_found(accumulated)}"
    )
    out.append("\n--- PASS 3 (temperature=0.6) — INNOVATION sur 1+2 ---")
    out.append("\nSUFFIXE AJOUTÉ :")
    out.append(innovate_suffix)
    t_p3 = time.time()
    print(f"→ Phase 1.2: EXPAND pass 3 (temp=0.6, innovate)... [{t_p2e - t_p2:.1f}s]", flush=True)
    raw_p3 = await _do_pass(base_prompt + innovate_suffix, 0.6)
    t_p3e = time.time()
    llm_calls.append(
        {
            "label": "Phase 1.2 — EXPAND pass 3 (innovate, temp=0.6)",
            "system_prompt": system2,
            "user_prompt": base_prompt + innovate_suffix,
            "raw_response": raw_p3,
            "duration_sec": round(t_p3e - t_p3, 2),
            "temperature": 0.6,
        }
    )
    pass3 = _parse_pass(raw_p3)
    pass3_terms = _collect_terms(pass3)
    t2 = time.time()
    out.append(f"\nRÉPONSE BRUTE ({t_p3e - t_p3:.1f}s) :")
    out.append(raw_p3)
    out.append(f"\nTERMES PASS 3 — NOUVEAUX ({len(pass3_terms)}) :")
    for concept, variants in sorted(pass3.items()):
        out.append(f"  {concept}: {variants}")

    # RÉCAPITULATIF DES 3 PASSES PAR CONCEPT
    out.append(f"\n{'=' * 100}")
    out.append("RÉCAPITULATIF DES 3 PASSES PAR CONCEPT")
    out.append("=" * 100)
    all_concepts: set[str] = set()
    for p in (pass1, pass2, pass3):
        all_concepts.update(p.keys())
    for concept in sorted(all_concepts):
        p1 = pass1.get(concept, [])
        p2 = pass2.get(concept, [])
        p3 = pass3.get(concept, [])
        out.append(f"\n  {concept}:")
        if p1:
            out.append(f"    Pass 1 (temp=0.0): {p1}")
        if p2:
            out.append(f"    Pass 2 (temp=0.3): {p2}")
        if p3:
            out.append(f"    Pass 3 (temp=0.6): {p3}")
        all_for_concept = sorted(set(p1 + p2 + p3))
        out.append(f"    TOTAL ({len(all_for_concept)}): {all_for_concept}")
    out.append("")

    # MERGE term_origins + décomposition des underscores
    term_origins: dict[str, set[str]] = {}
    for pass_data in (pass1, pass2, pass3):
        for concept, variants in pass_data.items():
            for v in variants:
                term_origins.setdefault(v, set()).add(concept)
    to_remove: list[str] = []
    decomposed: dict[str, set[str]] = {}
    for term, parents in term_origins.items():
        if "_" in term:
            to_remove.append(term)
            for part in term.split("_"):
                part = part.strip()
                if part and part not in listo_set:
                    decomposed.setdefault(part, set()).update(parents)
    for term in to_remove:
        del term_origins[term]
    for part, parents in decomposed.items():
        term_origins.setdefault(part, set()).update(parents)
    expanded = set(term_origins.keys())

    out.append(f"{'=' * 100}")
    out.append(
        f"MERGE ({t2 - t_p1:.1f}s) — {len(expanded)} termes uniques, "
        f"{len(to_remove)} underscores décomposés"
    )
    out.append("=" * 100)
    out.append("\nTERMES AVEC ORIGINES :")
    for term in sorted(term_origins.keys()):
        parents = sorted(term_origins[term])
        out.append(f"  {term:<35} <- {', '.join(parents)}")

    full_listo = list(termes)
    for v in sorted(expanded):
        if v not in full_listo:
            full_listo.append(v)

    out.append(f"\nLISTO FINALE — {len(full_listo)} termes :")
    for i, t in enumerate(full_listo, 1):
        if t in term_origins:
            parents = sorted(term_origins[t])
            out.append(f"  {i:>3}. {t:<40} [expand <- {', '.join(parents)}]")
        else:
            out.append(f"  {i:>3}. {t:<40} [extract]")
    out.append("")

    # Construire le dict d'extraction (utilisé en input par Phase 1.6).
    extracted_payload = {
        "termes": termes,
        "concepts": data1.get("concepts", []),
        "valeurs": data1.get("valeurs", []),
        "exclusions": data1.get("exclusions", []),
        "groupes": groupes_llm,
        "derivables": derivables_llm,
        "full_listo": full_listo,
        "term_origins": {k: sorted(v) for k, v in term_origins.items()},
        # === V2 ENRICHED FIELDS (cf. PHASE1_EXTRACT_TERMS_V2) ===
        "intent": data1.get("intent", "read"),
        "concepts_v2": data1.get("concepts_v2", []),
        "values_inline_lists": data1.get("values_inline_lists", []),
    }

    # === Phase 1.6 — couverture tokens NL ===
    # Intégrée à la fin de Phase 1.1+1.2 (et non en phase séparée dans
    # PHASES_ORDER) pour minimiser les changements de checkpoint et
    # rester rétro-compatible avec les `--resume` existants. Son trace
    # est concaténée au trace principal pour apparaître dans run.md.
    coverage = phase_1_6_coverage(query, extracted_payload, debug_traces=debug_traces)
    out.append("")
    out.append(coverage["trace_text"])

    trace_text = "\n".join(out)

    # Trace debug optionnelle (sur disque seulement si demandé).
    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_1_1_1_2_extract.txt").write_text(
            trace_text,
            encoding="utf-8",
        )

    return {
        **extracted_payload,
        "coverage": {
            "tokens_total": coverage["tokens_total"],
            "tokens_covered": coverage["tokens_covered"],
            "tokens_orphans": coverage["tokens_orphans"],
            "coverage_score": coverage["coverage_score"],
            "covered_below_threshold": coverage["covered_below_threshold"],
        },
        "trace_text": trace_text,
        "llm_calls": llm_calls,
    }


def _phase1_empty_concepts_clarification(extracted: dict) -> str | None:
    """P1 #12(a) — Détecte « la requête a du contenu mais Phase 1 n'a extrait
    AUCUN concept exploitable » → message de clarification (sinon None).

    Cas couverts : requête vide/quasi-vide, trop courte/ambiguë, dans une autre
    langue, ou réponse LLM dégénérée renvoyant ``concepts_v2=[]``. Sans cette
    détection, le crash survenait en aval (Phase 2 L~12481 / Phase 3 L~14377 :
    ``RuntimeError`` nu → error_kind=unhandled) au lieu d'une demande de
    reformulation actionnable.

    Heuristique : si ``concepts_v2`` est vide MAIS qu'il y a du signal NL
    (``full_listo`` non vide OU ``coverage.tokens_total`` > 0), c'est une
    extraction ratée sur une vraie requête → on demande à reformuler. Si AUCUN
    signal NL (requête réellement vide), idem (rien à exploiter). Si
    ``concepts_v2`` non vide → None (pas de problème, flux normal).

    Générique : raisonne sur la structure abstraite Phase 1, 0 nom BDD.
    Retourne le texte de clarification (le caller lève
    ``ConceptUnresolvedError`` que le runner mappe en clarification user).
    """
    if not isinstance(extracted, dict):
        return None
    concepts_v2 = extracted.get("concepts_v2") or []
    if concepts_v2:
        return None  # flux normal — au moins un concept extrait.
    full_listo = extracted.get("full_listo") or []
    coverage = extracted.get("coverage") or {}
    tokens_total = coverage.get("tokens_total", 0) if isinstance(coverage, dict) else 0
    orphans = coverage.get("tokens_orphans") or [] if isinstance(coverage, dict) else []
    if full_listo or tokens_total:
        hint = ""
        if orphans:
            hint = " Termes non rattachés : " + ", ".join(str(o) for o in orphans[:8]) + "."
        return (
            "Je n'ai identifié aucun concept exploitable dans votre demande pour "
            "construire une requête.{hint} Pouvez-vous la reformuler en précisant "
            "ce que vous cherchez (quelle donnée, quel critère) ?"
        ).format(hint=hint)
    # Requête réellement vide / sans aucun signal.
    return (
        "Votre demande semble vide ou ne contient aucun élément interprétable. "
        "Pouvez-vous préciser ce que vous souhaitez obtenir ?"
    )


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.6 NEW — Couverture des tokens NL
# ─────────────────────────────────────────────────────────────────────
#
# Vérifie que TOUS les tokens "intéressants" du NL utilisateur (longueur
# ≥ 4 chars, alphanumérique, hors stopwords structurels courts) sont
# couverts par au moins UN champ extrait par Phase 1 (concepts, valeurs,
# exclusions, derivables, values_inline_lists, concepts_v2.values).
#
# **Pourquoi** : transforme les omissions Phase 1 (silencieuses
# aujourd'hui) en signal observable. Si Phase 1 oublie un substantif
# multi-mots du message utilisateur (ex : « <qualificatif> <rôle> »),
# au moins un token apparaîtra orphan → l'utilisateur le voit dans
# run.md et peut adapter le prompt Phase 1.
#
# **Ce que ça n'est PAS** : un blocage. Phase 1.6 émet uniquement un
# warning + score. Pas de fail-fast (cf. user feedback : « le mieux
# c'est de faire en sorte que l'événement pour lequel le blocage a été
# créé n'arrive pas ou presque jamais »). Couverture < 90 % = signal
# que le prompt Phase 1 doit être amélioré, pas que le run doit casser.
#
# **Generic** : aucun pattern lexical hardcodé, aucune stoplist
# hardcodée FR ou EN. La filtration ≥ 4 chars est universelle (élimine
# la quasi-totalité des prépositions/déterminants courants dans toutes
# les langues européennes : « le », « la », « du », « and », « or »,
# « of », « in », « für », « die »). Token avec digits = on garde
# (codes, années, identifiants).
#
# **Tokenization** : on **strip les accents** côté tokens NL ET côté
# haystack pour éviter les faux orphans (« facturé » contient
# « facture » mais ne match pas si on garde les accents). C'est
# une normalisation Unicode standard (NFKD + filter Mn), pas un
# heuristique langue-spécifique.


def _strip_accents_lower(text: str) -> str:
    """Normalise un texte : casse minuscule + accents supprimés (NFKD).

    Ex : ``"Forfaité"`` → ``"forfaite"``. Universel, agnostique de la
    langue (utilise la base Unicode officielle).
    """
    nfkd = unicodedata.normalize("NFKD", str(text or ""))
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


# Regex Unicode-aware : ``\w`` en Python 3 matche par défaut tous les
# caractères de mots Unicode (latin, cyrillique, CJK, arabe, devanagari,
# etc.). Indispensable pour la généricité multi-langues.
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize_nl(query: str, *, min_len: int = 4) -> list[str]:
    """Découpe une query NL en tokens "intéressants".

    - Découpe sur tout sauf alphanumérique + ``_``.
    - Strip accents + lowercase.
    - Garde les tokens de longueur ≥ ``min_len`` (défaut 4 chars).
    - Dédoublonne en préservant l'ordre d'apparition.

    Le seuil de 4 chars élimine la majorité des stopwords structurels
    multi-langues (FR : « le », « du », « et », « ou », « pour » →
    écarté ; EN : « the », « and », « of », « in » → écarté), sans
    nécessiter de stoplist hardcodée par langue.
    """
    norm = _strip_accents_lower(query)
    seen: set[str] = set()
    out: list[str] = []
    for match in _TOKEN_RE.finditer(norm):
        tok = match.group(0)
        if len(tok) < min_len or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
    return out


def _build_coverage_haystack(extracted: dict) -> set[str]:
    """Construit le **set de tokens** extraits par Phase 1 (haystack normalisé).

    Sources concaténées :
        - ``termes`` (Phase 1.1)
        - ``concepts``, ``valeurs``, ``exclusions``
        - ``groupes`` (clés ET valeurs)
        - ``derivables`` (clés ET sources)
        - ``concepts_v2[].name``, ``[].values``, ``[].derivation_formula``
        - ``values_inline_lists[].concept``, ``[].items``
        - ``full_listo`` (expansions LLM Phase 1.2)

    Chaque chaîne est tokenisée avec la MÊME regex que `_tokenize_nl`
    (Unicode-aware, longueur ≥ ``min_len``) puis strippée d'accents.
    On retourne un **set** pour le match O(1) côté `phase_1_6_coverage`.

    **Pourquoi tokens-set et non concaténation** : la concat ouvre la
    porte aux faux positifs substring (token NL ``"cap"`` matchait
    accidentellement le haystack ``"capital"``). Le set match exige
    que le token soit présent **identiquement** comme un token extrait,
    ce qui élimine ces collisions.

    **Important** : le coût pour le caller est un cap inférieur sur
    ``min_len`` cohérent entre `_tokenize_nl` et ce builder — on
    tokenise le haystack avec ``min_len=2`` pour préserver les codes
    courts (ex : ``"T3"``, ``"FN"``) qu'on veut pouvoir matcher si
    l'utilisateur les utilise. La filtration ``min_len ≥ 4`` côté NL
    reste le filtre principal.
    """
    parts: list[str] = []
    parts.extend(str(t) for t in extracted.get("termes", []) or [])
    parts.extend(str(t) for t in extracted.get("full_listo", []) or [])
    parts.extend(str(c) for c in extracted.get("concepts", []) or [])
    parts.extend(str(v) for v in extracted.get("valeurs", []) or [])
    parts.extend(str(e) for e in extracted.get("exclusions", []) or [])
    for k, vs in (extracted.get("groupes", {}) or {}).items():
        parts.append(str(k))
        parts.extend(str(v) for v in vs or [])
    for k, srcs in (extracted.get("derivables", {}) or {}).items():
        parts.append(str(k))
        parts.extend(str(s) for s in srcs or [])
    for c2 in extracted.get("concepts_v2", []) or []:
        if not isinstance(c2, dict):
            continue
        parts.append(str(c2.get("name", "")))
        parts.extend(str(v) for v in c2.get("values", []) or [])
        df = c2.get("derivation_formula")
        if df:
            parts.append(str(df))
    for il in extracted.get("values_inline_lists", []) or []:
        if not isinstance(il, dict):
            continue
        parts.append(str(il.get("concept", "")))
        parts.extend(str(v) for v in il.get("items", []) or [])
    # Tokenisation finale : agrégation + tokenize unifié.
    aggregated = _strip_accents_lower(" ".join(parts))
    return {m.group(0) for m in _TOKEN_RE.finditer(aggregated) if len(m.group(0)) >= 2}


def phase_1_6_coverage(
    query: str,
    extracted: dict,
    *,
    coverage_warn_threshold: float = 0.7,
    debug_traces: bool = False,
) -> dict:
    """Phase 1.6 — Vérifie la couverture des tokens NL par les extractions Phase 1.

    Output (dict) :
        - tokens_total          : int
        - tokens_covered        : int
        - tokens_orphans        : list[str] — tokens NL non couverts
        - coverage_score        : float in [0, 1]
        - covered_below_threshold : bool — True si score < `coverage_warn_threshold`
        - trace_text            : str — synthèse lisible

    Le seuil `coverage_warn_threshold` (défaut 0.7) sert UNIQUEMENT à
    classer le run dans le trace_text — la fonction ne lève AUCUNE
    exception. Le user voit le warning dans `run.md` et peut adapter le
    prompt Phase 1.

    **Pourquoi 0.7 et non 0.9** : avec un filtre longueur ≥ 4 chars, les
    queries NL réelles laissent typiquement passer 15-25% de stopwords
    structurels (verbes courants : « veux », « entre », « pour »,
    « avec »). Un seuil 0.9 alerterait à chaque run sans valeur
    informative. 0.7 ne se déclenche que sur de **vrais** oublis Phase 1.
    Phase b améliorera la précision en utilisant le schéma BDD comme
    corpus IDF (mot absent du schéma → probablement stopword).

    **Generic** : zéro pattern lexical, zéro stoplist langue-spécifique.
    Tokenization basée sur regex alphanumérique + filtre longueur ≥ 4.
    """
    tokens = _tokenize_nl(query)
    haystack_tokens = _build_coverage_haystack(extracted)

    orphans: list[str] = []
    covered: list[str] = []
    for tok in tokens:
        # Match **token-level** (set lookup O(1)) — pas substring.
        # Substring match induisait des faux positifs cross-frontières
        # (« cap » matchait « capital »). Le LLM Phase 1 doit produire
        # les sous-mots décomposés (RÈGLE 1 du prompt V2 : « expressions
        # composées : garde l'expression complète ET chaque mot séparément »),
        # donc « livraison » sera dans haystack_tokens si « date de livraison »
        # est extrait. Si le LLM n'a pas décomposé → vrai signal d'omission
        # à corriger côté prompt, pas à masquer ici.
        if tok in haystack_tokens:
            covered.append(tok)
        else:
            orphans.append(tok)

    score = (len(covered) / len(tokens)) if tokens else 1.0
    below = score < coverage_warn_threshold

    out: list[str] = []
    out.append("=" * 100)
    out.append("PHASE 1.6 — COUVERTURE TOKENS NL")
    out.append("=" * 100)
    out.append(f"\nTokens NL extraits (≥4 chars, normalisés) : {len(tokens)}")
    out.append(f"Tokens couverts par Phase 1 : {len(covered)}")
    out.append(f"Tokens orphelins : {len(orphans)}")
    out.append(f"Coverage score : {score:.2%}")
    if below:
        out.append(
            f"\n⚠️  Couverture < {coverage_warn_threshold:.0%} — Phase 1 a probablement "
            f"omis des concepts. Tokens orphelins ci-dessous indiquent quelle info "
            f"du NL n'a pas été extraite. Améliorer le prompt Phase 1 ou enrichir le "
            f"NL utilisateur."
        )
    if orphans:
        out.append(f"\nORPHELINS ({len(orphans)}) :")
        for tok in orphans:
            out.append(f"  - {tok}")
    if covered:
        out.append(f"\nCOUVERTS ({len(covered)}) — pour info :")
        out.append("  " + ", ".join(covered))
    out.append("")

    trace_text = "\n".join(out)
    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_1_6_coverage.txt").write_text(
            trace_text,
            encoding="utf-8",
        )

    return {
        "tokens_total": len(tokens),
        "tokens_covered": len(covered),
        "tokens_orphans": orphans,
        "coverage_score": score,
        "covered_below_threshold": below,
        "trace_text": trace_text,
    }


# ─────────────────────────────────────────────────────────────────────
# PHASE 2.5 NEW — Concept Resolution (data-driven, 0 LLM call)
# ─────────────────────────────────────────────────────────────────────
#
# Pour chaque concept émis par Phase 1 V2 (avec son `value_kind` typé),
# trouve la (table, col) canonique en interrogeant `komptia.db.value_mapping`
# (29M rows, 221 tables, 3006 colonnes — samples distincts pré-syncés).
#
# **Pourquoi data-driven sans probe Sage** : la table `value_mapping` est
# déjà construite par le sync Sage→komptia, indexée sur `real_value_lower`.
# Une query sub-seconde nous donne pour n'importe quel token NL la liste
# des (table, col) où il existe et leur cardinalité. Pas besoin de probe
# supplémentaire sur Sage — on évite : (a) les coûts réseau, (b) le
# semaphore Sage partagé avec l'app, (c) tout risque d'injection (ce sont
# des SQLite local queries paramétrées pyodbc-style).
#
# **Pourquoi 0 LLM call** : la doctrine Komptia/Gladys (« le système
# orchestre, le LLM ne devine rien »). Phase 2.5 est purement déterministe :
# mêmes inputs → mêmes outputs. Le LLM Phase 4 (futur) verra le résultat
# de cette résolution dans son prompt et n'aura plus à inventer la mapping
# concept→col.
#
# **Generic** : zéro pattern lexical (`*Millesime`, `*Libelle`), zéro
# stoplist FR/EN, zéro hardcode Sage/Coala. Marche sur n'importe quelle
# BDD SQL Server connectée à komptia (le sync alimente value_mapping
# avec ce qu'il trouve, le matching opère dessus).
#
# **Output** :
#     concept_resolution = {
#         concept_name: {
#             "top_candidates": [
#                 {"table", "col", "evidence_score", "evidence_method",
#                  "n_rows_matching", "n_distinct", "value_type", "samples"},
#                 ...
#             ],
#             "best": {table, col} | None,
#             "ambiguous": bool,            # gap top1-top2 < 15%
#             "score_gap_pct": float,
#             "fallback_used": bool,        # True si name-match (pas de value match)
#         },
#         ...
#     }


_VM_LIKE_ESCAPE = "\\"

# Whitelist `value_type` reconnu par le sync Sage→komptia. Centralisé ici
# pour éviter les hardcodes en aval. Si une autre BDD source utilise des
# value_types différents (ex: en majuscules, ou autres labels), le sync
# doit les aligner sur cette whitelist OU cette constante doit être
# étendue. Cf. `app/services/anonymization/strategies.py` qui produit
# ces labels.
_VM_TEXTUAL_VALUE_TYPES: tuple[str, ...] = ("text", "code")
_VM_NUMERIC_VALUE_TYPES: tuple[str, ...] = ("number", "date")

# Magic numbers Phase 2.5 — hissés en constantes documentées (cf.
# adversarial review). Modifications doivent être justifiées par un test.
_VM_MAX_DISTINCT_FOR_TEMPORAL: int = 200  # 100 ans × millésimes+calendrier
_VM_MIN_NAME_SCORE: float = 0.15  # name match floor (au-dessus)
_VM_AMBIGUITY_GAP_PCT: float = 15.0  # gap top1-top2 < x% → ambigu
_VM_MAX_TOKEN_LEN: int = 200  # cohérent avec value_mapping.real_value VARCHAR(200)

# T29★ — Confiance Phase 2.5 (multi-candidate par défaut quand basse).
# Le rerank LLM Phase 2 a un biais lexical (mots qui matchent une FK numérique
# alors qu'une colonne text-FvEx est sémantiquement meilleure). On ne fait pas
# confiance aveuglément à top-1 : si la confiance est basse, on expose top-N
# en aval (préflight Phase 4, agent IA via T3a). Cf. log 2026-05-10 où
# `dosCabinetEntite` (FK num) a été choisi pour valeur user "DOSSIER_A PAP"
# alors que `dosNomDossier` (text) était dans top-3.
_PHASE_2_5_LOW_CONFIDENCE_THRESHOLD: float = 60.0  # confidence_score < x → low_confidence
_PHASE_2_5_MAX_TOP_CANDIDATES_LOW_CONF: int = 5  # cap top_candidates étendu si low conf
_PHASE_2_5_TYPE_MISMATCH_PENALTY: float = 25.0  # top-1 value_type ≠ expected_type
_PHASE_2_5_AMBIGUITY_PENALTY: float = 30.0  # 2+ compat sur tables différentes OU ties
_PHASE_2_5_TOP1_INCOMPATIBLE_PENALTY: float = 60.0  # top-1 _compat=False (dégradé)

# F5 (task #81) — pénalité role-based pour identifier-of-record (PK/FK).
# Une FK numérique (ex: `proNoEnregMis`) porte ZÉRO sémantique métier — c'est
# juste un join key. Mais le rerank Phase 2 a un biais qui la choisit pour
# un concept `temporal` (« année ») parce que `value_type=number` matche
# les valeurs user `'2023'/'2024'`. On déprioriste donc programmatiquement
# les colonnes détectées PK/FK (via PRAGMA, 100 % générique — pas de regex
# de convention de nommage Sage) pour les concepts dont le role n'est PAS
# `dimension` ni `filter` (qui peuvent légitimement filtrer sur une FK).
# Détection PK/FK via `_phase_2_5_is_primary_key` / `_phase_2_5_is_foreign_key`
# (PRAGMA table_info / foreign_key_list, indépendant de la convention BDD).
_PHASE_2_5_IDENTIFIER_OF_RECORD_PENALTY_MULTIPLIER: float = 0.3  # 70% penalty
_PHASE_2_5_ROLES_TOLERATING_IDENTIFIER: frozenset[str] = frozenset(
    {"dimension", "filter", "unknown"}
)

# T29★ — Phase 4 préflight : cap nombre de probes oracle par concept en
# disambiguation. Probes Sage coûteuses → budget borné (cf. T2 + T24).
_PHASE_4_MAX_DISAMBIGUATION_PROBES_PER_CONCEPT: int = 3

# Regex de validation année/mois/date ISO 8601 (anti-density-score-dégénéré).
# Utilisé par `_vm_search_temporal_years` pour rejeter les requested_values
# qui ne ressemblent à rien de temporel.
import re as _re_temporal_validation

_TEMPORAL_VALUE_RE = _re_temporal_validation.compile(
    # Accepte : YYYY, YYYY-MM, YYYY-MM-DD, YYYY-MM-DD HH:MM:SS,
    # YYYY-MM-DD'T'HH:MM:SS, YYYY-MM-DD'T'HH:MM:SS'Z' (ISO 8601 étendu).
    # Élargi pour supporter les datetimes T-SQL (proDate, facDate, etc.).
    r"^(?:\d{4}"
    r"|\d{4}-\d{2}"
    r"|\d{4}-\d{2}-\d{2}"
    r"|\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?"
    r")$"
)


def _vm_sanitize_token(token: str) -> str:
    """Échappe un token pour usage dans un LIKE param-bindé pyodbc-style.

    - Refuse caractères de contrôle ``[\\x00-\\x1f]`` et quotes ``'`` (ValueError).
    - Échappe les wildcards LIKE : ``\\``, ``%``, ``_`` → préfixe ``\\``.

    Le caller utilise ensuite ``... LIKE ? ESCAPE '\\'`` avec le param bindé.
    Aucune interpolation directe — anti-injection by design.
    """
    if not isinstance(token, str):
        raise ValueError(f"_vm_sanitize_token: token must be str, got {type(token).__name__}")
    if len(token) > _VM_MAX_TOKEN_LEN:
        # Cap dur cohérent avec ``VARCHAR(200)`` du modèle ; protège aussi
        # contre les DoS LIKE %hugepattern%.
        raise ValueError(f"_vm_sanitize_token: token length {len(token)} > {_VM_MAX_TOKEN_LEN}")
    for ch in token:
        # Tous les caractères Unicode catégories C (controls/format/surrogate)
        # sont refusés — couvre CRLF, NUL, U+2028/2029, format chars, etc.
        # Generic multi-langues (catégorie Unicode standard).
        if unicodedata.category(ch).startswith("C"):
            raise ValueError(f"_vm_sanitize_token: control char in token: {token!r}")
    # Quote simple : pas autorisée dans le NL côté pipeline (anti-injection
    # défensive même avec param bindé — par convention, on refuse).
    if "'" in token:
        raise ValueError(f"_vm_sanitize_token: quote in token: {token!r}")
    # Échapper wildcards LIKE.
    out = token.replace(_VM_LIKE_ESCAPE, _VM_LIKE_ESCAPE * 2)
    out = out.replace("%", _VM_LIKE_ESCAPE + "%")
    out = out.replace("_", _VM_LIKE_ESCAPE + "_")
    return out


def _vm_search_literal(
    con,
    value: str,
    *,
    candidate_tables: set[str] | None = None,
    limit: int = 50,
) -> list[dict]:
    """Trouve (table, col) où ``real_value_lower = ?`` exact (case-insensitive).

    Output : list[{table, col, n_rows, value_type, samples}].
    Trié par n_rows DESC. Filtré par ``candidate_tables`` si fourni.
    """
    rows = con.execute(
        "SELECT table_name, column_name, COUNT(*) AS n_rows, "
        "       MAX(value_type) AS value_type "
        "FROM value_mapping "
        "WHERE real_value_lower = ? "
        "GROUP BY table_name, column_name "
        "ORDER BY n_rows DESC "
        "LIMIT ?",
        (value.lower(), limit),
    ).fetchall()
    out = []
    for tbl, col, n_rows, vtype in rows:
        if candidate_tables and tbl not in candidate_tables:
            continue
        out.append(
            {
                "table": tbl,
                "col": col,
                "n_rows": n_rows,
                "value_type": vtype,
                "samples": [value],
            }
        )
    return out


def _vm_search_token(
    con,
    token: str,
    *,
    candidate_tables: set[str] | None = None,
    limit: int = 50,
    value_types: tuple[str, ...] = _VM_TEXTUAL_VALUE_TYPES,
) -> list[dict]:
    """Trouve (table, col) où ``real_value_lower LIKE '%token%'``.

    Token sanitisé via `_vm_sanitize_token`. Param-bindé. Restreint par
    défaut à ``value_type IN ('text', 'code')`` — les colonnes numériques
    sont rarement des textual_token.
    """
    # Lowercase **avant** sanitize : la colonne ``real_value_lower`` est
    # déjà lowercase via Python ``str.lower()`` (Unicode-aware côté sync).
    # Si on laisse le token en CamelCase ou en cyrillique majuscule, le
    # LIKE SQLite ne fait QUE l'ASCII case-folding (les caractères Unicode
    # non-ASCII restent case-sensitive) → faux négatifs sur multi-langues.
    safe_pattern = f"%{_vm_sanitize_token(token.lower())}%"
    placeholders = ",".join("?" * len(value_types))
    sql = (
        "SELECT table_name, column_name, COUNT(*) AS n_rows, "
        "       COUNT(DISTINCT real_value) AS n_distinct, "
        "       MAX(value_type) AS value_type "
        "FROM value_mapping "
        f"WHERE real_value_lower LIKE ? ESCAPE '{_VM_LIKE_ESCAPE}' "
        f"  AND value_type IN ({placeholders}) "
        "GROUP BY table_name, column_name "
        "ORDER BY n_rows DESC "
        "LIMIT ?"
    )
    rows = con.execute(sql, (safe_pattern, *value_types, limit)).fetchall()
    out = []
    for tbl, col, n_rows, n_dist, vtype in rows:
        if candidate_tables and tbl not in candidate_tables:
            continue
        # Récupère 3 samples illustratifs (utilise le pattern lowercased
        # déjà calculé pour le LIKE SQL — cohérent avec la query principale).
        sample_rows = con.execute(
            "SELECT DISTINCT real_value FROM value_mapping "
            "WHERE table_name=? AND column_name=? "
            f"  AND real_value_lower LIKE ? ESCAPE '{_VM_LIKE_ESCAPE}' "
            "LIMIT 3",
            (tbl, col, safe_pattern),
        ).fetchall()
        samples = [r[0] for r in sample_rows]
        out.append(
            {
                "table": tbl,
                "col": col,
                "n_rows": n_rows,
                "n_distinct": n_dist,
                "value_type": vtype,
                "samples": samples,
            }
        )
    return out


def _vm_search_temporal_years(
    con,
    requested_years: list[str],
    *,
    candidate_tables: set[str] | None = None,
    limit: int = 30,
    max_distinct_for_temporal: int = _VM_MAX_DISTINCT_FOR_TEMPORAL,
) -> list[dict]:
    """Trouve (table, col) où ≥1 valeur demandée est présente ET la cardinalité
    distincte est **bornée** (entre 2 et ``max_distinct_for_temporal``).

    Pourquoi la borne haute : sans elle, les colonnes ID auto-incrément
    (qui contiennent par hasard 2023, 2024 parmi des millions de valeurs)
    sont matchées comme « temporelles ». La borne 200 = 100 ans × 2
    (millésimes + années calendaires) couvre tous les cas légitimes.

    **Pas de pattern lexical** (ex : ``*Millesime``, ``*Year``). Pure
    data-driven : on lit la cardinalité réelle de chaque colonne et on
    rejette celles trop denses pour être temporelles.

    Score = ``n_match_requested / n_distinct_total`` — proportion des
    valeurs distinctes qui matchent les années NL. Une vraie colonne
    millésime aura un score élevé (ex : 2/8 = 0.25 pour 2 années sur 8
    millésimes connus). Une colonne ID avec 2/1000000 ≈ 0 sera reléguée.
    """
    if not requested_years:
        return []
    # Validation format ISO 8601 (année / mois / date complète). Rejette
    # les valeurs absurdes qui pourraient gonfler le density_score :
    # `["2","3"]` (codes courts), `["actif","inactif"]` (booléens),
    # `["abc","xyz"]` (textuel), etc. Tout ce qui ne ressemble pas à du
    # temporel ISO est ignoré ici → cohérent avec le contrat « concept
    # temporel = valeurs temporelles ».
    valid_temporal = [
        v for v in requested_years if isinstance(v, str) and _TEMPORAL_VALUE_RE.match(v)
    ]
    if not valid_temporal:
        return []
    # SQLite ``SQLITE_MAX_VARIABLE_NUMBER`` = 999 par défaut depuis 3.32.
    # On cap à 500 pour rester sous le seuil avec une marge confortable.
    if len(valid_temporal) > 500:
        valid_temporal = valid_temporal[:500]
    # Lowercase pour matcher real_value_lower (cohérent avec
    # `_vm_search_literal`) — Phase 2 normalise tous les real_value en
    # lowercase via Python str.lower() (Unicode-aware).
    lowered = [v.lower() for v in valid_temporal]
    placeholders = ",".join("?" * len(lowered))
    rows = con.execute(
        "SELECT table_name, column_name, COUNT(*) AS n_rows_match, "
        "       (SELECT COUNT(DISTINCT real_value) FROM value_mapping vm2 "
        "        WHERE vm2.table_name=v.table_name AND vm2.column_name=v.column_name) AS n_distinct, "
        "       MAX(value_type) AS value_type "
        "FROM value_mapping v "
        f"WHERE real_value_lower IN ({placeholders}) "
        "GROUP BY table_name, column_name "
        "HAVING n_distinct BETWEEN 2 AND ? "
        "ORDER BY (CAST(COUNT(*) AS FLOAT) / n_distinct) DESC "
        "LIMIT ?",
        (*lowered, int(max_distinct_for_temporal), limit),
    ).fetchall()
    out = []
    for tbl, col, n_match, n_dist, vtype in rows:
        if candidate_tables and tbl not in candidate_tables:
            continue
        density_score = round(n_match / max(1, n_dist), 4)
        out.append(
            {
                "table": tbl,
                "col": col,
                "n_rows": n_match,
                "n_distinct": n_dist,
                "value_type": vtype,
                "samples": list(requested_years),
                "density_score": density_score,
            }
        )
    return out


def _name_match_score(concept_name: str, expansions: list[str], col_name: str) -> float:
    """Score similarité nom_colonne ↔ {concept_name, expansions Phase 1.2}.

    100% générique : substring match après strip-accents+lowercase.
    Pas de stoplist langue-spécifique. Score = (needles trouvées / |needles|).

    **Substring vs token-level** : on choisit substring dans la string
    normalisée du nom de colonne (pas set-intersection sur les tokens),
    parce que les conventions BDD usuelles (camelCase ``proPrixVenteTotal``,
    snake_case ``customer_id``, PascalCase ``CustomerID``) collent les
    composants sans séparateur fiable. Un set-intersection sur les
    "tokens" tronquerait massivement les matches légitimes. Le risque de
    faux positif (« cap » dans « capital ») est borné car le score
    fait la moyenne sur N needles (concept_name + expansions Phase 1.2).
    """
    norm_col = _strip_accents_lower(col_name)
    needles_raw = [concept_name] + (expansions or [])
    needles_tokens: set[str] = set()
    for n in needles_raw:
        for tok in _TOKEN_RE.findall(_strip_accents_lower(n)):
            if len(tok) >= 3:
                needles_tokens.add(tok)
    if not needles_tokens:
        return 0.0
    matches = sum(1 for tok in needles_tokens if tok in norm_col)
    return matches / len(needles_tokens)


def _vm_search_by_name_match(
    con,
    concept_name: str,
    expansions: list[str],
    *,
    candidate_tables: set[str] | None = None,
    min_name_score: float = _VM_MIN_NAME_SCORE,
    limit: int = 30,
) -> list[dict]:
    """Trouve (table, col) où le nom de la colonne matche les expansions.

    Pour les concepts sans valeur (free_text, measure abstraite). Iter
    ALL distinct (table, col) de value_mapping et scorer par name match.
    Cap à ``limit``.
    """
    rows = con.execute(
        "SELECT DISTINCT table_name, column_name, MAX(value_type) AS value_type "
        "FROM value_mapping GROUP BY table_name, column_name"
    ).fetchall()
    scored: list[tuple[float, str, str, str]] = []
    for tbl, col, vtype in rows:
        if candidate_tables and tbl not in candidate_tables:
            continue
        s = _name_match_score(concept_name, expansions, col)
        if s >= min_name_score:
            scored.append((s, tbl, col, vtype))
    scored.sort(key=lambda x: -x[0])
    return [
        {"table": tbl, "col": col, "name_score": round(s, 3), "value_type": vtype, "samples": []}
        for s, tbl, col, vtype in scored[:limit]
    ]


def _resolve_concept(
    con,
    concept_v2: dict,
    expansions_per_concept: dict[str, list[str]],
    *,
    candidate_tables: set[str] | None = None,
) -> dict:
    """Résout UN concept_v2 → top candidates par méthode adaptée à value_kind.

    Méthodes (mutuellement exclusives, pas de fallback caché) :
        - literal_value / identifier_code → _vm_search_literal sur values
        - textual_token                   → _vm_search_token sur values
        - temporal                        → _vm_search_temporal_years (years NL)
        - free_text / numeric_range / autre → _vm_search_by_name_match
    """
    name = concept_v2.get("name", "")
    role = concept_v2.get("role", "dimension")
    value_kind = concept_v2.get("value_kind", "free_text")
    values = list(concept_v2.get("values", []) or [])
    expansions = expansions_per_concept.get(name, [])

    method = ""
    aggregated: dict[tuple, dict] = {}  # (table, col) → row

    # Détermine la méthode de matching attendue **avant** d'agir, pour
    # pouvoir distinguer (a) une absence de valeurs requises (= bug
    # Phase 1 ou concept user-side) de (b) un cas où on tombe naturellement
    # en name_match (free_text). Anti-fallback-caché.
    expects_values_branch = role == "temporal" or value_kind in (
        "literal_value",
        "identifier_code",
        "textual_token",
    )
    fallback_used = False

    try:
        if role == "temporal":
            if not values:
                return {
                    "top_candidates": [],
                    "best": None,
                    "ambiguous": False,
                    "score_gap_pct": 0.0,
                    "fallback_used": False,
                    "method": "temporal_no_values",
                    "error": (
                        "concept temporal sans values — Phase 1 a omis les valeurs "
                        "temporelles attendues, ou le NL ne mentionne pas d'année/date. "
                        "Pas de fallback name-match (anti-faux-positif)."
                    ),
                }
            method = "temporal"
            year_values = [v for v in values if isinstance(v, str) and v.strip()]
            for cand in _vm_search_temporal_years(
                con,
                year_values,
                candidate_tables=candidate_tables,
            ):
                aggregated[(cand["table"], cand["col"])] = cand
        elif value_kind in ("literal_value", "identifier_code") and values:
            method = "literal"
            for v in values:
                if not isinstance(v, str) or not v.strip():
                    continue
                for cand in _vm_search_literal(con, v, candidate_tables=candidate_tables):
                    key = (cand["table"], cand["col"])
                    if key in aggregated:
                        aggregated[key]["n_rows"] += cand["n_rows"]
                        # Dédup samples + cap 5 (anti-bruit dans les traces).
                        merged = list(dict.fromkeys(aggregated[key]["samples"] + cand["samples"]))
                        aggregated[key]["samples"] = merged[:5]
                    else:
                        aggregated[key] = cand
        elif value_kind == "textual_token" and values:
            method = "textual_token"
            for v in values:
                if not isinstance(v, str) or not v.strip():
                    continue
                try:
                    for cand in _vm_search_token(con, v, candidate_tables=candidate_tables):
                        key = (cand["table"], cand["col"])
                        if key in aggregated:
                            aggregated[key]["n_rows"] += cand["n_rows"]
                        else:
                            aggregated[key] = cand
                except ValueError:
                    # Token contient un caractère interdit (quote, control).
                    # On skip cette valeur — pas de fallback caché.
                    continue
        elif expects_values_branch:
            # Branche attendait des values mais en a pas reçu → fail-fast
            # explicite (pas de chute silencieuse vers name_match).
            return {
                "top_candidates": [],
                "best": None,
                "ambiguous": False,
                "score_gap_pct": 0.0,
                "fallback_used": False,
                "method": f"{value_kind}_no_values",
                "error": (
                    f"concept value_kind={value_kind} sans values — Phase 1 a omis "
                    f"les valeurs attendues. Pas de fallback name-match (anti-faux-positif)."
                ),
            }
        else:
            # Cas légitime : free_text, numeric_range sans valeurs, etc.
            # → name_match est la méthode primaire, pas un fallback.
            method = "name_match"
            for cand in _vm_search_by_name_match(
                con,
                name,
                expansions,
                candidate_tables=candidate_tables,
            ):
                aggregated[(cand["table"], cand["col"])] = cand
    except sqlite3.OperationalError as exc:
        # Erreur SQLite (table absente, query invalide) — surface l'erreur,
        # pas de fallback caché.
        return {
            "top_candidates": [],
            "best": None,
            "ambiguous": False,
            "score_gap_pct": 0.0,
            "fallback_used": False,
            "method": method,
            "error": str(exc),
        }

    # Score = méthode-spécifique (pas un seul scoring uniforme — chaque
    # value_kind a sa propre métrique de "qualité").
    cands = list(aggregated.values())
    import math

    for c in cands:
        if method == "temporal":
            # density_score (n_match / n_distinct) déjà calculé.
            # Multiplie par log(1+n_match) pour que les colonnes qui
            # matchent N années (vs 1) montent.
            density = c.get("density_score", 0.0)
            c["evidence_score"] = round(density * math.log(1 + c.get("n_rows", 0)), 3)
        elif method in ("literal", "textual_token"):
            # Spécificité = n_match / n_distinct (si dispo).
            n_dist = c.get("n_distinct") or c.get("n_rows", 1)
            specificity = c.get("n_rows", 0) / max(1, n_dist)
            c["evidence_score"] = round(
                math.log(1 + c.get("n_rows", 0)) * (0.5 + 0.5 * specificity), 3
            )
        elif method == "name_match":
            c["evidence_score"] = round(c.get("name_score", 0.0), 3)
        else:
            c["evidence_score"] = 0.0
        c["evidence_method"] = method
    cands.sort(key=lambda c: -c["evidence_score"])
    cands = cands[:10]  # cap top-10

    best = None
    ambiguous = False
    score_gap_pct = 0.0
    if cands:
        # Si top1 a un score 0 (cas : free_text matche aucun nom de col,
        # ou name_match avec scores tous nuls), best=None — pas de
        # « confiance » fictive vers Phase 4.
        if cands[0]["evidence_score"] > 0:
            best = {"table": cands[0]["table"], "col": cands[0]["col"]}
            if len(cands) >= 2:
                top1 = cands[0]["evidence_score"]
                top2 = cands[1]["evidence_score"]
                score_gap_pct = round((top1 - top2) / top1 * 100, 1)
                ambiguous = score_gap_pct < _VM_AMBIGUITY_GAP_PCT

    # `fallback_used=True` quand on est tombé en name_match alors qu'on
    # avait du value_kind autre que free_text (cas : LLM a déclaré
    # textual_token/literal_value mais sans values → on a forcé en
    # name_match comme dernier recours). Aujourd'hui l'archi évite ça
    # via fail-fast au-dessus, donc fallback_used=True ne sera jamais
    # observé en pratique — mais le contrat reste honoré.
    fallback_used = method == "name_match" and value_kind in (
        "literal_value",
        "identifier_code",
        "textual_token",
    )
    return {
        "top_candidates": cands,
        "best": best,
        "ambiguous": ambiguous,
        "score_gap_pct": score_gap_pct,
        "fallback_used": fallback_used,
        "method": method,
    }


# Mots de liaison FR à stripper pour le matching fuzzy concept_v2 ↔ rerank.
# Phase 2 rerank LLM reformule souvent : "nom du dossier" ↔ "nom de dossier",
# "écart production" ↔ "écart de production". Sans normalisation, le match
# par clé exacte rate.
_PHASE2_5_FR_STOPWORDS: frozenset[str] = frozenset(
    {
        "de",
        "du",
        "des",
        "à",
        "la",
        "le",
        "les",
        "l",
        "d",
        "un",
        "une",
        "au",
        "aux",
        "par",
        "en",
        "pour",
    }
)


def _phase_2_5_normalize_concept_name(name: str) -> str:
    """Normalise un nom de concept pour le matching fuzzy.

    Lowercase + strip mots de liaison FR + tokens dédup.
    Utilisé pour matcher concept_v2 (Phase 1.1+1.2) vs rerank (Phase 2)
    qui reformulent les noms.
    """
    if not isinstance(name, str):
        return ""
    norm = name.lower().strip().replace("'", " ")
    parts = [p for p in norm.split() if p and p not in _PHASE2_5_FR_STOPWORDS]
    return " ".join(parts)


def _phase_2_5_match_rerank_for_concept(
    concept_name: str,
    reranks_per_concept: dict,
) -> dict | None:
    """Trouve l'entrée rerank la plus proche pour un concept.

    Stratégie en 3 niveaux (du plus strict au plus permissif) :
        1. Match exact (clé identique)
        2. Match exact après normalisation (stripping mots de liaison)
        3. Inclusion de tokens (concept_v2 ⊆ rerank OR rerank ⊆ concept_v2)

    Retourne le dict rerank correspondant, ou None si aucun match raisonnable.
    """
    if concept_name in reranks_per_concept:
        return reranks_per_concept[concept_name]
    c_norm = _phase_2_5_normalize_concept_name(concept_name)
    if not c_norm:
        return None
    c_tokens = set(c_norm.split())
    # 2. Match normalisé exact
    for r_name, r_data in reranks_per_concept.items():
        if _phase_2_5_normalize_concept_name(r_name) == c_norm:
            return r_data
    # 3. Inclusion de tokens (best match par overlap relatif)
    best_match: dict | None = None
    best_score = 0.0
    for r_name, r_data in reranks_per_concept.items():
        r_tokens = set(_phase_2_5_normalize_concept_name(r_name).split())
        if not c_tokens or not r_tokens:
            continue
        inter = c_tokens & r_tokens
        if not inter:
            continue
        # Inclusion stricte : un set ⊆ l'autre
        if c_tokens.issubset(r_tokens) or r_tokens.issubset(c_tokens):
            # Score = couverture du plus petit set
            score = len(inter) / min(len(c_tokens), len(r_tokens))
            if score > best_score:
                best_score = score
                best_match = r_data
    # Seuil : exiger au moins 100% du plus petit set (= inclusion stricte non
    # vide). Pas de match flou laxiste — on préfère un FAILED explicite à
    # une fausse résolution silencieuse.
    if best_score >= 1.0:
        return best_match
    return None


def _t4_enrich_reranks_with_missing_fvex(
    reranks_per_concept: dict | None,
    concepts_v2: list | None,
    v2_text: str,
    *,
    fvex_recovery_rank: int = 99,
) -> dict | None:
    """T4 — Garantit que **toutes** les FvEx empiriques sont candidates en aval.

    Le rerank LLM Phase 2 peut, par biais lexical, omettre une colonne FvEx
    textuelle au profit d'une FK numérique (cas log 2026-05-10 : ``dosCabinetEntite``
    top-1 alors que ``dosNomDossier`` matche empiriquement ``DOSSIER_A PAP``).

    Ce helper compare ce que le LLM a produit (``ranking_top[*].key_columns``)
    contre les FvEx **empiriquement validées** (colonne contient effectivement
    une valeur user, détecté en Phase 1.3-1.4). Toute paire ``(table, col)``
    FvEx manquante dans le ranking_top est **réinjectée** :

    - Si l'entity existe déjà dans le ranking_top → ajoute ``col`` à
      ``key_columns`` (la colonne ne disparaît pas même si l'LLM l'avait
      ignorée).
    - Sinon → crée une nouvelle entry ``{rank=99, kind='T', source='fvex_recovery'}``
      en queue (le LLM garde la main sur le tri ; on ajoute un filet de sécurité).

    Phase 2.5 (et T29★) verront ces colonnes comme alternatives compat ; les
    probes oracle T2 pourront alors trancher empiriquement.

    **Idempotent** : second appel = no-op (les pairs déjà présentes sont skippées).

    **Fail-safe** : v2_text vide / reranks None / concepts_v2 None / dict
    corrompu → retourne reranks_per_concept inchangé. Aucun raise.

    **Mute in-place** (return aussi pour chainage). Le caller (mode=ir) garde
    la référence vers reranks_per_concept.

    Generic : 0 nom BDD hardcodé. Reverse-lookup via v2_text + concepts_v2.values
    + parse_fvex_from_v2 (existant). Fuzzy match concept_name via
    ``_phase_2_5_match_rerank_for_concept`` (cohérent avec Phase 2.5).

    Args:
        reranks_per_concept: ``state.reranks["per_concept"]`` (dict {cname: {ranking_top: [...]}})
        concepts_v2: ``state.extracted["concepts_v2"]``
        v2_text: ``state.scored["v2_text"]`` (contient les blocs FvEx)
        fvex_recovery_rank: rank attribué aux entries nouvellement créées
            (défaut 99 — derrière tout ce que le LLM a produit).

    Returns:
        Le dict ``reranks_per_concept`` muté (référence retournée pour chainage).
        Si entrée invalide, retourne tel quel.
    """
    if not isinstance(reranks_per_concept, dict) or not reranks_per_concept:
        return reranks_per_concept
    if not isinstance(concepts_v2, list) or not concepts_v2:
        return reranks_per_concept
    if not isinstance(v2_text, str) or not v2_text:
        return reranks_per_concept

    injected_total = 0
    for c2 in concepts_v2:
        if not isinstance(c2, dict):
            continue
        cname = c2.get("name")
        if not isinstance(cname, str) or not cname:
            continue
        values = c2.get("values") or []
        if not isinstance(values, list) or not values:
            continue

        # Parse FvEx empiriques pour ce concept (réutilise helper existant)
        fvex_per_value = parse_fvex_from_v2(v2_text, [str(v) for v in values if v])
        fvex_pairs_for_concept: set[tuple[str, str]] = set()
        for _value_lower, pairs in fvex_per_value.items():
            for pair in pairs:
                if (
                    isinstance(pair, (list, tuple))
                    and len(pair) == 2
                    and isinstance(pair[0], str)
                    and isinstance(pair[1], str)
                ):
                    fvex_pairs_for_concept.add((pair[0], pair[1]))

        if not fvex_pairs_for_concept:
            continue

        # Match concept_name → rerank entry (fuzzy)
        rerank = _phase_2_5_match_rerank_for_concept(cname, reranks_per_concept)
        if not isinstance(rerank, dict):
            # Pas d'entrée rerank pour ce concept — on n'invente pas, on skip.
            # (Une fois T4.B en place, l'appel rerank a déjà eu lieu.)
            continue
        ranking_top = rerank.get("ranking_top")
        if not isinstance(ranking_top, list):
            ranking_top = []
            rerank["ranking_top"] = ranking_top

        # Index des entries existantes par entity name (pour mute key_columns).
        entries_by_entity: dict[str, dict] = {}
        for entry in ranking_top:
            if not isinstance(entry, dict):
                continue
            ent = entry.get("entity")
            if isinstance(ent, str) and ent:
                # 1re occurrence garde priorité (LLM préférence).
                entries_by_entity.setdefault(ent, entry)

        for table, col in sorted(fvex_pairs_for_concept):
            entry = entries_by_entity.get(table)
            if entry is not None:
                # Entity déjà présente : check si col déjà listée.
                key_cols = entry.get("key_columns")
                if not isinstance(key_cols, list):
                    key_cols = []
                    entry["key_columns"] = key_cols
                if col in key_cols:
                    continue  # idempotent : déjà présent
                key_cols.append(col)
                injected_total += 1
            else:
                # Entity absente : créer une nouvelle entry "fvex_recovery"
                # rangée en queue (rank=99 par défaut → LLM préférences gardent
                # la priorité, T4 est filet de sécurité).
                new_entry = {
                    "rank": int(fvex_recovery_rank),
                    "entity": table,
                    "kind": "T",
                    "key_columns": [col],
                    "rationale": (
                        "T4 fvex_recovery — FvEx empirique (valeur user présente "
                        "dans cette colonne) non remontée par le rerank LLM"
                    ),
                    "source": "fvex_recovery",
                }
                ranking_top.append(new_entry)
                entries_by_entity[table] = new_entry
                injected_total += 1

    if injected_total > 0:
        print(
            f"→ T4 fvex_recovery : {injected_total} paires (table, col) "
            f"réinjectées dans le ranking_top (LLM rerank avait omis).",
            flush=True,
        )

    return reranks_per_concept


def _t14_enrich_reranks_with_missing_fvco(
    reranks_per_concept: dict | None,
    concepts_v2: list | None,
    v2_text: str,
    *,
    fvco_recovery_rank: int = 199,
) -> dict | None:
    """T14 — Réinjecte les FvCo (sous-chaîne / fuzzy) omises par le rerank LLM.

    Symétrique à :func:`_t4_enrich_reranks_with_missing_fvex` mais pour les
    matches **sous-chaîne** (``FvCo``) au lieu d'égalité stricte (``FvEx``).

    **Pourquoi T14** : si l'utilisateur tape ``DOSSIER_A`` et la BDD a
    ``DOSSIER_A PAP``, l'égalité stricte échoue mais la sous-chaîne match.
    Phase 1.4 produit déjà ces signaux dans le ``v2_text`` (section FvCo).
    T4 les ignore (FvEx-only). T14 les remonte avec un rang bas (199 par
    défaut, derrière T4@99) → Phase 2.5 voit la colonne comme alternative
    **basse confiance** ; T29★ détectera l'ambigüité ; T16 distinguera 0-rows
    bug vs légitime.

    **Idempotent** : pair déjà présente (via T4 ou rerank LLM ou T14
    précédent) → skip. Ordre d'appel recommandé : T4 d'abord (FvEx priorité
    haute), puis T14 (FvCo signal complémentaire).

    **Fail-safe** : entrées vides / corrompues → retourne ``reranks_per_concept``
    inchangé.

    Generic : 0 nom BDD hardcodé. Reverse-lookup via ``parse_fvco_from_v2``.

    Args:
        reranks_per_concept: ``state.reranks["per_concept"]``.
        concepts_v2: ``state.extracted["concepts_v2"]``.
        v2_text: ``state.scored["v2_text"]``.
        fvco_recovery_rank: rank attribué aux entries FvCo nouvellement créées.

    Returns:
        Dict ``reranks_per_concept`` muté (référence retournée pour chainage).
    """
    if not isinstance(reranks_per_concept, dict) or not reranks_per_concept:
        return reranks_per_concept
    if not isinstance(concepts_v2, list) or not concepts_v2:
        return reranks_per_concept
    if not isinstance(v2_text, str) or not v2_text:
        return reranks_per_concept

    injected_total = 0
    for c2 in concepts_v2:
        if not isinstance(c2, dict):
            continue
        cname = c2.get("name")
        if not isinstance(cname, str) or not cname:
            continue
        values = c2.get("values") or []
        if not isinstance(values, list) or not values:
            continue

        # T14 différence avec T4 : FvCo au lieu de FvEx
        fvco_per_value = parse_fvco_from_v2(v2_text, [str(v) for v in values if v])
        fvco_pairs_for_concept: set[tuple[str, str]] = set()
        for _value_lower, pairs in fvco_per_value.items():
            for pair in pairs:
                if (
                    isinstance(pair, (list, tuple))
                    and len(pair) == 2
                    and isinstance(pair[0], str)
                    and isinstance(pair[1], str)
                ):
                    fvco_pairs_for_concept.add((pair[0], pair[1]))

        if not fvco_pairs_for_concept:
            continue

        rerank = _phase_2_5_match_rerank_for_concept(cname, reranks_per_concept)
        if not isinstance(rerank, dict):
            continue
        ranking_top = rerank.get("ranking_top")
        if not isinstance(ranking_top, list):
            ranking_top = []
            rerank["ranking_top"] = ranking_top

        entries_by_entity: dict[str, dict] = {}
        for entry in ranking_top:
            if not isinstance(entry, dict):
                continue
            ent = entry.get("entity")
            if isinstance(ent, str) and ent:
                entries_by_entity.setdefault(ent, entry)

        for table, col in sorted(fvco_pairs_for_concept):
            entry = entries_by_entity.get(table)
            if entry is not None:
                key_cols = entry.get("key_columns")
                if not isinstance(key_cols, list):
                    key_cols = []
                    entry["key_columns"] = key_cols
                if col in key_cols:
                    continue  # idempotent (déjà via LLM, T4, ou T14 précédent)
                key_cols.append(col)
                injected_total += 1
            else:
                new_entry = {
                    "rank": int(fvco_recovery_rank),
                    "entity": table,
                    "kind": "T",
                    "key_columns": [col],
                    "rationale": (
                        "T14 fvco_recovery — valeur user trouvée comme "
                        "sous-chaîne (FvCo) dans cette colonne, non remontée "
                        "par le rerank LLM"
                    ),
                    "source": "fvco_recovery",
                }
                ranking_top.append(new_entry)
                entries_by_entity[table] = new_entry
                injected_total += 1

    if injected_total > 0:
        print(
            f"→ T14 fvco_recovery : {injected_total} paires (table, col) "
            f"FvCo (sous-chaîne) réinjectées dans le ranking_top.",
            flush=True,
        )

    return reranks_per_concept


def _phase_2_5_table_has_any_fk(
    table_name: str,
    fk_lookup: dict[str, list[dict]],
) -> bool:
    """Check si ``table_name`` a au moins une FK (sortante ou entrante).

    Une table sans FK est inutilisable pour les JOINs multi-table — le BFS
    `_ir_compute_join_chain` la considère comme « non-joignable ». C'est
    typique des tables de reporting/cache (TempRpt*, vues de log) qui ne
    déclarent pas de FK même si sémantiquement elles dépendent d'autres
    tables.
    """
    if not table_name or not fk_lookup:
        return False
    # Outgoing FKs
    if fk_lookup.get(table_name):
        return True
    # Incoming FKs (autres tables qui pointent vers celle-ci)
    for fks in fk_lookup.values():
        for fk in fks:
            if fk.get("to_table") == table_name:
                return True
    return False


def _phase_2_5_user_values_expected_type(values: list) -> str:
    """Détecte le type attendu (number / text) à partir des valeurs user d'un concept.

    Utilisé pour scorer les ``key_columns`` candidats par compatibilité
    avec ce que l'utilisateur a écrit (cf. fix bug Phase 2.5 du 2026-05-10 :
    pour ``entité = ['DOSSIER_A PAP']``, on doit préférer une colonne text à
    une colonne number, peu importe l'ordre LLM).

    Retourne :
        - ``"number"`` si TOUTES les valeurs non-vides ET non-None sont
          parseables en ``float`` (couvre int, décimal, négatif).
        - ``"text"`` sinon (défaut sûr — couvre aussi liste vide où on
          n'a aucune info de type, ou liste de None purs).

    ``None`` et ``""`` sont **filtrés AVANT le parse** (cf. adversarial
    review CRITICAL #4) : un ``values=[None, '70610000']`` représente une
    extraction partielle où Phase 1 n'a pas pu typer une valeur. On
    préfère ne pas la laisser polluer le typage des autres.
    """
    if not values:
        return "text"
    clean: list[str] = []
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        clean.append(s)
    if not clean:
        return "text"
    for s in clean:
        try:
            float(s)
        except (ValueError, TypeError):
            return "text"
    return "number"


# Rôles sémantiques dont une instance SANS valeur exemple attend une colonne
# numérique (mesure agrégeable / dérivation calculée). Source unique pour le
# typage rôle-aware Phase 2.5 (cf. adversarial review F2). Sous-ensemble de
# ``_ROLE_VALUES`` (le vocabulaire complet des rôles concept).
_NUMERIC_EXPECTED_ROLES: frozenset[str] = frozenset({"measure", "derivation"})


def _phase_2_5_expected_type_for_concept(values: list, role: str | None) -> str:
    """Type attendu (number/text) pour scorer les key_cols, RÔLE-aware.

    Étend :func:`_phase_2_5_user_values_expected_type` : les valeurs user
    typées restent le signal PRIORITAIRE ; le rôle sémantique ne sert QUE de
    repli quand l'utilisateur n'a fourni aucune valeur exemple.

    Pourquoi (run #16, 2026-05-30) : une mesure SANS valeur exemple
    (``production réalisée``, ``chiffre d'affaires``) tombait à
    ``expected_type='text'`` (défaut de la fonction de base sur liste vide).
    Le tri compat du fast-path Phase 2.5 préférait alors une colonne
    texte/libellé à la vraie colonne montant → la mesure résolvait vers une
    colonne NOM (``nomCollaborateurProduction``) au lieu du montant
    (``truMtProduction``) → **SOMMES FAUSSES SILENCIEUSES** (pas de crash, un
    résultat numérique aberrant). Une mesure/dérivation est agrégeable donc
    numérique : sans valeur user, on attend ``number``.

    Règles (ordre de priorité) :
      1. ``values`` parseables en number → ``number`` (signal user fort).
      2. ``values`` texte non vide → ``text`` (filtre texte explicite, ex.
         ``DOSSIER_A PAP`` — NE PAS le surcharger via le rôle).
      3. Aucune valeur exemple ET role ∈ {measure, derivation} → ``number``.
      4. Sinon → ``text`` (comportement historique inchangé).

    100 % générique : ``role`` est un champ sémantique posé par le LLM
    Phase 1 ; aucun nom de table/colonne BDD.
    """
    base = _phase_2_5_user_values_expected_type(values)
    if base == "number":
        return "number"
    # base == "text" : distinguer "user a écrit du texte" (signal fort) de
    # "aucune valeur" (pas de signal → le rôle guide le typage).
    has_value = any(v is not None and str(v).strip() for v in (values or []))
    if has_value:
        return "text"  # filtre texte explicite de l'utilisateur — fait foi.
    r = (role or "").strip().lower()
    if r in _NUMERIC_EXPECTED_ROLES:
        return "number"
    return "text"


def _phase_2_5_value_type_compatible(col_value_type: str, expected_type: str) -> bool:
    """Compatibilité ``value_type`` colonne ↔ type attendu des valeurs user.

    Tolérance volontaire :
    - ``text`` user matche ``text`` OU ``code`` côté colonne (Sage range
      souvent les codes alphanumériques courts dans ``code``).
    - ``number`` user matche ``number`` OU ``code`` côté colonne (cf.
      adversarial review BLOCKING #1) — Sage stocke souvent des comptes
      comptables ou codes courts numériques dans ``value_type='code'``,
      par ex. ``LignesFactures.lfaCompte = '70610000'`` peut être classifié
      ``code`` selon la config du sampler. Ne PAS rejeter ce match
      silencieusement, sinon on retombe sur l'ancien bug Phase 2.5
      (mauvaise col choisie).
    - Type inconnu (chaîne vide ou ``None``) côté colonne = compatible
      (fallback safe — on n'élimine pas une col faute d'info).

    Conséquence : une col non-classée n'est pas pénalisée. Une col mal
    classée (ex: ``number`` à cause d'un outlier — voir fix vote
    majoritaire) sera correctement écartée si user_values sont du texte
    pur (e.g. 'DOSSIER_A PAP', non-numérique).
    """
    col_t = (col_value_type or "").lower()
    exp_t = (expected_type or "").lower()
    if not col_t:
        return True
    if exp_t == "text":
        return col_t in ("text", "code")
    if exp_t == "number":
        return col_t in ("number", "code")
    return True  # type user inconnu : on n'élimine pas


def _phase_2_5_is_primary_key(con, table: str, col: str) -> bool:
    """Détecte si ``(table, col)`` est une PRIMARY KEY via PRAGMA table_info.

    100 % générique : aucune convention de nommage hardcodée (pas de regex
    ``XxxNoEnreg`` Sage Coala). Marche sur n'importe quelle BDD source dont
    le schéma est miroirisé en SQLite local (cas standard Komptia).

    Cf. task #81 F5 — utilisé pour déprioriter les identifiers-of-record
    sur les concepts ``temporal`` / ``measure`` / ``derivation``.
    """
    if not table or not col:
        return False
    try:
        cols = con.execute(f'PRAGMA table_info("{table}")').fetchall()
        for c in cols:
            # PRAGMA table_info colonnes : (cid, name, type, notnull, dflt_value, pk)
            if c[1] == col:
                return bool(c[5])
    except sqlite3.Error:
        return False
    return False


def _phase_2_5_is_foreign_key(con, table: str, col: str) -> bool:
    """Détecte si ``(table, col)`` est une FOREIGN KEY déclarée via
    ``PRAGMA foreign_key_list``.

    100 % générique : aucune convention de nommage hardcodée. Lit les FK
    déclarées (DDL ``REFERENCES``). Les FK convention Sage ``XxxNoEnreg``
    non déclarées ne sont PAS détectées ici — c'est volontaire (sinon on
    pollue avec une hardcode-back, cf. tâche pendante #48 GFP-G1).

    Pour les FK inférées (table ``inferred_foreign_keys``), un autre helper
    pourrait les couvrir si besoin — hors scope F5.
    """
    if not table or not col:
        return False
    try:
        rows = con.execute(f'PRAGMA foreign_key_list("{table}")').fetchall()
        for r in rows:
            # PRAGMA foreign_key_list colonnes : (id, seq, to_table, from_col,
            # to_col, on_update, on_delete, match)
            if r[3] == col:
                return True
    except sqlite3.Error:
        return False
    return False


def _phase_2_5_lookup_value_type_majority(con, table: str, col: str) -> tuple[str, list]:
    """Lookup ``value_type`` (vote majoritaire) + 3 samples pour ``(table, col)``.

    Bug fix 2026-05-10 : l'ancien code faisait
    ``SELECT value_type, real_value FROM value_mapping WHERE ... LIMIT 3``
    et retenait ``rows[0][0]`` — soit le ``value_type`` du premier rowid, sans
    ``ORDER BY``. Conséquence : pour ``Collaborateurs.colCodeCollabo`` avec
    1 row ``number`` + 416 rows ``text``, le lookup retournait ``number`` car
    le rowid 1 se trouvait être l'outlier numérique. Le préflight Phase 4
    crashait alors sur incompatibilité texte↔number.

    Le vote majoritaire (``GROUP BY value_type ORDER BY n DESC``) reflète
    la classification réelle de la colonne.

    Returns:
        ``(value_type, samples)`` où :
        - ``value_type=""`` si la colonne est absente de ``value_mapping``
          OU si le top vote a un ``value_type`` NULL/vide (cf. adversarial
          review CRITICAL #2 : retourner ``"text"`` ferait passer une col
          non-classifiée pour text alors que c'est un fallback safe — la
          chaîne vide laisse ``_value_type_compatible`` décider de garder).
        - ``samples`` filtrés sur le ``value_type`` majoritaire (cf.
          adversarial review SUGGESTION #3) : sinon les samples affichés
          en trace humaine peuvent être des outliers d'autres types,
          trompeurs (ex: '3368' pour une col text).
    """
    type_rows = con.execute(
        "SELECT value_type, COUNT(*) AS n FROM value_mapping "
        "WHERE table_name = ? AND column_name = ? "
        "GROUP BY value_type ORDER BY n DESC",
        (table, col),
    ).fetchall()
    if not type_rows:
        return "", []
    value_type = type_rows[0][0] or ""
    if value_type:
        sample_rows = con.execute(
            "SELECT real_value FROM value_mapping "
            "WHERE table_name = ? AND column_name = ? AND value_type = ? "
            "LIMIT 3",
            (table, col, value_type),
        ).fetchall()
    else:
        sample_rows = con.execute(
            "SELECT real_value FROM value_mapping "
            "WHERE table_name = ? AND column_name = ? LIMIT 3",
            (table, col),
        ).fetchall()
    samples = [r[0] for r in sample_rows]
    return value_type, samples


def _compute_phase_2_5_confidence(
    candidates: list[dict],
    *,
    expected_type: str = "",
    threshold: float = _PHASE_2_5_LOW_CONFIDENCE_THRESHOLD,
) -> dict:
    """T29★ — Signal de confiance objectif sur la résolution Phase 2.5.

    Calcul **programmatique** (0 appel LLM, 0 query BDD). Agrège plusieurs
    signaux structurels sur la liste ``candidates`` (top_candidates produits
    par Phase 2.5 après tri compat/rank) pour produire un score 0-100.

    Signaux pris en compte :

    1. **`top1_type_incompatible`** : si `candidates[0]["_compat"]` est False,
       le top-1 ne matche pas le ``expected_type`` user. Mode dégradé majeur
       (préflight Phase 4 va probablement raise). Penalty
       ``_PHASE_2_5_TOP1_INCOMPATIBLE_PENALTY``.

    2. **`ambiguous_across_tables`** : si 2+ candidats ``_compat=True``
       portent sur des **tables différentes**, le LLM hésitait entre
       plusieurs entités métier. Penalty ``_PHASE_2_5_AMBIGUITY_PENALTY``.

    3. **`multiple_compat_cols_same_table`** : 2+ compat sur la même
       table mais colonnes différentes — ambigu mais moins critique
       (penalty proportionnelle / 2).

    4. **`top1_type_inconsistent_with_user_values`** : ``expected_type=text``
       mais top-1 ``value_type ∈ NUMERIC`` (ou inverse). Cas distinct du
       point 1 car ``_compat`` peut être True (compat tolère ``code``).
       Penalty ``_PHASE_2_5_TYPE_MISMATCH_PENALTY``.

    5. **`tied_top_rank`** : 2+ candidats partagent le même
       ``_original_rank`` (LLM ouvertement indécis). Penalty
       ``_PHASE_2_5_AMBIGUITY_PENALTY``.

    Args:
        candidates: liste de dicts (déjà triés Phase 2.5). Champs attendus :
            ``table``, ``col``, ``value_type``, ``_compat``, ``_original_rank``,
            ``evidence_score``. Liste vide ou len==1 → confiance haute (rien
            à départager).
        expected_type: ``"text"`` ou ``"number"`` ou ``""`` (inconnu) — produit
            par ``_phase_2_5_user_values_expected_type``.
        threshold: seuil en-dessous duquel ``low_confidence=True``.

    Returns:
        dict avec :
        - ``confidence_score`` (float, [0, 100])
        - ``low_confidence`` (bool)
        - ``score_gap_pct`` (float, écart top1/top2 en %)
        - ``tied_count`` (int)
        - ``distinct_tables_compat`` (int)
        - ``signals`` (list[str])

    Generic : aucun nom de table/colonne hardcodé. Signaux applicables à
    toute BDD SQL Server (ou autre) qui passe par le pipeline.
    """
    if not candidates:
        return {
            "confidence_score": 100.0,
            "low_confidence": False,
            "score_gap_pct": 100.0,
            "tied_count": 0,
            "distinct_tables_compat": 0,
            "signals": [],
        }

    confidence = 100.0
    signals: list[str] = []

    top1 = candidates[0]
    top1_compat = bool(top1.get("_compat", True))
    top1_vt = (top1.get("value_type") or "").lower()
    exp_t = (expected_type or "").lower()

    # 1. Top-1 incompat (mode dégradé)
    if not top1_compat:
        confidence -= _PHASE_2_5_TOP1_INCOMPATIBLE_PENALTY
        signals.append("top1_type_incompatible")

    # 2/3. Distribution des compat candidates (cross-tables vs same-table)
    compat_candidates = [c for c in candidates if c.get("_compat")]
    distinct_tables_compat = len({c.get("table", "") for c in compat_candidates if c.get("table")})
    if distinct_tables_compat >= 2:
        confidence -= _PHASE_2_5_AMBIGUITY_PENALTY
        signals.append(f"ambiguous_across_{distinct_tables_compat}_tables")
    elif len(compat_candidates) >= 2:
        confidence -= _PHASE_2_5_AMBIGUITY_PENALTY / 2.0
        signals.append(f"multiple_compat_cols_{len(compat_candidates)}_same_table")

    # 4. Type alignment user_values ↔ top-1 value_type
    # (distinct de point 1 : _compat tolère ``code`` ; ici on signale les cas
    # où le LLM a choisi un type différent du type principal user)
    if exp_t in ("text", "number") and top1_vt:
        if exp_t == "text" and top1_vt in _VM_NUMERIC_VALUE_TYPES:
            confidence -= _PHASE_2_5_TYPE_MISMATCH_PENALTY
            signals.append("top1_type_inconsistent_with_user_values")
        elif exp_t == "number" and top1_vt in _VM_TEXTUAL_VALUE_TYPES:
            confidence -= _PHASE_2_5_TYPE_MISMATCH_PENALTY
            signals.append("top1_type_inconsistent_with_user_values")

    # 5. Ties par _original_rank (LLM hésite ouvertement)
    top1_rank = top1.get("_original_rank")
    tied_count = 0
    if top1_rank is not None:
        tied_count = sum(1 for c in candidates if c.get("_original_rank") == top1_rank)
        if tied_count >= 2:
            confidence -= _PHASE_2_5_AMBIGUITY_PENALTY
            signals.append(f"tied_top_rank_{tied_count}_candidates")

    # 6. score_gap_pct (informatif — pas une penalty, juste exposé)
    if len(candidates) >= 2:
        s1 = float(top1.get("evidence_score") or 0)
        s2 = float(candidates[1].get("evidence_score") or 0)
        score_gap_pct = ((s1 - s2) / s1 * 100.0) if s1 else 0.0
    else:
        score_gap_pct = 100.0

    confidence = max(0.0, min(100.0, confidence))
    low_confidence = confidence < float(threshold)

    return {
        "confidence_score": confidence,
        "low_confidence": low_confidence,
        "score_gap_pct": score_gap_pct,
        "tied_count": tied_count,
        "distinct_tables_compat": distinct_tables_compat,
        "signals": signals,
    }


def _phase_2_5_resolve_from_reranks(
    concepts_v2: list,
    reranks_per_concept: dict,
    con,
    *,
    candidate_tables: set[str] | None = None,
    fk_lookup: dict[str, list[dict]] | None = None,
    top_k: int = 5,
) -> dict:
    """Phase 2.5 fast-path — résout les concepts depuis ``state.reranks``.

    Phase 2 rerank produit déjà, pour chaque concept, un ``ranking_top`` avec
    ``[{rank, entity (table/view), kind, key_columns: [...], rationale}]``. La
    colonne candidate est le premier ``key_columns[0]``. On lookup uniquement
    ``value_type`` + 3 samples via ``idx_vm_table_col`` (indexed → ms).

    **Pourquoi** : Phase 2.5 d'origine fait des ``LIKE '%token%'`` non-indexable
    sur 29M lignes (full scan, plusieurs minutes par token). Le rerank fait
    déjà le travail amont avec les indexes RAM de Phase 1.3-1.4. Le fast-path
    saute la duplication.

    Returns ``{concept_name: resolution_dict}`` au même format que la version
    LIKE % (compat) :
        ``{"best": {"table","col"}, "top_candidates": [...], "method":
        "rerank_fastpath", "ambiguous": False, "error": None}``

    Si un concept n'a pas d'entrée exploitable dans reranks (rerank manquant,
    pas de ``key_columns``), retourne ``{"error": "no rerank match", "best": None}``
    pour ce concept — le caller peut fallback sur la méthode LIKE % d'origine
    concept par concept.
    """
    out: dict[str, dict] = {}
    # Memo cache local : ~21 concepts × ~5 entries × ~3 cols = ~315 lookups
    # potentiels, dont beaucoup duplicates (mêmes (table, col) pour des
    # concepts différents — ex: Dossiers.dosNomDossier matché par "dossier",
    # "nom du dossier", "entité"). Le memo réduit les round-trips SQLite.
    # Cf. adversarial review CRITICAL #5.
    vt_cache: dict[tuple[str, str], tuple[str, list]] = {}

    def _cached_lookup(table: str, col: str) -> tuple[str, list]:
        key = (table, col)
        if key not in vt_cache:
            vt_cache[key] = _phase_2_5_lookup_value_type_majority(con, table, col)
        return vt_cache[key]

    # F5 task #81 (adversarial fix BLOCKING #4) — cache PRAGMA par table pour
    # PK/FK. PRAGMA table_info / foreign_key_list retournent les méta de la
    # table entière → 1 PRAGMA par table suffit (vs 1 par candidate sans
    # cache). Sur ~21 concepts × ~5 entries × ~3 cols = 315 candidates max
    # MAIS sur ~20 tables uniques → 40 PRAGMA au lieu de 1500. Critique
    # surtout sous SQLCipher où chaque PRAGMA = roundtrip décrypt.
    _pk_fk_cache: dict[str, dict[str, set[str]]] = {}

    def _cached_pk_fk_cols(table: str) -> dict[str, set[str]]:
        if table not in _pk_fk_cache:
            pks: set[str] = set()
            fks: set[str] = set()
            if table:
                try:
                    for c in con.execute(f'PRAGMA table_info("{table}")').fetchall():
                        # PRAGMA columns: (cid, name, type, notnull, dflt, pk)
                        if c[5]:
                            pks.add(c[1])
                except sqlite3.Error:
                    pass
                try:
                    for r in con.execute(
                        f'PRAGMA foreign_key_list("{table}")'
                    ).fetchall():
                        # PRAGMA columns: (id, seq, to_table, from_col, to_col, ...)
                        if r[3]:
                            fks.add(r[3])
                except sqlite3.Error:
                    pass
            _pk_fk_cache[table] = {"pk": pks, "fk": fks}
        return _pk_fk_cache[table]

    def _is_cached_pk_or_fk(table: str, col: str) -> bool:
        if not table or not col:
            return False
        info = _cached_pk_fk_cols(table)
        return col in info["pk"] or col in info["fk"]

    for c2 in concepts_v2:
        if not isinstance(c2, dict):
            continue
        cname = c2.get("name")
        if not isinstance(cname, str) or not cname:
            continue
        # P0-B (2026-05-30) — Concept DÉRIVÉ (role=derivation) : c'est une
        # MESURE COMPOSÉE (ex: rentabilité = facturation - production), PAS une
        # colonne du schéma. Doctrine data_construction : on ne CHERCHE pas une
        # colonne, on COMPOSE la formule en Phase 4. On NE le marque PAS en
        # ``error`` (sinon il sort de l'enum Phase 4 et la dérivation ne peut
        # JAMAIS être composée — bug run #16 : rentabilité → rerank_fastpath_failed).
        # Générique : branché sur le flag ``role`` posé par le LLM Phase 1 sur
        # tout calcul (marge, taux, ratio, YoY...), zéro nom de table/colonne.
        _raw_role = c2.get("role")
        if isinstance(_raw_role, str) and _raw_role.lower() == "derivation":
            # Garde-fou anti faux-positif LLM (désambiguïsation EMPIRIQUE — cf.
            # règle « jamais de SQL à l'aveugle ») : le LLM a pu classer à tort
            # un concept en dérivation alors qu'une vraie colonne porte ce nom.
            # Signal SANS requête additionnelle : Phase 2 rerank a-t-il quand même
            # trouvé des candidats colonne pour ce nom ? (un dérivé est normalement
            # absent du rerank → présence = ambiguïté à signaler, pas composer en
            # silence).
            _dv_rerank = _phase_2_5_match_rerank_for_concept(cname, reranks_per_concept)
            _dv_candidates: list = []
            if isinstance(_dv_rerank, dict):
                _dv_rt = _dv_rerank.get("ranking_top") or []
                if isinstance(_dv_rt, list):
                    for _dv_e in _dv_rt:
                        if not isinstance(_dv_e, dict):
                            continue
                        _dv_kc = _dv_e.get("key_columns") or []
                        if isinstance(_dv_kc, list) and _dv_kc:
                            _dv_candidates.append(
                                {"table": _dv_e.get("entity"), "col": _dv_kc[0]}
                            )
            _dv_ambiguous = bool(_dv_candidates)
            out[cname] = {
                "best": None,
                "top_candidates": _dv_candidates[:top_k],
                "method": "derivation",
                "ambiguous": _dv_ambiguous,
                "error": None,
                "warning": (
                    f"Concept '{cname}' interprété comme mesure DÉRIVÉE "
                    f"(formule : {c2.get('derivation_formula')}). Des colonnes "
                    f"portent aussi ce nom ({[c['table'] for c in _dv_candidates]}) "
                    f"— la pipeline COMPOSE la formule ; précise si tu voulais une "
                    f"colonne dédiée."
                )
                if _dv_ambiguous
                else None,
                "is_derived": True,
                "derivation_formula": c2.get("derivation_formula"),
            }
            continue
        # Match fuzzy : Phase 2 rerank LLM peut reformuler les noms
        # (ex: "nom du dossier" → "nom de dossier"). On cherche d'abord
        # l'exact, puis normalisé, puis inclusion stricte de tokens.
        rerank = _phase_2_5_match_rerank_for_concept(
            cname,
            reranks_per_concept,
        )
        if not isinstance(rerank, dict):
            out[cname] = {
                "best": None,
                "top_candidates": [],
                "method": "rerank_fastpath",
                "ambiguous": False,
                # Message ACTIONABLE pour le LLM Iris (fix L8 2026-05-20) :
                # propose une suite plutôt qu'un "no rerank entry" cryptique.
                # Le LLM voit ce message via tool_result et peut décider
                # de demander clarification user ou de re-formuler le concept.
                "error": (
                    f"Concept '{cname}' non interprété par Phase 2 rerank "
                    f"(aucune entrée dans reranks_per_concept malgré le fuzzy "
                    f"match). Le LLM doit soit demander à l'utilisateur de "
                    f"reformuler ce concept, soit l'omettre s'il est secondaire."
                ),
                "warning": None,
            }
            continue
        ranking_top = rerank.get("ranking_top") or []
        if not isinstance(ranking_top, list) or not ranking_top:
            out[cname] = {
                "best": None,
                "top_candidates": [],
                "method": "rerank_fastpath",
                "ambiguous": False,
                # Cas observé run #7 (2026-05-20) sur 'montant TTC' : Phase 2
                # rerank LLM ne renvoie aucun candidat → concept non résolu →
                # Phase 4 crash IRValidationError. Message actionable.
                "error": (
                    f"Concept '{cname}' sans candidats schéma : Phase 2 "
                    f"rerank a renvoyé un ranking_top vide. Soit aucune "
                    f"table de la BDD ne porte cette information (concept "
                    f"absent du schéma), soit le rerank LLM a échoué. "
                    f"Suggestions : (a) demander clarification user, "
                    f"(b) omettre ce concept du SQL final s'il est secondaire."
                ),
                "warning": None,
            }
            continue

        # Tri pré-fast-path : préférer les entries joignables.
        # Critères (ordre lexicographique) :
        #   1. kind="T" (table physique) > kind="V" (vue, FKs souvent absentes
        #      en local SQLite)
        #   2. Table avec FK déclarée > table sans FK (les tables sans FK
        #      type TempRpt*, caches reporting, sont non-joignables via BFS)
        #   3. rank d'origine du Phase 2 (tie-break)
        # Sans ce tri, Phase 2 rerank LLM peut choisir TempRptProdUser
        # comme top-1 pour "année" → IR plante au render BFS.
        ranking_sorted = sorted(
            ranking_top,
            key=lambda e: (
                0 if e.get("kind") == "T" else 1,
                (
                    0
                    if (
                        fk_lookup
                        and _phase_2_5_table_has_any_fk(
                            e.get("entity") or "",
                            fk_lookup,
                        )
                    )
                    else 1
                ),
                e.get("rank", 999),
            ),
        )
        # Type attendu pour scorer les key_cols : si l'utilisateur a écrit
        # des nombres ('70610000'), préférer une col number ; s'il a écrit
        # du texte ('DOSSIER_A PAP'), préférer text/code. Cf. bug fix
        # 2026-05-10 : l'ancien code prenait ``key_cols[0]`` aveuglément,
        # ce qui choisissait ``Dossiers.dosCabinetEntite`` (FK numérique)
        # au lieu de ``Dossiers.dosNomDossier`` (texte) pour ``entité``.
        user_values = c2.get("values") or []
        # P0-D (run #16, 2026-05-30) : rôle-aware. Une mesure SANS valeur
        # exemple attend une colonne number (sinon le tri compat préfère une
        # col texte/libellé → mesure résolue vers un NOM → sommes fausses
        # silencieuses). Les valeurs user typées restent prioritaires.
        expected_type = _phase_2_5_expected_type_for_concept(
            user_values, c2.get("role")
        )

        candidates: list[dict] = []
        for entry in ranking_sorted:
            if not isinstance(entry, dict):
                continue
            entity = entry.get("entity")
            kind = entry.get("kind")
            key_cols = entry.get("key_columns") or []
            # ``kind`` peut être "T"/"V" (Phase 2 actuelle) ou "table"/"view"
            # (variante future) — les 2 acceptés. Les "C" (column) seraient
            # malformés ici (entity = nom de colonne, pas de table) — skip.
            if kind not in ("T", "V", "table", "view"):
                continue
            if not isinstance(entity, str) or not entity:
                continue
            if not isinstance(key_cols, list) or not key_cols:
                continue
            if candidate_tables and entity not in candidate_tables:
                continue
            # Score chaque key_col par compatibilité value_type ↔ expected_type.
            # On garde la mieux scorée pour cette entry. Tie-break = ordre
            # d'origine LLM (préserve la sémantique « la 1re est sa
            # préférée à compatibilité égale »).
            scored: list[dict] = []
            for col_idx, col in enumerate(key_cols):
                if not isinstance(col, str) or not col:
                    continue
                value_type, samples = _cached_lookup(entity, col)
                compat = _phase_2_5_value_type_compatible(value_type, expected_type)
                scored.append(
                    {
                        "col": col,
                        "value_type": value_type,
                        "samples": samples,
                        "compat": compat,
                        "llm_position": col_idx,
                    }
                )
            if not scored:
                continue
            # Tri : compat=True en premier, puis ordre LLM ascendant.
            scored.sort(key=lambda s: (0 if s["compat"] else 1, s["llm_position"]))
            chosen = scored[0]
            # Flag dégradé : aucune col compat (cf. adversarial review
            # SUGGESTION #2). Permet au caller de logger un signal
            # actionnable plutôt qu'un crash Phase 4 générique.
            all_incompat = not any(s["compat"] for s in scored)
            evidence_raw = 100 - entry.get("rank", 99)

            # F5 (task #81) — pénalité role-based pour identifier-of-record.
            # Si la colonne choisie est PK ou FK ET le rôle du concept n'est
            # pas dans `_PHASE_2_5_ROLES_TOLERATING_IDENTIFIER`, on déprioriste
            # cette candidate (× 0.3). Cas typique : concept `temporal`
            # « année » qui matche `proNoEnregMis` (FK numérique pour join)
            # alors qu'il devrait pointer vers `misCodeMillesime` (millésime).
            # Détection PK/FK 100% générique via PRAGMA (pas de regex Sage),
            # cachée par-table (1 PRAGMA / table, pas par candidate).
            # Adversarial fix BLOCKING #5 : type guard sur c2.get("role")
            # (peut être None, bool, int via run.json corrompu) → fallback
            # "unknown" qui est dans `_PHASE_2_5_ROLES_TOLERATING_IDENTIFIER`.
            raw_role = c2.get("role")
            concept_role = raw_role.lower() if isinstance(raw_role, str) else "unknown"
            is_pk_or_fk = _is_cached_pk_or_fk(entity, chosen["col"])
            apply_role_penalty = (
                is_pk_or_fk
                and concept_role not in _PHASE_2_5_ROLES_TOLERATING_IDENTIFIER
            )
            evidence_score = (
                evidence_raw * _PHASE_2_5_IDENTIFIER_OF_RECORD_PENALTY_MULTIPLIER
                if apply_role_penalty
                else evidence_raw
            )

            cand = {
                "table": entity,
                "col": chosen["col"],
                "value_type": chosen["value_type"],
                "samples": chosen["samples"],
                "evidence_score": evidence_score,
                "n_rows": len(chosen["samples"]),
                "_compat": chosen["compat"],
                "_all_incompatible": all_incompat,
                "_original_rank": entry.get("rank", 99),
                "_is_pk_or_fk": is_pk_or_fk,
                "_role_penalty_applied": apply_role_penalty,
                "_concept_role": concept_role,
            }
            candidates.append(cand)
            if len(candidates) >= top_k:
                break

        if not candidates:
            out[cname] = {
                "best": None,
                "top_candidates": [],
                "method": "rerank_fastpath",
                "ambiguous": False,
                # Message actionable (fix L8 2026-05-20).
                "error": (
                    f"Concept '{cname}' : Phase 2 rerank a renvoyé des "
                    f"candidats mais aucun n'a de ``key_columns`` exploitable. "
                    f"C'est probablement un bug du prompt Phase 2 (le LLM "
                    f"oublie les key_columns). Suggestions : (a) demander "
                    f"clarification user, (b) re-exécuter run_pipeline."
                ),
                "warning": None,
            }
            continue

        # Tri INTER-entry : préférer une entry dont au moins une col est
        # compat plutôt qu'une entry rank-1 dont aucune col ne matche.
        # Sans ce tri, si LLM met en rank-1 une table avec key_cols toutes
        # incompatibles et en rank-2 une table avec une col compat, on
        # crashe en Phase 4 alors qu'une alternative existait. Tie-break :
        # rank d'origine LLM (préserve la préférence sémantique).
        # Cf. adversarial review CRITICAL #3.
        # F5 (task #81 + adversarial fix CRITICAL C7) — tri continu via
        # `evidence_score` au lieu d'un bucket binaire {0,1} sur la pénalité.
        # Le tri binaire dégradait à tort : un candidate rank-15 sans pénalité
        # battait un candidate rank-1 pénalisé même si l'écart d'évidence
        # restait en faveur du rank-1 (penalty 0.3× : 99 * 0.3 = 29.7 > 100-15
        # = 85 ? Non : 29.7 < 85, donc rank-15 gagnerait). Avec le tri continu,
        # rank-15 ne gagne QUE si son evidence_score brut surpasse réellement
        # rank-1 ×0.3 → décision proportionnelle, pas catégorique.
        # Critères : (1) compat type, (2) evidence_score DESC (haute→basse),
        # (3) original_rank ASC (tie-break stable).
        candidates.sort(
            key=lambda c: (
                0 if c["_compat"] else 1,
                -float(c.get("evidence_score") or 0),
                c["_original_rank"],
            )
        )

        # T29★ — Dédup par (table, col) AVANT calcul de confiance.
        # Le LLM peut hallucinier la même entry 2× (kind=T puis kind=V sur la
        # même entity, ou doublons explicites dans ranking_top). Sans dédup,
        # le score_gap_pct top1/top2 est biaisé (top-2 = top-1 dupliqué = écart 0%
        # artificiel). On garde la 1re occurrence (meilleur tri pré-fast-path).
        _seen_pairs: set[tuple[str, str]] = set()
        _deduped: list[dict] = []
        for _cand in candidates:
            _key = (_cand.get("table") or "", _cand.get("col") or "")
            if _key in _seen_pairs:
                continue
            _seen_pairs.add(_key)
            _deduped.append(_cand)
        candidates = _deduped

        best_cand = candidates[0]
        # Signal degraded mode : si même la meilleure entry est incompat,
        # on continue avec best_cand (1er ordre LLM rerank) au lieu de
        # crasher Phase 4. Le typage value_type est une HEURISTIQUE
        # d'optimisation, pas une condition de validation : si la table
        # FactureTVA a une col facMontantHT en value_type='number' et que
        # l'utilisateur écrit "montant HT" sans valeur exemple,
        # expected_type tombe à 'text' par défaut (cf.
        # _phase_2_5_user_values_expected_type) → toutes les cols numériques
        # rejetées par le filtre type → ancien comportement = "error" posé
        # → Phase 4 crash IRValidationError → query inutilisable.
        # Nouveau comportement : on pose un ``warning`` observable mais
        # **pas** ``error``. Phase 4 (_ir_resolve_concept) continue avec
        # best_cand. Si le SQL final échoue côté Sage (mauvais type au
        # WHERE/JOIN), le message SQL Server est clair et le flow
        # diagnose+retry est déjà branché — recoverable. Cf. brainstorm
        # GFP 2026-05-20.
        degraded_warning = None
        if not best_cand["_compat"]:
            degraded_warning = (
                f"fast-path dégradé : aucun key_col compatible avec "
                f"expected_type={expected_type!r} "
                f"sur les {len(candidates)} entries du rerank. "
                f"Best candidate retenu malgré tout : "
                f"{best_cand['table']}.{best_cand['col']} "
                f"(value_type={best_cand['value_type']!r})"
            )
            logger.warning(
                "Phase 2.5 fast-path degraded (concept=%r, expected_type=%r): "
                "best_cand=%s.%s value_type=%r — Phase 4 continuera avec ce "
                "candidat (warning non-bloquant)",
                cname,
                expected_type,
                best_cand["table"],
                best_cand["col"],
                best_cand["value_type"],
            )

        # T29★ — Signal de confiance objectif (cf. _compute_phase_2_5_confidence).
        # Si confidence basse, marquer requires_disambiguation pour que Phase 4
        # préflight déclenche le multi-candidate flow (probes oracle + ask user)
        # plutôt qu'un top-1 aveugle.
        confidence_data = _compute_phase_2_5_confidence(
            candidates,
            expected_type=expected_type,
        )
        low_confidence = bool(confidence_data["low_confidence"])
        out[cname] = {
            "best": {"table": best_cand["table"], "col": best_cand["col"]},
            "top_candidates": candidates,
            "method": "rerank_fastpath",
            # ``ambiguous`` reste False ici (preserve l'API legacy de Phase 2.5
            # pour les callers existants). La nouvelle sémantique se lit via
            # ``requires_disambiguation`` ci-dessous.
            "ambiguous": False,
            # ``error`` réservé aux vraies erreurs irrécouvrables (no
            # rerank entry, ranking_top vide, sans key_columns). Le type-
            # incompat n'en est pas une — on remonte un ``warning`` non
            # bloquant que Phase 4 peut ignorer.
            "error": None,
            "warning": degraded_warning,
            # T29★ : score_gap_pct **réel** (anciennement figé à 0.0).
            "score_gap_pct": confidence_data["score_gap_pct"],
            "confidence_score": confidence_data["confidence_score"],
            "low_confidence": low_confidence,
            "confidence_signals": confidence_data["signals"],
            # ``requires_disambiguation`` = low_confidence ET il existe ≥ 2
            # candidats (rien à départager si un seul). Phase 4 préflight lit
            # ce flag pour brancher en mode multi-candidate (cf. T29.C).
            "requires_disambiguation": low_confidence and len(candidates) >= 2,
        }
        # (Pas de trace state-level ici : les readers downstream (Phase 4,
        # pont T3a, tests) lisent directement ``low_confidence`` per-concept.
        # Aucun hack-clé spéciale dans ``out`` — ``out`` reste un dict pur
        # ``{concept_name: resolution_dict}``.)
    return out


def phase_2_5_concept_resolution(
    extracted: dict,
    *,
    komptia_db: Path = KOMPTIA_DB,
    candidate_tables: set[str] | None = None,
    reranks_per_concept: dict | None = None,
    debug_traces: bool = False,
) -> dict:
    """Phase 2.5 — Résout chaque concept_v2 en (table, col) data-driven.

    Inputs :
        - ``extracted`` : output Phase 1.1+1.2 (avec ``concepts_v2``,
          ``values_inline_lists``, ``groupes``)
        - ``candidate_tables`` : optionnel, restreint le scope aux tables
          shortlistées par Phase 1.5 (rerank). None = toutes les tables.
        - ``reranks_per_concept`` : optionnel, ``state.reranks["per_concept"]``
          (Phase 2 output). Si fourni, **fast-path** (cf.
          ``_phase_2_5_resolve_from_reranks``) — 0 query value_mapping
          coûteuse, juste lookups indexés. Concepts non couverts par les
          reranks fallback sur l'ancienne méthode LIKE % (lente mais correcte).
          Si None, comportement legacy (toutes résolutions via LIKE %, lent
          sur grosse value_mapping).

    Output :
        ``{"concept_resolution": {...}, "trace_text": "...", "stats": {...}}``

    **0 LLM call**, **0 probe Sage**. Lookups SQLite ``value_mapping``
    minimaux quand reranks_per_concept fourni.
    """
    if not komptia_db.exists():
        return {
            "concept_resolution": {},
            "trace_text": f"Phase 2.5 — komptia.db absent ({komptia_db})",
            "stats": {"resolved": 0, "ambiguous": 0, "errors": 0},
        }

    concepts_v2 = extracted.get("concepts_v2", []) or []
    if not concepts_v2:
        return {
            "concept_resolution": {},
            "trace_text": "Phase 2.5 — concepts_v2 vide (Phase 1 V2 incomplet ?)",
            "stats": {"resolved": 0, "ambiguous": 0, "errors": 0},
        }

    # Expansions Phase 1.2 par concept (pour name-match).
    expansions_per_concept: dict[str, list[str]] = {}
    term_origins = extracted.get("term_origins", {}) or {}
    for term, parents in term_origins.items():
        for parent in parents or []:
            expansions_per_concept.setdefault(parent, []).append(term)

    out: list[str] = []
    out.append("=" * 100)
    out.append("PHASE 2.5 — CONCEPT RESOLUTION (data-driven, 0 LLM, 0 Sage probe)")
    out.append("=" * 100)
    out.append(f"\nConcepts à résoudre : {len(concepts_v2)}")
    out.append(f"Source corpus : {komptia_db.name} (table value_mapping)")
    if candidate_tables:
        out.append(f"Filtre tables candidates : {len(candidate_tables)} tables")

    con = sqlite3.connect(f"file:{komptia_db}?mode=ro", uri=True)
    try:
        resolution: dict[str, dict] = {}
        n_resolved = 0
        n_ambiguous = 0
        n_errors = 0

        # Fast-path : si reranks dispo, résoudre via Phase 2 reranks
        # (key_columns) au lieu de LIKE % full-scan. Compatible : si un
        # concept n'est pas couvert par reranks, fallback à l'ancien
        # `_resolve_concept`.
        # On charge fk_lookup ENRICHI vues (W2.3) pour que le fast-path
        # considère les vues comme joignables (les tables sources de la
        # vue propagent leurs FKs). Sans ça, viewMissions03 serait
        # rétrogradée comme "non-joignable" alors qu'elle expose les FKs
        # de Missions.
        fk_lookup_for_fastpath = get_fk_lookup_from_db_with_views(SAGE_DB)
        fastpath_resolutions: dict[str, dict] = {}
        if reranks_per_concept:
            fastpath_resolutions = _phase_2_5_resolve_from_reranks(
                concepts_v2,
                reranks_per_concept,
                con,
                candidate_tables=candidate_tables,
                fk_lookup=fk_lookup_for_fastpath,
            )
            n_fast = sum(1 for r in fastpath_resolutions.values() if r.get("best"))
            n_fast_fail = len(fastpath_resolutions) - n_fast
            out.append(
                f"\nFast-path rerank : {n_fast}/{len(fastpath_resolutions)} "
                f"concepts résolus directement ({n_fast_fail} fallback LIKE %)"
            )

        # Si fast-path actif (reranks fournis), pas de fallback LIKE %
        # par défaut : un concept manqué par les reranks = bug amont à
        # corriger côté Phase 2 (rerank LLM), pas à masquer ici via un
        # full-scan 29M lignes qui peut prendre 10+ min par concept. On
        # marque simplement l'erreur.
        # Si fast-path INACTIF (pas de reranks), comportement legacy
        # (full LIKE %) — peut être lent mais c'est l'option de secours.
        for c2 in concepts_v2:
            if not isinstance(c2, dict):
                continue
            cname = c2.get("name")
            if not isinstance(cname, str) or not cname:
                continue
            fast_res = fastpath_resolutions.get(cname)
            if fast_res and fast_res.get("best"):
                res = fast_res
                print(f"  → {cname}: rerank fast-path OK", flush=True)
            elif fast_res and fast_res.get("is_derived"):
                # P0-B (2026-05-30) — concept DÉRIVÉ : pas de ``best`` (il se
                # compose, pas de colonne) MAIS ce n'est PAS un échec. On garde
                # le statut derivation tel quel (sinon il serait écrasé en
                # ``rerank_fastpath_failed`` → exclu de l'enum Phase 4 → la
                # dérivation ne peut jamais être composée, bug du run #16).
                res = fast_res
                print(f"  → {cname}: mesure dérivée (composée en Phase 4)", flush=True)
            elif fastpath_resolutions:
                # Fast-path actif mais ce concept n'a pas matché.
                # Pas de LIKE % fallback : on documente l'erreur.
                err = (fast_res or {}).get("error", "no rerank entry for concept")
                res = {
                    "best": None,
                    "top_candidates": [],
                    "method": "rerank_fastpath_failed",
                    "ambiguous": False,
                    "error": err,
                }
                print(
                    f"  ⚠ {cname}: rerank fast-path FAILED ({err}) — "
                    f"concept non résolu (Phase 2 rerank à enrichir)",
                    flush=True,
                )
            else:
                # Mode legacy : fast-path inactif, fallback LIKE % d'origine.
                print(f"  → {cname}: legacy LIKE % (lent)...", flush=True)
                res = _resolve_concept(
                    con,
                    c2,
                    expansions_per_concept,
                    candidate_tables=candidate_tables,
                )
            resolution[cname] = res
            if res.get("error"):
                n_errors += 1
            elif res.get("best"):
                n_resolved += 1
                if res.get("ambiguous"):
                    n_ambiguous += 1

            # Trace lisible.
            method = res.get("method", "?")
            best = res.get("best")
            best_str = f"{best['table']}.{best['col']}" if best else "(aucun)"
            gap = res.get("score_gap_pct", 0.0)
            ambig_marker = " ⚠️ AMBIGU" if res.get("ambiguous") else ""
            err = res.get("error")
            err_str = f" ❌ {err}" if err else ""
            out.append(
                f"\n  [{cname}] role={c2.get('role')} value_kind={c2.get('value_kind')} "
                f"-> {best_str} (method={method} gap={gap}%){ambig_marker}{err_str}"
            )
            for i, cand in enumerate(res.get("top_candidates", [])[:3]):
                samples_str = ", ".join(str(s) for s in cand.get("samples", [])[:3])
                if samples_str:
                    samples_str = f" | samples=[{samples_str}]"
                n_rows_str = f" rows={cand.get('n_rows')}" if "n_rows" in cand else ""
                name_score_str = (
                    f" name_score={cand.get('name_score')}" if "name_score" in cand else ""
                )
                out.append(
                    f"      #{i+1} {cand['table']}.{cand['col']} "
                    f"score={cand.get('evidence_score', 0)}{n_rows_str}{name_score_str}{samples_str}"
                )

    finally:
        con.close()

    # T29★ — Stats supplémentaires sur la confiance.
    n_low_conf = sum(1 for r in resolution.values() if r.get("low_confidence") is True)
    n_requires_disambig = sum(
        1 for r in resolution.values() if r.get("requires_disambiguation") is True
    )
    stats = {
        "resolved": n_resolved,
        "ambiguous": n_ambiguous,
        "errors": n_errors,
        "total": len(concepts_v2),
        "low_confidence": n_low_conf,
        "requires_disambiguation": n_requires_disambig,
    }
    out.append(
        f"\n{'─' * 80}\n"
        f"RÉSUMÉ : {n_resolved}/{len(concepts_v2)} résolus | "
        f"{n_ambiguous} ambigus (gap top1-top2 < 15%) | "
        f"{n_low_conf} confiance basse (T29★) | "
        f"{n_requires_disambig} disambiguation requise | "
        f"{n_errors} erreurs"
    )
    trace_text = "\n".join(out)

    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_2_5_concept_resolution.txt").write_text(
            trace_text,
            encoding="utf-8",
        )

    return {
        "concept_resolution": resolution,
        "trace_text": trace_text,
        "stats": stats,
    }


# ─────────────────────────────────────────────────────────────────────
# PHASE 5 NEW — IR → SQL Composer (100% Python, 0 LLM)
# ─────────────────────────────────────────────────────────────────────
#
# Compose un T-SQL exécutable à partir d'un Intermediate Representation
# (IR) JSON conceptuel + ``concept_resolution`` (Phase 2.5).
#
# **Pourquoi un composer Python pur** : rend les bugs A/B/C/F/G/H
# **impossibles par construction** :
#   - Pas de colonne hallucinée : le composer ne peut référencer que
#     les ``(table, col)`` fournies par concept_resolution
#   - Pas d'expression SELECT dupliquée : validation pré-composition
#     (alias + sémantique unique)
#   - Pas de filtre destructeur : Phase 2.5 a déjà disqualifié les
#     colonnes 99%+ NULL
#   - Pas d'op-type mismatch : matrice typée
#   - Pas de JOIN cartésien implicite : chemin FK calculé déterministique
#
# **0 hardcode BDD** : aucun nom de table/colonne dans le code. Tout
# vient de concept_resolution + DDL SQLite mirror.
#
# **Schéma IR** (Python dict, validé par `_ir_validate`) :
#
# ir = {
#   "select": [
#     {"alias": "<str>", "concept": "<concept_name>",
#      "agg": "sum|avg|count|min|max|none",
#      "filters": [{"concept", "op", "val"}, ...]   # filtres conditionnels (CASE)
#     },
#     {"alias": "<str>", "derivation": {
#         "op": "subtract|add|multiply|divide",
#         "left": {"select_ref": "<alias>"} | {<inline select_item>},
#         "right": ...
#     }},
#   ],
#   "from_concept": "<concept_name>",        # concept racine (FROM)
#   "filters_global": [{"concept", "op", "val"}, ...],
#   "group_by_concepts": ["<concept_name>", ...],
#   "order_by": [{"concept_or_alias": "<str>", "direction": "ASC|DESC"}],
#   "limit": <int> | null,
# }


_IR_VALID_AGGS: tuple[str, ...] = (
    "sum",
    "avg",
    "count",
    "min",
    "max",
    "none",
    # Task #100 — REFONTE-L2 primitive 1 (2026-05-22) : string_agg ordonné.
    # Émet ``STRING_AGG(DISTINCT col, sep) WITHIN GROUP (ORDER BY col)`` en
    # T-SQL — résout précisément l'hallucination du run #201 où Iris écrit
    # ``STRING_AGG(DISTINCT col) WITHIN GROUP`` mais oublie le `ORDER BY`
    # ou compose une syntaxe non supportée. Voir ``_ir_render_string_agg``
    # pour les options ``string_agg_options`` admises.
    "string_agg",
)


def _ir_render_string_agg(
    inner_expr: str,
    item: dict,
    concept_resolution: dict,
    table_alias: dict,
) -> str:
    """Compose un ``STRING_AGG(DISTINCT col, sep) WITHIN GROUP (ORDER BY ...)``
    valide T-SQL à partir d'un select item IR.

    Options reconnues dans ``item.get("string_agg_options")`` (dict optionnel) :
    - ``separator`` (str, défaut ``", "``) — séparateur entre éléments
    - ``distinct`` (bool, défaut ``True``) — applique DISTINCT
    - ``order_by`` (str | None, défaut = même que ``concept``) — concept ou
      ``column`` à utiliser pour le ORDER BY WITHIN GROUP. Si None, fallback
      sur ``inner_expr`` (équivalent à ORDER BY sur la colonne agrégée).

    Args:
        inner_expr : expression SQL déjà composée pour la colonne à agréger
            (typiquement ``T0.[colCodeCollabo]`` ou un CASE WHEN ...).
        item : le select item IR — pour récupérer string_agg_options.
        concept_resolution : pour résoudre order_by si c'est un concept name.
        table_alias : pour qualifier order_by si c'est un concept name.

    Génère du T-SQL valide qui ne peut PAS halluciner la syntaxe (ce que
    Iris a fait sur le run #201). Le LLM IR fournit seulement les
    options, jamais le SQL natif.

    Garde-fous :
    - separator est échappé pour éviter SQL injection (quotes doublées).
    - ORDER BY est obligatoire en T-SQL après WITHIN GROUP — si options
      n'en fournit pas, fallback sur inner_expr.
    """
    opts = item.get("string_agg_options") or {}
    if not isinstance(opts, dict):
        raise IRValidationError(
            f"string_agg_options doit être un dict (reçu {type(opts).__name__})"
        )

    # Separator (échappement quotes T-SQL : ' → '')
    separator = opts.get("separator", ", ")
    if not isinstance(separator, str):
        raise IRValidationError(
            f"string_agg_options.separator doit être str (reçu {type(separator).__name__})"
        )
    sep_escaped = separator.replace("'", "''")

    distinct = bool(opts.get("distinct", True))
    distinct_kw = "DISTINCT " if distinct else ""

    # ORDER BY — concept name OU expression brute OU fallback sur inner_expr.
    order_by_spec = opts.get("order_by")
    if order_by_spec:
        # Tente de résoudre comme concept name (préféré — type-safe)
        if isinstance(order_by_spec, str) and order_by_spec in concept_resolution:
            ob_table, ob_col, _vt = _ir_resolve_concept(
                order_by_spec, concept_resolution
            )
            ob_alias = _ir_alias_for(order_by_spec, ob_table, table_alias)
            order_by_sql = (
                f"{_ir_quote_sql_identifier(ob_alias)}."
                f"{_ir_quote_sql_identifier(ob_col)}"
            )
        elif isinstance(order_by_spec, str):
            # Concept inconnu — interdire pour éviter SQL injection / hallucination
            raise IRValidationError(
                f"string_agg_options.order_by '{order_by_spec}' n'est pas dans "
                f"concept_resolution. Utiliser un concept name valide."
            )
        else:
            raise IRValidationError(
                f"string_agg_options.order_by doit être un concept name (str), "
                f"reçu {type(order_by_spec).__name__}"
            )
    else:
        # Fallback : ORDER BY sur l'inner_expr (= la colonne agrégée elle-même).
        # T-SQL exige un ORDER BY dans WITHIN GROUP — sans, syntax error.
        order_by_sql = inner_expr

    return (
        f"STRING_AGG({distinct_kw}{inner_expr}, '{sep_escaped}') "
        f"WITHIN GROUP (ORDER BY {order_by_sql})"
    )


def _ir_render_partition_by_set(
    item: dict,
    concept_resolution: dict,
    table_alias: dict,
) -> tuple[str, str]:
    """Compose le SQL CASE WHEN pour ``partition_by_set`` — primitive 3/4
    task #100.

    Sémantique : ventiler une mesure selon que la valeur d'un autre
    concept appartient ou non à un **ensemble explicite** (IN ou NOT IN).

    Cas d'usage canonique du run #201 : « production des chefs de mission
    vs production des autres collaborateurs » — où « chefs de mission »
    est une liste fermée de 22 codes. Sans cette primitive, le LLM Iris
    a généré une CTE avec ``UNION ALL SELECT`` de 22 valeurs littérales
    + un LEFT JOIN — beaucoup de bruit pour une logique simple
    « collaborateur IN (liste) ».

    Spec attendue (à l'intérieur d'un select item agg standard) :
        ``item["partition_by_set"]`` = ``{
            "set_name": "chefs_mission",         # libellé documentaire
            "values": ["alpha", "bravo", ...], # liste de littéraux
            "on_concept": "collaborateur_code",  # concept à comparer
            "membership": "in" | "not_in"        # défaut "in"
        }``

    Retourne ``(case_expr_sql, agg_safe)`` où :
    - ``case_expr_sql`` est le ``CASE WHEN <membership> THEN <value> ELSE
      <neutral> END`` prêt à être wrapé par l'agg.
    - ``agg_safe`` est l'agg effectif compatible (passé tel quel, sauf si
      l'agg appelant est ``none`` — alors on retourne juste le case).

    Le caller (``_ir_render_select_item``) wrap ensuite dans
    ``SUM(...)`` / ``COUNT(...)`` etc. selon ``item["agg"]``.

    Garde-fous :
    - ``on_concept`` doit être dans concept_resolution (anti-hallucination)
    - ``values`` doit être une liste non vide
    - ``membership`` doit être ``"in"`` ou ``"not_in"``
    - Chaque valeur de ``values`` est échappée (T-SQL '' doublé) pour
      éviter SQL injection
    """
    spec = item.get("partition_by_set") or {}
    if not isinstance(spec, dict):
        raise IRValidationError(
            f"partition_by_set doit être un dict (reçu {type(spec).__name__})"
        )
    on_concept = spec.get("on_concept")
    if not on_concept or not isinstance(on_concept, str):
        raise IRValidationError(
            "partition_by_set.on_concept doit être un concept name (str non vide)"
        )
    values = spec.get("values")
    if not isinstance(values, list) or not values:
        raise IRValidationError(
            "partition_by_set.values doit être une liste non vide"
        )
    membership = (spec.get("membership") or "in").lower()
    if membership not in ("in", "not_in"):
        raise IRValidationError(
            f"partition_by_set.membership doit être 'in' ou 'not_in', "
            f"reçu {membership!r}"
        )

    # Résoudre on_concept
    on_table, on_col, _vt = _ir_resolve_concept(on_concept, concept_resolution)
    on_alias = _ir_alias_for(on_concept, on_table, table_alias)
    on_qualified = (
        f"{_ir_quote_sql_identifier(on_alias)}."
        f"{_ir_quote_sql_identifier(on_col)}"
    )

    # Échappement des littéraux. Pour anti-SQL-injection : doubler les
    # apostrophes (convention T-SQL) + refuser les non-strings/non-numeric
    # qui pourraient indiquer une injection structurelle.
    escaped_values: list[str] = []
    for v in values:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            escaped_values.append(str(v))
        elif isinstance(v, str):
            escaped_values.append("'" + v.replace("'", "''") + "'")
        else:
            raise IRValidationError(
                f"partition_by_set.values : type {type(v).__name__} non supporté "
                f"(valeur {v!r}). Utilisez str ou int."
            )
    in_clause = ", ".join(escaped_values)
    membership_op = "IN" if membership == "in" else "NOT IN"

    # Résoudre la mesure (value concept) — le caller a déjà validé que
    # ``item["concept"]`` existe.
    value_concept = item.get("concept")
    if not value_concept:
        raise IRValidationError(
            "partition_by_set : item.concept (la mesure à agréger) est requis"
        )
    val_table, val_col, _vvt = _ir_resolve_concept(value_concept, concept_resolution)
    val_alias = _ir_alias_for(value_concept, val_table, table_alias)
    val_qualified = (
        f"{_ir_quote_sql_identifier(val_alias)}."
        f"{_ir_quote_sql_identifier(val_col)}"
    )

    agg = (item.get("agg") or "none").lower()
    # Élément neutre : 0 pour sum/count (additif), NULL pour min/max/avg
    # (préserve la sémantique : pas faux-positif sur 0 si le concept
    # accepte des vraies valeurs nulles).
    else_value = "0" if agg in ("sum", "count") else "NULL"
    case_expr = (
        f"CASE WHEN {on_qualified} {membership_op} ({in_clause}) "
        f"THEN {val_qualified} ELSE {else_value} END"
    )
    return case_expr, agg


def _ir_render_version_fallback(
    item: dict,
    concept_resolution: dict,
    table_alias: dict,
    fk_lookup: dict | None = None,
) -> str:
    """Compose le SQL pour ``version_fallback`` — primitive 2/4 task #100.

    Sémantique : « prends la valeur du concept selon le 1er filtre qui
    produit non-NULL, puis fallback sur le 2e, etc. ».

    Cas d'usage canonique du run #201 : « expert-comptable signataire =
    version millésime 2024 si existe, sinon 2023 ». Sans cette primitive,
    le LLM Iris a généré ``ORDER BY dopNoEnreg DESC`` (assume que le
    DossierSuppl le plus récent par ID = celui de 2024 — assomption
    fausse silencieusement).

    Spec attendue :
        ``item["version_fallback"]`` = ``{
            "value_concept": "expert_comptable",   # concept à récupérer
            "versions": [                          # 1+ filtres ordonnés
                {"filter": {"concept": "millesime", "op": "=", "val": "2024"}},
                {"filter": {"concept": "millesime", "op": "=", "val": "2023"}},
                # ... N versions
            ]
        }``

    Émet en T-SQL :
        ``COALESCE(
            MAX(CASE WHEN <f1> THEN <T>.<col> ELSE NULL END),
            MAX(CASE WHEN <f2> THEN <T>.<col> ELSE NULL END),
            ...
        )``

    L'idiome ``MAX(CASE WHEN cond THEN val ELSE NULL END)`` est l'approche
    standard pour « valeur conditionnelle dans un GROUP BY » (préserve
    NULL si cond=False). COALESCE prend le 1er non-NULL.

    Garde-fous (anti-hallucination, anti-SQL-injection) :
    - ``value_concept`` doit être dans concept_resolution (pas de SQL natif)
    - ``versions`` doit être une liste non vide
    - chaque ``filter`` est validé par ``_ir_render_filter`` (même
      validation que les filtres standard de l'IR)
    """
    spec = item.get("version_fallback") or {}
    if not isinstance(spec, dict):
        raise IRValidationError(
            f"version_fallback doit être un dict (reçu {type(spec).__name__})"
        )
    value_concept = spec.get("value_concept")
    if not value_concept or not isinstance(value_concept, str):
        raise IRValidationError(
            "version_fallback.value_concept doit être un concept name (str non vide)"
        )
    versions = spec.get("versions")
    if not isinstance(versions, list) or not versions:
        raise IRValidationError(
            "version_fallback.versions doit être une liste non vide "
            "(au moins 1 version)"
        )

    # Résoudre la colonne valeur via concept_resolution
    value_table, value_col, _vt = _ir_resolve_concept(value_concept, concept_resolution)
    value_alias = _ir_alias_for(value_concept, value_table, table_alias)
    qualified_value = (
        f"{_ir_quote_sql_identifier(value_alias)}."
        f"{_ir_quote_sql_identifier(value_col)}"
    )

    # Pour chaque version, émettre MAX(CASE WHEN <filter> THEN val ELSE NULL END)
    branches: list[str] = []
    for idx, version in enumerate(versions):
        if not isinstance(version, dict):
            raise IRValidationError(
                f"version_fallback.versions[{idx}] doit être un dict, "
                f"reçu {type(version).__name__}"
            )
        f = version.get("filter")
        if not isinstance(f, dict):
            raise IRValidationError(
                f"version_fallback.versions[{idx}].filter doit être un "
                f"filter dict (concept/op/val), reçu {type(f).__name__}"
            )
        # Réutilise le renderer de filter standard de l'IR (compound OK :
        # any_of/all_of/not). Pas de SQL natif possible — toute condition
        # passe par _ir_render_filter qui valide les concepts et les ops.
        cond_sql = _ir_render_filter(
            f,
            concept_resolution,
            table_alias,
            fk_lookup=fk_lookup,
        )
        branches.append(
            f"MAX(CASE WHEN {cond_sql} THEN {qualified_value} ELSE NULL END)"
        )

    if len(branches) == 1:
        # Optimisation : pas besoin de COALESCE si 1 seule version
        return branches[0]
    return f"COALESCE({', '.join(branches)})"
_IR_VALID_OPS: tuple[str, ...] = (
    "=",
    "!=",
    "<>",
    "<",
    ">",
    "<=",
    ">=",
    "IN",
    "NOT_IN",
    "LIKE",
    "NOT_LIKE",
    "IS_NULL",
    "IS_NOT_NULL",
    "EXISTS",
    "NOT_EXISTS",
)
_IR_VALID_DERIV_OPS: tuple[str, ...] = ("subtract", "add", "multiply", "divide")
_IR_VALID_DIRECTIONS: tuple[str, ...] = ("ASC", "DESC")

# F4 (2026-05-21) — Window functions génériques SQL standard. Permet
# d'exprimer YoY/MoM/Top-N-par-groupe SANS pattern analytique hardcodé.
# Le composer rend ces fonctions via OVER(PARTITION BY ... ORDER BY ...).
_IR_VALID_WINDOW_FNS: tuple[str, ...] = (
    "lag",
    "lead",
    "row_number",
    "rank",
    "dense_rank",
)
# Window functions qui prennent un argument `expr` (vs row_number/rank/dense_rank
# qui n'en prennent pas). lag/lead acceptent aussi offset (défaut 1) et default.
_IR_WINDOW_FNS_REQUIRE_EXPR: frozenset[str] = frozenset({"lag", "lead"})

# Phase Z.1 — profondeur max des compound filters all_of/any_of/not (anti-DoS).
# FIX F10 (adversarial review) — 4 niveaux suffisent largement pour toute
# requête analytique réaliste. 10 était trop laxiste (combiné à maxItems=50
# du schéma JSON, autorisait des IR pathologiques de 50⁴+ filtres).
_IR_COMPOUND_MAX_DEPTH: int = 4

# Matrice op × value_type — quels op sont compatibles avec quels types.
# Generic SQL standard, pas BDD-spécifique.
_IR_OP_TYPE_MATRIX: dict[str, set[str]] = {
    "=": {"text", "code", "number", "date"},
    "!=": {"text", "code", "number", "date"},
    "<>": {"text", "code", "number", "date"},
    "<": {"number", "date"},
    ">": {"number", "date"},
    "<=": {"number", "date"},
    ">=": {"number", "date"},
    "IN": {"text", "code", "number", "date"},
    "NOT_IN": {"text", "code", "number", "date"},
    "LIKE": {"text", "code"},
    "NOT_LIKE": {"text", "code"},
    "IS_NULL": {"text", "code", "number", "date"},
    "IS_NOT_NULL": {"text", "code", "number", "date"},
}


class IRValidationError(ValueError):
    """L'IR ne respecte pas le schéma. Levée AVANT toute composition SQL."""


class EmptySelectError(IRValidationError):
    """Sous-type d'``IRValidationError`` : l'IR a un ``select`` vide/manquant.

    C'est le symptôme typique d'une mesure centrale non résolue (run #16 :
    rentabilité non composée → aucun item dans le select). On le distingue des
    autres erreurs structurelles d'IR (alias dupliqué, item malformé...) pour
    que ``_phase4_convert_ir_error`` ne convertisse en ``ConceptUnresolvedError``
    recoverable QUE ce cas dégénéré — et NE masque PAS un vrai bug structurel
    (cf. adversarial review F1). Reste une ``IRValidationError`` : tous les
    ``except IRValidationError`` existants continuent de la catcher.
    """


class ConceptUnresolvedError(IRValidationError):
    """Sous-type d'``IRValidationError`` levé quand un concept n'a pas été
    résolu par Phase 2.5 (best=None ou error posé).

    Permet aux callers de catch spécifiquement ce cas et de proposer une
    récupération graceful — typiquement appeler ``ask_user_clarification``
    pour demander à l'utilisateur de préciser le concept manquant, plutôt
    que de crasher l'ensemble de la pipeline (cf. run #7 2026-05-20 où
    'montant TTC' faisait planter toute la pipeline).

    Attribut ``concept_name`` exposé pour permettre au caller de cibler
    sa recovery sur le bon concept.

    Note (introduit 2026-05-20 dans le cadre du fix L8) : aujourd'hui les
    12+ call-sites de ``_ir_resolve_concept`` lèvent cette exception qui
    n'est PAS encore catchée par les callers en amont (qui voient juste
    un ``IRValidationError`` standard via héritage). Pose les fondations
    pour un futur ``try ... except ConceptUnresolvedError → ask_user``
    sans casser le comportement actuel (héritage = compat totale).
    """

    def __init__(self, message: str, *, concept_name: str = ""):
        super().__init__(message)
        self.concept_name = concept_name


def _ir_quote_sql_identifier(name: str) -> str:
    """Échappe un identifiant SQL Server (table/colonne/alias) en ``[name]``.

    Refuse les ``]`` dans le nom (anti-injection T-SQL). Generic.
    """
    if not isinstance(name, str) or not name:
        raise IRValidationError(f"empty/non-str identifier: {name!r}")
    if "]" in name or "[" in name:
        raise IRValidationError(f"forbidden char in identifier: {name!r}")
    if any(unicodedata.category(ch).startswith("C") for ch in name):
        raise IRValidationError(f"control char in identifier: {name!r}")
    return f"[{name}]"


_NUMBER_LITERAL_RE = re.compile(r"^-?\d+(\.\d+)?$")
# Caractères Unicode invisibles à refuser même hors catégorie C : line/paragraph
# separators (Zl/Zp), BOM, ZWSP, RTL/LTR overrides. Vecteur classique d'attaques
# anti-WAF sur les literals SQL — cf. CVE multiples sur drivers ODBC.
_INVISIBLE_FORBIDDEN_CODEPOINTS = frozenset(
    {
        0x2028,
        0x2029,  # Line/Paragraph Separator (catégorie Zl/Zp)
        0xFEFF,  # Byte Order Mark / Zero Width No-Break Space
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,  # ZWSP / ZWJ / ZWNJ / LRM / RLM
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,  # LRE/RLE/PDF/LRO/RLO
    }
)


def _ir_quote_sql_literal(value, value_type: str) -> str:
    """Sérialise une valeur en T-SQL literal sûre.

    Escape les quotes simples (doublage standard SQL Server). Numeric/date
    sérialisés selon le type.

    **Anti-injection (cf. adversarial review)** :
    - Catégorie Unicode C (controls/format/surrogate) refusée
    - Catégorie Z séparateurs invisibles (U+2028/2029) refusée
    - BOM, ZWSP, RTL/LTR overrides refusés explicitement par codepoint
    - Number serialisé via str-regex (préserve la précision décimale, pas float)

    **Note dialecte** : sortie T-SQL SQL Server. Quoting ``''``, dates en
    string ISO 8601 entre quotes simples. Pour Postgres/MySQL, un dialect
    ABC sera nécessaire (cf. issue ouverte ``IR_DIALECT_ABSTRACTION``).
    """
    if value is None:
        return "NULL"
    if value_type == "number":
        # Préserve la précision décimale : on lit la string telle quelle
        # plutôt que de passer par float (qui perd 17+ digits significatifs).
        s = str(value).strip()
        if not _NUMBER_LITERAL_RE.match(s):
            raise IRValidationError(f"value {value!r} not number-castable")
        return s
    if value_type == "date":
        s = str(value).strip()
        if not _TEMPORAL_VALUE_RE.match(s):
            raise IRValidationError(f"date value {value!r} not ISO 8601 (YYYY[-MM[-DD]])")
        return f"'{s}'"
    # Text / code → escape quotes simples (T-SQL).
    raw = str(value)
    # Pre-check Unicode hostile chars AVANT escape (sinon escape masque l'audit).
    for ch in raw:
        if unicodedata.category(ch).startswith("C"):
            raise IRValidationError(f"control char in literal: {value!r}")
        if ord(ch) in _INVISIBLE_FORBIDDEN_CODEPOINTS:
            raise IRValidationError(
                f"forbidden invisible char U+{ord(ch):04X} in literal: {value!r}"
            )
    return "'" + raw.replace("'", "''") + "'"


def _ir_resolve_concept(
    concept_name: str,
    concept_resolution: dict,
) -> tuple[str, str, str]:
    """Résout un concept en ``(table, col, value_type)`` via concept_resolution.

    Lève IRValidationError si :
        - concept absent
        - best=None (ambiguous ou no candidates)
        - error présent (Phase 2.5 a fail-fast)

    **Phase Z.5 — vues SQL pré-jointes** : ``best.table`` peut être un nom
    de vue (ex: ``viewGroupes01``, ``viewMissions03``) au lieu d'une table
    physique. Le composer utilise ce nom verbatim dans le SQL — la BDD cible
    résout la vue. Pour les FKs, ``fk_lookup`` doit contenir une entry pour
    la vue (mêmes FKs que la table sous-jacente) ; le composer ne propage
    pas automatiquement (responsabilité du caller, ex. ``schema_sync.py``
    enrichit fk_lookup avec les vues détectées).

    Generic : aucun pattern lexical sur ``view*``. Côté composer, vue =
    table. Le routage est porté par concept_resolution + fk_lookup.
    """
    if not isinstance(concept_name, str) or not concept_name:
        raise IRValidationError(f"empty/non-str concept name: {concept_name!r}")
    cr = concept_resolution.get(concept_name)
    if not cr:
        raise IRValidationError(
            f"concept '{concept_name}' absent de concept_resolution. "
            f"Phase 2.5 ne l'a pas résolu — vérifier extracted.concepts_v2."
        )
    if cr.get("error"):
        # Sous-type ConceptUnresolvedError : permet aux callers futurs de
        # catch spécifiquement ce cas et de proposer ask_user_clarification
        # plutôt que de crasher la pipeline (cf. L8 et la fondation posée
        # par la classe). Aujourd'hui se comporte comme IRValidationError
        # via héritage — 0 changement de comportement, juste un sous-type.
        raise ConceptUnresolvedError(
            f"concept '{concept_name}' a une erreur Phase 2.5 : {cr['error']}",
            concept_name=concept_name,
        )
    best = cr.get("best")
    if not best:
        raise ConceptUnresolvedError(
            f"concept '{concept_name}' sans best "
            f"(ambiguity={cr.get('ambiguous')}, "
            f"top_candidates={len(cr.get('top_candidates', []))}). "
            f"Le LLM Iris peut soit demander clarification user pour ce "
            f"concept, soit le retirer de la requête s'il est secondaire.",
            concept_name=concept_name,
        )
    table = best.get("table")
    col = best.get("col")
    if not table or not col:
        raise ConceptUnresolvedError(
            f"concept '{concept_name}' best malformé : {best!r}",
            concept_name=concept_name,
        )
    # Récupère le value_type depuis le top candidate (fallback "text").
    value_type = "text"
    for cand in cr.get("top_candidates", []) or []:
        if cand.get("table") == table and cand.get("col") == col:
            value_type = cand.get("value_type") or "text"
            break
    return (table, col, value_type)


def _ir_alias_for(
    concept: str,
    table: str,
    alias_map: dict[str, str],
) -> str:
    """Phase Z.3 — résout l'alias SQL pour un concept.

    Priorité : ``alias_map[concept]`` (self-join via ``role_hint``) >
    ``alias_map[table]`` (legacy partage par table) > nom de la table.

    Permet à 2 concepts différents de partager la même table physique avec des
    aliases distincts (ex: ``dossier_facture`` AS T0 + ``dossier_entite`` AS T1).
    """
    if concept and concept in alias_map:
        return alias_map[concept]
    return alias_map.get(table, table)


def _ir_render_filter(
    flt: dict,
    concept_resolution: dict,
    table_alias: dict[str, str],
    _depth: int = 0,
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """Rend un filtre `{concept, op, val}` en T-SQL ``[alias].[col] OP val``.

    Op-type matrix appliquée → `IRValidationError` si op incompatible
    avec value_type de la colonne.

    Phase Z.1 — supporte compound filters récursifs :
        - ``{"all_of": [<filter>, ...]}`` → ``(f1) AND (f2) AND ...``
        - ``{"any_of": [<filter>, ...]}`` → ``(f1) OR (f2) OR ...``
        - ``{"not": <filter>}`` → ``NOT (f)``
    Profondeur récursive bornée par ``_IR_COMPOUND_MAX_DEPTH`` (anti-DoS).
    Liste vide refusée (anti-faux-silencieux : ``()`` produirait SQL ambigu).

    Phase Z.4 — supporte ``EXISTS`` / ``NOT_EXISTS`` (subquery filter avec
    corrélation FK auto). Format ::

        {"op": "EXISTS"|"NOT_EXISTS",
         "subquery": {"from_concept": "<inner>", "filters": [...]},
         "correlate_via_fk": {"outer_concept": "<>", "inner_concept": "<>"}}

    ``fk_lookup`` requis quand un EXISTS/NOT_EXISTS est utilisé (sinon
    impossible de résoudre la corrélation).
    """
    if not isinstance(flt, dict):
        raise IRValidationError(f"filter doit être un dict, got {type(flt).__name__}: {flt!r}")

    # ── Compound filters (Z.1) : récursion contrôlée ──
    compound_keys = [k for k in ("all_of", "any_of", "not") if k in flt]
    if compound_keys:
        if _depth > _IR_COMPOUND_MAX_DEPTH:
            raise IRValidationError(
                f"compound filter dépasse profondeur {_IR_COMPOUND_MAX_DEPTH} "
                f"(pathologic IR). Aplatir la structure."
            )
        if len(compound_keys) > 1:
            raise IRValidationError(
                f"compound filter doit contenir exactement UN de "
                f"all_of/any_of/not. Got: {compound_keys}"
            )
        op_kind = compound_keys[0]
        if op_kind == "not":
            sub = flt["not"]
            if not isinstance(sub, dict):
                raise IRValidationError(
                    f"compound 'not' requiert un dict filter, got " f"{type(sub).__name__}: {sub!r}"
                )
            # FIX C1 (adversarial review) — propager fk_lookup au sub-filter
            # pour permettre `not(EXISTS(...))` (Z.1 ∘ Z.4). Sans ça, le sub
            # _ir_render_exists_filter lève faussement « requires fk_lookup »
            # sur un IR sémantiquement valide.
            rendered = _ir_render_filter(
                sub,
                concept_resolution,
                table_alias,
                _depth=_depth + 1,
                fk_lookup=fk_lookup,
            )
            return f"NOT ({rendered})"
        sub_filters = flt[op_kind]
        if not isinstance(sub_filters, list):
            raise IRValidationError(
                f"compound '{op_kind}' requiert une list. " f"Got: {type(sub_filters).__name__}"
            )
        if not sub_filters:
            raise IRValidationError(
                f"compound '{op_kind}' liste vide — refusé. Une liste vide "
                f"produirait du SQL ambigu '()' ou un faux silencieux."
            )
        rendered_list = [
            _ir_render_filter(
                s,
                concept_resolution,
                table_alias,
                _depth=_depth + 1,
                fk_lookup=fk_lookup,
            )
            for s in sub_filters
        ]
        if len(rendered_list) == 1:
            # all_of([f]) ≡ f, any_of([f]) ≡ f — pas de parens en plus.
            return rendered_list[0]
        joiner = " AND " if op_kind == "all_of" else " OR "
        return "(" + joiner.join(f"({r})" for r in rendered_list) + ")"

    # ── Atomic filter (existant) ──
    op = flt.get("op")
    if op in ("EXISTS", "NOT_EXISTS"):
        # Phase Z.4 — filter EXISTS / NOT EXISTS, format spécial (subquery +
        # corrélation FK), pas de concept/val attendus au top-level.
        return _ir_render_exists_filter(
            flt,
            op,
            concept_resolution,
            table_alias,
            fk_lookup,
        )
    concept = flt.get("concept")
    val = flt.get("val")
    if op not in _IR_VALID_OPS:
        raise IRValidationError(f"op '{op}' invalide. Valides: {_IR_VALID_OPS}")
    table, col, vtype = _ir_resolve_concept(concept, concept_resolution)
    if op not in ("IS_NULL", "IS_NOT_NULL"):
        compatible_types = _IR_OP_TYPE_MATRIX[op]
        if vtype not in compatible_types:
            raise IRValidationError(
                f"op '{op}' incompatible avec value_type '{vtype}' "
                f"(concept '{concept}', col {table}.{col})"
            )
    alias = _ir_alias_for(concept, table, table_alias)
    qualified = f"{_ir_quote_sql_identifier(alias)}.{_ir_quote_sql_identifier(col)}"
    if op == "IS_NULL":
        return f"{qualified} IS NULL"
    if op == "IS_NOT_NULL":
        return f"{qualified} IS NOT NULL"
    if op in ("IN", "NOT_IN"):
        if not isinstance(val, list) or not val:
            raise IRValidationError(f"op '{op}' requiert une list non vide")
        # FIX M4 (adversarial review) — refuser None dans la liste IN/NOT_IN.
        # En T-SQL/ANSI 3-valued logic, ``X NOT IN (..., NULL)`` retourne
        # toujours UNKNOWN → 0 ligne (faux silencieux). ``X IN (..., NULL)``
        # est aussi piégeux (un X NULL ne match jamais via IN). Le LLM doit
        # utiliser un compound ``any_of: [{NOT_IN, ...}, {IS_NULL}]``.
        if any(v is None for v in val):
            raise IRValidationError(
                f"op '{op}' avec NULL dans la liste — refusé (faux silencieux "
                f"SQL 3-valued logic). Utiliser un compound any_of avec "
                f"IS_NULL/IS_NOT_NULL séparé. Concept '{concept}'."
            )
        # Anti-faux-positif silencieux : refuse les listes hétérogènes en
        # types. T-SQL fait coercion implicite qui peut masquer des bugs
        # (ex : `IN (42, '42')` est valide mais sémantiquement louche).
        # Chaque élément doit être sérialisable selon vtype — la fonction
        # `_ir_quote_sql_literal` lève si incompatible (number non castable,
        # date hors ISO, control char dans text). On amplifie le check :
        # tous les éléments doivent être castables au même vtype.
        rendered_vals = []
        for v in val:
            try:
                rendered_vals.append(_ir_quote_sql_literal(v, vtype))
            except IRValidationError as exc:
                raise IRValidationError(
                    f"op '{op}' avec valeur {v!r} non compatible avec "
                    f"value_type '{vtype}' (concept '{concept}'): {exc}"
                ) from exc
        sql_op = "IN" if op == "IN" else "NOT IN"
        return f"{qualified} {sql_op} ({', '.join(rendered_vals)})"
    if op in ("LIKE", "NOT_LIKE"):
        sql_op = "LIKE" if op == "LIKE" else "NOT LIKE"
        return f"{qualified} {sql_op} {_ir_quote_sql_literal(val, vtype)}"
    # Comparateurs binaires.
    sql_op = op if op != "<>" else "!="  # T-SQL accepte les deux, on normalise
    return f"{qualified} {sql_op} {_ir_quote_sql_literal(val, vtype)}"


def _ir_render_exists_filter(
    flt: dict,
    op: str,
    concept_resolution: dict,
    table_alias: dict[str, str],
    fk_lookup: dict[str, list[dict]] | None,
) -> str:
    """Phase Z.4 — render EXISTS / NOT EXISTS subquery filter avec corrélation FK.

    Format IR ::

        {"op": "EXISTS"|"NOT_EXISTS",
         "subquery": {"from_concept": "<inner>", "filters": [...]},
         "correlate_via_fk": {"outer_concept": "<>", "inner_concept": "<>"}}

    Le composer :
        - résout la FK directe entre outer et inner table (via ``fk_lookup``)
        - génère ``EXISTS (SELECT 1 FROM [inner] AS [S0] WHERE
          [outer_alias].[fk_outer] = [S0].[fk_inner] AND <internal filters>)``
        - les filters internes sont rendus via récursion (compound supporté)

    MVP Z.4 :
        - subquery avec UNE seule table interne (pas de joins internes)
        - filters internes simples ou compound
        - subquery imbriquée non supportée (refus explicite)
    """
    if fk_lookup is None:
        raise IRValidationError(
            f"op '{op}' requires fk_lookup pour résoudre la corrélation. "
            f"Le call-site doit passer fk_lookup."
        )
    subquery = flt.get("subquery")
    if not isinstance(subquery, dict):
        raise IRValidationError(
            f"op '{op}' requires `subquery` (dict). Got: " f"{type(subquery).__name__}"
        )
    if "joins" in subquery and subquery["joins"]:
        raise IRValidationError(
            f"op '{op}' MVP Z.4 : subquery.joins (joins internes) non "
            f"supportés. Subquery doit utiliser UNE seule table interne."
        )
    correlate = flt.get("correlate_via_fk")
    if not isinstance(correlate, dict):
        raise IRValidationError(
            f"op '{op}' requires `correlate_via_fk` (dict avec "
            f"outer_concept + inner_concept). Got: {type(correlate).__name__}"
        )
    outer_cn = correlate.get("outer_concept")
    inner_cn = correlate.get("inner_concept")
    if not outer_cn or not inner_cn:
        raise IRValidationError(
            f"op '{op}' correlate_via_fk requires non-empty outer_concept "
            f"and inner_concept. Got: {correlate!r}"
        )
    # FIX M8 (adversarial review) — `subquery.from_concept` est redondant
    # avec `inner_concept` (le composer utilise inner_concept comme source
    # de vérité). On accepte from_concept SEULEMENT s'il est identique à
    # inner_concept (informatif redondant) ; on refuse s'il diverge — sinon
    # le LLM a une fausse impression de contrôle de la subquery alors
    # qu'elle est silencieusement ignorée.
    sq_from = subquery.get("from_concept")
    if sq_from is not None and sq_from != inner_cn:
        raise IRValidationError(
            f"op '{op}' : `subquery.from_concept` ('{sq_from}') diverge de "
            f"`correlate_via_fk.inner_concept` ('{inner_cn}'). La table "
            f"interne est inférée via inner_concept — soit retirer "
            f"from_concept, soit l'aligner."
        )
    outer_table, _ocol, _ovt = _ir_resolve_concept(outer_cn, concept_resolution)
    inner_table, _icol, _ivt = _ir_resolve_concept(inner_cn, concept_resolution)
    if outer_table == inner_table:
        raise IRValidationError(
            f"op '{op}' : outer_concept '{outer_cn}' ({outer_table}) et "
            f"inner_concept '{inner_cn}' ({inner_table}) résolvent vers la "
            f"même table physique — subquery EXISTS sur même table interdit "
            f"(self-EXISTS = pattern différent, non supporté MVP)."
        )
    outer_alias = _ir_alias_for(outer_cn, outer_table, table_alias)

    fk = _ir_find_direct_fk(outer_table, inner_table, fk_lookup)
    if not fk:
        raise IRValidationError(
            f"op '{op}' : aucune FK directe entre outer '{outer_cn}' "
            f"({outer_table}) et inner '{inner_cn}' ({inner_table}). "
            f"Subquery non corrélable — utiliser un chemin via table "
            f"intermédiaire (non supporté MVP)."
        )

    # Subquery scope : alias dédié S0 (single table interne).
    sub_alias = "S0"
    cr_inner_best = concept_resolution.get(inner_cn, {}).get("best") or {}
    sub_role_hint = cr_inner_best.get("role_hint")
    sub_table_alias: dict[str, str] = {inner_table: sub_alias}
    if sub_role_hint:
        sub_table_alias[inner_cn] = sub_alias

    # WHERE clauses : corrélation FK + internal filters.
    sub_where: list[str] = []
    correl = (
        f"{_ir_quote_sql_identifier(outer_alias)}."
        f"{_ir_quote_sql_identifier(fk['left_col'])} = "
        f"{_ir_quote_sql_identifier(sub_alias)}."
        f"{_ir_quote_sql_identifier(fk['right_col'])}"
    )
    sub_where.append(correl)

    for f in subquery.get("filters") or []:
        if not isinstance(f, dict):
            raise IRValidationError(f"op '{op}' subquery.filter doit être un dict. Got: {f!r}")
        # Récursion sur _ir_render_filter (compound supporté).
        # NOTE : on reset _depth=0 dans le scope subquery (depth distinct).
        sub_where.append(
            _ir_render_filter(
                f,
                concept_resolution,
                sub_table_alias,
                _depth=0,
                fk_lookup=fk_lookup,
            )
        )

    sub_sql = (
        f"SELECT 1 FROM {_ir_quote_sql_identifier(inner_table)} "
        f"AS {_ir_quote_sql_identifier(sub_alias)} "
        f"WHERE {' AND '.join(sub_where)}"
    )
    sql_op = "EXISTS" if op == "EXISTS" else "NOT EXISTS"
    return f"{sql_op} ({sub_sql})"


_IR_VALID_EXPR_FNS: tuple[str, ...] = ("year", "month", "day", "concat")
_IR_CONCAT_MAX_ARGS: int = (
    50  # Phase Z.7 — anti-DoS sur concat (T-SQL le permet, mais limit raisonnable)
)


def _ir_render_expr_fn(
    fn_expr: dict,
    concept_resolution: dict,
    table_alias: dict[str, str],
) -> str:
    """Rend `{"fn": "year"|"month"|"day"|"concat", ...}` en SQL.

    ``year``/``month``/``day`` (Phase d) : ``{"fn": "year", "concept": "X"}``
    → ``YEAR([T0].[col])``.

    ``concat`` (Phase Z.7) : ``{"fn": "concat", "args": [<expr>, ...]}``
    → ``CONCAT(<expr1>, <expr2>, ...)``. Chaque arg est rendu via
    ``_ir_render_simple_expr`` (concept / literal / nested fn). Pas de
    ``select_ref`` accepté dans les args (pas pertinent dans concat).
    """
    fn = fn_expr.get("fn")
    if fn not in _IR_VALID_EXPR_FNS:
        raise IRValidationError(f"expr_fn '{fn}' invalide. Valides: {_IR_VALID_EXPR_FNS}")
    if fn == "concat":
        args = fn_expr.get("args")
        if not isinstance(args, list) or not args:
            raise IRValidationError(
                "concat requires `args` (list non-vide). Vide → SQL " "ambigu ('CONCAT()'), refusé."
            )
        if len(args) > _IR_CONCAT_MAX_ARGS:
            raise IRValidationError(
                f"concat trop d'args ({len(args)} > " f"{_IR_CONCAT_MAX_ARGS}, limit anti-DoS)"
            )
        rendered: list[str] = []
        for i, arg in enumerate(args):
            if not isinstance(arg, dict):
                raise IRValidationError(
                    f"concat.args[{i}] doit être un dict, got " f"{type(arg).__name__}"
                )
            if "select_ref" in arg:
                raise IRValidationError(
                    f"concat.args[{i}] : `select_ref` non supporté dans "
                    f"concat (utiliser concept/literal/fn)"
                )
            rendered.append(
                _ir_render_simple_expr(
                    arg,
                    concept_resolution,
                    table_alias,
                    {},
                )
            )
        return f"CONCAT({', '.join(rendered)})"
    # year/month/day : format standard {"fn": "...", "concept": "X"}.
    concept = fn_expr.get("concept")
    if not isinstance(concept, str) or not concept:
        raise IRValidationError(f"expr_fn '{fn}' sans concept: {fn_expr!r}")
    table, col, _vt = _ir_resolve_concept(concept, concept_resolution)
    alias_sql_table = _ir_alias_for(concept, table, table_alias)
    qualified = f"{_ir_quote_sql_identifier(alias_sql_table)}." f"{_ir_quote_sql_identifier(col)}"
    return f"{fn.upper()}({qualified})"


def _ir_render_simple_expr(
    expr,
    concept_resolution: dict,
    table_alias: dict[str, str],
    select_alias_to_expr: dict[str, str],
) -> str:
    """Rend une expression simple en SQL.

    Types supportés (Phase d MVP) :
        - `{"concept": "X"}` — réf concept résolu
        - `{"literal": <val>, "value_type": "<type>"}` — valeur litérale
        - `{"fn": "year"|"month"|"day", "concept": "X"}` — extraction date
        - `{"select_ref": "<alias>"}` — réf alias select
    """
    if not isinstance(expr, dict):
        raise IRValidationError(f"expression doit être un dict, got {type(expr).__name__}")
    if "fn" in expr:
        return _ir_render_expr_fn(expr, concept_resolution, table_alias)
    if "concept" in expr:
        cn = expr["concept"]
        table, col, _vt = _ir_resolve_concept(cn, concept_resolution)
        alias_sql_table = _ir_alias_for(cn, table, table_alias)
        return f"{_ir_quote_sql_identifier(alias_sql_table)}." f"{_ir_quote_sql_identifier(col)}"
    if "literal" in expr:
        vtype = expr.get("value_type", "text")
        return _ir_quote_sql_literal(expr["literal"], vtype)
    if "select_ref" in expr:
        ref = expr["select_ref"]
        if ref not in select_alias_to_expr:
            raise IRValidationError(
                f"select_ref '{ref}' inexistant. Disponibles: " f"{list(select_alias_to_expr)}"
            )
        return f"({select_alias_to_expr[ref]})"
    raise IRValidationError(
        f"expression non-reconnue: {expr!r}. " f"Types supportés: concept, literal, fn, select_ref"
    )


def _ir_render_case_when(
    case_when: list,
    else_expr,
    concept_resolution: dict,
    table_alias: dict[str, str],
    select_alias_to_expr: dict[str, str],
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """Rend ``CASE WHEN <cond> THEN <expr> ... ELSE <else_expr> END``.

    Format de chaque branche : ``{"when": <filter>, "then": <expression>}``.
    L'else_expr peut être ``None`` → ``ELSE NULL``.

    Phase Z.4 — ``fk_lookup`` propagé au render des filters internes (pour
    permettre EXISTS / NOT EXISTS dans le ``when``).
    """
    if not isinstance(case_when, list) or not case_when:
        raise IRValidationError("case_when doit être une list non-vide")
    if len(case_when) > 50:
        raise IRValidationError(
            f"case_when trop long ({len(case_when)} > 50 branches). "
            f"Limit anti-DoS et anti-pathologic-IR."
        )
    branches: list[str] = []
    for i, branch in enumerate(case_when):
        if not isinstance(branch, dict):
            raise IRValidationError(f"case_when[{i}] doit être un dict")
        cond = branch.get("when")
        then_expr = branch.get("then")
        if cond is None or then_expr is None:
            raise IRValidationError(f"case_when[{i}] requires when+then: {branch!r}")
        if not isinstance(cond, dict):
            raise IRValidationError(f"case_when[{i}].when doit être un dict (filter)")
        cond_sql = _ir_render_filter(
            cond,
            concept_resolution,
            table_alias,
            fk_lookup=fk_lookup,
        )
        then_sql = _ir_render_simple_expr(
            then_expr,
            concept_resolution,
            table_alias,
            select_alias_to_expr,
        )
        branches.append(f"WHEN {cond_sql} THEN {then_sql}")
    if else_expr is None:
        else_sql = "NULL"
    else:
        else_sql = _ir_render_simple_expr(
            else_expr,
            concept_resolution,
            table_alias,
            select_alias_to_expr,
        )
    return "CASE " + " ".join(branches) + f" ELSE {else_sql} END"


def _ir_render_window_fn(
    item: dict,
    concept_resolution: dict,
    table_alias: dict[str, str],
    select_alias_to_expr: dict[str, str],
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """F4 (2026-05-21) — Rend une window function en SQL T-SQL.

    Génère ``<FN>(<args>) OVER (PARTITION BY ... ORDER BY ...)``.

    Args contractuels (validés par ``_ir_validate_window_spec``) :
        - ``item["window"]["fn"]`` : lag|lead|row_number|rank|dense_rank
        - ``item["window"]["expr"]`` : présent ssi fn ∈ {lag, lead}
        - ``item["window"]["offset"]`` : optionnel pour lag/lead
        - ``item["window"]["partition_by_concepts"]`` : optionnel
        - ``item["window"]["order_by"]`` : REQUIS (validation amont)

    Le ``expr`` peut être un inline select_item (récursion via
    ``_ir_render_select_item``) ou une ``{"select_ref": "<alias>"}``.
    """
    window = item["window"]
    fn = window["fn"].lower()
    # 1. Construction de l'argument (expr) selon le type de fn.
    args_sql = ""
    if fn in _IR_WINDOW_FNS_REQUIRE_EXPR:
        expr_spec = window["expr"]
        if "select_ref" in expr_spec:
            ref = expr_spec["select_ref"]
            if ref not in select_alias_to_expr:
                raise IRValidationError(
                    f"window.expr.select_ref '{ref}' inexistant. "
                    f"Disponibles: {list(select_alias_to_expr)}"
                )
            # Wrap dans parenthèses si l'expr est complexe (CASE, agrégat).
            inner = select_alias_to_expr[ref]
            # Trim éventuel "<expr> AS [alias]" (ne devrait pas arriver — on stocke l'expr nue).
            args_sql = inner
        else:
            # Inline : récursion en alias temporaire.
            inline_item = dict(expr_spec)
            inline_item.setdefault("alias", "_win_expr")
            _, inline_expr = _ir_render_select_item(
                inline_item,
                concept_resolution,
                table_alias,
                select_alias_to_expr,
                fk_lookup=fk_lookup,
            )
            args_sql = inline_expr
        # Offset + default (lag/lead supportent jusqu'à 3 args : expr, offset, default).
        if "offset" in window:
            offset = int(window["offset"])
            args_sql = f"{args_sql}, {offset}"
        # `default` est intentionnellement non supporté en F4 MVP — couvre les
        # cas usuels (LAG(x) ou LAG(x, 1)). Default complique la sérialisation
        # type-safe (date vs number vs text) et nécessiterait `_ir_quote_sql_literal`
        # avec le type_hint. À ajouter en F4b si nécessaire.

    # 2. PARTITION BY (optionnel).
    partition_concepts = window.get("partition_by_concepts") or []
    partition_cols: list[str] = []
    for cn in partition_concepts:
        table, col, _vt = _ir_resolve_concept(cn, concept_resolution)
        alias_sql = _ir_alias_for(cn, table, table_alias)
        partition_cols.append(
            f"{_ir_quote_sql_identifier(alias_sql)}.{_ir_quote_sql_identifier(col)}"
        )

    # 3. ORDER BY (REQUIS, validé en amont).
    order_cols: list[str] = []
    for o in window["order_by"]:
        cn = o.get("concept")
        ref_alias = o.get("alias")
        direction = o.get("direction", "ASC")
        if ref_alias and ref_alias in select_alias_to_expr:
            order_cols.append(f"{_ir_quote_sql_identifier(ref_alias)} {direction}")
        elif cn:
            table, col, _vt = _ir_resolve_concept(cn, concept_resolution)
            alias_sql = _ir_alias_for(cn, table, table_alias)
            order_cols.append(
                f"{_ir_quote_sql_identifier(alias_sql)}."
                f"{_ir_quote_sql_identifier(col)} {direction}"
            )
        else:
            raise IRValidationError(
                f"window.order_by entry doit avoir 'concept' ou 'alias': {o!r}"
            )

    over_parts: list[str] = []
    if partition_cols:
        over_parts.append(f"PARTITION BY {', '.join(partition_cols)}")
    over_parts.append(f"ORDER BY {', '.join(order_cols)}")
    over_sql = " ".join(over_parts)
    return f"{fn.upper()}({args_sql}) OVER ({over_sql})"


def _ir_render_select_item(
    item: dict,
    concept_resolution: dict,
    table_alias: dict[str, str],
    select_alias_to_expr: dict[str, str],
    fk_lookup: dict[str, list[dict]] | None = None,
) -> tuple[str, str]:
    """Rend un item de SELECT en ``(alias_or_None, expression_sql)``.

    Phase d : 3 modes mutuellement exclusifs :
        - ``case_when: [...]`` + optionnel ``else``, ``agg`` → CASE WHEN
        - ``derivation: {op, left, right}`` → expression arithmétique
        - ``concept: "X"`` + ``agg`` + optionnel ``filters`` → mesure
        - F4 (2026-05-21) : ``window: {...}`` → LAG/LEAD/ROW_NUMBER/RANK/DENSE_RANK

    Phase Z.4 — ``fk_lookup`` propagé pour autoriser EXISTS dans CASE WHEN.
    """
    alias = item.get("alias", "")
    if not alias:
        raise IRValidationError(f"select item sans alias: {item!r}")
    # F4 — window function (LAG/LEAD/ROW_NUMBER/RANK/DENSE_RANK).
    if "window" in item:
        return alias, _ir_render_window_fn(
            item,
            concept_resolution,
            table_alias,
            select_alias_to_expr,
            fk_lookup=fk_lookup,
        )
    # Task #100 primitive 2 (2026-05-22) — version_fallback : récupère
    # la valeur d'un concept selon une **liste ordonnée de filtres**.
    # Premier filtre qui produit une valeur non-NULL gagne. Cas typique :
    # « expert-comptable signataire 2024, sinon 2023 ». Émet en T-SQL :
    # ``COALESCE(MAX(CASE WHEN <f1> THEN val), MAX(CASE WHEN <f2> THEN val), ...)``.
    if "version_fallback" in item:
        return alias, _ir_render_version_fallback(
            item, concept_resolution, table_alias, fk_lookup=fk_lookup
        )
    # Task #100 primitive 3 (2026-05-22) — partition_by_set : ventiler une
    # mesure selon que la valeur d'un autre concept est IN/NOT IN une
    # liste fermée. Émet ``CASE WHEN col IN (...) THEN val ELSE 0 END``,
    # wrapé par ``item["agg"]`` (sum, count, avg, etc.). Cas typique :
    # « production des chefs de mission (liste 22 codes) vs autres ».
    if "partition_by_set" in item:
        case_expr, agg = _ir_render_partition_by_set(
            item, concept_resolution, table_alias
        )
        if agg not in _IR_VALID_AGGS:
            raise IRValidationError(f"partition_by_set : agg '{agg}' invalide.")
        if agg == "none":
            return alias, case_expr
        if agg == "count":
            return alias, f"COUNT({case_expr})"
        if agg == "string_agg":
            return alias, _ir_render_string_agg(
                case_expr, item, concept_resolution, table_alias
            )
        return alias, f"{agg.upper()}({case_expr})"
    if "case_when" in item:
        case_sql = _ir_render_case_when(
            item["case_when"],
            item.get("else"),
            concept_resolution,
            table_alias,
            select_alias_to_expr,
            fk_lookup=fk_lookup,
        )
        agg = item.get("agg", "none")
        if agg not in _IR_VALID_AGGS:
            raise IRValidationError(f"agg '{agg}' invalide.")
        if agg == "none":
            return alias, case_sql
        if agg == "count":
            return alias, f"COUNT({case_sql})"
        # Task #100 (2026-05-22) — string_agg ordonné via helper dédié.
        # Émet T-SQL STRING_AGG(DISTINCT col, sep) WITHIN GROUP (ORDER BY ...)
        if agg == "string_agg":
            return alias, _ir_render_string_agg(
                case_sql, item, concept_resolution, table_alias
            )
        return alias, f"{agg.upper()}({case_sql})"
    if "derivation" in item:
        deriv = item["derivation"]
        deriv_op = deriv.get("op")
        if deriv_op not in _IR_VALID_DERIV_OPS:
            raise IRValidationError(
                f"derivation.op '{deriv_op}' invalide. " f"Valides: {_IR_VALID_DERIV_OPS}"
            )
        sql_op = {"subtract": "-", "add": "+", "multiply": "*", "divide": "/"}[deriv_op]

        def _render_operand(operand) -> str:
            if "select_ref" in operand:
                ref = operand["select_ref"]
                if ref not in select_alias_to_expr:
                    raise IRValidationError(
                        f"derivation.select_ref '{ref}' inexistant. "
                        f"Disponibles: {list(select_alias_to_expr)}"
                    )
                # Wrap dans parenthèses pour clarité numérique.
                return f"({select_alias_to_expr[ref]})"
            # Inline : récursion. Pas d'alias persisté pour les operandes.
            inline_item = dict(operand)
            inline_item.setdefault("alias", "_inline")
            _, expr = _ir_render_select_item(
                inline_item,
                concept_resolution,
                table_alias,
                select_alias_to_expr,
                fk_lookup=fk_lookup,
            )
            return f"({expr})"

        left_sql = _render_operand(deriv["left"])
        right_sql = _render_operand(deriv["right"])
        # Division → ISNULL pour anti-divide-by-zero ? T-SQL = NULLIF.
        if deriv_op == "divide":
            return alias, f"{left_sql} / NULLIF({right_sql}, 0)"
        return alias, f"{left_sql} {sql_op} {right_sql}"

    # Cas standard : agg(col) optionnellement filtré par CASE WHEN.
    concept = item.get("concept")
    agg = item.get("agg", "none")
    if agg not in _IR_VALID_AGGS:
        raise IRValidationError(f"agg '{agg}' invalide. Valides: {_IR_VALID_AGGS}")
    table, col, vtype = _ir_resolve_concept(concept, concept_resolution)
    alias_sql_table = _ir_alias_for(concept, table, table_alias)
    qualified = f"{_ir_quote_sql_identifier(alias_sql_table)}." f"{_ir_quote_sql_identifier(col)}"
    filters = item.get("filters") or []
    if filters:
        # CASE WHEN <conditions> THEN <col> ELSE 0/NULL END.
        # FIX C2 (adversarial review) — propager fk_lookup pour permettre
        # NOT_EXISTS dans les filters d'une mesure conditionnelle.
        conditions = " AND ".join(
            _ir_render_filter(
                f,
                concept_resolution,
                table_alias,
                fk_lookup=fk_lookup,
            )
            for f in filters
        )
        else_value = "0" if agg in ("sum", "count") else "NULL"
        case_expr = f"CASE WHEN {conditions} THEN {qualified} ELSE {else_value} END"
        if agg == "none":
            return alias, case_expr
        # Task #100 (2026-05-22) — string_agg avec filtres CASE WHEN
        if agg == "string_agg":
            return alias, _ir_render_string_agg(
                case_expr, item, concept_resolution, table_alias
            )
        return alias, f"{agg.upper()}({case_expr})"
    # Pas de filtre conditionnel.
    if agg == "none":
        return alias, qualified
    if agg == "count":
        return alias, f"COUNT({qualified})"
    # Task #100 (2026-05-22) — string_agg simple (sans CASE filter)
    if agg == "string_agg":
        return alias, _ir_render_string_agg(
            qualified, item, concept_resolution, table_alias
        )
    return alias, f"{agg.upper()}({qualified})"


_IR_VALID_DERIV_SEMANTICS: tuple[str, ...] = ("case_when", "full_outer")


def _flatten_compound_filters_for_disjoint_check(
    filters: list,
    _depth: int = 0,
) -> list[dict]:
    """FIX C3 (adversarial review) — extrait les filters atomiques d'une liste
    qui peut contenir des compound `all_of` (Z.1).

    On ne suit QUE `all_of` (sémantique AND, le filtre s'applique). On ignore
    `any_of` (sémantique OR, le check disjoint n'est plus pertinent — un
    filtre `any_of: [A, B]` n'isole pas une période donnée) et `not`
    (inverse, sémantique compliquée).

    Sans ce flatten, un LLM peut wrapper un filtre `{concept:year, val:2024}`
    dans `{all_of: [...]}` pour passer sous le radar du check disjoint et
    déclencher le faux silencieux que le check prétend bloquer.

    Profondeur limitée à 8 (anti-DoS).
    """
    if _depth > 8:
        return []
    out: list[dict] = []
    for f in filters:
        if not isinstance(f, dict):
            continue
        # Atomique (concept + op).
        if "concept" in f and "op" in f:
            out.append(f)
            continue
        # Compound all_of → récursion (s'applique tous, AND).
        if "all_of" in f and isinstance(f["all_of"], list):
            out.extend(
                _flatten_compound_filters_for_disjoint_check(
                    f["all_of"],
                    _depth + 1,
                )
            )
        # any_of / not : on ne flatten PAS — sémantique non équivalente.
    return out


def _ir_subtract_disjoint_filter_check(item: dict) -> None:
    """Détecte le pattern dangereux (cf. adversarial review issue #6) :
    ``derivation.subtract`` entre 2 alias dont les filtres portent sur
    la **même** colonne (typiquement l'année) avec des valeurs
    **disjointes** (ex : 2024 vs 2023).

    Sémantique sous CASE WHEN : si une entité existe en 2023 mais pas
    en 2024, ``CASE WHEN year=2024 THEN ... ELSE 0`` retourne 0 → écart
    calculé = ``0 - X = -X`` au lieu de NULL. **Résultat faux silencieux**
    sur des dossiers présents qu'une seule année.

    Fix MVP : on **bloque** ce pattern et l'utilisateur doit utiliser
    ``derivation.semantic = "full_outer"`` (à implémenter Phase d) ou
    écrire l'IR différemment. Mieux vaut un blocage explicite qu'un
    résultat faux silencieux.
    """
    if "derivation" not in item:
        return
    deriv = item["derivation"]
    if deriv.get("op") != "subtract":
        return
    # Phase d : si semantic="full_outer", l'utilisateur demande explicitement
    # le mode CTE+FULL_OUTER_JOIN qui gère correctement les entités présentes
    # une seule période. Le check disjoint ne s'applique plus (le pattern
    # devient légitime).
    if deriv.get("semantic") == "full_outer":
        return
    left = deriv.get("left", {})
    right = deriv.get("right", {})
    # Le pattern dangereux nécessite des inline operands (pas select_ref —
    # on ne peut pas inspecter l'item référencé ici sans contexte). Si
    # l'utilisateur passe par select_ref, il a accepté la sémantique CASE.
    if "select_ref" in left or "select_ref" in right:
        return
    l_filters = left.get("filters") or []
    r_filters = right.get("filters") or []
    # FIX C3 — flatten compound `all_of` pour démasquer les filtres atomiques
    # potentiellement disjoints. Sans ce flatten, le LLM peut contourner le
    # check via `{all_of: [{concept:year, val:2024}]}`.
    l_filters_flat = _flatten_compound_filters_for_disjoint_check(l_filters)
    r_filters_flat = _flatten_compound_filters_for_disjoint_check(r_filters)
    # On cherche un concept commun avec valeurs disjointes.
    l_by_concept = {f.get("concept"): f.get("val") for f in l_filters_flat if isinstance(f, dict)}
    r_by_concept = {f.get("concept"): f.get("val") for f in r_filters_flat if isinstance(f, dict)}
    common_concepts = set(l_by_concept) & set(r_by_concept)
    for cn in common_concepts:
        l_vals = (
            {l_by_concept[cn]} if not isinstance(l_by_concept[cn], list) else set(l_by_concept[cn])
        )
        r_vals = (
            {r_by_concept[cn]} if not isinstance(r_by_concept[cn], list) else set(r_by_concept[cn])
        )
        if l_vals and r_vals and not (l_vals & r_vals):
            raise IRValidationError(
                f"derivation.subtract avec filtres disjoints sur concept '{cn}' "
                f"(left={sorted(l_vals)} vs right={sorted(r_vals)}) — risque de "
                f"faux résultat silencieux sur entités présentes une seule "
                f"période. Utiliser select_ref vers 2 alias séparés ou "
                f"derivation.semantic='full_outer' (Phase d)."
            )


def _ir_validate_window_spec(window: dict, alias: str) -> None:
    """F4 (2026-05-21) — Valide la spec d'une window function.

    Contrat :
        - ``fn`` ∈ ``_IR_VALID_WINDOW_FNS``
        - ``order_by`` REQUIS (liste non-vide) — sinon résultat indéterminé
          silencieux (SQL Server accepte sans ORDER BY mais retourne "any row"
          imprévisible). C'est précisément le piège que F4 doit fermer.
        - ``expr`` REQUIS pour lag/lead, INTERDIT pour row_number/rank/dense_rank.
        - ``offset`` optionnel pour lag/lead (entier > 0), défaut 1.
        - ``partition_by_concepts`` optionnel (list[str]).

    Aucune validation croisée avec ``concept_resolution`` ici — fait au render.
    """
    if not isinstance(window, dict):
        raise IRValidationError(
            f"select '{alias}' window doit être un dict, got {type(window).__name__}"
        )
    fn = window.get("fn")
    if not isinstance(fn, str) or fn.lower() not in _IR_VALID_WINDOW_FNS:
        raise IRValidationError(
            f"select '{alias}' window.fn '{fn}' invalide. "
            f"Valides: {_IR_VALID_WINDOW_FNS}"
        )
    fn_lower = fn.lower()
    # ORDER BY obligatoire dans OVER — sans lui, SQL Server retourne des
    # résultats indéterminés silencieusement (anti-faux-résultat).
    order_by = window.get("order_by") or []
    if not isinstance(order_by, list) or not order_by:
        raise IRValidationError(
            f"select '{alias}' window.order_by REQUIS (liste non-vide). "
            f"Sans ORDER BY dans OVER(), la fonction {fn_lower.upper()} "
            f"retourne des résultats indéterminés silencieusement."
        )
    for o in order_by:
        if not isinstance(o, dict):
            raise IRValidationError(
                f"select '{alias}' window.order_by entries doivent être des dicts"
            )
        if o.get("direction") not in _IR_VALID_DIRECTIONS:
            raise IRValidationError(
                f"select '{alias}' window.order_by direction "
                f"'{o.get('direction')}' invalide. Valides: {_IR_VALID_DIRECTIONS}"
            )
    # expr requis pour lag/lead, INTERDIT pour row_number/rank/dense_rank.
    has_expr = "expr" in window
    if fn_lower in _IR_WINDOW_FNS_REQUIRE_EXPR:
        if not has_expr:
            raise IRValidationError(
                f"select '{alias}' window.fn '{fn_lower}' nécessite un 'expr' "
                f"(la valeur à décaler dans le temps)."
            )
        if not isinstance(window["expr"], dict):
            raise IRValidationError(
                f"select '{alias}' window.expr doit être un dict "
                f"(inline select item ou {{select_ref: <alias>}})."
            )
        # Adversarial fix : interdire window-inside-window (SQL Server reject
        # explicitement les nested window fns, mais on catch en validation
        # plutôt que de laisser un round-trip Sage le découvrir).
        if "window" in window["expr"]:
            raise IRValidationError(
                f"select '{alias}' window.expr contient un autre 'window' — "
                f"window-inside-window interdit (SQL Server rejette)."
            )
    else:
        if has_expr:
            raise IRValidationError(
                f"select '{alias}' window.fn '{fn_lower}' ne prend PAS "
                f"d'argument 'expr' (SQL: {fn_lower.upper()}() — sans param)."
            )
    # offset optionnel — uniquement pour lag/lead, doit être int > 0.
    if "offset" in window:
        if fn_lower not in _IR_WINDOW_FNS_REQUIRE_EXPR:
            raise IRValidationError(
                f"select '{alias}' window.offset interdit pour fn '{fn_lower}'."
            )
        off = window["offset"]
        if not isinstance(off, int) or isinstance(off, bool) or off <= 0:
            raise IRValidationError(
                f"select '{alias}' window.offset '{off}' invalide — entier > 0 attendu."
            )
    # partition_by_concepts optionnel, list[str] si présent.
    pby = window.get("partition_by_concepts") or []
    if not isinstance(pby, list):
        raise IRValidationError(
            f"select '{alias}' window.partition_by_concepts doit être une liste"
        )
    for p in pby:
        if not isinstance(p, str) or not p:
            raise IRValidationError(
                f"select '{alias}' window.partition_by_concepts entries "
                f"doivent être des concept names non-vides"
            )
    # Adversarial fix : reject duplicates dans partition_by_concepts —
    # SQL Server accepte `PARTITION BY a, a` mais c'est toujours une
    # hallucination du LLM (et le tri/output reste correct mais l'IR snapshot
    # est bruité).
    if len(set(pby)) != len(pby):
        raise IRValidationError(
            f"select '{alias}' window.partition_by_concepts a des doublons : "
            f"{pby}. Chaque concept ne peut apparaître qu'une fois."
        )


def _ir_validate_having_filter(f: dict, idx: int) -> None:
    """F4 (2026-05-21) — Valide un filter HAVING.

    Format imposé : ``{"alias_ref": "<select_alias>", "op": "...", "val": ...}``
    où ``alias_ref`` désigne un alias déjà défini dans ``ir.select`` qui DOIT
    référencer une expression agrégée (sum/avg/count/min/max).

    Le pattern ``alias_ref`` est choisi (vs réinjecter l'agrégat in-place) pour :
        1. Empêcher la duplication de l'expression agrégée (single source of truth).
        2. Permettre au LLM de filtrer sur des agrégats CASE WHEN complexes
           sans les re-décrire dans le HAVING.
        3. Bloquer les erreurs courantes ``WHERE SUM(x) > 100`` (qui passent
           comme un agrégat dans WHERE — erreur SQL Server explicite).

    La validation que l'``alias_ref`` pointe vers un agrégat est faite au
    render-time (besoin de l'expression résolue).
    """
    if not isinstance(f, dict):
        raise IRValidationError(f"having_filters[{idx}] doit être un dict")
    alias_ref = f.get("alias_ref")
    if not isinstance(alias_ref, str) or not alias_ref:
        raise IRValidationError(
            f"having_filters[{idx}] doit avoir un 'alias_ref' (str non-vide) "
            f"référençant un alias select existant."
        )
    op = f.get("op")
    if op not in _IR_VALID_OPS:
        raise IRValidationError(
            f"having_filters[{idx}] op '{op}' invalide. Valides: {_IR_VALID_OPS}"
        )


def _ir_validate(ir: dict) -> None:
    """Valide la structure de l'IR. Lève IRValidationError sur 1ère erreur.

    Vérifie :
        - structure dict, select non-vide
        - alias unique dans select, format SQL-safe (cf. issue #1 adversarial)
        - from_concept non-vide
        - ops/aggs/directions parmi les valeurs autorisées
        - pas de subtract dangereux (cf. issue #6 adversarial)
        - F4 (2026-05-21) : window functions + having_filters

    Pas de validation croisée avec concept_resolution ici — fait au render time.
    """
    if not isinstance(ir, dict):
        raise IRValidationError(f"IR doit être un dict, got {type(ir).__name__}")
    select = ir.get("select", [])
    if not isinstance(select, list) or not select:
        # EmptySelectError (sous-type) : permet à _phase4_convert_ir_error de
        # ne convertir QUE ce cas dégénéré en ConceptUnresolvedError (F1).
        raise EmptySelectError("ir.select doit être une list non vide")
    aliases_seen: set[str] = set()
    for i, item in enumerate(select):
        if not isinstance(item, dict):
            raise IRValidationError(f"select[{i}] doit être un dict")
        a = item.get("alias")
        if not isinstance(a, str) or not a:
            raise IRValidationError(f"select[{i}] sans alias")
        if a in aliases_seen:
            raise IRValidationError(f"select[{i}] alias '{a}' dupliqué")
        # Validation format alias AU MOMENT de la validation IR, pas
        # seulement au render (defense-in-depth, cf. issue #1 adversarial).
        try:
            _ir_quote_sql_identifier(a)
        except IRValidationError as exc:
            raise IRValidationError(f"select[{i}] alias '{a}' invalide: {exc}") from exc
        aliases_seen.add(a)
        # Anti-faux-résultat-silencieux sur subtract avec filtres disjoints.
        _ir_subtract_disjoint_filter_check(item)
        # F4 — Si l'item est une window function, valider la spec.
        if "window" in item:
            _ir_validate_window_spec(item["window"], a)
    if not isinstance(ir.get("from_concept"), str) or not ir.get("from_concept"):
        raise IRValidationError("ir.from_concept doit être un concept non vide")
    for f in ir.get("filters_global") or []:
        if not isinstance(f, dict):
            raise IRValidationError("filters_global entries doivent être des dicts")
    # F4 — having_filters : liste de filters sur des alias select (agrégats).
    for i, f in enumerate(ir.get("having_filters") or []):
        _ir_validate_having_filter(f, i)
        # alias_ref doit pointer vers un alias select existant
        ar = f.get("alias_ref")
        if ar not in aliases_seen:
            raise IRValidationError(
                f"having_filters[{i}] alias_ref '{ar}' inconnu. "
                f"Aliases disponibles dans select: {sorted(aliases_seen)}"
            )
    for c in ir.get("group_by_concepts") or []:
        if not isinstance(c, str):
            raise IRValidationError("group_by_concepts doit être list[str]")
    for o in ir.get("order_by") or []:
        if not isinstance(o, dict):
            raise IRValidationError("order_by entries doivent être des dicts")
        if o.get("direction") not in _IR_VALID_DIRECTIONS:
            raise IRValidationError(
                f"order_by direction '{o.get('direction')}' invalide. "
                f"Valides: {_IR_VALID_DIRECTIONS}"
            )


def _ir_find_direct_fk(
    table_a: str,
    table_b: str,
    fk_lookup: dict[str, list[dict]],
) -> dict | None:
    """Trouve une FK directe entre `table_a` et `table_b` (outgoing OU incoming).

    Returns:
        ``{"left_table", "left_col", "right_table", "right_col"}`` avec
        right_table = table_b. Tri lex sur from_col pour déterminisme.
        ``None`` si aucune FK directe.

    **Pourquoi** : Phase e.2 — quand l'IR fournit un ``joins`` explicite,
    le composer doit trouver la FK directe entre 2 tables (sans BFS multi-hop).
    Si plusieurs FK directes existent (rare mais possible : 2 colonnes pointant
    vers la même table parent), on lève IRValidationError pour forcer le user
    à désambiguïser via ``via_col``.
    """
    candidates: list[dict] = []
    # Outgoing : table_a a une FK vers table_b.
    for fk in sorted(
        fk_lookup.get(table_a, []),
        key=lambda f: (str(f.get("to_table") or ""), str(f.get("from_col") or "")),
    ):
        if fk.get("to_table") == table_b:
            candidates.append(
                {
                    "left_table": table_a,
                    "left_col": fk.get("from_col"),
                    "right_table": table_b,
                    "right_col": fk.get("to_col"),
                }
            )
    # Incoming : table_b a une FK vers table_a (on inverse).
    for fk in sorted(
        fk_lookup.get(table_b, []),
        key=lambda f: (str(f.get("to_table") or ""), str(f.get("from_col") or "")),
    ):
        if fk.get("to_table") == table_a:
            candidates.append(
                {
                    "left_table": table_a,
                    "left_col": fk.get("to_col"),
                    "right_table": table_b,
                    "right_col": fk.get("from_col"),
                }
            )
    if not candidates:
        return None
    if len(candidates) > 1:
        raise IRValidationError(
            f"FK ambiguë entre {table_a} et {table_b} : "
            f"{len(candidates)} FK directes trouvées. Soit (a) préciser "
            f"`via_col` dans le IR.joins, soit (b) ajouter un `disambiguator` "
            f"(non supporté en Phase e.2 MVP)."
        )
    return candidates[0]


def _ir_compute_join_chain_from_hints(
    joins_hints: list[dict],
    concept_resolution: dict,
    fk_lookup: dict[str, list[dict]],
) -> list[dict]:
    """Construit la chaîne de JOINs depuis ``ir.joins`` (Phase e.2).

    Format ``joins_hints`` (list[dict]) :
        ``[{"from": "<concept_name>", "to": "<concept_name>"}, ...]``

    Pour chaque paire (from_concept, to_concept), résout en (table_a, table_b)
    via concept_resolution puis cherche la FK directe via `_ir_find_direct_fk`.
    Lève IRValidationError si :
        - concept inconnu
        - aucune FK directe entre les 2 tables
        - FK ambiguë (multiples FKs)

    Generic : aucun pattern lexical, fonctionne sur n'importe quelle BDD avec
    FK déclarées.
    """
    chain: list[dict] = []
    # Phase Z.3 — dédup par (from_concept, to_concept) PAS par (from_table,
    # to_table). Permet à 2 hints `{F1→dossier_facture}` + `{F2→dossier_entite}`
    # avec même tables de coexister si les concepts diffèrent.
    seen_concept_pairs: set[tuple[str, str]] = set()
    # W2 fix — dédup au niveau des STEPS de JOIN (tables + colonnes). Sans
    # ça, le BFS fallback peut ajouter le même JOIN `Collaborateurs ↔ Production`
    # plusieurs fois quand plusieurs hints (production, chef de mission, etc.)
    # résolvent vers la même table et déclenchent le même chemin BFS.
    seen_join_steps: set[tuple] = set()

    def _add_step(step: dict) -> None:
        """Ajoute un step à la chain s'il n'a pas déjà été ajouté
        (dédup par left_table+right_table+left_col+right_col)."""
        key = (
            step.get("left_table"),
            step.get("right_table"),
            step.get("left_col"),
            step.get("right_col"),
        )
        if key in seen_join_steps:
            return
        seen_join_steps.add(key)
        chain.append(step)

    for i, hint in enumerate(joins_hints):
        if not isinstance(hint, dict):
            raise IRValidationError(f"joins[{i}] doit être un dict")
        from_cn = hint.get("from")
        to_cn = hint.get("to")
        if not from_cn or not to_cn:
            raise IRValidationError(f"joins[{i}] : `from` et `to` (concepts) requis. Got {hint!r}")
        from_table, _fcol, _fvt = _ir_resolve_concept(from_cn, concept_resolution)
        to_table, _tcol, _tvt = _ir_resolve_concept(to_cn, concept_resolution)
        if from_table == to_table:
            # 2 concepts → même table physique. Si role_hint distinct (Z.3),
            # c'est un self-join via une FK qui pointe vers cette table depuis
            # une autre. Mais ce cas-là nécessite un hint via une 3e table
            # intermédiaire — on ne le supporte pas en direct ici. On saute
            # comme avant (pas de FK self-référentielle générique).
            continue
        concept_pair = (from_cn, to_cn)
        if concept_pair in seen_concept_pairs:
            continue
        seen_concept_pairs.add(concept_pair)
        fk = _ir_find_direct_fk(from_table, to_table, fk_lookup)
        if fk:
            # Cas idéal : FK directe → annoter avec les concepts pour le
            # rendering JOIN (Z.3 self-join : alias dédié via concept).
            fk_with_concepts = dict(fk)
            fk_with_concepts["left_concept"] = from_cn
            fk_with_concepts["right_concept"] = to_cn
            _add_step(fk_with_concepts)
        else:
            # Pas de FK directe : fallback BFS shortest-path multi-hop.
            # Moins strict que Phase e.2 (potentielle ambiguïté sur
            # multi-paths équivalents) mais plus tolérant sur les IRs
            # LLM imparfaits qui omettent les tables intermédiaires.
            # Ex : LLM met `{from: dossier, to: année}` alors que le chemin
            # passe par Production → Missions → Dossiers — on récupère via
            # BFS au lieu de planter hard.
            try:
                bfs_steps = _ir_compute_join_chain(
                    [to_table],
                    from_table,
                    fk_lookup,
                )
            except IRValidationError as exc:
                raise IRValidationError(
                    f"joins[{i}] : aucun chemin FK entre '{from_cn}' "
                    f"({from_table}) et '{to_cn}' ({to_table}) — ni direct, "
                    f"ni multi-hop. {exc}"
                ) from exc
            if not bfs_steps:
                raise IRValidationError(
                    f"joins[{i}] : aucun chemin FK entre '{from_cn}' "
                    f"({from_table}) et '{to_cn}' ({to_table}) "
                    f"(BFS shortest-path retourne vide)."
                )
            # Les concepts ne s'appliquent qu'aux tables d'origine. Pour les
            # étapes intermédiaires, pas de concept → l'alias par défaut
            # (alias par table) sera utilisé.
            for j, fk_step in enumerate(bfs_steps):
                step_dict = dict(fk_step)
                # Première étape part de from_table → annoter from_concept.
                if step_dict.get("left_table") == from_table and j == 0:
                    step_dict["left_concept"] = from_cn
                # Dernière étape arrive à to_table → annoter to_concept.
                if step_dict.get("right_table") == to_table:
                    step_dict["right_concept"] = to_cn
                _add_step(step_dict)
    return chain


def _ir_compute_join_chain(
    tables_used: list[str],
    from_table: str,
    fk_lookup: dict[str, list[dict]],
) -> list[dict]:
    """Calcule la séquence de JOIN (BFS shortest-path déterministe) depuis
    ``from_table`` pour atteindre toutes les tables de ``tables_used``.

    fk_lookup = {table: [{"to_table", "from_col", "to_col"}, ...]} —
    extrait via PRAGMA foreign_key_list ou équivalent sur sage_copy.db.

    Output : list[{"left_table", "left_col", "right_table", "right_col"}].
    Ordre = ordre des JOINs à appliquer après le FROM.

    **Déterminisme** : ordre lexicographique sur ``(to_table, from_col,
    to_col)`` à chaque expansion. Garantit que deux runs identiques
    génèrent le même SQL (cf. adversarial review issue #3).

    **Anti-cycle** : ``visited`` set + early-exit `if not needed: break`.
    Pas de boucle infinie possible même sur fk_lookup avec cycles A→B→A.

    Lève IRValidationError si une table n'est pas atteignable via FK.
    """
    visited = {from_table}
    join_path: list[dict] = []
    needed = set(tables_used) - {from_table}
    if not needed:
        return []

    # Pré-calcule incoming FK (cf. perf suggestion #13) — un seul pass.
    incoming_fk: dict[str, list[dict]] = {}
    for src, fks in fk_lookup.items():
        for fk in fks:
            tgt = fk.get("to_table")
            if not tgt:
                continue
            incoming_fk.setdefault(tgt, []).append(
                {
                    "src": src,
                    "from_col": fk.get("from_col"),
                    "to_col": fk.get("to_col"),
                }
            )

    from collections import deque

    queue: deque = deque([(from_table, [])])
    while queue and needed:
        current, path = queue.popleft()
        # Outgoing FK de current — tri lex pour déterminisme.
        out_fks = sorted(
            fk_lookup.get(current, []),
            key=lambda fk: (
                str(fk.get("to_table") or ""),
                str(fk.get("from_col") or ""),
                str(fk.get("to_col") or ""),
            ),
        )
        for fk in out_fks:
            tgt = fk.get("to_table")
            if not tgt or tgt in visited:
                continue
            new_step = {
                "left_table": current,
                "left_col": fk.get("from_col"),
                "right_table": tgt,
                "right_col": fk.get("to_col"),
            }
            new_path = path + [new_step]
            visited.add(tgt)
            if tgt in needed:
                join_path.extend(new_path)
                needed.discard(tgt)
            if not needed:
                break
            queue.append((tgt, new_path))
        if not needed:
            break
        # Incoming FK : tables qui pointent vers current — tri lex.
        in_fks = sorted(
            incoming_fk.get(current, []),
            key=lambda fk: (
                str(fk.get("src") or ""),
                str(fk.get("from_col") or ""),
                str(fk.get("to_col") or ""),
            ),
        )
        for fk in in_fks:
            src = fk.get("src")
            if not src or src in visited:
                continue
            new_step = {
                "left_table": current,
                "left_col": fk.get("to_col"),
                "right_table": src,
                "right_col": fk.get("from_col"),
            }
            new_path = path + [new_step]
            visited.add(src)
            if src in needed:
                join_path.extend(new_path)
                needed.discard(src)
            if not needed:
                break
            queue.append((src, new_path))
    if needed:
        raise IRValidationError(
            f"Tables non-joignables depuis {from_table}: {sorted(needed)}. "
            f"FK manquante ou table hors-schéma."
        )
    # Dédup ordering-stable : si plusieurs JOINs vers la même table, garder
    # le premier (= chemin le plus court grâce au BFS).
    seen_targets: set[str] = set()
    deduped: list[dict] = []
    for j in join_path:
        if j["right_table"] in seen_targets:
            continue
        seen_targets.add(j["right_table"])
        deduped.append(j)
    return deduped


# T11 — Sub-dialect ``komptia_tsql`` : hérite de tsql + preserve les formes
# négatives canoniques (``NOT LIKE`` / ``IS NOT NULL`` / ``NOT IN``) que le
# generator tsql stock normalise en ``NOT [x] LIKE / NOT [x] IS NULL / ...``.
# Ces deux formes sont sémantiquement équivalentes en ANSI SQL, mais la
# forme canonique est plus lisible pour le DBA et matche les conventions
# rédigées par les helpers ``_ir_render_filter`` historiques.
def _komptia_tsql_register() -> None:
    """Enregistre une seule fois le sub-dialect ``komptia_tsql`` dans sqlglot."""
    import sqlglot
    from sqlglot import exp as _exp
    from sqlglot.dialects.tsql import TSQL as _TSQL

    if "komptia_tsql" in getattr(sqlglot.Dialect, "classes", {}):
        return

    class _KomptiaTSQLGenerator(_TSQL.Generator):
        def not_sql(self, expression: _exp.Not) -> str:
            inner = expression.this
            if isinstance(inner, _exp.Like):
                return f"{self.sql(inner, 'this')} NOT LIKE " f"{self.sql(inner, 'expression')}"
            if isinstance(inner, _exp.ILike):
                return f"{self.sql(inner, 'this')} NOT ILIKE " f"{self.sql(inner, 'expression')}"
            if isinstance(inner, _exp.Is) and isinstance(inner.expression, _exp.Null):
                return f"{self.sql(inner, 'this')} IS NOT NULL"
            if isinstance(inner, _exp.In):
                this_sql = self.sql(inner, "this")
                args = self.expressions(inner, flat=True)
                return f"{this_sql} NOT IN ({args})"
            return f"NOT {self.sql(expression, 'this')}"

    class _KomptiaTSQL(_TSQL):
        class Generator(_KomptiaTSQLGenerator):
            pass

    sqlglot.Dialect.classes["komptia_tsql"] = _KomptiaTSQL


_komptia_tsql_register()


def _ir_assemble_select_sqlglot(
    *,
    from_table: str,
    from_alias: str,
    select_clauses: list[str],
    join_chain: list[dict],
    table_alias: dict[str, str],
    where_clauses: list[str],
    group_by_clauses: list[str],
    order_by_clauses: list[str],
    limit: int | None,
    having_clauses: list[str] | None = None,
    dialect: str = "tsql",
) -> str:
    """T11 — Compose le SQL final via sqlglot AST.

    Construit la structure ``SELECT + FROM + JOIN + WHERE + GROUP BY +
    ORDER BY + LIMIT`` en AST sqlglot, puis render via ``dialect``. Les
    fragments intra-clauses (CASE WHEN, EXISTS, agrégats, derivations) sont
    déjà rendus par les helpers ``_ir_render_*`` ; on les injecte dans
    l'AST en parsant des fragments T-SQL côté ``dialect``.

    Bénéfices vs concat string :
        - Validation structurelle : ``parse_one`` rejette les fragments
          malformés AVANT exécution (catch précoce des bugs composer).
        - Préparation T18 : ``dialect`` param permet de re-générer la même
          requête en postgres/mysql/etc (test multi-schémas CI).
        - Quoting cohérent : preserve ``[...]`` en tsql, ``"..."`` en
          postgres, ``` `...` ``` en mysql.

    Generic : aucun nom de table/colonne hardcodé. Le caller fournit les
    composants déjà résolus contre le schéma cible.

    Contrat d'input :
        - Les ``select_clauses`` / ``where_clauses`` / ``group_by_clauses``
          / ``order_by_clauses`` DOIVENT venir des helpers ``_ir_render_*``
          (validation Unicode hostile, escape ``'``, refus de ``[``/``]``
          dans les identifiers). Appeler ce composeur avec des fragments
          arbitraires non validés bypass la défense en profondeur Komptia.
        - Les identifiers passés en paramètres nommés (``from_table``,
          ``from_alias``, ``j["right_table"]``, ...) sont eux RE-validés
          via ``_ir_quote_sql_identifier`` au moment de la construction
          AST (helper ``_id``).

    Notes :
        - Les fragments en input ciblent tsql (les helpers ``_ir_render_*``
          produisent ``[T0].[col]``). On les parse donc TOUJOURS en
          ``dialect="tsql"`` indépendamment du dialect de sortie. Le
          render final utilise le dialect demandé.
        - Le paramètre ``dialect`` est normalisé en lowercase pour éviter
          qu'un caller passant ``"TSQL"`` ou ``"TSql"`` court-circuite le
          remap interne vers ``komptia_tsql``.
    """
    import sqlglot
    from sqlglot import exp

    parse_dialect = "tsql"

    def _id(name: str) -> "exp.Identifier":
        # Quoted identifier — sqlglot preserve les brackets/quotes natives
        # du dialect cible au render. On garde la validation historique
        # ``_ir_quote_sql_identifier`` en amont (refus de ``[``/``]``, chars
        # control, name vide) pour préserver la défense en profondeur que
        # ``ir_to_sql`` v0 portait.
        _ir_quote_sql_identifier(name)
        return exp.to_identifier(name, quoted=True)

    def _parse_or_raise(snippet: str, label: str) -> "exp.Expression":
        try:
            return sqlglot.parse_one(snippet, dialect=parse_dialect)
        except sqlglot.errors.ParseError as exc:
            raise IRValidationError(
                f"Fragment {label} non parseable en {parse_dialect}: " f"{snippet!r}: {exc}"
            ) from exc

    # 1. FROM clause
    from_expr = exp.Table(
        this=_id(from_table),
        alias=exp.TableAlias(this=_id(from_alias)),
    )

    # 2. SELECT items — parser chaque fragment "<expr> AS [alias]"
    select_exprs: list["exp.Expression"] = []
    for clause in select_clauses:
        stmt = _parse_or_raise(f"SELECT {clause}", "SELECT")
        items = getattr(stmt, "expressions", None) or []
        if not items:
            raise IRValidationError(f"Fragment SELECT vide: {clause!r}")
        if len(items) != 1:
            raise IRValidationError(f"Fragment SELECT inattendu (n={len(items)}): {clause!r}")
        select_exprs.append(items[0])

    sel = exp.Select(expressions=select_exprs).from_(from_expr)

    # 3. JOINs — construire chaque exp.Join manuellement (V1 = LEFT JOIN ON eq)
    for j in join_chain:
        l_concept = j.get("left_concept") or ""
        r_concept = j.get("right_concept") or ""
        l_alias_str = _ir_alias_for(l_concept, j["left_table"], table_alias)
        r_alias_str = _ir_alias_for(r_concept, j["right_table"], table_alias)
        join_table = exp.Table(
            this=_id(j["right_table"]),
            alias=exp.TableAlias(this=_id(r_alias_str)),
        )
        on_expr = exp.EQ(
            this=exp.Column(this=_id(j["left_col"]), table=_id(l_alias_str)),
            expression=exp.Column(this=_id(j["right_col"]), table=_id(r_alias_str)),
        )
        join_expr = exp.Join(this=join_table, on=on_expr, kind="LEFT")
        sel.args.setdefault("joins", []).append(join_expr)

    # 4. WHERE — combiner les clauses en AND puis parser une seule fois (preserve
    #    la sémantique des parens compound déjà produites par _ir_render_filter).
    if where_clauses:
        combined = " AND ".join(where_clauses)
        wrap = _parse_or_raise(
            f"SELECT 1 FROM _t WHERE {combined}",
            "WHERE",
        )
        where_node = wrap.find(exp.Where)
        if where_node is None or where_node.this is None:
            raise IRValidationError(f"WHERE introuvable après parse: {combined!r}")
        sel.set("where", exp.Where(this=where_node.this))

    # 5. GROUP BY — parser chaque clause individuellement et appender.
    for clause in group_by_clauses:
        wrap = _parse_or_raise(
            f"SELECT 1 FROM _t GROUP BY {clause}",
            "GROUP BY",
        )
        gb_node = wrap.find(exp.Group)
        if gb_node is None:
            raise IRValidationError(f"GROUP BY introuvable après parse: {clause!r}")
        for ge in list(gb_node.expressions):
            existing = sel.args.get("group")
            if existing is None:
                sel.set("group", exp.Group(expressions=[ge]))
            else:
                existing.expressions.append(ge)

    # 5b. HAVING — F4 (2026-05-21). Filtres sur agrégats. Combiner en AND
    # comme WHERE puis parser une seule fois.
    if having_clauses:
        combined = " AND ".join(having_clauses)
        wrap = _parse_or_raise(
            f"SELECT 1 FROM _t GROUP BY x HAVING {combined}",
            "HAVING",
        )
        having_node = wrap.find(exp.Having)
        if having_node is None or having_node.this is None:
            raise IRValidationError(f"HAVING introuvable après parse: {combined!r}")
        sel.set("having", exp.Having(this=having_node.this))

    # 6. ORDER BY — pareil.
    for clause in order_by_clauses:
        wrap = _parse_or_raise(
            f"SELECT 1 FROM _t ORDER BY {clause}",
            "ORDER BY",
        )
        ob_node = wrap.find(exp.Order)
        if ob_node is None:
            raise IRValidationError(f"ORDER BY introuvable après parse: {clause!r}")
        for oe in list(ob_node.expressions):
            existing = sel.args.get("order")
            if existing is None:
                sel.set("order", exp.Order(expressions=[oe]))
            else:
                existing.expressions.append(oe)

    # 7. LIMIT — dialect tsql render en ``TOP n`` ; postgres/mysql en ``LIMIT n``.
    if isinstance(limit, int) and limit > 0:
        sel.set("limit", exp.Limit(expression=exp.Literal.number(limit)))

    # 8. Render — pour ``tsql`` on utilise le sub-dialect ``komptia_tsql`` qui
    #    preserve les formes négatives canoniques (NOT LIKE / IS NOT NULL /
    #    NOT IN). Pour les autres dialects, on respecte la demande caller.
    #
    #    On normalise la casse (``TSQL`` / ``TSql`` / ``tsql``) AVANT le remap
    #    pour éviter qu'un caller passant la valeur en majuscules tombe
    #    silencieusement sur le generator stock.
    dialect_norm = (dialect or "").lower()
    render_dialect = "komptia_tsql" if dialect_norm == "tsql" else dialect_norm
    return sel.sql(dialect=render_dialect, pretty=False) + ";"


def ir_to_sql(
    ir: dict,
    concept_resolution: dict,
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """Compose un T-SQL SQL Server depuis l'IR + concept_resolution.

    Args:
        ir : Intermediate Representation (cf. schéma en haut du module).
        concept_resolution : Output Phase 2.5 (concept → table.col).
        fk_lookup : optionnel, ``{table: [{"to_table","from_col","to_col"}]}``.
                    Si None ou vide, pas de JOINs auto — le SELECT et le
                    WHERE doivent référencer une seule table (from_concept).

    Returns:
        T-SQL string exécutable.

    **0 LLM call**, **100% déterministe**, **0 hardcode BDD**.
    """
    # Phase Z.2 — mode multi-CTE chained (mutuellement exclusif avec single-IR).
    # Si `ir.ctes` est présent, dispatch vers le composer multi-CTE.
    # Le composer single-IR (ci-dessous) reste inchangé.
    if isinstance(ir, dict) and "ctes" in ir:
        return _ir_compose_multi_cte_chain_sql(
            ir,
            concept_resolution,
            fk_lookup=fk_lookup,
        )

    _ir_validate(ir)

    # Phase d.1 — détection du mode full_outer. Si un item dans select a
    # une derivation avec semantic="full_outer", on dispatch vers le
    # composer dédié qui génère 2 CTE + FULL OUTER JOIN.
    fo_match = _ir_find_full_outer_derivation(ir)
    if fo_match is not None:
        deriv_index, deriv_item = fo_match
        return _ir_compose_full_outer_sql(
            ir,
            deriv_index,
            deriv_item,
            concept_resolution,
            fk_lookup=fk_lookup,
        )

    # Résoudre tous les concepts utilisés → table_alias map (1 alias par
    # table, T-SQL standard).
    table_alias: dict[str, str] = {}
    tables_used: list[str] = []

    def _register_concept(cn: str) -> None:
        table, _col, _vt = _ir_resolve_concept(cn, concept_resolution)
        cr_best = concept_resolution.get(cn, {}).get("best") or {}
        role_hint = cr_best.get("role_hint")
        if role_hint:
            # Phase Z.3 — self-join : alias DÉDIÉ au concept (pas partagé).
            # FIX M5 (adversarial review) — refuser concept_name == table_name
            # avec role_hint : la collision dans `table_alias` produit un alias
            # ambigu (concept ou table ?) avec comportement imprévisible.
            # Le user doit nommer le concept différemment dans concept_resolution
            # (ex: `<table>_<role>`).
            if cn == table:
                raise IRValidationError(
                    f"concept '{cn}' avec role_hint='{role_hint}' a un nom "
                    f"identique à sa table physique. Renommer le concept dans "
                    f"concept_resolution (ex: '{cn}_{role_hint}') pour éviter "
                    f"une collision d'alias en self-join."
                )
            if cn not in table_alias:
                table_alias[cn] = f"T{len(table_alias)}"
                tables_used.append(table)  # même table peut figurer ≥2 fois
        else:
            # Cas standard : 1 alias par table, partagé entre concepts.
            if table not in table_alias:
                # Alias = T0, T1, T2... (générique, pas BDD-spécifique).
                table_alias[table] = f"T{len(table_alias)}"
                tables_used.append(table)

    # Walk de l'IR pour collecter tous les concepts → tables.
    def _walk_select_item(item: dict) -> None:
        if "derivation" in item:
            for side in ("left", "right"):
                operand = item["derivation"].get(side, {})
                if "select_ref" in operand:
                    continue  # Référence à un alias déjà résolu
                _walk_select_item(operand)
        elif "window" in item:
            # F4 — window function : parcours expr (inline) + partition_by + order_by.
            window = item["window"]
            expr_spec = window.get("expr")
            if isinstance(expr_spec, dict) and "select_ref" not in expr_spec:
                _walk_select_item(expr_spec)
            for cn_p in window.get("partition_by_concepts") or []:
                _register_concept(cn_p)
            for o in window.get("order_by") or []:
                cn_o = o.get("concept")
                if cn_o:
                    _register_concept(cn_o)
        else:
            cn = item.get("concept")
            if cn:
                _register_concept(cn)
        for f in item.get("filters") or []:
            cn_f = f.get("concept")
            if cn_f:
                _register_concept(cn_f)

    for it in ir["select"]:
        _walk_select_item(it)
    _register_concept(ir["from_concept"])
    for f in ir.get("filters_global") or []:
        cn_f = f.get("concept")
        if cn_f:
            _register_concept(cn_f)
    for cn in ir.get("group_by_concepts") or []:
        _register_concept(cn)
    for o in ir.get("order_by") or []:
        cn_o = o.get("concept")
        if cn_o:
            _register_concept(cn_o)
    # Phase e.2 — register les concepts apparaissant dans `joins` (sinon
    # les tables intermédiaires comme "mission" ne sont pas enregistrées
    # dans `tables_used` et la chaîne de JOIN ne se construit pas).
    for hint in ir.get("joins") or []:
        if isinstance(hint, dict):
            for key in ("from", "to"):
                cn_h = hint.get(key)
                if cn_h:
                    _register_concept(cn_h)

    # Table racine (FROM).
    from_table, _from_col, _from_vt = _ir_resolve_concept(
        ir["from_concept"],
        concept_resolution,
    )

    # Render SELECT items + collect derivations dépendances.
    select_alias_to_expr: dict[str, str] = {}
    select_clauses: list[str] = []
    for item in ir["select"]:
        alias, expr = _ir_render_select_item(
            item,
            concept_resolution,
            table_alias,
            select_alias_to_expr,
            fk_lookup=fk_lookup,
        )
        select_alias_to_expr[alias] = expr
        select_clauses.append(f"{expr} AS {_ir_quote_sql_identifier(alias)}")

    # JOINs : Phase e.2 — si l'IR fournit `joins` explicites, on les utilise
    # (chemin déterministe spécifié par le LLM ou le user). Sinon, fallback
    # BFS shortest-path. Le BFS peut produire un faux silencieux sur les
    # schémas avec multi-paths équivalents (cas Sage Coala : Dossiers ←
    # Collaborateurs vs Dossiers ← Missions, deux distances 1) → préférer
    # le mode `joins` explicite quand disponible.
    #
    # T11 — on conserve désormais la list[dict] join_chain (et non plus la
    # liste de strings préfabriquées) : c'est le composeur sqlglot qui
    # construit les ``exp.Join`` à partir de cette structure.
    join_chain_emitted: list[dict] = []
    explicit_joins = ir.get("joins") or []
    if explicit_joins and fk_lookup:
        join_chain = _ir_compute_join_chain_from_hints(
            explicit_joins,
            concept_resolution,
            fk_lookup,
        )
        for j in join_chain:
            # Phase Z.3 — alias prioritaire par concept (self-join via
            # role_hint), fallback sur table physique. Si ni le concept ni la
            # table n'ont d'alias (cas où la table n'apparaît qu'en hint),
            # on en crée un par table. La mutation de ``table_alias`` est
            # critique : l'assembleur sqlglot relit la map pour résoudre les
            # aliases.
            l_concept = j.get("left_concept") or ""
            r_concept = j.get("right_concept") or ""
            if l_concept not in table_alias and j["left_table"] not in table_alias:
                table_alias[j["left_table"]] = f"T{len(table_alias)}"
            if r_concept not in table_alias and j["right_table"] not in table_alias:
                table_alias[j["right_table"]] = f"T{len(table_alias)}"
            join_chain_emitted.append(j)
    elif fk_lookup and len(tables_used) > 1:
        join_chain = _ir_compute_join_chain(tables_used, from_table, fk_lookup)
        # BFS chain : pas de concepts associés (mode legacy) → lookup par
        # table uniquement. Les concepts à role_hint NE sont PAS ici (ils
        # passent toujours via explicit_joins).
        join_chain_emitted.extend(join_chain)
    elif len(tables_used) > 1:
        # Multi-table sans fk_lookup : refus explicite (anti-cartesien).
        raise IRValidationError(
            f"Multi-table SQL ({len(tables_used)} tables) sans fk_lookup — "
            f"impossible de calculer les JOIN. Fournir fk_lookup."
        )

    # WHERE filters_global.
    where_clauses: list[str] = []
    for f in ir.get("filters_global") or []:
        where_clauses.append(
            _ir_render_filter(
                f,
                concept_resolution,
                table_alias,
                fk_lookup=fk_lookup,
            )
        )

    # GROUP BY.
    group_by_clauses: list[str] = []
    for cn in ir.get("group_by_concepts") or []:
        table, col, _vt = _ir_resolve_concept(cn, concept_resolution)
        alias_sql = _ir_alias_for(cn, table, table_alias)
        group_by_clauses.append(
            f"{_ir_quote_sql_identifier(alias_sql)}.{_ir_quote_sql_identifier(col)}"
        )

    # F4 — HAVING (filtres sur agrégats via alias_ref).
    # Adversarial fix : le ``value_type`` doit être pris du filter (champ
    # explicite optionnel) — sinon on infère depuis l'agrégat sous-jacent
    # (concept_resolution). HARDCODE "number" cassait sur MIN/MAX de texte
    # (cas légitime « clients dont MIN(status) = 'paid' »).
    having_clauses: list[str] = []
    for hf in ir.get("having_filters") or []:
        ar = hf["alias_ref"]
        # Render le filter en remplaçant alias_ref par l'expression résolue.
        if ar not in select_alias_to_expr:
            raise IRValidationError(
                f"having_filters alias_ref '{ar}' inexistant après render select"
            )
        agg_expr = select_alias_to_expr[ar]
        op = hf["op"]
        if op in ("IS_NULL",):
            having_clauses.append(f"{agg_expr} IS NULL")
            continue
        if op == "IS_NOT_NULL":
            having_clauses.append(f"{agg_expr} IS NOT NULL")
            continue

        # Inférer le value_type :
        #   1. Champ explicite `value_type` du filter (le LLM peut le fournir)
        #   2. Sinon : lookup le concept du select item référencé pour récupérer
        #      le value_type côté concept_resolution (SOT).
        #   3. Sinon : LIKE/NOT_LIKE → text, autres → number (fallback historique)
        explicit_vtype = hf.get("value_type")
        inferred_vtype: str | None = None
        if explicit_vtype in ("text", "code", "number", "date"):
            inferred_vtype = explicit_vtype
        else:
            # Trace back : find the select item with this alias, get its concept.
            for si in ir["select"]:
                if si.get("alias") == ar and "concept" in si:
                    cn_si = si["concept"]
                    cr_entry = concept_resolution.get(cn_si, {})
                    best = cr_entry.get("best") if isinstance(cr_entry, dict) else None
                    if isinstance(best, dict):
                        vt_concept = best.get("value_type")
                        if vt_concept in ("text", "code", "number", "date"):
                            inferred_vtype = vt_concept
                    break
        if inferred_vtype is None:
            inferred_vtype = "text" if op in ("LIKE", "NOT_LIKE") else "number"

        if op in ("IN", "NOT_IN"):
            vals = hf.get("val") or []
            if not isinstance(vals, list) or not vals:
                raise IRValidationError(
                    f"having_filters[{ar}] op '{op}' nécessite val=list non-vide"
                )
            literals = ", ".join(_ir_quote_sql_literal(v, inferred_vtype) for v in vals)
            sql_op = "IN" if op == "IN" else "NOT IN"
            having_clauses.append(f"{agg_expr} {sql_op} ({literals})")
        else:
            # Op binaire scalaire — =, !=, <>, <, >, <=, >=, LIKE, NOT_LIKE.
            val = hf.get("val")
            if val is None:
                raise IRValidationError(
                    f"having_filters[{ar}] op '{op}' nécessite val non-null"
                )
            sql_op_map = {
                "=": "=",
                "!=": "!=",
                "<>": "<>",
                "<": "<",
                ">": ">",
                "<=": "<=",
                ">=": ">=",
                "LIKE": "LIKE",
                "NOT_LIKE": "NOT LIKE",
            }
            sql_op = sql_op_map.get(op)
            if sql_op is None:
                raise IRValidationError(f"having_filters op '{op}' non rendable")
            having_clauses.append(
                f"{agg_expr} {sql_op} {_ir_quote_sql_literal(val, inferred_vtype)}"
            )

    # ORDER BY (par concept ou par alias SELECT).
    order_by_clauses: list[str] = []
    for o in ir.get("order_by") or []:
        cn = o.get("concept")
        ref_alias = o.get("alias")
        direction = o.get("direction", "ASC")
        if ref_alias and ref_alias in select_alias_to_expr:
            order_by_clauses.append(f"{_ir_quote_sql_identifier(ref_alias)} {direction}")
        elif cn:
            table, col, _vt = _ir_resolve_concept(cn, concept_resolution)
            alias_sql = _ir_alias_for(cn, table, table_alias)
            order_by_clauses.append(
                f"{_ir_quote_sql_identifier(alias_sql)}."
                f"{_ir_quote_sql_identifier(col)} {direction}"
            )

    # T11 — Assemblage SQL via sqlglot AST (remplace concat string).
    # Le helper construit ``exp.Select`` avec FROM/JOIN/WHERE/GROUP/ORDER/LIMIT
    # et render via ``dialect``. Les fragments intra-clauses (CASE WHEN,
    # EXISTS, agrégats) restent rendus par ``_ir_render_*`` puis injectés
    # via parsing ``dialect=tsql``.
    limit_val: int | None = None
    raw_limit = ir.get("limit")
    if isinstance(raw_limit, int) and raw_limit > 0:
        limit_val = raw_limit

    return _ir_assemble_select_sqlglot(
        from_table=from_table,
        from_alias=table_alias[from_table],
        select_clauses=select_clauses,
        join_chain=join_chain_emitted,
        table_alias=table_alias,
        where_clauses=where_clauses,
        group_by_clauses=group_by_clauses,
        having_clauses=having_clauses,
        order_by_clauses=order_by_clauses,
        limit=limit_val,
        dialect="tsql",
    )


PHASE4_COMPOSE_IR_SYSTEM_PROMPT = """\
Tu es un compositeur de requêtes analytiques. Ta mission : produire un \
**Intermediate Representation (IR) JSON conceptuel** qui sera traduit \
programmatiquement en SQL par le système. Tu ne connais pas le dialecte SQL \
cible — c'est le système qui choisit le dialecte exécuté et applique les \
conventions adaptées.

# Contrat strict

- Tu n'écris JAMAIS de SQL natif. Tu remplis uniquement les champs de l'IR \
fourni par le tool `compose_ir`.
- Les concepts que tu peux référencer dans l'IR sont **strictement limités** \
à ceux listés dans la section « Concepts résolus » ci-dessous. Référencer \
un concept absent = échec runtime.
- Le système (`ir_to_sql`) traduit ton IR en SQL en utilisant les \
résolutions `(table, col)` déjà calculées. Tu n'as PAS à connaître les \
noms de tables/colonnes ni le dialecte cible.

# Choisir le bon mode

L'IR a deux modes de composition mutuellement exclusifs :

- **Mode A — single-IR** : `select` + `from_concept`. Pour les requêtes à un \
seul niveau d'agrégation : « somme des montants par catégorie », « top-N \
entités », « entités filtrées sur conditions », etc.

- **Mode B — multi-CTE chained** : `ctes` (liste de mini-IR) + `compose` \
(``type: "full_outer_chain"``, ``join_key_alias``, ``select`` final). À \
utiliser quand la requête compare plusieurs périodes ou agrégations \
indépendantes qui doivent être réunies sur une clé commune (ex : « comparer \
metric A en T1 vs T2 par entity », « X et Y agrégés séparément puis combinés »).

# Modes de composition à connaître

## Filters compound (any_of / all_of / not)

Un filter peut être atomique `{concept, op, val}` OU compound :
- `{"any_of": [<filter1>, <filter2>, ...]}` → ``OR`` logique
- `{"all_of": [<filter1>, <filter2>, ...]}` → ``AND`` logique
- `{"not": <filter>}` → ``NOT``

À utiliser quand la condition combine plusieurs critères ou inclut un \
``IS_NULL`` qu'un simple ``NOT_IN`` ne capturerait pas (NULL non comparable \
par ``NOT_IN`` en SQL standard).

Exemple générique : « tous les enregistrements SAUF ceux marqués X (les \
NULL inclus) » → ``{"any_of": [{"concept": "flag", "op": "NOT_IN", "val": ["X"]}, \
{"concept": "flag", "op": "IS_NULL"}]}``.

## CASE WHEN (case_when + else)

Pour ventiler une mesure selon des conditions (ex : « somme par catégorie »), \
utilise un select item ``case_when`` :

```
{"alias": "somme_cat_A", "case_when": [
   {"when": {"concept": "category", "op": "=", "val": "A"},
    "then": {"concept": "amount"}}
 ], "else": {"literal": 0, "value_type": "number"},
 "agg": "sum"}
```

Le ``when`` peut être un filter compound (any_of/all_of/not).

## Partition by Set (partition_by_set)

Pour **ventiler une mesure** selon que la valeur d'un autre concept \
appartient (IN) ou non (NOT IN) à une **liste fermée** de littéraux. \
Cas typique : « production des chefs de mission (liste de 22 codes) vs \
production des autres collaborateurs » :

```
{"alias": "prod_chefs_2023", "concept": "production_amount", "agg": "sum",
 "partition_by_set": {
   "set_name": "chefs_mission",                   # libellé doc
   "values": ["alpha", "bravo", "charlie", ...],   # liste fermée
   "on_concept": "collaborateur_code",            # concept à comparer
   "membership": "in"                             # ou "not_in"
 }}
```

Émet en T-SQL :
``SUM(CASE WHEN T1.[colCodeCollabo] IN ('alpha','bravo',...) THEN T0.[proPrixVenteTotal] ELSE 0 END)``.

Pour la partition complémentaire (« autres collaborateurs »), répéter avec \
``membership: "not_in"`` et la même liste — ainsi tu obtiens 2 colonnes \
qui couvrent l'ensemble sans intersection.

**Garde-fous (le système valide pour toi)** :
- ``on_concept`` doit être dans ``concept_resolution`` (anti-hallucination).
- ``values`` doit être une liste non vide. Types acceptés : ``str`` (quoté \
T-SQL avec échappement apostrophe) ou ``int/float`` (littéraux numériques).
- ``membership`` doit être ``"in"`` ou ``"not_in"``.
- L'élément ELSE est ``0`` pour les aggs additives (sum/count), ``NULL`` \
sinon — préserve la sémantique sans introduire de faux zéros.

Avantage vs UNION ALL de VALUES (anti-pattern run #201) : pas de CTE \
verbeuse, IN clause directe en T-SQL natif. Lisibilité × performance.

## Version Fallback (version_fallback)

Pour récupérer la valeur d'un concept selon une **liste ordonnée de filtres** \
— premier filtre qui retourne non-NULL gagne. Cas typique : « code de \
l'expert-comptable signataire, version 2024 si elle existe, sinon 2023 » :

```
{"alias": "expert_avec_fallback",
 "version_fallback": {
   "value_concept": "expert_comptable",     # concept à récupérer
   "versions": [
     {"filter": {"concept": "millesime", "op": "=", "val": "2024"}},
     {"filter": {"concept": "millesime", "op": "=", "val": "2023"}}
   ]
 }}
```

Émet en T-SQL :
``COALESCE(MAX(CASE WHEN <f1> THEN val), MAX(CASE WHEN <f2> THEN val), ...)``.

L'idiome ``MAX(CASE WHEN cond THEN val ELSE NULL END)`` est l'approche \
standard pour « valeur conditionnelle dans un GROUP BY ». ``COALESCE`` \
prend le 1er non-NULL — donc la 1ère version qui matche gagne.

**Garde-fous** :
- ``value_concept`` et ``filter.concept`` doivent être dans \
``concept_resolution`` (le système refuse les autres formes).
- ``versions`` doit être une liste non vide (1+ versions).
- Chaque ``filter`` accepte les opérateurs IR standard (=, IN, IS_NULL, etc.) \
et les filter compound (any_of/all_of/not).

Avantage vs ``ORDER BY <col> DESC LIMIT 1`` (anti-pattern run #201) : pas \
d'assomption sur l'ordre d'insertion BDD — la sélection est **explicite \
par filtre métier**, pas par ID interne.

## STRING_AGG ordonné (string_agg + string_agg_options)

Pour concaténer les valeurs d'une colonne en une chaîne (ex : « liste des codes \
collaborateurs ayant produit sur le dossier, séparés par virgule, ordonnés \
alphabétiquement, sans doublons »), utilise ``agg: "string_agg"`` :

```
{"alias": "codes_collabs", "concept": "collaborateur", "agg": "string_agg",
 "string_agg_options": {
   "separator": ", ",         # défaut ", "
   "distinct": true,          # défaut true
   "order_by": "collaborateur" # concept name, défaut = même que ``concept``
 }}
```

Émet en T-SQL :
``STRING_AGG(DISTINCT T0.[colCodeCollabo], ', ') WITHIN GROUP (ORDER BY [T0].[colCodeCollabo])``.

**Garde-fous (le système valide pour toi)** :
- ``order_by`` doit être un concept name déjà présent dans ``concept_resolution`` \
(le système refuse les autres formes — pas de SQL natif possible).
- ``separator`` est échappé automatiquement contre les apostrophes (T-SQL).
- ``ORDER BY`` est TOUJOURS émis (T-SQL exige WITHIN GROUP avec ORDER BY).

Si tu as besoin d'agréger des valeurs déjà filtrées (ex : codes des CHEFS DE \
MISSION uniquement), combine avec ``filters`` au niveau du select item — le \
système wrap le CASE WHEN automatiquement dans le STRING_AGG.

## Multi-CTE chained (ctes + compose.full_outer_chain)

Pour comparer N périodes ou agrégations sur une clé commune :

```
{"ctes": [
   {"name": "T1", "select": [...], "from_concept": "...", "filters_global": [...]},
   {"name": "T2", "select": [...], "from_concept": "...", "filters_global": [...]}
 ],
 "compose": {
   "type": "full_outer_chain",
   "join_key_alias": "Entity",          # alias commun à TOUS les CTEs
   "select": [
     {"alias": "Entity", "coalesce_join_key": true},
     {"alias": "MetricT1", "cte_ref": "T1", "alias_in_cte": "Metric"},
     {"alias": "MetricT2", "cte_ref": "T2", "alias_in_cte": "Metric"},
     {"alias": "Delta", "derivation": {
        "op": "subtract",
        "left":  {"cte_ref": "T2", "alias_in_cte": "Metric"},
        "right": {"cte_ref": "T1", "alias_in_cte": "Metric"}}}
   ]}}
```

``coalesce_join_key`` génère ``COALESCE(T1.key, T2.key, ...)`` automatiquement \
(évite les NULL quand une entité n'apparaît que dans certains CTEs). \
``derivation`` peut être imbriquée pour des écarts d'écarts.

### Pattern YoY canonique (rentabilité 2023 vs 2024) — COMBINE 4 primitives

Voici un exemple complet montrant comment composer un **rapport YoY \
multi-mesure ventilé** sans une ligne de SQL natif. Cas réel : « production \
chefs de mission vs autres, par dossier, 2023 vs 2024, avec écart » :

```
{"ctes": [
   {"name": "T2023",
    "select": [
      {"alias": "Dossier", "concept": "dossier_nom"},
      {"alias": "ExpSign", "version_fallback": {
        "value_concept": "expert_comptable",
        "versions": [
          {"filter": {"concept": "millesime", "op": "=", "val": "2024"}},
          {"filter": {"concept": "millesime", "op": "=", "val": "2023"}}
        ]}},
      {"alias": "ProdChefs", "concept": "production_amount", "agg": "sum",
       "partition_by_set": {
         "values": ["alpha", "bravo", "charlie", ...],
         "on_concept": "collaborateur_code",
         "membership": "in"}},
      {"alias": "ProdAutres", "concept": "production_amount", "agg": "sum",
       "partition_by_set": {
         "values": ["alpha", "bravo", "charlie", ...],
         "on_concept": "collaborateur_code",
         "membership": "not_in"}},
      {"alias": "ListChefs", "concept": "collaborateur_code", "agg": "string_agg",
       "string_agg_options": {"separator": ", ", "distinct": true,
                              "order_by": "collaborateur_code"},
       "filters": [{"concept": "collaborateur_code", "op": "IN",
                    "val": ["alpha", "bravo", "charlie", ...]}]}
    ],
    "from_concept": "production_amount",
    "filters_global": [
      {"concept": "millesime", "op": "=", "val": "2023"},
      {"concept": "entite", "op": "=", "val": "EXEMPLE SA"}
    ]},
   {"name": "T2024",
    "select": [/* mêmes select items que T2023 */],
    "from_concept": "production_amount",
    "filters_global": [
      {"concept": "millesime", "op": "=", "val": "2024"},
      {"concept": "entite", "op": "=", "val": "EXEMPLE SA"}
    ]}
 ],
 "compose": {
   "type": "full_outer_chain",
   "join_key_alias": "Dossier",
   "select": [
     {"alias": "Dossier", "coalesce_join_key": true},
     {"alias": "ExpSign", "cte_ref": "T2024", "alias_in_cte": "ExpSign"},
     {"alias": "ProdChefs_2023", "cte_ref": "T2023", "alias_in_cte": "ProdChefs"},
     {"alias": "ProdAutres_2023", "cte_ref": "T2023", "alias_in_cte": "ProdAutres"},
     {"alias": "ProdChefs_2024", "cte_ref": "T2024", "alias_in_cte": "ProdChefs"},
     {"alias": "ProdAutres_2024", "cte_ref": "T2024", "alias_in_cte": "ProdAutres"},
     {"alias": "EcartProd", "derivation": {
        "op": "subtract",
        "left":  {"cte_ref": "T2024", "alias_in_cte": "ProdChefs"},
        "right": {"cte_ref": "T2023", "alias_in_cte": "ProdChefs"}}}
   ]}}
```

**Pattern à retenir** : `ctes` = liste de N CTE (une par période/scope) qui \
agrègent par clé commune. `compose.full_outer_chain` joint sur cette clé \
et expose les colonnes inter-période + les écarts (`derivation` op subtract). \
Tu peux combiner librement avec ``partition_by_set``, ``version_fallback``, \
``string_agg`` dans les CTEs.

**Avantage vs SQL natif manuel** (anti-pattern run #201) : **pas un seul \
SQL hallucinable**. Le LLM IR décrit l'intention métier ; le composer \
émet du T-SQL valide.

## NOT EXISTS / EXISTS (subquery anti-join)

Pour exprimer « X qui n'a aucun Y » (ou « X qui a au moins un Y »), utilise un \
filter avec ``op: "NOT_EXISTS"`` (ou ``"EXISTS"``) :

```
{"op": "NOT_EXISTS",
 "subquery": {"from_concept": "<inner>", "filters": [...]},
 "correlate_via_fk": {"outer_concept": "<X>", "inner_concept": "<Y>"}}
```

Le système trouve automatiquement la FK entre X et Y et génère la \
sous-requête corrélée.

## Self-join (rôles distincts sur la même table)

Si deux concepts résolvent vers la même table physique mais représentent des \
rôles sémantiquement différents (visible dans la section « Concepts résolus » \
via le ``role_hint``), tu peux les utiliser comme s'il s'agissait de tables \
distinctes. Le système crée automatiquement deux alias.

## Joins explicites (joins)

Pour les requêtes multi-tables, tu peux fournir le chemin de jointure via \
``joins: [{"from": "<concept_a>", "to": "<concept_b>"}, ...]``. Chaque paire \
de concepts résout en (table_a, table_b) et le système trouve la FK directe. \
Si tu omets ``joins``, le système utilise un BFS shortest-path qui peut \
choisir un chemin sous-optimal sur les schémas avec multi-paths équivalents — \
préfère toujours fournir ``joins`` pour les requêtes complexes.

## Concat et fonctions d'expression

Pour composer une chaîne à partir de plusieurs colonnes/literals, utilise \
``{"fn": "concat", "args": [<expr1>, <expr2>, ...]}``. Pour extraire \
``YEAR/MONTH/DAY`` d'une date : ``{"fn": "year", "concept": "date_col"}``.

## Window functions (LAG / LEAD / ROW_NUMBER / RANK / DENSE_RANK)

Pour exprimer une comparaison entre lignes adjacentes d'un même résultat (YoY \
sur une seule CTE, top-N par groupe, ranking) sans recourir à plusieurs CTEs \
ou self-join, utilise un select item avec un ``window`` :

```
{"alias": "PrevYearAmount", "window": {
   "fn": "lag",                              # ou "lead", "row_number", "rank", "dense_rank"
   "expr": {"concept": "amount", "agg": "sum"},  # requis pour lag/lead, INTERDIT pour row_number/rank/dense_rank
   "offset": 1,                              # optionnel pour lag/lead (défaut 1)
   "partition_by_concepts": ["entity"],      # optionnel — partitionne le calcul
   "order_by": [{"concept": "year", "direction": "ASC"}]   # OBLIGATOIRE — sans lui, résultat indéterminé
 }}
```

Le système rend ``LAG(SUM(amount), 1) OVER (PARTITION BY ... ORDER BY ...)``. \
**``order_by`` est strictement obligatoire** — sans ORDER BY dans OVER(), \
SQL Server retourne des résultats indéterminés silencieusement.

Pour ROW_NUMBER/RANK/DENSE_RANK (pas d'expression à décaler), omet ``expr`` \
et ``offset`` : ``{"window": {"fn": "row_number", "partition_by_concepts": [...], "order_by": [...]}}``.

Cas d'usage typiques :
- **YoY sans Mode B** : `lag` sur une mesure agrégée groupée par période.
- **Top-N par groupe** : `row_number` + filter externe sur le rank ≤ N (via Mode B + sous-requête, à venir).
- **Croissance % entre lignes** : `derivation.divide` entre une mesure et son `lag`.

## HAVING (filtres sur agrégats)

Les filtres sur des **agrégats** (SUM/AVG/COUNT/MIN/MAX) vont dans \
``having_filters`` (PAS dans ``filters_global``, qui est WHERE et s'évalue \
AVANT l'agrégation).

```
{"having_filters": [
   {"alias_ref": "TotalAmount", "op": ">", "val": 1000},
   {"alias_ref": "OrderCount",  "op": ">=", "val": 10}
 ]}
```

``alias_ref`` doit référencer un alias déjà présent dans ``select`` qui calcule \
un agrégat. Le système combine les filtres en AND et rend ``HAVING <expr> > 1000 \
AND <expr> >= 10``.

**Quand utiliser** : « clients avec au moins 10 commandes », « entités dont le \
total dépasse X ». **Ne PAS utiliser ``filters_global`` pour ça** — ça filtre \
les lignes individuelles AVANT le SUM, donc le total final reste inchangé.

# Comment penser

1. Identifie les **mesures** (sum/avg/count) et **dimensions** (group by).
2. La requête compare-t-elle plusieurs périodes ou agrégations ? → Mode B \
   (multi-CTE). Sinon → Mode A.
3. Pour chaque mesure conditionnelle, exprime-la via ``case_when`` (avec \
   ``when`` compound si la condition est complexe).
4. Pour « X sans Y » → filter ``NOT_EXISTS``.
5. Pour les comparaisons (Δ, ratio), utilise ``derivation`` (single-IR) ou \
   ``compose.select.derivation`` (multi-CTE).

# Anti-patterns à éviter (le composer les rejette de toute façon)

- Alias dupliqué → IRValidationError.
- ``derivation.subtract`` avec filtres disjoints sur le même concept (ex : \
  ``[T2] - [T1]``) en mode single-IR → bloqué (faux silencieux sur entités \
  présentes une seule période). À la place : utilise Mode B (multi-CTE).
- Op incompatible avec le type (ex : ``LIKE`` sur une colonne numérique) → \
  IRValidationError.
- Concept inexistant dans ``concept_resolution`` → IRValidationError.
- ``NOT_IN`` sans ``OR IS_NULL`` quand la colonne peut être NULL → faux \
  silencieux (les NULL sont exclus de NOT_IN en SQL standard). Utilise un \
  compound ``any_of: [NOT_IN, IS_NULL]``.
- Diviser par une expression possiblement nulle sans précaution → le composer \
  wrap automatiquement le denominator dans NULLIF, mais signale-le à \
  l'utilisateur si pertinent.

# Format

Tu DOIS appeler exactement une fois l'outil ``compose_ir`` avec un objet IR \
qui valide le schéma fourni. Pas de texte avant/après l'appel d'outil.
"""


_PHASE4_IR_TOOL_NAME = "compose_ir"


def _phase4_build_ir_tool_schema(
    concept_resolution: dict,
) -> dict:
    """Construit le tool_use schema Anthropic pour Phase 4 IR.

    L'enum ``concept`` est dynamiquement peuplé depuis les concepts effectivement
    résolus par Phase 2.5. Si le LLM tente de référencer un concept absent, le
    SDK Anthropic lève une erreur de schéma (côté serveur ou côté validation).

    **Generic** : aucune mention de table/colonne BDD-spécifique. Le LLM
    voit uniquement des noms de concepts (extraits Phase 1 V2).

    **Phase W.1 (wiring Z.1-Z.8)** — le schéma expose désormais :
        - compound filters (any_of/all_of/not) — Z.1
        - mode multi-CTE chained avec ``ctes`` + ``compose.full_outer_chain`` — Z.2
        - filter EXISTS/NOT_EXISTS avec ``subquery`` + ``correlate_via_fk`` — Z.4
        - derivation arithmetic dans compose.select — Z.6
        - expr_fn ``concat`` + arg ``args`` — Z.7
        - case_when dans select item — pré-Z (manquait au schéma)
        - joins explicites (Phase e.2)

    Stratégie : schéma **permissif** (additionalProperties tolérée sur les
    nouveaux modes) + composer **strict** (``ir_to_sql`` valide tout au render).
    Évite l'explosion de récursion JSON Schema et réduit le risque de divergence
    entre schéma et composer.
    """
    resolved_concept_names = sorted(
        [
            cn
            for cn, res in (concept_resolution or {}).items()
            # P0-C (2026-05-30) : un concept résolu (best) OU une mesure DÉRIVÉE
            # (is_derived — pas de colonne mais composée via sa formule) doit
            # être référençable par le LLM dans l'IR. Sans ``or is_derived``, la
            # mesure dérivée sortait de l'enum → le LLM ne pouvait pas l'émettre
            # → dérivation jamais composée → select vide (bug run #16).
            if isinstance(res, dict)
            and ((res.get("best") and not res.get("error")) or res.get("is_derived"))
        ]
    )
    if not resolved_concept_names:
        resolved_concept_names = ["__no_concept_resolved__"]

    concept_enum = {"type": "string", "enum": resolved_concept_names}

    # ── value scalar (pour val dans filters et literal dans expressions) ──
    scalar_val_schema = {
        "anyOf": [
            {"type": "string", "maxLength": 4000},
            {"type": "number"},
            {"type": "boolean"},
            {"type": "null"},
            {
                "type": "array",
                "items": {
                    "anyOf": [
                        {"type": "string", "maxLength": 4000},
                        {"type": "number"},
                    ],
                },
                "maxItems": 1000,
            },
        ],
    }

    # ── Filter schema (atomique + compound + EXISTS) ──
    # Récursif via un object permissif (composer valide au render).
    filter_schema: dict = {
        "type": "object",
        "properties": {
            # Atomique
            "concept": concept_enum,
            "op": {"type": "string", "enum": list(_IR_VALID_OPS)},
            "val": scalar_val_schema,
            # Compound (Z.1)
            "all_of": {"type": "array", "maxItems": 50},
            "any_of": {"type": "array", "maxItems": 50},
            "not": {"type": "object"},
            # EXISTS / NOT_EXISTS (Z.4)
            "subquery": {"type": "object"},
            "correlate_via_fk": {
                "type": "object",
                "properties": {
                    "outer_concept": concept_enum,
                    "inner_concept": concept_enum,
                },
                "required": ["outer_concept", "inner_concept"],
            },
        },
        # Pas de `required` ni `additionalProperties: False` — un compound
        # n'a ni concept ni op ; un EXISTS n'a pas de val. Composer valide.
    }

    # ── Simple expression (used in case_when then/else, concat args, etc.) ──
    simple_expr_schema = {
        "type": "object",
        "properties": {
            "concept": concept_enum,
            "literal": scalar_val_schema,
            "value_type": {"type": "string", "enum": ["text", "code", "number", "date"]},
            "fn": {"type": "string", "enum": list(_IR_VALID_EXPR_FNS)},
            "args": {"type": "array", "maxItems": 50},  # Z.7 concat
            "select_ref": {"type": "string", "maxLength": 128},
        },
    }

    # ── Case when branch (Z.1-friendly : when peut être compound) ──
    case_when_branch_schema = {
        "type": "object",
        "properties": {
            "when": filter_schema,
            "then": simple_expr_schema,
        },
        "required": ["when", "then"],
    }

    # ── Derivation schema (single-IR + multi-CTE) ──
    derivation_operand_schema = {
        "type": "object",
        # Operand peut être : {select_ref}, {cte_ref+alias_in_cte} (Z.6),
        # {derivation: {...}} (récursion), ou un select_item inline.
        # Composer valide au render.
    }
    derivation_schema = {
        "type": "object",
        "properties": {
            "op": {"type": "string", "enum": list(_IR_VALID_DERIV_OPS)},
            "semantic": {"type": "string", "enum": ["full_outer"]},  # Phase d.1
            "left": derivation_operand_schema,
            "right": derivation_operand_schema,
        },
        "required": ["op", "left", "right"],
    }

    # ── Order by item (commun single-IR + multi-CTE compose + window F4) ──
    # Défini AVANT window_spec_schema et select_item_schema qui le référencent.
    order_by_item_schema = {
        "type": "object",
        "properties": {
            "concept": concept_enum,
            "alias": {"type": "string", "maxLength": 128},
            "direction": {"type": "string", "enum": list(_IR_VALID_DIRECTIONS)},
        },
        "required": ["direction"],
    }

    # ── Window function schema (F4, 2026-05-21) ──
    # Permet d'exprimer YoY/MoM/Top-N-par-groupe sans pattern hardcodé.
    window_spec_schema = {
        "type": "object",
        "properties": {
            "fn": {"type": "string", "enum": list(_IR_VALID_WINDOW_FNS)},
            # expr requis pour lag/lead, interdit pour row_number/rank/dense_rank.
            # Composer valide via _ir_validate_window_spec.
            "expr": {"type": "object"},
            "offset": {"type": "integer", "minimum": 1, "maximum": 1000},
            "partition_by_concepts": {
                "type": "array",
                "items": concept_enum,
                "maxItems": 10,
            },
            "order_by": {
                "type": "array",
                "items": order_by_item_schema,
                "minItems": 1,
                "maxItems": 5,
            },
        },
        "required": ["fn", "order_by"],
    }

    # ── Select item (single-IR) — enrichi case_when (Z.1), window (F4) ──
    select_item_schema = {
        "type": "object",
        "properties": {
            "alias": {"type": "string", "minLength": 1, "maxLength": 128},
            "concept": concept_enum,
            "agg": {"type": "string", "enum": list(_IR_VALID_AGGS)},
            "filters": {"type": "array", "items": filter_schema, "maxItems": 50},
            "case_when": {  # Z.1 — exposé au schéma (pré-Z manquait)
                "type": "array",
                "items": case_when_branch_schema,
                "maxItems": 50,
            },
            "else": simple_expr_schema,
            "derivation": derivation_schema,
            "window": window_spec_schema,  # F4 — LAG/LEAD/ROW_NUMBER/RANK/DENSE_RANK
        },
        "required": ["alias"],
    }

    # ── Having filter schema (F4) — filter sur agrégat via alias_ref ──
    # Adversarial fix : `value_type` optionnel pour HAVING sur MIN/MAX text.
    having_filter_schema = {
        "type": "object",
        "properties": {
            "alias_ref": {"type": "string", "minLength": 1, "maxLength": 128},
            "op": {"type": "string", "enum": list(_IR_VALID_OPS)},
            "val": scalar_val_schema,
            "value_type": {"type": "string", "enum": ["text", "code", "number", "date"]},
        },
        "required": ["alias_ref", "op"],
    }

    # ── Join hint (Phase e.2 — chemin FK explicite) ──
    join_hint_schema = {
        "type": "object",
        "properties": {
            "from": concept_enum,
            "to": concept_enum,
        },
        "required": ["from", "to"],
    }

    # ── CTE schema (mini-IR avec name) — Z.2 ──
    cte_schema = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                # Pattern lâche : SQL identifier-friendly. Composer
                # rejette les ``[`` et ``]`` (anti-injection T-SQL).
                "pattern": r"^[A-Za-z_][A-Za-z0-9_]{0,127}$",
            },
            "select": {"type": "array", "items": select_item_schema, "minItems": 1, "maxItems": 50},
            "from_concept": concept_enum,
            "filters_global": {"type": "array", "items": filter_schema, "maxItems": 50},
            "group_by_concepts": {"type": "array", "items": concept_enum, "maxItems": 30},
            "joins": {"type": "array", "items": join_hint_schema, "maxItems": 50},
            "order_by": {"type": "array", "items": order_by_item_schema, "maxItems": 30},
            "limit": {"type": ["integer", "null"]},
        },
        "required": ["name", "select", "from_concept"],
    }

    # ── Compose select item (Z.2/Z.6/Z.8) ──
    compose_select_item_schema = {
        "type": "object",
        "properties": {
            "alias": {"type": "string", "minLength": 1, "maxLength": 128},
            # Mode coalesce_join_key (Z.8)
            "coalesce_join_key": {"type": "boolean"},
            # Mode cte_ref (Z.2)
            "cte_ref": {"type": "string", "maxLength": 128},
            "alias_in_cte": {"type": "string", "maxLength": 128},
            # Mode derivation (Z.6)
            "derivation": {"type": "object"},  # composer valide récursif
        },
        "required": ["alias"],
    }

    # ── Compose schema (multi-CTE chain top-level) ──
    compose_schema = {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["full_outer_chain"]},
            "join_key_alias": {"type": "string", "minLength": 1, "maxLength": 128},
            "select": {
                "type": "array",
                "items": compose_select_item_schema,
                "minItems": 1,
                "maxItems": 50,
            },
            "order_by": {"type": "array", "items": order_by_item_schema, "maxItems": 30},
        },
        "required": ["type", "join_key_alias", "select"],
    }

    # ── Top-level schema : single-IR + multi-CTE chained (mutuellement
    # exclusifs, validés par le composer). Pas d'``additionalProperties:
    # False`` ni ``required`` strict — le composer dispatch via présence
    # de ``ctes``. ──
    return {
        "name": _PHASE4_IR_TOOL_NAME,
        "description": (
            "Compose l'IR (Intermediate Representation) conceptuel. Le système "
            "le traduit en SQL via `ir_to_sql` en utilisant les résolutions "
            "concept→(table, col) calculées par Phase 2.5. Deux modes "
            "mutuellement exclusifs : (A) single-IR avec `select`+`from_concept` "
            "pour les requêtes simples (1 niveau d'agrégation) ; (B) multi-CTE "
            "chainé avec `ctes`+`compose` pour les comparaisons inter-périodes "
            "ou agrégations chainées. Voir le system prompt pour quand utiliser "
            "chaque mode."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                # ── Mode A : single-IR ──
                "select": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 50,
                    "items": select_item_schema,
                },
                "from_concept": concept_enum,
                "filters_global": {
                    "type": "array",
                    "items": filter_schema,
                    "maxItems": 50,
                },
                "group_by_concepts": {
                    "type": "array",
                    "items": concept_enum,
                    "maxItems": 30,
                },
                "having_filters": {  # F4 (2026-05-21) — filtres sur agrégats
                    "type": "array",
                    "items": having_filter_schema,
                    "maxItems": 50,
                },
                "order_by": {
                    "type": "array",
                    "items": order_by_item_schema,
                    "maxItems": 30,
                },
                "joins": {  # Phase e.2 — chemin FK explicite
                    "type": "array",
                    "items": join_hint_schema,
                    "maxItems": 50,
                },
                "limit": {"type": ["integer", "null"]},
                # ── Mode B : multi-CTE chained (Z.2) ──
                "ctes": {
                    "type": "array",
                    "items": cte_schema,
                    "minItems": 1,
                    "maxItems": 16,
                },
                "compose": compose_schema,
            },
        },
    }


def _phase4_anonymize_sample(sample: object) -> str:
    """Remplace les lettres par `X` et les chiffres par `9` dans un sample.

    Préserve la longueur et la structure pour que le LLM voie le
    `value_type` implicite (ex : `XXX-9999` indique un format code), mais
    ne fuit PAS les valeurs réelles.

    FIX F9 (adversarial review) — utilise les catégories Unicode au lieu de
    `isascii()` :
    - lettres (catégorie L*) → ``X`` (incluse cyrillique, grec, CJK, etc.)
    - chiffres décimaux (catégorie ``Nd``) → ``9`` (incluse arabe-indic
      ٠١٢, fullwidth ０１２, etc. — bug : les chiffres non-ASCII fuyaient
      avec l'ancien check ``isdigit() and isascii()``)
    Caractères spéciaux (`-`, `/`, espaces, ponctuation) → préservés.
    """
    s = str(sample)
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat.startswith("L"):  # Lu/Ll/Lt/Lm/Lo (toutes les lettres)
            out.append("X")
        elif cat == "Nd":  # Number, decimal digit (0-9 + Unicode equiv.)
            out.append("9")
        else:
            out.append(ch)
    return "".join(out)


def _phase4_format_value_constraints(
    extracted: dict,
    concept_resolution: dict,
) -> str:
    """Bloc prompt — par concept, expose ``value_type`` (Phase 2.5) + valeurs
    user (Phase 1). Aide le LLM à choisir le bon concept pour chaque filtre.

    Format human-friendly, sans révéler table/col (mêmes contraintes de
    confidentialité que ``_phase4_format_resolved_concepts``).

    Generic — aucune valeur BDD-spécifique injectée. On ne fait que mapper
    `concepts_v2[].name → values, value_type` depuis les structures
    abstraites Phase 1 / Phase 2.5.
    """
    concepts_v2 = extracted.get("concepts_v2") or []
    if not isinstance(concepts_v2, list):
        return ""

    rows: list[str] = []
    for c2 in concepts_v2:
        if not isinstance(c2, dict):
            continue
        cname = c2.get("name")
        if not isinstance(cname, str) or not cname:
            continue
        res = concept_resolution.get(cname) if isinstance(concept_resolution, dict) else None
        if not isinstance(res, dict) or res.get("error") or not res.get("best"):
            continue
        best = res.get("best")
        # Récupère value_type depuis le top_candidate matchant best.
        value_type = "text"
        for cand in res.get("top_candidates", []) or []:
            if (
                isinstance(cand, dict)
                and cand.get("table") == best.get("table")
                and cand.get("col") == best.get("col")
            ):
                value_type = cand.get("value_type") or "text"
                break
        values = c2.get("values") or []
        # Représentation tronquée des valeurs (max 5 affichées, reste compté)
        if isinstance(values, list) and values:
            shown = values[:5]
            tail = f" (+{len(values) - 5})" if len(values) > 5 else ""
            vals_str = f"valeurs={shown}{tail}"
        else:
            vals_str = "(pas de valeur user — concept dimensionnel)"
        rows.append(f"  - {cname} : value_type={value_type} | {vals_str}")

    if not rows:
        return ""

    header = (
        "# Contraintes valeurs ↔ concepts (Phase 1 + Phase 2.5)\n\n"
        "Pour CHAQUE filtre que tu poseras dans l'IR, choisis le concept dont "
        "le ``value_type`` est compatible avec la valeur (number/date/text/code). "
        "N'invente pas de valeurs — utilise uniquement celles listées ci-dessous.\n"
    )
    return header + "\n".join(rows)


def _phase4_format_resolved_concepts(concept_resolution: dict) -> str:
    """Texte humain-lisible des concepts résolus pour le prompt LLM.

    Ne révèle PAS les noms de tables/colonnes (cf. contrat « le LLM ne
    voit pas le SQL natif »). Les `samples` exposés sont **anonymisés**
    via `_phase4_anonymize_sample` (cf. adversarial review CRITICAL #6) :
    un sample `"AUDIT"` devient `"XXXXX"`, `"2024-01-15"` devient
    `"9999-99-99"` — le LLM voit la structure (longueur, format) sans
    voir la donnée réelle ni la convention BDD-source.
    """
    lines = ["# Concepts résolus (par Phase 2.5)"]
    for cn in sorted((concept_resolution or {}).keys()):
        res = concept_resolution[cn]
        if not isinstance(res, dict):
            continue
        if res.get("error"):
            lines.append(f"  - {cn} : ❌ {res['error']}")
            continue
        method = res.get("method", "?")
        amb = " ⚠️ AMBIGU" if res.get("ambiguous") else ""
        sample_vals: list = []
        value_type: str | None = None
        for c in res.get("top_candidates", [])[:1]:
            sample_vals = list(c.get("samples", []))[:3]
            value_type = c.get("value_type")
        # Anonymisation : on expose uniquement la structure des samples.
        anonymized = [_phase4_anonymize_sample(s) for s in sample_vals]
        extra_parts = []
        if value_type:
            extra_parts.append(f"value_type={value_type}")
        if anonymized:
            extra_parts.append(f"sample_shapes={anonymized}")
        extra_str = (" | " + " | ".join(extra_parts)) if extra_parts else ""
        lines.append(f"  - {cn} : method={method}{amb}{extra_str}")
    return "\n".join(lines)


def _phase4_extract_ir_from_response(response: dict) -> dict:
    """Extrait l'IR depuis la réponse `generate_with_tools` Anthropic-style.

    Format attendu : ``response["content"]`` = list de blocks, dont
    **exactement UN** de type ``tool_use`` avec ``name == "compose_ir"``
    et ``input`` = l'IR JSON.

    Lève `RuntimeError` si :
        - response ou content malformés
        - aucun tool_use ``compose_ir`` trouvé
        - **plusieurs** tool_use ``compose_ir`` (le composer ne sait pas
          lequel choisir — comportement non-défini et risque de faux
          résultat silencieux, cf. adversarial review BLOCKING #3)
        - input du tool_use pas un dict
    """
    content = response.get("content", []) if isinstance(response, dict) else []
    if not isinstance(content, list):
        raise RuntimeError(f"Phase 4 IR — content n'est pas une list: {type(content).__name__}")
    matching_blocks = [
        block
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "tool_use"
        and block.get("name") == _PHASE4_IR_TOOL_NAME
    ]
    if not matching_blocks:
        raise RuntimeError(
            f"Phase 4 IR — aucun tool_use '{_PHASE4_IR_TOOL_NAME}' dans la "
            f"réponse. Le LLM a probablement répondu en texte libre. "
            f"Content: {content!r}"
        )
    if len(matching_blocks) > 1:
        raise RuntimeError(
            f"Phase 4 IR — {len(matching_blocks)} tool_use "
            f"'{_PHASE4_IR_TOOL_NAME}' dans la réponse. Comportement non "
            f"défini : le LLM a appelé le composer plusieurs fois. Resoumets "
            f"avec un prompt plus directif ou rejette ce run."
        )
    ir = matching_blocks[0].get("input", {})
    if not isinstance(ir, dict):
        raise RuntimeError(f"Phase 4 IR — tool_use input pas un dict: " f"{type(ir).__name__}")
    return ir


def _phase4_sanitize_llm_text(text: str, *, limit: int = 280) -> str:
    """Sanitize un texte généré par le LLM avant ré-injection en prompt.

    Anti prompt-injection (FIX M7) : (a) collapse newlines/tabs (empêche un
    « \\n# IGNORE PREVIOUS »), (b) retire les markdown headers en début, (c)
    tronque. Utilisé pour ``interpretation`` (texte libre du LLM Phase 3).
    """
    if not isinstance(text, str) or not text:
        return ""
    s = re.sub(r"[\n\r\t]+", " ", text)
    s = re.sub(r"^#+", "", s.lstrip())
    return s[:limit].strip()


def _phase4_format_one_factsheet(concept_name: str, data: dict) -> list[str]:
    """Formate UNE fiche concept Phase 3 pour le prompt Phase 4 IR.

    Lit la VRAIE structure produite par ``phase_3_concept_factsheets`` :
    ``mode`` / ``interpretation`` / ``top_entity_names`` / ``probes`` (chaque
    probe : ``executed`` / ``error`` / ``row_count`` / ``columns`` /
    ``sample_rows`` / ``null_pct``). Cf. P1 #10 : l'ancien formatter lisait des
    clés inexistantes (samples/cardinality/fk_candidates/notes) → l'empirique
    des probes était SILENCIEUSEMENT PERDU pour le composeur IR.

    Confidentialité : les ``sample_rows`` sont anonymisés structurellement via
    ``_phase4_anonymize_sample`` (le LLM voit le FORMAT, pas les valeurs).

    Dégradation explicite : si ``mode != "ok"`` (degraded_empirical, error,
    parse_error, etc.), émet une ligne ⚠️ DÉGRADÉ pour que le LLM N'INVENTE PAS
    de mesure sans assise empirique.
    """
    if not isinstance(data, dict) or not concept_name:
        return []
    out: list[str] = [f"## Concept `{concept_name}`"]
    mode = data.get("mode", "?")
    if mode != "ok":
        reason = _phase4_sanitize_llm_text(str(data.get("degraded_reason") or ""))
        suffix = f" — {reason}" if reason else ""
        out.append(
            f"  - ⚠️ DÉGRADÉ (mode=`{mode}`{suffix}) : aucune assise empirique "
            f"fiable. NE compose PAS de mesure/filtre sur ce concept sans "
            f"confirmation ; préfère l'omettre ou demander une clarification."
        )
        out.append("")
        return out

    top_names = data.get("top_entity_names") or []
    if isinstance(top_names, list) and top_names:
        out.append(f"  - top entités candidates : {len(top_names)}")
    interp = _phase4_sanitize_llm_text(str(data.get("interpretation") or ""))
    if interp:
        out.append(f"  - interprétation : {interp}")

    probes = data.get("probes") or []
    # Une probe exploitable : exécutée, sans erreur, avec ≥1 ligne (SSoT _probe_is_proven).
    proven = [p for p in probes if _probe_is_proven(p)]
    if not proven:
        out.append(
            "  - ⚠️ aucune probe n'a renvoyé de résultat exploitable "
            "(0 ligne / erreurs) — empirique non confirmé."
        )
        out.append("")
        return out

    out.append(f"  - probes exploitables : {len(proven)}")
    for p in proven[:5]:
        cols = p.get("columns") or []
        cols_str = ", ".join(str(c) for c in cols[:8]) if isinstance(cols, list) else ""
        out.append(
            f"    • {p.get('purpose') or p.get('id') or 'probe'} : "
            f"{p.get('row_count')} ligne(s)"
            + (f" (cols: {cols_str})" if cols_str else "")
        )
        # Samples anonymisés (1re ligne suffit pour le FORMAT des valeurs).
        sample_rows = p.get("sample_rows") or []
        if isinstance(sample_rows, list) and sample_rows:
            first = sample_rows[0]
            cells = first if isinstance(first, (list, tuple)) else [first]
            anon = " | ".join(_phase4_anonymize_sample(c) for c in cells[:8])
            out.append(f"      sample (anonymisé) : {anon}")
        # NULL% : signal de complétude des colonnes (pas de valeur réelle).
        null_pct = p.get("null_pct") or {}
        if isinstance(null_pct, dict) and null_pct:
            high_null = {k: v for k, v in null_pct.items() if isinstance(v, (int, float)) and v >= 50}
            if high_null:
                out.append(
                    "      ⚠️ colonnes très nullables : "
                    + ", ".join(f"{k}={int(v)}%" for k, v in list(high_null.items())[:5])
                )
    out.append("")
    return out


def _phase4_format_factsheets_context(factsheets: dict) -> str:
    """Phase W.4 — texte du contexte empirique Phase 3 pour le prompt Phase 4 IR.

    P1 #10 (2026-05-30) — RÉÉCRIT sur la VRAIE structure des factsheets
    (``per_concept`` → ``mode``/``interpretation``/``top_entity_names``/
    ``probes``). L'ancienne version lisait des clés INEXISTANTES
    (samples/cardinality/fk_candidates/notes) → tout le travail empirique des
    probes Phase 3 était silencieusement perdu pour le composeur IR, qui
    composait à l'aveugle.

    **Confidentialité** : ``sample_rows`` anonymisés structurellement via
    ``_phase4_anonymize_sample`` (lettres → X, chiffres → 9). On ne réutilise
    PAS le bloc brut ``_build_factsheets_block`` (qui expose les valeurs
    réelles, OK pour le path legacy mais pas pour le contexte IR).

    **Dégradation** : chaque concept ``mode != "ok"`` est marqué DÉGRADÉ
    explicitement (anti-invention de mesure par le LLM).

    **Robustesse** : structure inattendue → texte minimal sans planter.
    """
    if not isinstance(factsheets, dict):
        return ""
    per_concept = factsheets.get("per_concept") or factsheets.get("concept_factsheets")
    if isinstance(per_concept, dict):
        items_iter = list(per_concept.items())
    elif isinstance(per_concept, list):
        items_iter = [
            (entry.get("concept", f"_unknown_{i}"), entry)
            for i, entry in enumerate(per_concept)
            if isinstance(entry, dict)
        ]
    else:
        return ""

    body: list[str] = []
    for concept_name, data in items_iter:
        body.extend(_phase4_format_one_factsheet(concept_name, data))
    if not body:
        return ""

    out: list[str] = ["# Contexte empirique BDD (probes Phase 3, samples anonymisés)"]
    out.append("")
    out.append(
        "Résultats de probes T-SQL exécutées sur la BDD réelle pour chaque "
        "concept. Les samples sont anonymisés (lettres → X, chiffres → 9) : tu "
        "vois le FORMAT des valeurs (longueur, structure) sans les données "
        "réelles. Un concept marqué ⚠️ DÉGRADÉ n'a aucune assise empirique — "
        "n'invente pas de mesure/filtre dessus."
    )
    out.append("")
    out.extend(body)
    return "\n".join(out).rstrip()


class Phase4PreflightError(RuntimeError):
    """Pre-validation Phase 4 a détecté une incompatibilité (concept, value)→colonne.

    Levée AVANT l'appel LLM : on refuse de demander au LLM un IR qu'on sait
    déjà infaisable. La cause racine est en amont (Phase 2 rerank ou
    Phase 2.5 résolution) — ce raise rend le bug visible plutôt que de
    le masquer par un crash au render `ir_to_sql`.
    """


class Phase4UnresolvableError(Phase4PreflightError):
    """Phase 4 a détecté des mismatches que la résolution automatique n'a pas
    pu corriger (zéro alternative compatible OU question utilisateur sans
    réponse exploitable).

    Hérite de ``Phase4PreflightError`` pour rétro-compat : les call-sites
    qui catchent l'ancienne exception catchent aussi la nouvelle.

    **Dual message** (anti-fuite topologie BDD) :

    - ``str(exc)`` / ``exc.args[0]`` retourne un message **public** ne
      contenant AUCUN nom de table/colonne — sûr à afficher à un utilisateur
      final via l'agent.
    - ``exc.diagnostic_internal`` contient le message **complet** avec les
      noms de table/colonne + alternatives — réservé aux logs, à l'agent
      LLM admin, et au debug.

    Sans cette séparation, un agent qui sérialise ``str(exc)`` à l'UI
    fuite la topologie BDD du déploiement client, contredisant l'effort de
    masquage de ``_phase4_format_metier_question`` (cf. confidentialité
    multi-niveaux CLAUDE.md).
    """

    def __init__(self, public_message: str, *, diagnostic_internal: str = ""):
        super().__init__(public_message)
        self.diagnostic_internal: str = diagnostic_internal or public_message


# Cap longueur de la réponse utilisateur acceptée par le mapper. Défense
# en profondeur contre une réponse géante (DoS asymétrique faible). Les
# vraies réponses ("1", "option 3", "deuxième") tiennent en <32 chars.
PHASE4_MAX_USER_RESPONSE_CHARS: int = 64

# Troncature du champ ``interpretation`` factsheets injecté dans la
# question utilisateur. Au-delà, on perd l'utilisateur dans le bruit.
PHASE4_INTERPRETATION_TRUNC_CHARS: int = 500

# Combien d'alternatives non-best on garde dans le mismatch (pour Phase 4
# composer + diagnostic). Aligné avec ``top_candidates`` qui en garde 5.
PHASE4_MAX_ALTERNATIVES_KEPT: int = 5

# Combien d'alternatives on affiche dans le message diagnostic humain.
# Plus court que kept car le diagnostic est lu rapidement.
PHASE4_MAX_ALTERNATIVES_SHOWN: int = 3


# Timeout pour ``bridge.ask()`` côté Phase 4 résolution mismatches.
# Plus court que le default 120s du bridge : un utilisateur qui doit
# choisir entre 2-3 candidats clairement formulés répond en <60s ; au-delà
# c'est probablement qu'il est parti ou ne sait pas. Configurable via env
# pour ne pas forcer un seuil sur les utilisateurs avec connexion lente.
import os as _os_phase4  # local alias pour ne pas polluer le namespace global

PHASE4_ASK_TIMEOUT_SECONDS: float = float(
    _os_phase4.environ.get("PHASE4_ASK_TIMEOUT_SECONDS", "60")
)

# Au-delà de ce nombre de questions utilisateur consécutives dans la même
# résolution mismatches, les concepts restants passent en mode degraded
# (log warning) plutôt que de harceler l'utilisateur. Aligné avec le
# principe "budget interaction max" (cf chantier T24).
PHASE4_MAX_ASK_QUESTIONS: int = int(_os_phase4.environ.get("PHASE4_MAX_ASK_QUESTIONS", "2"))


def _phase4_value_type_for_best(top_candidates, best: dict) -> str:
    """Retourne le ``value_type`` de la colonne ``best`` dans ``top_candidates``.

    Single source of truth pour l'extraction du type — utilisé par
    ``_phase4_compute_mismatches`` et tout call-site qui doit mirror la
    logique de ``_ir_resolve_concept``. Fallback "text" si la colonne
    n'est pas dans la liste OU si ``value_type`` y est vide/None.

    Tolère ``top_candidates`` None / non-list / contenant des entrées
    non-dict — retourne "text" par défaut sans raise.

    Generic : aucun nom de table/colonne hardcodé.
    """
    if not isinstance(top_candidates, list):
        return "text"
    best_table = best.get("table") if isinstance(best, dict) else None
    best_col = best.get("col") if isinstance(best, dict) else None
    for cand in top_candidates:
        if not isinstance(cand, dict):
            continue
        if cand.get("table") == best_table and cand.get("col") == best_col:
            return cand.get("value_type") or "text"
    return "text"


def _phase4_value_castable_to_type(value, value_type: str) -> bool:
    """Indique si ``value`` peut être sérialisée comme ``value_type`` par le composer.

    **Single source of truth** : appelle directement ``_ir_quote_sql_literal``
    et retourne False ssi cette fonction lève ``IRValidationError``. Aucune
    regex dupliquée — toute évolution du composer (nouveaux checks Unicode,
    nouveaux formats de date, etc.) est automatiquement répercutée ici sans
    risque de divergence (cf. adversarial review CRITIQUE #1+#2 du fix initial
    où les regex avaient divergé).

    Generic — aucun nom de colonne/table/BDD hardcodé. Coût : un appel regex
    (overhead négligeable pour <100 values par concept).
    """
    try:
        _ir_quote_sql_literal(value, value_type)
        return True
    except IRValidationError:
        return False


def _phase4_compute_mismatches(
    extracted: dict,
    concept_resolution: dict,
) -> list[dict]:
    """Détecte les incompatibilités (concept, value)→colonne sans raise.

    Lecture pure du state : itère sur les `concepts_v2` de Phase 1 et pour
    chaque concept ayant des `values` user, vérifie que la colonne résolue
    par Phase 2.5 (`best`) accepte ces values via `_phase4_value_castable_to_type`.

    Retourne la liste des mismatches détectés. Chaque mismatch contient :
        - concept : nom du concept
        - resolved_table, resolved_col : ce que Phase 2.5 a choisi
        - value_type : type courant déduit des top_candidates
        - incompatible_values : sous-ensemble des values qui ne passent pas
        - all_values : toutes les values user
        - alternatives : top_candidates ≠ best (avec value_type), max 5

    Liste vide si aucune incompatibilité. Generic : aucune connaissance
    BDD-spécifique — uniquement structure de `extracted` et `concept_resolution`.
    """
    concepts_v2 = extracted.get("concepts_v2") or []
    if not isinstance(concepts_v2, list):
        return []  # Phase 1 incomplète — on ne peut pas valider, on laisse passer

    mismatches: list[dict] = []
    for c2 in concepts_v2:
        if not isinstance(c2, dict):
            continue
        cname = c2.get("name")
        if not isinstance(cname, str) or not cname:
            continue
        values = c2.get("values") or []
        if not isinstance(values, list) or not values:
            continue  # Pas de valeurs Phase 1 → rien à valider amont

        res = concept_resolution.get(cname)
        if not isinstance(res, dict):
            continue
        if res.get("error"):
            continue  # Concept non résolu — bug différent, sort du scope preflight
        best = res.get("best")
        if not isinstance(best, dict):
            continue

        # Récupère value_type via le helper unique (mirror de `_ir_resolve_concept`).
        top_cands = res.get("top_candidates")
        if not isinstance(top_cands, list):
            top_cands = []
        value_type = _phase4_value_type_for_best(top_cands, best)

        # Vérifie chaque valeur.
        bad_vals = [v for v in values if not _phase4_value_castable_to_type(v, value_type)]
        if bad_vals:
            mismatches.append(
                {
                    "concept": cname,
                    "resolved_table": best.get("table"),
                    "resolved_col": best.get("col"),
                    "value_type": value_type,
                    "incompatible_values": bad_vals,
                    "all_values": list(values),
                    "alternatives": [
                        {
                            "table": cand.get("table"),
                            "col": cand.get("col"),
                            "value_type": cand.get("value_type"),
                            # T9 — propager samples (cap 5) pour permettre au
                            # helper _phase4_infer_metier_label_for_candidate
                            # d'inférer le pattern. Samples utilisés en lecture
                            # seule, jamais exposés dans le label final.
                            "samples": list((cand.get("samples") or [])[:5]),
                        }
                        for cand in top_cands[:PHASE4_MAX_ALTERNATIVES_KEPT]
                        if isinstance(cand, dict)
                        and (
                            cand.get("table") != best.get("table")
                            or cand.get("col") != best.get("col")
                        )
                    ],
                    "kind": "type_mismatch",
                    "confidence_signals": res.get("confidence_signals") or [],
                    "confidence_score": res.get("confidence_score"),
                }
            )
        elif res.get("requires_disambiguation"):
            # T29★ — Phase 2.5 a signalé une ambiguïté (low_confidence + multi-candidats)
            # mais le top-1 passe quand même le cast. Ne pas trancher aveuglément :
            # exposer un mismatch ``disambiguation_needed`` pour que le resolver
            # tente une preuve empirique via probes T2, ou fallback degraded.
            mismatches.append(
                {
                    "concept": cname,
                    "resolved_table": best.get("table"),
                    "resolved_col": best.get("col"),
                    "value_type": value_type,
                    "incompatible_values": [],  # rien d'incompat — juste ambigu
                    "all_values": list(values),
                    "alternatives": [
                        {
                            "table": cand.get("table"),
                            "col": cand.get("col"),
                            "value_type": cand.get("value_type"),
                            "samples": list((cand.get("samples") or [])[:5]),  # T9
                        }
                        for cand in top_cands[:PHASE4_MAX_ALTERNATIVES_KEPT]
                        if isinstance(cand, dict)
                        and (
                            cand.get("table") != best.get("table")
                            or cand.get("col") != best.get("col")
                        )
                    ],
                    "kind": "disambiguation_needed",
                    "confidence_signals": res.get("confidence_signals") or [],
                    "confidence_score": res.get("confidence_score"),
                }
            )

    return mismatches


def _phase4_format_mismatches_diagnostic(mismatches: list[dict]) -> str:
    """Construit le message diagnostic humain-lisible d'une liste de mismatches.

    Conserve le format exact de l'ancien ``_phase4_preflight_validate`` pour
    rétro-compat (les tests/agent qui parsent ce message continuent à matcher).
    T29★ : les mismatches ``kind="disambiguation_needed"`` sont formatés
    différemment (pas d'incompat à signaler, juste une ambiguïté).
    """
    lines = [
        "Phase 4 — Préflight a détecté des incompatibilités concept↔valeur :",
        "",
    ]
    for m in mismatches:
        kind = m.get("kind", "type_mismatch")
        if kind == "disambiguation_needed":
            # Format T29★ — ambiguïté Phase 2.5, pas un fail dur.
            signals = m.get("confidence_signals") or []
            conf = m.get("confidence_score")
            conf_str = f"{conf:.0f}" if isinstance(conf, (int, float)) else "?"
            lines.append(
                f"  Concept « {m['concept']} » — ambiguïté Phase 2.5 "
                f"(résolution actuelle : {m['resolved_table']}.{m['resolved_col']}, "
                f"value_type={m['value_type']}, confiance={conf_str}/100)"
            )
            if signals:
                lines.append(f"    Signaux d'ambiguïté : {', '.join(signals)}")
            if m.get("alternatives"):
                alt_strs = [
                    f"{a['table']}.{a['col']} ({a['value_type']})"
                    for a in m["alternatives"][:PHASE4_MAX_ALTERNATIVES_SHOWN]
                ]
                lines.append(f"    Alternatives top_candidates : {', '.join(alt_strs)}")
            lines.append("")
            continue
        # Legacy (type_mismatch) — format exact préservé pour rétro-compat.
        lines.append(
            f"  Concept « {m['concept']} » résolu vers "
            f"{m['resolved_table']}.{m['resolved_col']} (value_type={m['value_type']})"
        )
        lines.append(f"    Valeurs user attendues : {m['all_values']}")
        lines.append(f"    Valeurs incompatibles : {m['incompatible_values']}")
        if m["alternatives"]:
            alt_strs = [
                f"{a['table']}.{a['col']} ({a['value_type']})"
                for a in m["alternatives"][:PHASE4_MAX_ALTERNATIVES_SHOWN]
            ]
            lines.append(f"    Alternatives candidates (top_candidates) : {', '.join(alt_strs)}")
        lines.append("")
    lines.append(
        "Cause probable : Phase 2 rerank ou Phase 2.5 ont choisi la mauvaise "
        "colonne pour ce concept. Vérifier le rerank LLM (les `key_columns` "
        "renvoyées) ou la résolution data-driven."
    )
    return "\n".join(lines)


def _phase4_preflight_validate(
    extracted: dict,
    concept_resolution: dict,
) -> None:
    """Wrapper rétro-compat : raise ``Phase4PreflightError`` sur mismatches.

    **Utilisation recommandée** : appeler plutôt
    ``_phase4_resolve_mismatches_async`` qui applique les 4 stratégies
    auto-fix → ask → degraded → unresolvable au lieu de raise tout de suite.

    Cette fonction reste exposée pour les call-sites legacy + tests existants
    qui dépendent de l'ancien comportement. Elle délègue à
    ``_phase4_compute_mismatches`` pour la détection puis raise sur le
    diagnostic formaté.

    **T29★** : les mismatches ``kind="disambiguation_needed"`` ne sont **pas**
    une cause de raise (pas une erreur fatale — le top-1 reste valide au cast,
    juste incertain métier). Ces cas sont gérés par
    ``_phase4_resolve_mismatches_async`` (auto-fix probe / ask / degraded).
    On filtre donc le diagnostic ici sur les seuls ``type_mismatch``.

    Generic : aucune connaissance BDD-spécifique.
    """
    mismatches = _phase4_compute_mismatches(extracted, concept_resolution)
    type_mismatches = [m for m in mismatches if m.get("kind", "type_mismatch") == "type_mismatch"]
    if not type_mismatches:
        return
    raise Phase4PreflightError(_phase4_format_mismatches_diagnostic(type_mismatches))


def _phase4_pick_disambiguation_candidates(
    mismatch: dict,
    probe_validated_pairs: set[tuple[str, str]] | None,
    *,
    max_candidates: int = _PHASE_4_MAX_DISAMBIGUATION_PROBES_PER_CONCEPT,
) -> list[dict]:
    """T29★ — Filtre alternatives pour un mismatch ``kind="disambiguation_needed"``.

    Sélectionne UNIQUEMENT les alternatives **probe-validées** (preuve empirique
    Phase 3 que la (table, col) contient des rows). Sans probe validation pour
    ce concept → retourne ``[]`` (caller marque degraded sans toucher best).

    Différences avec ``_phase4_pick_compat_alternatives`` :
    - Filtrage **strictement probe-driven** (pas juste le cast).
    - Inclut le ``best`` courant **si lui-même est probe-validé** (utile pour
      le présenter à l'utilisateur comme une option parmi d'autres quand 2+
      alternatives probe-validées existent).
    - Cap au ``max_candidates`` premiers (preserve ordre rerank pour ties).

    Cf. chantier T29★ + T2 (probes oracle). Si aucune probe n'a tourné pour ce
    concept (Phase 3 a sauté, etc.), aucune disambiguation possible — fallback
    degraded silencieux (top-1 reste avec ``_degraded_warning``).

    Generic : aucun nom BDD hardcodé.
    """
    if not probe_validated_pairs:
        return []
    all_values = mismatch.get("all_values") or []
    out: list[dict] = []

    # Le best courant peut lui aussi être probe-validé. Le présenter comme une
    # option permet à l'utilisateur de confirmer le top-1 plutôt que de subir
    # un switch implicite.
    best_table = mismatch.get("resolved_table")
    best_col = mismatch.get("resolved_col")
    best_vt = mismatch.get("value_type") or "text"
    if (
        best_table
        and best_col
        and (best_table, best_col) in probe_validated_pairs
        and all(_phase4_value_castable_to_type(v, best_vt) for v in all_values)
    ):
        out.append({"table": best_table, "col": best_col, "value_type": best_vt})

    for alt in mismatch.get("alternatives") or []:
        if not isinstance(alt, dict):
            continue
        alt_t = alt.get("table")
        alt_c = alt.get("col")
        if not alt_t or not alt_c:
            continue
        if (alt_t, alt_c) not in probe_validated_pairs:
            continue
        if alt_t == best_table and alt_c == best_col:
            continue  # déjà ajouté en tête
        alt_vt = alt.get("value_type") or "text"
        if not all(_phase4_value_castable_to_type(v, alt_vt) for v in all_values):
            continue
        out.append(alt)

    return out[:max_candidates]


def _phase4_pick_compat_alternatives(
    mismatch: dict,
    probe_validated_pairs: set[tuple[str, str]] | None = None,
) -> list[dict]:
    """Filtre les alternatives du mismatch sur celles dont le ``value_type``
    accepte TOUTES les ``all_values`` user.

    Conserve l'ordre d'apparition (qui reflète la préférence du rerank Phase 2).
    Aucune alternative compatible → liste vide.

    **Chantier T2** : si ``probe_validated_pairs`` est fourni, les alternatives
    dont ``(table, col)`` apparaît dans ce set sont **boostées en tête** de la
    liste (preuve empirique Phase 3 que cette colonne contient des rows
    exploitables). Les autres compat restent à la suite dans l'ordre rerank.

    Generic : utilise uniquement ``_phase4_value_castable_to_type``, aucun
    nom de table/colonne hardcodé.
    """
    all_values = mismatch.get("all_values") or []
    compat: list[dict] = []
    for alt in mismatch.get("alternatives") or []:
        if not isinstance(alt, dict):
            continue
        alt_vt = alt.get("value_type") or "text"
        if all(_phase4_value_castable_to_type(v, alt_vt) for v in all_values):
            compat.append(alt)

    # Bump T2 : si on a des paires probe-validées, on stable-sort par
    # "validated d'abord" tout en préservant l'ordre original pour les
    # ties (preserve rerank preference within each bucket).
    if probe_validated_pairs:
        compat.sort(
            key=lambda alt: 0 if (alt.get("table"), alt.get("col")) in probe_validated_pairs else 1
        )

    return compat


# ── T2 : Probe oracle (Phase 3 → Phase 4) ─────────────────────────────
#
# Stratégie post-adversarial review :
#   1. Pré-stripper les string literals SQL (`'...'`) AVANT regex pour
#      éviter les faux positifs sur dates `'2024.01.15'`, IPs `'192.168.1.1'`,
#      paths `'a.b.c'`. Sans ce strip, `\w+\.\w+` capture des paires bidon.
#   2. Regex exigent lettre/underscore au début (pas chiffre) → exclut
#      décimaux `2024.01`, `3.14`.
#   3. Mapping alias → table via `FROM/JOIN <table> [AS]? <alias>` ; le
#      pattern `alias.col` est résolu en `(real_table, col)`. Évite que
#      `T1.c` (alias) booste `("T1", "c")`.
#   4. Pseudo-cols détectées par SYNTAXE `AS <col>` (pas une liste
#      hardcodée — respect règle GÉNÉRICITÉ).
#   5. Le single-probe-validated-among-N en `auto_fix` est RETIRÉ
#      (auto_fix uniquement quand 1 seule compat existe ; sinon ask, même
#      avec probe-validation). Évite le silent commit en cas de mauvaise
#      probe.

# Regex compilés au module-level (perf — évite recompilation à chaque appel).
_T2_STRING_LITERAL_PATTERN = re.compile(r"'(?:[^']|'')*'")
_T2_TABLE_PATTERN = re.compile(
    r"\b(?:FROM|JOIN)\s+(?:\[(?P<bracketed>[A-Za-z_]\w*)\]|(?P<bare>[A-Za-z_]\w*))"
    r"(?:\s+(?:AS\s+)?(?P<alias>[A-Za-z_]\w*))?",
    re.IGNORECASE,
)
# Identifier qualifié `table.col` exigeant lettre/_ au début (anti-décimal).
_T2_QUALIFIED_PATTERN = re.compile(r"\b\[?([A-Za-z_]\w*)\]?\s*\.\s*\[?([A-Za-z_]\w*)\]?")
# Pseudo-col via `AS <col>` (alias d'agrégat).
_T2_AS_ALIAS_PATTERN = re.compile(r"\bAS\s+\[?([A-Za-z_]\w*)\]?", re.IGNORECASE)

# Mots-clés SQL qui ne sont JAMAIS des alias de table (évite que `WHERE`,
# `ON`, etc. soient pris pour alias suite à `FROM tbl WHERE`).
_T2_NON_ALIAS_KEYWORDS: frozenset[str] = frozenset(
    {
        "WHERE",
        "ON",
        "GROUP",
        "ORDER",
        "HAVING",
        "LIMIT",
        "INNER",
        "LEFT",
        "RIGHT",
        "FULL",
        "OUTER",
        "JOIN",
        "CROSS",
        "UNION",
        "INTERSECT",
        "EXCEPT",
        "WITH",
        "SELECT",
    }
)


def _t2_strip_string_literals(sql: str) -> str:
    """Remplace les string literals ``'...'`` par ``''`` (vide).

    Évite que ``a.b.c`` ou ``2024.01.15`` dans une string literal soient
    interprétés comme `(table, col)` par les regex aval.
    """
    return _T2_STRING_LITERAL_PATTERN.sub("''", sql)


def _t2_parse_tables_and_aliases(sql_no_strings: str) -> tuple[set[str], dict[str, str]]:
    """Parse les tables FROM/JOIN et leur alias.

    Retourne ``(tables, alias_to_table)``. Les alias qui sont des mots-clés
    SQL réservés sont écartés (pas un alias légitime).
    """
    tables: set[str] = set()
    alias_to_table: dict[str, str] = {}
    for m in _T2_TABLE_PATTERN.finditer(sql_no_strings):
        t = m.group("bracketed") or m.group("bare")
        if not t:
            continue
        tables.add(t)
        alias = m.group("alias")
        if alias and alias.upper() not in _T2_NON_ALIAS_KEYWORDS:
            alias_to_table[alias] = t
    return tables, alias_to_table


def _t2_pseudo_cols(sql_no_strings: str) -> set[str]:
    """Détecte les pseudo-cols via la syntaxe ``AS <col>`` (générique).

    Toute colonne mentionnée après ``AS`` est probablement un alias
    d'agrégat ou de calcul (ex: ``COUNT(*) AS nb`` → ``{"nb"}``). Pas de
    liste hardcodée (respect règle GÉNÉRICITÉ — un user peut avoir une
    vraie col ``COUNT`` ou ``NB``).
    """
    return {m.group(1) for m in _T2_AS_ALIAS_PATTERN.finditer(sql_no_strings)}


def _extract_validated_pairs_from_probe(probe: dict) -> set[tuple[str, str]]:
    """Extrait les ``(table, col)`` valides depuis UNE probe Phase 3 exécutée.

    Étapes :
        1. Validation probe : ``executed`` + ``row_count >= 1`` + pas d'erreur.
        2. Strip string literals SQL (anti faux positif).
        3. Parse tables + alias mapping.
        4. Détecte pseudo-cols (AS …).
        5. ``X.col`` qualifié : si X table physique → ajoute. Si X alias →
           résout via mapping. Sinon skip.
        6. Columns field : association non-ambigüe seulement si 1 table
           FROM/JOIN (skip pseudo-cols).

    Generic : aucun nom BDD hardcodé. Aucune liste-stop-words pour col names.
    """
    if not isinstance(probe, dict):
        return set()
    if not probe.get("executed"):
        return set()
    if probe.get("error"):
        return set()
    row_count = probe.get("row_count")
    if not isinstance(row_count, int) or row_count < 1:
        return set()

    sql = probe.get("sql") or ""
    if not isinstance(sql, str) or not sql.strip():
        return set()

    # 1. Strip string literals AVANT toute regex (anti faux positif).
    sql_no_strings = _t2_strip_string_literals(sql)

    # 2. Tables + alias.
    tables_in_sql, alias_to_table = _t2_parse_tables_and_aliases(sql_no_strings)

    # 3. Pseudo-cols (alias AS) à exclure.
    pseudo_cols = _t2_pseudo_cols(sql_no_strings)

    pairs: set[tuple[str, str]] = set()

    # 4. Références qualifiées `X.col`. X doit être table physique OU alias
    # connu. Sinon on skip (anti faux positif d'alias inconnu).
    for m in _T2_QUALIFIED_PATTERN.finditer(sql_no_strings):
        x, c = m.group(1), m.group(2)
        if c in pseudo_cols:
            continue
        if x in tables_in_sql:
            pairs.add((x, c))
        elif x in alias_to_table:
            pairs.add((alias_to_table[x], c))
        # Sinon : alias inconnu / table hors scope → skip.

    # 5. Columns field non-ambigu seulement si UNE table FROM/JOIN.
    columns = probe.get("columns") or []
    if isinstance(columns, list) and len(tables_in_sql) == 1:
        the_table = next(iter(tables_in_sql))
        for col in columns:
            if not isinstance(col, str) or not col:
                continue
            if col in pseudo_cols:
                continue
            pairs.add((the_table, col))

    return pairs


def _build_probe_validations(factsheets: dict | None) -> dict[str, set[tuple[str, str]]]:
    """Construit un dict ``{concept: set[(table, col)]}`` des paires validées
    par les probes Phase 3 (chantier T2).

    Une paire est "probe-validée" pour un concept c ssi au moins UNE probe
    de ``factsheets["per_concept"][c]["probes"]`` exécutée avec succès
    (``row_count >= 1``, pas d'error) référence cette paire (cf.
    ``_extract_validated_pairs_from_probe``).

    Returns un dict vide si :
        - factsheets None / non-dict
        - per_concept absent / non-dict
        - aucune probe validée

    Generic : aucune connaissance BDD-spécifique.
    """
    if not isinstance(factsheets, dict):
        return {}
    per_concept = factsheets.get("per_concept")
    if not isinstance(per_concept, dict):
        return {}
    validations: dict[str, set[tuple[str, str]]] = {}
    for concept, fs in per_concept.items():
        if not isinstance(fs, dict):
            continue
        probes = fs.get("probes")
        if not isinstance(probes, list):
            continue
        concept_pairs: set[tuple[str, str]] = set()
        for probe in probes:
            concept_pairs |= _extract_validated_pairs_from_probe(probe)
        if concept_pairs:
            validations[concept] = concept_pairs
    return validations


def _phase4_infer_metier_label_for_candidate(
    alt: dict,
    *,
    fallback_index: int = 0,
) -> str:
    """T9 — Génère un libellé métier court pour une alternative compat.

    Le but : différencier les options présentées à l'utilisateur sans
    exposer (a) les noms de tables/colonnes BDD (b) les samples bruts —
    juste un descripteur **sémantique** (forme/type) pour orienter le choix.

    Stratégie 0 LLM (programmatique) :

    1. ``value_type='date'`` → ``"date"``
    2. Analyse des samples (si dispo) pour inférer un pattern :
       - longueur moyenne ≤6 chars + alphanumeric → ``"code court alphanumérique"``
       - ≤6 chars + digits only → ``"code numérique court"``
       - ≤6 chars + alpha only → ``"code texte court"``
       - >20 chars + spaces → ``"libellé textuel long"``
       - 7-20 chars + spaces → ``"libellé textuel"``
       - has_punct (-, /, _, .) + has_digit → ``"code structuré (avec séparateurs)"``
       - has_digit + has_alpha + 7-20 chars → ``"code alphanumérique"``
    3. Fallback par ``value_type`` :
       - ``"number"`` → ``"valeur numérique"``
       - ``"code"`` → ``"code"``
       - ``"text"`` → ``"libellé textuel"``
       - autre → ``f"option {fallback_index}"`` (générique)

    **Sécurité confidentialité — CRITIQUE** : ce helper n'expose JAMAIS la
    valeur d'un sample dans le label retourné. Les samples sont LUS pour
    inférer le pattern (longueur, classes de caractères), mais le label
    final décrit le pattern abstraitement (``"code court alphanumérique"``,
    pas ``"code court alphanumérique comme 'XX-1', 'YZ-2'"``).

    Generic : aucun nom de table/colonne ni valeur réelle hardcodée. Aucune
    connaissance Sage/Coala-spécifique. Fonctionne sur toute BDD source.

    Args:
        alt: dict d'alternative avec keys ``value_type``, ``samples`` (optionnel).
            Autres keys (table, col, evidence_score, ...) ignorées.
        fallback_index: numéro d'option à utiliser dans le fallback final
            (rarement atteint). Par convention le caller passe ``i`` (1-based).

    Returns:
        Un libellé métier court (str), sans noms BDD ni samples bruts.
    """
    if not isinstance(alt, dict):
        return f"option {fallback_index}"
    vt = (alt.get("value_type") or "").lower()
    if vt == "date":
        return "date"
    samples_raw = alt.get("samples") or []
    if not isinstance(samples_raw, list):
        samples_raw = []
    # Filtre samples utilisables (str non vide)
    sample_strs: list[str] = [str(s) for s in samples_raw[:10] if s is not None and str(s).strip()]
    if sample_strs:
        lens = [len(s) for s in sample_strs]
        avg_len = sum(lens) / len(lens)
        has_digit = any(any(c.isdigit() for c in s) for s in sample_strs)
        has_alpha = any(any(c.isalpha() for c in s) for s in sample_strs)
        has_space = any(" " in s for s in sample_strs)
        has_punct = any(any(c in "-/_." for c in s) for s in sample_strs)

        if avg_len <= 6:
            if has_digit and has_alpha:
                return "code court alphanumérique"
            if has_digit and not has_alpha:
                return "code numérique court"
            if has_alpha and not has_digit:
                return "code texte court"
            return "code court"
        if avg_len > 20 and has_space:
            return "libellé textuel long"
        if has_space:
            return "libellé textuel"
        if has_punct and has_digit:
            return "code structuré (avec séparateurs)"
        if has_digit and has_alpha:
            return "code alphanumérique"
        if has_alpha and not has_digit:
            return "libellé textuel"

    # Fallback par value_type uniquement
    if vt == "number":
        return "valeur numérique"
    if vt == "code":
        return "code"
    if vt == "text":
        return "libellé textuel"
    return f"option {fallback_index}"


def _phase4_format_metier_question(
    mismatch: dict,
    compat_alternatives: list[dict],
    factsheets: dict | None = None,
) -> tuple[str, list[str]]:
    """Génère une question MÉTIER (NL) à partir d'un mismatch + alternatives.

    Format retourné : ``(question_text, options_labels)``.

    Principe : ne PAS exposer les noms de tables/colonnes à l'utilisateur.
    Les labels sont enrichis (T9) avec un descripteur métier inféré
    programmatiquement (type, forme, longueur des samples) — sans exposer
    les valeurs samples. Quand ``factsheets[concept]["interpretation"]``
    existe, on l'injecte en contexte (l'interprétation LLM Phase 3 est déjà
    rédigée en termes métier).

    **T9 (2026-05-11)** : chaque option a maintenant un descripteur métier
    court (``"Option 1 — code court alphanumérique"`` au lieu de ``"Option 1"``
    seul). Inféré via :func:`_phase4_infer_metier_label_for_candidate`. 0
    appel LLM, déterministe.

    ``mismatch["samples"]`` ne sont volontairement PAS injectés EN BRUT :
    exposer des samples = fuite des données réelles du déploiement client
    (interdit par la confidentialité Komptia). Les samples sont utilisés
    UNIQUEMENT pour inférer le pattern abstrait du label.

    Generic : aucune valeur de domaine (nom d'entité, libellé métier, etc.)
    hardcodée.
    """
    concept = mismatch.get("concept") or "?"

    intro: list[str] = [
        f"Pour le concept « {concept} », plusieurs interprétations sont possibles "
        f"dans cette base.",
    ]

    # Contexte factsheets si dispo (interprétation déjà en termes métier).
    if isinstance(factsheets, dict):
        per_concept = factsheets.get("per_concept")
        if isinstance(per_concept, dict):
            fs = per_concept.get(concept)
            if isinstance(fs, dict):
                interp = fs.get("interpretation")
                if isinstance(interp, str) and interp.strip():
                    # Tronquer pour ne pas noyer l'utilisateur.
                    interp_short = interp.strip()[:PHASE4_INTERPRETATION_TRUNC_CHARS]
                    intro.append("")
                    intro.append(f"Contexte : {interp_short}")

    intro.append("")
    intro.append("Lequel correspond à ton intention ?")
    intro.append("")

    option_labels: list[str] = []
    for i, alt in enumerate(compat_alternatives, start=1):
        # T9 : libellé métier inféré (pas de fuite de table/col/sample bruts).
        metier_descr = _phase4_infer_metier_label_for_candidate(
            alt if isinstance(alt, dict) else {},
            fallback_index=i,
        )
        label = f"Option {i} — {metier_descr}"
        option_labels.append(label)
        intro.append(f"  {label}")

    intro.append("")
    intro.append(
        "Réponds par le numéro (« 1 », « 2 », …) ou laisse vide pour me "
        "laisser choisir avec une note de prudence."
    )
    return "\n".join(intro), option_labels


# Ordinals reconnus dans la réponse utilisateur. Trié par longueur de clé
# décroissante pour éviter qu'un mot court ("first") soit matché en
# substring quand le mot plus long voulu ("firstable") est présent.
# Le mapper utilise `\bWORD\b` (word-boundary regex) pour éliminer les
# faux positifs de type "secondaire" → "second", "firstable" → "first".
_PHASE4_ORDINALS: tuple[tuple[str, int], ...] = tuple(
    sorted(
        [
            ("premier", 1),
            ("première", 1),
            ("1er", 1),
            ("1ère", 1),
            ("first", 1),
            ("deuxième", 2),
            ("deuxieme", 2),
            ("second", 2),
            ("seconde", 2),
            ("2e", 2),
            ("2nd", 2),
            ("troisième", 3),
            ("troisieme", 3),
            ("3e", 3),
            ("3rd", 3),
            ("third", 3),
            ("quatrième", 4),
            ("quatrieme", 4),
            ("4e", 4),
            ("4th", 4),
            ("fourth", 4),
            ("cinquième", 5),
            ("cinquieme", 5),
            ("5e", 5),
            ("5th", 5),
            ("fifth", 5),
        ],
        key=lambda kv: -len(kv[0]),
    )
)


def _phase4_map_user_response_to_alternative(
    response: str,
    compat_alternatives: list[dict],
    option_labels: list[str],
) -> dict | None:
    """Map la réponse user (string libre) à une alternative concrète.

    Stratégies en cascade (priorité décroissante) :
      1. Type/longueur invalide → None (str cap = ``PHASE4_MAX_USER_RESPONSE_CHARS``)
      2. Entier direct ("1", "2") dans les bornes → l'alternative
      3. Pattern ``\\boption\\s*(\\d+)\\b`` → l'alternative
      4. Ordinal exact en français/anglais (word-boundary, plus long en
         premier) → l'alternative. Critère word-boundary élimine les
         faux positifs comme "secondaire", "firstable", "thirdparty".
      5. Sinon → None (degraded, log warning)

    Generic : aucune sémantique BDD. Mapping pur sur les labels structurels.
    """
    if not isinstance(response, str):
        return None
    cleaned = response.strip().lower()
    if not cleaned:
        return None
    # Défense en profondeur : cap longueur (sécurité — pas d'int() sur
    # une string géante qui pourrait faire un BigInt alloc + bloquer
    # l'event loop). Le WS handler doit aussi capper côté input.
    if len(cleaned) > PHASE4_MAX_USER_RESPONSE_CHARS:
        return None

    # Étape 2 : entier direct
    try:
        idx = int(cleaned)
        if 1 <= idx <= len(compat_alternatives):
            return compat_alternatives[idx - 1]
    except (ValueError, TypeError):
        pass

    # Étape 3 : "option N" pattern (word-boundary autour de "option")
    import re as _re_local

    m = _re_local.search(r"\boption\s*(\d+)\b", cleaned)
    if m:
        try:
            idx = int(m.group(1))
            if 1 <= idx <= len(compat_alternatives):
                return compat_alternatives[idx - 1]
        except (ValueError, TypeError):
            pass

    # Étape 4 : ordinal word-boundary. Cherche tous les ordinaux présents
    # comme mots entiers (re.escape protège les chars regex spéciaux dans
    # les ordinaux comme "1er"). Si plusieurs ordinaux matchent, on
    # retourne None (ambiguïté = degraded, ex: "le deuxième pas le premier"
    # ne doit pas être interprété comme "premier"). L'ordre de tri par
    # longueur DESC garantit déjà que les mots longs soient testés d'abord.
    matched_indices: set[int] = set()
    for word, idx in _PHASE4_ORDINALS:
        if not (1 <= idx <= len(compat_alternatives)):
            continue
        pattern = r"\b" + _re_local.escape(word) + r"\b"
        if _re_local.search(pattern, cleaned):
            matched_indices.add(idx)
    if len(matched_indices) == 1:
        return compat_alternatives[matched_indices.pop() - 1]
    # 0 match OU ambiguïté (plusieurs ordinaux distincts présents) → degraded.

    # Étape 5 : pas de match clair → degraded
    return None


async def _phase4_resolve_mismatches_async(
    extracted: dict,
    concept_resolution: dict,
    factsheets: dict | None = None,
    bridge: "object | None" = None,
) -> dict:
    """Résout les mismatches Phase 4 via cascade auto-fix → ask → degraded → unresolvable.

    Mute ``concept_resolution`` en place pour les concepts auto-fixés ou
    résolus par l'utilisateur. Retourne un dict de signaux par catégorie
    pour audit et pour notifier les phases aval (T3a pont agent).

    **Stratégies (cascade dans l'ordre)** :

    1. **Auto-fix batch** : pour tous les mismatches ayant exactement UNE
       alternative compatible avec les ``all_values`` user → override
       ``concept_resolution[c]["best"]`` silencieusement (log INFO).

    2. **Ask user batch** : pour les mismatches restants ayant 2+ alternatives
       compatibles ET un ``bridge`` actif, jusqu'à ``PHASE4_MAX_ASK_QUESTIONS``
       questions consécutives. Chaque question est MÉTIER (sans noms de
       table/col). Réponse mappée à une alternative via fuzzy match. Si
       aucun match → degraded.

    3. **Degraded fallback** : pour les mismatches restants (bridge=None,
       timeout, réponse vide, dépassement budget questions) → laisser
       ``best`` tel quel mais ajouter ``"_degraded_warning": True`` dans
       ``concept_resolution[c]``. Phase 4 LLM verra ce flag et adaptera.

    4. **Unresolvable** : pour les mismatches sans aucune alternative
       compatible → reste dans ``unresolvable``. Le caller raise
       ``Phase4UnresolvableError`` après.

    Returns:
        dict avec clés ``auto_fixed``, ``asked``, ``degraded``, ``unresolvable``.
        Chaque liste contient des dicts ``{"concept": str, "reason": str,
        "old_best": dict, "new_best": dict | None}`` selon le cas.

    Generic : aucune connaissance BDD. La fonction lit ``concepts_v2`` et
    ``top_candidates``, applique des heuristiques structurelles uniquement.
    """
    signals: dict[str, list[dict]] = {
        "auto_fixed": [],
        "asked": [],
        "degraded": [],
        "unresolvable": [],
    }

    mismatches = _phase4_compute_mismatches(extracted, concept_resolution)
    if not mismatches:
        return signals

    # T2 chantier : extraire les paires (table, col) validées par les probes
    # Phase 3 (rows réels retournés ⇒ preuve empirique que la col existe et
    # contient des données). Utilisé pour booster les alternatives en T1.
    probe_validations = _build_probe_validations(factsheets)

    # Classification : sépare les mismatches en 3 buckets selon le nombre
    # d'alternatives compatibles. Pas de mutation côté concept_resolution
    # dans cette phase — pure lecture.
    classified = _phase4_classify_mismatches(mismatches, probe_validations)

    # Apply ordre déterministe :
    # 1) Push unresolvable d'abord (pas de mutation cr — caller raise)
    # 2) Apply auto-fix (mutation cr)
    # 3) Apply ask user batch (mutation cr + I/O bridge)
    # 4) T29★ : mark degraded silencieux (disambiguation_needed sans probe)
    for m in classified["unresolvable"]:
        _phase4_record_unresolvable(m, signals)
    for m, compat in classified["auto_fix"]:
        _phase4_apply_auto_fix(m, compat, concept_resolution, signals, probe_validations)
    if classified["ask"]:
        await _phase4_apply_ask_batch(
            classified["ask"],
            concept_resolution,
            factsheets,
            bridge,
            signals,
            probe_validations,
        )
    for m in classified.get("degraded", []):
        # T29★ — disambiguation_needed sans probe-validation : top-1 garde,
        # mais marqué ``_degraded_warning`` (l'agent IA voit le signal et
        # peut prévenir l'utilisateur).
        _phase4_mark_degraded(
            m,
            concept_resolution,
            signals,
            "disambiguation_no_probe_evidence",
        )

    return signals


def _phase4_classify_mismatches(
    mismatches: list[dict],
    probe_validations: dict[str, set[tuple[str, str]]] | None = None,
) -> dict[str, list]:
    """Sépare mismatches en buckets ``unresolvable`` / ``auto_fix`` / ``ask``.

    Pure : aucune mutation de ``concept_resolution``. Aucun I/O. Permet à
    ``_phase4_resolve_mismatches_async`` de rester un orchestrateur fin.

    **Chantier T2** : si ``probe_validations`` fourni, les alternatives
    probe-validées sont placées EN TÊTE de la liste compat (preuve empirique
    Phase 3 que la col contient des rows). MAIS on NE bascule PAS en
    ``auto_fix`` même quand 1 seule est probe-validée (cf. adversarial
    review HIGH #2) — une probe Phase 3 peut être structurellement OK
    mais sémantiquement incorrecte. L'utilisateur garde le contrôle quand
    plusieurs compat existent ; T2 aide juste à présenter le bon ordre.

    Retourne :
        - ``unresolvable`` : list[mismatch] (0 alternative compat)
        - ``auto_fix`` : list[(mismatch, [unique_compat])] (1 SEULE alt compat)
        - ``ask`` : list[(mismatch, compat_alternatives)] (2+ compat ;
          probe-validées en tête pour aider l'utilisateur à choisir)
    """
    classified: dict[str, list] = {
        "unresolvable": [],
        "auto_fix": [],
        "ask": [],
        "degraded": [],  # T29★ — disambiguation_needed sans probe-validation
    }
    for m in mismatches:
        cname = m.get("concept")
        kind = m.get("kind", "type_mismatch")
        validated_pairs = (
            probe_validations.get(cname, set())
            if probe_validations and isinstance(cname, str)
            else set()
        )

        if kind == "disambiguation_needed":
            # T29★ — Ambiguïté Phase 2.5 (low_confidence). On ne route PAS sur
            # unresolvable même sans probe : le top-1 reste valide au cast,
            # juste pas certain métier. Sans probe → degraded (best garde,
            # ``_degraded_warning`` flag pour l'agent). Avec probe(s) →
            # auto_fix ou ask classique.
            disambig_compat = _phase4_pick_disambiguation_candidates(m, validated_pairs)
            if len(disambig_compat) == 0:
                classified["degraded"].append(m)
            elif len(disambig_compat) == 1:
                # Une seule probe-validée : si c'est le best courant → pas de
                # changement (degraded silencieux) ; sinon → auto_fix vers la
                # probe-validée. Le helper inclut best en tête s'il est lui-même
                # probe-validé, donc longueur==1 et premier élément == best →
                # rien à faire ; sinon, premier élément != best → auto_fix.
                first = disambig_compat[0]
                if first.get("table") == m.get("resolved_table") and first.get("col") == m.get(
                    "resolved_col"
                ):
                    # Le best lui-même est la seule probe-validée → on ne
                    # change rien, mais on log degraded pour audit.
                    classified["degraded"].append(m)
                else:
                    classified["auto_fix"].append((m, disambig_compat))
            else:
                classified["ask"].append((m, disambig_compat))
            continue

        # Comportement legacy (kind="type_mismatch") : filtrage par cast.
        compat = _phase4_pick_compat_alternatives(m, validated_pairs)
        if len(compat) == 0:
            classified["unresolvable"].append(m)
        elif len(compat) == 1:
            classified["auto_fix"].append((m, compat))
        else:
            classified["ask"].append((m, compat))
    return classified


def _phase4_record_unresolvable(mismatch: dict, signals: dict) -> None:
    """Ajoute un mismatch à signals['unresolvable']. Pas de mutation cr."""
    signals["unresolvable"].append(
        {
            "concept": mismatch["concept"],
            "reason": "no_compat_alternative",
            "old_best": {"table": mismatch["resolved_table"], "col": mismatch["resolved_col"]},
            "new_best": None,
        }
    )


def _phase4_apply_auto_fix(
    mismatch: dict,
    compat_alternatives: list[dict],
    concept_resolution: dict,
    signals: dict,
    probe_validations: dict[str, set[tuple[str, str]]] | None = None,
) -> None:
    """Applique l'auto-fix : override ``best`` avec l'unique compat + log + signal.

    Mutate ``concept_resolution[mismatch.concept]["best"]`` en place.

    **T2** : si ``probe_validations`` fourni et que l'alternative choisie est
    probe-validée, le signal porte ``reason="probe_validated_alternative"``
    (audit + confiance plus haute) au lieu de ``unique_compat_alternative``.
    """
    if len(compat_alternatives) != 1:
        # Garde-fou : ce helper attend exactement 1 alternative compatible.
        return
    alt = compat_alternatives[0]
    new_best = {"table": alt["table"], "col": alt["col"]}
    concept_resolution[mismatch["concept"]]["best"] = new_best

    # T2 : déterminer la raison précise (probe-validated vs unique-compat).
    cname = mismatch["concept"]
    validated_pairs = (
        probe_validations.get(cname, set())
        if probe_validations and isinstance(cname, str)
        else set()
    )
    reason = (
        "probe_validated_alternative"
        if (new_best["table"], new_best["col"]) in validated_pairs
        else "unique_compat_alternative"
    )
    signals["auto_fixed"].append(
        {
            "concept": mismatch["concept"],
            "reason": reason,
            "old_best": {"table": mismatch["resolved_table"], "col": mismatch["resolved_col"]},
            "new_best": new_best,
        }
    )
    logger.info(
        "Phase 4 auto-fix (%s): concept '%s' resolved %s.%s (incompat) → %s.%s",
        reason,
        mismatch["concept"],
        mismatch["resolved_table"],
        mismatch["resolved_col"],
        new_best["table"],
        new_best["col"],
    )


async def _phase4_apply_ask_batch(
    asks: list[tuple[dict, list[dict]]],
    concept_resolution: dict,
    factsheets: dict | None,
    bridge: "object | None",
    signals: dict,
    probe_validations: dict[str, set[tuple[str, str]]] | None = None,
) -> None:
    """Applique la phase "ask user" : itère sur la liste avec budget limité.

    Pour chaque ``(mismatch, compat_alternatives)`` dans ``asks`` :
      - Si bridge=None OU budget épuisé → degraded silencieux.
      - Sinon → ``bridge.ask()`` + mapping de la réponse.
      - Réponse vide/non-mappable → degraded.
      - Réponse mappée → mute cr + signal asked.

    Mute ``concept_resolution`` en place. Propage ``CancelledError`` (cancel
    utilisateur du run). Toute autre erreur du bridge passe en degraded
    avec log warning (le run continue, on n'arrête pas Phase 4 pour un bug
    bridge transitoire).

    ``probe_validations`` (T2) propagé pour audit du choix utilisateur :
    le signal ``asked`` porte ``reason="probe_validated"`` si la réponse
    user matche une alternative probe-validée.
    """
    questions_asked = 0
    for mismatch, compat in asks:
        if bridge is None or questions_asked >= PHASE4_MAX_ASK_QUESTIONS:
            reason = "no_bridge" if bridge is None else "ask_budget_exceeded"
            _phase4_mark_degraded(mismatch, concept_resolution, signals, reason)
            continue

        response = await _phase4_ask_user_safely(mismatch, compat, factsheets, bridge)
        questions_asked += 1

        formatted_question, option_labels = _phase4_format_metier_question(
            mismatch, compat, factsheets
        )
        # Task #73 — persister la Q/A dans qa_session (y compris quand
        # response="" = "user a laissé vide → Iris choisit par défaut"). Ces
        # entrées sont utilisées par le récap final pour montrer les hypothèses
        # retenues à l'utilisateur, qu'il pourra valider/corriger en aval.
        try:
            from app.services.ai import user_qa_session as _p4_qa_session

            concept_label = mismatch.get("concept") if isinstance(mismatch, dict) else None
            _p4_qa_session.add_qa(
                "phase_4_mismatch",
                formatted_question,
                response,
                concept=concept_label,
            )
        except Exception as _qa_exc:  # noqa: BLE001
            # qa_session ne doit JAMAIS bloquer Phase 4 — log et continue.
            print(f"⚠ Phase 4 — qa_session.add_qa skipped: {_qa_exc}", flush=True)

        chosen_alt = _phase4_map_user_response_to_alternative(
            response,
            compat,
            option_labels,
        )
        if chosen_alt is None:
            _phase4_mark_degraded(
                mismatch,
                concept_resolution,
                signals,
                "user_response_unmapped",
            )
        else:
            _phase4_commit_user_choice(
                mismatch,
                chosen_alt,
                concept_resolution,
                signals,
                probe_validations,
            )


async def _phase4_ask_user_safely(
    mismatch: dict,
    compat_alternatives: list[dict],
    factsheets: dict | None,
    bridge: "object",
) -> str:
    """Wrap ``bridge.ask()`` : formate la question + catch précis des erreurs.

    ``asyncio.CancelledError`` est propagé (le run a été cancelled). Toute
    autre exception (TimeoutError, ConnectionError, RuntimeError du bridge,
    AttributeError sur un bridge corrompu, etc.) est loguée et la réponse
    est forcée à "" → le caller mettra le concept en degraded.

    Catch large mais avec ``logger.exception`` pour traçabilité — un bug
    grave n'est pas masqué silencieusement.
    """
    question_text, _ = _phase4_format_metier_question(mismatch, compat_alternatives, factsheets)
    try:
        return await bridge.ask(
            question_text,
            context={
                "phase_id": "4",
                "concept": mismatch["concept"],
                "num_options": len(compat_alternatives),
            },
            timeout=PHASE4_ASK_TIMEOUT_SECONDS,
            default_response="",
        )
    except asyncio.CancelledError:
        # Le run a été cancelled par l'utilisateur — propagate.
        raise
    except (TimeoutError, asyncio.TimeoutError) as exc:
        logger.warning(
            "Phase 4 ask user timeout for concept '%s': %s — falling back to degraded",
            mismatch["concept"],
            exc,
        )
    except (ConnectionError, OSError) as exc:
        logger.warning(
            "Phase 4 ask user connection error for concept '%s': %s — falling back to degraded",
            mismatch["concept"],
            exc,
        )
    except Exception:  # noqa: BLE001 — log+continue pour bugs bridge transitoires
        # Log avec stack trace pour traçabilité (différent d'un swallow silencieux).
        logger.exception(
            "Phase 4 ask user unexpected error for concept '%s' — falling back to degraded",
            mismatch["concept"],
        )
    return ""


def _phase4_mark_degraded(
    mismatch: dict,
    concept_resolution: dict,
    signals: dict,
    reason: str,
) -> None:
    """Marque un concept en degraded : flag dans cr + signal."""
    concept_resolution[mismatch["concept"]]["_degraded_warning"] = True
    signals["degraded"].append(
        {
            "concept": mismatch["concept"],
            "reason": reason,
            "old_best": {"table": mismatch["resolved_table"], "col": mismatch["resolved_col"]},
            "new_best": None,
        }
    )


def _phase4_commit_user_choice(
    mismatch: dict,
    chosen_alt: dict,
    concept_resolution: dict,
    signals: dict,
    probe_validations: dict[str, set[tuple[str, str]]] | None = None,
) -> None:
    """Applique le choix utilisateur : mute cr + log + signal asked.

    ``probe_validations`` (T2) : si la paire (table, col) du choix utilisateur
    matche une probe-validation Phase 3, on enrichit le signal avec
    ``reason="user_chose_alternative_probe_validated"`` (audit + confiance).
    """
    new_best = {"table": chosen_alt["table"], "col": chosen_alt["col"]}
    concept_resolution[mismatch["concept"]]["best"] = new_best

    cname = mismatch["concept"]
    validated_pairs = (
        probe_validations.get(cname, set())
        if probe_validations and isinstance(cname, str)
        else set()
    )
    reason = (
        "user_chose_alternative_probe_validated"
        if (new_best["table"], new_best["col"]) in validated_pairs
        else "user_chose_alternative"
    )
    signals["asked"].append(
        {
            "concept": mismatch["concept"],
            "reason": reason,
            "old_best": {"table": mismatch["resolved_table"], "col": mismatch["resolved_col"]},
            "new_best": new_best,
        }
    )
    logger.info(
        "Phase 4 user-resolved (%s): concept '%s' %s.%s → %s.%s",
        reason,
        mismatch["concept"],
        mismatch["resolved_table"],
        mismatch["resolved_col"],
        new_best["table"],
        new_best["col"],
    )


def _phase4_unresolved_required_concepts(concept_resolution: dict) -> list:
    """Concepts que Phase 2.5 n'a pas su mapper à une colonne.

    Un concept est « non résolu » s'il porte une ``error`` OU n'a pas de
    ``best``, SAUF s'il est dérivé (``is_derived`` — une mesure dérivée n'a
    légitimement pas de colonne, elle se compose). Sert à transformer un IR
    dégénéré (ex: ``select`` vide) en ``ConceptUnresolvedError`` recoverable
    plutôt qu'en crash brut ``error_kind=unhandled`` (cf. run #16 2026-05-29 :
    rentabilité/facturation non résolus → select vide → IRValidationError nu).
    """
    out: list = []
    for cname, cr in (concept_resolution or {}).items():
        if not isinstance(cr, dict):
            continue
        if cr.get("is_derived"):
            continue
        if cr.get("error") or not cr.get("best"):
            out.append(cname)
    return out


def _phase4_convert_ir_error(exc, concept_resolution: dict):
    """Rend une ``IRValidationError`` « gracieuse » si elle est causée par des
    concepts non résolus.

    Si l'IR est invalide (typiquement ``select`` vide) ALORS que des concepts
    requis n'ont pas été résolus par Phase 2.5, renvoie un
    ``ConceptUnresolvedError`` (sous-type déjà géré par ``PipelineRunner`` →
    ``error_kind=concept_unresolved`` + ``recoverable_via=ask_user_clarification``)
    au lieu d'un crash opaque. Sinon, renvoie l'exception d'origine inchangée
    (vraie erreur structurelle d'IR — ne pas la masquer). Generic : 0 nom BDD.
    """
    if isinstance(exc, ConceptUnresolvedError):
        return exc
    # F1 (adversarial review) : ne convertir QUE le cas dégénéré select-vide.
    # Une vraie erreur structurelle d'IR (alias dupliqué, item malformé, op
    # inconnue...) NE doit PAS être relabelée en concept_unresolved juste
    # parce qu'un concept secondaire est non résolu — sinon on envoie l'user
    # clarifier le mauvais concept et on masque le vrai bug.
    if not isinstance(exc, EmptySelectError):
        return exc
    unresolved = _phase4_unresolved_required_concepts(concept_resolution)
    if not unresolved:
        return exc
    new_exc = ConceptUnresolvedError(
        "Composition SQL impossible : "
        f"{len(unresolved)} concept(s) non résolu(s) par l'analyse du schéma "
        f"({', '.join(str(c) for c in unresolved)}). Demande une clarification "
        "à l'utilisateur pour préciser ces concepts, ou retire-les s'ils sont "
        f"secondaires. (cause interne : {exc})",
        concept_name=str(unresolved[0]),
    )
    new_exc.__cause__ = exc
    return new_exc


def _phase4_build_derivation_lines(extracted: dict) -> list[str]:
    """Lignes prompt « mesures dérivées à composer » pour Phase 4 IR.

    Pour chaque concept ``role=derivation``, produit une ligne décrivant la
    formule (source de vérité) et les concepts sources à composer.

    P0-E (run #16, 2026-05-30) — **anti concepts fantômes** : le dict
    ``derivables`` peut pointer des concepts « fantômes » (générés en
    reconstruction défensive, marqués ``_reconstructed="full"``, JAMAIS
    validés par le LLM). Ex run #16 : ``rentabilité`` avait
    ``derivation_formula = 'facturation totale - production réalisée'`` (vraies
    mesures) MAIS ``derivables['rentabilité'] = ['facturation', 'production']``
    (fantômes courts). Injecter les fantômes en « composer depuis » créait une
    instruction CONTRADICTOIRE pour le LLM (formule = vraies mesures, hint =
    fantômes). On filtre donc les sources ``_reconstructed="full"`` : la
    ``derivation_formula`` reste la SEULE source de vérité de la composition.

    Remap-first (pas de suppression de concept) : on ne touche pas
    ``concepts_v2``, on filtre seulement ce qu'on SUGGÈRE au LLM. Aucune
    fusion de concepts. Générique : ``role``/``_reconstructed`` sont des
    champs sémantiques, 0 nom de table/colonne BDD.
    """
    cv2 = (extracted or {}).get("concepts_v2") or []
    derivables = (extracted or {}).get("derivables", {}) or {}
    # Index des concepts reconstruits "full" (jamais validés LLM) = fantômes.
    # Anti-fusion (adversarial F4) : un nom n'est « fantôme » que si AUCUN
    # concept réel (non reconstruit "full") ne le porte. Si un homonyme réel
    # existe, on NE filtre PAS la source — on ne fusionne/supprime jamais sur
    # une simple collision de nom (cas redouté par l'utilisateur). En pratique
    # concepts_v2 est dédupliqué par nom en amont, mais on ne dépend pas de
    # cette invariante ici.
    real_names = {
        c.get("name")
        for c in cv2
        if isinstance(c, dict) and c.get("_reconstructed") != "full"
    }
    phantom_names = {
        c.get("name")
        for c in cv2
        if isinstance(c, dict) and c.get("_reconstructed") == "full"
    } - real_names
    lines: list[str] = []
    for c in cv2:
        if not isinstance(c, dict):
            continue
        role = c.get("role")
        if not (isinstance(role, str) and role.lower() == "derivation"):
            continue
        cname = c.get("name")
        if not cname:
            continue
        formula = c.get("derivation_formula")
        raw_sources = derivables.get(cname) or []
        # Filtre fantômes : ne suggérer que des sources réelles (validées LLM).
        sources = [s for s in raw_sources if s not in phantom_names]
        line = f"- **{cname}**"
        if formula:
            line += f" : `{formula}`"
        if sources:
            line += f" (composer depuis : {', '.join(str(s) for s in sources)})"
        lines.append(line)
    return lines


async def phase_4_compose_ir(
    query: str,
    extracted: dict,
    concept_resolution: dict,
    *,
    model_id: str,
    api_key: str,
    db_path: Path,
    debug_traces: bool = False,
    factsheets: dict | None = None,
) -> dict:
    """Phase 4 mode IR — LLM produit un IR JSON via tool_use, le système
    traduit en SQL via ``ir_to_sql``.

    Inputs :
        - query : NL utilisateur
        - extracted : output Phase 1.1+1.2 (concepts_v2, etc.)
        - concept_resolution : output Phase 2.5
        - factsheets : optionnel, output Phase 3 (Phase W.4 wiring) — si
          fourni, enrichit le user prompt avec samples anonymisés + cardinalité
          + FK candidates pour donner du contexte au LLM

    Output (dict) :
        - sql                : str — T-SQL composé par le système
        - ir                 : dict — IR JSON émis par le LLM
        - raw_response       : dict — réponse brute SDK
        - tool_schema        : dict — schema tool_use envoyé au LLM
        - system_prompt, user_prompt : str (debug)

    **0 SQL libre** : le LLM n'a aucun moyen d'émettre du SQL natif.
    Le composer Python (`ir_to_sql`) traduit l'IR à partir des résolutions
    concept→(table, col) déjà calculées. Bugs A/B/C/F/G/H impossibles
    par construction.

    **Mismatch resolution** : avant tout appel LLM, on tente de résoudre les
    incompatibilités (concept, value)→colonne détectées par Phase 2.5 via
    une cascade auto-fix → ask_user → degraded → unresolvable
    (cf. ``_phase4_resolve_mismatches_async``). Seuls les mismatches sans
    AUCUNE alternative compatible lèvent ``Phase4UnresolvableError`` et
    arrêtent la pipeline ; les autres cas mutent ``concept_resolution`` en
    place ou ajoutent un signal degraded, et le LLM continue avec le contexte
    enrichi.
    """
    from app.services.ai.llm_providers import AnthropicProvider, LLMRequest
    from app.services.ai.pipeline_ask_user_bridge import get_current_bridge

    if not concept_resolution:
        raise RuntimeError(
            "Phase 4 IR — concept_resolution vide. Phase 2.5 doit être "
            "exécutée avant Phase 4 IR."
        )

    # Résolution des mismatches (auto-fix → ask → degraded → unresolvable).
    # Mute `concept_resolution` en place pour les cas auto-fixés/résolus user.
    # Retourne les signaux par catégorie pour audit et pour informer le LLM
    # via le user_prompt (cas degraded).
    bridge = get_current_bridge()
    resolution_signals = await _phase4_resolve_mismatches_async(
        extracted,
        concept_resolution,
        factsheets,
        bridge,
    )

    # Si des concepts sont strictement irrécupérables (zéro alternative
    # compatible), on raise — le LLM ne peut pas inventer une colonne.
    # Dual message : (a) public sans noms de tables/colonnes (sûr à
    # afficher à un utilisateur final), (b) internal complet pour log/agent
    # LLM (cf. confidentialité multi-niveaux CLAUDE.md).
    if resolution_signals["unresolvable"]:
        unresolvable_concepts = [s["concept"] for s in resolution_signals["unresolvable"]]
        # Internal : full diagnostic avec table.col + alternatives (pour log/agent).
        remaining_mismatches = _phase4_compute_mismatches(extracted, concept_resolution)
        internal_diagnostic = _phase4_format_mismatches_diagnostic(remaining_mismatches)
        internal_diagnostic += (
            "\n\nConcepts strictement irrécupérables (aucune alternative "
            f"compatible) : {unresolvable_concepts}\n"
            "L'agent aval peut tenter ask_user_clarification avec un "
            "discriminateur métier, OU reformuler la query."
        )
        # Public : message sanitized, AUCUN nom de table/colonne exposé.
        # On donne uniquement la liste des concepts (déjà niveau métier).
        public_message = (
            "Phase 4 — impossible de mapper certains concepts à des colonnes "
            "compatibles avec les valeurs fournies par l'utilisateur. "
            f"Concepts concernés : {unresolvable_concepts}. "
            "Pour résoudre, l'utilisateur peut reformuler sa demande, "
            "préciser ce que désigne chaque valeur, ou laisser l'agent "
            "explorer manuellement."
        )
        raise Phase4UnresolvableError(public_message, diagnostic_internal=internal_diagnostic)

    # Log les signaux non-bloquants pour traçabilité.
    if resolution_signals["auto_fixed"]:
        logger.info(
            "Phase 4 IR: %d concept(s) auto-fixed via compat alternative: %s",
            len(resolution_signals["auto_fixed"]),
            [s["concept"] for s in resolution_signals["auto_fixed"]],
        )
    if resolution_signals["asked"]:
        logger.info(
            "Phase 4 IR: %d concept(s) resolved via user clarification: %s",
            len(resolution_signals["asked"]),
            [s["concept"] for s in resolution_signals["asked"]],
        )
    if resolution_signals["degraded"]:
        logger.warning(
            "Phase 4 IR: %d concept(s) in degraded mode (best left as-is): %s",
            len(resolution_signals["degraded"]),
            [s["concept"] for s in resolution_signals["degraded"]],
        )

    # Build tool schema avec enum dynamique sur les concepts résolus.
    tool_schema = _phase4_build_ir_tool_schema(concept_resolution)

    # User prompt : query NL + concepts résolus (sans table/col exposés).
    resolved_block = _phase4_format_resolved_concepts(concept_resolution)
    # Bloc additionnel : pour chaque concept, expose son value_type + les
    # valeurs user Phase 1. Aide le LLM à choisir le bon concept pour chaque
    # filtre (ex: ne pas poser une valeur text sur un concept résolu number).
    # Surface d'erreur réduite : le LLM voit la map (concept → type + values)
    # au lieu d'avoir à deviner.
    values_constraint_block = _phase4_format_value_constraints(extracted, concept_resolution)
    # Phase W.4 — si factsheets dispo, enrichir le contexte avec samples
    # anonymisés des valeurs réelles + observations (cardinalité, FKs).
    factsheets_block = ""
    if factsheets:
        try:
            factsheets_block = _phase4_format_factsheets_context(factsheets)
        except Exception as exc:  # noqa: BLE001
            # Fallback gracieux : si formatage échoue, on continue sans le bloc.
            # Pas de raise — un factsheets corrompu ne doit pas bloquer Phase 4.
            print(f"⚠ Phase 4 IR — factsheets context skipped: {exc}", flush=True)
            factsheets_block = ""
    user_prompt_parts = [
        # Task #95 — date courante injectée en tête de prompt pour interpréter
        # les références temporelles relatives de la requête (« ce mois »,
        # « l'année dernière », etc.). PAS de dialect T-SQL ici (mode IR =
        # dialect-agnostic par doctrine).
        _build_runtime_context_block(),
        f"# Requête utilisateur (NL)\n\n{query}",
        resolved_block,
    ]
    # Task #72 — qa_block étanche cross-phase : injecter les Q/A collectées
    # depuis Phase 1.2.5 / 1.2.6 / Phase 3 pour que Phase 4 IR respecte les
    # précisions déjà obtenues de l'utilisateur (variante de mesure, périmètre,
    # définition de période, etc. — selon le domaine de la BDD).
    from app.services.ai import user_qa_session as p4_qa_session

    p4_qa_block = p4_qa_session.format_for_prompt()
    if p4_qa_block:
        user_prompt_parts.append(p4_qa_block)

    # Todo #9 — Pont apprentissage chat ↔ pipeline autonome.
    # Injecte les Q/SQL validés (insights chat) similaires à la query
    # courante comme few-shot examples. Sans ce pont, la pipeline ne
    # bénéficie PAS des apprentissages accumulés via ``learn_insight``
    # côté chat agent. Helper fail-safe : la pipeline continue toujours
    # même si le training_store est inaccessible (CLI, BDD down, etc.).
    try:
        from app.services.ai.chat_pipeline_bridge import (
            fetch_learned_q_sql_pairs_for,
            format_learned_pairs_for_prompt,
        )

        _learned_pairs = await fetch_learned_q_sql_pairs_for(query, n_results=5)
        _learned_block = format_learned_pairs_for_prompt(_learned_pairs)
        if _learned_block:
            user_prompt_parts.append(
                "# Apprentissages précédents\n\n"
                "Exemples de Q/SQL validés dans le passé pour des questions "
                "similaires (issus du chat agent). Les concepts (table, "
                "colonne) peuvent différer si la BDD a évolué — utilise "
                "comme INSPIRATION, pas comme vérité absolue. Référence "
                "uniquement les concepts résolus de la section précédente.\n\n"
                + _learned_block
            )
    except Exception as exc:  # noqa: BLE001
        # Fail-safe : pas bloquer Phase 4 IR si le pont chat échoue.
        print(f"⚠ Phase 4 IR — chat_pipeline_bridge skipped: {exc}", flush=True)

    if values_constraint_block:
        user_prompt_parts.append(values_constraint_block)
    if factsheets_block:
        user_prompt_parts.append(factsheets_block)
    # Signal degraded : informer le LLM que la résolution de certains concepts
    # est incertaine, qu'il doit en tenir compte (par ex. en filtrant
    # défensivement ou en omettant ce concept du SELECT si le risque est élevé).
    if resolution_signals["degraded"]:
        degraded_concepts = [s["concept"] for s in resolution_signals["degraded"]]
        user_prompt_parts.append(
            "# ⚠ Résolution incertaine\n\n"
            "Les concepts suivants ont une résolution colonne dégradée (le "
            "système n'a pas pu confirmer la bonne colonne avec certitude) :\n"
            f"  {degraded_concepts}\n\n"
            "Pour ces concepts, sois conservateur : préfère NE PAS les inclure "
            "comme filtre dur si le risque de filtrer faussement existe ; "
            "tu peux les inclure dans le SELECT pour information."
        )
    # P0-C (2026-05-30) — Mesures DÉRIVÉES : injecter explicitement la formule de
    # composition. Sans ce bloc, ``derivation_formula`` (extraite Phase 1)
    # n'atteignait JAMAIS le composeur IR (câblée seulement dans le Phase 4
    # LEGACY) → le LLM ne savait pas que rentabilité = facturation - production →
    # select vide → crash (run #16). Le composeur sait déjà rendre l'op
    # derivation (subtract/add/multiply/divide). Générique : lit
    # derivation_formula + derivables produits par Phase 1, zéro nom BDD.
    # P0-E (2026-05-30) — la construction des lignes est extraite dans
    # ``_phase4_build_derivation_lines`` qui FILTRE les sources fantômes
    # (``_reconstructed="full"``) pour ne pas contredire la formule.
    _deriv_lines = _phase4_build_derivation_lines(extracted)
    if _deriv_lines:
        user_prompt_parts.append(
            "# Mesures dérivées à COMPOSER (ne PAS chercher de colonne)\n\n"
            "Ces concepts sont des calculs sur d'autres concepts résolus. "
            "Compose-les via l'opération `derivation` (op `subtract`/`add`/"
            "`multiply`/`divide`) en référençant les concepts sources — n'essaie "
            "PAS de les mapper à une colonne (aucune n'existe).\n\n"
            + "\n".join(_deriv_lines)
        )
    user_prompt_parts.append(
        "# Mission\n\n"
        "Compose l'IR (Intermediate Representation) en appelant l'outil "
        "`compose_ir`. Référence uniquement les concepts listés ci-dessus. "
        "Le système se chargera de traduire en SQL."
    )
    user_prompt = "\n\n".join(user_prompt_parts)

    # Import local — `clamped_max_tokens` lit le registre BDD via constants_ai
    # pour respecter le contrat dynamique LLM (CLAUDE.md). Pas d'import global
    # car constants_ai dépend de l'init BDD (asynchrone).
    from app.constants_ai import clamped_max_tokens

    # tool_choice = forcer l'usage du tool IR (pas de texte libre).
    provider = AnthropicProvider(api_key=api_key)
    request = LLMRequest(
        prompt=user_prompt,
        system=PHASE4_COMPOSE_IR_SYSTEM_PROMPT,
        temperature=0.0,
        max_tokens=clamped_max_tokens(8000, model_name=model_id),
        model=model_id,
    )
    messages = [{"role": "user", "content": user_prompt}]

    print("→ Phase 4 IR : LLM émet l'IR via tool_use...", flush=True)
    # `tool_choice` force l'usage du tool — pas de réponse text-only
    # possible. Côté Anthropic, validation côté serveur (le modèle peut
    # quand même produire un block text + le tool_use, mais doit appeler
    # le tool). Cf. adversarial review BLOCKING #1.
    raw_response = await provider.generate_with_tools(
        request,
        [tool_schema],
        messages,
        tool_choice={"type": "tool", "name": _PHASE4_IR_TOOL_NAME},
        user_id=_pipeline_user_id.get(),
    )

    # Parse IR.
    ir = _phase4_extract_ir_from_response(raw_response)

    # Sauvegarde IR brut AVANT validation (debug — utile pour diagnoser un
    # IR malformé qui ferait planter `ir_to_sql`).
    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_4_compose_ir.json").write_text(
            json.dumps(ir, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # Compose SQL via composer Python pur.
    # NB : pas de pré-call `_ir_validate(ir)` ici car la validation est
    # mode-dependant : `ir_to_sql` dispatch vers `_ir_validate_multi_cte`
    # si `ir.ctes` présent, sinon `_ir_validate` (single-IR). Un pré-call
    # `_ir_validate` plante sur un IR multi-CTE (qui n'a pas de `select`
    # au top-level).
    # W2.3 : utiliser fk_lookup enrichi avec FKs propagées des vues SQL —
    # permet aux concepts résolus vers viewMissions03/viewGroupes01/etc.
    # d'être joints au reste du graphe FK (sinon BFS retourne
    # « tables non-joignables »).
    fk_lookup = get_fk_lookup_from_db_with_views(db_path)
    try:
        sql = ir_to_sql(ir, concept_resolution, fk_lookup=fk_lookup)
    except IRValidationError as _ir_exc:
        # Dégradation gracieuse (P0-A 2026-05-30) : un IR invalide causé par des
        # concepts non résolus (ex: select vide quand la mesure centrale a échoué
        # — run #16) doit remonter en ConceptUnresolvedError recoverable (le
        # runner pose error_kind=concept_unresolved + recoverable_via=ask_user)
        # au lieu d'un crash unhandled avec stacktrace brute. Une vraie erreur
        # structurelle d'IR (sans concept non résolu) reste levée telle quelle.
        raise _phase4_convert_ir_error(_ir_exc, concept_resolution)

    if debug_traces:
        (DEBUG_TRACES_DIR / "phase_4_compose_ir.sql").write_text(
            sql,
            encoding="utf-8",
        )

    # F9 (2026-05-21) — Estimer le grain attendu à partir des factsheets.
    # Non bloquant : si pas de factsheets ou cardinalité manquante → None.
    # Le caller peut comparer cette estimation à un COUNT(*) post-exec via
    # ``validate_grain_post_exec`` pour détecter cartesien / over-filtering.
    expected_grain = compute_expected_grain(ir, factsheets)

    # Todo #19 — Tracer les agrégations choisies par l'IR pour le récap user.
    # La promesse Komptia : l'utilisatrice doit pouvoir dire « non, par 'CA'
    # je voulais dire la MOYENNE pas la SOMME ». Sans ce tracing, le LLM Iris
    # ne sait pas quelle fonction d'agrégation a été appliquée à chaque concept
    # mesure → le récap reste muet sur ce choix critique. Voir aussi
    # ``_extract_aggregations_from_ir`` (générique, 0 hardcode BDD).
    resolution_signals["aggregations"] = _extract_aggregations_from_ir(ir)

    return {
        "sql": sql,
        "ir": ir,
        "raw_response": raw_response,
        "tool_schema": tool_schema,
        "system_prompt": PHASE4_COMPOSE_IR_SYSTEM_PROMPT,
        "user_prompt": user_prompt,
        # Signaux de résolution mismatches — exposés pour audit + futur pont
        # agent (T3a) qui pourra surfacer les concepts degraded à l'utilisateur.
        # Contient aussi ``aggregations`` (todo #19) pour le récap user.
        "resolution_signals": resolution_signals,
        # F9 — grain attendu (estimation Phase 3 × group_by IR). None si pas
        # estimable (factsheets manquantes ou cardinalité manquante).
        "expected_grain": expected_grain,
    }


def _extract_aggregations_from_ir(ir: Any) -> list[dict[str, str]]:
    """Extrait la liste des agrégations utilisées par l'IR (single ou multi-CTE).

    Pour chaque item ``select`` qui utilise une fonction d'agrégation
    (``sum``, ``avg``, ``count``, ``min``, ``max``, ``string_agg`` — pas
    ``"none"``), retourne ``{"concept": str, "function": str}``. Sert au
    récap user final (todo #19) — l'agent Iris voit cette liste et peut
    expliquer dans la réponse que telle mesure a été agrégée avec telle
    fonction. L'utilisatrice peut alors corriger ("non, je voulais la
    moyenne, pas la somme").

    Générique : aucun nom de table/colonne ni concept métier hardcodé.
    Lit uniquement la structure IR déjà validée par ``_ir_validate*``.

    Modes supportés :
        - IR single  : ``ir["select"]``
        - IR multi-CTE : ``ir["ctes"][i]["select"]`` + ``ir["compose"]["select"]``
        - IR full_outer : structure cas particulier, géré via ``ctes``
    """
    if not isinstance(ir, dict):
        return []
    aggs: list[dict[str, str]] = []

    def _walk_select(select_items: Any) -> None:
        if not isinstance(select_items, list):
            return
        for item in select_items:
            if not isinstance(item, dict):
                continue
            agg = item.get("agg")
            concept = item.get("concept")
            if not isinstance(agg, str) or not isinstance(concept, str):
                continue
            if agg == "none" or not agg:
                continue
            aggs.append({"concept": concept, "function": agg})

    # Mode single : top-level "select"
    if "select" in ir:
        _walk_select(ir.get("select"))

    # Mode multi-CTE : chaque CTE a son propre "select" + compose.select.
    if isinstance(ir.get("ctes"), list):
        for cte in ir["ctes"]:
            if isinstance(cte, dict):
                _walk_select(cte.get("select"))
        compose = ir.get("compose")
        if isinstance(compose, dict):
            _walk_select(compose.get("select"))

    return aggs


# ─────────────────────────────────────────────────────────────────────
# F9 (2026-05-21) — Validation post-exec du SQL généré
# ─────────────────────────────────────────────────────────────────────


# Seuils de validation grain. Empiriques — ajustables si retours faux positifs.
# Le ratio actual/expected hors de [_F9_RATIO_LOW, _F9_RATIO_HIGH] = warning.
# Adversarial fix : ratio_low=0 désactive le faux-positif "underflow" qui
# fire systématiquement dès qu'un WHERE filtre les lignes (cas attendu, pas
# une anomalie). Le cas réellement signalable = actual==0 (status="empty").
_F9_RATIO_LOW: float = 0.0  # Disabled — over-filtering trop courant pour signaler.
# Adversarial fix : ratio_high resserré 10→3. Une explosion ×3 du grain
# attendu indique souvent un FK manquant (fan-out cartésien partiel) qui
# passait sous le radar avant.
_F9_RATIO_HIGH: float = 3.0  # Explosion cartésienne ou FK manquant.
_F9_DEFAULT_TIMEOUT_MS: int = 10_000  # 10s — un COUNT(*) raisonnable doit tenir.


def compute_expected_grain(ir: dict | None, factsheets: dict | None) -> int | None:
    """F9 — Estime la cardinalité ATTENDUE du résultat final.

    Stratégie générique (0 hardcode BDD) :
        - Pour chaque concept dans ``ir.group_by_concepts``, lis sa cardinalité
          (champ ``cardinality`` ou ``distinct_count``) depuis ``factsheets``.
        - Multiplie ces cardinalités → cardinalité MAX du résultat (borne haute).
        - Pour multi-CTE (``ir.ctes``), prend l'union des group_by_concepts
          sur l'ensemble des CTEs (approximation conservative — le compose
          réduit, mais on veut une borne haute).
        - Pas de GROUP BY → résultat = 1 ligne (agrégat global) ou si pas
          d'agrégat = on retourne None (impossible à estimer).

    Returns:
        int  : estimation (borne haute) en lignes.
        None : si pas estimable (factsheets manquantes, concept inconnu,
               cardinalité non renseignée, ou requête sans GROUP BY+agrégat).

    Le caller traite ``None`` comme "validation skip" — pas comme une erreur.
    """
    if not isinstance(ir, dict) or not isinstance(factsheets, dict):
        return None

    def _card_for_concept(concept_name: str) -> int | None:
        fs = factsheets.get(concept_name)
        if not isinstance(fs, dict):
            return None
        card = fs.get("cardinality") or fs.get("distinct_count")
        # Adversarial fix : isinstance(True, int) == True. Exclure explicitement
        # les bool — sinon un factsheet corrompu `{"cardinality": True}`
        # passerait comme cardinalité=1 silencieusement.
        if isinstance(card, bool):
            return None
        if isinstance(card, int) and card > 0:
            return card
        return None

    # Mode multi-CTE : agréger les group_by de chaque CTE (union).
    if "ctes" in ir and isinstance(ir["ctes"], list):
        union_concepts: set[str] = set()
        for cte in ir["ctes"]:
            if isinstance(cte, dict):
                for cn in cte.get("group_by_concepts") or []:
                    if isinstance(cn, str):
                        union_concepts.add(cn)
        group_by_concepts: list[str] = sorted(union_concepts)
    else:
        group_by_concepts = [
            cn for cn in ir.get("group_by_concepts") or [] if isinstance(cn, str)
        ]

    if not group_by_concepts:
        # Pas de GROUP BY → soit 1 ligne (agrégat global) soit N lignes (SELECT
        # nu). Sans plus d'info, on retourne None (le caller skip la check).
        return None

    product = 1
    for cn in group_by_concepts:
        card = _card_for_concept(cn)
        if card is None:
            # Une cardinalité manquante invalide l'estimation entière.
            # Mieux vaut "None" (skip check) qu'un nombre faux qui produit
            # un faux warning de grain mismatch.
            return None
        product *= card
        # Anti-overflow : si le produit dépasse ~10⁹, on plafonne (la borne
        # haute n'est pas informative au-delà — la table source elle-même
        # n'a sûrement pas plus de 10⁹ lignes).
        if product > 1_000_000_000:
            return 1_000_000_000

    return product


def _strip_order_and_limit_for_count(sql: str) -> str:
    """F9 — Strip ORDER BY et TOP/LIMIT du SQL pour le wrapper COUNT(*).

    SQL Server interdit ORDER BY dans une sous-requête (sauf si TOP est aussi
    présent). Donc pour faire ``SELECT COUNT(*) FROM (<sql>) AS x``, il faut
    retirer ORDER BY et idéalement TOP (sinon le count = min(top, total) au
    lieu du grain réel).

    Utilise sqlglot pour parsing T-SQL safe. Si parse échoue (rare), fallback
    sur le SQL original (le COUNT pourrait échouer mais c'est un cas dégradé).
    """
    try:
        import sqlglot

        parsed = sqlglot.parse_one(sql, dialect="tsql")
        if parsed is None:
            return sql
        # Strip ORDER BY (top-level — les ORDER BY dans les CTEs restent).
        parsed.set("order", None)
        # Strip TOP / LIMIT.
        parsed.set("limit", None)
        # T-SQL : TOP est dans expressions[0] avec un attribut spécial. sqlglot
        # le gère via le ``hint`` ou ``limit`` selon la version. On tente les 2.
        if "hint" in parsed.args:
            parsed.set("hint", None)
        return parsed.sql(dialect="tsql")
    except Exception:
        # Fallback gracieux : retourne le SQL original.
        return sql


async def validate_grain_post_exec(
    sql: str,
    expected_grain: int | None,
    connector,
    *,
    timeout_ms: int = _F9_DEFAULT_TIMEOUT_MS,
) -> dict:
    """F9 — Exécute COUNT(*) sur le SQL généré et compare au grain attendu.

    Args:
        sql : T-SQL généré par Phase 4.
        expected_grain : estimation du grain (output de ``compute_expected_grain``).
        connector : sage_connector avec méthode ``async execute(sql, ...)``.
        timeout_ms : timeout par défaut 10s — un COUNT(*) raisonnable doit
                     tenir, sinon c'est probablement déjà un signal.

    Returns:
        dict avec clés :
            - actual_grain : int | None — résultat du COUNT(*)
            - expected_grain : int | None — input (relayé)
            - ratio : float | None — actual / expected
            - status : "ok" | "explosion" | "underflow" | "empty" |
                       "no_estimate" | "timeout" | "error"
            - message : str — diagnostic humain
            - elapsed_ms : float | None — durée d'exécution

    Le caller décide quoi faire du résultat (log, surface UI, re-diagnose,
    etc.). Cette fonction NE LOOP PAS automatiquement — coût Sage trop élevé
    pour faire ça implicitement.

    Generic : pas de nom de table/colonne hardcodé. Le SQL d'origine est
    juste wrappé.
    """
    import time

    result: dict = {
        "actual_grain": None,
        "expected_grain": expected_grain,
        "ratio": None,
        "status": "no_estimate",
        "message": "",
        "elapsed_ms": None,
    }

    if not isinstance(sql, str) or not sql.strip():
        result["status"] = "error"
        result["message"] = "SQL vide ou non-string"
        return result

    # Wrap SQL en COUNT(*). Strip ORDER BY/TOP pour subquery valid T-SQL.
    inner_sql = _strip_order_and_limit_for_count(sql).rstrip(";").strip()
    count_sql = f"SELECT COUNT(*) AS grain_count FROM ({inner_sql}) AS _grain_subq"

    start = time.perf_counter()
    try:
        # Exécution avec VRAI timeout via asyncio.wait_for (adversarial fix —
        # avant, on observait elapsed_ms après coup mais on attendait
        # indéfiniment si le connector hangait). La signature exacte de
        # ``connector.execute`` varie — on tente d'abord la signature riche,
        # fallback minimal.
        async def _run() -> object:
            try:
                return await connector.execute(count_sql, max_rows=1)
            except TypeError:
                return await connector.execute(count_sql)

        exec_result = await asyncio.wait_for(_run(), timeout=timeout_ms / 1000.0)
        elapsed = (time.perf_counter() - start) * 1000.0
        result["elapsed_ms"] = round(elapsed, 1)
        # Connector retourne soit un QueryResult avec .rows soit un dict.
        rows = getattr(exec_result, "rows", None) or (
            exec_result.get("rows") if isinstance(exec_result, dict) else None
        )
        if not rows or len(rows) == 0:
            result["status"] = "error"
            result["message"] = "COUNT(*) n'a retourné aucune ligne (anormal)"
            return result
        first = rows[0]
        # Récup du COUNT : dict, tuple, ou ligne plate.
        count_val = None
        if isinstance(first, dict):
            count_val = first.get("grain_count") or next(iter(first.values()), None)
        elif isinstance(first, (list, tuple)):
            count_val = first[0] if first else None
        else:
            count_val = first
        if count_val is None:
            result["status"] = "error"
            result["message"] = "COUNT(*) NULL — anormal sur SELECT COUNT(*)"
            return result
        try:
            actual = int(count_val)
        except (TypeError, ValueError):
            result["status"] = "error"
            result["message"] = f"COUNT(*) non convertible en int: {count_val!r}"
            return result
        result["actual_grain"] = actual
    except asyncio.TimeoutError:
        elapsed = (time.perf_counter() - start) * 1000.0
        result["elapsed_ms"] = round(elapsed, 1)
        result["status"] = "timeout"
        result["message"] = (
            f"COUNT(*) timeout strict après {timeout_ms}ms (asyncio.wait_for)."
        )
        return result
    except Exception as exc:  # noqa: BLE001 — best-effort validation
        elapsed = (time.perf_counter() - start) * 1000.0
        result["elapsed_ms"] = round(elapsed, 1)
        msg = str(exc)
        # Heuristique timeout — les drivers SQL Server raisent parfois avec
        # ``timeout`` dans le message (côté SQL Server) avant qu'asyncio.wait_for
        # ne déclenche (driver détecte timeout server-side).
        if "timeout" in msg.lower():
            result["status"] = "timeout"
            result["message"] = f"COUNT(*) timeout SQL Server-side: {msg[:200]}"
        else:
            result["status"] = "error"
            result["message"] = f"COUNT(*) erreur: {msg[:300]}"
        return result

    # Comparaison au grain attendu.
    actual = result["actual_grain"]
    if expected_grain is None or not isinstance(expected_grain, int) or expected_grain <= 0:
        # Pas d'estimation → on retourne juste le count actuel sans verdict.
        result["status"] = "no_estimate"
        result["message"] = (
            f"COUNT(*) = {actual:,} lignes ; pas d'estimation expected_grain "
            f"(factsheets incomplètes ou requête sans GROUP BY)."
        )
        return result

    if actual == 0:
        result["status"] = "empty"
        result["ratio"] = 0.0
        result["message"] = (
            f"COUNT(*) = 0 lignes (attendu ~{expected_grain:,}). "
            f"Filtres possiblement trop restrictifs OU valeur référencée "
            f"absente de la table source."
        )
        return result

    ratio = actual / expected_grain
    result["ratio"] = round(ratio, 4)
    if ratio > _F9_RATIO_HIGH:
        result["status"] = "explosion"
        result["message"] = (
            f"COUNT(*) = {actual:,} lignes ≫ attendu ~{expected_grain:,} "
            f"(ratio ×{ratio:.1f}). Cartesien probable — vérifier les JOINs."
        )
    elif ratio < _F9_RATIO_LOW:
        result["status"] = "underflow"
        result["message"] = (
            f"COUNT(*) = {actual:,} lignes ≪ attendu ~{expected_grain:,} "
            f"(ratio {ratio:.4f}). Sur-filtrage probable."
        )
    else:
        result["status"] = "ok"
        result["message"] = (
            f"COUNT(*) = {actual:,} lignes ≈ attendu ~{expected_grain:,} "
            f"(ratio {ratio:.2f}). Grain cohérent."
        )
    return result


def _ir_find_full_outer_derivation(ir: dict) -> tuple[int, dict] | None:
    """Cherche la première derivation `semantic="full_outer"` dans le SELECT.

    Phase d.1 MVP : on ne supporte qu'une seule derivation full_outer par
    IR. Si plusieurs sont présentes, le composer ne peut pas les chainer
    correctement (dimensions de jointure ambiguës) — on lève une erreur.

    Returns:
        (index_in_select, full_select_item) ou None si aucune.
    """
    selects = ir.get("select", []) or []
    found: list[tuple[int, dict]] = []
    for i, item in enumerate(selects):
        if not isinstance(item, dict):
            continue
        deriv = item.get("derivation")
        if isinstance(deriv, dict) and deriv.get("semantic") == "full_outer":
            found.append((i, item))
    if len(found) > 1:
        raise IRValidationError(
            f"Phase d.1 MVP : plusieurs derivations 'full_outer' dans le "
            f"même IR (alias: {[item.get('alias') for _, item in found]}). "
            f"Non supporté — séparer en plusieurs requêtes ou attendre "
            f"Phase e (multi-CTE chained)."
        )
    return found[0] if found else None


def _ir_compose_full_outer_sql(
    ir: dict,
    deriv_index: int,
    deriv_item: dict,
    concept_resolution: dict,
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """Génère un T-SQL avec 2 CTE + FULL OUTER JOIN pour une derivation
    ``semantic="full_outer"``.

    **Pourquoi** : sans CTE+FULL_OUTER, ``a - b`` avec filters disjoints sur
    dates produit du faux silencieux (entités présentes une seule période
    voient ``CASE WHEN year=N THEN amt ELSE 0 END`` retourner 0 au lieu
    de NULL). Les CTE séparées + FULL OUTER JOIN + COALESCE garantissent
    le résultat correct sémantiquement.

    **Limitations MVP** (rejets explicites avec IRValidationError) :
        - 1 seule derivation full_outer par IR
        - left/right operands inline (pas ``select_ref``)
        - Mêmes ``concept`` et ``agg`` côté gauche/droite (même mesure
          comparée sur 2 périmètres)
        - Autres select items dans l'IR doivent référencer une dimension du
          ``group_by_concepts`` (pas de mesure supplémentaire)
        - ``group_by_concepts`` non vide (les dimensions de jointure)

    SQL généré (squelette) :

    .. code-block:: sql

        WITH [cte_left] AS (
            SELECT <dims>, AGG(measure) AS [measure_value]
            FROM <from> [JOINs] WHERE <filters_global + left_filters>
            GROUP BY <dims>
        ),
        [cte_right] AS (idem côté droit)
        SELECT COALESCE(L.dim, R.dim) AS dim_out,
               (COALESCE(L.measure_value, 0) OP COALESCE(R.measure_value, 0))
                   AS <deriv_alias>
        FROM [cte_left] L FULL OUTER JOIN [cte_right] R ON L.dim = R.dim
        ORDER BY ...
    """
    deriv = deriv_item["derivation"]
    deriv_op = deriv.get("op")
    if deriv_op not in _IR_VALID_DERIV_OPS:
        raise IRValidationError(
            f"full_outer derivation.op '{deriv_op}' invalide. " f"Valides: {_IR_VALID_DERIV_OPS}"
        )
    left = deriv.get("left", {})
    right = deriv.get("right", {})
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise IRValidationError("full_outer left/right doivent être des dicts")
    if "select_ref" in left or "select_ref" in right:
        raise IRValidationError(
            "full_outer Phase d.1 MVP : operands doivent être inline (pas "
            "select_ref). Utiliser concept+agg+filters directement dans "
            "left/right."
        )
    # BLOCKING fix adversarial #1 : refuser derivation imbriquée dans
    # operands. Sinon le composer perd silencieusement la sous-derivation
    # (le `_build_cte_ir` ne récupère que concept/agg/filters et ignore
    # le reste) → faux résultat silencieux.
    if "derivation" in left or "derivation" in right:
        raise IRValidationError(
            "full_outer : operands ne peuvent PAS contenir une derivation "
            "imbriquée. Utiliser des operands simples (concept+agg+filters)."
        )
    if "case_when" in left or "case_when" in right:
        raise IRValidationError(
            "full_outer : operands ne peuvent PAS contenir un case_when. "
            "Utiliser des operands simples (concept+agg+filters)."
        )
    l_concept = left.get("concept")
    r_concept = right.get("concept")
    if not l_concept or not r_concept or l_concept != r_concept:
        raise IRValidationError(
            f"full_outer left.concept ('{l_concept}') et right.concept "
            f"('{r_concept}') doivent être identiques (même mesure)"
        )
    l_agg = left.get("agg", "none")
    r_agg = right.get("agg", "none")
    if l_agg != r_agg:
        raise IRValidationError(
            f"full_outer left.agg ('{l_agg}') et right.agg ('{r_agg}') " f"doivent être identiques"
        )
    if l_agg == "none":
        raise IRValidationError("full_outer requires une agg (sum/count/avg/min/max), pas 'none'.")

    dims = ir.get("group_by_concepts", []) or []
    if not isinstance(dims, list) or not dims:
        raise IRValidationError(
            "full_outer requires `group_by_concepts` non-vide (= dimensions "
            "de jointure entre les 2 CTE)."
        )
    # CRITICAL fix adversarial : measure_concept ne peut pas être aussi dans
    # dims (sinon GROUP BY mesure = absurde sémantiquement, résultat faux).
    if l_concept in dims:
        raise IRValidationError(
            f"full_outer : measure_concept '{l_concept}' ne peut pas être "
            f"aussi dans group_by_concepts {dims}."
        )

    # BLOCKING fix adversarial #2 : valider que from_concept et tous les
    # concepts référencés ont une résolution AVANT la récursion. Sinon
    # le récursif `ir_to_sql` plante avec un message peu actionnable.
    measure_concept = l_concept
    from_concept = ir.get("from_concept")
    for cn in [from_concept, measure_concept] + list(dims):
        if not cn:
            raise IRValidationError(
                f"full_outer : concept manquant (from_concept={from_concept}, "
                f"measure={measure_concept}, dims={dims})"
            )
        cr = concept_resolution.get(cn)
        if not cr or not cr.get("best") or cr.get("error"):
            raise IRValidationError(
                f"full_outer : concept '{cn}' non résolu par Phase 2.5 "
                f"(best={cr.get('best') if cr else None}, "
                f"error={cr.get('error') if cr else 'absent'})."
            )

    # CRITICAL fix adversarial : refuser conflits filters_global vs left/right.
    # Sinon CTE retourne 0 ligne et le composer reproduit le faux silencieux
    # qu'il prétend corriger.
    fg_eq: dict[str, set] = {}
    for f in ir.get("filters_global") or []:
        if isinstance(f, dict) and f.get("op") == "=":
            cn = f.get("concept")
            v = f.get("val")
            if cn:
                fg_eq.setdefault(cn, set()).add(v)
    for side_label, side in (("left", left), ("right", right)):
        for f in side.get("filters") or []:
            if isinstance(f, dict) and f.get("op") == "=":
                cn = f.get("concept")
                v = f.get("val")
                if cn and cn in fg_eq and v not in fg_eq[cn]:
                    raise IRValidationError(
                        f"full_outer : conflit entre filters_global "
                        f"({cn}={sorted(fg_eq[cn], key=str)}) et "
                        f"{side_label}.filters ({cn}={v}). "
                        f"CTE {side_label} retournerait 0 ligne → faux "
                        f"silencieux. Corriger les filtres."
                    )

    deriv_alias = deriv_item.get("alias")
    if not isinstance(deriv_alias, str) or not deriv_alias:
        raise IRValidationError(f"full_outer derivation sans alias: {deriv_item!r}")

    agg = l_agg
    filters_global = ir.get("filters_global", []) or []
    l_filters = left.get("filters", []) or []
    r_filters = right.get("filters", []) or []

    # Construire IR pour CTE LEFT — group by dims + agg(measure) avec filtres
    # globaux + filtres spécifiques côté gauche.
    # Phase e.2 : propager `joins` du IR parent vers les CTE pour que le
    # composer respecte le chemin FK explicite spécifié par le user/LLM.
    parent_joins = ir.get("joins") or []

    def _build_cte_ir(side_filters: list[dict]) -> dict:
        cte_ir = {
            "select": [
                # Dimensions exposées comme aliases dim_0, dim_1, ...
                *[{"alias": f"dim_{i}", "concept": d, "agg": "none"} for i, d in enumerate(dims)],
                # Mesure agrégée, alias fixe "measure_value".
                {"alias": "measure_value", "concept": measure_concept, "agg": agg},
            ],
            "from_concept": ir.get("from_concept"),
            "filters_global": filters_global + side_filters,
            "group_by_concepts": list(dims),
        }
        if parent_joins:
            # Deep copy pour ne pas muter le IR parent (l'utilisateur peut
            # vouloir réutiliser le même IR plusieurs fois).
            cte_ir["joins"] = [dict(j) for j in parent_joins]
        return cte_ir

    left_cte_ir = _build_cte_ir(l_filters)
    right_cte_ir = _build_cte_ir(r_filters)

    # Récursion via ir_to_sql — évite la duplication de logique de composition.
    # Strip le ";" final de chaque CTE car on l'embarque dans une plus grande
    # query.
    left_sql = ir_to_sql(left_cte_ir, concept_resolution, fk_lookup=fk_lookup).rstrip(";").strip()
    right_sql = ir_to_sql(right_cte_ir, concept_resolution, fk_lookup=fk_lookup).rstrip(";").strip()

    # Expression de la dérivation côté SELECT externe.
    sql_op = {"subtract": "-", "add": "+", "multiply": "*", "divide": "/"}[deriv_op]
    if deriv_op == "divide":
        deriv_expr = (
            "COALESCE([L].[measure_value], 0) / " "NULLIF(COALESCE([R].[measure_value], 0), 0)"
        )
    else:
        deriv_expr = (
            f"(COALESCE([L].[measure_value], 0) {sql_op} " f"COALESCE([R].[measure_value], 0))"
        )

    # Condition JOIN : sur toutes les dimensions, NULL-safe via IS [NOT] DISTINCT
    # FROM... mais T-SQL n'a pas cette construction. Fallback compatible :
    # `(L.dim = R.dim OR (L.dim IS NULL AND R.dim IS NULL))`.
    join_conds: list[str] = []
    for i in range(len(dims)):
        l_id = f"[L].[dim_{i}]"
        r_id = f"[R].[dim_{i}]"
        join_conds.append(f"({l_id} = {r_id} OR ({l_id} IS NULL AND {r_id} IS NULL))")
    join_clause = " AND ".join(join_conds)

    # SELECT externe : autres items (= dimensions) + derivation.
    # BLOCKING fix adversarial #3 : on construit `valid_aliases` directement
    # depuis l'IR (single source of truth), pas en re-parsant les SQL clauses
    # générées (l'ancien `split(' AS ')` cassait silencieusement sur les
    # aliases contenant la sous-chaîne ` AS `).
    other_clauses: list[str] = []
    other_aliases: list[str] = []  # liste ordered pour valid_aliases
    for i, item in enumerate(ir.get("select", []) or []):
        if i == deriv_index:
            continue
        item_concept = item.get("concept")
        item_alias = item.get("alias")
        if not isinstance(item_alias, str) or not item_alias:
            raise IRValidationError(f"full_outer : select[{i}] sans alias: {item!r}")
        if item_concept not in dims:
            raise IRValidationError(
                f"full_outer Phase d.1 MVP : select[{i}] concept "
                f"'{item_concept}' (alias '{item_alias}') n'est pas dans "
                f"group_by_concepts. Seules les dimensions du group_by "
                f"peuvent être projetées en plus de la derivation."
            )
        # Mesures avec agg ≠ none non supportées en MVP (cf. limitations).
        if item.get("agg", "none") != "none":
            raise IRValidationError(
                f"full_outer Phase d.1 MVP : select[{i}] avec agg "
                f"'{item.get('agg')}' non supporté. Seul l'item full_outer "
                f"peut être agrégé."
            )
        dim_idx = list(dims).index(item_concept)
        other_clauses.append(
            f"COALESCE([L].[dim_{dim_idx}], [R].[dim_{dim_idx}]) "
            f"AS {_ir_quote_sql_identifier(item_alias)}"
        )
        other_aliases.append(item_alias)
    deriv_clause = f"{deriv_expr} AS {_ir_quote_sql_identifier(deriv_alias)}"

    # ORDER BY (limité aux aliases du SELECT externe).
    valid_aliases = set(other_aliases) | {deriv_alias}
    order_by_clauses: list[str] = []
    for o in ir.get("order_by") or []:
        if not isinstance(o, dict):
            continue
        ref_alias = o.get("alias")
        direction = o.get("direction", "ASC")
        if ref_alias and ref_alias in valid_aliases:
            if ref_alias == deriv_alias:
                order_by_clauses.append(f"{deriv_expr} {direction}")
            else:
                order_by_clauses.append(f"{_ir_quote_sql_identifier(ref_alias)} {direction}")
        else:
            raise IRValidationError(
                f"full_outer Phase d.1 MVP : order_by '{ref_alias}' doit "
                f"référencer un alias du SELECT externe ({sorted(valid_aliases)})"
            )

    # CRITICAL fix adversarial : tracker l'index de la ligne SELECT
    # explicitement, pas par index magique `parts[5]` (fragile aux ajouts
    # futurs entre les CTE et le SELECT externe).
    parts: list[str] = []
    parts.append("WITH [cte_left] AS (")
    parts.append(left_sql)
    parts.append("),")
    parts.append("[cte_right] AS (")
    parts.append(right_sql)
    parts.append(")")
    select_top_clause = ""
    if isinstance(ir.get("limit"), int) and ir["limit"] > 0:
        select_top_clause = f"TOP {int(ir['limit'])} "
    parts.append(f"SELECT {select_top_clause}" + ", ".join(other_clauses + [deriv_clause]))
    parts.append("FROM [cte_left] AS [L]")
    parts.append(f"FULL OUTER JOIN [cte_right] AS [R] ON {join_clause}")
    if order_by_clauses:
        parts.append("ORDER BY " + ", ".join(order_by_clauses))

    return "\n".join(parts) + ";"


_IR_MULTI_CTE_MAX: int = 16  # Limit anti-DoS / pathologic IR pour multi-CTE chained.
_IR_DERIVATION_MAX_DEPTH: int = 8  # Phase Z.6 — récursion max derivation


def _ir_validate_compose_derivation(
    deriv: dict,
    cte_names: list[str],
    cte_aliases_by_name: dict[str, set],
    _depth: int,
    _path: str,
) -> None:
    """Phase Z.6 — valide récursivement une derivation dans compose.select.

    Format ::
        {"op": "subtract|add|multiply|divide",
         "left":  <operand>,  # operand = {cte_ref, alias_in_cte} | {derivation}
         "right": <operand>}

    Limite de profondeur stricte (anti-DoS / pathologic IR).
    """
    if _depth > _IR_DERIVATION_MAX_DEPTH:
        raise IRValidationError(
            f"{_path} dépasse profondeur {_IR_DERIVATION_MAX_DEPTH} "
            f"(pathologic IR). Aplatir la derivation."
        )
    if not isinstance(deriv, dict):
        raise IRValidationError(f"{_path} doit être un dict")
    op = deriv.get("op")
    if op not in _IR_VALID_DERIV_OPS:
        raise IRValidationError(f"{_path}.op '{op}' invalide. Valides: {_IR_VALID_DERIV_OPS}")
    for side in ("left", "right"):
        operand = deriv.get(side)
        if not isinstance(operand, dict):
            raise IRValidationError(
                f"{_path}.{side} doit être un dict, got " f"{type(operand).__name__}"
            )
        if "derivation" in operand:
            _ir_validate_compose_derivation(
                operand["derivation"],
                cte_names,
                cte_aliases_by_name,
                _depth=_depth + 1,
                _path=f"{_path}.{side}.derivation",
            )
        elif "cte_ref" in operand:
            ref = operand["cte_ref"]
            if ref not in cte_names:
                raise IRValidationError(
                    f"{_path}.{side}.cte_ref '{ref}' inconnu. " f"CTEs définis: {cte_names}"
                )
            ain_cte = operand.get("alias_in_cte")
            if not isinstance(ain_cte, str) or not ain_cte:
                raise IRValidationError(f"{_path}.{side} cte_ref='{ref}' sans `alias_in_cte`")
            if ain_cte not in cte_aliases_by_name[ref]:
                raise IRValidationError(
                    f"{_path}.{side}.alias_in_cte '{ain_cte}' absent du "
                    f"CTE '{ref}' (aliases: "
                    f"{sorted(a for a in cte_aliases_by_name[ref] if a)})"
                )
        else:
            raise IRValidationError(
                f"{_path}.{side} doit contenir `cte_ref+alias_in_cte` ou "
                f"`derivation` (récursion). Got keys: {list(operand)}"
            )


def _ir_render_compose_derivation(deriv: dict) -> str:
    """Phase Z.6 — rend une derivation inter-CTE en SQL.

    Récursif. Pour ``divide`` → wrap right dans ``NULLIF(..., 0)``
    automatiquement (anti-divbyzero silencieux, retourne NULL au lieu de
    lever).
    """
    op = deriv["op"]
    sql_op = {"subtract": "-", "add": "+", "multiply": "*", "divide": "/"}[op]

    def _render_operand(operand: dict) -> str:
        if "derivation" in operand:
            return f"({_ir_render_compose_derivation(operand['derivation'])})"
        ref_q = _ir_quote_sql_identifier(operand["cte_ref"])
        ain_q = _ir_quote_sql_identifier(operand["alias_in_cte"])
        return f"{ref_q}.{ain_q}"

    left_sql = _render_operand(deriv["left"])
    right_sql = _render_operand(deriv["right"])
    if op == "divide":
        # NULLIF(denom, 0) → si denom=0, le SELECT retourne NULL au lieu de
        # crasher. Choix volontaire : NULL = "indéterminé" plutôt que faux
        # silencieux à 0.
        return f"{left_sql} / NULLIF({right_sql}, 0)"
    return f"{left_sql} {sql_op} {right_sql}"


def _ir_validate_multi_cte(ir: dict) -> None:
    """Valide la structure d'un IR multi-CTE chained (Phase Z.2).

    Format attendu (mutuellement exclusif avec single-IR — pas de `select`/
    `from_concept`/`filters_global` au niveau top) :

        {
            "ctes": [
                {"name": "<sql_safe>", "select": [...], "from_concept": "...",
                 "joins": [...], "filters_global": [...], "group_by_concepts": [...]},
                ...
            ],
            "compose": {
                "type": "full_outer_chain",
                "join_key_alias": "<str>",   # alias commun à TOUS les CTEs
                "select": [
                    {"alias": "<str>", "coalesce_join_key": True} |
                    {"alias": "<str>", "cte_ref": "<name>", "alias_in_cte": "<str>"},
                    ...
                ],
                "order_by": [{"alias": "<str>", "direction": "ASC|DESC"}]  # opt
            }
        }

    Validations (anti-faux-silencieux + anti-DoS) :
        - ctes non-vide, ≤ _IR_MULTI_CTE_MAX
        - chaque CTE a un `name` SQL-safe et unique
        - chaque CTE est un mini-IR valide (récursion sur _ir_validate)
        - nesting `ctes` dans un CTE interdit
        - join_key_alias présent dans CHAQUE CTE (sinon FULL OUTER ambigu)
        - compose.select : exactement UN de coalesce_join_key/cte_ref par item
        - cte_ref pointe sur un CTE existant ; alias_in_cte existe dans ce CTE
        - pas de `select`/`from_concept` au niveau top (mutuellement exclusif)
    """
    if not isinstance(ir, dict):
        raise IRValidationError(f"IR doit être un dict, got {type(ir).__name__}")
    # `limit` autorisé au top-level (TOP N sur le SELECT final).
    # `order_by` interdit ici — utiliser `compose.order_by`.
    # F4 adversarial fix : `having_filters` top-level dans multi-CTE est
    # silencieusement ignoré sinon. Le bon usage = inclure having_filters
    # à l'intérieur de chaque `ctes[i]` (filtre par CTE), pas au global.
    forbidden_top = [
        k
        for k in (
            "select",
            "from_concept",
            "filters_global",
            "group_by_concepts",
            "order_by",
            "having_filters",
        )
        if k in ir
    ]
    if forbidden_top:
        raise IRValidationError(
            f"multi-CTE IR : champs top-level interdits {forbidden_top}. "
            f"Utiliser `compose.select`/`compose.order_by` à la place. "
            f"Pour `having_filters` : à placer dans chaque `ctes[i].having_filters`."
        )
    ctes = ir.get("ctes")
    if not isinstance(ctes, list) or not ctes:
        raise IRValidationError("multi-CTE IR : `ctes` doit être une list non-vide")
    if len(ctes) > _IR_MULTI_CTE_MAX:
        raise IRValidationError(
            f"multi-CTE IR : trop de CTEs ({len(ctes)} > {_IR_MULTI_CTE_MAX} "
            f"limit anti-DoS / pathologic IR)"
        )
    cte_names: list[str] = []  # ordered pour messages d'erreur déterministes
    cte_aliases_by_name: dict[str, set[str]] = {}
    for i, cte in enumerate(ctes):
        if not isinstance(cte, dict):
            raise IRValidationError(f"ctes[{i}] doit être un dict")
        name = cte.get("name")
        if not isinstance(name, str) or not name:
            raise IRValidationError(f"ctes[{i}] sans `name`")
        try:
            _ir_quote_sql_identifier(name)
        except IRValidationError as exc:
            raise IRValidationError(f"ctes[{i}].name '{name}' invalide: {exc}") from exc
        if name in cte_names:
            raise IRValidationError(f"ctes[{i}].name '{name}' dupliqué")
        cte_names.append(name)
        # Anti-récursion : interdire `ctes` imbriqué.
        if "ctes" in cte:
            raise IRValidationError(
                f"ctes[{i}] (name='{name}') : nesting `ctes` interdit " f"(anti-récursion)."
            )
        # Valider le mini-IR via _ir_validate standard (lève si malformé).
        # Strip le `name` avant validation (champ propre au mode multi-CTE).
        mini_ir = {k: v for k, v in cte.items() if k != "name"}
        try:
            _ir_validate(mini_ir)
        except IRValidationError as exc:
            raise IRValidationError(f"ctes[{i}] (name='{name}') invalide: {exc}") from exc
        cte_aliases_by_name[name] = {
            it.get("alias") for it in cte.get("select", []) if isinstance(it, dict)
        }

    compose = ir.get("compose")
    if not isinstance(compose, dict):
        raise IRValidationError("multi-CTE IR : `compose` doit être un dict")
    compose_type = compose.get("type")
    if compose_type != "full_outer_chain":
        raise IRValidationError(
            f"multi-CTE IR : compose.type doit être 'full_outer_chain', " f"got '{compose_type}'"
        )
    join_key = compose.get("join_key_alias")
    if not isinstance(join_key, str) or not join_key:
        raise IRValidationError("multi-CTE IR : `compose.join_key_alias` requis (str non-vide)")
    try:
        _ir_quote_sql_identifier(join_key)
    except IRValidationError as exc:
        raise IRValidationError(
            f"multi-CTE IR : join_key_alias '{join_key}' invalide: {exc}"
        ) from exc
    # Le join_key_alias DOIT exister dans chaque CTE — sinon FULL OUTER JOIN
    # impossible et faux silencieux ou échec syntaxe.
    for name in cte_names:
        if join_key not in cte_aliases_by_name[name]:
            raise IRValidationError(
                f"multi-CTE IR : join_key_alias '{join_key}' absent du CTE "
                f"'{name}' (aliases: {sorted(a for a in cte_aliases_by_name[name] if a)})"
            )

    select_items = compose.get("select")
    if not isinstance(select_items, list) or not select_items:
        raise IRValidationError("multi-CTE IR : `compose.select` doit être une list non-vide")
    output_aliases: set[str] = set()
    for i, item in enumerate(select_items):
        if not isinstance(item, dict):
            raise IRValidationError(f"compose.select[{i}] doit être un dict")
        alias = item.get("alias")
        if not isinstance(alias, str) or not alias:
            raise IRValidationError(f"compose.select[{i}] sans alias")
        try:
            _ir_quote_sql_identifier(alias)
        except IRValidationError as exc:
            raise IRValidationError(f"compose.select[{i}] alias '{alias}' invalide: {exc}") from exc
        if alias in output_aliases:
            raise IRValidationError(f"compose.select[{i}] alias '{alias}' dupliqué")
        output_aliases.add(alias)
        modes = [k for k in ("coalesce_join_key", "cte_ref", "derivation") if k in item]
        if len(modes) != 1:
            raise IRValidationError(
                f"compose.select[{i}] : exactement UN de "
                f"`coalesce_join_key`/`cte_ref`/`derivation` requis. "
                f"Got: {modes}."
            )
        if "cte_ref" in item:
            ref = item["cte_ref"]
            if ref not in cte_names:
                raise IRValidationError(
                    f"compose.select[{i}].cte_ref '{ref}' inconnu. " f"CTEs définis: {cte_names}"
                )
            ain_cte = item.get("alias_in_cte")
            if not isinstance(ain_cte, str) or not ain_cte:
                raise IRValidationError(f"compose.select[{i}] cte_ref='{ref}' sans `alias_in_cte`")
            if ain_cte not in cte_aliases_by_name[ref]:
                raise IRValidationError(
                    f"compose.select[{i}].alias_in_cte '{ain_cte}' absent du "
                    f"CTE '{ref}' (aliases: "
                    f"{sorted(a for a in cte_aliases_by_name[ref] if a)})"
                )
        elif "derivation" in item:
            # Phase Z.6 — arithmetic inter-CTE. Validate récursivement.
            _ir_validate_compose_derivation(
                item["derivation"],
                cte_names,
                cte_aliases_by_name,
                _depth=0,
                _path=f"compose.select[{i}].derivation",
            )
        else:
            # coalesce_join_key=True → pas d'autres champs requis.
            if item["coalesce_join_key"] is not True:
                raise IRValidationError(f"compose.select[{i}].coalesce_join_key doit être True")

    # order_by (optionnel) — référence aliases du compose.select uniquement.
    for j, o in enumerate(compose.get("order_by") or []):
        if not isinstance(o, dict):
            raise IRValidationError(f"compose.order_by[{j}] doit être un dict")
        ref_alias = o.get("alias")
        if ref_alias not in output_aliases:
            raise IRValidationError(
                f"compose.order_by[{j}].alias '{ref_alias}' absent du SELECT "
                f"final (output_aliases: {sorted(output_aliases)})"
            )
        direction = o.get("direction", "ASC")
        if direction not in _IR_VALID_DIRECTIONS:
            raise IRValidationError(
                f"compose.order_by[{j}].direction invalide: {direction!r}. "
                f"Valides: {_IR_VALID_DIRECTIONS}"
            )

    # limit top-level optionnel sur le SELECT final.
    limit = ir.get("limit")
    if limit is not None and (not isinstance(limit, int) or limit <= 0):
        raise IRValidationError(
            f"multi-CTE IR : limit doit être un int positif ou None, got {limit!r}"
        )


def _ir_compose_multi_cte_chain_sql(
    ir: dict,
    concept_resolution: dict,
    fk_lookup: dict[str, list[dict]] | None = None,
) -> str:
    """Génère un T-SQL multi-CTE + FULL OUTER JOIN chaîné (Phase Z.2).

    Squelette N≥2 ::

        WITH [c1] AS (<mini-IR c1>),
             [c2] AS (<mini-IR c2>),
             [c3] AS (<mini-IR c3>)
        SELECT
            COALESCE([c1].[key], [c2].[key], [c3].[key]) AS [key],
            [c1].[a] AS [out_a],
            [c2].[b] AS [out_b]
        FROM [c1]
        FULL OUTER JOIN [c2] ON [c1].[key] = [c2].[key]
        FULL OUTER JOIN [c3] ON COALESCE([c1].[key], [c2].[key]) = [c3].[key]
        ORDER BY ...;

    Si N=1 : pas de FULL OUTER, juste ``SELECT … FROM [c1]``.
    """
    _ir_validate_multi_cte(ir)
    ctes = ir["ctes"]
    compose = ir["compose"]
    join_key = compose["join_key_alias"]
    join_key_q = _ir_quote_sql_identifier(join_key)

    # Compose chaque CTE via récursion sur ir_to_sql (chaque CTE est un mini-IR
    # valide, sans le champ `name` propre au mode multi-CTE).
    cte_sqls: list[tuple[str, str]] = []
    for cte in ctes:
        name = cte["name"]
        mini_ir = {k: v for k, v in cte.items() if k != "name"}
        cte_sql = (
            ir_to_sql(
                mini_ir,
                concept_resolution,
                fk_lookup=fk_lookup,
            )
            .rstrip(";")
            .strip()
        )
        cte_sqls.append((name, cte_sql))

    # SELECT final clauses.
    select_clauses: list[str] = []
    for item in compose["select"]:
        alias = item["alias"]
        alias_q = _ir_quote_sql_identifier(alias)
        if item.get("coalesce_join_key"):
            coalesce_args = [
                f"{_ir_quote_sql_identifier(name)}.{join_key_q}" for name, _ in cte_sqls
            ]
            if len(coalesce_args) == 1:
                expr = coalesce_args[0]  # N=1 → pas de COALESCE inutile
            else:
                expr = "COALESCE(" + ", ".join(coalesce_args) + ")"
            select_clauses.append(f"{expr} AS {alias_q}")
        elif "derivation" in item:
            # Phase Z.6 — arithmetic inter-CTE.
            expr = _ir_render_compose_derivation(item["derivation"])
            select_clauses.append(f"{expr} AS {alias_q}")
        else:
            ref_q = _ir_quote_sql_identifier(item["cte_ref"])
            ain_q = _ir_quote_sql_identifier(item["alias_in_cte"])
            select_clauses.append(f"{ref_q}.{ain_q} AS {alias_q}")

    # Squelette : WITH ... AS (...), ... AS (...) SELECT ... FROM ... [JOINs].
    parts: list[str] = []
    cte_clauses = [f"{_ir_quote_sql_identifier(name)} AS (\n{sql}\n)" for name, sql in cte_sqls]
    parts.append("WITH " + ",\n".join(cte_clauses))
    select_top = ""
    if isinstance(ir.get("limit"), int) and ir["limit"] > 0:
        select_top = f"TOP {int(ir['limit'])} "
    parts.append(f"SELECT {select_top}")
    parts.append("    " + ",\n    ".join(select_clauses))

    if len(cte_sqls) == 1:
        # N=1 : pas de FULL OUTER, juste FROM unique CTE.
        parts.append(f"FROM {_ir_quote_sql_identifier(cte_sqls[0][0])}")
    else:
        # N≥2 : FROM premier CTE + FULL OUTER JOIN cumulatif.
        first_name = cte_sqls[0][0]
        parts.append(f"FROM {_ir_quote_sql_identifier(first_name)}")
        seen_names: list[str] = [first_name]
        for next_name, _ in cte_sqls[1:]:
            next_q = _ir_quote_sql_identifier(next_name)
            if len(seen_names) == 1:
                left_side = f"{_ir_quote_sql_identifier(seen_names[0])}.{join_key_q}"
            else:
                left_side = (
                    "COALESCE("
                    + ", ".join(f"{_ir_quote_sql_identifier(n)}.{join_key_q}" for n in seen_names)
                    + ")"
                )
            right_side = f"{next_q}.{join_key_q}"
            parts.append(f"FULL OUTER JOIN {next_q} ON {left_side} = {right_side}")
            seen_names.append(next_name)

    order_by = compose.get("order_by") or []
    if order_by:
        order_clauses = []
        for o in order_by:
            ref = _ir_quote_sql_identifier(o["alias"])
            # FIX M6 (adversarial review) — defense-in-depth : valider
            # direction avant interpolation SQL. Si l'IR bypass _ir_validate
            # (test fixture, replay), un direction crafted (ex: "ASC; DROP")
            # ne doit JAMAIS arriver au SQL généré.
            raw_dir = o.get("direction", "ASC")
            direction = raw_dir if raw_dir in _IR_VALID_DIRECTIONS else "ASC"
            order_clauses.append(f"{ref} {direction}")
        parts.append("ORDER BY " + ", ".join(order_clauses))

    return "\n".join(parts) + ";"


def _parse_view_source_tables(view_sql: str) -> list[str]:
    """Extrait les noms de tables sources d'un SELECT de vue.

    Tente d'abord sqlglot (parser robuste, dialect T-SQL pour les vues
    SQL Server) ; fallback regex sur ``FROM ... [AS x]`` et ``JOIN ...``
    si sqlglot n'est pas disponible ou plante sur une syntaxe complexe.

    Generic : aucun pattern hardcodé sur des noms de tables/vues.
    Retourne une liste triée déterministe (utilisée pour dédup downstream).
    """
    if not isinstance(view_sql, str) or not view_sql.strip():
        return []
    try:
        import sqlglot

        ast = sqlglot.parse_one(view_sql, dialect="tsql")
        # find_all(exp.Table) retourne tous les nœuds Table (FROM, JOIN, etc.)
        names: set[str] = set()
        for t in ast.find_all(sqlglot.exp.Table):
            tn = t.name  # nom de table sans schema/alias
            if tn and isinstance(tn, str):
                names.add(tn)
        if names:
            return sorted(names)
    except Exception:
        pass
    # Fallback regex (heuristique). Match ``FROM <ident>`` et ``JOIN <ident>``
    # avec brackets T-SQL [name] optionnels et alias optionnel.
    pattern = re.compile(
        r"\b(?:FROM|JOIN)\s+\[?([A-Za-z_][A-Za-z0-9_]*)\]?",
        re.IGNORECASE,
    )
    found: set[str] = set()
    for m in pattern.finditer(view_sql):
        found.add(m.group(1))
    return sorted(found)


# Cache module-level pour `get_fk_lookup_from_db_with_views` : 423 vues à
# parser sur sage_copy.db = quelques secondes. Inutile de refaire le calcul
# 2-3 fois par run. Invalidation simple sur (db_path, mtime).
_FK_LOOKUP_VIEWS_CACHE: dict[tuple, dict] = {}


def get_fk_lookup_from_db_with_views(
    db_path: Path,
) -> dict[str, list[dict]]:
    """W2.3 — Étend ``get_fk_lookup_from_db`` avec les FKs propagées des
    vues SQL.

    Pour chaque vue de la BDD :
        1. Parse son SELECT pour extraire les tables sources.
        2. Propage les FKs sortantes des tables sources vers la vue
           (la vue "expose" les FKs de sa source canonique).

    Permet aux concepts résolus vers une vue (ex: ``viewMissions03``)
    d'être joints au reste du graphe FK comme s'ils étaient sur la table
    source. Sans ça, le BFS retourne « tables non-joignables » dès qu'un
    chemin passe par une vue.

    Generic : aucun pattern lexical sur ``view*``. Tout passe par le
    schema_dump (sqlite_master + parser SQL).

    **Robustesse** : si sqlglot manque ou si une vue SQL malformée plante
    le parser, fallback regex. Si la BDD ne contient aucune vue, retourne
    le fk_lookup standard sans erreur.
    """
    # Cache lookup (key = path + mtime).
    try:
        cache_key = (str(db_path), db_path.stat().st_mtime)
        cached = _FK_LOOKUP_VIEWS_CACHE.get(cache_key)
        if cached is not None:
            # Retourner une copie shallow pour éviter mutations cross-call.
            return {k: list(v) for k, v in cached.items()}
    except OSError:
        cache_key = None  # Si stat échoue, pas de cache.
    fk = get_fk_lookup_from_db(db_path)
    if not db_path.exists():
        return fk
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return fk
    try:
        rows = con.execute(
            "SELECT name, sql FROM sqlite_master " "WHERE type='view' AND sql IS NOT NULL"
        ).fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        con.close()
    for view_name, view_sql in rows:
        if not isinstance(view_name, str) or not view_name:
            continue
        sources = _parse_view_source_tables(view_sql or "")
        if not sources:
            continue
        # Propager FKs sortantes : pour chaque source S, FK(S → Y) devient
        # aussi FK(view → Y) (la vue expose les jointures de sa source).
        propagated: list[dict] = []
        seen_keys: set[tuple] = set()
        for src_table in sources:
            for fk_entry in fk.get(src_table, []):
                key = (
                    fk_entry.get("from_col"),
                    fk_entry.get("to_col"),
                    fk_entry.get("to_table"),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                propagated.append(
                    {
                        "from_col": fk_entry.get("from_col"),
                        "to_col": fk_entry.get("to_col"),
                        "to_table": fk_entry.get("to_table"),
                    }
                )
        if propagated:
            # Si la vue a déjà des FKs (rare en SQLite mais possible), on
            # merge sans écraser.
            existing = fk.get(view_name, [])
            existing_keys = {
                (e.get("from_col"), e.get("to_col"), e.get("to_table")) for e in existing
            }
            for p in propagated:
                pkey = (p["from_col"], p["to_col"], p["to_table"])
                if pkey not in existing_keys:
                    existing.append(p)
                    existing_keys.add(pkey)
            fk[view_name] = existing
    if cache_key is not None:
        _FK_LOOKUP_VIEWS_CACHE[cache_key] = {k: list(v) for k, v in fk.items()}
    return fk


def get_fk_lookup_from_db(db_path: Path) -> dict[str, list[dict]]:
    """Construit ``fk_lookup = {table: [{"to_table","from_col","to_col"}]}``
    depuis sage_copy.db via ``PRAGMA foreign_key_list``.

    Generic : marche sur n'importe quelle SQLite mirror avec PRAGMA support.
    """
    if not db_path.exists():
        return {}
    fk_lookup: dict[str, list[dict]] = {}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        # Liste les tables.
        tables = [
            r[0]
            for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        ]
        for tbl in tables:
            # PRAGMA foreign_key_list retourne (id, seq, table_to, col_from, col_to, ...).
            try:
                rows = con.execute(f"PRAGMA foreign_key_list([{tbl}])").fetchall()
            except sqlite3.OperationalError:
                continue
            fks: list[dict] = []
            for r in rows:
                # PRAGMA layout : id=0, seq=1, to_table=2, from_col=3, to_col=4
                fks.append(
                    {
                        "to_table": r[2],
                        "from_col": r[3],
                        "to_col": r[4],
                    }
                )
            if fks:
                fk_lookup[tbl] = fks
    finally:
        con.close()
    return fk_lookup


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.2.5 — Filtrage entités hors-sujet (✅ converti)
# ─────────────────────────────────────────────────────────────────────


_FILTER_SYSTEM_PROMPT = """\
Tu es un agent qui filtre dynamiquement les tables et vues d'une base de
données SQL pour un agent IA SQL aval. Ton rôle : identifier les entités
(tables/vues) MANIFESTEMENT hors-sujet pour la requête utilisateur, afin
qu'elles ne polluent pas le scoring downstream.

# Contexte du pipeline

Un pipeline en amont a déjà :
1. Pris la requête utilisateur en langage naturel
2. Extrait des concepts et leurs termes candidats
3. Trié et routé les termes (curate)

Tu reçois maintenant la liste COMPLÈTE des tables et vues de la BDD source
(avec leur row_count quand disponible). La phase suivante effectuera une
recherche textuelle de chaque terme dans 5 dimensions (T, V, C, VC, Val) sur
ces entités. Si tu droppes une entité, ses colonnes/valeurs ne seront pas
considérées non plus dans le scoring.

# Mode de sortie : SOIT questions, SOIT filtre — JAMAIS les deux

→ Si tu identifies au moins une vraie ambiguïté d'INTENTION qui t'empêche
  de décider proprement quelles tables sont hors-sujet : tu sors UNIQUEMENT
  les questions, sans toucher au filtre.

→ Sinon : tu sors UNIQUEMENT le filtre final (drop_tables + drop_views).

# Critère de drop

Drop UNIQUEMENT une table/vue si tu as une **forte certitude** qu'elle est
hors-sujet pour cette requête utilisateur. Dans le doute → KEEP. Mieux vaut
laisser passer 50 entités neutres que de droper 1 entité utile.

Drop si :
- Le nom révèle clairement un artefact technique de la BDD (table/vue
  temporaire de calcul, table système, dump de migration, copie de
  sauvegarde, etc.) ET le contenu probable n'a aucun rapport avec la requête
- Le nom révèle un domaine fonctionnel manifestement étranger à la requête
  (ex: si la requête concerne uniquement de la facturation et que tu vois
  des tables clairement liées à un autre métier, sans relation transitive
  possible)
- L'entité a manifestement un row_count de 0 ET un nom suggérant un
  contenu technique non utile

Ne drop PAS si :
- Le nom est ambigu / pourrait contenir de la donnée utile
- L'entité est une copie historique ou archive d'une table métier (un
  audit, un calcul rétroactif, une consolidation pourrait s'en servir)
- L'entité est une table de paramétrage / référentiel / configuration : ces
  tables sont souvent jointes aux requêtes métier
- Tu hésites : KEEP

# ask_user — uniquement si vraiment nécessaire

L'utilisateur n'a aucune idée de ce qui se passe en interne. Vocabulaire
technique INTERDIT (tables, vues, scoring, filtre, drop…).

Tu poses une question UNIQUEMENT quand :
- Une vraie ambiguïté d'INTENTION t'empêche de décider du périmètre métier
  de la requête
- Cette ambiguïté change matériellement quelles entités tu vas droper

Sinon → pas de question, sors directement le filtre.

✅ Exemples LÉGITIMES (intention, langage métier) :
  - "Tu demandes les 'meilleurs clients' — tu inclus aussi les anciens
    clients (archivés) ou seulement les actifs ?"
  - "Quand tu parles de 'données récentes', est-ce qu'on regarde aussi les
    données pré-migration importées historiquement ?"

❌ Exemples INTERDITS (workflow technique) :
  - "Je drop la table X ou je la garde ?"
  - "Cette vue contient des données archivées, je l'inclus ?"

# Format de sortie (JSON strict, rien d'autre)

CAS 1 — questions :
```json
{
  "mode": "questions",
  "ask_user": ["question 1", "question 2"]
}
```

CAS 2 — filtre :
```json
{
  "mode": "filter",
  "drop_tables": ["TableA", "TableB", ...],
  "drop_views":  ["ViewX", "ViewY", ...]
}
```

Règles JSON :
- `mode` obligatoire, soit "questions" soit "filter"
- Si mode="questions" : seul `ask_user` est présent (non vide)
- Si mode="filter" : `drop_tables` et `drop_views` présents (peuvent être
  vides si rien à droper)
- Les noms doivent correspondre EXACTEMENT (casse, accents) aux noms fournis
  en input. Pas d'invention.
- Réponds UNIQUEMENT le JSON, pas de markdown autour, pas de prose
"""


_FILTER_USER_PROMPT_TEMPLATE = """\
# Demande utilisateur (langage naturel — contexte uniquement)

> {user_query}

{session_qa_block}# Tables de la BDD ({n_tables} tables)

Format : `nom (row_count)`

{tables_block}

# Vues de la BDD ({n_views} vues)

{views_block}

# Ta tâche

Identifie les tables et vues MANIFESTEMENT hors-sujet pour cette requête
utilisateur. Sois CONSERVATEUR : dans le doute → KEEP.

Si tu manques de contexte d'INTENTION pour bien décider → mode questions.
Sinon → mode filter avec drop_tables et drop_views (qui peuvent être vides).

JSON strict.
"""

_FILTER_PHASE_NAME = "1.2.5_filter_entities"


def _list_db_entities(
    db_path: Path,
) -> tuple[list[tuple[str, int | None]], list[str]]:
    """List tables (with row_count) + views from a SQLite database."""
    if not db_path.exists():
        raise RuntimeError(f"❌ {db_path} introuvable")
    tables: list[tuple[str, int | None]] = []
    views: list[str] = []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        for name, kind in conn.execute(
            "SELECT name, type FROM sqlite_master "
            "WHERE type IN ('table', 'view') ORDER BY type, name"
        ):
            if kind == "table":
                try:
                    rc = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                except sqlite3.Error:
                    rc = None
                tables.append((name, rc))
            else:
                views.append(name)
    finally:
        conn.close()
    return tables, views


def _list_training_data_views(komptia_db: Path) -> list[str]:
    """Énumère les vues `auto_sync_view` dans `komptia.db` training_data.

    Source distincte de `sage_copy.db` : training_data peut contenir des
    vues plus récentes (sync direct depuis SQL Server) absentes du snapshot
    sage_copy local. Sans cette source, `--block-all-views` laisse passer
    les ~12 vues "résiduelles".
    """
    if not komptia_db.exists():
        return []
    conn = sqlite3.connect(f"file:{komptia_db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT DISTINCT table_name FROM training_data "
            "WHERE source = 'auto_sync_view' AND table_name IS NOT NULL"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return sorted({r[0] for r in rows if r[0]})


def _format_tables_block(tables: list[tuple[str, int | None]]) -> str:
    return "\n".join(
        f"  - {name} ({rc:,})" if rc is not None else f"  - {name} (?)" for name, rc in tables
    )


def _format_views_block(views: list[str]) -> str:
    return "\n".join(f"  - {v}" for v in views)


def _validate_drop_lists(
    drop_tables: list[str],
    drop_views: list[str],
    real_tables: set[str],
    real_views: set[str],
) -> tuple[list[str], list[str], list[str]]:
    """Retourne (valid_drop_tables, valid_drop_views, hallucinated_names)."""
    valid_t = [t for t in drop_tables if t in real_tables]
    valid_v = [v for v in drop_views if v in real_views]
    halluc = [t for t in drop_tables if t not in real_tables] + [
        v for v in drop_views if v not in real_views
    ]
    return valid_t, valid_v, halluc


def _render_filter_recap(
    drop_tables: list[str],
    drop_views: list[str],
    n_tables_total: int,
    n_views_total: int,
    hallucinated: list[str],
) -> str:
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("FILTERED ENTITIES — Phase 1.2.5 (drop dynamique tables/vues)")
    lines.append("=" * 80)
    lines.append("")
    lines.append(
        f"Tables  : {len(drop_tables):>4} dropped / {n_tables_total:>4} total "
        f"({len(drop_tables) * 100 // max(n_tables_total, 1)}%)"
    )
    lines.append(
        f"Vues    : {len(drop_views):>4} dropped / {n_views_total:>4} total "
        f"({len(drop_views) * 100 // max(n_views_total, 1)}%)"
    )
    if hallucinated:
        lines.append(
            f"⚠️  Hallucinations détectées : {len(hallucinated)} noms invalides "
            "ignorés (le LLM a inventé)"
        )
        for h in hallucinated[:10]:
            lines.append(f"     - {h}")
        if len(hallucinated) > 10:
            lines.append(f"     ... (+{len(hallucinated) - 10})")
    lines.append("")
    lines.append("─" * 80)
    lines.append(f"Drop tables ({len(drop_tables)}) :")
    lines.append("─" * 80)
    for t in sorted(drop_tables):
        lines.append(f"  - {t}")
    lines.append("")
    lines.append("─" * 80)
    lines.append(f"Drop vues ({len(drop_views)}) :")
    lines.append("─" * 80)
    for v in sorted(drop_views):
        lines.append(f"  - {v}")
    return "\n".join(lines)


class UserInputUnavailableError(RuntimeError):
    """L'agent a posé une question mais AUCUN canal de réponse n'est dispo
    (stdin non-TTY ET aucun ``AskUserBridge`` actif).

    Sous-type de ``RuntimeError`` : en mode standalone (``python
    scripts/pipeline.py`` sans TTY), les callers historiques qui catchent
    ``RuntimeError`` continuent de fail-fast comme avant. MAIS les phases
    1.2.5 / 1.2.6 le catchent **spécifiquement** pour dégrader gracieusement
    (fail-open) au lieu de crasher toute la pipeline (error_kind=unhandled) —
    sans masquer les autres ``RuntimeError`` (erreur LLM, JSON, mode inconnu).
    Cf. P1 #7 + doctrine F1 (ne convertir QUE le cas ciblé).
    """


def _collect_user_answers_filter(questions: list[str]) -> list[str]:
    """Pose les questions via input() (mode CLI). Fail fast si non-TTY.

    Utilisé en mode standalone (``python scripts/pipeline.py``). En mode
    Iris/runtime, c'est ``_ask_user_via_bridge_or_input()`` (async) qui
    est appelé en amont — il détecte ``AskUserBridge`` actif et délègue
    sans toucher stdin.
    """

    if not sys.stdin.isatty():
        raise UserInputUnavailableError(
            "❌ L'agent a posé des questions mais le script tourne en mode "
            "non-interactif (stdin non-TTY) ET aucun ``AskUserBridge`` n'est "
            "actif. Questions du LLM :\n  - " + "\n  - ".join(questions)
        )
    answers: list[str] = []
    print()
    print("─" * 72)
    print("L'agent a besoin de précisions :")
    print("─" * 72)
    for i, q in enumerate(questions, 1):
        print(f"\nQ{i}: {q}")
        ans = input(f"R{i}: ").strip()
        answers.append(ans)
    print("─" * 72)
    return answers


async def _ask_user_via_bridge_or_input(questions: list[str], *, phase_id: str) -> list[str]:
    """Pose les questions via ``AskUserBridge`` si présent, sinon CLI.

    Path bridge (runtime Iris) :
      - Pour chaque question, ``await bridge.ask(q, default_response="")``
      - Si timeout (default 120s côté bridge) → réponse vide.

    Path CLI (script standalone) :
      - Wrappe l'appel sync ``_collect_user_answers_filter`` dans
        ``asyncio.to_thread`` pour ne pas bloquer un éventuel event loop
        parent (rare en CLI, mais safe).
    """

    try:
        from app.services.ai.pipeline_ask_user_bridge import get_current_bridge
    except Exception:  # noqa: BLE001
        get_current_bridge = lambda: None  # type: ignore[assignment]

    bridge = get_current_bridge()
    if bridge is not None:
        answers: list[str] = []
        for q in questions:
            ans = await bridge.ask(
                q,
                context={"phase_id": phase_id},
                default_response="",
            )
            answers.append(ans)
        return answers
    return await asyncio.to_thread(_collect_user_answers_filter, questions)


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.2.4 — Concept Disambiguation (task #98 REFONTE-L3, 2026-05-22)
# ─────────────────────────────────────────────────────────────────────


def _parse_disambiguation_answers(
    raw_answer: str,
    ambiguities: list,
) -> dict[str, str]:
    """Parse la réponse user free-form en ``{concept: chosen_label}``.

    Heuristique générique (pas de format strict imposé à l'user) :
    pour chaque ambiguïté, on cherche dans la réponse les ``label``
    des candidates (format ``table.column``). Si exactement UN
    candidate est mentionné dans la réponse → c'est le choix.
    Sinon → laissé vide (le LLM aval verra l'ambiguïté non résolue
    dans le ``qa_session`` et pourra demander une précision).

    Pas de regex stricte : on accepte que l'user copie-colle le label,
    cite uniquement le nom de colonne, ou écrive en langage naturel
    si le nom de colonne est reconnaissable.
    """
    if not raw_answer or not ambiguities:
        return {}
    raw_lower = raw_answer.lower()
    answers: dict[str, str] = {}
    for amb in ambiguities:
        # ``amb`` peut être un objet Ambiguity (dataclass) ou un dict
        # sérialisé. On normalise.
        if hasattr(amb, "concept"):
            concept = amb.concept
            candidates = amb.candidates
        else:
            concept = amb.get("concept", "")
            candidates = amb.get("candidates", [])
        if not concept or not candidates:
            continue
        matched: list[str] = []
        for c in candidates:
            if hasattr(c, "label"):
                label = c.label()
                col_only = c.column
            elif isinstance(c, dict):
                label = f"{c.get('table', '')}.{c.get('column', '')}"
                col_only = c.get("column", "")
            else:
                continue
            # Match label complet (table.column) ou nom de colonne seul.
            # Le nom de colonne est généralement distinctif vu camelCase.
            if label.lower() in raw_lower or (
                col_only and len(col_only) >= 4 and col_only.lower() in raw_lower
            ):
                matched.append(label)
        # Choix unique = on retient. Ambiguïté maintenue ou zéro
        # match → on ne fait rien (le LLM aval ré-explorera).
        if len(matched) == 1:
            answers[concept] = matched[0]
    return answers


async def phase_1_2_4_disambiguate(
    extracted: dict,
    *,
    debug_traces: bool = False,
) -> dict:
    """Détecte les concepts user ambigus par inspection DDL au runtime.

    Doctrine **ingénierie amont** (vision Komptia 2026-05-22) : lever
    l'ambiguïté métier AVANT que le LLM produise du SQL faux silencieusement
    (cf. run #201 où Phase 3 a posé 3 Q vides auto-soumises).

    Architecture isolable :
    - **Détection** déléguée au module ``app.services.ai.concept_disambiguation``
      (testé indépendamment, pas de pattern hardcodé par BDD).
    - **Sortie** : ``{ambiguities: [...], answers: {...}, batch_question, trace_text}``.
    - **Pas de mécanisme Q user dans cette première itération** — l'intégration
      via ``pipeline_ask_user_bridge`` viendra dans une PR suivante. Pour
      l'instant, la phase logue les ambiguïtés détectées et continue.
      C'est sûr (aucun blocage pipeline, aucune Q posée) — la valeur
      apparaît dès qu'on branche le bridge dans la suite.

    Args:
        extracted : sortie de Phase 1.1-1.2 (dict avec clé ``concepts`` qui
            contient la liste des concepts user à analyser).
        debug_traces : si True, écrit la trace dans
            ``DEBUG_TRACES_DIR / phase_1_2_4_disambiguate.txt``.

    Returns:
        dict :
        - ``ambiguities`` : liste sérialisée des ambiguïtés détectées
        - ``answers`` : dict des réponses user (vide tant que le bridge
          n'est pas branché)
        - ``batch_question`` : la question formatée prête à poser
        - ``trace_text`` : trace lisible (humain)
    """
    from app.services.ai.concept_disambiguation import (
        detect_ambiguous_concepts,
        format_disambiguation_batch_question,
    )
    from app.services.ai.schema_loader import get_schema_loader

    concepts_raw = (extracted or {}).get("concepts") or []
    # Tolère deux formats : liste de strings OU liste de dicts {text, role, ...}
    concept_names: list[str] = []
    for c in concepts_raw:
        if isinstance(c, str):
            concept_names.append(c)
        elif isinstance(c, dict):
            name = c.get("text") or c.get("name") or c.get("concept") or ""
            if name:
                concept_names.append(str(name))

    if not concept_names:
        # Pas de concepts → rien à désambiguïser. Renvoie un résultat
        # vide mais structuré pour que les phases aval sachent que la
        # détection a été exécutée (pas None) et qu'aucune ambiguïté
        # n'existe.
        return {
            "ambiguities": [],
            "answers": {},
            "batch_question": None,
            "trace_text": "Phase 1.2.4 : aucun concept extrait — skip détection.",
        }

    # Charge le schéma DDL réel. ``get_table_columns`` retourne la liste
    # ``[{name, type, ...}]`` — pas de description (le YAML/cache ne la
    # contient pas systématiquement). La détection se base alors sur les
    # noms de colonnes + tokens (camelCase split).
    schema_loader = get_schema_loader()
    try:
        schema_loader.load()
    except Exception as exc:  # noqa: BLE001 — fail-soft
        # Sans schéma, on ne peut pas détecter. Renvoie un résultat vide
        # plutôt que crash — Phase 1.2.5 continuera normalement.
        logger.warning(
            "Phase 1.2.4 : schéma non chargeable, skip disambiguation (%s)",
            exc,
        )
        return {
            "ambiguities": [],
            "answers": {},
            "batch_question": None,
            "trace_text": f"Phase 1.2.4 : schéma indisponible, skip ({exc})",
        }

    # Construit le dict {table_name: [{name, description}, ...]} attendu
    # par detect_ambiguous_concepts. Utilise ``get_tables()`` puis
    # ``get_table_columns(name)`` pour chaque table — interface
    # SchemaLoader stable, pas de fouille du dict interne.
    schema_dict: dict[str, list[dict]] = {}
    try:
        tables = schema_loader.get_tables()
        # get_tables() peut renvoyer une liste de dicts ou de strings —
        # tolère les deux.
        table_names: list[str] = []
        for t in tables or []:
            if isinstance(t, str):
                table_names.append(t)
            elif isinstance(t, dict):
                tn = t.get("name") or t.get("table") or ""
                if tn:
                    table_names.append(str(tn))
        for tn in table_names:
            cols = schema_loader.get_table_columns(tn)
            if cols:
                schema_dict[tn] = cols
    except Exception as exc:  # noqa: BLE001
        logger.warning("Phase 1.2.4 : extraction schema partielle (%s)", exc)

    ambiguities = detect_ambiguous_concepts(concept_names, schema_dict)
    batch_question = format_disambiguation_batch_question(ambiguities)

    # Refactor 2026-05-25 — hint async au lieu de blocage synchrone.
    # Historiquement : `bridge.ask()` bloquait la pipeline en attendant la
    # réponse user à la batch question. Maintenant : on propage TOUJOURS
    # les ambiguïtés détectées via qa_session avec `auto_submitted=True`,
    # ce qui injecte un hint dans le prompt des phases aval (1.2.5, 2.5,
    # 3) sous le wording "auto-soumis, décide toi-même". Le LLM voit la
    # détection d'ambiguïté + les candidates et tranche par raisonnement
    # (contexte SQL, sémantique des noms de colonnes, qa_session précédents).
    # answers reste un dict vide — c'est l'agent qui résout, plus le pre-flow.
    answers: dict[str, str] = {}
    if ambiguities and batch_question:
        try:
            from app.services.ai import user_qa_session as _qs

            for amb in ambiguities:
                candidate_labels = ", ".join(c.label() for c in amb.candidates)
                _qs.add_qa(
                    "1.2.4_disambiguate",
                    f"Pour le concept « {amb.concept} », quelle colonne "
                    f"utiliser parmi : {candidate_labels} ?",
                    "",  # pas de réponse — hint async, le LLM tranchera
                    concept=amb.concept,
                    auto_submitted=True,
                )
            logger.info(
                "Phase 1.2.4 — %d ambiguïté(s) détectée(s), propagées "
                "comme hint async aux phases aval (qa_session auto-submit).",
                len(ambiguities),
            )
        except Exception as exc:  # noqa: BLE001
            # Fail-soft : la phase n'a pas le droit de bloquer la pipeline.
            logger.warning(
                "Phase 1.2.4 — qa_session.add_qa failed (%s), ambiguïtés "
                "loggées seulement",
                exc,
            )

    # Sérialisation pour run.json (dataclasses → dicts)
    serialized_ambigs = [
        {
            "concept": a.concept,
            "candidates": [
                {
                    "table": c.table,
                    "column": c.column,
                    "description": c.description,
                }
                for c in a.candidates
            ],
            "hint": a.hint,
        }
        for a in ambiguities
    ]

    n_amb = len(ambiguities)
    trace_lines = [
        f"Phase 1.2.4 — Concept Disambiguation",
        f"Concepts examinés : {len(concept_names)}",
        f"Concepts ambigus détectés : {n_amb}",
        f"Ambiguïtés résolues par l'user : {len(answers)}",
        "",
    ]
    if n_amb:
        for a in ambiguities:
            trace_lines.append(f"• {a.concept}")
            for c in a.candidates:
                desc = f" ({c.description})" if c.description else ""
                trace_lines.append(f"    - {c.label()}{desc}")
            if a.concept in answers:
                trace_lines.append(f"    → user a choisi : {answers[a.concept]}")
        trace_lines.append("")
        if not answers and not bool(ambiguities):
            trace_lines.append("Aucune ambiguïté → pas de Q user à poser.")
        elif not answers:
            trace_lines.append(
                "Pas de bridge user actif (CLI standalone) OU user n'a pas "
                "résolu les ambiguïtés — les phases aval verront le qa_session "
                "vide et ré-exploreront."
            )
    else:
        trace_lines.append("Aucune ambiguïté → pas de Q user à poser.")

    trace_text = "\n".join(trace_lines)
    if debug_traces:
        (DEBUG_TRACES_DIR / "phase_1_2_4_disambiguate.txt").write_text(
            trace_text, encoding="utf-8"
        )

    logger.info(
        "Phase 1.2.4 — %d ambiguïté(s) détectée(s) sur %d concept(s) "
        "(%d résolues par l'user)",
        n_amb,
        len(concept_names),
        len(answers),
    )

    return {
        "ambiguities": serialized_ambigs,
        "answers": answers,  # {concept: chosen_label} si user a répondu
        "batch_question": batch_question,
        "trace_text": trace_text,
    }


async def phase_1_2_5_filter(
    query: str,
    extracted: dict,
    *,
    model_id: str,
    api_key: str,
    db_path: Path,
    max_qa_loops: int = 2,
    block_all_views: bool = False,
    debug_traces: bool = False,
) -> dict:
    """Phase 1.2.5 — Filtrage dynamique des tables/vues hors-sujet (LLM).

    Inputs :
        query        : requête utilisateur en NL (déjà extraite)
        extracted    : output Phase 1.1+1.2 (utilisé pour reset session si query change)
        db_path      : BDD source (sage_copy.db)
        max_qa_loops : nb max de cycles Q/A avant abandon
        block_all_views : mode test, ajoute TOUTES les vues au drop list
                          en plus du filtrage LLM normal (orthogonal au LLM —
                          le LLM continue à filtrer les entités hors-sujet
                          par requête, et toutes les vues sont droppées par
                          dessus pour forcer le LLM aval à reconstituer les
                          paths via les tables uniquement)

    Output (dict) :
        - mode               : 'filter' ou 'max_loops_exceeded' (sentinelle)
        - drop_tables        : list[str]
        - drop_views         : list[str]
        - hallucinated       : list[str] (noms inventés par LLM, ignorés)
        - test_mode          : str | None (info si block_all_views)
        - block_sources      : dict | None (détail si block_all_views)
        - last_questions     : list[str] | None (si max_loops_exceeded)
        - trace_text         : str — récap human-readable
        - raw_responses      : list[str] — bruts LLM par loop (debug, vide si block_all_views)
    """
    from app.services.ai import user_qa_session as qa_session

    tables, views = _list_db_entities(db_path)
    real_tables = {n for n, _ in tables}
    real_views = set(views)

    # --- Mode normal : appel LLM avec boucle Q/A ---
    raw_responses: list[str] = []
    for loop in range(max_qa_loops + 1):
        user_prompt = _FILTER_USER_PROMPT_TEMPLATE.format(
            user_query=query,
            session_qa_block=qa_session.format_for_prompt(),
            n_tables=len(tables),
            n_views=len(views),
            tables_block=_format_tables_block(tables),
            views_block=_format_views_block(views),
        )

        print(f"→ Phase 1.2.5: appel LLM (loop {loop + 1}/{max_qa_loops + 1})...", flush=True)
        try:
            raw = await call_llm(
                _FILTER_SYSTEM_PROMPT,
                user_prompt,
                model_id=model_id,
                api_key=api_key,
                caller="pipeline_p125_filter",
                max_tokens=8000,
            )
        except Exception as e:
            raise RuntimeError(f"Phase 1.2.5 — erreur LLM : {e}") from e
        raw_responses.append(raw)

        data = parse_llm_json(raw)
        if data is None:
            raise RuntimeError(
                f"Phase 1.2.5 — JSON parse échoué (loop {loop + 1}). " f"Raw : {raw[:200]}..."
            )

        mode = data.get("mode")
        # Validation either/or stricte.
        if mode == "questions" and ("drop_tables" in data or "drop_views" in data):
            print(
                "⚠️  mode=questions ET drop_* présent — drop ignoré "
                "(devra être recalculé après réponses)"
            )
            data.pop("drop_tables", None)
            data.pop("drop_views", None)
        elif mode == "filter" and data.get("ask_user"):
            print(
                f"⚠️  mode=filter mais ask_user non vide — questions ignorées : "
                f"{data.get('ask_user')}"
            )
            data["ask_user"] = []

        if mode == "questions":
            questions = data.get("ask_user", [])
            if not questions:
                raise RuntimeError("Phase 1.2.5 — mode=questions mais ask_user vide")
            if loop >= max_qa_loops:
                # Sentinelle : aval doit fail-fast plutôt que lire un drop trompeur.
                print(
                    "❌ Max QA loops atteint sans converger vers filter. " "Sentinelle retournée."
                )
                return {
                    "mode": "max_loops_exceeded",
                    "drop_tables": [],
                    "drop_views": [],
                    "hallucinated": [],
                    "test_mode": None,
                    "block_sources": None,
                    "last_questions": questions,
                    "trace_text": (
                        "❌ Phase 1.2.5 : max_qa_loops atteint sans converger "
                        "vers filter. Dernières questions LLM :\n  - " + "\n  - ".join(questions)
                    ),
                    "raw_responses": raw_responses,
                }
            try:
                answers = await _ask_user_via_bridge_or_input(questions, phase_id="1.2.5")
            except UserInputUnavailableError:
                # P1 #7 — non-interactif sans bridge : le LLM voulait préciser
                # le périmètre mais on ne peut pas demander. Dégradation
                # gracieuse FAIL-OPEN : on ne droppe RIEN (mode=filter vide).
                # Conséquence : la recherche aval considère TOUTES les entités
                # (plus large, jamais une donnée fausse — au pire du bruit que
                # le scoring/rerank écarte). Bien préférable à un crash
                # error_kind=unhandled de toute la pipeline.
                print(
                    "⚠️  Phase 1.2.5 : questions LLM mais aucun canal user "
                    "(non-TTY, pas de bridge) → fail-open, aucun drop.",
                    flush=True,
                )
                return {
                    "mode": "filter",
                    "drop_tables": [],
                    "drop_views": [],
                    "hallucinated": [],
                    "test_mode": None,
                    "block_sources": None,
                    "last_questions": questions,
                    "trace_text": (
                        "⚠️ Phase 1.2.5 : input utilisateur indisponible "
                        "(non-interactif). Fail-open : aucune entité droppée. "
                        "Questions LLM non posées :\n  - " + "\n  - ".join(questions)
                    ),
                    "raw_responses": raw_responses,
                }
            for q, a in zip(questions, answers):
                qa_session.add_qa(_FILTER_PHASE_NAME, q, a)
            continue

        if mode == "filter":
            drop_t = data.get("drop_tables", [])
            drop_v = data.get("drop_views", [])
            if not isinstance(drop_t, list) or not all(isinstance(x, str) for x in drop_t):
                raise RuntimeError(
                    f"Phase 1.2.5 — drop_tables doit être list[str], "
                    f"reçu : {type(drop_t).__name__}"
                )
            if not isinstance(drop_v, list) or not all(isinstance(x, str) for x in drop_v):
                raise RuntimeError(
                    f"Phase 1.2.5 — drop_views doit être list[str], "
                    f"reçu : {type(drop_v).__name__}"
                )
            valid_t, valid_v, halluc = _validate_drop_lists(
                drop_t,
                drop_v,
                real_tables,
                real_views,
            )
            if halluc:
                print(
                    f"⚠️  {len(halluc)} noms hallucinés ignorés "
                    f"(le LLM a inventé) : {halluc[:5]}..."
                )
            # Mode block-all-views : on garde le filtrage LLM normal sur
            # tables ET vues (= entités hors-sujet par requête), puis on
            # AJOUTE toutes les vues restantes au drop_views — pour que
            # le LLM aval reconstitue les paths via tables uniquement.
            test_mode_label: str | None = None
            block_sources: dict | None = None
            if block_all_views:
                training_views = _list_training_data_views(KOMPTIA_DB)
                all_views = set(views) | set(training_views)
                # Union avec ce que le LLM avait déjà droppé (déduplication)
                final_drop_views = sorted(all_views | set(valid_v))
                extra_views_from_training = [v for v in training_views if v not in set(views)]
                test_mode_label = "block-all-views (LLM filter normal + toutes vues ajoutées)"
                block_sources = {
                    "sage_copy_views": len(views),
                    "training_data_extra_views": len(extra_views_from_training),
                    "llm_dropped_views": len(valid_v),
                    "total_dropped_views": len(final_drop_views),
                }
                valid_v = final_drop_views
                print(
                    f"⚠️  block-all-views actif : LLM a droppé {len(drop_v)} vues + on ajoute "
                    f"{len(all_views) - len(set(valid_v) & all_views)} vues additionnelles "
                    f"(total {len(final_drop_views)})"
                )
            trace_text = _render_filter_recap(
                valid_t,
                valid_v,
                len(tables),
                len(views),
                halluc,
            )
            if debug_traces:
                DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
                (DEBUG_TRACES_DIR / "phase_1_2_5_filter_recap.txt").write_text(
                    trace_text,
                    encoding="utf-8",
                )
                (DEBUG_TRACES_DIR / "phase_1_2_5_filter_raw.txt").write_text(
                    "\n\n--- LOOP SEPARATOR ---\n\n".join(raw_responses),
                    encoding="utf-8",
                )
            print(
                f"✓ Drop tables : {len(valid_t):>4} / {len(tables)} "
                f"({len(valid_t) * 100 // max(len(tables), 1)}%)  "
                f"| Drop vues : {len(valid_v):>4} / {len(views)} "
                f"({len(valid_v) * 100 // max(len(views), 1)}%)"
            )
            return {
                "mode": "filter",
                "drop_tables": sorted(valid_t),
                "drop_views": sorted(valid_v),
                "hallucinated": halluc,
                "test_mode": test_mode_label,
                "block_sources": block_sources,
                "last_questions": None,
                "trace_text": trace_text,
                "raw_responses": raw_responses,
            }

        raise RuntimeError(f"Phase 1.2.5 — mode inconnu : {mode!r}")

    raise RuntimeError("Phase 1.2.5 — boucle Q/A terminée sans return (cas impossible)")


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.2.6 — Curate routing par concept (✅ converti)
# ─────────────────────────────────────────────────────────────────────


_CURATE_SYSTEM_PROMPT = """\
Tu es un agent qui prépare la recherche de termes dans une base de données SQL pour
un agent IA SQL aval. Tu reçois UN concept à la fois avec ses termes candidats.
Ton rôle : trier et router les termes pour ce concept, et signaler les ambiguïtés
UNIQUEMENT si elles t'empêchent réellement de décider.

# Contexte du pipeline

Un pipeline en amont a déjà :
1. Pris la requête utilisateur en langage naturel
2. Extrait des concepts et leurs termes candidats
3. Généré des variantes / synonymes / dérivations pour chaque terme

Tu reçois maintenant UN concept précis avec ses termes (originaux + expansions).
La phase suivante effectuera une recherche textuelle de chaque terme conservé
dans 5 dimensions de la BDD :
- **T**   = nom de table
- **V**   = nom de vue
- **C**   = nom de colonne d'une table
- **VC**  = nom de colonne d'une vue
- **Val** = valeur stockée dans une colonne

Ton boulot : décider QUELS termes garder, en AJOUTER si pertinent, et choisir SUR
QUELLES dimensions chacun doit être cherché.

# Mode de sortie : SOIT questions, SOIT routage — JAMAIS les deux

→ Si tu identifies au moins une vraie ambiguïté d'INTENTION qui t'empêche de
  décider : tu sors UNIQUEMENT les questions, sans toucher au routage.

→ Sinon : tu sors UNIQUEMENT le routage final, sans questions.

# Tri des termes

DROP (silencieusement) :
- Mots de liaison / remplissage : "tout", "chaque", "même", "lequel"
- Politesse / préambule : "bonjour", "merci", "peux-tu", "j'aimerais"
- Adjectifs / adverbes vagues sans potentiel de match : "important", "principal"
- Variantes d'expansion sans aucune chance de matcher

KEEP : tout terme qui pourrait matcher dans au moins UNE des 5 dimensions
       de recherche (T, V, C, VC ou Val).

# Ajout de termes (ADD)

Si tu juges qu'un terme évident manque pour ce concept (synonyme, lemme,
abréviation courante, forme dérivée), ajoute-le. Sois mesuré.

# Routage des dimensions

Pour chaque terme conservé / ajouté, choisis la combinaison de dimensions où
il apportera un signal UTILE pour ce concept dans le contexte de la requête
utilisateur. **Ton seul objectif : éviter le bruit.**

Toutes les combinaisons des 5 dimensions sont possibles (31 au total). Aucune
forme imposée : choisis librement selon le terme et le concept.

# ask_user — uniquement si vraiment nécessaire

L'utilisateur n'a aucune idée de ce qui se passe en interne. Vocabulaire
technique INTERDIT (tables, vues, dimensions, routage, tri, drop…).

Tu poses une question UNIQUEMENT quand :
- Tu identifies une vraie ambiguïté dans **l'intention** de l'utilisateur
- Cette ambiguïté t'empêche réellement de décider du tri ou du routage

✅ LÉGITIMES (intention, langage métier) :
  - "Tu demandes les 'meilleurs clients' — par quel critère : chiffre
    d'affaires, nombre d'achats, ancienneté ?"
  - "Quand tu dis 'commandes en cours', c'est non livrées, non payées, autre ?"

❌ INTERDITS (workflow technique) :
  - "Je cherche le terme X dans Val ou dans C ?"
  - "Je conserve le terme Y ou je le drop ?"

# Format de sortie (JSON strict)

CAS 1 — questions :
```json
{
  "concept": "<nom du concept reçu>",
  "mode": "questions",
  "ask_user": ["question 1", "question 2"]
}
```

CAS 2 — routage :
```json
{
  "concept": "<nom du concept reçu>",
  "mode": "routing",
  "routing": {
    "[T,V,C,VC]": ["terme1", "terme2"],
    "[Val]": ["valeur1"],
    "[C,VC]": ["terme3"]
  }
}
```

Règles JSON :
- `concept` = nom exact du concept reçu en input
- `mode` obligatoire, soit "questions" soit "routing"
- Si mode="questions" : seul `ask_user` est présent (non vide)
- Si mode="routing" : seul `routing` est présent (non vide)
- Clés de `routing` = combinaisons de dimensions, dans l'ordre fixe
  **T, V, C, VC, Val**, entre crochets séparées par virgules sans espaces
- Réponds UNIQUEMENT le JSON, pas de markdown autour
"""


_CURATE_USER_PROMPT_TEMPLATE = """\
# Demande utilisateur (langage naturel — contexte uniquement)

> {user_query}

{session_qa_block}# Concept à traiter

**{concept}**{values_clause}

# Termes candidats

{terms_list}

Trie / ajoute / route ces termes selon le SYSTEM. JSON strict.
"""

_CURATE_PHASE_NAME = "1.2.6_curate"


def _build_terms_per_concept(extracted: dict) -> dict[str, list[str]]:
    """Pour chaque concept, retourne [concept_name, *valeurs, *expansions].

    Reconstruit la liste des termes candidats à curate à partir de l'état
    Phase 1.1+1.2 (au lieu de la re-parser depuis un fichier texte).
    Déduplication par lowercase, ordre stable.
    """
    groupes = extracted.get("groupes", {}) or {}
    term_origins = extracted.get("term_origins", {}) or {}

    out: dict[str, list[str]] = {}
    for concept, values in groupes.items():
        seen: set[str] = set()
        ordered: list[str] = []

        def _add(t: str) -> None:
            t = t.strip()
            if t and t.lower() not in seen:
                seen.add(t.lower())
                ordered.append(t)

        _add(concept)
        for v in values:
            _add(v)
        # Expansions : term_origins maps expansion → list of parent concepts.
        for term, parents in term_origins.items():
            if concept in parents:
                _add(term)

        out[concept] = ordered
    return out


def _render_curated_recap(results: dict[str, dict]) -> str:
    """Format le récap human-readable des résultats curate."""
    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("CURATED TERMS — Phase 1.2.6 (tri + routage par concept)")
    lines.append("=" * 80)
    lines.append("")
    for concept in sorted(results):
        data = results[concept]
        mode = data.get("mode", "?")
        lines.append("=" * 80)
        lines.append(f"CONCEPT: {concept}  [{mode}]")
        lines.append("=" * 80)
        if mode == "questions":
            for q in data.get("ask_user", []):
                lines.append(f"  ❓ {q}")
        elif mode == "routing":
            routing = data.get("routing", {})
            for combo in sorted(routing, key=lambda k: (-len(k), k)):
                terms = routing[combo]
                lines.append(f"  {combo} ({len(terms)}):")
                for t in terms:
                    lines.append(f"    - {t}")
        else:
            lines.append(f"  (mode {mode!r})")
        lines.append("")
    return "\n".join(lines)


def _collect_user_answers_curate(questions: list[str]) -> list[str]:
    """Pose les questions via input(). Fail fast si non-TTY."""
    if not sys.stdin.isatty():
        raise UserInputUnavailableError(
            "❌ L'agent (curate) a posé des questions mais stdin n'est pas TTY.\n"
            "Questions :\n  - " + "\n  - ".join(questions)
        )
    answers: list[str] = []
    print()
    print("─" * 72)
    print("L'agent a besoin de précisions :")
    print("─" * 72)
    for i, q in enumerate(questions, 1):
        print(f"\nQ{i}: {q}")
        ans = input(f"R{i}: ").strip()
        answers.append(ans)
    print("─" * 72)
    return answers


async def phase_1_2_6_curate(
    query: str,
    extracted: dict,
    filtered: dict,
    *,
    model_id: str,
    api_key: str,
    max_qa_loops: int = 2,
    concept_filter: str | None = None,
    debug_traces: bool = False,
) -> dict:
    """Phase 1.2.6 — Curation et routage des termes par concept (LLM).

    Inputs :
        query           : requête NL
        extracted       : output Phase 1.1+1.2 (groupes, term_origins)
        filtered        : output Phase 1.2.5 (non utilisé directement par
                          curate — concepts ≠ entités, mais gardé pour
                          consistance d'API)
        max_qa_loops    : nb max de cycles Q/A par concept
        concept_filter  : substring match — restreint à un seul concept (debug)

    Output (dict) :
        - per_concept   : dict[concept, dict] — un payload par concept :
                          - mode : 'routing' / 'questions' / 'max_loops_exceeded'
                                  / 'parse_error' / 'error'
                          - routing : dict (si mode=routing)
                          - ask_user : list (si mode=questions)
                          - last_questions / error / raw : selon le cas
        - trace_text    : récap human-readable
        - raw_responses : dict[concept, list[str]] — bruts LLM par loop (debug)
    """
    from app.services.ai import user_qa_session as qa_session

    terms_per_concept = _build_terms_per_concept(extracted)
    if not terms_per_concept:
        raise RuntimeError("Phase 1.2.6 — aucun concept dans extracted (Phase 1.1+1.2 KO ?)")

    if concept_filter:
        match = [c for c in terms_per_concept if concept_filter.lower() in c.lower()]
        if not match:
            raise RuntimeError(
                f"Phase 1.2.6 — concept '{concept_filter}' introuvable. "
                f"Disponibles : {list(terms_per_concept)}"
            )
        concepts_to_run = match
    else:
        concepts_to_run = list(terms_per_concept)

    print(f"→ Phase 1.2.6 : {len(concepts_to_run)} concept(s) à traiter")

    groupes = extracted.get("groupes", {}) or {}
    all_results: dict[str, dict] = {}
    raw_per_concept: dict[str, list[str]] = {}
    prompts_per_concept: dict[str, list[str]] = {}

    # Stratégie de parallélisation : 1ère passe LLM en PARALLÈLE pour tous
    # les concepts (gain ×N quand pas de Q/A nécessaire). Les concepts qui
    # répondent en mode="questions" sont ensuite traités en SÉQUENTIEL pour
    # gérer input() proprement (sinon les Q/A se chevauchent à l'écran).

    async def _first_pass(concept: str) -> tuple[str, str | None, dict | None, str]:
        """1ʳᵉ passe LLM pour UN concept (sans Q/A loop).

        Retourne (concept, raw_response, parsed_data, user_prompt).
        user_prompt toujours retourné pour debug même si LLM fail.
        """
        terms = terms_per_concept[concept]
        values = groupes.get(concept, [])
        values_clause = (
            f" — valeurs explicites mentionnées par l'utilisateur : {', '.join(values)}"
            if values
            else ""
        )
        terms_block = "\n".join(f"  - {t}" for t in terms)
        user_prompt = _CURATE_USER_PROMPT_TEMPLATE.format(
            user_query=query,
            concept=concept,
            values_clause=values_clause,
            terms_list=terms_block,
            session_qa_block=qa_session.format_for_prompt(),
        )
        try:
            raw = await call_llm(
                _CURATE_SYSTEM_PROMPT,
                user_prompt,
                model_id=model_id,
                api_key=api_key,
                caller="pipeline_p126_curate",
                max_tokens=4000,
            )
        except Exception as e:
            print(f"  ❌ {concept} — erreur LLM : {e}", flush=True)
            return concept, None, None, user_prompt
        data = parse_llm_json(raw)
        return concept, raw, data, user_prompt

    print(f"→ Lancement de {len(concepts_to_run)} curates en parallèle (1ʳᵉ passe)...", flush=True)
    first_pass_results = await asyncio.gather(
        *[_first_pass(c) for c in concepts_to_run],
        return_exceptions=False,
    )

    # Tri : routing/error/parse_error sont fini ; questions partent en séquentiel après.
    needs_qa: list[tuple[str, str, dict]] = []
    for concept, raw, data, user_prompt in first_pass_results:
        prompts_per_concept[concept] = [user_prompt]
        if raw is None:
            all_results[concept] = {"concept": concept, "mode": "error"}
            raw_per_concept[concept] = []
            continue
        raw_per_concept[concept] = [raw]
        if data is None:
            print(f"  ⚠️  {concept} — JSON parse échoué", flush=True)
            all_results[concept] = {"concept": concept, "mode": "parse_error", "raw": raw}
            continue
        mode = data.get("mode")
        if mode == "questions" and "routing" in data:
            data.pop("routing", None)
        elif mode == "routing" and data.get("ask_user"):
            data["ask_user"] = []

        if mode == "routing":
            routing = data.get("routing", {})
            n_terms = sum(len(ts) for ts in routing.values())
            print(
                f"  ✓ {concept} — {n_terms} termes routés sur {len(routing)} combinaisons",
                flush=True,
            )
            all_results[concept] = data
        elif mode == "questions":
            qs = data.get("ask_user", [])
            if not qs:
                all_results[concept] = data
            else:
                print(
                    f"  ❓ {concept} — {len(qs)} question(s) à poser après la passe parallèle",
                    flush=True,
                )
                needs_qa.append((concept, raw, data))
        else:
            print(f"  ⚠️  {concept} — mode inconnu : {mode!r}", flush=True)
            all_results[concept] = data

    # Q/A séquentiel pour les concepts qui en ont besoin (input() interactif)
    if needs_qa:
        print(f"\n→ Q/A séquentiel pour {len(needs_qa)} concept(s)...", flush=True)
    for concept, raw_initial, data_initial in needs_qa:
        terms = terms_per_concept[concept]
        values = groupes.get(concept, [])
        values_clause = (
            f" — valeurs explicites mentionnées par l'utilisateur : {', '.join(values)}"
            if values
            else ""
        )
        terms_block = "\n".join(f"  - {t}" for t in terms)
        raws = list(raw_per_concept.get(concept, []))
        prompts_qa = list(prompts_per_concept.get(concept, []))
        result: dict | None = None

        # Pose la 1ʳᵉ question (déjà chargée), puis loop QA.
        questions = data_initial.get("ask_user", [])
        try:
            answers = await _ask_user_via_bridge_or_input(questions, phase_id="1.2.6")
        except UserInputUnavailableError:
            # P1 #7 — non-interactif sans bridge : on ne peut pas préciser le
            # routing de ce concept. Fail-open : on le marque input_unavailable
            # (mode ≠ routing). _curate_routing_from_state le SKIP → filtre dim
            # désactivé pour ce concept = ses termes ne sont pas restreints
            # (recherche plus large, jamais de donnée fausse). Pas de crash.
            print(
                f"  ⚠️  {concept} — input utilisateur indisponible (non-TTY, "
                f"pas de bridge) → fail-open, routing dim désactivé pour ce concept.",
                flush=True,
            )
            all_results[concept] = {
                "concept": concept,
                "mode": "input_unavailable",
                "last_questions": questions,
            }
            raw_per_concept[concept] = raws
            prompts_per_concept[concept] = prompts_qa
            continue
        for q, a in zip(questions, answers):
            qa_session.add_qa(_CURATE_PHASE_NAME, q, a, concept=concept)

        for loop in range(max_qa_loops):
            user_prompt = _CURATE_USER_PROMPT_TEMPLATE.format(
                user_query=query,
                concept=concept,
                values_clause=values_clause,
                terms_list=terms_block,
                session_qa_block=qa_session.format_for_prompt(),
            )
            prompts_qa.append(user_prompt)
            try:
                raw = await call_llm(
                    _CURATE_SYSTEM_PROMPT,
                    user_prompt,
                    model_id=model_id,
                    api_key=api_key,
                    caller="pipeline_p126_curate",
                    max_tokens=4000,
                )
            except Exception as e:
                print(f"  ❌ {concept} — erreur LLM (retry {loop+1}) : {e}", flush=True)
                result = {"concept": concept, "mode": "error", "error": str(e)}
                break
            raws.append(raw)
            data = parse_llm_json(raw)
            if data is None:
                result = {"concept": concept, "mode": "parse_error", "raw": raw}
                break
            mode = data.get("mode")
            if mode == "routing":
                result = data
                break
            if mode == "questions":
                qs = data.get("ask_user", [])
                if not qs or loop + 1 >= max_qa_loops:
                    result = {
                        "concept": concept,
                        "mode": "max_loops_exceeded",
                        "last_questions": qs,
                    }
                    break
                try:
                    ans = await _ask_user_via_bridge_or_input(qs, phase_id="1.2.6")
                except UserInputUnavailableError:
                    # P1 #7 — fail-open identique au 1er tour : input indispo →
                    # input_unavailable (skip routing dim pour ce concept).
                    print(
                        f"  ⚠️  {concept} — input utilisateur indisponible "
                        f"(retry {loop+1}) → fail-open, routing dim désactivé.",
                        flush=True,
                    )
                    result = {
                        "concept": concept,
                        "mode": "input_unavailable",
                        "last_questions": qs,
                    }
                    break
                for q, a in zip(qs, ans):
                    qa_session.add_qa(_CURATE_PHASE_NAME, q, a, concept=concept)
                continue
            result = data
            break

        if result is None:
            result = {"concept": concept, "mode": "max_loops"}
        all_results[concept] = result
        raw_per_concept[concept] = raws
        prompts_per_concept[concept] = prompts_qa

    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        for concept, raws in raw_per_concept.items():
            if not raws:
                continue
            slug = slug_from_concept(concept)
            (DEBUG_TRACES_DIR / f"phase_1_2_6_curate_{slug}.raw.txt").write_text(
                "\n\n--- LOOP SEPARATOR ---\n\n".join(raws),
                encoding="utf-8",
            )

    trace_text = _render_curated_recap(all_results)
    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_1_2_6_curate_recap.txt").write_text(
            trace_text,
            encoding="utf-8",
        )

    return {
        "per_concept": all_results,
        "trace_text": trace_text,
        "raw_responses": raw_per_concept,
        "system_prompt": _CURATE_SYSTEM_PROMPT,
        "prompts_per_concept": prompts_per_concept,
    }


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.3+1.4 — Search BDD + groupage par concept (✅ converti)
# ─────────────────────────────────────────────────────────────────────


def _curate_routing_from_state(curated: dict) -> dict[str, set[str]]:
    """Construit {concept: {dim_internal}} depuis l'état curated en mémoire.

    Équivalent in-memory de `load_curate_routing` qui lisait
    `outputs/llm_curate/*.json`. Ici on lit directement curated['per_concept'].
    """
    per_concept = curated.get("per_concept", {}) or {}
    routing: dict[str, set[str]] = {}
    skipped: list[str] = []
    for concept, data in per_concept.items():
        mode = data.get("mode")
        if mode != "routing":
            skipped.append(f"{concept}: mode={mode!r}")
            continue
        allowed: set[str] = set()
        for combo, _terms in (data.get("routing") or {}).items():
            for dim_short in parse_routing_combo(combo):
                internal = ROUTING_DIM_TO_INTERNAL.get(dim_short)
                if internal:
                    allowed.add(internal)
        # P1 #8 (2026-05-30) — FAIL-OPEN sur routing vide. Si le LLM a renvoyé
        # mode=routing mais que les combos sont illisibles / non mappables
        # (allowed == set() vide), NE PAS poser ``routing[concept] = set()`` :
        # en aval ``allowed_dims is not None`` serait True et ``dim not in
        # set()`` TOUJOURS vrai → TOUS les matches du concept écartés → 0
        # candidat → crash aval (même symptôme que run #16). On distingue donc
        # None (pas de routing → on ne filtre pas) du set vide (bug LLM →
        # fail-open + warning). Le routing est une OPTIMISATION anti-bruit,
        # jamais une garantie de correction.
        if not allowed:
            skipped.append(f"{concept}: routing vide (combos illisibles → filtre désactivé)")
            continue
        routing[concept] = allowed
    if skipped:
        print(
            f"⚠️  curate routing : {len(skipped)} concept(s) skippé(s) "
            f"(filtre dim désactivé pour ces concepts) :"
        )
        for s in skipped:
            print(f"     - {s}")
    return routing


def _expanded_per_concept_from_state(extracted: dict) -> dict[str, list[str]]:
    """Inverse term_origins ({term: [parents]}) en {concept: [terms]}."""
    term_origins = extracted.get("term_origins", {}) or {}
    out: dict[str, list[str]] = {}
    for term, parents in term_origins.items():
        for p in parents:
            out.setdefault(p, []).append(term)
    return out


def _routing_keeps_match(match_type: Optional[str], score: Optional[float]) -> bool:
    """``True`` si un match doit être CONSERVÉ malgré un routing qui l'écarterait
    (dimension hors ``allowed_dims``).

    Le routing (Phase 1.2.6) est une optimisation anti-bruit, PAS une garantie de
    correction : un match EXACT à haut score (≥ 0.9) est une évidence trop forte
    pour être jetée par le routing seul (sinon risque 0 candidat → crash). Extrait
    de ``phase_1_3_1_4_search`` en helper pur testable (review snapshot 20b8902,
    finding 4 : la logique était inline et sans test → un renommage de
    ``match_type``/``score`` l'aurait neutralisée silencieusement)."""
    return match_type == "exact" and (score or 0) >= 0.9


async def phase_1_3_1_4_search(
    extracted: dict,
    filtered: dict,
    curated: dict,
    *,
    db_path: Path,
    debug_traces: bool = False,
) -> dict:
    """Phase 1.3+1.4 — Search BDD + groupage par concept (programmatique).

    Inputs :
        extracted  : output Phase 1.1+1.2 (full_listo, term_origins, groupes…)
        filtered   : output Phase 1.2.5 (drop_tables, drop_views)
        curated    : output Phase 1.2.6 (per_concept routing)
        db_path    : BDD source (sage_copy.db, non utilisé directement —
                     le search passe par TrainingStore qui lit komptia.db)

    Output (dict) :
        - search_text    : str — full output (équivalent search_results_test.txt)
                           consommé par Phase 1.5 ET Phase 3 (parse FvEx).
                           ⚠️ Le format DOIT rester compatible avec les
                           parsers downstream.
        - n_total_matches      : int
        - n_filtered_by_routing: int
    """
    user_query = extracted.get("trace_text", "")  # fallback for parse_user_query()
    # Mais on a la query directement passée via state.query — on l'utilise.
    # extracted.trace_text contient déjà la query mais on préfère la source.

    full_listo = extracted.get("full_listo", []) or []
    term_origins_raw = extracted.get("term_origins", {}) or {}
    # term_origins est sérialisé list ; on remet en set pour parents_match_concept
    term_origins: dict[str, set[str]] = {t: set(parents) for t, parents in term_origins_raw.items()}
    concept_values = extracted.get("groupes", {}) or {}
    derivables = extracted.get("derivables", {}) or {}
    termes_extract = extracted.get("termes", []) or []
    expanded_per_concept = _expanded_per_concept_from_state(extracted)

    if not full_listo:
        raise RuntimeError("Phase 1.3+1.4 — full_listo vide (Phase 1.1+1.2 KO ?)")

    # Phase 1.2.5 — entités droppées (union tables + vues)
    dropped: set[str] = set()
    if filtered.get("mode") == "filter":
        for n in (filtered.get("drop_tables") or []) + (filtered.get("drop_views") or []):
            if isinstance(n, str):
                dropped.add(n)

    # Phase 1.2.6 — routage par concept
    curate_routing = _curate_routing_from_state(curated)

    out: list[str] = []
    out.append("=" * 100)
    out.append("PHASE 1.3 + 1.4 — SEARCH + GROUPAGE")
    out.append("=" * 100)
    out.append("")
    # On RÉ-ÉMET la query au format historique attendu par parse_user_query
    # (Phase 3 generate_sql peut la re-parser si besoin pour FvEx).
    user_query_full = ""  # placeholder — on récupère depuis extracted.trace_text
    # Extract query from extracted.trace_text if available, else use empty
    # (the orchestrator passes it explicitly via run_pipeline state.query)
    # NOTE: la query est aussi dans state.query mais pas passée ici — on
    # parse depuis extracted.trace_text par robustesse.
    import re as _re

    m = _re.search(
        r"\*\*Requête utilisateur :\*\*\s*\n(.+?)\n", extracted.get("trace_text", "") or ""
    )
    if m:
        user_query_full = m.group(1).strip()
    # Fallback : reconstruction depuis groupes (concepts) si trace_text vide
    if not user_query_full:
        user_query_full = "(query inconnue — extracted.trace_text absent)"

    out.append("**Requête utilisateur :**")
    out.append(user_query_full)
    out.append("")
    if concept_values:
        out.append(f"STRUCTURE CONCEPT → VALEURS ({len(concept_values)} concepts) :")
        for c, vs in sorted(concept_values.items()):
            if vs:
                out.append(f"  {c} -> {', '.join(vs)}")
            else:
                out.append(f"  {c}")
        out.append("")
    if derivables:
        out.append(f"STRUCTURE CONCEPT DÉRIVABLES ({len(derivables)} concepts) :")
        out.append(
            "  (concepts calculables par formule SQL depuis d'autres concepts — "
            "PAS de recherche de table dédiée pour ceux-là)"
        )
        for c, srcs in sorted(derivables.items()):
            out.append(f"  {c} <- {', '.join(srcs)}")
        out.append("")

    # === PHASE 1.3 — BUILD INDEX + SEARCH ===
    from app.core.database import init_database

    await init_database()

    from app.services.ai.orchestrator_search import (
        build_search_indexes,
        search_all_terms,
    )
    from app.services.ai.training_store import TrainingStore

    t_idx_start = time.time()
    print("→ Phase 1.3: BUILD INDEX (tables/vues/colonnes en RAM)...", flush=True)
    store = TrainingStore()
    indexes = await build_search_indexes(store, excluded_entities=dropped)
    t_idx_end = time.time()
    print(
        f"  Index: {len(indexes.tables)} tables, {len(indexes.views)} vues, "
        f"{len(indexes.columns)} colonnes [{t_idx_end - t_idx_start:.1f}s]",
        flush=True,
    )

    out.append("=" * 100)
    out.append(
        f"PHASE 1.3 — BUILD INDEX ({t_idx_end - t_idx_start:.1f}s) — "
        f"{len(indexes.tables)} tables, {len(indexes.views)} vues, "
        f"{len(indexes.columns)} colonnes (valeurs: SQLite direct)"
        + (f" — {len(dropped)} entités exclues (Phase 1.2.5)" if dropped else "")
    )
    out.append("=" * 100)

    print(f"→ Phase 1.3: SEARCH {len(full_listo)} termes...", flush=True)
    results_cache = await search_all_terms(full_listo, indexes, excluded_entities=dropped)
    t_search_end = time.time()
    total_matches = sum(len(r.matches) for r in results_cache.values())
    print(f"  Recherche terminée [{t_search_end - t_idx_end:.1f}s]", flush=True)
    out.append(
        f"\nSEARCH ({t_search_end - t_idx_end:.1f}s) — "
        f"{len(results_cache)} termes → {total_matches} résultats"
    )

    cache_unacc_index = build_unacc_index(results_cache.keys())

    def _matched_cache_keys(search_key: str) -> list[str]:
        return lookup_cache_keys(search_key, cache_unacc_index)

    # Summary par terme original
    for orig_term in termes_extract:
        related = {orig_term.lower().strip()}
        for term, parents in term_origins.items():
            if parents_match_concept(parents, orig_term):
                related.add(term.lower().strip())
        mc = 0
        seen_ck: set[str] = set()
        for k in related:
            for ck in _matched_cache_keys(k):
                if ck in seen_ck:
                    continue
                seen_ck.add(ck)
                mc += len(results_cache[ck].matches)
        out.append(f"  {orig_term}: {mc} résultats")
    out.append("")

    # === PHASE 1.4 — RÉSULTATS GROUPÉS PAR CONCEPT ===
    print("→ Phase 1.4: Groupage par concept (avec routage 1.2.6)...", flush=True)
    out.append("=" * 100)
    out.append("PHASE 1.4 — RÉSULTATS GROUPÉS PAR CONCEPT")
    out.append("=" * 100)
    out.append("")

    derivables_set = set(derivables.keys())
    n_filtered_by_routing = 0

    for concept, values in sorted(concept_values.items()):
        out.append("=" * 80)
        if values:
            out.append(f"CONCEPT: {concept} -> {', '.join(values)}")
        else:
            out.append(f"CONCEPT: {concept}")
        out.append("=" * 80)

        if concept in derivables_set:
            sources = derivables.get(concept, [])
            out.append(
                f"  [DÉRIVABLE depuis : {', '.join(sources)}] "
                f"— pas de recherche en BDD, formule appliquée Phase 3"
            )
            out.append("")
            continue

        allowed_dims = curate_routing.get(concept)

        search_keys: set[str] = {concept.lower().strip()}
        for word in concept.split():
            if len(word) > 2:
                search_keys.add(word.lower().strip())
        for val in values:
            search_keys.add(val.lower().strip())
            for part in val.split():
                if len(part) > 2:
                    search_keys.add(part.lower().strip())
        for term, parents in term_origins.items():
            if parents_match_concept(parents, concept):
                search_keys.add(term.lower().strip())
        for t in expanded_per_concept.get(concept, []):
            search_keys.add(t.lower().strip())

        all_matches = []
        for key in search_keys:
            for ck in _matched_cache_keys(key):
                cache_entry = results_cache.get(ck)
                if not cache_entry or not cache_entry.matches:
                    continue
                for m_item in cache_entry.matches:
                    if allowed_dims is not None and m_item.dimension not in allowed_dims:
                        # P1 #8 — GARDE : un match EXACT haut-score (≥0.9) ne
                        # doit JAMAIS être écarté par le routing seul. Le
                        # routing 1.2.6 est une optimisation anti-bruit, pas une
                        # garantie de correction : si une valeur user matche
                        # EXACTEMENT une colonne hors des dimensions routées,
                        # l'évidence est trop forte pour la jeter (sinon risque
                        # 0 candidat → crash). Worst case = un peu de bruit que
                        # le scoring/rerank aval pondère.
                        if not _routing_keeps_match(
                            getattr(m_item, "match_type", None),
                            getattr(m_item, "score", 0),
                        ):
                            n_filtered_by_routing += 1
                            continue
                    all_matches.append((ck, m_item))

        seen: set[tuple] = set()
        deduped = []
        for searched, m_item in all_matches:
            key = (
                m_item.dimension,
                m_item.table_name,
                m_item.column_name,
                m_item.real_value,
                searched,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append((searched, m_item))

        by_dim: dict[str, list] = {}
        for searched, m_item in deduped:
            by_dim.setdefault(m_item.dimension, []).append((searched, m_item))

        out.append(f"  {len(deduped)} résultats (dédupliqués)")
        out.append(f"  Termes recherchés: {sorted(search_keys)}")
        if allowed_dims is not None:
            out.append(f"  Routage 1.2.6 — dimensions autorisées : {sorted(allowed_dims)}")
        out.append("")

        for dim in ("table", "view", "column", "view_column", "value"):
            if dim not in by_dim:
                continue
            items = by_dim[dim]
            items.sort(
                key=lambda x: (
                    -{"exact": 3, "contains": 2, "fuzzy": 1}.get(x[1].match_type, 0),
                    -x[1].score,
                )
            )
            out.append(f"  [{dim.upper()}] ({len(items)} résultats)")
            for searched, m_item in items:
                stats = []
                if m_item.row_count:
                    stats.append(f"rows={m_item.row_count:,}")
                if m_item.distinct_count:
                    stats.append(f"distinct={m_item.distinct_count:,}")
                if m_item.null_pct > 0:
                    stats.append(f"null={m_item.null_pct:.0f}%")
                if m_item.estimated_occurrence:
                    stats.append(f"occur={m_item.estimated_occurrence:,}")
                if m_item.real_value:
                    stats.append(f"val='{m_item.real_value}'")
                via = (
                    f" (via '{searched}')"
                    if strip_accents(searched) != strip_accents(concept.lower().strip())
                    else ""
                )
                col_info = f".{m_item.column_name}" if m_item.column_name else ""
                out.append(
                    f"    {m_item.match_type:<10} {m_item.score:>5.0%}  "
                    f"{m_item.table_name}{col_info}{via}  [{' | '.join(stats)}]"
                )
        out.append("")

    t_group_end = time.time()
    print(f"  Groupage terminé [{t_group_end - t_search_end:.1f}s]", flush=True)
    if n_filtered_by_routing:
        print(f"  Filtre 1.2.6 routing : {n_filtered_by_routing:,} matches écartés", flush=True)

    out.append("=" * 100)
    out.append("STATISTIQUES")
    out.append("=" * 100)
    out.append(f"\n  Termes (full listo)        : {len(full_listo)}")
    out.append(f"  Concepts traités           : {len(concept_values) - len(derivables_set)}")
    out.append(f"  Concepts dérivables        : {len(derivables_set)} (skip)")
    out.append(
        f"  Index                      : {len(indexes.tables)} tables, "
        f"{len(indexes.views)} vues, {len(indexes.columns)} colonnes"
    )
    out.append(f"  Résultats bruts            : {total_matches:,}")
    out.append(f"  Filtre 1.2.6 routing       : {n_filtered_by_routing:,} matches écartés")
    out.append("")
    out.append("--- TIMING ---")
    out.append(f"  Phase 1.3 BUILD INDEX  : {t_idx_end - t_idx_start:>7.1f}s")
    out.append(f"  Phase 1.3 SEARCH       : {t_search_end - t_idx_end:>7.1f}s")
    out.append(f"  Phase 1.4 GROUPAGE     : {t_group_end - t_search_end:>7.1f}s")
    out.append(f"  TOTAL                  : {t_group_end - t_idx_start:>7.1f}s")

    search_text = "\n".join(out)

    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_1_3_1_4_search.txt").write_text(
            search_text,
            encoding="utf-8",
        )

    return {
        "search_text": search_text,
        "n_total_matches": total_matches,
        "n_filtered_by_routing": n_filtered_by_routing,
        "n_concepts": len(concept_values),
        "n_derivables": len(derivables_set),
    }


# ─────────────────────────────────────────────────────────────────────
# PHASE 1.5 — Scoring + FK subgraph (✅ converti via temp-files hybride)
# ─────────────────────────────────────────────────────────────────────


def phase_1_5_scoring_fk(
    search: dict,
    filtered: dict,
    curated: dict,
    *,
    db_path: Path,
    block_view_mined_fk: bool = False,
    block_inferred_fk: bool = False,
    debug_traces: bool = False,
) -> dict:
    """Phase 1.5 — Scoring d'inclusion d'entités + sous-graphe FK.

    Stratégie d'intégration : `test_pipeline_v2.py` (2156 lignes, 40 fonctions)
    n'est PAS réécrit dans pipeline.py — coût/risque trop élevé pour un seul
    refactor. À la place, on patche temporairement ses globals (chemins de
    fichiers) pour pointer vers un répertoire temporaire, on écrit les inputs
    Phase 1.3+1.4/1.2.5/1.2.6 dans ce répertoire, on appelle `v2.main()` dans
    le même process Python (PAS de subprocess — donc pas de timeout), puis on
    lit les outputs en mémoire et on nettoie.

    Les outputs disque finaux (search_results_test_v2*.txt) ne sont JAMAIS
    écrits dans `outputs/` — seulement dans le tmpdir, qui est supprimé
    automatiquement à la sortie du `with`.

    Inputs :
        search    : output Phase 1.3+1.4 (search_text)
        filtered  : output Phase 1.2.5 (drop_tables, drop_views)
        curated   : output Phase 1.2.6 (per_concept routing)

    Output (dict) :
        - v2_text       : str — contenu de search_results_test_v2.txt
        - v2_annex_text : str — contenu de search_results_test_v2_annex.txt
    """
    import tempfile
    from pathlib import Path as _P

    search_text = search.get("search_text", "")
    if not search_text:
        raise RuntimeError("Phase 1.5 — search.search_text vide (Phase 1.3+1.4 KO ?)")

    with tempfile.TemporaryDirectory(prefix="pipeline_phase15_") as td:
        td_path = _P(td)

        # Écriture des inputs au format que test_pipeline_v2 attend.
        src = td_path / "search_results_test.txt"
        src.write_text(search_text, encoding="utf-8")

        filter_dir = td_path / "llm_filter"
        filter_dir.mkdir(parents=True, exist_ok=True)
        # Réécrit dropped_entities.json depuis state.filtered.
        dropped_payload = {
            "mode": filtered.get("mode", "filter"),
            "drop_tables": filtered.get("drop_tables", []),
            "drop_views": filtered.get("drop_views", []),
            "hallucinated": filtered.get("hallucinated", []),
        }
        (filter_dir / "dropped_entities.json").write_text(
            json.dumps(dropped_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        curate_dir = td_path / "llm_curate"
        curate_dir.mkdir(parents=True, exist_ok=True)
        for concept, payload in (curated.get("per_concept", {}) or {}).items():
            # Format attendu par v2.load_curate_routing : un JSON par concept
            slug = slug_from_concept(concept)
            (curate_dir / f"{slug}.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

        dst_main = td_path / "search_results_test_v2.txt"
        dst_annex = td_path / "search_results_test_v2_annex.txt"

        # Patch les globals INLINÉS de pipeline.py pour rediriger les IO
        # vers le tmpdir. Plus d'import scripts.test_pipeline_v2 — le code
        # de v2 a été inliné dans ce fichier (cf. section "PHASE 1.5 —
        # INLINED helpers" plus bas). _p15_main_legacy() est l'ancien
        # v2.main() avec juste ses defs renamed pour éviter collisions.
        global SRC, DB, DST_MAIN, DST_ANNEX, _DROPPED_ENTITIES_FILE, _CURATE_DIR
        old_SRC, old_DB = SRC, DB
        old_DST_MAIN, old_DST_ANNEX = DST_MAIN, DST_ANNEX
        old_DROPPED, old_CURATE = _DROPPED_ENTITIES_FILE, _CURATE_DIR
        SRC = src
        DB = db_path
        DST_MAIN = dst_main
        DST_ANNEX = dst_annex
        _DROPPED_ENTITIES_FILE = filter_dir / "dropped_entities.json"
        _CURATE_DIR = curate_dir

        # Patch sys.argv pour les flags de skip ciblé.
        old_argv = sys.argv
        argv_flags: list[str] = ["pipeline.py"]
        if block_view_mined_fk:
            argv_flags.append("--block-view-mined-fk")
        if block_inferred_fk:
            argv_flags.append("--block-inferred-fk")
        sys.argv = argv_flags

        # Note (review adversariale fix #2) : le try/finally couvre les
        # exceptions Python normales (RuntimeError, KeyboardInterrupt,
        # asyncio.CancelledError). En cas de SIGKILL/OOM, le finally ne
        # s'exécute pas — globals corrompus pour le run suivant. Mitigation
        # complète = refactor `_p15_main_legacy` pour accepter ses paths
        # en paramètres (TODO Lot ultérieur). En attendant, le runner
        # restart auto au boot serveur reset les globals à leur valeur
        # module-level d'origine.
        try:
            ret = _p15_main_legacy()
            if ret not in (None, 0):
                raise RuntimeError(f"Phase 1.5 — _p15_main_legacy() returned {ret}")
        finally:
            # Restore les globals.
            SRC, DB = old_SRC, old_DB
            DST_MAIN, DST_ANNEX = old_DST_MAIN, old_DST_ANNEX
            _DROPPED_ENTITIES_FILE, _CURATE_DIR = old_DROPPED, old_CURATE
            sys.argv = old_argv

        v2_text = dst_main.read_text(encoding="utf-8")
        v2_annex_text = dst_annex.read_text(encoding="utf-8")

    # F3 (2026-05-21, adversarial fix complétude) — Audit FK composition.
    # `_p15_main_legacy` print() déjà ces counts sur stdout, mais (a) stdout
    # n'est pas systématiquement capturé par le runtime, (b) on veut les counts
    # dans `state.scored` pour persistance run.json + analyse post-mortem.
    # On capture les 4 SOURCES du FK graph utilisé par BFS Phase 1.5 :
    # explicit (PRAGMA) + implicit (naming convention) + view_mined
    # (training_data.join_pattern) + inferred (table inferred_foreign_keys).
    # Coût : ~30-50ms cumulé (négligeable face aux 30-60s de Phase 1.5).
    # Les helpers sont fail-safe sur DB/table absente.
    fk_audit: dict[str, int | float | bool] = {
        "fk_explicit_count": 0,
        "fk_implicit_count": 0,
        "fk_view_mined_count": 0,
        "fk_inferred_count": 0,
        "inferred_threshold": _INFERRED_FK_MIN_CONFIDENCE,
        "block_view_mined_fk": bool(block_view_mined_fk),
        "block_inferred_fk": bool(block_inferred_fk),
    }
    try:
        fk_audit["fk_explicit_count"] = len(extract_fk_explicit(db_path))
    except Exception:
        # Pas bloquant — l'audit est nice-to-have, pas garantie fonctionnelle.
        pass
    try:
        fk_audit["fk_implicit_count"] = len(extract_fk_implicit(db_path))
    except Exception:
        pass
    if not block_view_mined_fk:
        try:
            fk_audit["fk_view_mined_count"] = len(
                extract_join_patterns_from_komptia(KOMPTIA_DB)
            )
        except Exception:
            pass
    if not block_inferred_fk:
        try:
            fk_audit["fk_inferred_count"] = len(extract_fk_inferred_persistent(KOMPTIA_DB))
        except Exception:
            pass

    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_1_5_scoring_v2.txt").write_text(v2_text, encoding="utf-8")
        (DEBUG_TRACES_DIR / "phase_1_5_scoring_v2_annex.txt").write_text(
            v2_annex_text,
            encoding="utf-8",
        )
        (DEBUG_TRACES_DIR / "phase_1_5_fk_audit.json").write_text(
            json.dumps(fk_audit, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return {
        "v2_text": v2_text,
        "v2_annex_text": v2_annex_text,
        "fk_audit": fk_audit,
    }


# ─────────────────────────────────────────────────────────────────────
# PHASE 2 — Rerank LLM par concept (✅ converti)
# ─────────────────────────────────────────────────────────────────────


_RERANK_SYSTEM_PROMPT = """\
Tu es un agent expert en bases de données SQL Server qui aide un autre agent
IA générateur de SQL à converger vers la BONNE requête finale pour une demande
utilisateur exprimée en langage naturel.

# Contexte du système

Comme tu le sais le SQL est un langage de programmation et on peut faire
énormément de choses avec, ça ne s'arrête pas à `SELECT * FROM TABLE WHERE…`
on peut extraire un nombre infini de choses d'une même base de données.

L'objectif avec cet agent IA SQL c'est le langage naturel-to-SQL, sauf que
c'est un langage naturel d'**utilisateur qui ne connaît rien aux bases de
données, rien au SQL**. Ses demandes ouvriront un large choix de requêtes SQL
possibles. Comment l'agent IA SQL converge-t-il vers le bon résultat ?

# Ton rôle dans cette chaîne

Pour aider l'agent IA SQL à converger, on a déjà :
1. Décomposé la demande NL en **concepts** sémantiques
2. Pour chaque concept, identifié les **valeurs explicites** mentionnées
3. Recherché dans la base toutes les tables, vues, colonnes et valeurs qui
   matchent le concept (FvEx/FvCo/FvFz/ColEx/TblEx/etc.)
4. Compté les matches dans 9 catégories et **pré-classé** les candidats avec
   un scoring algorithmique pondéré
5. Toi, tu interviens **maintenant** : on te donne UN concept précis et la
   liste de ses entités candidates **DÉJÀ ORDONNÉES par notre scoring algo**.
   Ton travail est de **RECLASSER** cette liste avec ton raisonnement
   sémantique — promouvoir, rétrograder, bousculer l'ordre quand justifié.

# Question fondamentale

> **Quelles entités sont les plus probables de CONTENIR ce concept ?**

"Contenir le concept" = être la source primaire de la donnée. Pas une copie,
pas un log, pas une table de reporting qui agrège, pas un artefact d'impression
— la source.

# Comment lire les buckets

- **FvEx (FvCo, FvFz)** = valeurs EXPLICITES du concept trouvées dans cette
  colonne. Indice TRÈS FORT.
- **ColEx (ColCo, ColFz / VColEx, etc.)** = nom de colonne contient le concept.
  Indice fort.
- **TblEx (TblCo, TblFz / VueEx, etc.)** = nom de table/vue contient le concept.

# Comment combiner

Une entité **canonique** a typiquement plusieurs FvEx purs ET/OU un ColEx ou
TblEx, avec un signal **concentré**. Une entité avec **uniquement** beaucoup
de FvCo (libellés) est probablement une table de log/référence — rétrograder.

# Rôle sémantique du concept (CRITIQUE pour le choix de colonne)

Chaque concept a un **rôle sémantique** qui contraint le **type de
question** à se poser sur la colonne candidate. Le bon choix dépend de
ce que la colonne **représente sémantiquement**, pas de son type SQL.

## Test à appliquer pour chaque rôle

### `measure` — quantité agrégeable

Question : *« SUM/AVG/MIN/MAX appliqué à cette colonne a-t-il un sens
métier dans le contexte de cette requête ? »*

- **Oui** si la colonne représente une **valeur métier qui s'additionne ou
  se moyenne logiquement** : montant, quantité, prix, durée, score, taux.
- **Non** si la colonne est :
  - une **clé technique** (identifiant primaire/étranger, numéro
    d'enregistrement) — agréger un ID n'a aucun sens
  - une **valeur catégorielle** (code, statut, libellé) — la somme d'un
    code n'a aucun sens
  - une **valeur temporelle** sauf si la mesure est explicitement une
    durée/délai (ex: « durée moyenne entre commande et livraison »)
- **Vérifier les samples** : la colonne doit montrer des valeurs avec
  une **distribution numérique réaliste** pour ce qui est demandé. Si
  les samples sont des dates ou des codes courts, ce n'est pas une
  mesure pour ce concept.

### `dimension` — axe de regroupement (GROUP BY)

Question : *« Si je GROUP BY cette colonne, obtiens-je des groupes
significatifs ? »*

- **Oui** : codes, identifiants métier, libellés, catégories.
- **Non** : colonnes à cardinalité = 1 (constante) ou ~= nb de lignes
  (= clé technique unique → 1 ligne par groupe = inutile).

### `temporal` — point ou intervalle dans le temps

Question : *« Cette colonne situe-t-elle un événement dans le temps ? »*

- Type SQL **date/datetime/timestamp** : oui directement.
- Type **texte/numérique** : oui si elle représente une période ou un point
  temporel (code période métier, libellé de mois, année sous forme de string
  ou d'int, etc.). Vérifier sur les samples qu'on a bien un format temporel.
- **Non** si c'est un montant, un identifiant ou une valeur sans
  composante temporelle.

### `filter` — critère avec valeurs explicites

Question : *« Les `values` mentionnées par l'utilisateur sont-elles
présentes dans les samples de cette colonne ? »*

- **Oui** = FvEx fort → choisir cette colonne.
- **Non** = chercher une autre colonne où les valeurs sont effectivement
  présentes.

### `derivation` — concept calculé par formule

Question : *« Une colonne expose-t-elle DÉJÀ le résultat de la formule ? »*

- **Oui** (rare) : pointer cette colonne en `key_columns[0]`. La
  sémantique du résultat doit matcher (un écart de montants → colonne
  numérique de différence).
- **Non** : retourner `key_columns: []`. Le concept sera composé
  en aval depuis ses opérandes.

### `exclusion` — restriction (« hors X »)

Question : *« Quelle colonne identifie X ? »* — pour permettre un
`NOT EXISTS` / `<> X` downstream. Choisir l'identifiant métier de X.

## Méta-anti-pattern (universel à toutes les BDDs)

Le scoring algorithmique pré-classé peut mettre en haut une colonne
parce qu'elle a beaucoup de matches **structurels** (FvCo dense, ColEx)
sans vérifier si elle a la **sémantique d'agrégation** attendue par le
rôle. Ton job est de **désambiguïser sur la sémantique métier**, pas
de promouvoir aveuglément les colonnes les mieux scorées.

Generic : ce raisonnement s'applique à n'importe quelle BDD. Aucun nom
de table/colonne explicite ici — uniquement des questions à te poser
sur la **fonction métier** de la colonne candidate au regard du rôle
du concept.

# Garde-fous critiques

1. **Ne JAMAIS inventer une entité** absente du détail.
2. **Ne JAMAIS inventer un nom de colonne**. Les `key_columns` doivent être
   présentes littéralement dans la section concept.
3. **Citer le bucket dominant** dans la rationale (FvEx, ColEx, etc.).
4. **Justifier la position #1 explicitement**.
5. **Respecter le rôle sémantique** : ta `key_columns[0]` (top-1 colonne)
   doit matcher le type attendu par le `role` du concept (cf. section
   ci-dessus). Si aucune colonne du bon type n'existe dans cette entité,
   rétrograder l'entité ou laisser `key_columns` vide.

# Format de sortie ATTENDU (JSON strict)

```json
{
  "concept": "<nom du concept>",
  "ranking_top": [
    {
      "rank": 1,
      "entity": "<nom exact>",
      "kind": "T" ou "V",
      "rationale": "1-2 phrases courtes en français.",
      "key_columns": ["col1", "col2"]
    }
  ],
  "rejected_or_low": [
    {"entity": "<nom>", "reason": "1 phrase"}
  ],
  "notes": "Note optionnelle (≤ 3 phrases)"
}
```

Règles JSON :
- `ranking_top` : 5 à 15 entités max
- `rejected_or_low` : 3 à 8 entités notables faux positifs
- Réponds UNIQUEMENT le JSON, pas de markdown autour
"""


_RERANK_USER_PROMPT_TEMPLATE = """\
# Demande utilisateur (langage naturel)

{user_query}

{session_qa_block}# Concept à reclasser

**{concept}**{values_clause}{semantic_clause}

# Détail par concept (DÉJÀ pré-classés à reclasser)

⚠️ Cette liste est **déjà ordonnée par notre scoring algorithmique** (top en
haut). C'est ton **point de départ**, pas ta réponse finale. **Tu dois le
RECLASSER** — promouvoir, rétrograder, bousculer si justifié.

Chaque entité (table `[T]` ou vue `[V]`) est annotée avec sa proba globale,
ses buckets de matches, et pour les vues `↪{{T1,T2,…}}` = tables sources.

Légende : `=` exact · `⊂` contains · `~` fuzzy

```
{concept_block}
```

# Ta tâche

**Reclasse** la liste selon : "Quelles entités sont les plus probables de
CONTENIR ce concept ?", en intégrant le contexte de la requête utilisateur
globale (rappel : "{user_query_short}…").

Réponds UNIQUEMENT en JSON valide selon le format spécifié dans le system.
"""


def _parse_rerank_concept_blocks(text: str) -> dict[str, str]:
    """{concept_name: section_text} parsé depuis le v2_text.

    Un bloc commence à `^CONCEPT: <name>` et finit au prochain ou à EOF.
    """
    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    for i, ln in enumerate(lines):
        if ln.startswith("CONCEPT: "):
            starts.append((i, ln[len("CONCEPT: ") :].strip()))
    blocks: dict[str, str] = {}
    for idx, (i, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        while end > i + 1 and not lines[end - 1].strip():
            end -= 1
        sec_start = i
        if sec_start - 1 >= 0 and lines[sec_start - 1].startswith("="):
            sec_start -= 1
        # Strip "concept -> values" suffix to get clean name
        clean_name = name.split(" -> ", 1)[0].strip()
        if clean_name in blocks:
            # Flag plutôt que silent overwrite (cf. consequences.md
            # "résultats faux qui passent inaperçus") : si Phase 1.5
            # émet "CONCEPT: X" et "CONCEPT: X -> a, b" pour le même X,
            # un seul bloc gagne. Improbable vu le format actuel, mais
            # warner explicitement.
            print(
                f"⚠ Phase 2 — bloc CONCEPT dupliqué pour {clean_name!r}, "
                f"on garde le dernier (concaténation des sections perdue)."
            )
        blocks[clean_name] = "\n".join(lines[sec_start:end])
    return blocks


def _parse_rerank_concept_values(block: str) -> list[str]:
    """`val1, val2` from `CONCEPT: code groupe -> AUDIT, MENS, DOSSIER_A`."""
    m = re.search(r"^CONCEPT:\s*[^\n]+?\s*->\s*([^\n]+)$", block, re.MULTILINE)
    if not m:
        return []
    return [v.strip() for v in m.group(1).split(",") if v.strip()]


async def phase_2_rerank(
    query: str,
    scored: dict,
    *,
    model_id: str,
    api_key: str,
    concept_filter: str | None = None,
    debug_traces: bool = False,
    extracted: dict | None = None,
) -> dict:
    """Phase 2 — Rerank LLM par concept.

    Pour chaque concept, fait UN appel LLM avec le détail du concept (entités
    candidates pré-classées par scoring algo Phase 1.5) + la requête NL globale,
    et reclasse selon raisonnement sémantique.

    Inputs :
        query           : requête NL
        scored          : output Phase 1.5 (v2_text contient les blocs CONCEPT:)
        concept_filter  : substring match — restreint à un seul concept (debug)
        extracted       : optionnel, output Phase 1.1+1.2. Si fourni, le
                          ``role`` et ``value_kind`` de chaque concept_v2 est
                          injecté dans le user prompt → le LLM choisit
                          la bonne colonne par type sémantique (ex: measure
                          → colonne montant, pas date). Sans ``extracted``,
                          comportement legacy (LLM peut choisir proDate
                          pour une mesure).

    Output (dict) :
        - per_concept : dict[concept, dict] — payload par concept (ranking_top,
                        rejected_or_low, notes)
        - raw_responses : dict[concept, str] — bruts LLM (debug)
    """

    v2_text = scored.get("v2_text", "")
    if not v2_text:
        raise RuntimeError("Phase 2 — scored.v2_text vide (Phase 1.5 KO ?)")

    blocks = _parse_rerank_concept_blocks(v2_text)
    if not blocks:
        raise RuntimeError("Phase 2 — aucun bloc CONCEPT: trouvé dans v2_text")

    if concept_filter:
        match = [c for c in blocks if concept_filter.lower() in c.lower()]
        if not match:
            raise RuntimeError(
                f"Phase 2 — concept '{concept_filter}' introuvable. "
                f"Disponibles : {list(blocks)}"
            )
        concepts_to_run = match
    else:
        concepts_to_run = list(blocks)

    print(f"→ Phase 2 : {len(concepts_to_run)} concept(s) à reranker")

    # Map concept_name → concept_v2 dict pour exposer role/value_kind dans
    # le user prompt (W2.2 fix : éviter que le LLM choisisse une colonne
    # date pour un concept mesure).
    concepts_v2_by_name: dict[str, dict] = {}
    if isinstance(extracted, dict):
        for c2 in extracted.get("concepts_v2") or []:
            if isinstance(c2, dict) and c2.get("name"):
                concepts_v2_by_name[c2["name"]] = c2

    per_concept: dict[str, dict] = {}
    raw_per_concept: dict[str, str] = {}
    prompts_per_concept: dict[str, str] = {}

    # Parallélisation : les concepts sont indépendants (chaque concept est
    # rerank par 1 appel LLM autonome — pas de Q/A, pas de dépendance entre
    # concepts). On lance N appels en parallèle via asyncio.gather. Gain
    # massif quand le pipeline a 8-15 concepts (ex 6 min séquentiel → 30s).
    async def _process_concept(c: str) -> tuple[str, str | None, dict | None, str]:
        """Traite UN concept. Retourne (concept, raw_response, parsed_data, user_prompt).

        raw_response = None si erreur LLM, parsed_data = None si parse KO.
        user_prompt toujours retourné (utile pour debug même si LLM fail).
        """
        block = blocks[c]
        values = _parse_rerank_concept_values(block)
        values_clause = (
            f" — valeurs explicites mentionnées par l'utilisateur : {', '.join(values)}"
            if values
            else " — pas de valeurs explicites mentionnées"
        )
        # W2.2 fix : injecter role/value_kind du concept_v2 pour que le LLM
        # respecte le contrat type-sémantique (cf. system prompt section
        # « Type sémantique du concept »). Generic : aucun nom de table/
        # colonne. Si concept_v2 absent (mode dégradé), pas de clause.
        cv2 = concepts_v2_by_name.get(c) or {}
        role = cv2.get("role")
        value_kind = cv2.get("value_kind")
        semantic_parts = []
        if role:
            semantic_parts.append(f"`role={role}`")
        if value_kind:
            semantic_parts.append(f"`value_kind={value_kind}`")
        semantic_clause = (
            (
                "\n- Attributs sémantiques : "
                + ", ".join(semantic_parts)
                + " (cf. section « Type sémantique du concept » du system "
                "prompt — la `key_columns[0]` choisie DOIT matcher ce rôle)"
            )
            if semantic_parts
            else ""
        )
        # Task #72 — qa_block étanche cross-phase : injecter les Q/A déjà
        # collectées en Phase 1.2.5 / 1.2.6 pour ne pas re-trancher des
        # ambiguïtés déjà résolues par l'utilisateur.
        from app.services.ai import user_qa_session as qa_session

        qa_block = qa_session.format_for_prompt()
        qa_block_inline = (qa_block + "\n\n") if qa_block else ""
        user_prompt = _RERANK_USER_PROMPT_TEMPLATE.format(
            user_query=query,
            concept=c,
            values_clause=values_clause,
            semantic_clause=semantic_clause,
            concept_block=block,
            user_query_short=query[:200],
            session_qa_block=qa_block_inline,
        )
        slug = slug_from_concept(c)
        try:
            raw = await call_llm(
                _RERANK_SYSTEM_PROMPT,
                user_prompt,
                model_id=model_id,
                api_key=api_key,
                caller="pipeline_p2_rerank",
                max_tokens=4000,
            )
        except Exception as e:
            print(f"  ❌ {c} ({slug}) — erreur LLM : {e}", flush=True)
            return c, None, None, user_prompt
        data = parse_llm_json(raw)
        if data is None:
            print(f"  ⚠️ {c} ({slug}) — JSON parse échoué", flush=True)
            return c, raw, None, user_prompt
        return c, raw, data, user_prompt

    print(f"→ Lancement de {len(concepts_to_run)} reranks en parallèle...", flush=True)
    results = await asyncio.gather(
        *[_process_concept(c) for c in concepts_to_run],
        return_exceptions=False,  # erreurs déjà capturées dans _process_concept
    )

    for c, raw, data, user_prompt in results:
        prompts_per_concept[c] = user_prompt
        if raw is not None:
            raw_per_concept[c] = raw
        if data is not None:
            per_concept[c] = data
            top = data.get("ranking_top", [])
            print(f"  ✓ {c} — {len(top)} entités classées au top", flush=True)
            for entry in top[:3]:  # top 3 (vs 5 avant) pour limiter le bruit en parallèle
                print(
                    f"    #{entry.get('rank')} [{entry.get('kind')}] "
                    f"{entry.get('entity')} — {entry.get('rationale', '')[:80]}",
                    flush=True,
                )

    if debug_traces and raw_per_concept:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        for c, raw in raw_per_concept.items():
            slug = slug_from_concept(c)
            (DEBUG_TRACES_DIR / f"phase_2_rerank_{slug}.raw.txt").write_text(
                raw,
                encoding="utf-8",
            )

    return {
        "per_concept": per_concept,
        "raw_responses": raw_per_concept,
        "system_prompt": _RERANK_SYSTEM_PROMPT,
        "prompts_per_concept": prompts_per_concept,
    }


# =============================================================================
# Helpers SQL — exécution + validation + transpile T-SQL→SQLite + introspection
# (rétablis depuis les sections INLINED Phase 3/4 supprimées par le refactor
#  concept fact sheets, 2026-05-06)
# =============================================================================

ROWS_CAP_PER_QUERY = 200
SQLITE_TIMEOUT_SEC = 30


def _ast_fix_string_concat(sql: str) -> str:
    """Remplace `+` par `||` (Concat) quand au moins un opérande est string.

    sqlglot 30.x ne reconnaît pas le `+` T-SQL comme concat même avec une
    string literal en opérande. On parse l'AST en SQLite, on cherche tous
    les `Add` dont un côté est `'literal'` ou `CAST(... AS VARCHAR/TEXT)` ou
    `Concat` ou `COALESCE(<string-yielding>, ...)`, et on les transforme en
    `Concat`. Robuste contre les imbrications profondes (boucle jusqu'à
    point fixe).

    Si le parse fail (SQL trop atypique), retourne le sql d'origine — best
    effort, l'exécution révélera le souci.
    """
    import sqlglot
    from sqlglot import expressions as exp

    try:
        tree = sqlglot.parse_one(sql, dialect="sqlite")
    except Exception:
        return sql

    def cast_target_is_text(cast_node) -> bool:
        try:
            to = cast_node.args.get("to")
            if to is None:
                return False
            name = (
                to.this.name if hasattr(to, "this") and hasattr(to.this, "name") else str(to)
            ).upper()
            return any(kw in name for kw in ("TEXT", "VARCHAR", "NVARCHAR", "CHAR"))
        except Exception:
            return False

    def is_stringlike(node) -> bool:
        if node is None:
            return False
        if isinstance(node, exp.Literal) and node.is_string:
            return True
        if isinstance(node, exp.Cast) and cast_target_is_text(node):
            return True
        if isinstance(node, (exp.Concat, exp.DPipe)):
            return True
        if isinstance(node, exp.Coalesce):
            args = node.args.get("expressions", []) or []
            this = node.args.get("this")
            children = ([this] if this is not None else []) + args
            return any(is_stringlike(c) for c in children)
        if isinstance(node, exp.Case):
            ifs = node.args.get("ifs", []) or []
            default = node.args.get("default")
            return any(is_stringlike(i.args.get("true")) for i in ifs) or is_stringlike(default)
        if isinstance(node, exp.Paren):
            return is_stringlike(node.this)
        return False

    for _ in range(20):
        target = None
        for add_node in tree.find_all(exp.Add):
            if is_stringlike(add_node.left) or is_stringlike(add_node.right):
                target = add_node
                break
        if target is None:
            break
        left_copy = target.left.copy()
        right_copy = target.right.copy()
        new = exp.DPipe(this=left_copy, expression=right_copy)
        target.replace(new)

    return tree.sql(dialect="sqlite", pretty=False)


def _post_process_sqlite_sql(sql: str) -> str:
    """Comble les trous de sqlglot pour T-SQL → SQLite (concat + date modifier signe)."""
    sql = _ast_fix_string_concat(sql)
    sql = re.sub(
        r"DATE\(([^,]+),\s*'([+\-]?)(\d+)\s+(DAY|MONTH|YEAR|HOUR|MINUTE|SECOND)S?\s*'\s*\)",
        lambda m: (
            f"DATE({m.group(1)}, '" f"{m.group(2) or '+'}{m.group(3)} {m.group(4).lower()}')"
        ),
        sql,
        flags=re.IGNORECASE,
    )
    return sql


def transpile_tsql_to_sqlite(sql: str) -> tuple[str, str | None]:
    """Transpile T-SQL → SQLite via sqlglot + post-processing.

    Returns (sqlite_sql, error_or_None). Si le transpile fail, retourne
    le SQL T-SQL d'origine + un message d'erreur (best effort).
    """
    import sqlglot

    try:
        out = sqlglot.transpile(sql, read="tsql", write="sqlite", pretty=False)
        if not out:
            return sql, "sqlglot returned empty"
        return _post_process_sqlite_sql(out[0]), None
    except Exception as e:
        return sql, f"{type(e).__name__}: {e}"


def _register_tsql_udfs(conn: sqlite3.Connection) -> None:
    """Enregistre YEAR / MONTH / DAY / GETDATE comme UDFs Python sur SQLite.

    SQLite n'a pas ces fonctions nativement. UDFs préservent la lisibilité
    du SQL T-SQL (pas de pre-process) et tolèrent NULL.
    """

    def _year(x):
        if x is None:
            return None
        s = str(x)
        return int(s[:4]) if len(s) >= 4 and s[:4].isdigit() else None

    def _month(x):
        if x is None:
            return None
        s = str(x)
        return int(s[5:7]) if len(s) >= 7 and s[5:7].isdigit() else None

    def _day(x):
        if x is None:
            return None
        s = str(x)
        return int(s[8:10]) if len(s) >= 10 and s[8:10].isdigit() else None

    def _getdate():
        import datetime

        return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    conn.create_function("YEAR", 1, _year, deterministic=True)
    conn.create_function("MONTH", 1, _month, deterministic=True)
    conn.create_function("DAY", 1, _day, deterministic=True)
    conn.create_function("GETDATE", 0, _getdate)


def get_sqlite_schema(db_path: Path) -> dict[str, set[str]]:
    """Map { lower_table_name -> {lower_column_name, ...} } depuis sqlite_master.

    Utilisé pour valider les requêtes diagnostiques avant exécution
    (refuser celles qui référencent des colonnes inventées).
    """
    schema: dict[str, set[str]] = {}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=SQLITE_TIMEOUT_SEC)
    try:
        for name, kind in conn.execute(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view')"
        ).fetchall():
            try:
                cols = conn.execute(f'PRAGMA table_info("{name}")').fetchall()
                schema[name.lower()] = {c[1].lower() for c in cols}
            except sqlite3.Error:
                schema[name.lower()] = set()
    finally:
        conn.close()
    return schema


def validate_sql_against_schema(sql: str, schema: dict[str, set[str]]) -> list[str]:
    """Best-effort schema check : table identifiers in FROM/JOIN doivent exister.

    Retourne une liste de warnings (vide = OK).
    """
    import sqlglot
    from sqlglot import expressions as exp

    warnings: list[str] = []
    try:
        tree = sqlglot.parse_one(sql, dialect="tsql")
    except Exception as e:
        warnings.append(f"parse_error: {e}")
        return warnings

    seen_tables: set[str] = set()
    for t in tree.find_all(exp.Table):
        name = (t.name or "").lower()
        if not name or name in seen_tables:
            continue
        seen_tables.add(name)
        if name not in schema:
            warnings.append(f"unknown_table: {t.name}")
    return warnings


def validate_sql_columns_against_schema(
    sql: str,
    schema: dict[str, set[str]],
) -> tuple[list[str], list[dict]]:
    """Vérifie que chaque ``alias.column`` référencé dans le SQL existe dans le
    schéma de la table résolue. Complément de ``validate_sql_against_schema``
    (qui ne valide QUE les noms de tables).

    Catche le bug Phase 3 : LLM hallucine ``g.grpCode`` alors que la vraie
    colonne est ``g.grpCodeGroupe`` — exécution échoue silencieusement avec
    ``no such column: g.grpCode``, probe perdue, Phase 4 reçoit une fact sheet
    appauvrie. Avec cette validation, on rejette la probe AVANT exécution et
    on fournit un feedback structuré (alternatives proches via difflib).

    Cas non-couverts (faux négatifs intentionnels — préférable au faux positif) :
    - Colonnes sans alias quand plusieurs tables + sans `default_table`
    - Colonnes de CTE / subquery (table résolue absente de schema → skip)
    - Colonnes calculées (alias.col où alias est un derived alias)

    Args:
        sql: la requête T-SQL à valider
        schema: ``{table_name_lower: set(column_name_lower)}`` — typiquement
            issu de ``build_schema_map_from_sqlite_master()``

    Returns:
        ``(warnings, unknown_columns)`` :
        - warnings : list[str] — messages text à logger / afficher
        - unknown_columns : list[dict] — entries structurées
          ``{"column", "table", "alternatives"}`` pour le feedback machine
    """
    import sqlglot
    from sqlglot import expressions as exp
    from sqlglot.optimizer.scope import traverse_scope, Scope
    from difflib import get_close_matches

    warnings: list[str] = []
    unknown: list[dict] = []
    try:
        tree = sqlglot.parse_one(sql, dialect="tsql")
    except Exception as e:
        # Fail-closed : un parse_error est rare mais s'il arrive, on ne peut
        # pas valider les colonnes. Plutôt que laisser passer (faux négatif —
        # une probe hallucinée passerait), on flag comme "validation impossible"
        # via une entrée unknown sentinelle. Le caller décide de rejeter ou
        # exécuter quand même selon sa politique de risque (Phase 3 = rejette).
        # Cf. adversarial review ÉLEVÉ #2 du fix initial.
        warnings.append(f"parse_error: {e}")
        unknown.append(
            {
                "column": "<parse_failed>",
                "table": "<unknown>",
                "alternatives": [],
                "_parse_error": str(e)[:200],
            }
        )
        return warnings, unknown

    # Approche par scope : chaque CTE / subquery / SELECT racine a son propre
    # alias map. Sans ça, le même alias `p` peut être à 2 scopes (table BDD
    # dans une CTE + alias de CTE dans le SELECT racine) → collision globale →
    # faux positifs sur les colonnes alias-CTE (ex: `P.CmProd2023` flag à tort
    # comme `production.CmProd2023`). Cf. adversarial review smoke test SQL
    # gold rentabilité.
    seen_signatures: set[tuple[str, str]] = set()

    for scope in traverse_scope(tree):
        # Build local alias map for THIS scope only.
        local_aliases: dict[str, str] = {}  # alias_lower → real_table_lower
        local_tables: list[str] = []  # ordered, for "single table no alias" fallback
        for source_alias, source in (scope.sources or {}).items():
            # source peut être un Table expr OU un Scope (CTE/subquery).
            # Si Scope → colonnes dérivées, non validables contre schéma BDD.
            if isinstance(source, Scope):
                continue
            if not hasattr(source, "name"):
                continue
            real_name = (source.name or "").lower()
            if not real_name:
                continue
            alias_lower = (source_alias or "").lower() if source_alias else real_name
            local_aliases[alias_lower] = real_name
            if real_name not in local_tables:
                local_tables.append(real_name)

        # Walk les Columns DE CE SCOPE uniquement (pas descendre dans les
        # sub-scopes — ils seront traités par leur propre itération).
        for col_expr in scope.columns:
            col_name = (col_expr.name or "").lower()
            if not col_name or col_name == "*":
                continue
            col_table_alias = (col_expr.table or "").lower()

            if col_table_alias:
                resolved_table = local_aliases.get(col_table_alias)
                if resolved_table is None:
                    # Alias inconnu dans ce scope → probablement un CTE alias
                    # (skipped via isinstance(source, Scope) plus haut), ou
                    # une référence externe (corrélée). Skip silencieusement
                    # plutôt que faux positif.
                    continue
            else:
                # Pas d'alias : si UNE seule table dans ce scope, on résout.
                # Sinon ambigu → skip (préférer faux négatif au faux positif).
                if len(local_tables) == 1:
                    resolved_table = local_tables[0]
                else:
                    continue

            # Si la table résolue n'est pas dans le schéma → skip
            # (validate_sql_against_schema gère ce cas).
            if resolved_table not in schema:
                continue

            # Dédup par (table, col) — éviter de reporter 5x la même colonne.
            sig = (resolved_table, col_name)
            if sig in seen_signatures:
                continue
            seen_signatures.add(sig)

            if col_name not in schema[resolved_table]:
                alternatives = get_close_matches(
                    col_name, list(schema[resolved_table]), n=3, cutoff=0.6
                )
                unknown.append(
                    {
                        "column": col_expr.name,
                        "table": resolved_table,
                        "alternatives": alternatives,
                    }
                )
                alt_str = ", ".join(alternatives) if alternatives else "(aucune proche)"
                warnings.append(
                    f"unknown_column: {col_expr.name} sur {resolved_table} "
                    f"(suggestions: {alt_str})"
                )
    return warnings, unknown


def execute_sqlite(
    sql: str,
    db_path: Path,
    row_cap: int = ROWS_CAP_PER_QUERY,
) -> tuple[list[tuple], list[str], str | None, float]:
    """Exécute un SELECT sur la BDD locale (read-only).

    Retourne (rows, columns, error_or_None, duration_sec). Cap à `row_cap`
    lignes pour ne pas saturer la mémoire si la requête est mal cadrée.
    """
    t0 = time.time()
    rows: list[tuple] = []
    columns: list[str] = []
    err: str | None = None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=SQLITE_TIMEOUT_SEC)
    _register_tsql_udfs(conn)
    try:
        cur = conn.execute(sql)
        columns = [d[0] for d in (cur.description or [])]
        for i, r in enumerate(cur):
            if i >= row_cap:
                break
            rows.append(r)
    except (sqlite3.Error, Exception) as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        conn.close()
    return rows, columns, err, time.time() - t0


def get_table_schema(db_path: Path, table_name: str) -> dict | None:
    """Return {name, kind: 'T'|'V', columns: [{name, type, pk, notnull}], view_sql?}.

    Utilisé pour construire le DDL contextuel envoyé aux LLM Phase 3 et 4.
    Tolère le préfixe `dbo_` (essaie sans préfixe en fallback).
    """
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT type, sql FROM sqlite_master WHERE name=? LIMIT 1",
            (table_name,),
        ).fetchone()
        if not row:
            stripped = re.sub(r"^dbo_", "", table_name)
            if stripped != table_name:
                row = conn.execute(
                    "SELECT type, sql FROM sqlite_master WHERE name=? LIMIT 1",
                    (stripped,),
                ).fetchone()
                if row:
                    table_name = stripped
        if not row:
            return None
        kind_str, view_sql = row
        kind = "V" if kind_str == "view" else "T"
        try:
            cols = conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
        except sqlite3.Error:
            cols = []
        columns = [
            {"name": c[1], "type": c[2], "notnull": bool(c[3]), "pk": bool(c[5])} for c in cols
        ]
        out: dict = {"name": table_name, "kind": kind, "columns": columns}
        if kind == "V" and view_sql:
            out["view_sql"] = view_sql
        return out
    finally:
        conn.close()


def analyze_null_ratios(
    rows: list[tuple],
    columns: list[str],
    threshold_global: float,
    threshold_per_column: float,
    min_rows: int,
) -> tuple[list[str], dict]:
    """Calcule les ratios NULL global + par colonne. Retourne (warnings, stats).

    `warnings` non-vide = caller doit traiter le résultat comme suspect.
    `stats.per_column_null_pct` = utilisé par les fiches concept.
    """
    warnings: list[str] = []
    stats: dict = {
        "row_count": len(rows),
        "column_count": len(columns),
        "global_null_pct": 0.0,
        "per_column_null_pct": {},
        "skipped_reason": None,
    }

    if not rows or not columns:
        stats["skipped_reason"] = "empty_result"
        return warnings, stats
    if len(rows) < min_rows:
        stats["skipped_reason"] = f"row_count<{min_rows}"
        return warnings, stats

    for col_idx, col_name in enumerate(columns):
        col_nulls = sum(1 for r in rows if r[col_idx] is None)
        col_pct = col_nulls / len(rows)
        stats["per_column_null_pct"][col_name] = col_pct
        if col_pct >= threshold_per_column:
            warnings.append(
                f"colonne '{col_name}' = {col_pct * 100:.0f}% NULL "
                f"({col_nulls}/{len(rows)} lignes)"
            )

    total_cells = len(rows) * len(columns)
    total_nulls = sum(round(pct * len(rows)) for pct in stats["per_column_null_pct"].values())
    global_pct = total_nulls / total_cells if total_cells else 0.0
    stats["global_null_pct"] = global_pct
    if global_pct >= threshold_global:
        warnings.insert(
            0,
            f"NULL global = {global_pct * 100:.0f}% "
            f"({total_nulls}/{total_cells} cells, {len(rows)} lignes)",
        )

    return warnings, stats


# =============================================================================
# Désobfuscation valeurs anonymisées (anti-bug "WHERE col = 'SFGC PP'" qui rate
# parce que la BDD a 'DOSSIER_A PAP'). Le bloc concept v2_text contient des
# valeurs obfusquées par anonymisation Niveau 2 (suppression voyelles). On
# remplace AVANT de passer au LLM en utilisant le mapping data/komptia.db
# table value_mapping (anonymized_value → real_value).
# =============================================================================


_ANON_QUOTED_RE = re.compile(r"'([^']+)'")


def load_anon_to_real_map(
    komptia_db_path: Path = KOMPTIA_DB,
    *,
    real_values_filter: list[str] | None = None,
) -> dict[str, str]:
    """Stub no-op depuis 2026-05-22.

    Avant : retournait un mapping ``{anonymized_value → real_value}`` depuis
    ``value_mapping.anonymized_value``. La colonne a été supprimée
    (cf. ``project_value_mapping_removed_2026_05_22.md``) : ``/data-privacy``
    (table ``anonymization_terms``) est désormais la seule source des pseudos
    runtime, et c'est ``ConfidentialityManager.restore_anonymized_values`` qui
    réalise le mapping inverse pour le user courant.

    On garde la signature pour ne pas casser les call sites ``phase 3`` et
    ``phase 4`` qui appellent cette fonction puis filtrent via
    ``if anon_to_real``. Retourner ``{}`` rend le bloc inactif sans erreur.
    """
    return {}


def resolve_anon_in_text(text: str, anon_to_real: dict[str, str]) -> str:
    """Remplace les valeurs entre quotes par leur version désobfuscée si match.

    Conservative : ne touche que les chaînes entre `'...'` qui matchent une
    clé du mapping. Le reste passe inchangé. Le LLM voit donc le texte avec
    les vraies valeurs aux endroits qui comptent (samples, key_columns,
    valeurs explicites dans FvEx).

    Tests :
      input  : "dosNomDossier='SFGC PP'"
      output : "dosNomDossier='DOSSIER_A PAP'"  (si mapping a 'SFGC PP'→'DOSSIER_A PAP')
      input  : "WHERE x = 'foo'"  (mapping ne contient pas 'foo')
      output : "WHERE x = 'foo'"  (inchangé)
    """
    if not text or not anon_to_real:
        return text

    def _sub(m: re.Match) -> str:
        v = m.group(1)
        real = anon_to_real.get(v)
        return f"'{real}'" if real else m.group(0)

    return _ANON_QUOTED_RE.sub(_sub, text)


# =============================================================================
# SYSTEM PROMPTS — Phase 3 (concept fact sheets) + Phase 4 (SQL composer)
# =============================================================================

# PERF (2026-05-21, task #88) — Cap d'exécution par probe Sage en Phase 3.
# Pourquoi : pyodbc cursor.execute() N'A PAS de timeout natif côté Python
# (le ``Connection Timeout=30`` ODBC ne couvre QUE la phase de connexion).
# Une probe sur une table monstrueuse (LignesFactures 112k lignes, Production
# 500k+) sans index optimal peut tourner plusieurs minutes silencieusement.
# Cap empirique : 60s = largement suffisant pour les probes informatives
# (< 5s typique), capable de catch les pathologies (scan complet sans WHERE).
# Au-delà : la probe est marquée ``executed=False`` avec ``error="probe_timeout_60s"``
# et les autres probes continuent en parallèle (gather isole les échecs).
# Limite connue (follow-up) : asyncio.wait_for cancel la task asyncio mais
# pyodbc cursor.execute() continue côté thread/serveur. Pour COUPER la query
# Sage Server-side, il faut set ``Connection.timeout`` pyodbc — pas fait ici
# car module sage_connector partagé avec d'autres callers.
_PHASE_3_PROBE_TIMEOUT_S: int = 60

# SSOT — bloc « dialect T-SQL » réutilisable pour les prompts qui demandent
# au LLM de générer du SQL natif (Phase 3 probes + Phase 4 legacy SQL).
# PAS injecté dans Phase 4 IR mode (le LLM IR est volontairement
# dialect-agnostic, cf. docstring ``PHASE4_COMPOSE_IR_SYSTEM_PROMPT``).
# Format few-shot ❌/✅ pour patterns courants où le LLM (entraîné majoritairement
# sur PostgreSQL/MySQL) génère du SQL non-T-SQL. Centralisé ici pour SSOT —
# tout ajout/correction se fait à un seul endroit. Task #95 du 2026-05-21.
_TSQL_DIALECT_GUIDE: str = """\

# Dialect cible : T-SQL (SQL Server)

Le moteur d'exécution est SQL Server (T-SQL). Évite les constructions non
supportées en T-SQL — voici les patterns courants à connaître :

| Cas | ❌ NE PAS faire | ✅ FAIRE |
|---|---|---|
| Limiter le nb de lignes | `SELECT ... LIMIT 50` | `SELECT TOP 50 ...` |
| Borne haute sur date | `col <= '2026-01-31'` ou `col BETWEEN a AND b` | `col >= '2026-01-01' AND col < '2026-02-01'` (borne exclusive sur jour+1, évite l'exclusion silencieuse des lignes ayant une composante horaire) |
| Date courante | `NOW()`, `CURRENT_DATE` | `GETDATE()` ou `CAST(GETDATE() AS DATE)` |
| Année / mois d'une date | `EXTRACT(YEAR FROM col)` | `YEAR(col)`, `MONTH(col)`, `DAY(col)` |
| Cast date | `col::DATE` | `CAST(col AS DATE)` ou `CONVERT(DATE, col)` |
| Concaténation strings | `'a' \\|\\| 'b'` | `CONCAT('a','b')` ou `'a' + 'b'` (attention aux NULL) |
| Longueur d'une chaîne | `LENGTH(col)` | `LEN(col)` |
| NULL fallback | `IFNULL(col, 0)` | `ISNULL(col, 0)` ou `COALESCE(col, 0)` |
| Identifiant avec espace ou mot réservé | `"my col"` | `[my col]` (T-SQL utilise les crochets, pas les quotes) |
| NOT LIKE plusieurs patterns | `col NOT LIKE '%X%','%Y%'` (invalide) | `col NOT LIKE '%X%' AND col NOT LIKE '%Y%'` (une condition par pattern) |
| Booléen littéral | `WHERE flag = TRUE` | `WHERE flag = 1` (T-SQL n'a pas de type bool natif — c'est BIT/0/1) |

**Réflexe** : si tu hésites entre une syntaxe PostgreSQL/MySQL et une T-SQL,
choisis la T-SQL. Le transpilateur aval n'adapte qu'un sous-ensemble — mieux
vaut générer T-SQL directement.
"""


def _build_runtime_context_block() -> str:
    """Retourne un bloc Markdown avec la date/heure courante et infos
    dérivées (jour de la semaine, trimestre, année).

    Injecté dans le **user prompt** (pas le system prompt) pour les phases
    pipeline qui en bénéficient (Phase 3 + Phase 4 SQL). Permet au LLM
    d'interpréter correctement les références temporelles relatives de la
    requête utilisateur (« ce mois », « l'année dernière », « le trimestre
    en cours »).

    NB : volontairement dans le user prompt — la date change à chaque appel,
    la mettre dans le system prompt casserait le cache prefix (le system
    prompt est partagé entre tous les concepts d'un même run).

    Format **strictement neutre** (juste des faits temporels), pas de jargon
    métier ni d'hypothèses sur le domaine de la BDD (cf. règle générique
    Komptia : la date courante est universelle, la sémantique métier ne l'est
    pas).

    Timezone : utilise ``config.server.timezone`` (SSOT Komptia, ex.
    ``Europe/Paris``) pour éviter le drift soir/nuit en déploiement Docker
    UTC. Si la résolution TZ échoue (boot incomplet, test isolé), fallback
    sur ``datetime.now()`` naïf — la garde est nécessaire car ce helper est
    appelé depuis ``run_pipeline`` qui peut tourner en mode test sans config.
    Task #95 + adversarial fix #M4 du 2026-05-21.
    """
    from datetime import datetime as _dt

    try:
        from zoneinfo import ZoneInfo

        from app.config import config as _komptia_config

        now = _dt.now(ZoneInfo(_komptia_config.server.timezone))
    except Exception:
        # Fallback tz-naive — process TZ (legacy). Garde le helper qui
        # tourne même si la config n'est pas chargée (tests isolés).
        now = _dt.now()
    weekday_fr = (
        "lundi", "mardi", "mercredi", "jeudi",
        "vendredi", "samedi", "dimanche",
    )[now.weekday()]
    quarter = (now.month - 1) // 3 + 1
    return (
        "# Contexte temporel d'exécution\n\n"
        f"- Date courante : **{now.strftime('%Y-%m-%d')}** ({weekday_fr})\n"
        f"- Heure locale : {now.strftime('%H:%M')}\n"
        f"- Année : {now.year} — Trimestre courant : Q{quarter} "
        f"({now.year}-Q{quarter}) — Mois courant : {now.year}-{now.month:02d}\n"
        "\n"
        "Utilise ces valeurs pour interpréter les références temporelles "
        "relatives de la requête utilisateur (« ce mois », « l'année "
        "dernière », « le trimestre en cours », « hier », etc.).\n"
    )


# SSOT — nombre max de cycles Q/A *pour Phase 3 uniquement* (concept factsheets).
# Phase 3 tourne en parallèle (asyncio.gather sur N concepts) → toute Q/A est
# auto-soumise R="" côté pipeline (jamais bridgée vers user) puis le LLM retry
# avec ces R vides. La valeur réelle d'itérations exécutables = N+1
# (``range(max_qa_loops + 1)``) → 1 = au plus 2 tours = 1er tour avec auto-submit
# vide possible + 2nd tour de décision. Default volontairement bas (task #96 du
# 2026-05-21) : sur le run #7, Phase 3 a fait 3 tours par concept ≈ 5 min
# gaspillées vs 1 tour décide-direct. Le prompt FACTSHEET_SYSTEM_PROMPT a une
# section dédiée « Mode parallèle » qui pousse le LLM à décider DÈS le 1er tour.
# IMPORTANT — séparé de ``max_qa_loops`` (qui pilote Phase 1.2.5 + 1.2.6 et
# reste à 2 par défaut, sémantique différente). Override CLI :
# ``--phase-3-max-qa-loops <N>``.
_PHASE_3_DEFAULT_MAX_QA_LOOPS: int = 1

# Lock partagé pour sérialiser les ``print()`` pendant le gather des probes —
# sinon les lignes de log peuvent s'interleaver (5 prints simultanés = log
# corrompu visuellement, observabilité dégradée).
_PHASE_3_PRINT_LOCK: "asyncio.Lock | None" = None


def _get_phase_3_print_lock() -> "asyncio.Lock":
    """Lazy init du lock (lié à l'event loop courant, doit être recréé
    si reset de l'event loop entre tests/processes)."""
    global _PHASE_3_PRINT_LOCK
    if _PHASE_3_PRINT_LOCK is None:
        _PHASE_3_PRINT_LOCK = asyncio.Lock()
    return _PHASE_3_PRINT_LOCK


def _stable_probe_id(q: dict, fallback_index: int) -> str:
    """Adversarial fix C4 — id stable et déterministe pour une probe.

    Si le LLM Phase 3 fournit un ``id`` non vide et ≠ ``"?"``, on le garde.
    Sinon on génère un id stable basé sur le hash du SQL → ordre du snapshot
    reproductible run-to-run, et pas de collision sur ``"?"`` quand plusieurs
    probes du LLM ont oublié leur id.
    """
    import hashlib

    raw_id = (q.get("id") or "").strip()
    if raw_id and raw_id != "?":
        return raw_id
    sql_for_hash = (q.get("sql") or "").encode("utf-8", errors="replace")
    if not sql_for_hash:
        return f"P_unknown_{fallback_index}"
    h = hashlib.md5(sql_for_hash).hexdigest()[:8]
    return f"P_hash_{h}"


FACTSHEET_SYSTEM_PROMPT = """\
Tu es un explorateur de données pour UN SEUL concept de la requête utilisateur.
Tu reçois la requête NL globale, le concept que tu dois éclairer, le DDL des
tables/vues les plus pertinentes pour ce concept (déjà classées par un scoring
algorithmique), un sous-graphe FK, et le bloc FvEx (où chaque valeur littérale
mentionnée par l'utilisateur a été retrouvée dans la BDD).

# Ton rôle EXACT

Tu génères **5 à 12 sous-requêtes T-SQL** (« probes ») qui, une fois exécutées
sur la vraie BDD, donneront à un agent SQL final aval toute l'information
empirique nécessaire pour comprendre **comment ce concept vit dans cette BDD**
dans le contexte de cette requête utilisateur.

Tu n'écris PAS le SQL final. Tu n'es PAS un debugger. Tu es un explorateur :
tes probes doivent surfacer les chemins, les distributions, les pièges, qui
permettront à l'agent aval de prendre les bonnes décisions structurelles.

# Garde-fous (à respecter strictement)

- **Aucune invention** : chaque table et chaque colonne mentionnée DOIT
  apparaître textuellement dans le DDL ou le sous-graphe FK fournis.
- **Une hypothèse / une question par probe** : ne combine pas 3 vérifications
  en 1. On doit pouvoir lire chaque résultat indépendamment.
- **Dialect T-SQL (SQL Server)** : cf. section dédiée plus bas
  « Dialect cible : T-SQL (SQL Server) » pour les patterns courants.
- **Cap d'output** : `SELECT TOP 50` (ou `TOP 10` pour les samples). JAMAIS
  de probe sans LIMIT/TOP.
- **Entre 5 et 8 probes** — pas plus, pas moins. Si tu n'as que 5 angles
  intéressants, n'en force pas 8. Si tu en vois 20, garde les 8 les plus
  informatives pour CE concept. Le plafond a été abaissé de 12 → 8 le
  2026-05-20 (fix L4 #42) : sur le run #7, Phase 3 prenait 14 min avec
  12 probes × 12 concepts ≈ 144 probes sériennes. À 8 max, on coupe
  d'environ 1/3 sans dégrader la qualité (les 4 probes supprimées sont
  typiquement les angles redondants — n-ième vérification du même path FK).

<<TSQL_DIALECT_GUIDE>>

# Angles que tes probes peuvent éclairer (liste non exhaustive — adapte au cas)

- Quels sont les paths FK concrets pour atteindre les tables clés du concept,
  et lequel matche réellement la sémantique attendue (la valeur visible côté
  utilisateur) ?
- Quelle est la distribution des valeurs sur les colonnes-clés du concept
  (top valeurs, ratio NULL, cardinalité totale) ?
- Les valeurs littérales mentionnées par l'utilisateur existent-elles dans
  la BDD ? Dans quelles colonnes exactement ? Combien de fois ? Avec quelle
  variante orthographique ?
- Si le concept est dérivable (ex. valeur calculée par formule depuis une
  colonne existante), quelle est la distribution de cette valeur dérivée ?
- Si plusieurs tables peuvent porter le concept, laquelle est la « source de
  vérité » selon les volumes / la fraîcheur / les FK ?
- Y a-t-il des paths FK alternatifs qui changeraient le sens du résultat ?

# Mode questions (rare — uniquement ambiguïté MÉTIER)

Le mapping (table, colonne) du concept est résolu **en amont** par Phase 2.5
(data-driven, 0 LLM) et te sera fourni dans le user prompt sous la section
« Résolution Phase 2.5 (data-driven, AUTORITAIRE) ». Tu n'as donc PLUS le
droit de poser une question pour redemander :
- quelle table porte le concept ;
- quelle colonne porte le concept ;
- quelle jointure utiliser pour atteindre la table ;
- de quel enregistrement / champ / FK on parle ;
- bref, AUCUNE question technique sur le schéma.

Si Phase 2.5 a marqué le concept « AMBIGÜ » (plusieurs candidates), c'est à
TOI de les départager via probes empiriques (count, distribution, NULL%),
PAS de demander à l'utilisateur.

Tu PEUX poser **1 à 3 questions** dans `ask_user` UNIQUEMENT si une
ambiguïté **purement métier** subsiste :
- variante de la même mesure (valeur avant vs après transformation, taxes incluses
  ou non, brut vs net — selon les conventions du domaine de la BDD) ;
- définition exacte d'une période (période métier vs calendaire ; granularité
  jour/mois/trimestre/année) ;
- inclusion/exclusion d'états ou de catégories (enregistrements annulés, archivés,
  internes, en cours, etc.) ;
- choix de définition métier non résolu par les artefacts disponibles (DDL,
  documentation indexée, échantillons).

Les questions sont formulées en langage NON technique (l'utilisateur ne
connaît rien aux noms de tables/colonnes). Si tu poses des questions, tu
produis quand même au moins 3 probes exploratoires « inconditionnelles ».

# ⚠️ Mode parallèle — DÉCIDE DÈS LE 1ER TOUR

Cette phase tourne en parallèle (asyncio.gather) sur N concepts en simultané.
**Les questions dans `ask_user` ne sont JAMAIS bridgées vers l'utilisateur** :
le système te répondra automatiquement par R="" (réponse vide) pour chaque
question et tu retry. Tu n'as **qu'un nombre très limité de retries** (1 par
défaut, configuré côté pipeline) — la valeur exacte est pilotée par
``phase_3_max_qa_loops`` côté code, ne te repose pas sur un chiffre précis,
considère que tu n'as **au plus 1 seule chance de revoir tes réponses**.

→ Conséquence directe sur ton comportement :

1. **N'utilise `ask_user` qu'en dernier recours absolu.** Si tu hésites entre
   2-3 interprétations métier raisonnables, **tranche avec ton meilleur
   jugement DÈS le 1er tour** plutôt que de poser une Q vide qui te reviendra
   avec R="" au tour suivant (pure perte de temps + 1 appel LLM gaspillé).

2. **Couvre tes alternatives par des PROBES, pas par des questions.** Si tu
   identifies 2 définitions plausibles d'une mesure (ex: avec vs sans
   transformation), fais 1 probe pour chacune en plus du choix par défaut —
   l'agent SQL aval verra les distributions et tranchera empiriquement.

3. **Si tu hérites de Q/A déjà auto-soumises vides au 2nd tour** (visibles
   dans le qa_block avec la mention « auto-soumises vides, décide toi-même »),
   ne RE-POSE PAS les mêmes questions. Décide avec ton meilleur jugement +
   probes alternatives. Reposer = boucle infinie, jamais d'info nouvelle.

4. **Cas où poser une Q reste légitime** : ambiguïté métier irréductible
   sans contexte humain (ex: « parmi ces 2 codes catégorie, lequel est le
   bon ? » et les 2 ont des distributions sémantiquement identiques). Reste
   l'exception, pas la règle.

L'objectif système : **1 appel LLM par concept** (pas 3), gain ~5 min sur
runs longs (cf. task #96 du 2026-05-21).

# Format de sortie (JSON strict, rien d'autre)

```json
{
  "concept": "<le concept que tu explores>",
  "interpretation": "1-3 phrases en langage métier sur ce que tu vas explorer pour ce concept et pourquoi ces angles sont pertinents",
  "ask_user": [],
  "probes": [
    {
      "id": "P1",
      "purpose": "1 phrase métier (PAS technique) qui décrit ce que cette probe éclaire",
      "hypothesis": "Ce que chaque résultat possible signifie. Ex: si retourne 0 → A ; si retourne >0 avec valeurs X/Y → B ; si >50% NULL → C",
      "sql": "SELECT TOP 50 ..."
    }
  ]
}
```

Réponds UNIQUEMENT le JSON. Pas de markdown autour, pas de prose.
"""


# PRÉFIXE STABLE (commun à tous les concepts d'un run) — éligible au cache
# Anthropic via `prompt_cache_prefix`. Économise les input tokens sur les N
# appels parallèles Phase 3 (10 concepts × ~5KB = ~50KB économisés par cache).
FACTSHEET_USER_PREFIX_TEMPLATE = """\
# Demande utilisateur (langage naturel)

> {user_query}

# Valeurs explicites mentionnées par l'utilisateur (en clair)

{explicit_values_block}

⚠️ **Utilise ces valeurs littérales (ci-dessus) dans tes probes SQL**, JAMAIS les
versions tronquées/obfusquées que tu pourrais voir dans le bloc concept ou les
samples ci-dessous. Si tu écris `WHERE col = 'XYZ'`, vérifie que `'XYZ'` est
bien la valeur ORIGINALE de l'utilisateur — pas une version anonymisée.

# Filtres globaux résolus (s'appliquent à tous les concepts)

(Source : extraction Phase 1 + résolution Phase 2.5 data-driven. Ces filtres
et leurs colonnes cibles sont AUTORITAIRES — quel que soit le concept que tu
explores, ces mappings valent. NE POSE PAS de question pour redemander où
ces valeurs existent : c'est déjà résolu ci-dessous.)

{global_filters_block}

# Sous-graphe FK pertinent (commun à tous les concepts)

{fk_context}
"""


# Injecte le dialect T-SQL guide à la position du marker (juste après
# « Garde-fous », avant « Angles » et avant « Format de sortie »). Position
# choisie d'après le pattern « rôle → garde-fous → règles → format EN
# DERNIER » — le LLM se souvient surtout du dernier bloc, qui doit être le
# format de sortie. Task #95 du 2026-05-21 + adversarial fix #M2.
FACTSHEET_SYSTEM_PROMPT = FACTSHEET_SYSTEM_PROMPT.replace(
    "<<TSQL_DIALECT_GUIDE>>", _TSQL_DIALECT_GUIDE.strip()
)
assert "<<TSQL_DIALECT_GUIDE>>" not in FACTSHEET_SYSTEM_PROMPT, (
    "Marker <<TSQL_DIALECT_GUIDE>> non remplacé — config cassée"
)


# Suffixe VARIABLE par concept — non-cacheable
FACTSHEET_USER_TEMPLATE = """\
{runtime_context}

# Concept à explorer

**{concept}**

{derivable_info}

# Résolution Phase 2.5 (data-driven, AUTORITAIRE)

(Source : Phase 2.5 — résolution `value_mapping` + types + samples,
0 appel LLM, 0 hallucination. Cette résolution doit être ta source
PRIMAIRE pour cartographier le concept en (table, colonne). Le DDL et le
rerank ci-dessous sont des contextes complémentaires, pas autoritaires.)

{concept_resolution_block}

# Top entités candidates pour ce concept (rerank Phase 2 — complément)

{top_entities_for_concept}

# DDL des tables / vues les plus pertinentes pour ce concept

{schema_context}

{columns_inventory}

# FvEx — où chaque valeur littérale existe-t-elle dans la BDD

(Source : Phase 1.4. Pour chaque valeur explicite mentionnée par
l'utilisateur, on a déjà cherché dans toute la BDD les colonnes où
cette valeur apparaît exactement. C'est la source de vérité pour
valider que les filtres `WHERE col = 'val'` peuvent matcher.)

{fvex_context}

# Ta tâche

Génère 5 à 8 probes T-SQL pour éclairer **ce concept dans CETTE requête
utilisateur**, en t'appuyant en PRIORITÉ sur la résolution Phase 2.5
ci-dessus. Réponds en JSON strict selon le format du SYSTEM.

Si — et SEULEMENT si — une ambiguïté **purement métier** subsiste, ajoute
1-3 questions dans `ask_user`, formulées en langage NON technique. JAMAIS
de questions sur le mapping table↔concept (c'est résolu en amont par
Phase 2.5).
"""


COMPOSE_SQL_SYSTEM_PROMPT = """\
Tu es un expert SQL Server qui produit la requête SQL FINALE pour une
demande utilisateur sur une base de données réelle.

Tu reçois :
1. La requête utilisateur en langage naturel
2. Le DDL des tables/vues impliquées
3. Un sous-graphe FK
4. Le bloc FvEx (où chaque valeur littérale mentionnée existe dans la BDD)
5. **Une fiche par concept identifié dans la requête.** Chaque fiche
   contient des probes SQL **déjà exécutées sur la vraie BDD** avec leurs
   résultats (samples + row_count + ratio NULL par colonne) et une
   interprétation métier. Ces fiches sont ta **mise à terre empirique** —
   elles te disent ce qui marche réellement dans cette BDD pour chaque
   dimension de la requête.

# Comment utiliser les fiches concept

- Pour chaque concept, lis l'interpretation et les probes. Les samples
  réels te disent quelle table porte la bonne sémantique, quel path FK
  matche les valeurs visibles côté utilisateur, où sont les NULL massifs,
  quelles valeurs explicites existent et où.
- **Si une probe retourne 0 lignes**, c'est un signal : le path FK que la
  probe testait est probablement faux pour cette intention utilisateur.
- **Si une probe a un ratio NULL massif sur une colonne-clé** (ex. >70%),
  c'est un signal : un filtre `= valeur` sur cette colonne exclura
  silencieusement toutes les lignes NULL. Réfléchis à `IS NULL OR ...`
  ou évite ce filtre.
- **Si plusieurs probes proposent des paths alternatifs** (deux JOIN
  candidats), choisis celui dont les samples correspondent à la
  sémantique demandée par l'utilisateur, pas celui qui « ressemble au
  nom ».

# Garde-fous (à respecter strictement)

- **Aucune invention** : chaque table, chaque colonne et chaque jointure
  utilisée DOIT apparaître textuellement dans le DDL ou le sous-graphe FK.
- **Dialect T-SQL (SQL Server)** : cf. section dédiée plus bas
  « Dialect cible : T-SQL (SQL Server) » pour les patterns courants.
- **Pas de TOP N global** sauf si l'utilisateur le demande explicitement
  (l'utilisateur veut le résultat complet, pas un échantillon).
- **Cite tes sources empiriques** : juste avant chaque JOIN, ajoute un
  commentaire SQL `-- Path validé par P<N> de la fiche <concept>` qui
  référence la probe qui a confirmé que ce path matche la sémantique
  utilisateur. Si tu utilises un filtre WHERE non trivial, idem :
  `-- WHERE validé par P<N>`. C'est obligatoire pour la traçabilité.
- **Pas de filtre destructeur sur colonne NULL** sans IS NULL fallback,
  si une probe a montré un ratio NULL massif sur cette colonne.

<<TSQL_DIALECT_GUIDE>>

# Réflexes critiques anti-régression (à ne pas oublier)

## R1. Une table peut avoir plusieurs rôles dans la même requête
Une même table peut être utilisée plusieurs fois (avec alias distincts)
quand la demande implique deux rôles : par exemple, une table d'entités
peut représenter à la fois un "parent" (relié via une FK) et un "enfant"
(relié via une autre FK). Si la demande mentionne deux rôles distincts
pour ce qui pourrait être la même table, ET que la structure permet de
joindre la table à elle-même par des FK différentes : self-join obligatoire
avec alias distincts (R6). **Réflexe que le LLM oublie souvent.**

## R17. Range sur date — borne haute exclusive sur jour+1, jamais `<=` ni `BETWEEN`
Une colonne porteuse (ou potentiellement porteuse) d'un composant horaire
compare différemment d'un littéral sans heure selon le moteur et le format
de stockage : `<= '<date>'` ou `BETWEEN start AND end` peuvent silencieusement
exclure tout ou partie du dernier jour.

Forme robuste universelle, sans connaître le type exact :
  `col >= '<start>' AND col < '<end_plus_one_day>'`

`<=` / `BETWEEN` ne sont sûrs que si tu peux PROUVER via le DDL que la
colonne est un type DATE pur sans aucun composant horaire — rare en
données legacy.

## R23. NOT LIKE — une condition par pattern
`col NOT LIKE '%X%','%Y%'` n'existe pas en SQL standard. Pour exclure
plusieurs patterns, multiplier les conditions :
```
AND col NOT LIKE '%X%'
AND col NOT LIKE '%Y%'
```

## R25. Vue vs table source — auditer le `CREATE VIEW` avant utilisation
Une vue n'est PAS un raccourci magique : c'est du SQL qui s'exécute, avec
ses propres `FROM`, `JOIN`, `WHERE`, `GROUP BY`. **Avant** de l'utiliser,
audite son DDL `CREATE VIEW` complet pour détecter :
- `INNER JOIN` interne qui filtre silencieusement (perd des lignes si la
  table jointée ne couvre pas 100% du périmètre demandé) ;
- `WHERE archive=0` / `WHERE actif=1` / etc. qui réduit silencieusement.

Si la vue couvre EXACTEMENT ton besoin → utilise-la (gain de propreté).
Si la vue contient un filtre involontaire pour ta demande → utilise les
tables sources et recopie les `ON` clauses comme référence.

## R28. Vérifier l'EXISTENCE des colonnes dans le DDL avant de les référencer
Avant d'écrire `<table>.<col>`, vérifie que `<col>` apparaît littéralement
dans la section "Colonnes" du DDL fourni pour `<table>`. Cas piège :
une vue de la forme `CREATE VIEW V AS SELECT base.*, expr AS extraCol
FROM base ...` expose `extraCol` SUR LA VUE, pas sur la table `base`.
Référencer `base.extraCol` dans le SQL produira une erreur SQL Server
"Invalid column name". Solution : utiliser la vue (`V.extraCol`) ou
dériver/joindre la donnée manuellement depuis les tables sources.

## R29. Vérifier que la valeur d'un filtre existe dans la COLONNE choisie (FvEx)
Avant d'écrire `WHERE <table>.<col> = '<val>'` (ou `IN`, ou `LIKE`),
**croiser la valeur avec les sections "FvEx" / "FvCo"** :
- Si `<val>` apparaît dans FvEx/FvCo MAIS la colonne `<table>.<col>` choisie
  n'est PAS dans la liste pour cette valeur → tu hallucines : la valeur
  n'existe pas dans cette colonne. Le filtre retournera **0 ligne
  silencieusement**. Choisis une colonne RÉELLEMENT listée pour cette
  valeur.
- Si `<val>` n'apparaît dans AUCUNE section → la valeur n'existe nulle
  part TELLE QUELLE dans la BDD. Le filtre par égalité est inopérant ;
  il faut **CONSTRUIRE** la donnée depuis les colonnes brutes (CASE WHEN,
  calcul, dérivation) plutôt que filtrer sur une table existante.

**Test mental obligatoire** avant tout `WHERE col = '<val>'` : "ai-je vu
`<val>` listée à côté de `<table>.<col>` dans la section FvEx ?" Si non,
soit ce n'est pas la bonne colonne, soit la valeur n'existe pas et il
faut la dériver.

## R30. Concepts DÉRIVABLES — formule SQL plutôt que JOIN sur table dédiée
Certains concepts sont marqués **DÉRIVABLES** (calculables par une formule
depuis les concepts sources). Pour ces concepts :
1. **Pas de JOIN** vers une table dédiée à ce concept.
2. **Identifier la (les) colonne(s) source** dans les concepts listés.
3. **Écrire l'expression SQL appropriée** dans `SELECT`/`GROUP BY`/`WHERE` :
   - composante temporelle d'une date → `YEAR(...)`, `MONTH(...)`,
     `CASE WHEN MONTH(...) < N ...`
   - calcul arithmétique → `SUM`, `AVG`, `+`, `*`
   - règle métier conditionnelle → `CASE WHEN ... THEN ... END`
4. **Pas de fallback paresseux** vers une table d'apparence proche : si une
   formule peut se calculer depuis une colonne déjà présente dans le scope
   courant, préférer le calcul direct à une jointure supplémentaire vers une
   table dont le nom semble juste « ressembler » au concept demandé.

# ⚠️ CONFIDENTIALITÉ — RÈGLE CRITIQUE
Les vraies valeurs mentionnées par l'utilisateur sont fournies en clair
dans la section "Valeurs explicites" du USER prompt. **N'utilise dans le
SQL que ces valeurs explicites** (ou des valeurs que l'utilisateur a
données dans sa demande NL).

Si tu vois encore une chaîne entre apostrophes qui ressemble à une version
tronquée/obfusquée d'un mot (ex `'SFGC PP'` au lieu de `'DOSSIER_A PAP'`,
ou `'DPN'` au lieu de `'DUPONT'`), c'est une version **anonymisée**
(Niveau 2 — Peek obfusqué) qui ne doit JAMAIS apparaître dans le SQL
final. Utilise plutôt les valeurs littérales de la demande NL ou marque
l'hypothèse explicitement en commentaire `--`.

# Format de sortie

Tu réponds UNIQUEMENT par le SQL final, dans un bloc ```sql ... ```.
Pas de prose autour, juste le SQL avec ses commentaires de traçabilité
en `--`. Inclus 4-8 lignes de commentaires `--` AU DÉBUT du SQL pour
résumer ta stratégie (quelles fiches/probes ont guidé tes choix
structurels les plus importants).
"""


# Injecte le dialect T-SQL guide à la position du marker (juste après
# « Garde-fous », avant « Réflexes » et avant « Format de sortie »).
# Task #95 du 2026-05-21 + adversarial fix #M2.
COMPOSE_SQL_SYSTEM_PROMPT = COMPOSE_SQL_SYSTEM_PROMPT.replace(
    "<<TSQL_DIALECT_GUIDE>>", _TSQL_DIALECT_GUIDE.strip()
)
assert "<<TSQL_DIALECT_GUIDE>>" not in COMPOSE_SQL_SYSTEM_PROMPT, (
    "Marker <<TSQL_DIALECT_GUIDE>> non remplacé — config cassée"
)


COMPOSE_SQL_USER_TEMPLATE = """\
{runtime_context}

# Demande utilisateur (langage naturel)

> {user_query}

{session_qa_block}# Valeurs explicites mentionnées par l'utilisateur

{explicit_values_block}

# DDL des tables / vues impliquées

{schema_context}

# Sous-graphe FK

{fk_context}

# Concepts dérivables (calculables par formule SQL — pas de JOIN dédié, cf. R30)

{derivables_block}

# FvEx — colonnes qui matchent EXACTEMENT chaque valeur explicite

C'est la **source la plus fiable** pour décider QUELLE colonne mettre dans
un filtre `WHERE col = 'val'` ou `WHERE col NOT LIKE '%val%'`. Pour chaque
valeur explicite de l'utilisateur, voici les colonnes où cette valeur EXISTE
TELLE QUELLE dans la BDD.

**Règle absolue (R29)** : si tu mets `WHERE X.col = 'val'` dans le SQL, `X.col`
DOIT figurer dans la liste ci-dessous pour cette valeur — sinon tu hallucines
(la valeur n'existe pas dans cette colonne, le filtre retournera 0 ligne
silencieusement).

{fvex_context}

# FvCo — colonnes qui CONTIENNENT chaque valeur (pour LIKE / NOT LIKE)

En complément des FvEx (égalité stricte), pour chaque valeur explicite la
liste des colonnes où la valeur apparaît comme **sous-chaîne** d'une cellule.
À utiliser pour les filtres `LIKE '%val%'` ou `NOT LIKE '%val%'` — la colonne
DOIT figurer dans cette liste pour cette valeur, sinon le filtre est inopérant.

{fvco_context}

# Fiches concept (probes EXÉCUTÉES sur la BDD réelle)

{factsheets_block}

# Ta tâche

Produis le SQL FINAL en T-SQL (SQL Server) qui répond à la demande
utilisateur. Cite les probes qui valident chaque jointure et chaque
filtre non trivial via des commentaires `--`. Réponds uniquement par
le bloc ```sql ... ``` (rien d'autre).
"""


# ─────────────────────────────────────────────────────────────────────
# NOUVELLE PHASE 3 — Concept Fact Sheets (probes par concept, parallèle)
# ─────────────────────────────────────────────────────────────────────


def _build_ddl_for_entities(
    entities: list[str],
    db_path: Path,
    max_entities: int = 10,
) -> str:
    """Construit un bloc DDL textuel pour les entités fournies.

    Pour chaque entité (table ou vue), on récupère ses colonnes via
    `get_table_schema()` et on formate en pseudo-CREATE TABLE/VIEW.
    Cap `max_entities` pour borner la taille du prompt.

    Format de sortie :
        CREATE TABLE Foo (
          colA TEXT,
          colB INTEGER NOT NULL,
          ...
        )

        CREATE VIEW Bar AS  -- view_sql récupéré tel quel
        ...

    Returns "" si la BDD n'existe pas / aucune entité trouvée.
    """
    if not db_path.exists() or not entities:
        return ""
    parts: list[str] = []
    seen: set[str] = set()
    for ent in entities:
        if ent in seen:
            continue
        seen.add(ent)
        if len(seen) > max_entities:
            break
        schema = get_table_schema(db_path, ent)
        if not schema:
            continue
        kind = schema.get("kind", "T")
        cols = schema.get("columns", []) or []
        if kind == "V":
            view_sql = schema.get("view_sql", "")
            if view_sql:
                parts.append(view_sql.rstrip(";").strip())
                parts.append("")
                continue
        col_lines = []
        for c in cols:
            name = c.get("name", "?")
            typ = c.get("type") or "TEXT"
            notnull = " NOT NULL" if c.get("notnull") else ""
            pk = " PRIMARY KEY" if c.get("pk") else ""
            col_lines.append(f"  {name} {typ}{notnull}{pk}")
        kind_kw = "VIEW" if kind == "V" else "TABLE"
        parts.append(f"CREATE {kind_kw} {schema['name']} (")
        parts.append(",\n".join(col_lines))
        parts.append(");")
        parts.append("")
    return "\n".join(parts).strip()


def _build_columns_inventory_for_entities(
    entities: list[str],
    db_path: Path,
    max_entities: int = 10,
    max_cols_per_table: int = 60,
) -> str:
    """Construit un bloc "inventaire colonnes" en bullets pour le prompt LLM.

    Complément du DDL CREATE TABLE (`_build_ddl_for_entities`) : le DDL est
    dense et le LLM peut le scanner mal. Ce bloc liste les colonnes EN
    bullets, format "checklist" plus saillant pour réduire les hallucinations
    (ex: LLM écrit `g.grpCode` parce qu'il extrapole le pattern préfixe+suffixe
    sans avoir bien lu que la vraie colonne est `grpCodeGroupe`).

    Format :
        ## Inventaire colonnes (référence rapide pour rédiger le SQL)

        - **Groupes** (4 colonnes) : grpNoEnreg, grpCodeGroupe, grpLibelleGroupe,
          grpNoEnregDos
        - **Dossiers** (53 colonnes) : dosNoEnreg, dosCodeDossier, ... (+45)

    Generic — aucune table/colonne hardcodée. Cap ``max_cols_per_table`` pour
    éviter d'exploser le prompt sur les tables larges (ex: 100+ colonnes).
    """
    if not db_path.exists() or not entities:
        return ""
    lines: list[str] = []
    seen: set[str] = set()
    for ent in entities:
        if ent in seen:
            continue
        seen.add(ent)
        if len(seen) > max_entities:
            break
        schema = get_table_schema(db_path, ent)
        if not schema:
            continue
        cols = schema.get("columns", []) or []
        if not cols:
            continue
        col_names = [c.get("name", "?") for c in cols if c.get("name")]
        n_total = len(col_names)
        shown = col_names[:max_cols_per_table]
        suffix = (
            f" (+{n_total - max_cols_per_table} colonnes supplémentaires)"
            if n_total > max_cols_per_table
            else ""
        )
        lines.append(f"- **{schema['name']}** ({n_total} colonnes) : " + ", ".join(shown) + suffix)
    if not lines:
        return ""
    return "## Inventaire colonnes (référence rapide pour rédiger le SQL)\n\n" + "\n".join(lines)


def _extract_fk_subgraph_from_v2(v2_text: str) -> str:
    """Extrait la section 'SOUS-GRAPHE FK' de scored.v2_text.

    Le scored.v2_text de Phase 1.5 contient un bloc balisé par
    `SOUS-GRAPHE FK (entités shortlistées uniquement)` suivi du
    contenu jusqu'au prochain `=====` séparateur lourd.

    Returns "" si introuvable.
    """
    if not v2_text:
        return ""
    lines = v2_text.splitlines()
    start_idx = None
    for i, ln in enumerate(lines):
        if "SOUS-GRAPHE FK" in ln:
            start_idx = i
            break
    if start_idx is None:
        return ""
    # Skip the header line + separator lines
    j = start_idx + 1
    while j < len(lines) and (
        lines[j].startswith("=")
        or lines[j].startswith("─")
        or "Légende:" in lines[j]
        or lines[j].strip().startswith("par convention")
    ):
        j += 1
    # End at next major section
    end_idx = len(lines)
    for k in range(j, len(lines)):
        ln = lines[k]
        if ln.startswith("=" * 30) and k + 1 < len(lines):
            next_ln = lines[k + 1].strip()
            if next_ln and not next_ln.startswith("=") and not next_ln.startswith("─"):
                end_idx = k
                break
    return "\n".join(lines[start_idx:end_idx]).rstrip()


def _extract_fvex_for_concept(concept_block: str) -> str:
    """Extrait juste le bloc FvEx du concept_block (où user values matchent exactement).

    Le concept_block contient FvEx, FvCo, ColEx, ColCo, ColFz, etc.
    Pour le prompt FACTSHEET, on garde tout (le LLM en a besoin pour
    les probes). Cette fonction = identité pour l'instant — elle
    existe pour symétrie + extension future si on veut filtrer.
    """
    return concept_block


# ─────────────────────────────────────────────────────────────────────
# Parsers FvEx / FvCo depuis le format scored.v2_text par concept.
# Format observé (par concept) :
#   [T] <TableName> (<rows>r) | proba=<n>  +Annex(<n>)
#      FvEx (<count>):
#        = <value> (<n_columns>):
#          <col1>='<val>', <col2>='<val>', ...
#          <col3>={'<val1>','<val2>',...,+N}
#      FvCo (<count>):
#        ⊂ <substring> (<n_columns>):
#          <col1>='<val>'
# ─────────────────────────────────────────────────────────────────────


_ENTITY_HEADER_RE = re.compile(r"^\[(T|V)\]\s+(\S+)\s+\(", re.MULTILINE)
_FV_VALUE_HEADER_RE = re.compile(r"^\s+[=⊂]\s+(.+?)\s+\(\d+\):", re.MULTILINE)
_COL_NAME_RE = re.compile(r"\b([a-z][a-zA-Z0-9_]*)\s*=")


def _parse_fv_per_value(
    v2_text: str,
    explicit_values: list[str],
    fv_kind: str = "FvEx",
) -> dict[str, list[tuple[str, str]]]:
    """Parse les blocs FvEx ou FvCo de scored.v2_text par valeur explicite.

    Retourne `{value_lowered: [(table, column), ...]}` dédupliqué,
    pour CHAQUE valeur littérale mentionnée par l'utilisateur.

    `fv_kind` : 'FvEx' (égalité stricte) ou 'FvCo' (sous-chaîne).

    Robuste aux 2 formats de cellule observés :
      - col='val'                                       (1 valeur)
      - col={'v1','v2',...} ou col={'v1',...,+N}        (multi)
    """
    if not v2_text or not explicit_values:
        return {}

    needle_set = {v.lower().strip() for v in explicit_values if v and v.strip()}
    if not needle_set:
        return {}

    result: dict[str, set[tuple[str, str]]] = {}

    # Découpe par entité (par bloc [T] ou [V])
    matches = list(_ENTITY_HEADER_RE.finditer(v2_text))
    for i, m in enumerate(matches):
        entity_name = m.group(2)
        block_start = m.start()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(v2_text)
        block = v2_text[block_start:block_end]

        # Trouver la section "FvEx (N):" ou "FvCo (N):"
        section_re = re.compile(rf"^   {fv_kind}\s+\(\d+\):", re.MULTILINE)
        section_match = section_re.search(block)
        if not section_match:
            continue
        section_start = section_match.end()
        # Section finit au prochain "  XxxX (N):" au même niveau d'indent (2 spaces)
        section_end = block.find("\n   ", section_start + 1)
        # Plus précis : trouve le prochain bloc niveau 3-spaces qui n'est pas
        # un sous-bloc de FvEx (= ou ⊂).
        next_section_re = re.compile(r"\n   [A-Z][a-zA-Z]*\s+\(\d+\):", re.MULTILINE)
        next_match = next_section_re.search(block, section_start)
        section_end = next_match.start() if next_match else len(block)
        section_text = block[section_start:section_end]

        # Parse les `= <value> (N):` (FvEx) ou `⊂ <value> (N):` (FvCo)
        for vm in _FV_VALUE_HEADER_RE.finditer(section_text):
            value = vm.group(1).strip()
            value_lower = value.lower()
            if value_lower not in needle_set:
                continue
            # Lignes suivantes (jusqu'à la prochaine `= <value>` ou fin) =
            # listes col='val' ou col={'val1',...}
            value_start = vm.end()
            next_value_match = _FV_VALUE_HEADER_RE.search(section_text, value_start)
            value_end = next_value_match.start() if next_value_match else len(section_text)
            cols_text = section_text[value_start:value_end]
            # Extrait les noms de colonnes (suffixe d'un `=`)
            for col_m in _COL_NAME_RE.finditer(cols_text):
                col = col_m.group(1)
                # Filtre faux positifs : col doit commencer par lower
                # (les colonnes Sage Coala respectent xxxNomCol convention)
                if col[:1].islower():
                    result.setdefault(value_lower, set()).add((entity_name, col))

    return {v: sorted(s) for v, s in result.items()}


def parse_fvex_from_v2(
    v2_text: str,
    explicit_values: list[str],
) -> dict[str, list[tuple[str, str]]]:
    """Wrapper FvEx (égalité stricte)."""
    return _parse_fv_per_value(v2_text, explicit_values, fv_kind="FvEx")


def parse_fvco_from_v2(
    v2_text: str,
    explicit_values: list[str],
) -> dict[str, list[tuple[str, str]]]:
    """Wrapper FvCo (sous-chaîne)."""
    return _parse_fv_per_value(v2_text, explicit_values, fv_kind="FvCo")


# ─────────────────────────────────────────────────────────────────────
# Builders de blocs prompt — produisent du texte structuré pour le LLM.
# ─────────────────────────────────────────────────────────────────────


def build_explicit_values_block(extracted: dict) -> str:
    """Section "Valeurs explicites mentionnées par l'utilisateur" en clair.

    Ces valeurs viennent de extracted.groupes (parse Phase 1.1+1.2 du LLM).
    Sont les VRAIES valeurs (non obfusquées) que l'utilisateur a tapées.
    Le LLM doit les utiliser dans les filtres `WHERE col = 'val'` (cf. R29).
    """
    groupes = (extracted or {}).get("groupes", {}) or {}
    lines = []
    for c, vs in sorted(groupes.items()):
        if vs:
            lines.append(f"- **{c}** : `{', '.join(vs)}`")
    return "\n".join(lines) if lines else "_(aucune valeur explicite mentionnée par l'utilisateur)_"


def build_fvex_context_from_v2(
    v2_text: str,
    explicit_values: list[str],
) -> str:
    """Formate la liste FvEx pour le prompt LLM.

    Output structuré : pour chaque valeur, liste les (table, column) où
    elle existe TELLE QUELLE dans la BDD. Le LLM utilise ça pour choisir
    la bonne colonne dans son `WHERE col = 'val'` (cf. R29).
    """
    fvex = parse_fvex_from_v2(v2_text, explicit_values)
    if not fvex:
        return "_(aucune valeur explicite ne match exactement dans la BDD — filtre par égalité inopérant pour ces valeurs)_"
    lines: list[str] = []
    for value, cols in fvex.items():
        lines.append(f"\n**Valeur `'{value}'`** — match exact dans :")
        for tbl, col in cols[:30]:  # cap pour éviter explosion taille
            lines.append(f"  - `{tbl}.{col}`")
        if len(cols) > 30:
            lines.append(f"  - ... (+{len(cols) - 30} colonnes)")
    return "\n".join(lines)


def build_fvco_context_from_v2(
    v2_text: str,
    explicit_values: list[str],
) -> str:
    """Formate la liste FvCo pour le prompt LLM (LIKE / NOT LIKE)."""
    fvco = parse_fvco_from_v2(v2_text, explicit_values)
    if not fvco:
        return "_(aucune valeur explicite trouvée comme sous-chaîne dans la BDD)_"
    lines: list[str] = []
    for value, cols in fvco.items():
        lines.append(f"\n**Valeur `'{value}'`** — sous-chaîne trouvée dans :")
        for tbl, col in cols[:30]:
            lines.append(f"  - `{tbl}.{col}`")
        if len(cols) > 30:
            lines.append(f"  - ... (+{len(cols) - 30} colonnes)")
    return "\n".join(lines)


def build_derivables_block(extracted: dict) -> str:
    """Section "Concepts dérivables" formatée pour le prompt (cf. R30).

    Format :
      - **<concept_dérivé>** ← calculé depuis : <concept_source1>, <concept_source2>
    """
    derivables = (extracted or {}).get("derivables", {}) or {}
    if not derivables:
        return "_(aucun concept dérivable identifié)_"
    lines = []
    for derived, sources in sorted(derivables.items()):
        lines.append(f"- **{derived}** ← calculé depuis : {', '.join(sources)}")
    return "\n".join(lines)


def _build_global_filters_block(
    extracted: dict | None,
    concept_resolution: dict | None,
) -> str:
    """Bloc autoritaire des filtres globaux (concept role=filter avec
    literal_value) + leur résolution Phase 2.5 (table.col).

    Injecté dans le préfixe Phase 3 cacheable (`FACTSHEET_USER_PREFIX_TEMPLATE`).
    Tous les LLM Phase 3 parallèles voient ce bloc avec leur concept courant.
    Empêche les Q comme « où existe la valeur X ? » alors que la résolution
    Phase 2.5 a déjà mappé X→table.col (cf. cas FN run 9, task #70).

    Format compact, une ligne par filtre :
        - **concept** = `val1`, `val2` → table.col (type=`text`)
        - **concept (exclusion)** = `val` → table.col (type=`text`)

    Si pas de concepts filter détectés, retourne placeholder explicite (pas
    de bloc vide qui dérouterait le LLM).
    """
    if not isinstance(extracted, dict):
        return "_(pas de filtres extraits)_"
    concepts_v2 = extracted.get("concepts_v2") or []
    groupes = extracted.get("groupes") or {}
    if not concepts_v2:
        return "_(pas de concepts extraits — extraction vide)_"

    cr_dict: dict = concept_resolution if isinstance(concept_resolution, dict) else {}

    lines: list[str] = []
    for c in concepts_v2:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("concept") or ""
        role = (c.get("role") or "").lower()
        value_kind = (c.get("value_kind") or "").lower()
        if not name:
            continue
        # On garde les concepts qui ont un rôle de filtrage : "filter" +
        # literal_value (cas standard), ou les concepts marqués comme exclusion.
        is_filter = role == "filter" and value_kind == "literal_value"
        is_exclusion = "exclusion" in name.lower() or "exclus" in role
        if not (is_filter or is_exclusion):
            continue
        # Valeurs littérales explicites (depuis extracted.groupes principalement)
        values = list(groupes.get(name, []) or [])
        if not values:
            inline = c.get("inline_lists") or {}
            for v_list in (inline.values() if isinstance(inline, dict) else []):
                if isinstance(v_list, list):
                    values.extend(v_list)
        # Cap à 8 valeurs pour lisibilité (les longues listes sont déjà
        # ailleurs dans le prompt)
        truncated_values = values[:8]
        suffix_more = f" (+{len(values) - 8} autres)" if len(values) > 8 else ""
        values_str = (
            ", ".join(f"`{v}`" for v in truncated_values) + suffix_more
            if truncated_values
            else "_(aucune valeur littérale)_"
        )
        # Résolution Phase 2.5 si dispo
        resolved_str = "_(non résolu Phase 2.5)_"
        cr_entry = cr_dict.get(name) if isinstance(cr_dict, dict) else None
        if isinstance(cr_entry, dict):
            best = cr_entry.get("best")
            if isinstance(best, dict) and best.get("table") and best.get("col"):
                vt = best.get("value_type") or "?"
                resolved_str = f"`{best.get('table')}.{best.get('col')}` (type=`{vt}`)"
        excl_tag = " [EXCLUSION]" if is_exclusion else ""
        lines.append(f"- **{name}**{excl_tag} = {values_str} → {resolved_str}")

    if not lines:
        return "_(aucun filtre/exclusion littéral identifié dans cette query)_"
    return "\n".join(lines)


def _build_concept_resolution_block(
    concept: str,
    concept_resolution: dict | None,
) -> str:
    """Formate la résolution Phase 2.5 pour UN concept, à injecter dans le
    prompt Phase 3 comme source autoritaire (table/col/type/samples déjà
    résolus data-driven, 0 LLM, 0 hallucination).

    Cf. task #67 : Phase 3 hésitait et posait des Q techniques (mapping
    table↔concept) parce qu'elle ne voyait pas la résolution Phase 2.5. En
    lui passant ce bloc en tête de prompt, on supprime l'ambiguïté en amont
    plutôt que de filtrer les Q en aval.

    3 cas :
      - Best résolu (résolution claire) → bloc "AUTORITAIRE — mapping résolu"
      - Disambiguation nécessaire (N candidates équivalentes) → bloc
        "AMBIGÜ — départage par probes empiriques"
      - Pas de résolution (concept absent de Phase 2.5) → bloc minimal +
        fallback sur rerank classique
    """
    if not concept_resolution:
        return (
            "_(Phase 2.5 non disponible — utilise le rerank Phase 2 et le DDL "
            "ci-dessous comme sources de mapping.)_"
        )
    cr_entry = concept_resolution.get(concept) if isinstance(concept_resolution, dict) else None
    if not isinstance(cr_entry, dict):
        return (
            f"_(Phase 2.5 n'a pas résolu le concept `{concept}`. Utilise le "
            f"rerank Phase 2 et le DDL ci-dessous pour cartographier les "
            f"candidates et génère des probes exploratoires.)_"
        )

    def _is_usable_candidate(cand: object) -> bool:
        """Une candidate Phase 2.5 est exploitable si elle a un nom de table
        ET un nom de colonne non-vides. Filtre les dict partiels/buggy
        (ex: ``{"table": None}``) qui produiraient un bloc ``?.?`` autoritaire
        — pire que pas de bloc du tout."""
        return isinstance(cand, dict) and bool(cand.get("table")) and bool(cand.get("col"))

    best_raw = cr_entry.get("best")
    best = best_raw if _is_usable_candidate(best_raw) else None
    top_candidates_raw = cr_entry.get("top_candidates") or []
    top_candidates = [c for c in top_candidates_raw if _is_usable_candidate(c)]
    requires_disamb = bool(cr_entry.get("requires_disambiguation"))
    low_conf = bool(cr_entry.get("low_confidence"))
    method = cr_entry.get("method") or "?"

    def _sanitize_sample(s: object) -> str:
        """Échappe les caractères qui casseraient le rendu markdown du prompt
        (backticks, newlines) et cap à 40 chars. Anti prompt-injection si un
        sample BDD contient des directives markdown."""
        ss = str(s).replace("`", "'").replace("\n", " ").replace("\r", " ").strip()
        return ss if len(ss) <= 40 else ss[:37] + "..."

    def _fmt_samples(samples: list) -> str:
        if not samples:
            return "_(aucun sample)_"
        return ", ".join(f"`{_sanitize_sample(s)}`" for s in samples[:5])

    def _fmt_candidate(cand: dict) -> str:
        table = _sanitize_sample(cand.get("table") or "?")
        col = _sanitize_sample(cand.get("col") or "?")
        vt = _sanitize_sample(cand.get("value_type") or "?")
        samples = cand.get("samples") or []
        return f"`{table}.{col}` (type=`{vt}`, samples: {_fmt_samples(samples)})"

    lines: list[str] = []
    if best and not requires_disamb:
        lines.append("**Résolution AUTORITAIRE (Phase 2.5 data-driven, 0 LLM)** :")
        lines.append(f"- Best match : {_fmt_candidate(best)}")
        if low_conf:
            lines.append(
                "- ⚠️ Confiance faible — valide empiriquement la résolution avec tes probes."
            )
        # Autres candidates (utiles pour validation comparative)
        others = [c for c in top_candidates if isinstance(c, dict) and c is not best][:3]
        if others:
            lines.append("- Autres candidates équivalentes (pour comparaison empirique) :")
            for c in others:
                lines.append(f"    - {_fmt_candidate(c)}")
        lines.append("")
        lines.append("**Consignes pour tes probes** :")
        lines.append(
            "- Tes probes VALIDENT cette résolution (distribution, % NULL, "
            "cardinalité, comparaison avec les autres candidates si pertinent)."
        )
        lines.append(
            "- Tu n'as PAS le droit de redemander à l'utilisateur quelle "
            "table/colonne porte ce concept — c'est résolu data-driven en amont."
        )
        return "\n".join(lines)

    # Disambiguation nécessaire (pas de best clair)
    valid_cands = [c for c in top_candidates if isinstance(c, dict)][:5]
    if valid_cands:
        lines.append("**Résolution AMBIGÜE (Phase 2.5 n'a pas pu départager)** :")
        lines.append(
            f"Méthode tentée : `{method}`. {len(valid_cands)} candidates équivalentes "
            f"— tu dois les départager EMPIRIQUEMENT via probes (pas via question à l'user) :"
        )
        for c in valid_cands:
            lines.append(f"- {_fmt_candidate(c)}")
        lines.append("")
        lines.append("**Consignes pour tes probes** :")
        lines.append(
            "- Génère des probes pour CHACUNE des candidates ci-dessus "
            "(distribution, count, NULL%) et compare empiriquement."
        )
        lines.append(
            "- Tu n'as PAS le droit de demander à l'utilisateur quelle "
            "table/colonne choisir — c'est exactement le travail empirique "
            "de tes probes."
        )
        return "\n".join(lines)

    # Aucune candidate exploitable
    return (
        f"_(Phase 2.5 n'a trouvé aucune candidate solide pour `{concept}` "
        f"(method={method}). Explore via le rerank Phase 2 + DDL ci-dessous "
        f"et génère des probes de cartographie.)_"
    )


async def phase_3_concept_factsheets(
    query: str,
    extracted: dict,
    scored: dict,
    reranks: dict,
    *,
    model_id: str,
    api_key: str,
    db_path: Path,
    max_probes_per_concept: int = 12,
    max_qa_loops: int = _PHASE_3_DEFAULT_MAX_QA_LOOPS,
    debug_traces: bool = False,
    use_sage: bool = False,
    concept_resolution: dict | None = None,
    filtered: dict | None = None,
) -> dict:
    """Phase 3 — Concept Fact Sheets (probes par concept, parallèle).

    Pour chaque concept (depuis les reranks Phase 2) :
    1. Construit un user_prompt FACTSHEET dédié à ce concept (avec DDL des
       top entités, FK subgraph, bloc concept v2_text, et le bloc autoritaire
       de résolution Phase 2.5).
    2. 1 appel LLM → JSON {probes, interpretation, ask_user}.
    3. Si `ask_user` non vide → **AUTO-SUBMIT empty pour chaque Q** (pas de
       bridge user en parallèle, cf. task #71) + re-call LLM avec le qa_block
       contenant Q + R="" → le LLM décide par lui-même. Les Q sont conservées
       dans qa_session avec `auto_submitted=True` pour le récap final.
    4. Exécute chaque probe (transpile T-SQL→SQLite + execute_sqlite + null_pct).
    5. Retourne la fiche concept (mode `degraded_no_probes` si LLM n'a généré
       aucune probe après le retry — Phase 4 doit alors compenser via
       concept_resolution).

    Tous les concepts tournent en parallèle (asyncio.gather) car indépendants.
    Aucune interaction utilisateur en mode parallèle — l'expérience UX serait
    cassée par 10+ questions simultanées (cf. task #71).

    Inputs :
        query   : requête NL
        extracted : output Phase 1.1+1.2 (pour `derivables`)
        scored  : output Phase 1.5 (v2_text — concept blocks + FK subgraph)
        reranks : output Phase 2 (per_concept ranking_top)
        filtered : output Phase 1.2.5 (drop_tables, drop_views). Quand fourni,
            les entités shortlistées par le rerank Phase 2 qui sont aussi dans
            drop_tables/drop_views sont retirées de top_entries — évite les
            probes Sage gaspillées sur tables/vues exclues en amont. Wiring
            task #68.
        concept_resolution : output Phase 2.5 (mapping concept→(table,col)
            data-driven). Quand fourni, son contenu est injecté EN TÊTE du
            prompt de chaque concept comme source autoritaire — le LLM
            Phase 3 ne refait pas le mapping et ne pose donc plus de Q
            techniques (cf. task #67).

    Output (dict) :
        - per_concept    : {concept: {interpretation, probes: [...],
                            ask_user: [...], raw_response, ...}}
        - formatted_block : str — toutes les fiches concaténées (pour Phase 4)
        - system_prompt  : str (debug)
        - prompts_per_concept : {concept: [user_prompts...]}
        - raw_responses  : {concept: [raw_responses...]}
    """
    from app.services.ai import user_qa_session as qa_session

    rerank_per_concept = (reranks or {}).get("per_concept", {}) or {}
    if not rerank_per_concept:
        raise RuntimeError("Phase 3 — reranks.per_concept vide (Phase 2 KO ?)")

    v2_text_raw = (scored or {}).get("v2_text", "")
    if not v2_text_raw:
        raise RuntimeError("Phase 3 — scored.v2_text vide (Phase 1.5 KO ?)")

    # Désobfuscation des valeurs avant transmission au LLM (sinon le LLM
    # voit `'SFGC PP'` mais la BDD a `'DOSSIER_A PAP'` → probes WHERE col='SFGC PP'
    # retournent 0 lignes silencieusement).
    # Filter sur les vraies valeurs explicites de l'utilisateur — value_mapping
    # fait 29M lignes, sans filter le load bloque 1+ minute.
    real_values_filter = []
    for vs in (extracted or {}).get("groupes", {}).values():
        real_values_filter.extend(vs)
    anon_to_real = load_anon_to_real_map(real_values_filter=real_values_filter)
    if anon_to_real:
        v2_text = resolve_anon_in_text(v2_text_raw, anon_to_real)
        n_replaced = sum(1 for k in anon_to_real if f"'{k}'" in v2_text_raw)
        print(
            f"→ Phase 3 : désobfuscation des valeurs (mapping {len(anon_to_real)} entrées filtrées, ≥{n_replaced} remplacements possibles dans v2_text)",
            flush=True,
        )
    else:
        v2_text = v2_text_raw
        print(
            "⚠ Phase 3 : value_mapping vide ou aucune valeur explicite — pas de désobfuscation",
            flush=True,
        )

    # FK subgraph commun à toutes les fiches (déjà filtré aux entités shortlistées)
    fk_subgraph = _extract_fk_subgraph_from_v2(v2_text)
    if not fk_subgraph:
        print("⚠ Phase 3 — sous-graphe FK introuvable dans scored.v2_text", flush=True)
        fk_subgraph = "_(non extrait)_"

    # Par-concept blocks (top entités + FvEx/FvCo/ColEx/ColCo)
    concept_blocks = _parse_rerank_concept_blocks(v2_text)

    # Derivables pour annoter les concepts calculés par formule
    derivables = (extracted or {}).get("derivables", {}) or {}

    # Valeurs explicites en clair (anti-obfuscation côté prompt)
    explicit_values_block_text = build_explicit_values_block(extracted)

    # PRÉFIXE STABLE pour le cache Anthropic — commun à tous les N appels
    # Phase 3 parallèles. Économise les input tokens (le préfixe est facturé
    # une seule fois au lieu de N fois).
    # Task #70 — bloc filtres globaux dans le préfixe (commun à tous les
    # concepts) pour que CHAQUE LLM Phase 3 voie où sont résolues les valeurs
    # littérales de la query (ex: FN → LignesFactures.lfaCodeStatistique).
    # Empêche les Q « où existe FN ? » quand un concept measure (facturation)
    # est exploré alors que l'info est dans le concept-voisin (code statistique
    # exclusion).
    global_filters_block = _build_global_filters_block(extracted, concept_resolution)
    factsheet_cache_prefix = FACTSHEET_USER_PREFIX_TEMPLATE.format(
        user_query=query,
        explicit_values_block=explicit_values_block_text,
        global_filters_block=global_filters_block,
        fk_context=fk_subgraph,
    )

    concepts_to_run = list(rerank_per_concept.keys())
    print(
        f"→ Phase 3 : {len(concepts_to_run)} concept(s) — fact sheets en parallèle (cache prefix : {len(factsheet_cache_prefix):,} chars)",
        flush=True,
    )

    # Wiring task #68 : entités droppées par Phase 1.2.5 (filtered) à exclure
    # du ranking_top avant probes — évite les probes Sage gaspillées sur des
    # tables/vues que la phase amont a déjà jugées hors-sujet (mais que le LLM
    # Phase 2 rerank a réinjectées par biais lexical).
    dropped_entities: set[str] = set()
    if isinstance(filtered, dict):
        for key in ("drop_tables", "drop_views"):
            for name in filtered.get(key) or []:
                if isinstance(name, str) and name:
                    dropped_entities.add(name)
    if dropped_entities:
        print(
            f"→ Phase 3 : {len(dropped_entities)} entité(s) droppée(s) par "
            f"Phase 1.2.5 exclue(s) des probes",
            flush=True,
        )

    per_concept: dict[str, dict] = {}
    prompts_per_concept: dict[str, list[str]] = {}
    raw_per_concept: dict[str, list[str]] = {}

    async def _factsheet_for_concept(c: str) -> tuple[str, dict, list[str], list[str]]:
        """Génère la fiche concept pour `c`. Retourne (concept, factsheet, prompts, raws).

        Retourne factsheet avec mode='error' si LLM/parse fail (jamais raise).
        """
        # Top entités du concept depuis reranks
        rerank_payload = rerank_per_concept.get(c, {}) or {}
        top_entries_raw = rerank_payload.get("ranking_top", []) or []
        # Wiring task #68 : exclure les entités droppées par Phase 1.2.5
        # (LLM Phase 2 peut les réinjecter par biais lexical → probes
        # Sage gaspillées sur tables hors-sujet).
        if dropped_entities:
            top_entries = [e for e in top_entries_raw if e.get("entity") not in dropped_entities]
        else:
            top_entries = list(top_entries_raw)
        top_entity_names: list[str] = [e.get("entity") for e in top_entries[:8] if e.get("entity")]

        # Top entities formatté pour le prompt (kind + name + rationale)
        top_lines = []
        for entry in top_entries[:8]:
            rank = entry.get("rank", "?")
            kind = entry.get("kind", "?")
            ent = entry.get("entity", "?")
            rationale = (entry.get("rationale", "") or "")[:200]
            top_lines.append(f"  #{rank} [{kind}] {ent} — {rationale}")
        top_entities_block = "\n".join(top_lines) or "_(aucune top entité — Phase 2 vide ?)_"

        # DDL des top entités
        schema_context = _build_ddl_for_entities(top_entity_names, db_path, max_entities=10)
        if not schema_context:
            schema_context = "_(DDL indisponible — BDD locale absente ?)_"

        # Inventaire colonnes en bullets — complément du DDL pour rendre les
        # noms de colonnes plus saillants (anti-hallucination LLM Phase 3).
        # Cf. incident 2026-05-09 : LLM extrapolait `grpCode` au lieu de
        # `grpCodeGroupe` malgré le DDL fourni.
        columns_inventory = _build_columns_inventory_for_entities(
            top_entity_names, db_path, max_entities=10
        )
        if not columns_inventory:
            columns_inventory = ""

        # FvEx context = le bloc concept du v2_text (déjà inclut FvEx + FvCo + ColEx)
        fvex_context = _extract_fvex_for_concept(concept_blocks.get(c, ""))
        if not fvex_context:
            fvex_context = "_(bloc concept v2_text introuvable)_"

        # Derivable info — 1 phrase si concept calculé
        if c in derivables:
            sources = derivables[c]
            derivable_info = (
                f"⚠️ **Concept dérivable** : `{c}` est calculé par formule depuis "
                f"d'autres concepts ({', '.join(sources)}). Il n'a probablement PAS "
                f"de table dédiée — explore la formule dérivante plutôt que de "
                f"chercher une table {c}."
            )
        else:
            derivable_info = ""

        # Bloc résolution Phase 2.5 — source AUTORITAIRE de mapping
        # concept→(table,col) dans le prompt (cf. task #67). Ce bloc supprime
        # en amont les ambiguïtés techniques qui poussaient Phase 3 à poser
        # des questions de mapping à l'utilisateur.
        concept_resolution_block = _build_concept_resolution_block(c, concept_resolution)

        prompts_for_c: list[str] = []
        raws_for_c: list[str] = []
        last_factsheet: dict | None = None

        for loop_idx in range(max_qa_loops + 1):
            user_prompt = FACTSHEET_USER_TEMPLATE.format(
                runtime_context=_build_runtime_context_block(),
                concept=c,
                derivable_info=derivable_info or "_(concept non dérivable)_",
                concept_resolution_block=concept_resolution_block,
                top_entities_for_concept=top_entities_block,
                schema_context=schema_context,
                columns_inventory=columns_inventory,
                fvex_context=fvex_context,
            )
            # Append session Q/A — DÈS la 1ère passe (task #72 wiring qa étanche).
            # Avant : `if loop_idx > 0` masquait les Q/A des phases amont à la
            # 1ère passe → le LLM Phase 3 pouvait reposer une Q déjà répondue en
            # Phase 1.2.5 / 1.2.6. Maintenant on injecte toujours.
            qa_block = qa_session.format_for_prompt()
            if qa_block:
                user_prompt += "\n\n# Réponses utilisateur reçues\n\n" + qa_block

            # Sauve la concaténation prefix+user pour traçabilité dans run.md
            prompts_for_c.append(factsheet_cache_prefix + "\n" + user_prompt)

            try:
                raw = await call_llm(
                    FACTSHEET_SYSTEM_PROMPT,
                    user_prompt,
                    model_id=model_id,
                    api_key=api_key,
                    caller="pipeline_p3_factsheet",
                    max_tokens=6000,
                    cache_prefix=factsheet_cache_prefix,
                )
            except Exception as e:
                print(f"  ❌ {c} — erreur LLM : {e}", flush=True)
                last_factsheet = {"concept": c, "mode": "error", "error": str(e)}
                break
            raws_for_c.append(raw)

            data = parse_llm_json(raw)
            if data is None:
                print(f"  ⚠️ {c} — JSON parse échoué", flush=True)
                last_factsheet = {"concept": c, "mode": "parse_error", "raw": raw}
                break

            ask_user = data.get("ask_user") or []
            probes_raw = data.get("probes") or []

            # Si questions ET on a encore un budget de loop, **AUTO-SUBMIT VIDE**
            # (task #71) : Phase 3 tourne en parallèle (asyncio.gather) sur N
            # concepts → bridger N×3 Q vers l'user en simultané = UX cassée. À la
            # place on submit une réponse vide pour chaque Q, EXACTEMENT comme
            # si l'user avait validé sans rien taper (« laisser vide pour
            # décider »). Le LLM Phase 3 retry avec ces R="" dans le qa_block
            # et décide par lui-même. Les Q + R="" restent dans `qa_session` →
            # consultables dans le récap final pour que l'user puisse corriger
            # ciblé en aval.
            if ask_user and loop_idx < max_qa_loops:
                print(
                    f"  🤖 {c} — {len(ask_user)} question(s) Phase 3 — "
                    f"auto-submit vide (parallèle, pas de bridge user) :",
                    flush=True,
                )
                # Normalise en list[str] (les questions peuvent être dict).
                qs_text: list[str] = []
                for q in ask_user:
                    text = q if isinstance(q, str) else (q.get("question") or str(q))
                    print(f"    [{c}] {text}")
                    qs_text.append(text)
                # Pas de bridge user : R="" pour toutes les Q + flag
                # `auto_submitted=True` (cf. adversarial finding C1) — le
                # format_for_prompt rendra ces entries sous un header dédié
                # « auto-soumises vides, décide toi-même », évitant la confusion
                # avec de vraies précisions utilisateur.
                for text in qs_text:
                    qa_session.add_qa(
                        "phase_3_factsheet",
                        text,
                        "",
                        concept=c,
                        auto_submitted=True,
                    )
                continue  # retry avec le bloc Q/A (R="")

            # Sinon on a les probes — on continue
            interpretation = data.get("interpretation") or ""

            # Cap probes
            if len(probes_raw) > max_probes_per_concept:
                print(
                    f"  ⚠ {c} : LLM a généré {len(probes_raw)} probes — cap à "
                    f"{max_probes_per_concept}",
                    flush=True,
                )
                probes_raw = probes_raw[:max_probes_per_concept]

            # Adversarial finding C2 du 2026-05-21 : Phase 3 peut converger
            # sur `mode="ok"` avec `probes_raw=[]` quand le LLM persiste à
            # poser des questions à chaque loop sans jamais émettre de probe.
            # On marque alors le factsheet `degraded_no_probes` au lieu de
            # `ok` silencieux — Phase 4 peut ainsi détecter le trou empirique
            # et compenser (degraded block, fallback sur concept_resolution
            # seul, etc.) au lieu d'halluciner.
            mode_label = "degraded_no_probes" if not probes_raw else "ok"
            if mode_label == "degraded_no_probes":
                print(
                    f"  ⚠ {c} : factsheet vide après {loop_idx + 1} loop(s) — "
                    f"LLM n'a généré AUCUNE probe. Phase 4 devra compenser "
                    f"via concept_resolution sans empirique pour ce concept.",
                    flush=True,
                )
            last_factsheet = {
                "concept": c,
                "mode": mode_label,
                "interpretation": interpretation,
                "ask_user": ask_user,
                "probes_raw": probes_raw,
                "top_entity_names": top_entity_names,
            }
            break

        if last_factsheet is None:
            last_factsheet = {"concept": c, "mode": "max_loops_exceeded"}

        return c, last_factsheet, prompts_for_c, raws_for_c

    # Lance les N concepts en parallèle (Q/A interactifs séquentiels via lock)
    print(
        f"→ Lancement de {len(concepts_to_run)} factsheets LLM en parallèle...",
        flush=True,
    )
    _check_cancel_or_raise()  # fix #16 — sortie rapide si user cancel
    results = await asyncio.gather(
        *[_factsheet_for_concept(c) for c in concepts_to_run],
        return_exceptions=False,
    )

    _check_cancel_or_raise()

    # Exécute les probes pour chaque fiche en mode "ok"
    schema_map = get_sqlite_schema(db_path) if db_path.exists() else {}

    # Si use_sage : ouvrir UN connecteur Sage pour toutes les probes (vs un par
    # probe = 100+ connexions). On exécute alors le T-SQL en natif (pas de
    # transpile vers SQLite). Sinon : execute_sqlite sur sage_copy.db.
    sage_conn = None
    sage_conn_is_singleton = False  # noqa: F841 — utilisé pour skip close à la fin
    if use_sage:
        # IMPORTANT : passer par ``get_sage_connector()`` (singleton) qui
        # respecte ``_force_sqlite_mode`` posé par /admin/database. Sans
        # ça, l'admin a beau switch en mode SQLite local, la pipeline
        # essaie quand même le vrai SQL Server → timeout/crash si Sage
        # est inaccessible. Le singleton retourne ``SqliteSageConnector``
        # quand le mode admin l'exige (interface 100% compatible : host,
        # database, execute, close).
        from app.services.database.sage_connector import (
            get_current_sage_mode,
            get_sage_connector,
        )

        sage_conn = get_sage_connector()
        sage_conn_is_singleton = True
        mode = get_current_sage_mode()
        if mode == "sqlite":
            print(
                f"→ Phase 3 : probes exécutées sur SQLite local "
                f"(mode admin SQLite ; database={sage_conn.database})",
                flush=True,
            )
        else:
            print(
                f"→ Phase 3 : probes exécutées sur VRAIE Sage Coala "
                f"({sage_conn.host}, DB={sage_conn.database})",
                flush=True,
            )
    else:
        print(f"→ Phase 3 : probes exécutées sur {db_path.name} (mirror SQLite)", flush=True)

    # PERF (2026-05-21, task #88) — Probes Sage en PARALLÈLE.
    # Avant : double boucle for séquentielle (21 concepts × 8 probes × ~5s = 12-15 min).
    # Après : asyncio.gather sur toutes les probes ; le sémaphore Sage
    # (_SAGE_MAX_CONCURRENT=5) throttle naturellement à 5 requêtes concurrentes,
    # ce qui divise par ~5-10 le temps d'exécution sur Phase 3.
    # Mitigation hang : asyncio.wait_for(60s) par probe — coupe les requêtes qui
    # scannent une table monstrueuse sans timeout côté pyodbc cursor.

    # Étape 1 — Construire la liste de probes à exécuter et initialiser
    # `factsheet["probes"]` (liste mutée par append en parallèle ; safe en
    # async monothread).
    probe_tasks: list[tuple[str, dict, dict]] = []
    for c, factsheet, prompts, raws in results:
        prompts_per_concept[c] = prompts
        raw_per_concept[c] = raws

        if factsheet.get("mode") != "ok":
            per_concept[c] = factsheet
            continue

        probes_raw = factsheet.pop("probes_raw", [])
        factsheet["probes"] = []  # initialisée vide, remplie en parallèle
        per_concept[c] = factsheet
        for q in probes_raw:
            probe_tasks.append((c, factsheet, q))

    if probe_tasks:
        print(
            f"→ Phase 3 : exécution de {len(probe_tasks)} probes en parallèle "
            f"(throttle Sage = {_PHASE_3_PROBE_TIMEOUT_S}s / probe).",
            flush=True,
        )
    _check_cancel_or_raise()

    async def _exec_one_probe(
        concept_name: str,
        factsheet_ref: dict,
        q: dict,
        probe_index: int,
    ) -> None:
        """Exécute une probe et l'ajoute (append) à ``factsheet_ref['probes']``.

        Adversarial fix B3 : TOUT le corps est wrappé dans un try/except global
        — un échec ne tue jamais les autres probes en cours (chaque coroutine
        retourne None proprement, même sur bug interne dans validate_sql ou
        analyze_null_ratios).

        Adversarial fix C5 : check cancel au début et après l'exec → un Ctrl+C
        utilisateur prend effet au prochain yield (pas après les 60s du gather).

        Adversarial fix C2 : ``print()`` sérialisé via lock partagé pour
        éviter l'interleaving des lignes de log entre coroutines concurrentes.
        """
        import time as _time

        # Adversarial fix C4 : id stable même si LLM en a oublié.
        probe: dict = {
            "id": _stable_probe_id(q, probe_index),
            "purpose": q.get("purpose", ""),
            "hypothesis": q.get("hypothesis", ""),
            "sql": q.get("sql", ""),
        }

        async def _log(line: str) -> None:
            """Print sérialisé via lock partagé."""
            async with _get_phase_3_print_lock():
                print(line, flush=True)

        try:
            # Adversarial fix C5 — cancel rapidement détecté au démarrage de
            # chaque probe (pas qu'avant/après le gather).
            _check_cancel_or_raise()

            sql = probe["sql"]
            if not sql.strip():
                probe["executed"] = False
                probe["error"] = "sql vide"
                probe["row_count"] = 0
                factsheet_ref["probes"].append(probe)
                return

            if schema_map:
                validation = validate_sql_against_schema(sql, schema_map)
                if validation:
                    probe["validation_warnings"] = validation
                # Validation colonnes : rejette la probe AVANT exécution si le
                # LLM a halluciné un nom de colonne (cf. incident 2026-05-09).
                col_warnings, unknown_cols = validate_sql_columns_against_schema(
                    sql, schema_map
                )
                if unknown_cols:
                    probe["executed"] = False
                    probe["error"] = "rejected_unknown_columns: " + "; ".join(
                        f"{u['column']} sur {u['table']} "
                        f"(suggestions: {', '.join(u['alternatives']) or '(none)'})"
                        for u in unknown_cols
                    )
                    probe["row_count"] = 0
                    probe["columns"] = []
                    probe["sample_rows"] = []
                    probe["null_pct"] = {}
                    probe["duration_sec"] = 0.0
                    probe["unknown_columns"] = unknown_cols
                    if col_warnings:
                        probe["validation_warnings"] = (
                            probe.get("validation_warnings") or []
                        ) + col_warnings
                    factsheet_ref["probes"].append(probe)
                    await _log(
                        f"  ⚠ [{concept_name}] {probe['id']} : probe rejetée "
                        f"(colonnes inconnues : "
                        f"{', '.join(u['column'] for u in unknown_cols)})"
                    )
                    return

            if sage_conn is not None:
                # T-SQL natif sur SQL Server. asyncio.wait_for cap par probe.
                # Limite connue (cf. constante header) : le thread pyodbc peut
                # continuer après le timeout — la query continue côté serveur
                # jusqu'à sa fin naturelle. C'est rare (< 5% des probes) et
                # acceptable face au gain de parallélisme global.
                t0 = _time.time()
                try:
                    result = await asyncio.wait_for(
                        sage_conn.execute(sql, max_rows=200, bypass_admin_cap=True),
                        timeout=_PHASE_3_PROBE_TIMEOUT_S,
                    )
                    rows = [tuple(r) for r in result.rows]
                    cols = list(result.columns)
                    exec_err = None
                except asyncio.TimeoutError:
                    rows = []
                    cols = []
                    exec_err = f"probe_timeout_{_PHASE_3_PROBE_TIMEOUT_S}s"
                except Exception as e:
                    rows = []
                    cols = []
                    exec_err = f"{type(e).__name__}: {e}"
                dur = _time.time() - t0
            else:
                # Adversarial fix B2 : execute_sqlite est SYNCHRONE — sans
                # run_in_executor, l'event loop est bloqué pendant chaque
                # probe → annule TOUT le bénéfice du gather + ralenti d'autres
                # opérations async en cours.
                sqlite_sql, transpile_err = transpile_tsql_to_sqlite(sql)
                if transpile_err:
                    probe["transpile_warning"] = transpile_err
                loop = asyncio.get_running_loop()
                try:
                    rows, cols, exec_err, dur = await asyncio.wait_for(
                        loop.run_in_executor(
                            None,  # default executor (asyncio thread pool)
                            execute_sqlite,
                            sqlite_sql,
                            db_path,
                        ),
                        timeout=_PHASE_3_PROBE_TIMEOUT_S,
                    )
                except asyncio.TimeoutError:
                    rows = []
                    cols = []
                    exec_err = f"probe_timeout_{_PHASE_3_PROBE_TIMEOUT_S}s"
                    dur = float(_PHASE_3_PROBE_TIMEOUT_S)

            probe["executed"] = exec_err is None
            probe["error"] = exec_err
            probe["columns"] = cols
            probe["row_count"] = len(rows)
            probe["sample_rows"] = [list(r) for r in rows[:10]]
            probe["duration_sec"] = round(dur, 3)
            if rows and cols:
                _, null_stats = analyze_null_ratios(
                    rows,
                    cols,
                    threshold_global=1.0,
                    threshold_per_column=1.0,
                    min_rows=1,
                )
                probe["null_pct"] = null_stats.get("per_column_null_pct", {})
            else:
                probe["null_pct"] = {}

            factsheet_ref["probes"].append(probe)
            marker = "✓" if probe["executed"] else "✗"
            await _log(
                f"  {marker} [{concept_name}] {probe['id']} : {probe['row_count']} rows "
                f"({dur:.2f}s) — {probe['purpose'][:60]}"
            )
            # Adversarial fix C5 — re-check cancel après l'exec (avant de
            # potentiellement démarrer une autre probe via le sémaphore).
            _check_cancel_or_raise()

        except asyncio.CancelledError:
            # Propager la cancellation (cancel_event ou cancel parent) — c'est
            # un signal de sortie, pas un bug interne à catcher.
            raise
        except Exception as exc:  # noqa: BLE001 — adversarial fix B3
            # Toute autre exception (validate_sql_*, analyze_null_ratios,
            # bug logique) → marquer probe failed, ne JAMAIS propager dans
            # le gather (sinon tous les siblings sont cancellés).
            probe.setdefault("executed", False)
            probe["error"] = f"internal_exception: {type(exc).__name__}: {exc}"
            probe.setdefault("row_count", 0)
            factsheet_ref["probes"].append(probe)
            try:
                await _log(
                    f"  ✗ [{concept_name}] {probe['id']} : internal exception — "
                    f"{type(exc).__name__}: {str(exc)[:120]}"
                )
            except Exception:  # noqa: BLE001 — log best-effort
                pass

    if probe_tasks:
        # Adversarial fix B3 : `_exec_one_probe` catche ALL exceptions en
        # interne (wrapper try/except global) → un échec n'arrête pas les
        # siblings. ``return_exceptions=False`` reste OK car aucune coroutine
        # ne raise sauf asyncio.CancelledError (qu'on veut propager).
        # L'index ``i`` est passé pour générer un id stable de fallback si
        # le LLM a oublié l'id (cf. ``_stable_probe_id``).
        await asyncio.gather(
            *[
                _exec_one_probe(c, fs, q, i)
                for i, (c, fs, q) in enumerate(probe_tasks)
            ],
            return_exceptions=False,
        )
    _check_cancel_or_raise()

    # Tri des probes par id pour préserver l'ordre déterministe dans les
    # snapshots run.json (post-gather, l'ordre dépend des temps d'exécution).
    for fs in per_concept.values():
        if isinstance(fs, dict) and isinstance(fs.get("probes"), list):
            fs["probes"].sort(key=lambda p: str(p.get("id") or ""))

    # P1 #9 (2026-05-30) — RECALCUL EMPIRIQUE du mode APRÈS exécution des probes.
    # Le `mode="ok"` posé en amont (_factsheet_for_concept) signifie seulement
    # « le LLM a généré des probes », PAS « les probes ont prouvé quelque
    # chose ». Sans ce recalcul, un concept dont TOUTES les probes échouent
    # ensuite (colonnes inconnues rejetées, 0 ligne, timeout, erreur SQL) reste
    # `mode="ok"` → Phase 4 le croit résolu et compose à l'aveugle. La décision
    # est déléguée à ``_phase3_recompute_factsheet_mode`` (pur, testable).
    for c, fs in per_concept.items():
        if _phase3_recompute_factsheet_mode(fs):
            print(
                f"  ⚠ Phase 3 [{c}] : mode rétrogradé 'ok'→'degraded_empirical' "
                f"({fs.get('degraded_reason')}).",
                flush=True,
            )

    # Fermeture du connecteur Sage (si ouvert et NON singleton).
    # IMPORTANT : le singleton ``get_sage_connector()`` est partagé avec
    # le reste de l'app — le close fermerait la connexion pour tous les
    # autres callers (autre user qui fait execute_sql, etc.). Le shutdown
    # serveur s'occupe de fermer le singleton au lifecycle global.
    if sage_conn is not None and not sage_conn_is_singleton:
        try:
            await sage_conn.close()
        except Exception:
            pass

    # Format un bloc texte global (pour Phase 4 et debug)
    formatted_block = _build_factsheets_block(per_concept)

    if debug_traces and raw_per_concept:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        for c, raws in raw_per_concept.items():
            slug = slug_from_concept(c)
            (DEBUG_TRACES_DIR / f"phase_3_factsheet_{slug}.raw.txt").write_text(
                "\n\n--- LOOP SEPARATOR ---\n\n".join(raws or []),
                encoding="utf-8",
            )
        (DEBUG_TRACES_DIR / "phase_3_factsheets_block.txt").write_text(
            formatted_block,
            encoding="utf-8",
        )

    return {
        "per_concept": per_concept,
        "formatted_block": formatted_block,
        "system_prompt": FACTSHEET_SYSTEM_PROMPT,
        "prompts_per_concept": prompts_per_concept,
        "raw_responses": raw_per_concept,
    }


def _probe_is_proven(p: object) -> bool:
    """``True`` si une probe est EXPLOITABLE : un dict exécuté (``executed`` non
    ``False``), sans erreur, ayant renvoyé ≥1 ligne.

    SSoT du prédicat « probe probante » — partagé par
    ``_phase3_recompute_factsheet_mode`` (rétrogradation du mode) et
    ``_phase4_format_one_factsheet`` (affichage du contexte). Centralisé pour
    éviter une dérive entre les deux call-sites (review snapshot 20b8902 : avant,
    le prédicat était dupliqué à l'identique aux deux endroits)."""
    return (
        isinstance(p, dict)
        and p.get("executed") is not False
        and not p.get("error")
        and (p.get("row_count") or 0) > 0
    )


def _phase3_recompute_factsheet_mode(factsheet: dict) -> bool:
    """P1 #9 — Recalcule EMPIRIQUEMENT le mode d'un factsheet après exécution
    des probes. Mute ``factsheet`` en place. Retourne True si rétrogradé.

    Le ``mode="ok"`` posé en amont signifie seulement « le LLM a généré des
    probes », pas « les probes ont prouvé quelque chose ». Si AUCUNE probe n'a
    apporté de preuve (exécutée sans erreur ET ≥1 ligne), on rétrograde en
    ``degraded_empirical`` + ``degraded_reason`` lisible par Phase 4 — au lieu
    de laisser un faux « ok » tromper le composeur SQL.

    No-op (retourne False) si : pas un dict, ou mode != "ok", ou au moins une
    probe probante existe. Générique : 0 nom BDD, raisonne sur les résultats
    d'exécution (``executed`` / ``error`` / ``row_count``).
    """
    if not isinstance(factsheet, dict) or factsheet.get("mode") != "ok":
        return False
    probes = factsheet.get("probes") or []
    proven = [p for p in probes if _probe_is_proven(p)]
    if proven:
        return False
    if not probes:
        reason = "aucune probe exécutée"
    elif all(isinstance(p, dict) and p.get("error") for p in probes):
        # Anti-fuite PII (review adversariale du snapshot 20b8902) : NE PAS
        # réinjecter le texte d'erreur SQL Server BRUT dans ``degraded_reason`` —
        # il peut contenir des valeurs métier (ex: « Conversion failed ...
        # 'DUPONT' ... »). Ce ``degraded_reason`` part dans le prompt Phase 4
        # cloud, et ``_phase4_sanitize_llm_text`` ne fait que whitespace/markdown
        # (PAS d'anonymisation). On ne réinjecte donc que des CATÉGORIES
        # normalisées via la SSoT ``_categorize_sql_error`` — aucun fragment du
        # message serveur.
        # try/except défensif (review consolidée) : error_messages est stdlib-only
        # aujourd'hui (ne peut pas échouer), mais une régression d'import future ne
        # doit pas crasher toute la Phase 3 — on retombe sur un libellé générique
        # SANS texte serveur (la garantie anti-fuite PII reste tenue dans tous les cas).
        try:
            from app.services.data_access.error_messages import _categorize_sql_error

            _cats = sorted(
                {
                    _categorize_sql_error(None, str(p.get("error") or ""))
                    for p in probes
                    if isinstance(p, dict)
                }
            )
            reason = ("toutes les probes ont échoué (catégories : " + ", ".join(_cats) + ")")[:300]
        except Exception:  # noqa: BLE001 — ne jamais bloquer le downgrade sur la catégorisation
            reason = "toutes les probes ont échoué (erreur SQL)"
    else:
        reason = "aucune probe n'a renvoyé de ligne (0 résultat partout)"
    factsheet["mode"] = "degraded_empirical"
    factsheet["degraded_reason"] = reason
    return True


def _build_factsheets_block(per_concept: dict[str, dict]) -> str:
    """Concatène toutes les fiches concept en un bloc texte pour Phase 4.

    Format :
        ════════════════════════════════════════════════════════════════════
        FICHE CONCEPT : <concept>
        ════════════════════════════════════════════════════════════════════
        Top entités candidates : <list>
        Interprétation : <texte>
        Probes (N) :
          ─── P1 — <purpose> ───
          Hypothèse : <h>
          SQL :
          ```sql
          ...
          ```
          Résultat : 42 lignes (cols: a, b, c) en 0.05s
          Sample :
          a | b | c
          1 | x | y
          NULL% : col_x=82%
        (… probes suivantes …)
    """
    parts: list[str] = []
    parts.append("=" * 80)
    parts.append("FICHES CONCEPT — résultats empiriques par concept de la requête")
    parts.append("=" * 80)
    parts.append("")
    parts.append(
        "Chaque fiche concentre des probes T-SQL exécutées sur la BDD réelle "
        "pour éclairer un concept de la requête utilisateur. Utilise ces "
        "résultats pour construire le SQL final."
    )
    parts.append("")

    for concept, fs in per_concept.items():
        parts.append("=" * 80)
        parts.append(f"FICHE CONCEPT : {concept}")
        parts.append("=" * 80)
        mode = fs.get("mode", "?")
        if mode != "ok":
            parts.append(f"⚠️ Fiche en mode `{mode}` — pas de probes exploitables.")
            parts.append("")
            continue

        top_names = fs.get("top_entity_names", []) or []
        if top_names:
            parts.append(f"**Top entités candidates** : {', '.join(top_names)}")
        interp = fs.get("interpretation", "")
        if interp:
            parts.append(f"**Interprétation** : {interp}")
        ask_user = fs.get("ask_user", []) or []
        if ask_user:
            parts.append(f"**Questions posées à l'utilisateur** ({len(ask_user)})")
        parts.append("")

        probes = fs.get("probes", []) or []
        parts.append(f"**Probes ({len(probes)})** :")
        parts.append("")

        for p in probes:
            parts.append("─" * 80)
            parts.append(f"### {p.get('id', '?')} — {p.get('purpose', '(sans purpose)')}")
            parts.append("─" * 80)
            if p.get("hypothesis"):
                parts.append(f"**Hypothèse** : {p['hypothesis']}")
            parts.append("")
            parts.append("**SQL** :")
            parts.append("```sql")
            parts.append((p.get("sql", "") or "").strip())
            parts.append("```")
            parts.append("")
            if p.get("transpile_warning"):
                parts.append(f"⚠ Transpile T-SQL→SQLite : {p['transpile_warning']}")
            if p.get("validation_warnings"):
                parts.append("⚠ Validation contre schéma :")
                for w in p["validation_warnings"]:
                    parts.append(f"  - {w}")
            parts.append("")

            if not p.get("executed"):
                # Distinguer un REJET programmatique (validation a flag des colonnes
                # hallucinées par le LLM AVANT exécution) d'une vraie ERREUR
                # d'exécution (SQL Server / SQLite a renvoyé une erreur). Le LLM
                # Phase 4 doit réagir différemment :
                #   - rejet programmatique → utiliser les suggestions de colonnes
                #     pour reformuler ; la valeur user EXISTE peut-être quand même
                #   - erreur exec → la table/colonne est probablement le vrai
                #     problème
                err = p.get("error", "?") or ""
                if err.startswith("rejected_unknown_columns:"):
                    unknown = p.get("unknown_columns") or []
                    parts.append(
                        "⚠ **Probe rejetée par validation programmatique** "
                        "(le LLM Phase 3 a référencé des colonnes inexistantes "
                        "— pas une erreur SQL Server, l'exécution n'a PAS été "
                        "tentée) :"
                    )
                    for u in unknown:
                        alts = u.get("alternatives") or []
                        alt_str = ", ".join(alts) if alts else "(aucune proche)"
                        parts.append(
                            f"  - colonne hallucinée : `{u['column']}` sur "
                            f"`{u['table']}` — colonnes proches : {alt_str}"
                        )
                else:
                    parts.append(f"❌ **Erreur d'exécution SQL** : `{err}`")
                parts.append("")
                continue

            row_count = p.get("row_count", 0)
            cols = p.get("columns", []) or []
            sample = p.get("sample_rows", []) or []
            null_pct = p.get("null_pct", {}) or {}
            dur = p.get("duration_sec", 0.0)

            parts.append(
                f"**Résultat** : {row_count:,} ligne(s), {len(cols)} colonne(s), {dur:.2f}s"
            )
            if cols:
                parts.append(f"**Colonnes** : {', '.join(cols)}")
            if sample:
                parts.append("")
                parts.append(f"**Sample (top {len(sample)})** :")
                parts.append("```")
                for row in sample:
                    parts.append(" | ".join(str(c)[:60] for c in row))
                parts.append("```")
            else:
                parts.append("**Sample** : (aucune ligne retournée)")

            if null_pct:
                high_null = [(c, p) for c, p in null_pct.items() if p > 0]
                if high_null:
                    parts.append("")
                    parts.append("**Ratio NULL par colonne** :")
                    for col, pct in sorted(high_null, key=lambda x: -x[1]):
                        parts.append(f"  - `{col}` : {pct * 100:.0f}%")
            parts.append("")

        parts.append("")

    return "\n".join(parts)


# ─────────────────────────────────────────────────────────────────────
# NOUVELLE PHASE 4 — SQL Composer (1 LLM, fiches → SQL final)
# ─────────────────────────────────────────────────────────────────────


async def phase_4_compose_sql(
    query: str,
    factsheets: dict,
    scored: dict,
    reranks: dict,
    extracted: dict,
    *,
    model_id: str,
    api_key: str,
    db_path: Path,
    debug_traces: bool = False,
) -> dict:
    """Phase 4 — SQL Composer (mode LEGACY).

    ⚠️  DEPRECATED (todo #7, 2026-05-26)
    ═══════════════════════════════════════════════════════════════════
    Cette fonction est le mode LEGACY de la Phase 4 : le LLM produit du
    SQL libre en texte, extrait par regex ``` ```sql ... ``` ```. Pas de
    validation structurelle pré-exécution — hallucinations possibles sur
    les noms de tables/colonnes, JOINs cartésiens silencieux, etc.

    Le mode IR (``phase_4_compose_ir``) est désormais le DEFAULT — le LLM
    produit un JSON IR validé, et le SQL est composé en Python pur via
    ``ir_to_sql``. Zéro hallucination structurelle par construction.

    **Pourquoi conservé** : 3 tests (``test_phase3_qa_loops_runtime.py``
    aux lignes 253/303/348) passent encore ``"mode": "legacy"``
    explicitement. Une suppression brutale ferait fail ces tests + leur
    refactor est hors scope d'un cycle MVP.

    **Pour retirer définitivement** :
    1. Adapter les 3 tests pour utiliser ``"mode": "ir"`` ou supprimer
       les tests s'ils ne couvrent plus rien d'utile.
    2. Supprimer cette fonction + ``_extract_sql_from_llm_response`` +
       le branchement legacy dans ``_execute_phase`` ligne ~15765.
    3. Mettre à jour la doctrine dans CLAUDE.md.

    Production : le caller ``pipeline_runner.py`` utilise déjà
    ``PipelineMode.IR`` par défaut depuis avant ce changement, donc
    aucun utilisateur en prod ne tombe sur ce code.
    ═══════════════════════════════════════════════════════════════════

    1 appel LLM qui prend toutes les fiches concept + DDL/FK/FvEx/FvCo +
    valeurs explicites + dérivables + query NL et produit le SQL final.

    Output (dict) :
        - sql                : str — SQL exécutable
        - raw_response       : str — réponse LLM brute
        - system_prompt      : str (debug)
        - user_prompt        : str (debug)
        - formatted_factsheets : str — bloc des fiches inclus dans le prompt
    """
    fs_block = (factsheets or {}).get("formatted_block", "")
    if not fs_block:
        raise RuntimeError("Phase 4 — factsheets.formatted_block vide (Phase 3 KO ?)")

    v2_text_raw = (scored or {}).get("v2_text", "")
    if not v2_text_raw:
        raise RuntimeError("Phase 4 — scored.v2_text vide (Phase 1.5 KO ?)")

    # Désobfuscation pour Phase 4 (cohérence avec Phase 3) — résout `'SFGC PP'` en
    # `'DOSSIER_A PAP'` dans v2_text avant transmission au LLM.
    # Filter sur les vraies valeurs explicites — sinon load 29M lignes (~1 min).
    real_values_filter_p4 = []
    for vs in (extracted or {}).get("groupes", {}).values():
        real_values_filter_p4.extend(vs)
    anon_to_real = load_anon_to_real_map(real_values_filter=real_values_filter_p4)
    v2_text = resolve_anon_in_text(v2_text_raw, anon_to_real) if anon_to_real else v2_text_raw

    # Construire schema_context = DDL des top entités cumulées sur tous les concepts
    rerank_per_concept = (reranks or {}).get("per_concept", {}) or {}
    all_top_entities: list[str] = []
    seen: set[str] = set()
    for c, payload in rerank_per_concept.items():
        for entry in (payload.get("ranking_top") or [])[:5]:
            ent = entry.get("entity")
            if ent and ent not in seen:
                seen.add(ent)
                all_top_entities.append(ent)
    schema_context = (
        _build_ddl_for_entities(
            all_top_entities,
            db_path,
            max_entities=25,
        )
        or "_(DDL indisponible)_"
    )

    # FK subgraph
    fk_context = _extract_fk_subgraph_from_v2(v2_text) or "_(non extrait)_"

    # Valeurs explicites en clair (depuis extracted.groupes — vraies valeurs
    # mentionnées par l'utilisateur, jamais obfusquées). Concatène toutes
    # les valeurs en une liste plate pour les parsers FvEx/FvCo.
    explicit_values_block = build_explicit_values_block(extracted)
    groupes = (extracted or {}).get("groupes", {}) or {}
    all_explicit_values: list[str] = []
    for vs in groupes.values():
        all_explicit_values.extend(vs)

    # FvEx structurée — pour chaque valeur explicite, liste les (table, col)
    # où elle existe TELLE QUELLE en BDD. Le LLM utilise cette info pour
    # choisir la bonne colonne dans `WHERE col = 'val'` (cf. R29 du SYSTEM).
    fvex_context = build_fvex_context_from_v2(v2_text, all_explicit_values)
    # FvCo structurée — pour les filtres LIKE / NOT LIKE.
    fvco_context = build_fvco_context_from_v2(v2_text, all_explicit_values)

    # Concepts dérivables (cf. R30 — formule SQL pas JOIN dédié)
    derivables_block = build_derivables_block(extracted)

    # Task #72 — qa_block étanche cross-phase : injecter les Q/A obtenues en
    # amont (Phase 1.2.5 / 1.2.6 / Phase 3) pour que le SQL composé respecte
    # les précisions déjà données par l'utilisateur (variante de mesure,
    # définition de période, périmètre, etc. — selon le domaine de la BDD).
    from app.services.ai import user_qa_session as p4_qa_session

    p4_qa_block = p4_qa_session.format_for_prompt()
    p4_qa_block_inline = (p4_qa_block + "\n\n") if p4_qa_block else ""

    user_prompt = COMPOSE_SQL_USER_TEMPLATE.format(
        runtime_context=_build_runtime_context_block(),
        user_query=query,
        session_qa_block=p4_qa_block_inline,
        explicit_values_block=explicit_values_block,
        schema_context=schema_context,
        fk_context=fk_context,
        derivables_block=derivables_block,
        fvex_context=fvex_context,
        fvco_context=fvco_context,
        factsheets_block=fs_block,
    )

    print("→ Phase 4 : LLM compose le SQL final à partir des fiches concept...", flush=True)
    raw = await call_llm(
        COMPOSE_SQL_SYSTEM_PROMPT,
        user_prompt,
        model_id=model_id,
        api_key=api_key,
        caller="pipeline_p4_compose",
        max_tokens=8000,
    )

    # Extraire SQL : balises ```sql ... ``` prioritaire, sinon réponse brute
    sql = _extract_sql_from_llm_response(raw)

    if debug_traces:
        DEBUG_TRACES_DIR.mkdir(parents=True, exist_ok=True)
        (DEBUG_TRACES_DIR / "phase_4_compose.sql").write_text(sql, encoding="utf-8")
        (DEBUG_TRACES_DIR / "phase_4_compose_raw.txt").write_text(raw, encoding="utf-8")
        (DEBUG_TRACES_DIR / "phase_4_compose_user_prompt.txt").write_text(
            user_prompt,
            encoding="utf-8",
        )

    return {
        "sql": sql,
        "raw_response": raw,
        "system_prompt": COMPOSE_SQL_SYSTEM_PROMPT,
        "user_prompt": user_prompt,
        "formatted_factsheets": fs_block,
    }


def _extract_sql_from_llm_response(raw: str) -> str:
    """Extrait le SQL d'une réponse LLM.

    Cherche d'abord un bloc ```sql ... ``` (extraction propre),
    sinon retourne la réponse brute strippée. Si la réponse contient
    plusieurs blocs ```sql, garde le plus long (souvent le SQL final
    vs un exemple court).
    """
    if not raw:
        return ""
    matches = re.findall(r"```(?:sql|tsql|SQL|T-SQL)?\s*\n(.*?)\n```", raw, re.DOTALL)
    if matches:
        # Pick the longest block (heuristic : the final SQL is usually the largest)
        return max(matches, key=len).strip()
    return raw.strip()


# ─────────────────────────────────────────────────────────────────────
# ORCHESTRATEUR
# ─────────────────────────────────────────────────────────────────────


def _extract_candidate_tables_from_state(
    state: "PipelineState",
) -> set[str] | None:
    """Phase W.3 — extrait les tables shortlistées par Phase 2 (reranks).

    Lit ``state.reranks["per_concept"][<concept>]["ranking_top"]`` et collecte
    les ``entity`` dont ``kind in ("table", "view")``. Retourne ``None`` si
    aucune source disponible (= pas de filtrage, comportement legacy).

    Generic : aucun pattern lexical, aucun nom de table hardcodé. Si la
    structure de reranks change, retourne ``None`` (fallback gracieux —
    Phase 2.5 résout sur tout le schéma comme avant).

    **Anti-faux-silencieux** : si l'extraction réussit MAIS retourne un set
    vide (cas pathologique : reranks présent mais 0 entité shortlistée),
    on retourne ``None`` plutôt qu'un set vide. Un set vide passé à Phase
    2.5 ferait échouer toutes les résolutions silencieusement.
    """
    if state is None:
        return None
    reranks = getattr(state, "reranks", None)
    if not isinstance(reranks, dict):
        return None
    per_concept = reranks.get("per_concept")
    if not isinstance(per_concept, dict) or not per_concept:
        return None
    candidates: set[str] = set()
    for concept_name, data in per_concept.items():
        if not isinstance(data, dict):
            continue
        ranking_top = data.get("ranking_top")
        if not isinstance(ranking_top, list):
            continue
        for entry in ranking_top:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("kind")
            entity = entry.get("entity")
            # ``kind`` peut être "T"/"V" (Phase 2 actuelle) ou "table"/"view"
            # (variante future — accepté par tolérance). Bug pré-fix : seuls
            # "table"/"view" matchaient → set vide → None silencieux.
            if kind in ("T", "V", "table", "view") and isinstance(entity, str) and entity:
                candidates.add(entity)
    if not candidates:
        return None  # Anti-faux-silencieux : empty → fallback legacy.
    return candidates


async def run_pipeline(
    query: str,
    *,
    only_phase: str | None = None,
    resume: bool = False,
    no_clean: bool = False,
    block_all_views: bool = False,
    max_probes: int = 15,
    max_qa_loops: int = 2,
    phase_3_max_qa_loops: int = _PHASE_3_DEFAULT_MAX_QA_LOOPS,
    db_path: Path = SAGE_DB,
    debug_traces: bool = False,
    top_n: int = 3,
    concept_filter: str | None = None,
    dry_run: bool = False,
    use_sage: bool = False,
    mode: str = "legacy",
    output_dir: Path | None = None,
    cancel_event: "asyncio.Event | None" = None,
    progress_callback: "Callable[[str, str, dict | None], Awaitable[None]] | None" = None,
    additional_context: str | None = None,
    user_id: int | None = None,
) -> PipelineState:
    """Orchestre les 8 phases en fonction des flags.

    - Si `resume` : charge le run.json précédent et reprend après la
      dernière phase complétée.
    - Si `only_phase` : exécute UNE seule phase (lit run.json amont).
    - Sinon : run complet du début à la fin.

    Hooks d'orchestration externe (utilisés par
    ``app.services.ai.pipeline_runner`` pour intégration Iris) :

    - ``output_dir`` : dossier de sortie alternatif (défaut ``OUT_DIR``
      pour rétro-compat CLI). Permet ``outputs/runs/{run_id}/`` par run.
    - ``cancel_event`` : ``asyncio.Event`` ; ``set()`` provoque
      ``CancelledError`` au prochain check inter-phase.
    - ``progress_callback`` : ``await callback(phase_id, status, meta)``
      avec ``status ∈ {"start","complete","failed"}`` et ``meta`` dict
      optionnel (tokens, durée, artifact_path).

    Retourne `PipelineState` (état final).
    """
    # Validation amont des kwargs sensibles (fail-fast vs default silencieux).
    # ``phase_3_max_qa_loops`` doit valoir au moins 1 : la sémantique de la
    # boucle est ``range(N + 1)`` → N=0 produit 1 seul tour ET la garde
    # ``if loop_idx < max_qa_loops`` (0 < 0) refuse tout auto-submit, ce qui
    # tombe directement en degraded_no_probes si le LLM pose une Q. Aucun
    # usage utile de la valeur 0 : on bloque ici plutôt que de laisser une
    # surprise runtime aux callers.
    if phase_3_max_qa_loops < 1:
        raise ValueError(
            f"phase_3_max_qa_loops doit être >= 1 (reçu : "
            f"{phase_3_max_qa_loops}). Pour désactiver Phase 3 entièrement, "
            f"utilise --only-phase pour cibler une autre phase."
        )

    # Résolution des chemins (override ``output_dir`` ou défauts globaux)
    paths = _resolve_run_paths(output_dir)

    # Pose le cancel_event en ContextVar pour que les phases longues
    # (Phase 3 probes notamment) puissent appeler ``_check_cancel_or_raise()``
    # sans avoir à changer toutes les signatures (fix #16 review adv).
    cancel_token = _pipeline_cancel_event.set(cancel_event)
    # Pose l'identité du run en ContextVar (même rationale que cancel_event :
    # les phases profondes lisent user_id sans changer toutes les signatures).
    user_token = _pipeline_user_id.set(user_id)
    try:
        return await _run_pipeline_inner(
            query=query,
            only_phase=only_phase,
            resume=resume,
            no_clean=no_clean,
            block_all_views=block_all_views,
            max_probes=max_probes,
            max_qa_loops=max_qa_loops,
            phase_3_max_qa_loops=phase_3_max_qa_loops,
            db_path=db_path,
            debug_traces=debug_traces,
            top_n=top_n,
            concept_filter=concept_filter,
            dry_run=dry_run,
            use_sage=use_sage,
            mode=mode,
            paths=paths,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
            additional_context=additional_context,
        )
    finally:
        _pipeline_cancel_event.reset(cancel_token)
        _pipeline_user_id.reset(user_token)


async def _run_pipeline_inner(
    *,
    query: str,
    only_phase: str | None,
    resume: bool,
    no_clean: bool,
    block_all_views: bool,
    max_probes: int,
    max_qa_loops: int,
    phase_3_max_qa_loops: int,
    db_path: Path,
    debug_traces: bool,
    top_n: int,
    concept_filter: str | None,
    dry_run: bool,
    use_sage: bool,
    mode: str,
    paths: _RunPaths,
    cancel_event: "asyncio.Event | None",
    progress_callback: "Callable[[str, str, dict | None], Awaitable[None]] | None",
    additional_context: str | None = None,
) -> PipelineState:
    """Implémentation effective de ``run_pipeline``, sous ContextVar set."""

    # Setup state
    if resume or only_phase:
        # Phase 1.1+1.2 n'a pas de prerequisite amont — bootstrap fresh state
        # si seul cette phase est demandée et run.json absent. Sinon les autres
        # phases lèvent à juste titre sur run.json absent (elles ont besoin
        # d'artefacts amont).
        if only_phase == "1.1-1.2" and not paths.run_json.exists():
            state = PipelineState(query=query)
        else:
            state = PipelineState.load(paths.run_json)
            if not state.query:
                state.query = query  # tolérance si run.json incomplet
    else:
        if not no_clean:
            paths.run_json.unlink(missing_ok=True)
            paths.run_sql.unlink(missing_ok=True)
        state = PipelineState(query=query)

    # Q/A session — partagée entre Phase 1.2.5 (filter) et Phase 1.2.6
    # (curate). Reset à chaque nouveau run (sauf --resume qui conserve).
    # Le fingerprint est sha256(query) — détecte un nouveau run quand la
    # query change, même si le fichier session existe encore d'un ancien run.
    if not (resume or only_phase):
        from app.services.ai import user_qa_session as qa_session
        import hashlib

        fp = hashlib.sha256(state.query.encode("utf-8")).hexdigest() if state.query else None
        qa_session.init_session(src_fingerprint=fp)

    if dry_run:
        # Le dry-run global n'est pas implémenté pour le pipeline monolithique
        # (chaque phase ferait des appels LLM réels avec model_id="DRY-RUN" →
        # crash). Pour tester sans LLM, utiliser `--only-phase 1.3-1.4` ou
        # `1.5` (programmatiques, pas d'appel LLM) ou les anciens scripts via
        # `run_pipeline.py`. Fail-fast plutôt que comportement trompeur.
        raise SystemExit(
            "❌ --dry-run pas encore branché sur le mode monolithique.\n"
            "   Alternatives :\n"
            "   - Tester les phases programmatiques : `--only-phase 1.3-1.4` "
            "ou `--only-phase 1.5` (pas d'appel LLM)\n"
            "   - Tester par phase isolée avec un run.json existant : "
            "`--only-phase 1.2.6 --resume`"
        )

    # Credentials
    api_key = get_api_key()
    model_id = get_configured_model()

    # Liste des phases à exécuter
    if only_phase:
        phases_to_run = [
            (pid, attr, label) for pid, attr, label in PHASES_ORDER if pid == only_phase
        ]
        if not phases_to_run:
            valid = ", ".join(p[0] for p in PHASES_ORDER)
            raise SystemExit(f"❌ Phase inconnue : {only_phase}. Valides : {valid}")
    elif resume:
        last = state.last_completed_phase()
        if last is None:
            phases_to_run = list(PHASES_ORDER)
        else:
            idx = next(i for i, (pid, _, _) in enumerate(PHASES_ORDER) if pid == last)
            phases_to_run = list(PHASES_ORDER[idx + 1 :])
            print(
                f"→ Resume après phase {last} — reprend à {phases_to_run[0][0] if phases_to_run else '(rien)'}"
            )
    else:
        phases_to_run = list(PHASES_ORDER)

    # Boucle d'exécution
    for phase_id, attr, label in phases_to_run:
        # Check cancellation entre phases (l'event est posé par le runner
        # Iris quand l'utilisateur clique "Annuler" — la phase courante a
        # déjà fini, on sort avant la suivante).
        if cancel_event is not None and cancel_event.is_set():
            print(f"\n⚠ Pipeline annulée avant {label} (cancel_event set)", flush=True)
            state.save(paths.run_json)
            raise asyncio.CancelledError(f"pipeline cancelled before phase {phase_id}")

        print(f"\n{'=' * 80}\n▶  {label}\n{'=' * 80}", flush=True)
        if progress_callback is not None:
            try:
                await progress_callback(phase_id, "start", None)
            except Exception:  # noqa: BLE001
                logging.getLogger(__name__).exception(
                    "progress_callback(start) raised — pipeline continues"
                )

        t0 = time.time()
        try:
            result = await _execute_phase(
                phase_id,
                state,
                model_id=model_id,
                api_key=api_key,
                db_path=db_path,
                block_all_views=block_all_views,
                max_probes=max_probes,
                max_qa_loops=max_qa_loops,
                phase_3_max_qa_loops=phase_3_max_qa_loops,
                top_n=top_n,
                concept_filter=concept_filter,
                debug_traces=debug_traces,
                use_sage=use_sage,
                mode=mode,
                additional_context=additional_context,
            )
        except NotImplementedError as e:
            print(f"\n⚠ {e}", flush=True)
            print("→ Pipeline arrêté à la phase non convertie.", flush=True)
            if progress_callback is not None:
                try:
                    await progress_callback(phase_id, "failed", {"error_message": str(e)})
                except Exception:  # noqa: BLE001
                    pass
            state.save(paths.run_json)
            return state
        except asyncio.CancelledError:
            # Propagé depuis une phase qui a vu le cancel_event
            state.save(paths.run_json)
            raise
        except Exception as exc:  # noqa: BLE001
            # Toute autre exception : on notifie le callback puis on relève
            # pour que le caller décide de la suite (le runner Iris fail
            # le run, le CLI reraise via main()).
            if progress_callback is not None:
                try:
                    await progress_callback(phase_id, "failed", {"error_message": str(exc)})
                except Exception:  # noqa: BLE001
                    pass
            raise

        dur = time.time() - t0
        state.phase_durations[phase_id] = dur
        setattr(state, attr, result)
        state.save(paths.run_json)  # checkpoint après chaque phase
        print(f"\n[{label}] ✅ {dur:.1f}s — checkpoint saved", flush=True)

        if progress_callback is not None:
            # Métadonnées synthétiques par phase. Les coûts/tokens détaillés
            # ne sont pas exposés ici (phase-spécifique, dans les ``llm_calls``
            # du payload). Le runner peut enrichir via inspection du state
            # (ex : ``state.extracted["llm_calls"]``).
            meta: dict = {"duration_seconds": dur}
            try:
                await progress_callback(phase_id, "complete", meta)
            except Exception:  # noqa: BLE001
                logging.getLogger(__name__).exception(
                    "progress_callback(complete) raised — pipeline continues"
                )

    # SQL final → run.sql (humain) — priorité Phase 5 → Phase 3
    if state.sql_final and state.sql_final.get("sql"):
        state.final_sql = state.sql_final["sql"]
    if state.final_sql:
        paths.run_sql.write_text(state.final_sql, encoding="utf-8")
        try:
            print(f"\n→ SQL final écrit : {paths.run_sql.relative_to(ROOT)}")
        except ValueError:
            # output_dir hors de ROOT (test ou conteneur monté ailleurs)
            print(f"\n→ SQL final écrit : {paths.run_sql}")

    # Récap markdown lisible — concatène les trace_text de chaque phase
    # (équivalent monolithique des anciens fichiers extracted_terms.txt,
    # filtered_entities.txt, curated_terms.txt, search_results_test_v2.txt,
    # diagnose_loop.txt). Toujours écrit (pas de flag --debug-traces requis).
    try:
        run_md_text = _render_run_markdown(state)
        paths.run_md.write_text(run_md_text, encoding="utf-8")
        try:
            print(f"→ Récap humain écrit : {paths.run_md.relative_to(ROOT)}")
        except ValueError:
            print(f"→ Récap humain écrit : {paths.run_md}")
    except Exception as e:
        print(f"⚠ Génération run.md échouée (non-fatal) : {e}")

    state.save(paths.run_json)
    return state


def _render_run_markdown(state: PipelineState) -> str:
    """Construit un récap markdown lisible de toutes les phases.

    Concatène les `trace_text` / `search_text` / `v2_text` / `diagnose_log`
    issus des dicts d'état dans un format human-friendly. Sections par
    phase, code blocks pour le SQL, info sur les durées + statuts.
    """
    from datetime import datetime as _dt

    out: list[str] = []
    out.append(
        f"# Pipeline NL→SQL — Run du {_dt.fromtimestamp(state.started_at).strftime('%Y-%m-%d %H:%M:%S')}"
    )
    out.append("")
    out.append("## Query utilisateur")
    out.append("")
    out.append(f"> {state.query}")
    out.append("")

    # Timings
    if state.phase_durations:
        total = sum(state.phase_durations.values())
        out.append("## Durées par phase")
        out.append("")
        out.append("| Phase | Durée |")
        out.append("|---|---|")
        for pid, _attr, label in PHASES_ORDER:
            d = state.phase_durations.get(pid)
            if d is not None:
                out.append(f"| {label} | {d:.1f}s |")
        out.append(f"| **Total** | **{total:.1f}s** |")
        out.append("")

    # Phase 1.1+1.2 — Extract + Expand
    if state.extracted:
        out.append("## Phase 1.1+1.2 — Extract + Expand")
        out.append("")
        ex = state.extracted
        out.append(f"- **Termes Phase 1.1** : {len(ex.get('termes', []))}")
        out.append(f"- **Listo finale** (1.1 + expansions) : {len(ex.get('full_listo', []))}")
        out.append(f"- **Concepts** : {', '.join(ex.get('groupes', {}).keys())}")
        if ex.get("derivables"):
            out.append(f"- **Dérivables** : {len(ex['derivables'])} concept(s) skippé(s) en search")
        out.append("")
        # Bloc structuré : les 4 appels LLM (1 extract + 3 expand passes)
        # affichés un par un en repliable. Plus lisible que le trace_text brut.
        llm_calls = ex.get("llm_calls", []) or []
        if llm_calls:
            out.append(
                f"<details><summary>📨 {len(llm_calls)} appels LLM envoyés en Phase 1.1+1.2 (cliquer pour déplier)</summary>"
            )
            out.append("")
            for i, call in enumerate(llm_calls, 1):
                label = call.get("label", f"Call #{i}")
                temp = call.get("temperature")
                dur = call.get("duration_sec")
                meta_bits = []
                if temp is not None:
                    meta_bits.append(f"temp={temp}")
                if dur is not None:
                    meta_bits.append(f"{dur}s")
                meta = f" ({', '.join(meta_bits)})" if meta_bits else ""
                out.append(f"#### Appel #{i} — {label}{meta}")
                out.append("")
                out.append("**SYSTEM PROMPT :**")
                out.append("")
                out.append("```")
                out.append(call.get("system_prompt", ""))
                out.append("```")
                out.append("")
                out.append("**USER PROMPT :**")
                out.append("")
                out.append("```")
                out.append(call.get("user_prompt", ""))
                out.append("```")
                out.append("")
                out.append("**RÉPONSE LLM (raw) :**")
                out.append("")
                out.append("```")
                out.append(call.get("raw_response", ""))
                out.append("```")
                out.append("")
            out.append("</details>")
            out.append("")
        # Trace agrégée (legacy, conservée pour debug)
        out.append("<details><summary>Trace LLM agrégée (format legacy)</summary>")
        out.append("")
        out.append("```")
        out.append(ex.get("trace_text", "(trace_text absent)"))
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")

    # Phase 1.2.5 — Filter
    if state.filtered:
        f = state.filtered
        out.append("## Phase 1.2.5 — Filter entités")
        out.append("")
        out.append(f"- **Mode** : `{f.get('mode')}`")
        if f.get("test_mode"):
            out.append(f"- **Test mode** : {f['test_mode']}")
        out.append(f"- **Tables droppées** : {len(f.get('drop_tables', []))}")
        out.append(f"- **Vues droppées** : {len(f.get('drop_views', []))}")
        if f.get("hallucinated"):
            out.append(f"- ⚠ **Hallucinations LLM ignorées** : {len(f['hallucinated'])}")
        out.append("")
        out.append("<details><summary>Recap détaillé</summary>")
        out.append("")
        out.append("```")
        out.append(f.get("trace_text", "(trace_text absent)"))
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")

    # Phase 1.2.6 — Curate
    if state.curated:
        c = state.curated
        out.append("## Phase 1.2.6 — Curate routing")
        out.append("")
        per_concept = c.get("per_concept", {}) or {}
        modes = {pc.get("mode") for pc in per_concept.values()}
        out.append(f"- **Concepts traités** : {len(per_concept)}")
        out.append(f"- **Modes observés** : {sorted(m for m in modes if m)}")
        out.append("")
        # Prompts envoyés au LLM (1 ou plus par concept selon Q/A loops)
        sys_prompt_curate = c.get("system_prompt") or ""
        prompts_pc = c.get("prompts_per_concept") or {}
        raws_pc = c.get("raw_responses") or {}
        if sys_prompt_curate or prompts_pc:
            n_prompts = sum(len(v) if isinstance(v, list) else 1 for v in prompts_pc.values())
            out.append(
                f"<details><summary>📨 SYSTEM prompt + {n_prompts} USER prompts envoyés au LLM Phase 1.2.6 (cliquer pour déplier)</summary>"
            )
            out.append("")
            if sys_prompt_curate:
                out.append("#### SYSTEM PROMPT (commun à tous les concepts)")
                out.append("")
                out.append("```")
                out.append(sys_prompt_curate)
                out.append("```")
                out.append("")
            for concept, prompts in prompts_pc.items():
                if not isinstance(prompts, list):
                    prompts = [prompts]
                raws = raws_pc.get(concept, [])
                out.append(f"#### Concept : **{concept}** — {len(prompts)} appel(s)")
                out.append("")
                for i, up in enumerate(prompts):
                    out.append(f"**Appel #{i+1} — USER PROMPT :**")
                    out.append("")
                    out.append("```")
                    out.append(up or "")
                    out.append("```")
                    out.append("")
                    if i < len(raws):
                        out.append(f"**Appel #{i+1} — RÉPONSE LLM (raw) :**")
                        out.append("")
                        out.append("```")
                        out.append(raws[i] or "")
                        out.append("```")
                        out.append("")
            out.append("</details>")
            out.append("")
        out.append("<details><summary>Routing par concept (recap)</summary>")
        out.append("")
        out.append("```")
        out.append(c.get("trace_text", "(trace_text absent)"))
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")

    # Phase 1.3+1.4 — Search
    if state.search:
        s = state.search
        out.append("## Phase 1.3+1.4 — Search BDD")
        out.append("")
        out.append(f"- **Total matches** : {s.get('n_total_matches', 0):,}")
        out.append(f"- **Filtrés par routing 1.2.6** : {s.get('n_filtered_by_routing', 0):,}")
        out.append(
            f"- **Concepts** : {s.get('n_concepts', 0)} (dont {s.get('n_derivables', 0)} dérivables skippés)"
        )
        out.append("")

    # Phase 1.5 — Scoring + FK
    if state.scored and state.scored.get("v2_text"):
        out.append("## Phase 1.5 — Scoring + FK subgraph")
        out.append("")
        v2 = state.scored["v2_text"]
        # Extrait juste le bloc PROBABILITÉS si possible (résumé compact)
        m = re.search(r"PROBABILITÉS.*?(?=\n=|\Z)", v2, re.DOTALL)
        if m:
            out.append("```")
            out.append(m.group(0)[:3000])
            out.append("```")
        out.append("")
        out.append("<details><summary>v2_text complet (pavé envoyé au LLM Phase 2/3)</summary>")
        out.append("")
        out.append("```")
        out.append(v2[:50000])  # cap raisonnable
        if len(v2) > 50000:
            out.append(f"\n... ({len(v2) - 50000} chars truncated — voir run.json)")
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")

    # Phase 2 — Rerank
    if state.reranks and state.reranks.get("per_concept"):
        rr = state.reranks
        out.append("## Phase 2 — Rerank LLM par concept")
        out.append("")
        for concept, data in (rr["per_concept"] or {}).items():
            top = data.get("ranking_top", [])
            out.append(f"### Concept : **{concept}** — top {len(top)}")
            out.append("")
            for entry in top[:10]:
                rank = entry.get("rank", "?")
                kind = entry.get("kind", "?")
                ent = entry.get("entity", "?")
                rationale = (entry.get("rationale", "") or "")[:200]
                out.append(f"- `#{rank}` [{kind}] **{ent}** — {rationale}")
            out.append("")
        # Prompts envoyés (1 par concept reranké en parallèle)
        sys_prompt_rerank = rr.get("system_prompt") or ""
        prompts_pc = rr.get("prompts_per_concept") or {}
        raws_pc = rr.get("raw_responses") or {}
        if sys_prompt_rerank or prompts_pc:
            out.append(
                f"<details><summary>📨 SYSTEM prompt + {len(prompts_pc)} USER prompts envoyés au LLM Phase 2 (cliquer pour déplier)</summary>"
            )
            out.append("")
            if sys_prompt_rerank:
                out.append("#### SYSTEM PROMPT (commun à tous les concepts)")
                out.append("")
                out.append("```")
                out.append(sys_prompt_rerank)
                out.append("```")
                out.append("")
            for concept, up in prompts_pc.items():
                out.append(f"#### Concept : **{concept}**")
                out.append("")
                out.append("**USER PROMPT :**")
                out.append("")
                out.append("```")
                out.append(up or "")
                out.append("```")
                out.append("")
                raw = raws_pc.get(concept)
                if raw:
                    out.append("**RÉPONSE LLM (raw) :**")
                    out.append("")
                    out.append("```")
                    out.append(raw)
                    out.append("```")
                    out.append("")
            out.append("</details>")
            out.append("")

    # Phase 3 — Concept Fact Sheets (probes par concept, parallèle)
    if state.factsheets and state.factsheets.get("per_concept"):
        fs = state.factsheets
        per_concept = fs["per_concept"] or {}
        sys_prompt_p3 = fs.get("system_prompt", "") or ""
        prompts_pc = fs.get("prompts_per_concept", {}) or {}
        raws_pc = fs.get("raw_responses", {}) or {}

        out.append("## Phase 3 — Concept Fact Sheets (probes par concept)")
        out.append("")
        n_concepts = len(per_concept)
        n_probes = sum(
            len((d.get("probes") or [])) for d in per_concept.values() if isinstance(d, dict)
        )
        n_questions = sum(
            len((d.get("ask_user") or [])) for d in per_concept.values() if isinstance(d, dict)
        )
        out.append(f"- **Concepts traités** : {n_concepts}")
        out.append(f"- **Probes exécutées (total)** : {n_probes}")
        if n_questions:
            out.append(f"- **Questions posées à l'utilisateur** : {n_questions}")
        out.append("")

        # Résumé court par concept
        for concept, factsheet in per_concept.items():
            if not isinstance(factsheet, dict):
                continue
            mode = factsheet.get("mode", "?")
            probes_list = factsheet.get("probes", []) or []
            n_ok = sum(1 for p in probes_list if p.get("executed"))
            n_ko = len(probes_list) - n_ok
            interp = (factsheet.get("interpretation") or "").strip()
            out.append(f"### Concept : **{concept}** — mode `{mode}`")
            out.append("")
            if interp:
                out.append(f"_{interp}_")
                out.append("")
            if probes_list:
                out.append(f"- {len(probes_list)} probes — {n_ok} OK, {n_ko} KO")
                for p in probes_list:
                    mark = "✓" if p.get("executed") else "✗"
                    rc = p.get("row_count", 0)
                    purpose = (p.get("purpose", "") or "")[:80]
                    out.append(f"  - `{p.get('id', '?')}` {mark} {rc:,} rows — {purpose}")
            out.append("")

        # Bloc complet (toutes les fiches en détail)
        if fs.get("formatted_block"):
            out.append(
                "<details><summary>📋 Détail complet de toutes les fiches (samples, null%, hypothèses)</summary>"
            )
            out.append("")
            out.append("```")
            out.append(fs["formatted_block"])
            out.append("```")
            out.append("")
            out.append("</details>")
            out.append("")

        # Prompts envoyés (1 SYSTEM + N USER prompts, support Q/A multi-loop)
        if sys_prompt_p3 or prompts_pc:
            n_calls = sum(len(v) if isinstance(v, list) else 1 for v in prompts_pc.values())
            out.append(
                f"<details><summary>📨 SYSTEM prompt + {n_calls} USER prompts envoyés au LLM Phase 3 (cliquer pour déplier)</summary>"
            )
            out.append("")
            if sys_prompt_p3:
                out.append("#### SYSTEM PROMPT (commun à tous les concepts)")
                out.append("")
                out.append("```")
                out.append(sys_prompt_p3)
                out.append("```")
                out.append("")
            for concept, prompts in prompts_pc.items():
                if not isinstance(prompts, list):
                    prompts = [prompts]
                raws = raws_pc.get(concept, []) or []
                out.append(f"#### Concept : **{concept}** — {len(prompts)} appel(s)")
                out.append("")
                for i, up in enumerate(prompts):
                    out.append(f"**Appel #{i+1} — USER PROMPT :**")
                    out.append("")
                    out.append("```")
                    out.append(up or "")
                    out.append("```")
                    out.append("")
                    if i < len(raws):
                        out.append(f"**Appel #{i+1} — RÉPONSE LLM (raw JSON) :**")
                        out.append("")
                        out.append("```")
                        out.append(raws[i] or "")
                        out.append("```")
                        out.append("")
            out.append("</details>")
            out.append("")

    # Phase 4 — SQL Composer
    if state.sql_final and state.sql_final.get("sql"):
        sf = state.sql_final
        out.append("## Phase 4 — SQL Composer (final)")
        out.append("")
        out.append("```sql")
        out.append(sf["sql"])
        out.append("```")
        out.append("")
        # Prompt complet envoyé au LLM (system + user enrichi avec fiches + réponse brute)
        sys_prompt_p4 = sf.get("system_prompt") or ""
        user_prompt_p4 = sf.get("user_prompt") or ""
        raw_p4 = sf.get("raw_response") or ""
        if sys_prompt_p4 or user_prompt_p4:
            out.append(
                "<details><summary>📨 Prompt complet envoyé au LLM Phase 4 (system + user enrichi par fiches concept + réponse)</summary>"
            )
            out.append("")
            if sys_prompt_p4:
                out.append("**SYSTEM PROMPT :**")
                out.append("")
                out.append("```")
                out.append(sys_prompt_p4)
                out.append("```")
                out.append("")
            if user_prompt_p4:
                out.append("**USER PROMPT :**")
                out.append("")
                out.append("```")
                out.append(user_prompt_p4)
                out.append("```")
                out.append("")
            if raw_p4:
                out.append("**RÉPONSE LLM (raw) :**")
                out.append("")
                out.append("```")
                out.append(raw_p4)
                out.append("```")
                out.append("")
            out.append("</details>")
            out.append("")

    # SQL final exécutable (= Phase 4)
    if state.final_sql:
        out.append("## ✅ SQL final exécutable")
        out.append("")
        out.append("```sql")
        out.append(state.final_sql)
        out.append("```")
        out.append("")
        out.append(f"_(également dans `outputs/run.sql` pour exécution directe)_")
        out.append("")

    return "\n".join(out)


def _ensure_concept_resolution_loaded(
    state: PipelineState,
    *,
    debug_traces: bool = False,
    required: bool = False,
) -> dict:
    """Garantit que `state.concept_resolution` est rempli, l'exécute inline via
    Phase 2.5 sinon. Retourne le dict interne `{concept: {best, top_candidates,
    ...}}` prêt à être passé en aval (Phase 3, Phase 4 IR).

    Phase 2.5 n'est pas un step explicite de l'orchestrateur (TODO : la
    promouvoir dans `PHASES_ORDER` quand elle deviendra critique pour d'autres
    phases). Elle est exécutée à la demande au début de la première phase qui
    en a besoin. Single source of truth — utilisé par Phase 3 et Phase 4 IR
    (cf. task #67).

    Pattern : si reranks Phase 2 sont disponibles, fast-path via reranks
    (résolution <1s). Sinon, fallback LIKE % sur value_mapping (plusieurs
    minutes possibles).

    Args:
        required: si True, lève ``SystemExit`` quand ``state.extracted`` est
            absent (Phase 4 IR le requiert pour ne pas générer un SQL avec
            ``cr_dict={}`` silencieusement). Phase 3 peut tolérer (mode
            dégradé sur rerank seulement).

    **Side-effect** : mute ``state.concept_resolution`` à la première
    invocation. Idempotent ensuite (cache via dict non-None).

    Note RGPD : les ``samples`` portés par ``concept_resolution`` viennent de
    ``komptia.db.value_mapping`` — leur niveau d'obfuscation suit la politique
    sync (cf. chantier GFP-F1 RGPD). Ce helper ne change pas la politique
    existante (parité avec ``v2_text`` qui était déjà envoyé au LLM Phase 3
    en clair via ``resolve_anon_in_text``).
    """
    if state.extracted is None:
        if required:
            raise SystemExit(
                "❌ _ensure_concept_resolution_loaded(required=True) appelée "
                "mais state.extracted absent. Lance d'abord Phase 1.1-1.2."
            )
        return {}
    if state.concept_resolution is None:
        candidate_tables = _extract_candidate_tables_from_state(state)
        reranks_pc = None
        if isinstance(state.reranks, dict):
            reranks_pc = state.reranks.get("per_concept")
        if reranks_pc:
            print(
                f"→ Phase 2.5 inline : fast-path via reranks "
                f"({len(reranks_pc)} concepts pré-résolus, "
                f"{len(candidate_tables) if candidate_tables else 'toutes'} "
                f"tables candidates)...",
                flush=True,
            )
        else:
            print(
                "→ Phase 2.5 inline : LIKE % fallback (pas de reranks dispo — "
                "peut prendre plusieurs minutes)...",
                flush=True,
            )
        # T4 — Enrichir reranks avec FvEx empiriques que le LLM Phase 2 aurait
        # omises (biais lexical). T14 — Complète avec FvCo (sous-chaîne) au
        # rang plus bas. Ordre T4 → T14.
        if reranks_pc and state.scored and isinstance(state.scored, dict):
            v2_text_for_t4 = state.scored.get("v2_text", "") or ""
            if v2_text_for_t4 and state.extracted:
                concepts_v2_for_t4 = state.extracted.get("concepts_v2") or []
                reranks_pc = _t4_enrich_reranks_with_missing_fvex(
                    reranks_pc, concepts_v2_for_t4, v2_text_for_t4
                )
                reranks_pc = _t14_enrich_reranks_with_missing_fvco(
                    reranks_pc, concepts_v2_for_t4, v2_text_for_t4
                )
        cr_payload = phase_2_5_concept_resolution(
            state.extracted,
            candidate_tables=candidate_tables,
            reranks_per_concept=reranks_pc,
            debug_traces=debug_traces,
        )
        state.concept_resolution = cr_payload
    return (state.concept_resolution or {}).get("concept_resolution", {})


async def _execute_phase(
    phase_id: str,
    state: PipelineState,
    **kwargs: Any,
) -> Any:
    """Dispatch d'une phase ID vers sa fonction et ses kwargs.

    Le dispatch explicite (vs un dict de fonctions) permet à mypy/IDE
    de typer correctement chaque appel.
    """
    if phase_id == "1.1-1.2":
        _extracted = await phase_1_1_1_2_extract(
            state.query,
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            debug_traces=kwargs["debug_traces"],
            additional_context=kwargs.get("additional_context"),
        )
        # P1 #12(a) — dégradation gracieuse : aucun concept exploitable extrait
        # → ConceptUnresolvedError recoverable (le runner demande une
        # clarification user) au lieu d'un crash nu en aval (Phase 2/3).
        _clarif = _phase1_empty_concepts_clarification(_extracted)
        if _clarif:
            raise ConceptUnresolvedError(_clarif, concept_name="")
        return _extracted
    if phase_id == "1.2.4":
        return await phase_1_2_4_disambiguate(
            state.extracted or {},
            debug_traces=kwargs["debug_traces"],
        )
    if phase_id == "1.2.5":
        return await phase_1_2_5_filter(
            state.query,
            state.extracted or {},
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            db_path=kwargs["db_path"],
            max_qa_loops=kwargs["max_qa_loops"],
            block_all_views=kwargs["block_all_views"],
            debug_traces=kwargs["debug_traces"],
        )
    if phase_id == "1.2.6":
        return await phase_1_2_6_curate(
            state.query,
            state.extracted or {},
            state.filtered or {},
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            max_qa_loops=kwargs["max_qa_loops"],
            concept_filter=kwargs["concept_filter"],
            debug_traces=kwargs["debug_traces"],
        )
    if phase_id == "1.3-1.4":
        return await phase_1_3_1_4_search(
            state.extracted or {},
            state.filtered or {},
            state.curated or {},
            db_path=kwargs["db_path"],
            debug_traces=kwargs["debug_traces"],
        )
    if phase_id == "1.5":
        # Sérialisation cross-coroutine : Phase 1.5 patche des globals
        # module + ``sys.argv`` pour réutiliser ``_p15_main_legacy()``
        # (cf. doctrine ``_PHASE_1_5_LOCK``). Sans ce lock, deux runs
        # simultanés (deux users Iris) corrompraient leurs résultats.
        async with _get_phase_1_5_lock():
            # task #82 (bug fix) — découpler `block_view_mined_fk` de
            # `block_all_views`. Ces 2 flags ont des sémantiques différentes :
            #   - `block_all_views` (Phase 1.2.5) : drop les VUES elles-mêmes
            #     du shortlist (mode test). Default False → vues visibles.
            #   - `block_view_mined_fk` (Phase 1.5) : bloque les FK INFÉRÉES
            #     des vues (anti-hallucination FK). Toujours True en runtime
            #     pour ne jamais halluciner des FK depuis le SQL des vues.
            # L'ancien code passait `block_all_views` aux 2 endroits, ce qui
            # signifiait : « si on bloque les vues on bloque aussi les FK
            # minées » — corrélé, mais inversement, si on active les vues
            # on active aussi l'hallucination FK. Désormais découplé.
            return phase_1_5_scoring_fk(
                state.search or {},
                state.filtered or {},
                state.curated or {},
                db_path=kwargs["db_path"],
                block_view_mined_fk=True,
                debug_traces=kwargs["debug_traces"],
            )
    if phase_id == "2":
        return await phase_2_rerank(
            state.query,
            state.scored or {},
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            concept_filter=kwargs["concept_filter"],
            debug_traces=kwargs["debug_traces"],
            extracted=state.extracted,
        )
    if phase_id == "3":
        # Phase 2.5 doit tourner AVANT Phase 3 pour fournir la résolution
        # concept→(table,col) data-driven. Sans elle, Phase 3 refait le
        # mapping de tête et pose des Q techniques à l'utilisateur (task #67).
        cr_dict_for_p3 = _ensure_concept_resolution_loaded(
            state, debug_traces=kwargs["debug_traces"]
        )
        return await phase_3_concept_factsheets(
            state.query,
            state.extracted or {},
            state.scored or {},
            state.reranks or {},
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            db_path=kwargs["db_path"],
            max_probes_per_concept=kwargs.get("max_probes", 12),
            # Strict (pas de fallback) — cohérent avec Phase 1.2.5/1.2.6 qui
            # font ``kwargs["max_qa_loops"]`` KeyError-strict. ``run_pipeline``
            # garantit la présence de la clé via son default = constante SSOT
            # ``_PHASE_3_DEFAULT_MAX_QA_LOOPS``. Si un caller in-process oublie
            # le kwarg, on veut KeyError bruyante (pas un fallback silencieux
            # qui masque l'oubli). Adversarial fix #M1 task #96.
            max_qa_loops=kwargs["phase_3_max_qa_loops"],
            debug_traces=kwargs["debug_traces"],
            use_sage=kwargs.get("use_sage", False),
            concept_resolution=cr_dict_for_p3,
            filtered=state.filtered,
        )
    if phase_id == "4":
        # Todo #7 (2026-05-26) — Default CLI inversé legacy → ir.
        # Le mode IR (Phase 4 composer Python pur, 0 hallucination
        # structurelle) est désormais le default. Le mode legacy
        # (SQL libre via LLM + extraction regex) reste accessible
        # via ``--mode=legacy`` mais est documenté comme DEPRECATED
        # — cf. commentaire en tête de ``phase_4_compose_sql``.
        # Le production caller (``pipeline_runner.py``) utilise déjà
        # ``PipelineMode.IR`` par défaut depuis avant ce changement.
        mode = kwargs.get("mode", "ir")
        if mode == "ir":
            # Mode IR — Phase 4 consomme `state.extracted` (Phase 1.1-1.2)
            # + `state.concept_resolution` (Phase 2.5). Phase 2.5 est exécutée
            # inline si absente via le helper `_ensure_concept_resolution_loaded`
            # (single source of truth — même helper utilisé par Phase 3).
            # `required=True` fait raise SystemExit si state.extracted manque
            # (Phase 4 IR ne peut pas tourner avec cr_dict vide silencieusement).
            # Phase W.4 : si `state.factsheets` dispo, on l'injecte dans
            # le user prompt Phase 4 IR pour enrichir le contexte.
            cr_dict = _ensure_concept_resolution_loaded(
                state, debug_traces=kwargs["debug_traces"], required=True
            )
            # Phase W.4 — passer factsheets si dispo (enrichit prompt Phase 4 IR).
            factsheets = state.factsheets if state.factsheets else None
            return await phase_4_compose_ir(
                state.query,
                state.extracted or {},
                cr_dict,
                model_id=kwargs["model_id"],
                api_key=kwargs["api_key"],
                db_path=kwargs["db_path"],
                debug_traces=kwargs["debug_traces"],
                factsheets=factsheets,
            )
        # Mode legacy (default) — comportement historique avant archi IR.
        if not state.factsheets:
            raise SystemExit("❌ Phase 4 demandée mais factsheets absentes (Phase 3 non exécutée).")
        return await phase_4_compose_sql(
            state.query,
            state.factsheets,
            state.scored or {},
            state.reranks or {},
            state.extracted or {},
            model_id=kwargs["model_id"],
            api_key=kwargs["api_key"],
            db_path=kwargs["db_path"],
            debug_traces=kwargs["debug_traces"],
        )
    raise SystemExit(f"❌ Phase ID inconnu : {phase_id}")


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    valid_phases = [pid for pid, _, _ in PHASES_ORDER]
    p = argparse.ArgumentParser(
        description="Pipeline NL→SQL monolithique (orchestrateur unique).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "query",
        nargs="?",
        default=None,
        help="Requête utilisateur en langage naturel (entre guillemets)",
    )
    p.add_argument(
        "--only-phase",
        choices=valid_phases,
        default=None,
        help="Exécute UNE phase isolée (lit run.json pour les amont)",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Reprend après la dernière phase complétée dans run.json",
    )
    p.add_argument(
        "--no-clean", action="store_true", help="Ne wipe PAS run.json/run.sql avant le run"
    )
    p.add_argument(
        "--block-all-views",
        action="store_true",
        help=(
            "(OFF par défaut depuis task #82) Mode test : drop TOUTES les vues "
            "sans appel LLM, force Phase 3 à reconstituer JOINs depuis tables "
            "uniquement. Anti-hallucination FK des vues reste gérée séparément "
            "par `block_view_mined_fk=True` (hardcodé). Ne PAS passer en "
            "production — les vues métier (viewMissions03, viewGroupes01, etc.) "
            "sont utiles pour générer du SQL correct."
        ),
    )
    p.add_argument(
        "--max-probes",
        type=int,
        default=15,
        help="Max retries Phase 4 (défaut 2, 0 = skip Phase 4)",
    )
    p.add_argument(
        "--max-qa-loops", type=int, default=2, help="Max Q/A loops par concept (Phase 1.2.5/1.2.6)"
    )
    p.add_argument(
        "--phase-3-max-qa-loops",
        type=int,
        default=_PHASE_3_DEFAULT_MAX_QA_LOOPS,
        help=(
            f"Max Q/A loops par concept Phase 3 (défaut "
            f"{_PHASE_3_DEFAULT_MAX_QA_LOOPS}). Phase 3 tourne en parallèle "
            "et auto-soumet R='' (jamais bridgé vers user) — 1 retry suffit "
            "dans la plupart des cas. Min 1."
        ),
    )
    p.add_argument(
        "--db",
        default=str(SAGE_DB),
        help=f"BDD source pour probes (défaut {SAGE_DB.relative_to(ROOT)})",
    )
    p.add_argument(
        "--use-sage",
        action="store_true",
        help="Exécute les probes Phase 3 sur la VRAIE Sage Coala "
        "(SQL Server via SageConnector) au lieu de sage_copy.db. "
        "Schéma DDL/FK reste lu depuis --db (assumé identique). "
        "Élimine les divergences sage_copy vs Sage prod.",
    )
    p.add_argument(
        "--mode",
        choices=("legacy", "ir"),
        default="legacy",
        help="Mode Phase 4 : 'legacy' = SQL libre par LLM (existant), "
        "'ir' = LLM produit un IR JSON via tool_use, le système "
        "compose le SQL via ir_to_sql (data-driven, archi a/b/c/d). "
        "Mode 'ir' nécessite Phase 1.1+1.2 (extracted) ; Phase 2.5 "
        "(concept_resolution) est exécutée à la volée si absente.",
    )
    p.add_argument(
        "--debug-traces",
        action="store_true",
        help="Écrit les traces LLM brutes dans outputs/_debug_traces/",
    )
    p.add_argument(
        "--top-n", type=int, default=3, help="Phase 3, nb tables shortlistées par concept"
    )
    p.add_argument(
        "--concept", default=None, help="Filtre debug : restreint Phase 1.2.6/2 à ce concept"
    )
    p.add_argument("--dry-run", action="store_true", help="Imprime les prompts sans appeler le LLM")
    return p


def main() -> int:
    args = _build_parser().parse_args()

    # Validation : --resume et --only-phase n'exigent pas la query (déjà dans run.json)
    if not args.resume and not args.only_phase and not args.query:
        print("❌ Donne la requête utilisateur entre guillemets :", file=sys.stderr)
        print('   python scripts/pipeline.py "ta requête ici"', file=sys.stderr)
        return 2

    query = args.query or ""

    state = asyncio.run(
        run_pipeline(
            query,
            only_phase=args.only_phase,
            resume=args.resume,
            no_clean=args.no_clean,
            block_all_views=args.block_all_views,
            max_probes=args.max_probes,
            max_qa_loops=args.max_qa_loops,
            phase_3_max_qa_loops=args.phase_3_max_qa_loops,
            db_path=Path(args.db),
            debug_traces=args.debug_traces,
            top_n=args.top_n,
            concept_filter=args.concept,
            dry_run=args.dry_run,
            use_sage=args.use_sage,
            mode=args.mode,
        )
    )

    # Résumé final
    print(f"\n{'=' * 80}\nRÉSUMÉ DU RUN\n{'=' * 80}")
    print(f"Query : {state.query[:120]}{'...' if len(state.query) > 120 else ''}")
    completed = [pid for pid, attr, _ in PHASES_ORDER if getattr(state, attr) is not None]
    print(f"Phases complétées : {', '.join(completed) if completed else '(aucune)'}")
    if state.phase_durations:
        total = sum(state.phase_durations.values())
        print(f"Durée totale : {total:.1f}s")
    if state.final_sql:
        print(f"SQL final : outputs/run.sql ({len(state.final_sql)} chars)")
    print(f"Snapshot : outputs/run.json")
    return 0


# NOTE : le bloc `if __name__ == "__main__":` reste en fin de fichier
# (après la section INLINED Phase 1.5 qui définit les globals SRC/DB/
# DST_MAIN/DST_ANNEX/_DROPPED_ENTITIES_FILE/_CURATE_DIR utilisés par
# phase_1_5_scoring_fk). Les sections INLINED Phase 3 et Phase 4 ont
# été supprimées (refactor concept fact sheets, 2026-05-06).


# =====================================================================
# PHASE 1.5 — INLINED helpers from test_pipeline_v2.py (2026-05-05)
# Préfixés _p15_ pour éviter collisions avec les helpers Phase 1.1+1.2
# (parse_user_query/parse_concept_values/parse_derivables existent déjà
# au top de ce fichier pour le format extracted_terms.txt — ici les
# variantes _p15_* parsent le format search_results_test.txt).
# Globals SRC/DB/DST_MAIN/DST_ANNEX/_DROPPED_ENTITIES_FILE/_CURATE_DIR
# sont patchés par `phase_1_5_scoring_fk` vers un tmpdir avant l'appel.
# =====================================================================


# Globals patchés par phase_1_5_scoring_fk (vers tmpdir).
# Note (dedup 2026-05-20, fix #49 GFP-G2) : ``DB`` pointe par défaut sur
# ``DEFAULT_DB_PATH`` (= la même source de vérité que ``SAGE_DB`` défini en
# haut du fichier). Avant le fix, ce module avait DEUX constantes pour le
# même path (``SAGE_DB`` ligne 87 + ``DB`` ici) = source de confusion +
# double maintenance. Désormais une seule racine, l'alias mutable ``DB``
# reste pour la rétro-compat des helpers historiques _p15_* qui le
# réassignent temporairement vers un tmpdir lors des tests. Tout ce
# bloc devient dead code avant prod (cf. TODO sur ``DEFAULT_DB_PATH``).
SRC = ROOT / "outputs" / "search_results_test.txt"
DB = DEFAULT_DB_PATH
DST_MAIN = ROOT / "outputs" / "search_results_test_v2.txt"
DST_ANNEX = ROOT / "outputs" / "search_results_test_v2_annex.txt"


# =============================================================================
# CONSTANTS — single source of truth (ajustables sans toucher à la logique)
# =============================================================================

# Poids par catégorie de match. Calibrés pour que :
# - une valeur exacte du concept (FvEx) soit le signal le plus fort
# - les matches sur colonne (Col*) priment sur les matches sur table (Tbl*)
# - le fuzzy soit toléré mais peu influent
WEIGHTS: dict[str, int] = {
    "fvex": 100,
    "fvco": 60,
    "fvfz": 30,
    "colex": 80,
    "tblex": 70,
    "colco": 50,
    "tblco": 30,
    "colfz": 20,
    "tblfz": 10,
    "vcolex": 80,
    "vueex": 70,
    "vcolco": 50,
    "vueco": 30,
    "vcolfz": 20,
    "vuefz": 10,
}

# Priorités d'affichage par type de concept (pour le format compressé V-B).
# Ordre = ordre d'affichage et ordre de priorité du tri par entité.
PRIO_TBL_WITH_VALUES: list[tuple[str, str, str]] = [
    ("fvex", "FvEx", "="),
    ("fvco", "FvCo", "⊂"),
    ("fvfz", "FvFz", "~"),
    ("colex", "ColEx", "="),
    ("tblex", "TblEx", "="),
    ("colco", "ColCo", "⊂"),
    ("tblco", "TblCo", "⊂"),
    ("colfz", "ColFz", "~"),
    ("tblfz", "TblFz", "~"),
]
PRIO_TBL_NO_VALUES: list[tuple[str, str, str]] = [
    ("colex", "ColEx", "="),
    ("tblex", "TblEx", "="),
    ("colco", "ColCo", "⊂"),
    ("tblco", "TblCo", "⊂"),
    ("colfz", "ColFz", "~"),
    ("tblfz", "TblFz", "~"),
]
PRIO_VUE_WITH_VALUES: list[tuple[str, str, str]] = [
    ("fvex", "FvEx", "="),
    ("fvco", "FvCo", "⊂"),
    ("fvfz", "FvFz", "~"),
    ("vcolex", "VColEx", "="),
    ("vueex", "VueEx", "="),
    ("vcolco", "VColCo", "⊂"),
    ("vueco", "VueCo", "⊂"),
    ("vcolfz", "VColFz", "~"),
    ("vuefz", "VueFz", "~"),
]
PRIO_VUE_NO_VALUES: list[tuple[str, str, str]] = [
    ("vcolex", "VColEx", "="),
    ("vueex", "VueEx", "="),
    ("vcolco", "VColCo", "⊂"),
    ("vueco", "VueCo", "⊂"),
    ("vcolfz", "VColFz", "~"),
    ("vuefz", "VueFz", "~"),
]

# Convention DBA / SQL Server : préfixes ET fragments de noms d'artefact.
# Convention générique valable pour toute BDD SQL Server legacy : tables/vues
# temporaires, copies de travail, dumps d'impression, archives, etc.
# Aucune dépendance à un domaine métier particulier.
# `is_artifact()` utilise `re.search` pour matcher les fragments à
# n'importe quelle position (TempBudgAct, FactureImpr, dbo_view…Pdf, …).
ARTIFACT_REGEX = re.compile(
    r"^(TEMP|TMP|PARAMS?|SYS|ZZ|Z_)"  # préfixes (ancrés)
    r"|"
    r"(TEMP|IMPR|PDF|XLS|HISTO|ARCHIVE|BAK|BACKUP|EXPORT|REPORT)",  # fragments (anywhere)
    re.IGNORECASE,
)
ARTIFACT_MULT = 0.35  # multiplicateur sur le score (×0.35 — entité rétrogradée)

# =============================================================================
# Coefficients de scoring (single source of truth — utilisés par
# compute_global_scores ET render_probability_table pour éviter le drift)
# =============================================================================
COMBINED_SUM_WEIGHT = 0.7  # pondération du Σ(scores normalisés)
COMBINED_MAX_WEIGHT = 0.3  # pondération du n × max(scores)
MULTI_BONUS_RATE = 0.15  # 1 + rate × (n_concepts - 1)
FK_BONUS_RATE = 0.08  # 1 + rate × log(1 + fk_degree)
EXACT_BONUS = 1.5  # multiplicateur si ≥1 match exact (TblEx/ColEx/FvEx/...)
SIZE_BONUS_RATE = 0.05  # 1 + rate × log10(1 + row_count)
# Bonus appliqué aux VUES qui référencent N tables fortement scorées dans
# leur définition CREATE VIEW. Sage-style : les vues `viewXxx` encapsulent
# les patterns de JOIN — elles sont la "carte sémantique" idéale pour
# composer le SQL final, même si elles n'ont ni FK ni row_count propre.
VIEW_CENTRALITY_RATE = 0.4  # bonus = 1 + rate × n_tables_sources_dans_top
# Bonus de canonicité : FvEx / (FvCo + 1) discrimine les tables qui
# stockent proprement les valeurs explicites (peu de FvEx, peu de bruit
# textuel FvCo) vs les tables de reporting/log qui re-copient les valeurs
# dans plein de libellés (FvEx + énormément de FvCo). Sans ce bonus,
# `TempRptProdUser` (FvEx=9, FvCo=170) écrase `Groupes` (FvEx=6, FvCo=2)
# dans le scoring local du concept "code groupe".
CANONICITY_BONUS_RATE = 0.5  # bonus = 1 + rate × log(1 + ratio)
CANONICITY_RATIO_CAP = 5.0  # cap pour éviter explosion sur FvCo=0
# Poids de la composante "local effectif" dans le tri par concept :
# - haut si concept a des valeurs explicites (FvEx fiable → signal local fort)
# - bas si concept sans valeurs (signal local = matching textuel bruyant,
#   préférable de privilégier la proba globale plus stable).
LOCAL_WEIGHT_WITH_VALUES = 0.6
LOCAL_WEIGHT_NO_VALUES = 0.3

# Saturation : au-delà de N matches d'un même via dans une catégorie, le
# scoring n'augmente plus. Évite l'inflation des "tables-monstres" (ex.
# tables de reporting dénormalisées avec 460 colonnes).
CAP_PER_VIA = 10

# Affichage Principal : nb max d'items par via dans Fv*/Val. Au-delà,
# tronqué dans Principal avec marqueur (+N en annexe). L'annexe contient
# l'intégralité (zéro perte). Les buckets Col*/Tbl*/Vue*/VCol* ne sont
# pas tronqués (info structurelle directement utile au LLM).
DISPLAY_CAP_FV_PER_VIA = 10
DISPLAY_CAP_VAL_PER_VIA = 8
# Quand une colonne contient plusieurs valeurs anonymisées trouvées (ex:
# `truLibProduction={'val1,val2,...,val50'}`), on tronque à N valeurs.
DISPLAY_CAP_ANONS_PER_COL = 5

# Largeur de wrap pour les listes CSV dans le format compressé.
WRAP_WIDTH = 100

# Combien d'entités afficher dans le tableau de probabilités. Calibré à 70
# pour laisser de la place aux vues sémantiques top (qui prennent souvent
# 30-40% du top) + leurs tables canoniques sous-jacentes.
TOP_N_PROBABILITIES = 70

# Pour chaque concept, on ajoute à la shortlist globale les top K entités
# par signal LOCAL du concept (table + vue). Garantit que les sources
# canoniques d'un concept précis ne soient pas perdues si elles sont
# moyennes globalement (ex: `Groupes` pour "code groupe" : pic sur ce
# concept mais score global #157).
PER_CONCEPT_LOCAL_TOP_K = 50

# 1 hop FK : pour chaque entité shortlistée d'un concept, ajouter ses
# voisins FK directs. Indispensable pour les sources canoniques accessibles
# par structure FK plutôt que par matches textuels (ex : une table référencée
# par une autre via FK, mais dont aucun champ ne matche directement le mot
# du concept côté texte — le lien sémantique passe par la structure FK).
FK_CLOSURE_PER_CONCEPT = True

# Marqueurs de section dans le fichier source (test_pipeline.py).
# Détection tolérante : on accepte les variantes `=== STATISTIQUES ===`,
# `STATISTIQUES :`, `STATISTIQUES (Phase X)`, etc., pour ne pas casser sur
# une évolution mineure du format upstream.
PHASE14_HEADER = "PHASE 1.4 — RÉSULTATS GROUPÉS PAR CONCEPT"
STATS_HEADER_RE = re.compile(r"^=*\s*STATISTIQUES\b", re.IGNORECASE)

# Regex de parsing d'une ligne de match. Doit tolérer :
#   "    exact       100%  Produits (via 'produits')  [rows=1,102]"
#   "    contains     80%  Produits.prdLettreDeMission (via 'emis')  [rows=...]"
#   "    fuzzy        80%  Produits.prdSiret  []"
#   "    exact       100%  Famille.famCodeFamille  [rows=81 | distinct=...]"
MATCH_RE = re.compile(
    r"^\s+(exact|contains|fuzzy)\s+(\d+)%\s+"
    r"(\S+?)"
    r"(?:\s+\(via\s+'([^']+)'\))?"
    r"(?:\s+\[([^\]]*)\])?"
    r"\s*$"
)

# Validation : entités attendues dans le top du tableau pour la requête-test
# corpus historique (multi-concepts, filtre par valeur, plage temporelle).
# Inclut TANT les tables réellement utilisées dans le SQL final QUE les vues
# SQL Server qui ont servi de "carte mentale" pour composer la requête (le
# LLM doit y avoir accès pour reconstituer les patterns de JOIN).
# La validation accepte les variantes avec/sans préfixe `dbo_*`.
EXPECTED_TOP_ENTITIES = [
    "Factures",
    "LignesFactures",
    "viewGroupes01",  # alias dbo_viewGroupes01 / Groupes (table sous-jacente)
    "Dossiers",
    "DossierSuppl",
    "Collaborateurs",
    "viewLignesFactures05",  # vue Sage qui contient le pattern JOIN exact de la requête finale
]
EXPECTED_ALIASES: dict[str, list[str]] = {
    "viewGroupes01": ["dbo_viewGroupes01", "dbo_boViewGroupes01", "Groupes"],
    "viewLignesFactures05": ["dbo_viewLignesFactures05"],
}


# =============================================================================
# PARSING — outputs/search_results_test.txt
# =============================================================================


def _p15_parse_user_query(lines: list[str]) -> str:
    """Extract the NL query from Phase 1.1 prompt section.

    The query appears between the line "**Requête utilisateur :**" and the
    next blank line.
    """
    for i, line in enumerate(lines):
        if "Requête utilisateur" in line:
            # The query is on the next non-empty line(s) until a blank line
            j = i + 1
            buf: list[str] = []
            while j < len(lines) and lines[j].strip():
                buf.append(lines[j].rstrip())
                j += 1
            if buf:
                return " ".join(s.strip() for s in buf if s.strip()).strip()
    return "(requête introuvable dans le fichier source)"


def _p15_parse_concept_values(lines: list[str]) -> dict[str, list[str]]:
    """Parse the STRUCTURE CONCEPT → VALEURS block.

    Format expected:
        STRUCTURE CONCEPT → VALEURS (N concepts) :
          chiffre d'affaires
          code groupe -> AUDIT, MENS, DOSSIER_A
          ...

    Le matcher est strict sur "→ VALEURS" pour ne PAS gober la section
    parallèle "STRUCTURE CONCEPT DÉRIVABLES" (parsée séparément).
    """
    result: dict[str, list[str]] = {}
    in_block = False
    for line in lines:
        if "STRUCTURE CONCEPT → VALEURS" in line or (
            "STRUCTURE CONCEPT" in line and "VALEURS" in line and "DÉRIVABLES" not in line
        ):
            in_block = True
            continue
        if not in_block:
            continue
        # End of block: blank line or next section
        if not line.strip() or line.startswith("===") or line.startswith("---"):
            if in_block and result:
                break
            continue
        # Parse "  concept" or "  concept -> val1, val2"
        stripped = line.strip()
        if " -> " in stripped:
            concept, values_str = stripped.split(" -> ", 1)
            values = [v.strip() for v in values_str.split(",") if v.strip()]
            result[concept.strip()] = values
        else:
            result[stripped] = []
    return result


def _p15_parse_derivables(lines: list[str]) -> dict[str, list[str]]:
    """Parse la section STRUCTURE CONCEPT DÉRIVABLES (concept → [sources]).

    Format émis par test_pipeline.py :
        STRUCTURE CONCEPT DÉRIVABLES (N concepts) :
          (commentaire)
          concept_dérivé <- concept_source_1, concept_source_2

    Lignes sans `<-` (ex: commentaire entre parenthèses) sont skippées.
    Retourne {} si la section est absente (backward-compat avec runs
    antérieurs au feature derivables).
    """
    result: dict[str, list[str]] = {}
    in_block = False
    for line in lines:
        if "STRUCTURE CONCEPT DÉRIVABLES" in line:
            in_block = True
            continue
        if not in_block:
            continue
        if not line.strip() or line.startswith("===") or line.startswith("---"):
            if in_block and result:
                break
            continue
        stripped = line.strip()
        if " <- " not in stripped:
            continue
        concept, sources_str = stripped.split(" <- ", 1)
        sources = [s.strip() for s in sources_str.split(",") if s.strip()]
        result[concept.strip()] = sources
    return result


def parse_phase14(
    lines: list[str], concept_values: dict[str, list[str]]
) -> dict[str, dict[str, list[dict]]]:
    """Parse the Phase 1.4 block, returning per-concept dimension matches.

    Returns:
        { concept_name: { dimension: [match_dict, ...] } }

    where dimension ∈ {"TABLE", "VIEW", "COLUMN", "VIEW_COLUMN", "VALUE"}
    and match_dict has keys {match_type, score, target, via, stats}.
    """
    # Locate Phase 1.4 start and end
    start_idx = None
    end_idx = None
    for i, line in enumerate(lines):
        if PHASE14_HEADER in line and start_idx is None:
            start_idx = i
        elif start_idx is not None and STATS_HEADER_RE.match(line.strip()):
            end_idx = i
            break
    if start_idx is None:
        raise ValueError(f"Phase 1.4 header not found: {PHASE14_HEADER!r}")
    if end_idx is None:
        end_idx = len(lines)

    block = lines[start_idx:end_idx]

    # Iterate, splitting per concept (CONCEPT: <name> headers)
    # Pre-seed result with all known concept names from STRUCTURE so that a
    # concept with zero matches in Phase 1.4 (or whose section was omitted)
    # still appears with empty dimension lists in downstream rendering.
    result: dict[str, dict[str, list[dict]]] = {
        c: {"TABLE": [], "VIEW": [], "COLUMN": [], "VIEW_COLUMN": [], "VALUE": []}
        for c in concept_values
    }
    current_concept: str | None = None
    current_dim: str | None = None

    for raw in block:
        line = raw.rstrip("\n")
        s = line.strip()

        if s.startswith("CONCEPT:"):
            # Format: "CONCEPT: chiffre d'affaires" or "CONCEPT: code groupe -> AUDIT, ..."
            label = s[len("CONCEPT:") :].strip()
            # Strip the values part if present (we already have it from STRUCTURE)
            if " -> " in label:
                label = label.split(" -> ", 1)[0].strip()
            current_concept = label
            result.setdefault(
                current_concept,
                {
                    "TABLE": [],
                    "VIEW": [],
                    "COLUMN": [],
                    "VIEW_COLUMN": [],
                    "VALUE": [],
                },
            )
            current_dim = None
            continue

        if current_concept is None:
            continue

        if s.startswith("[TABLE]"):
            current_dim = "TABLE"
            continue
        if s.startswith("[VIEW_COLUMN]"):
            current_dim = "VIEW_COLUMN"
            continue
        if s.startswith("[VIEW]"):
            current_dim = "VIEW"
            continue
        if s.startswith("[COLUMN]"):
            current_dim = "COLUMN"
            continue
        if s.startswith("[VALUE]"):
            current_dim = "VALUE"
            continue

        if current_dim is None:
            continue

        m = MATCH_RE.match(line)
        if not m:
            continue
        match_type, score_str, target, via, stats = m.groups()
        result[current_concept][current_dim].append(
            {
                "match_type": match_type,
                "score": int(score_str),
                "target": target,
                # When (via '...') is absent, the match was triggered by the concept itself
                "via": via if via else current_concept,
                "stats": stats or "",
            }
        )

    return result


def split_target(target: str) -> tuple[str, str | None]:
    """Split 'Table.Column' or just 'Table'."""
    if "." in target:
        a, b = target.split(".", 1)
        return a, b
    return target, None


def extract_row_count(stats: str) -> str | None:
    m = re.search(r"rows=([\d,]+)", stats)
    return m.group(1) if m else None


def extract_anon(stats: str) -> str | None:
    m = re.search(r"anon='([^']*)'", stats)
    return m.group(1) if m else None


# =============================================================================
# FK EXTRACTION — data/sage_copy.db
# =============================================================================


def extract_fk_explicit(db_path: Path) -> list[dict]:
    """Extract declared FK via SQLite PRAGMA foreign_key_list.

    Returns a list of {source, src_col, target, tgt_col, kind='explicit'}.
    """
    fks: list[dict] = []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for tbl in tables:
            try:
                rows = conn.execute(f'PRAGMA foreign_key_list("{tbl}")').fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                # PRAGMA returns (id, seq, table, from, to, on_update, on_delete, match)
                _, _, ref_table, from_col, to_col, *_ = row
                fks.append(
                    {
                        "source": tbl,
                        "src_col": from_col,
                        "target": ref_table,
                        "tgt_col": to_col,
                        "kind": "explicit",
                    }
                )
    finally:
        conn.close()
    return fks


# Convention Sage-like : préfixe table en lowercase 2-5 chars suivis de "NoEnreg"
# (ex: "facNoEnreg" = PK de Factures préfixe "fac").
PK_RE = re.compile(r"^([a-z]{2,5})NoEnreg$")
# FK : <prefix_source>NoEnreg<Suffix> où Suffix correspond au préfixe (capitalisé)
# d'une table cible (ex: "lfaNoEnregFac" → "Fac" → Factures).
FK_RE = re.compile(r"^([a-z]{2,5})NoEnreg([A-Z][A-Za-z]+)$")


def extract_fk_implicit(db_path: Path) -> list[dict]:
    """Detect implicit FK via Sage-style naming convention.

    Returns a list of {source, src_col, target, tgt_col, kind='implicit', evidence}.
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        # Build prefix → table mapping (case-insensitive)
        # A table has a "prefix" if it has a column ^<prefix>NoEnreg$ (its PK).
        all_tables = [
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
        ]
        prefix_to_tables: dict[str, list[str]] = defaultdict(list)
        table_to_prefix: dict[str, str] = {}
        table_columns: dict[str, list[str]] = {}
        for tbl in all_tables:
            try:
                cols = conn.execute(f'PRAGMA table_info("{tbl}")').fetchall()
            except sqlite3.Error:
                continue
            col_names = [c[1] for c in cols]
            table_columns[tbl] = col_names
            for col in col_names:
                m = PK_RE.match(col)
                if m:
                    prefix = m.group(1).lower()
                    prefix_to_tables[prefix].append(tbl)
                    table_to_prefix[tbl] = prefix
                    break  # only one PK per table by convention

        # Scan all columns for FK pattern
        fks: list[dict] = []
        for tbl, cols in table_columns.items():
            src_prefix = table_to_prefix.get(tbl, "")
            for col in cols:
                m = FK_RE.match(col)
                if not m:
                    continue
                suffix = m.group(2)
                # Skip the table's own PK column
                if col == f"{src_prefix}NoEnreg":
                    continue
                # Match suffix to a known table prefix
                # Try longest-match first by trying prefixes from longest to shortest
                suffix_lower = suffix.lower()
                # Find candidate target prefixes that are a prefix of suffix_lower
                # (handles cases like "Dossier" matching prefix "dos")
                candidates: list[str] = []
                for cand_prefix in prefix_to_tables:
                    if suffix_lower.startswith(cand_prefix):
                        candidates.append(cand_prefix)
                if not candidates:
                    continue
                # Pick the longest matching prefix
                best = max(candidates, key=len)
                targets = prefix_to_tables[best]
                # If multiple tables share the same prefix, all are candidates
                for tgt in targets:
                    if tgt == tbl:
                        continue  # avoid self-FK on same prefix
                    fks.append(
                        {
                            "source": tbl,
                            "src_col": col,
                            "target": tgt,
                            "tgt_col": f"{best}NoEnreg",
                            "kind": "implicit",
                            "evidence": f"col '{col}' → prefix '{best}' (suffix '{suffix}')",
                        }
                    )
        return fks
    finally:
        conn.close()


JOIN_PATTERN_CAT_RE = re.compile(r"^join_pattern:([A-Z0-9_]+)\+([A-Z0-9_]+)$")
TABLES_IMPL_RE = re.compile(r"Tables impliquées\s*:\s*([^.]+)")
JOIN_EXPR_RE = re.compile(r"(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)")


def extract_join_patterns_from_komptia(db_path: Path) -> list[dict]:
    """Extract JOIN edges mined by view_miner.py from komptia.db training_data.

    Each row in training_data with `category LIKE 'join_pattern:%'` describes
    a JOIN edge between two entities (tables or views), extracted from a view's
    SQL definition. Format observed:

        category: "join_pattern:<UPPER_A>+<UPPER_B>"
        content : "Vue <ViewName> : <JOIN_TYPE> JOIN <TableX> ON <expr>.
                   Tables impliquées : <RealCaseA>, <RealCaseB>."

    Returns list of FK dicts (kind='view_mined') merged into the FK graph.
    Brings JOIN edges that the `<prefix>NoEnreg<Suffix>` convention misses
    (e.g. `Dossiers.dosProprietaireDossier = Dos01.dosCodeDossier`).
    """
    if not db_path.exists():
        return []
    edges: list[dict] = []
    seen: set[tuple[str, str]] = set()
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT category, content FROM training_data "
            "WHERE category LIKE 'join_pattern:%' AND is_active=1"
        ).fetchall()
        for cat, content in rows:
            m = JOIN_PATTERN_CAT_RE.match(cat or "")
            if not m:
                continue
            # Real-case names from "Tables impliquées : X, Y."
            tm = TABLES_IMPL_RE.search(content or "")
            a = b = None
            if tm:
                names = [n.strip().rstrip(".") for n in tm.group(1).split(",")]
                names = [n for n in names if n]
                if len(names) >= 2:
                    a, b = names[0], names[1]
            if not (a and b):
                # fallback to upper-case name from category (less ideal)
                a, b = m.group(1), m.group(2)
            # Dedup on unordered pair
            key = tuple(sorted([a.lower(), b.lower()]))
            if key in seen:
                continue
            seen.add(key)
            # Extract column names if possible (best-effort, optional)
            src_col = tgt_col = ""
            jm = JOIN_EXPR_RE.search(content or "")
            if jm:
                _t1, c1, _t2, c2 = jm.groups()
                src_col, tgt_col = c1, c2
            edges.append(
                {
                    "source": a,
                    "src_col": src_col,
                    "target": b,
                    "tgt_col": tgt_col,
                    "kind": "view_mined",
                    "evidence": cat,
                }
            )
    finally:
        conn.close()
    return edges


# Seuil minimum de confiance pour qu'une FK inférée persistée alimente le
# graphe BFS. En dessous, le signal est trop faible (naming seul sans
# corroboration valeur, ou containment < 0.85 sans naming) — risque de
# bruiter les chemins de JOIN. Sweet spot empirique : 0.85 garde les
# value_overlap moyens et les naming+value, écarte les naming-only.
_INFERRED_FK_MIN_CONFIDENCE = 0.85


def extract_fk_inferred_persistent(db_path: Path) -> list[dict]:
    """Lit la table ``inferred_foreign_keys`` (alimentée par ``schema_sync``)
    et la renvoie au format attendu par ``build_fk_graph``.

    La table peut être absente (boot frais sans sync, ou installation
    antérieure à T19) — on retourne ``[]`` sans crash (rétro-compat).

    Filtre sur ``confidence >= _INFERRED_FK_MIN_CONFIDENCE`` pour ne pas
    polluer le graphe avec des signaux faibles. Le seuil est ajustable
    via la constante ci-dessus (ne pas hardcoder dans un call-site).

    Generic : pas de filtrage par nom de table/colonne — applicable à
    n'importe quelle BDD synchronisée par Komptia.
    """
    if not db_path.exists():
        return []
    edges: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        # ``inferred_foreign_keys`` peut ne pas exister sur une BDD ancienne ;
        # sqlite_master nous renseigne sans risquer OperationalError au SELECT.
        row = conn.execute(
            "SELECT name FROM sqlite_master " "WHERE type='table' AND name='inferred_foreign_keys'"
        ).fetchone()
        if not row:
            return []
        rows = conn.execute(
            "SELECT source_table, source_column, target_table, target_column, "
            "       kind, confidence "
            "FROM inferred_foreign_keys "
            "WHERE confidence >= ? "
            "ORDER BY confidence DESC",
            (_INFERRED_FK_MIN_CONFIDENCE,),
        ).fetchall()
        for src_t, src_c, tgt_t, tgt_c, kind, confidence in rows:
            if not (src_t and tgt_t):
                continue
            # Dédup case-insensitive — le schéma a déjà un index unique
            # case-insensitive, mais une migration antérieure de la table
            # pourrait avoir laissé passer des doublons. Belt + braces.
            key = (
                src_t.lower(),
                (src_c or "").lower(),
                tgt_t.lower(),
                (tgt_c or "").lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                {
                    "source": src_t,
                    "src_col": src_c or "",
                    "target": tgt_t,
                    "tgt_col": tgt_c or "",
                    "kind": "inferred",
                    "evidence": f"{kind} (conf={float(confidence):.2f})",
                }
            )
    except sqlite3.Error:
        # Connexion fermée prématurément, BDD corrompue, etc. — non bloquant.
        return []
    finally:
        conn.close()
    return edges


def extract_view_dependencies(db_path: Path) -> dict[str, set[str]]:
    """Parse CREATE VIEW DDL from sqlite_master to extract referenced tables/views.

    Returns: {view_name: {referenced_entity, ...}}.

    Note: SQLite stores the original DDL. We use a generic SQL regex on FROM/JOIN
    clauses — works for any SQL Server view migrated to SQLite. Identifiers may
    appear with optional schema prefix (`dbo.`), with brackets `[name]`, or
    quoted `"name"` — we normalize.
    """
    # Regex: capture identifiers after FROM or JOIN keywords (case-insensitive,
    # word-boundary). Skips subquery markers.
    ref_re = re.compile(
        r"\b(?:FROM|JOIN)\s+"
        r"(?:\[([^\]]+)\]|\"([^\"]+)\"|`([^`]+)`|([A-Za-z_][\w]*))"
        r"(?:\.(?:\[([^\]]+)\]|\"([^\"]+)\"|`([^`]+)`|([A-Za-z_][\w]*)))?",
        re.IGNORECASE,
    )

    deps: dict[str, set[str]] = {}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='view' AND sql IS NOT NULL"
        ).fetchall()
        for view_name, sql in rows:
            refs: set[str] = set()
            for m in ref_re.finditer(sql or ""):
                # Pick the rightmost non-empty group: 5-8 are the parts after `.`
                # (schema-qualified case), 1-4 are the bare/first identifier.
                schema_part = next((g for g in m.groups()[0:4] if g), None)
                name_part = next((g for g in m.groups()[4:8] if g), None)
                ident = name_part or schema_part
                if not ident:
                    continue
                if ident.lower() in {"select", "where", "on", "and", "or", "as"}:
                    continue
                refs.add(ident)
            deps[view_name] = refs
    finally:
        conn.close()
    return deps


def build_fk_graph(fks: list[dict]) -> dict[str, list[dict]]:
    """Build bidirectional adjacency list keyed by uppercase table name.

    Returns:
        { TABLE_UPPER: [{target, src_col, tgt_col, kind, direction}] }
    """
    graph: dict[str, list[dict]] = defaultdict(list)
    seen = set()
    for fk in fks:
        src_u = fk["source"].upper()
        tgt_u = fk["target"].upper()
        key_out = (src_u, tgt_u, fk["src_col"], fk["tgt_col"], fk["kind"])
        key_in = (tgt_u, src_u, fk["tgt_col"], fk["src_col"], fk["kind"])
        if key_out not in seen:
            graph[src_u].append(
                {
                    "target": fk["target"],
                    "src_col": fk["src_col"],
                    "tgt_col": fk["tgt_col"],
                    "kind": fk["kind"],
                    "direction": "outgoing",
                }
            )
            seen.add(key_out)
        if key_in not in seen:
            graph[tgt_u].append(
                {
                    "target": fk["source"],
                    "src_col": fk["tgt_col"],
                    "tgt_col": fk["src_col"],
                    "kind": fk["kind"],
                    "direction": "incoming",
                }
            )
            seen.add(key_in)
    return dict(graph)


# =============================================================================
# ENTITIES PER CONCEPT
# =============================================================================


def empty_table_data() -> dict:
    return {
        "row_count": None,
        "tblex": [],
        "tblco": [],
        "tblfz": [],  # via str
        "colex": [],
        "colco": [],
        "colfz": [],  # (col, via)
        "fvex": [],
        "fvco": [],
        "fvfz": [],  # (col, anon, via)
        "value_other": [],  # (col, anon, via)
    }


def empty_view_data() -> dict:
    return {
        "row_count": None,
        "vueex": [],
        "vueco": [],
        "vuefz": [],
        "vcolex": [],
        "vcolco": [],
        "vcolfz": [],
        "fvex": [],
        "fvco": [],
        "fvfz": [],
        "value_other": [],
    }


# =============================================================================
# Filter loading — Phase 1.2.5 (entity drops) + Phase 1.2.6 (term routing)
# =============================================================================
# Branchement officiel des sorties standalone des phases LLM amont. Si les
# fichiers ne sont pas présents, on continue sans filtrer (backward compat).

_DROPPED_ENTITIES_FILE = ROOT / "outputs" / "llm_filter" / "dropped_entities.json"
_CURATE_DIR = ROOT / "outputs" / "llm_curate"

# Mapping dimension Phase 1.4 → lettre de routing curate
_DIM_TO_LETTER = {
    "TABLE": "T",
    "VIEW": "V",
    "COLUMN": "C",
    "VIEW_COLUMN": "VC",
    "VALUE": "Val",
}


def load_dropped_entities() -> set[str]:
    """Lit `outputs/llm_filter/dropped_entities.json` et retourne l'union
    drop_tables ∪ drop_views. Lower-case pour comparaison robuste downstream.

    Si le fichier n'existe pas / est mode questions / mode unexpected, retourne
    set vide (= pas de filtrage, backward compat).
    """
    if not _DROPPED_ENTITIES_FILE.exists():
        return set()
    try:
        data = json.loads(_DROPPED_ENTITIES_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()
    if data.get("mode") != "filter":
        return set()
    drops: set[str] = set()
    for n in data.get("drop_tables", []) + data.get("drop_views", []):
        if isinstance(n, str):
            drops.add(n)
    return drops


def _parse_routing_combo(key: str) -> set[str]:
    """`'[T,V,C,VC]'` → `{'T','V','C','VC'}`. Tolère les espaces."""
    inner = key.strip().lstrip("[").rstrip("]")
    return {part.strip() for part in inner.split(",") if part.strip()}


def load_curate_routing() -> dict[str, dict[str, set[str]]]:
    """Lit `outputs/llm_curate/*.json` et construit, par concept, un dict
    `{term_lower: set_of_allowed_dimension_letters}`.

    Si un terme n'est pas dans le routing du concept, il sera traité comme
    "non routé" → on ne filtrera PAS sur ce terme (tolérance — le LLM curate
    a pu en oublier, mieux vaut sur-conserver que sur-filtrer).

    Si le concept n'a pas de fichier curate / mode=questions, on retourne
    pas d'entrée pour ce concept → aucun filtrage côté curate pour lui.
    """
    routing: dict[str, dict[str, set[str]]] = {}
    if not _CURATE_DIR.exists():
        return routing
    for fp in sorted(_CURATE_DIR.glob("*.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        concept = data.get("concept")
        if not concept or data.get("mode") != "routing":
            continue
        term_to_dims: dict[str, set[str]] = {}
        for combo_key, terms in data.get("routing", {}).items():
            dims = _parse_routing_combo(combo_key)
            for t in terms:
                if not isinstance(t, str):
                    continue
                tk = t.lower().strip()
                if not tk:
                    continue
                term_to_dims.setdefault(tk, set()).update(dims)
        if term_to_dims:
            routing[concept] = term_to_dims
    return routing


def _is_match_allowed_by_routing(
    concept_routing: dict[str, set[str]] | None,
    via: str,
    dim_str: str,
) -> bool:
    """Décide si un match (via, dimension) est autorisé pour ce concept.

    Règle :
    - Si concept_routing est None (pas de fichier curate pour ce concept) → autorisé
    - Sinon, le terme `via` doit être dans le routing ET la dimension doit y être
    - Si le terme n'est PAS dans le routing du concept (oubli LLM possible) → autorisé
      par tolérance (on ne pénalise pas un terme que le LLM a oublié de classer)
    """
    if concept_routing is None:
        return True
    allowed = concept_routing.get(via.lower().strip())
    if allowed is None:
        return True  # tolérance : terme non listé → on garde
    dim_letter = _DIM_TO_LETTER.get(dim_str)
    if dim_letter is None:
        return True
    return dim_letter in allowed


def build_entities_per_concept(
    phase14: dict[str, dict[str, list[dict]]],
    concept_values: dict[str, list[str]],
    dropped_entities: set[str] | None = None,
    curate_routing: dict[str, dict[str, set[str]]] | None = None,
) -> dict[str, dict]:
    """For each concept, group matches by entity (table or view).

    Args:
        dropped_entities: si fourni, les matches dont l'entité (table_name ou
            view_name) appartient à ce set sont ignorés. Branche Phase 1.2.5.
        curate_routing: si fourni, dict {concept: {term_lower: set_of_dims}}.
            Les matches dont (via, dim) n'est pas dans le routing du concept
            sont ignorés. Branche Phase 1.2.6.

    Returns:
        { concept: {"tables": {tbl_name: data}, "views": {vue_name: data}} }
    """
    drops = dropped_entities or set()
    routing = curate_routing or {}
    result: dict[str, dict] = {}

    # Compteurs de filtrage pour log/visibilité
    skipped_dropped = 0
    skipped_routing = 0

    for concept, by_dim in phase14.items():
        tables: dict[str, dict] = defaultdict(empty_table_data)
        views: dict[str, dict] = defaultdict(empty_view_data)
        cr = routing.get(concept)

        # 1) TABLE matches
        for m in by_dim["TABLE"]:
            tbl, _ = split_target(m["target"])
            if tbl in drops:
                skipped_dropped += 1
                continue
            if not _is_match_allowed_by_routing(cr, m["via"], "TABLE"):
                skipped_routing += 1
                continue
            rc = extract_row_count(m["stats"])
            if rc:
                tables[tbl]["row_count"] = rc
            key = {"exact": "tblex", "contains": "tblco", "fuzzy": "tblfz"}[m["match_type"]]
            tables[tbl][key].append(m["via"])

        # 2) VIEW matches
        for m in by_dim["VIEW"]:
            v, _ = split_target(m["target"])
            if v in drops:
                skipped_dropped += 1
                continue
            if not _is_match_allowed_by_routing(cr, m["via"], "VIEW"):
                skipped_routing += 1
                continue
            key = {"exact": "vueex", "contains": "vueco", "fuzzy": "vuefz"}[m["match_type"]]
            views[v][key].append(m["via"])

        # 3) COLUMN matches (parent = table)
        for m in by_dim["COLUMN"]:
            tbl, col = split_target(m["target"])
            if col is None:
                continue
            if tbl in drops:
                skipped_dropped += 1
                continue
            if not _is_match_allowed_by_routing(cr, m["via"], "COLUMN"):
                skipped_routing += 1
                continue
            key = {"exact": "colex", "contains": "colco", "fuzzy": "colfz"}[m["match_type"]]
            tables[tbl][key].append((col, m["via"]))
            rc = extract_row_count(m["stats"])
            if rc and not tables[tbl]["row_count"]:
                tables[tbl]["row_count"] = rc

        # 4) VIEW_COLUMN matches (parent = view)
        for m in by_dim["VIEW_COLUMN"]:
            v, col = split_target(m["target"])
            if col is None:
                continue
            if v in drops:
                skipped_dropped += 1
                continue
            if not _is_match_allowed_by_routing(cr, m["via"], "VIEW_COLUMN"):
                skipped_routing += 1
                continue
            key = {"exact": "vcolex", "contains": "vcolco", "fuzzy": "vcolfz"}[m["match_type"]]
            views[v][key].append((col, m["via"]))

        # Determine entities seen so far
        table_names = set(tables.keys())
        view_names = set(views.keys())

        # 5) VALUE matches — distinguish "value of concept" vs "value other"
        val_keys: set[str] = set()
        for v in concept_values.get(concept, []):
            val_keys.add(v.lower().strip())
            for part in v.split():
                if len(part) > 2:
                    val_keys.add(part.lower().strip())

        for m in by_dim["VALUE"]:
            ent, col = split_target(m["target"])
            if col is None:
                continue
            if ent in drops:
                skipped_dropped += 1
                continue
            if not _is_match_allowed_by_routing(cr, m["via"], "VALUE"):
                skipped_routing += 1
                continue
            anon = extract_anon(m["stats"])
            via = m["via"]
            is_val = via.lower().strip() in val_keys
            target_dict = (
                tables[ent]
                if ent in table_names
                else (
                    views[ent] if ent in view_names else tables[ent]
                )  # default → table when unknown
            )
            if is_val:
                key = {"exact": "fvex", "contains": "fvco", "fuzzy": "fvfz"}[m["match_type"]]
                target_dict[key].append((col, anon, via))
            else:
                target_dict["value_other"].append((col, anon, via))
            rc = extract_row_count(m["stats"])
            if ent in table_names and rc and not tables[ent]["row_count"]:
                tables[ent]["row_count"] = rc

        result[concept] = {"tables": dict(tables), "views": dict(views)}

    if drops or routing:
        print(
            f"  Filtres appliqués : {skipped_dropped} matches droppés "
            f"(Phase 1.2.5 entities) + {skipped_routing} matches hors routing "
            f"(Phase 1.2.6 curate)"
        )

    return result


# =============================================================================
# SCORING ENGINE
# =============================================================================


def cap_via_counts(items: list, key_via_extractor) -> int:
    """Compute a cap-saturated count: sum of min(count_per_via, CAP_PER_VIA).

    items is a list whose elements yield a 'via' string via the extractor.
    """
    if not items:
        return 0
    via_counts = Counter(key_via_extractor(it) for it in items)
    return sum(min(n, CAP_PER_VIA) for n in via_counts.values())


def score_entity_for_concept(
    data: dict, has_values: bool, is_view: bool
) -> tuple[float, dict[str, int]]:
    """Compute weighted, cap-saturated score for an entity in a given concept.

    Returns (score, breakdown_per_bucket).
    """
    if is_view:
        priorities = PRIO_VUE_WITH_VALUES if has_values else PRIO_VUE_NO_VALUES
    else:
        priorities = PRIO_TBL_WITH_VALUES if has_values else PRIO_TBL_NO_VALUES

    breakdown: dict[str, int] = {}
    score = 0.0
    for key, _label, _op in priorities:
        items = data.get(key, [])
        if not items:
            continue
        if key.startswith("tbl") or key.startswith("vue"):
            cap_count = cap_via_counts(items, lambda v: v)
        elif key.startswith("col") or key.startswith("vcol"):
            cap_count = cap_via_counts(items, lambda t: t[1])
        else:  # fv*
            cap_count = cap_via_counts(items, lambda t: t[2])
        breakdown[key] = cap_count
        score += WEIGHTS.get(key, 0) * cap_count
    return score, breakdown


def normalize_per_concept(
    scores_per_entity_per_concept: dict[str, dict[str, float]],
) -> dict[str, dict[str, float]]:
    """Min-max normalize scores within each concept, *malus artefact appliqué*.

    Si on normalise sur les raw scores bruts, une table artefact à fort
    signal (ex: TempRptProdUser avec FvCo=170) devient le 1.0 du concept
    et écrase la vraie source canonique. On applique donc d'abord le malus
    artefact (×ARTIFACT_MULT) pour que les tables canoniques non-artefact
    aient une chance de devenir le pic du concept.
    """
    out: dict[str, dict[str, float]] = {}
    for concept, ent_scores in scores_per_entity_per_concept.items():
        if not ent_scores:
            out[concept] = {}
            continue
        # Apply artifact penalty BEFORE max-normalization
        effective = {
            ent: sc * (ARTIFACT_MULT if is_artifact(ent) else 1.0) for ent, sc in ent_scores.items()
        }
        m = max(effective.values())
        if m <= 0:
            out[concept] = {k: 0.0 for k in effective}
        else:
            out[concept] = {k: v / m for k, v in effective.items()}
    return out


def is_artifact(name: str) -> bool:
    """Detect artifact tables/views by generic DBA naming convention.

    Uses `re.search` so fragment alternations (TEMP, IMPR, PDF, …) match
    anywhere in the name (e.g. `FactureImpr`, `dbo_viewTempBudgAct04`).
    The first prefix branch is anchored via `^` inside the regex itself.
    """
    return bool(ARTIFACT_REGEX.search(name))


def canonicity_bonus_for_entity(breakdowns: dict[str, dict[str, dict]], ent: str) -> float:
    """Compute canonicity bonus across all concepts for an entity.

    Pour chaque concept où l'entité a des FvEx, on calcule le ratio
    FvEx / (FvCo + 1). Une table canonique a un haut ratio (signal pur,
    peu de bruit textuel) ; une table de log/reporting a un ratio bas
    (les FvEx sont noyées dans les FvCo qui matchent par hasard les
    libellés). On retient le ratio max sur tous les concepts touchés.

    Cap CANONICITY_RATIO_CAP pour éviter l'explosion quand FvCo=0.
    """
    max_ratio = 0.0
    for concept, ent_brk in breakdowns.items():
        brk = ent_brk.get(ent, {})
        fvex = brk.get("fvex", 0)
        fvco = brk.get("fvco", 0)
        if fvex <= 0:
            continue
        ratio = min(fvex / (fvco + 1), CANONICITY_RATIO_CAP)
        if ratio > max_ratio:
            max_ratio = ratio
    if max_ratio <= 0:
        return 1.0
    return 1 + CANONICITY_BONUS_RATE * math.log(1 + max_ratio)


def compute_global_scores(
    norm_per_concept: dict[str, dict[str, float]],
    fk_graph: dict[str, list[dict]],
    breakdowns: dict[str, dict[str, dict]] | None = None,
    row_counts: dict[str, str] | None = None,
    view_centrality_bonuses: dict[str, float] | None = None,
) -> dict[str, dict]:
    """Aggregate per-concept normalized scores into a global score per entity.

    Formula:
        sum_concepts        = Σ normalized_score
        max_per_concept     = max normalized_score across concepts (signal pic)
        n_concepts_touched  = count of concepts with score > 0
        multi_bonus         = 1 + 0.15 × (n - 1) for n ≥ 1 (calibré bas pour
                              ne pas dominer)
        fk_bonus            = 1 + 0.08 × log(1 + degree)
        exact_bonus         = 1 + 0.5 × indicator(any TblEx or ColEx in any concept)
        size_bonus          = 1 + 0.05 × log10(1 + row_count) si row_count > 0
        artifact_mult       = ARTIFACT_MULT (×0.35) si nom matche regex artefact
        raw_global          = (0.7 × sum + 0.3 × n × max_per_concept)
                              × multi_bonus × fk_bonus × exact_bonus
                              × size_bonus × artifact_mult

    L'ajout de `max_per_concept` évite que les tables transversales avec signal
    moyen dominent celles qui ont un signal fort sur 1-2 concepts précis.
    """
    by_entity: dict[str, dict] = defaultdict(
        lambda: {
            "sum": 0.0,
            "n_concepts": 0,
            "per_concept": {},
            "max_per_concept": 0.0,
        }
    )
    for concept, ent_scores in norm_per_concept.items():
        for ent, sc in ent_scores.items():
            if sc <= 0:
                continue
            by_entity[ent]["sum"] += sc
            by_entity[ent]["n_concepts"] += 1
            by_entity[ent]["per_concept"][concept] = sc
            if sc > by_entity[ent]["max_per_concept"]:
                by_entity[ent]["max_per_concept"] = sc

    # Detect "has any exact match" per entity across concepts
    has_exact: dict[str, bool] = defaultdict(bool)
    if breakdowns is not None:
        exact_keys = ("tblex", "colex", "vueex", "vcolex", "fvex")
        for concept, ent_breaks in breakdowns.items():
            for ent, brk in ent_breaks.items():
                for k in exact_keys:
                    if brk.get(k, 0) > 0:
                        has_exact[ent] = True
                        break

    for ent, data in by_entity.items():
        n = data["n_concepts"]
        s = data["sum"]
        mx = data["max_per_concept"]
        # Combined signal: COMBINED_SUM_WEIGHT × somme normalisée + COMBINED_MAX_WEIGHT × n × pic
        combined = COMBINED_SUM_WEIGHT * s + COMBINED_MAX_WEIGHT * n * mx
        multi_bonus = 1 + MULTI_BONUS_RATE * (n - 1) if n >= 1 else 1.0
        degree = len(fk_graph.get(ent.upper(), []))
        fk_bonus = 1 + FK_BONUS_RATE * math.log(1 + degree)
        exact_bonus = EXACT_BONUS if has_exact.get(ent, False) else 1.0
        rc_str = (row_counts or {}).get(ent, "")
        try:
            rc = int(rc_str.replace(",", "")) if rc_str else 0
        except ValueError:
            rc = 0
        size_bonus = 1 + SIZE_BONUS_RATE * math.log10(1 + rc) if rc > 0 else 1.0
        # NOTE: artifact_mult déjà appliqué dans normalize_per_concept (sur
        # les raw scores). Ne PAS le réappliquer ici sinon double pénalité.
        view_bonus = (view_centrality_bonuses or {}).get(ent, 1.0)
        canonicity_b = canonicity_bonus_for_entity(breakdowns, ent) if breakdowns else 1.0
        raw = (
            combined * multi_bonus * fk_bonus * exact_bonus * size_bonus * view_bonus * canonicity_b
        )
        data["raw"] = raw
        data["combined"] = combined
        data["multi_bonus"] = multi_bonus
        data["fk_bonus"] = fk_bonus
        data["exact_bonus"] = exact_bonus
        data["size_bonus"] = size_bonus
        data["view_bonus"] = view_bonus
        data["canonicity_bonus"] = canonicity_b
        data["artifact_mult"] = ARTIFACT_MULT if is_artifact(ent) else 1.0
        data["fk_degree"] = degree
        data["has_exact"] = has_exact.get(ent, False)
        data["row_count"] = rc

    if by_entity:
        m = max(d["raw"] for d in by_entity.values())
        for d in by_entity.values():
            d["proba"] = d["raw"] / m if m > 0 else 0.0
    return dict(by_entity)


def classify_entity(name: str, all_per_concept: dict[str, dict]) -> str:
    """Determine if entity is mostly seen as table or view across concepts.

    Returns 'T' (table) or 'V' (view).
    """
    table_hits = 0
    view_hits = 0
    for concept_data in all_per_concept.values():
        if name in concept_data["tables"]:
            table_hits += 1
        if name in concept_data["views"]:
            view_hits += 1
    return "V" if view_hits > table_hits else "T"


# =============================================================================
# RENDERERS
# =============================================================================


def wrap_csv(items: list[str], indent: str = "       ") -> list[str]:
    """Wrap a list of strings as comma-separated, indented, capped at WRAP_WIDTH."""
    if not items:
        return []
    out: list[str] = []
    line = indent
    first = True
    for item in items:
        sep = "" if first else ", "
        candidate = line + sep + item
        if len(candidate) > WRAP_WIDTH and not first:
            out.append(line.rstrip(", "))
            line = indent + item
        else:
            line = candidate
        first = False
    if line.strip():
        out.append(line)
    return out


def render_via_group(
    label: str,
    op: str,
    items: list,
    kind: str,
    display_cap_per_via: int | None = None,
) -> list[str]:
    """Render one bucket (e.g. ColCo) grouped by 'via' term, with CSV-wrapped names.

    kind ∈ {"tbl_or_vue", "col_or_vcol", "fv_or_value"}.
    Si display_cap_per_via est défini, tronque chaque groupe `via` à N items
    avec marqueur ` …(+M en annexe)`. L'annexe garde l'intégralité.
    """
    out: list[str] = []
    if not items:
        return out
    out.append(f"   {label} ({len(items)}):")

    if kind == "tbl_or_vue":
        c = Counter(items)
        ordered = sorted(c.items(), key=lambda x: -x[1])
        names = [f"{v} (×{n})" if n > 1 else v for v, n in ordered]
        out.extend(wrap_csv(names, indent="     " + op + " "))
    elif kind == "col_or_vcol":
        groups: dict[str, list[str]] = defaultdict(list)
        for col, via in items:
            groups[via].append(col)
        for via in sorted(groups, key=lambda v: -len(groups[v])):
            cols = sorted(set(groups[via]))
            out.append(f"     {op} {via} ({len(cols)}):")
            out.extend(wrap_csv(cols, indent="       "))
    elif kind == "fv_or_value":
        groups2: dict[str, list[tuple[str, str | None]]] = defaultdict(list)
        for col, anon, via in items:
            groups2[via].append((col, anon))
        for via in sorted(groups2, key=lambda v: -len(groups2[v])):
            entries = groups2[via]
            out.append(f"     {op} {via} ({len(entries)}):")
            by_col: dict[str, list[str]] = defaultdict(list)
            for col, anon in entries:
                if anon:
                    by_col[col].append(anon)
                else:
                    by_col.setdefault(col, [])
            tokens: list[str] = []
            cap_anons = DISPLAY_CAP_ANONS_PER_COL if display_cap_per_via is not None else None
            for col in sorted(by_col):
                anons = [a for a in by_col[col] if a]
                if not anons:
                    tokens.append(col)
                elif len(set(anons)) == 1:
                    tokens.append(f"{col}='{anons[0]}'")
                else:
                    uniq = sorted(set(anons))
                    if cap_anons is not None and len(uniq) > cap_anons:
                        more = len(uniq) - cap_anons
                        shown = uniq[:cap_anons]
                        quoted = ",".join(f"'{v}'" for v in shown)
                        tokens.append(f"{col}={{{quoted},+{more}}}")
                    else:
                        quoted = ",".join(f"'{v}'" for v in uniq)
                        tokens.append(f"{col}={{{quoted}}}")
            # Apply display cap if any
            if display_cap_per_via is not None and len(tokens) > display_cap_per_via:
                kept = tokens[:display_cap_per_via]
                overflow = len(tokens) - display_cap_per_via
                kept[-1] = kept[-1] + f"  …(+{overflow} en annexe)"
                tokens = kept
            out.extend(wrap_csv(tokens, indent="       "))
    return out


def render_compressed_variant_b(
    concept: str,
    concept_data: dict,
    has_values: bool,
    shortlist: set[str] | None = None,
    global_scores: dict[str, dict] | None = None,
    view_top_refs: dict[str, list[str]] | None = None,
    eff_local_norm: dict[str, float] | None = None,
) -> list[str]:
    """Render the compressed Variant-B section for one concept.

    Tri primaire = `global_scores[name]["proba"]` (probabilité globale
    multi-concept). Pertinence transversale > signal local. En cas
    d'égalité (ou entité sans proba globale), fallback au signal local
    pondéré, puis au nom alphabétique pour déterminisme.

    Si `shortlist` est fourni, restreint aux entités du Principal.
    `view_top_refs` permet d'annoter chaque vue de ses tables sources
    shortlistées (info contextuelle pour le LLM aval).
    """
    prio_t = PRIO_TBL_WITH_VALUES if has_values else PRIO_TBL_NO_VALUES
    prio_v = PRIO_VUE_WITH_VALUES if has_values else PRIO_VUE_NO_VALUES

    out: list[str] = []
    out.append("=" * 80)
    label = concept
    out.append(f"CONCEPT: {label}")
    out.append(f"Priorités tables: {' > '.join(l for _, l, _ in prio_t)}")
    out.append(f"Priorités vues  : {' > '.join(l for _, l, _ in prio_v)}")
    if has_values:
        out.append(
            "Tri = lexicographique strict sur les buckets de priorités "
            "(FvEx domine, puis FvCo, ...). Artefacts toujours après non-artefacts."
        )
    else:
        out.append(
            f"Tri = {LOCAL_WEIGHT_NO_VALUES:.1f}·local_effectif + "
            f"{1-LOCAL_WEIGHT_NO_VALUES:.1f}·proba_globale (concept sans valeurs : "
            "matching textuel local bruyant, proba globale plus stable)."
        )
    out.append("=" * 80)

    tables = concept_data.get("tables", {})
    views = concept_data.get("views", {})

    if shortlist is not None:
        tables = {n: d for n, d in tables.items() if n in shortlist}
        views = {n: d for n, d in views.items() if n in shortlist}

    drop_val = True

    def sort_key(name: str, data: dict, prio: list[tuple[str, str, str]]):
        if has_values:
            return _lex_local_key(name, data, prio)
        # Concept sans valeurs : mix pondéré local + proba globale
        loc = (eff_local_norm or {}).get(name, 0.0)
        proba = (global_scores or {}).get(name, {}).get("proba", 0.0)
        combined = LOCAL_WEIGHT_NO_VALUES * loc + (1 - LOCAL_WEIGHT_NO_VALUES) * proba
        return (-combined, name)

    out.append("")
    out.append("─── TABLES " + "─" * 70)
    out.append("")
    for name, data in sorted(tables.items(), key=lambda kv: sort_key(kv[0], kv[1], prio_t)):
        out.extend(
            _render_one_entity(
                name,
                data,
                prio_t,
                is_view=False,
                drop_value_other=drop_val,
                apply_display_cap=True,
                proba=(global_scores or {}).get(name, {}).get("proba"),
                view_refs=None,
            )
        )

    out.append("─── VUES " + "─" * 72)
    out.append("")
    for name, data in sorted(views.items(), key=lambda kv: sort_key(kv[0], kv[1], prio_v)):
        out.extend(
            _render_one_entity(
                name,
                data,
                prio_v,
                is_view=True,
                drop_value_other=drop_val,
                apply_display_cap=True,
                proba=(global_scores or {}).get(name, {}).get("proba"),
                view_refs=(view_top_refs or {}).get(name),
            )
        )

    return out


def _weighted_signal(data: dict, prio: list[tuple[str, str, str]]) -> float:
    """Sort key for entities within a concept: weighted, capped score.

    Aligned with score_entity_for_concept (cap-saturated × WEIGHTS) so that
    the per-concept compressed view ranks entities consistently with the
    global probability table.
    """
    score = 0.0
    for key, _, _ in prio:
        items = data.get(key, [])
        if not items:
            continue
        if key.startswith("tbl") or key.startswith("vue"):
            cap_count = cap_via_counts(items, lambda v: v)
        elif key.startswith("col") or key.startswith("vcol"):
            cap_count = cap_via_counts(items, lambda t: t[1])
        else:
            cap_count = cap_via_counts(items, lambda t: t[2])
        score += WEIGHTS.get(key, 0) * cap_count
    return score


def _lex_local_key(
    name: str,
    data: dict,
    prio: list[tuple[str, str, str]],
) -> tuple:
    """Strict lexicographic sort key on priority buckets (descending counts).

    Reproduit le tri de l'ancien fichier `search_results_test.txt`
    (FvEx > FvCo > ColEx > TblEx > ColCo > ...) où la première dimension
    domine et les autres ne servent qu'aux tie-breaks.

    Tuple = (is_artifact, -bucket1, -bucket2, ..., name)
    - `is_artifact` en tête : False < True → non-artefacts toujours d'abord
    - Buckets en `-count` : descending order
    - `name` en queue : déterminisme alphabétique
    """
    parts: list = [is_artifact(name)]
    for key, _, _ in prio:
        items = data.get(key, [])
        if not items:
            n = 0
        elif key.startswith(("tbl", "vue")):
            n = cap_via_counts(items, lambda v: v)
        elif key.startswith(("col", "vcol")):
            n = cap_via_counts(items, lambda t: t[1])
        else:
            n = cap_via_counts(items, lambda t: t[2])
        parts.append(-n)
    parts.append(name)
    return tuple(parts)


def _effective_local_score(
    name: str,
    data: dict,
    prio: list[tuple[str, str, str]],
) -> float:
    """Per-concept ranking signal = raw weighted × artifact × canonicity.

    Différent du score global : pas de bonus multi-concept ni FK ni
    view-centrality (qui dilueraient le ranking local). On garde
    seulement les signaux *intrinsèques* à l'entité dans ce concept :
    le poids des matches (capés par via), le malus artefact, le bonus
    canonicité (FvEx propre vs FvCo bruyant).
    """
    raw = _weighted_signal(data, prio)
    if raw <= 0:
        return 0.0
    artifact_m = ARTIFACT_MULT if is_artifact(name) else 1.0
    fvex = sum(min(c, CAP_PER_VIA) for c in Counter(t[2] for t in data.get("fvex", [])).values())
    fvco = sum(min(c, CAP_PER_VIA) for c in Counter(t[2] for t in data.get("fvco", [])).values())
    if fvex > 0:
        ratio = min(fvex / (fvco + 1), CANONICITY_RATIO_CAP)
        canonicity = 1 + CANONICITY_BONUS_RATE * math.log(1 + ratio)
    else:
        canonicity = 1.0
    return raw * artifact_m * canonicity


def render_overflow_section(
    concept: str,
    concept_data: dict,
    has_values: bool,
    shortlist: set[str],
    global_scores: dict[str, dict] | None = None,
    view_top_refs: dict[str, list[str]] | None = None,
    eff_local_norm: dict[str, float] | None = None,
) -> list[str]:
    """Annex section: entities NOT in shortlist for this concept, full data preserved.

    Tri identique au Principal (mix α·local + (1-α)·global selon has_values).
    """
    prio_t = PRIO_TBL_WITH_VALUES if has_values else PRIO_TBL_NO_VALUES
    prio_v = PRIO_VUE_WITH_VALUES if has_values else PRIO_VUE_NO_VALUES

    tables = {n: d for n, d in concept_data.get("tables", {}).items() if n not in shortlist}
    views = {n: d for n, d in concept_data.get("views", {}).items() if n not in shortlist}

    if not tables and not views:
        return []

    out: list[str] = []
    out.append("=" * 80)
    out.append(f"CONCEPT: {concept}  (entités hors shortlist du Principal)")
    out.append("=" * 80)
    out.append("")

    drop_val = False

    def sort_key(name: str, data: dict, prio: list[tuple[str, str, str]]):
        if has_values:
            return _lex_local_key(name, data, prio)
        loc = (eff_local_norm or {}).get(name, 0.0)
        proba = (global_scores or {}).get(name, {}).get("proba", 0.0)
        combined = LOCAL_WEIGHT_NO_VALUES * loc + (1 - LOCAL_WEIGHT_NO_VALUES) * proba
        return (-combined, name)

    if tables:
        out.append("─── TABLES (overflow) " + "─" * 60)
        out.append("")
        for name, data in sorted(tables.items(), key=lambda kv: sort_key(kv[0], kv[1], prio_t)):
            out.extend(
                _render_one_entity(
                    name,
                    data,
                    prio_t,
                    is_view=False,
                    drop_value_other=drop_val,
                    apply_display_cap=False,
                    proba=(global_scores or {}).get(name, {}).get("proba"),
                    view_refs=None,
                )
            )
    if views:
        out.append("─── VUES (overflow) " + "─" * 62)
        out.append("")
        for name, data in sorted(views.items(), key=lambda kv: sort_key(kv[0], kv[1], prio_v)):
            out.extend(
                _render_one_entity(
                    name,
                    data,
                    prio_v,
                    is_view=True,
                    drop_value_other=drop_val,
                    apply_display_cap=False,
                    proba=(global_scores or {}).get(name, {}).get("proba"),
                    view_refs=(view_top_refs or {}).get(name),
                )
            )
    return out


def _render_one_entity(
    name: str,
    data: dict,
    prio: list[tuple[str, str, str]],
    is_view: bool,
    drop_value_other: bool,
    apply_display_cap: bool = True,
    proba: float | None = None,
    view_refs: list[str] | None = None,
) -> list[str]:
    out: list[str] = []
    rc = f" ({data['row_count']}r)" if data.get("row_count") else ""
    has_any = any(data.get(k, []) for k, _, _ in prio)
    n_val = len(data.get("value_other", []))
    if not has_any and (not n_val or drop_value_other):
        return out
    prefix = "[V]" if is_view else "[T]"
    annex_marker = ""
    if drop_value_other and n_val:
        annex_marker = f"  +Annex({n_val})"
    elif (not has_any) and n_val:
        annex_marker = f"  ⏬ matches Val uniquement (×{n_val})"
    proba_str = f" | proba={proba:.2f}" if proba is not None else ""
    refs_str = ""
    if view_refs:
        # Affiche jusqu'à 6 refs, le reste en …
        refs_show = view_refs[:6]
        more = "" if len(view_refs) <= 6 else "…"
        refs_str = f" ↪{{{','.join(refs_show)}{more}}}"
    out.append(f"{prefix} {name}{rc}{proba_str}{refs_str}{annex_marker}")

    for key, label, op in prio:
        items = data.get(key, [])
        if not items:
            continue
        if key.startswith("tbl") or key.startswith("vue"):
            kind = "tbl_or_vue"
            cap = None
        elif key.startswith("col") or key.startswith("vcol"):
            kind = "col_or_vcol"
            cap = None
        else:  # fv*
            kind = "fv_or_value"
            cap = DISPLAY_CAP_FV_PER_VIA if apply_display_cap else None
        out.extend(render_via_group(label, op, items, kind, display_cap_per_via=cap))

    if not drop_value_other and n_val:
        cap = DISPLAY_CAP_VAL_PER_VIA if apply_display_cap else None
        out.extend(
            render_via_group(
                "Val(autre)",
                "⊂",
                data["value_other"],
                "fv_or_value",
                display_cap_per_via=cap,
            )
        )

    out.append("")
    return out


def render_annex_section(concept: str, concept_data: dict) -> list[str]:
    """Annex: Val(autre) preserved per concept, hors prompt principal."""
    out: list[str] = []
    out.append("=" * 80)
    out.append(f"CONCEPT: {concept}")
    out.append("=" * 80)
    out.append("")

    has_anything = False
    for kind_label, entities in (
        ("[T] TABLES", concept_data.get("tables", {})),
        ("[V] VUES", concept_data.get("views", {})),
    ):
        section_lines: list[str] = []
        for name, data in sorted(entities.items()):
            n_val = len(data.get("value_other", []))
            if not n_val:
                continue
            has_anything = True
            section_lines.append(f"{kind_label[0:3]} {name} (Val_autre={n_val})")
            section_lines.extend(
                render_via_group("Val(autre)", "⊂", data["value_other"], "fv_or_value")
            )
            section_lines.append("")
        if section_lines:
            out.append("─── " + kind_label + " " + "─" * (74 - len(kind_label)))
            out.append("")
            out.extend(section_lines)
    if not has_anything:
        out.append("(aucun match Val(autre) pour ce concept)")
        out.append("")
    return out


def render_user_query(query: str) -> list[str]:
    out = []
    out.append("┌" + "─" * 78 + "┐")
    out.append("│ DEMANDE UTILISATEUR" + " " * 58 + "│")
    out.append("├" + "─" * 78 + "┤")
    for line in textwrap.wrap(query, width=76) or [""]:
        padding = 76 - len(line)
        out.append(f"│ {line}{' ' * padding} │")
    out.append("└" + "─" * 78 + "┘")
    return out


def proba_bar(proba: float, width: int = 12) -> str:
    # Clamp pour résister aux floats limites (>1.0 ou <0.0) qui causeraient
    # un nombre négatif de caractères et raise ValueError sur multiplication.
    p = max(0.0, min(1.0, proba))
    filled = int(round(p * width))
    return "▓" * filled + "░" * (width - filled)


def render_probability_table(
    global_scores: dict[str, dict],
    classification: dict[str, str],
    fk_graph: dict[str, list[dict]],
    concept_values: dict[str, list[str]],
    norm_per_concept: dict[str, dict[str, float]],
    view_top_refs: dict[str, list[str]] | None = None,
    top_n: int = TOP_N_PROBABILITIES,
) -> list[str]:
    """Render the inclusion-probability table (top N entities)."""
    out: list[str] = []
    out.append("=" * 80)
    out.append("TABLEAU DES PROBABILITÉS D'INCLUSION DANS LA REQUÊTE FINALE")
    out.append("=" * 80)
    out.append("")
    out.append(
        f"Score = ({COMBINED_SUM_WEIGHT}·Σ + {COMBINED_MAX_WEIGHT}·n·max) "
        f"× (1 + {MULTI_BONUS_RATE}·(n-1)) × (1 + {FK_BONUS_RATE}·log(1+deg))"
    )
    out.append(f"      × ({EXACT_BONUS} si match exact ≥1) × (1 + {SIZE_BONUS_RATE}·log10(1+rows))")
    out.append(
        f"      × (1 + {VIEW_CENTRALITY_RATE}·n_top_refs si vue référençant n_top tables shortlistées)"
    )
    out.append(
        f"      × (1 + {CANONICITY_BONUS_RATE}·log(1 + FvEx/(FvCo+1)))  ← canonicité (signal pur)"
    )
    out.append(
        f"      Malus artefact (×{ARTIFACT_MULT}) appliqué pré-normalisation par concept "
        "(évite que TempXxx devienne le 1.0 d'un concept)."
    )
    out.append("Probabilité = score normalisé min-max sur l'ensemble des entités.")
    out.append("Les vues annotées ↪{T1,T2,...} référencent ces tables shortlistées dans leur DDL.")
    out.append("")

    # Sort by descending probability with deterministic tie-break on name
    ordered = sorted(global_scores.items(), key=lambda kv: (-kv[1]["proba"], kv[0]))

    out.append(
        f"  {'#':>3}  {'T':<2} {'Entité':<35}  {'Proba':>5}  {'Bar':<14} {'#Conc.':>6} {'FK°':>4}  Top contributions"
    )
    out.append("  " + "─" * 78)

    for idx, (ent, data) in enumerate(ordered[:top_n], start=1):
        cls = classification.get(ent, "T")
        proba = data["proba"]
        bar = proba_bar(proba)
        n_c = data["n_concepts"]
        deg = data.get("fk_degree", 0)

        per_c = data["per_concept"]
        top_c = sorted(per_c.items(), key=lambda x: -x[1])[:3]
        contribs = ", ".join(f"{c}({s:.2f})" for c, s in top_c)
        tags: list[str] = []
        if is_artifact(ent):
            tags.append("[ARTIFACT]")
        if cls == "V" and view_top_refs and view_top_refs.get(ent):
            refs = view_top_refs[ent]
            tags.append("↪{" + ",".join(refs[:6]) + ("…" if len(refs) > 6 else "") + "}")
        suffix = " " + " ".join(tags) if tags else ""
        out.append(
            f"  {idx:>3}  {cls:<2} {ent[:35]:<35}  {proba:>5.2f}  {bar:<14} "
            f"{n_c:>6} {deg:>4}  {contribs}{suffix}"
        )
    out.append("")
    return out


def render_fk_subgraph(top_entities: list[str], fk_graph: dict[str, list[dict]]) -> list[str]:
    """Render the FK subgraph restricted to shortlisted entities."""
    out: list[str] = []
    out.append("=" * 80)
    out.append("SOUS-GRAPHE FK (entités shortlistées uniquement)")
    out.append("=" * 80)
    out.append("Légende: → outgoing (FK depuis), ← incoming (FK vers), ")
    out.append("         <kind=explicit> déclarée par PRAGMA, <kind=implicit> détectée")
    out.append("         par convention <prefix>NoEnreg<Suffix>.")
    out.append("")
    top_upper = {e.upper() for e in top_entities}
    seen_edges: set[tuple] = set()
    for ent in top_entities:
        u = ent.upper()
        edges = fk_graph.get(u, [])
        rendered: list[str] = []
        for e in edges:
            tgt = e["target"]
            if tgt.upper() not in top_upper:
                continue  # restrict to shortlisted
            arrow = "→" if e["direction"] == "outgoing" else "←"
            edge_key = tuple(sorted([u, tgt.upper()])) + (e["src_col"], e["tgt_col"], e["kind"])
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            kind_tag = f"<{e['kind']}>"
            rendered.append(
                f"   {arrow} {tgt}.{e['tgt_col']}  via  {ent}.{e['src_col']}  {kind_tag}"
            )
        if rendered:
            out.append(f"{ent}:")
            out.extend(rendered)
            out.append("")
    if not seen_edges:
        out.append("(aucune arête FK entre les entités shortlistées)")
        out.append("")
    return out


# =============================================================================
# MAIN
# =============================================================================


def _p15_main_legacy():
    import argparse

    ap = argparse.ArgumentParser(description="Phase 1.5 — scoring + sous-graphe FK")
    ap.add_argument(
        "--block-view-mined-fk",
        action="store_true",
        help="MODE TEST : skip extract_join_patterns_from_komptia(). "
        "Le sous-graphe FK ne contient alors que les FK explicites + "
        "implicites (pas les patterns minés depuis les CREATE VIEW). "
        "À combiner avec llm_filter_entities.py --block-all-views pour "
        "tester strictement la pipeline sans aucune connaissance issue "
        "des vues DBA.",
    )
    ap.add_argument(
        "--block-inferred-fk",
        action="store_true",
        help="MODE TEST : skip extract_fk_inferred_persistent(). "
        "Le sous-graphe FK ne contient alors pas les FK *inférées* "
        "empiriquement par schema_sync (T19). Utile pour mesurer le "
        "lift apporté par la couche d'inférence sur une BDD legacy.",
    )
    args = ap.parse_args()

    if not SRC.exists():
        print(f"❌ Input file missing: {SRC}")
        print("   Run scripts/test_pipeline.py first to generate it.")
        return 1
    size = SRC.stat().st_size
    if size == 0:
        print(f"❌ Input file empty: {SRC}")
        return 1
    print(f"Reading {SRC} ({size/1e6:.1f} MB)...")
    with open(SRC, "r", encoding="utf-8") as f:
        lines = f.readlines()
    print(f"  {len(lines):,} lines")
    if not lines:
        print("❌ Input file has no lines")
        return 1
    if not DB.exists():
        print(f"❌ Database missing: {DB}")
        return 1

    print("Parsing user query...")
    query = _p15_parse_user_query(lines)
    print(f"  Query: {query[:90]}...")

    print("Parsing concept→values structure...")
    concept_values = _p15_parse_concept_values(lines)
    print(f"  {len(concept_values)} concepts")
    for c, vs in concept_values.items():
        print(f"    - {c}: {vs if vs else '(no values)'}")

    derivables = _p15_parse_derivables(lines)
    if derivables:
        print(f"  Concepts DÉRIVABLES : {len(derivables)} (skip scoring/rerank)")
        for c, srcs in derivables.items():
            print(f"    - {c} <- {', '.join(srcs)}")

    print("Parsing Phase 1.4 matches...")
    phase14 = parse_phase14(lines, concept_values)
    for c, by_dim in phase14.items():
        sizes = {k: len(v) for k, v in by_dim.items()}
        print(f"    - {c}: {sizes}")

    print(f"Reading FK from {DB.name}...")
    fk_explicit = extract_fk_explicit(DB)
    print(f"  Explicit FK: {len(fk_explicit)}")
    fk_implicit = extract_fk_implicit(DB)
    print(f"  Implicit FK: {len(fk_implicit)}")
    if args.block_view_mined_fk:
        fk_view_mined = []
        print(f"  View-mined FK from komptia.db: SKIPPED (--block-view-mined-fk)")
    else:
        fk_view_mined = extract_join_patterns_from_komptia(KOMPTIA_DB)
        print(f"  View-mined FK from komptia.db: {len(fk_view_mined)}")

    # T19 — FK *inférées* empiriquement par schema_sync (containment des
    # valeurs + matching nommage générique). Table ``inferred_foreign_keys``
    # dans komptia.db, alimentée à chaque sync programmatique. Filtrée à
    # confiance >= _INFERRED_FK_MIN_CONFIDENCE pour ne pas bruiter le graphe.
    if getattr(args, "block_inferred_fk", False):
        fk_inferred = []
        print(f"  Inferred FK from komptia.db: SKIPPED (--block-inferred-fk)")
    else:
        fk_inferred = extract_fk_inferred_persistent(KOMPTIA_DB)
        print(f"  Inferred FK from komptia.db: {len(fk_inferred)}")

    fk_graph = build_fk_graph(fk_explicit + fk_implicit + fk_view_mined + fk_inferred)
    print(f"  FK graph: {len(fk_graph)} nodes")

    # Branchement Phase 1.2.5 (filter entities) + Phase 1.2.6 (curate routing).
    # Si les fichiers ne sont pas présents → set/dict vides → backward compat
    # (pipeline tourne comme avant, sans filtrage LLM amont).
    dropped_entities = load_dropped_entities()
    curate_routing = load_curate_routing()
    if dropped_entities:
        print(f"  Phase 1.2.5 dropped entities chargées : {len(dropped_entities)}")
    if curate_routing:
        n_terms = sum(len(v) for v in curate_routing.values())
        print(
            f"  Phase 1.2.6 curate routing chargé : "
            f"{len(curate_routing)} concepts, {n_terms} termes routés"
        )

    print("Building per-concept entities...")
    per_concept = build_entities_per_concept(
        phase14,
        concept_values,
        dropped_entities=dropped_entities,
        curate_routing=curate_routing,
    )

    print("Scoring per concept...")
    raw_per_concept: dict[str, dict[str, float]] = {}
    breakdown_per_concept: dict[str, dict[str, dict]] = {}
    for concept, data in per_concept.items():
        # Skip les concepts DÉRIVABLES : pas d'entité à scorer (formule
        # SQL appliquée Phase 3 depuis les concepts source). On garde une
        # entrée vide pour cohérence des collections downstream.
        if concept in derivables:
            raw_per_concept[concept] = {}
            breakdown_per_concept[concept] = {}
            continue
        has_values = bool(concept_values.get(concept))
        ent_scores: dict[str, float] = {}
        ent_breakdowns: dict[str, dict] = {}
        for tbl_name, tbl_data in data["tables"].items():
            score, brk = score_entity_for_concept(tbl_data, has_values, is_view=False)
            ent_scores[tbl_name] = score
            ent_breakdowns[tbl_name] = brk
        for vue_name, vue_data in data["views"].items():
            score, brk = score_entity_for_concept(vue_data, has_values, is_view=True)
            ent_scores[vue_name] = score
            ent_breakdowns[vue_name] = brk
        raw_per_concept[concept] = ent_scores
        breakdown_per_concept[concept] = ent_breakdowns

    norm_per_concept = normalize_per_concept(raw_per_concept)

    # Collect row_counts across all concepts (max observed per entity)
    row_counts: dict[str, str] = {}
    for c_data in per_concept.values():
        for ent_dict in (c_data["tables"], c_data["views"]):
            for n, d in ent_dict.items():
                rc = d.get("row_count")
                if rc and (n not in row_counts or len(rc) > len(row_counts[n])):
                    row_counts[n] = rc

    # Pass 1: scoring sans view-centrality pour identifier les top tables
    pass1 = compute_global_scores(
        norm_per_concept,
        fk_graph,
        breakdowns=breakdown_per_concept,
        row_counts=row_counts,
    )

    classification: dict[str, str] = {}
    all_entities = set()
    for c_data in per_concept.values():
        all_entities.update(c_data["tables"].keys())
        all_entities.update(c_data["views"].keys())
    for ent in all_entities:
        classification[ent] = classify_entity(ent, per_concept)

    # Top tables (classification == 'T') du pass 1, normalisés en lookup set
    top_tables_pass1 = sorted(
        ((e, d["proba"]) for e, d in pass1.items() if classification.get(e) == "T"),
        key=lambda kv: (-kv[1], kv[0]),
    )[:TOP_N_PROBABILITIES]
    top_table_set = {e.lower() for e, _ in top_tables_pass1}

    # Pass 2: extraire dépendances de vues + computer view-centrality
    print("Extracting view dependencies (CREATE VIEW DDL parsing)...")
    view_deps = extract_view_dependencies(DB)
    print(f"  {len(view_deps)} views with parsed DDL")

    view_centrality_bonuses: dict[str, float] = {}
    view_top_refs: dict[str, list[str]] = {}  # for rendering: which top tables a view references
    for view_name, refs in view_deps.items():
        # Match view_name to entity names in our scoring (with possible dbo_ prefix)
        candidates = [view_name, f"dbo_{view_name}"]
        # Lookup which refs are top tables
        ref_top: list[str] = []
        for ref in refs:
            if ref.lower() in top_table_set:
                ref_top.append(ref)
        if not ref_top:
            continue
        bonus = 1 + VIEW_CENTRALITY_RATE * len(ref_top)
        for cand in candidates:
            if cand in pass1:
                view_centrality_bonuses[cand] = bonus
                view_top_refs[cand] = sorted(set(ref_top))

    # Pass 2: re-compute global scores with view-centrality
    global_scores = compute_global_scores(
        norm_per_concept,
        fk_graph,
        breakdowns=breakdown_per_concept,
        row_counts=row_counts,
        view_centrality_bonuses=view_centrality_bonuses,
    )

    # =========================================================================
    # Render Principal
    # =========================================================================
    main_out: list[str] = []
    main_out.append("# " + "=" * 76)
    main_out.append("# RAPPORT PIPELINE V2 — Phase 1.5 priorisation + scoring d'inclusion")
    main_out.append("# " + "=" * 76)
    main_out.append("")
    main_out.extend(render_user_query(query))
    main_out.append("")

    # Concepts traités
    if derivables:
        # Format identique à test_pipeline.py pour qu'un seul parseur
        # marche sur les deux fichiers (search_results_test.txt ET v2.txt).
        main_out.append(f"STRUCTURE CONCEPT DÉRIVABLES ({len(derivables)} concepts) :")
        main_out.append(
            "  (concepts calculables par formule SQL depuis d'autres concepts — "
            "PAS de recherche de table dédiée pour ceux-là)"
        )
        for c, srcs in sorted(derivables.items()):
            main_out.append(f"  {c} <- {', '.join(srcs)}")
        main_out.append("")
    main_out.append(f"CONCEPTS TRAITÉS ({len(concept_values)}) :")
    for c, vs in sorted(concept_values.items()):
        if vs:
            main_out.append(f"  - {c} → valeurs explicites : {', '.join(vs)}")
        else:
            main_out.append(f"  - {c} → (sans valeurs explicites)")
    main_out.append("")

    # Top entities list — used for FK subgraph and validation
    top_for_subgraph = [
        ent
        for ent, _ in sorted(
            global_scores.items(),
            key=lambda kv: (-kv[1]["proba"], kv[0]),  # déterministe sur ties
        )[:TOP_N_PROBABILITIES]
    ]

    # Probability table FIRST (most useful for LLM)
    main_out.extend(
        render_probability_table(
            global_scores,
            classification,
            fk_graph,
            concept_values,
            norm_per_concept,
            view_top_refs=view_top_refs,
            top_n=TOP_N_PROBABILITIES,
        )
    )

    # FK subgraph
    main_out.extend(render_fk_subgraph(top_for_subgraph, fk_graph))

    # Shortlist global = top N entités par probabilité globale
    shortlist_global = set(top_for_subgraph)

    # Shortlist effective par concept :
    #   shortlist_global  ∪  top K locaux  ∪  voisins FK (1 hop) des deux.
    # Le FK closure récupère les sources canoniques accessibles par
    # structure même quand leur signal textuel est faible : une table peut
    # n'avoir aucun champ qui matche le mot du concept tout en étant la
    # bonne cible (référencée via FK depuis une table dont les noms de
    # colonnes encodent la sémantique cible).
    def fk_neighbors(name: str) -> set[str]:
        edges = fk_graph.get(name.upper(), [])
        return {e["target"] for e in edges}

    def enrich_shortlist_for(concept_data: dict, has_values: bool) -> set[str]:
        prio_t = PRIO_TBL_WITH_VALUES if has_values else PRIO_TBL_NO_VALUES
        prio_v = PRIO_VUE_WITH_VALUES if has_values else PRIO_VUE_NO_VALUES
        local_tops: list[tuple[str, float]] = []
        # Restrict candidates to entities that have at least 1 match on this concept
        candidates = set(concept_data.get("tables", {}).keys()) | set(
            concept_data.get("views", {}).keys()
        )
        for n in candidates:
            td = concept_data.get("tables", {}).get(n)
            vd = concept_data.get("views", {}).get(n)
            if td is not None:
                sig_t = _weighted_signal(td, prio_t)
                if sig_t > 0:
                    local_tops.append((n, sig_t))
            if vd is not None:
                sig_v = _weighted_signal(vd, prio_v)
                if sig_v > 0:
                    local_tops.append((n, sig_v))
        local_tops.sort(key=lambda kv: (-kv[1], kv[0]))
        local_set = {n for n, _ in local_tops[:PER_CONCEPT_LOCAL_TOP_K]}

        keep = shortlist_global | local_set

        # FK closure (1 hop) : ajouter les voisins FK des entités déjà
        # gardées qui ont AU MOINS un match sur ce concept (sinon on
        # introduirait du bruit non-pertinent).
        if FK_CLOSURE_PER_CONCEPT:
            seed = set(keep)
            for ent in seed:
                for nbr in fk_neighbors(ent):
                    if nbr in candidates:
                        keep.add(nbr)
        return keep

    per_concept_shortlist: dict[str, set[str]] = {}
    for concept, c_data in per_concept.items():
        per_concept_shortlist[concept] = enrich_shortlist_for(
            c_data, bool(concept_values.get(concept))
        )

    # Eff local score normalisé par concept (max=1.0) — clé primaire du tri
    # local quand pondérée avec la proba globale.
    eff_local_norm_per_concept: dict[str, dict[str, float]] = {}
    for concept, c_data in per_concept.items():
        has_values = bool(concept_values.get(concept))
        prio_t = PRIO_TBL_WITH_VALUES if has_values else PRIO_TBL_NO_VALUES
        prio_v = PRIO_VUE_WITH_VALUES if has_values else PRIO_VUE_NO_VALUES
        scores: dict[str, float] = {}
        for n, td in c_data.get("tables", {}).items():
            scores[n] = _effective_local_score(n, td, prio_t)
        for n, vd in c_data.get("views", {}).items():
            # If both T and V exist, take the max
            sc_v = _effective_local_score(n, vd, prio_v)
            scores[n] = max(scores.get(n, 0.0), sc_v)
        m = max(scores.values()) if scores else 0.0
        if m > 0:
            eff_local_norm_per_concept[concept] = {k: v / m for k, v in scores.items()}
        else:
            eff_local_norm_per_concept[concept] = {k: 0.0 for k in scores}

    # Détail par concept (format compressé)
    main_out.append("=" * 80)
    main_out.append("DÉTAIL PAR CONCEPT — format compressé sans perte")
    main_out.append("=" * 80)
    main_out.append(
        f"Pour chaque concept : top {TOP_N_PROBABILITIES} globaux ∪ "
        f"top {PER_CONCEPT_LOCAL_TOP_K} locaux du concept. "
        "Le reste des matches (zéro perte) reste en annexe."
    )
    main_out.append("Légende: = exact · ⊂ contains · ~ fuzzy · +Annex(N) = N matches")
    main_out.append("        Val(autre) déplacés en annexe pour ce concept (sans valeurs).")
    main_out.append("")
    for concept in sorted(concept_values.keys()):
        if concept not in per_concept:
            continue
        has_values = bool(concept_values.get(concept))
        main_out.extend(
            render_compressed_variant_b(
                concept,
                per_concept[concept],
                has_values,
                shortlist=per_concept_shortlist[concept],
                global_scores=global_scores,
                view_top_refs=view_top_refs,
                eff_local_norm=eff_local_norm_per_concept.get(concept),
            )
        )

    main_text = "\n".join(main_out)
    DST_MAIN.write_text(main_text, encoding="utf-8")

    # =========================================================================
    # Render Annex (zéro perte — contient tout ce qui n'est pas dans Principal)
    # =========================================================================
    annex_out: list[str] = []
    annex_out.append("# " + "=" * 76)
    annex_out.append("# ANNEXE — préservée sans perte (hors prompt principal)")
    annex_out.append("# " + "=" * 76)
    annex_out.append("")
    annex_out.append("Cette annexe contient :")
    annex_out.append(" 1. Val(autre) — matches sur valeurs anonymisées par termes étendus,")
    annex_out.append("    hors valeurs explicites du concept (réduit le bruit dans Principal).")
    annex_out.append(" 2. Overflow — détail par concept des entités HORS shortlist du Principal")
    annex_out.append("    (les top-N entités sont déjà détaillées dans le Principal).")
    annex_out.append("")
    annex_out.append("Tous ces matches restent accessibles ; aucune donnée n'est perdue.")
    annex_out.append("")

    annex_out.append("=" * 80)
    annex_out.append("PARTIE 1 — Val(autre) par concept")
    annex_out.append("=" * 80)
    annex_out.append("")
    for concept in sorted(concept_values.keys()):
        if concept not in per_concept:
            continue
        annex_out.extend(render_annex_section(concept, per_concept[concept]))

    annex_out.append("=" * 80)
    annex_out.append("PARTIE 2 — Overflow (entités hors shortlist du Principal)")
    annex_out.append("=" * 80)
    annex_out.append("")
    for concept in sorted(concept_values.keys()):
        if concept not in per_concept:
            continue
        has_values = bool(concept_values.get(concept))
        # Annex utilise la même shortlist enrichie (par concept) que le
        # Principal pour rester complémentaire (pas de double comptage).
        annex_out.extend(
            render_overflow_section(
                concept,
                per_concept[concept],
                has_values,
                shortlist=per_concept_shortlist[concept],
                global_scores=global_scores,
                view_top_refs=view_top_refs,
                eff_local_norm=eff_local_norm_per_concept.get(concept),
            )
        )

    annex_text = "\n".join(annex_out)
    DST_ANNEX.write_text(annex_text, encoding="utf-8")

    # =========================================================================
    # Stats + validation
    # =========================================================================
    print()
    print("=" * 70)
    print("OUTPUTS")
    print("=" * 70)
    print(f"Principal: {DST_MAIN}")
    print(f"  Lines:  {len(main_out):>10,}")
    print(f"  Bytes:  {len(main_text.encode('utf-8')):>10,}")
    print(f"Annex:     {DST_ANNEX}")
    print(f"  Lines:  {len(annex_out):>10,}")
    print(f"  Bytes:  {len(annex_text.encode('utf-8')):>10,}")
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        n_main = len(enc.encode(main_text))
        n_annex = len(enc.encode(annex_text))
        print(
            f"  Tokens (cl100k_base): main={n_main:,} | annex={n_annex:,} | total={n_main+n_annex:,}"
        )
    except Exception as e:
        print(f"  Tokens: tiktoken unavailable ({e})")

    print()
    print("=" * 70)
    print("VALIDATION — rang des entités attendues + couverture via ↪{} des vues")
    print("=" * 70)
    ordered = [
        e
        for e, _ in sorted(
            global_scores.items(),
            key=lambda kv: (-kv[1]["proba"], kv[0]),
        )
    ]
    # Set of all entity names referenced by views appearing in top N
    referenced_by_top_views: set[str] = set()
    for ent in ordered[:TOP_N_PROBABILITIES]:
        for ref in view_top_refs.get(ent, []):
            referenced_by_top_views.add(ref)

    found_directly = 0
    found_via_view_ref = 0
    for expected in EXPECTED_TOP_ENTITIES:
        variants = [expected] + EXPECTED_ALIASES.get(expected, [])
        best_rank: int | None = None
        best_variant: str | None = None
        for v in variants:
            try:
                r = ordered.index(v) + 1
                if best_rank is None or r < best_rank:
                    best_rank = r
                    best_variant = v
            except ValueError:
                continue

        in_top = best_rank is not None and best_rank <= TOP_N_PROBABILITIES
        # Check if any variant is referenced by a top view
        in_via_ref = any(v in referenced_by_top_views for v in variants)

        if in_top:
            mark = "✅"
            found_directly += 1
        elif in_via_ref:
            mark = "↪ "  # accessible indirectement via ref de vue top
            found_via_view_ref += 1
        elif best_rank is None:
            mark = "❌"
        else:
            mark = "⚠️"

        if best_rank is None:
            print(f"  {mark} {expected:<25} NOT FOUND (no variant matches)")
            continue
        proba = global_scores[best_variant]["proba"]
        n_c = global_scores[best_variant]["n_concepts"]
        alias_note = f" (via '{best_variant}')" if best_variant != expected else ""
        ref_note = " — accessible via ↪{} de vues top" if (in_via_ref and not in_top) else ""
        print(
            f"  {mark} {expected:<25} rang #{best_rank:>3}  proba={proba:.2f}  "
            f"({n_c} concepts){alias_note}{ref_note}"
        )
    total_covered = found_directly + found_via_view_ref
    print()
    print(
        f"  → {found_directly}/{len(EXPECTED_TOP_ENTITIES)} dans le top {TOP_N_PROBABILITIES} directement, "
        f"+{found_via_view_ref} accessible via ↪{{}} des vues top "
        f"= {total_covered}/{len(EXPECTED_TOP_ENTITIES)} couvertes"
    )


# =====================================================================
# CLI ENTRY — fin de fichier (après la section INLINED Phase 1.5 qui
# définit les globals SRC/DB/DST_MAIN/DST_ANNEX/_DROPPED_ENTITIES_FILE/
# _CURATE_DIR utilisés par phase_1_5_scoring_fk).
# =====================================================================


if __name__ == "__main__":
    sys.exit(main())
