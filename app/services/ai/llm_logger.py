"""
Logger dédié pour capturer TOUS les échanges avec les LLM.

Tout est logué dans un seul fichier : llm_log.md
Chaque entrée est taguée [CONVERSATION] ou [ENRICHMENT] pour distinguer la source.

Format Markdown lisible par un humain, avec blocs JSON indentés.

Rotation : quand le fichier dépasse ``LLM_LOG_MAX_SIZE_BYTES`` (défaut 50 MB),
il est renommé en ``llm_log.YYYY-MM-DDTHHMMSS.md`` et un nouveau fichier vide
est ouvert. Les rotations âgées de plus de ``LLM_LOG_RETENTION_DAYS`` (défaut
14 jours) sont supprimées par ``cleanup_old_rotated_logs()`` (à appeler par un
scheduler — APScheduler par exemple).
"""

import datetime
import json
import logging
import os
import pathlib
import re
import threading
from typing import Any

from app.config import config
from app.core import clock

logger = logging.getLogger(__name__)

_PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
# Sous data/logs (volume Docker persistant), aux côtés de komptia.log/errors.log.
# Avant : _PROJECT_ROOT/'llm_log.md' = repo root, HORS du volume → le journal
# (et ses rotations) étaient perdus à chaque rebuild `make up`. La rotation /
# rétention (LLM_LOG_*) ne change pas, le fichier déménage juste dans le volume.
LOG_PATH = config.logs_dir / "llm_log.md"

# Compteur global d'échanges
_exchange_counter = 0

# Lock pour rotation atomique (write + rename ne doivent pas s'entrelacer).
_rotation_lock = threading.Lock()


_MAX_LOG_SIZE_HARD_CAP_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB — protège DoS env


def _max_log_size_bytes() -> int:
    """Taille max avant rotation. Configurable via env (défaut 50 MB).

    Lu à chaque appel pour permettre l'ajustement runtime sans redémarrage.

    Accepte ``LLM_LOG_MAX_BYTES`` (alias canonique, aligné avec
    ``LLMLogConfig``) ou ``LLM_LOG_MAX_SIZE_BYTES`` (alias historique
    conservé pour rétro-compat). Clampé à 10 GiB pour éviter qu'un
    ``.env`` mal copié neutralise silencieusement la rotation.
    """
    raw = ""
    try:
        raw = os.environ.get("LLM_LOG_MAX_BYTES", "") or os.environ.get(
            "LLM_LOG_MAX_SIZE_BYTES", ""
        )
        if raw:
            value = int(raw)
            if value > 0:
                if value > _MAX_LOG_SIZE_HARD_CAP_BYTES:
                    logger.warning(
                        "LLM_LOG_MAX_BYTES=%d > hard-cap %d, clampé",
                        value,
                        _MAX_LOG_SIZE_HARD_CAP_BYTES,
                    )
                    return _MAX_LOG_SIZE_HARD_CAP_BYTES
                return value
    except (TypeError, ValueError):
        # env mal formé — on log et on tombe sur le défaut
        logger.warning(
            "LLM_LOG_MAX_BYTES/LLM_LOG_MAX_SIZE_BYTES env mal formé (%r), " "fallback 50 MB",
            raw,
        )
    return 50 * 1024 * 1024


def _retention_days() -> int:
    """Nombre de jours de rétention des rotations (défaut 14).

    Accepte ``LLM_LOG_RETAIN_DAYS`` (alias canonique, aligné avec
    ``LLMLogConfig`` dans ``app/config.py``) ou ``LLM_LOG_RETENTION_DAYS``
    (alias historique conservé pour rétro-compat).
    """
    raw = ""
    try:
        raw = os.environ.get("LLM_LOG_RETAIN_DAYS", "") or os.environ.get(
            "LLM_LOG_RETENTION_DAYS", ""
        )
        if raw:
            value = int(raw)
            if value > 0:
                return value
    except (TypeError, ValueError):
        logger.warning(
            "LLM_LOG_RETAIN_DAYS/LLM_LOG_RETENTION_DAYS env mal formé (%r), " "fallback 14",
            raw,
        )
    return 14


_MAX_ARCHIVES_HARD_CAP = 10_000  # protège contre env absurde (DoS slice)


def _max_archives() -> int:
    """Nombre maximum d'archives de rotation à conserver (défaut 5).

    Cap dur indépendant du TTL : même si toutes les archives sont récentes
    (< ``LLM_LOG_RETAIN_DAYS``), les plus anciennes au-delà de ce cap sont
    supprimées. Protège contre une succession rapide de rotations
    (taille atteinte plusieurs fois sur la même journée) avant que le
    job cleanup quotidien (APScheduler 03:45) ne tourne.

    Configurable via env ``LLM_LOG_MAX_ARCHIVES``. Valeur 0 = aucune
    archive conservée (purge immédiate après rotation — usage valide
    pour les déploiements qui rotatent vers un système externe). Valeur
    négative ou non-int = fallback défaut + warning. Clampé à 10 000
    (au-delà = défense-en-profondeur contre un ``.env`` mal copié).
    """
    raw = ""
    try:
        raw = os.environ.get("LLM_LOG_MAX_ARCHIVES", "")
        if raw:
            value = int(raw)
            if value >= 0:  # 0 acceptable, négatif fallback
                if value > _MAX_ARCHIVES_HARD_CAP:
                    logger.warning(
                        "LLM_LOG_MAX_ARCHIVES=%d > hard-cap %d, clampé",
                        value,
                        _MAX_ARCHIVES_HARD_CAP,
                    )
                    return _MAX_ARCHIVES_HARD_CAP
                return value
    except (TypeError, ValueError):
        logger.warning("LLM_LOG_MAX_ARCHIVES env mal formé (%r), fallback 5", raw)
    return 5


_ROTATION_NAME_PATTERN_GLOB = "{stem}.????-??-??T??????{suffix}"


def _rotation_name_regex(stem: str, suffix: str) -> re.Pattern[str]:
    """Regex strict pour le nom d'une archive de rotation.

    Le glob ``????`` matche tout caractère (y compris lettres), donc
    ``llm_log.AAAA-BB-CCTDDEEFF.md`` ou ``llm_log.backup-2026-05.md``
    matcheraient — ce qui supprimerait silencieusement des backups
    manuels déposés dans le dossier (cas réaliste : ops avant un
    upgrade). On filtre via une regex stricte ``\\d{4}-\\d{2}-\\d{2}T\\d{6}``
    après le glob pour ne garder QUE les rotations légitimes.
    """
    return re.compile(
        r"^" + re.escape(stem) + r"\.\d{4}-\d{2}-\d{2}T\d{6}" + re.escape(suffix) + r"$"
    )


def _list_archives(log_path: pathlib.Path) -> list[pathlib.Path]:
    """Liste les fichiers d'archive de rotation de ``log_path``.

    Pattern strict : ``llm_log.YYYY-MM-DDTHHMMSS.md`` (le format produit
    par ``_rotate_if_needed``). Trois couches de sécurité :

    1. Glob ``????-??-??T??????`` (pré-filtre rapide)
    2. Regex stricte ``\\d{4}-\\d{2}-\\d{2}T\\d{6}`` (anti-faux-positif
       sur des fichiers tiers comme ``llm_log.backup-X.md``)
    3. Check ``resolve()`` contre le path actif (anti-symlink piégeux)
    """
    parent = log_path.parent
    stem = log_path.stem
    suffix = log_path.suffix
    pattern = _ROTATION_NAME_PATTERN_GLOB.format(stem=stem, suffix=suffix)
    strict_re = _rotation_name_regex(stem, suffix)
    try:
        log_path_resolved = log_path.resolve() if log_path.exists() else None
    except OSError:
        log_path_resolved = None

    archives: list[pathlib.Path] = []
    try:
        for candidate in parent.glob(pattern):
            if not strict_re.match(candidate.name):
                # Glob a matché un faux positif (ex: backup manuel
                # ``llm_log.backup-2026.md`` ou ``llm_log.AAAA-...md``)
                continue
            try:
                if log_path_resolved is not None and candidate.resolve() == log_path_resolved:
                    continue  # belt-and-suspenders — jamais l'actif
            except OSError:
                logger.warning("resolve() failed pour %s, skip", candidate.name)
                continue
            archives.append(candidate)
    except OSError as exc:
        logger.warning("Glob des rotations a échoué : %s", exc)
    return archives


def _enforce_max_archives_cap(log_path: pathlib.Path, max_archives: int | None = None) -> int:
    """Garde au plus ``max_archives`` archives, supprime les plus anciennes.

    Idempotent : appel répété avec le même cap = no-op après la première
    purge. Safe sous concurrence Tornado/APScheduler : chaque ``unlink``
    est isolé et catch ``FileNotFoundError`` (autre thread/process l'a déjà
    supprimé). La sémantique "garde les N plus récents" est best-effort
    sous concurrence — si la rotation Tornado et le cleanup APScheduler
    tournent en parallèle, le résultat final respecte le cap (≤ N) mais
    peut momentanément supprimer une archive très récente. Acceptable car
    le but premier est de borner la croissance disque, pas la précision
    fine de quelle archive est gardée.

    Tri : mtime DESC (plus récent en tête) avec le nom comme tiebreaker
    (le format timestamp ``YYYY-MM-DDTHHMMSS`` est lexicographiquement
    chronologique → résiste aux FS exotiques qui retournent mtime=0).

    Args:
        log_path: chemin du fichier actif (``llm_log.md``). Sert à
            dériver le pattern et le répertoire parent. N'est jamais
            supprimé.
        max_archives: nombre max d'archives. ``None`` → lit
            ``LLM_LOG_MAX_ARCHIVES`` via :func:`_max_archives`.

    Returns:
        Nombre d'archives supprimées.
    """
    if max_archives is None:
        max_archives = _max_archives()

    archives = _list_archives(log_path)
    if len(archives) <= max_archives:
        return 0

    # Annote chaque archive avec (mtime, name) pour le tri stable.
    annotated: list[tuple[float, str, pathlib.Path]] = []
    for archive in archives:
        try:
            mtime = archive.stat().st_mtime
        except OSError as exc:
            logger.warning("stat() failed pour %s : %s", archive.name, exc)
            mtime = 0.0
        annotated.append((mtime, archive.name, archive))

    # Tri : mtime DESC puis nom DESC (tiebreaker). Les plus récents
    # restent en tête, les plus anciens en queue → à supprimer.
    annotated.sort(key=lambda x: (x[0], x[1]), reverse=True)

    deleted = 0
    total = len(annotated)
    for _, _, archive in annotated[max_archives:]:
        try:
            archive.unlink()
            deleted += 1
            logger.info(
                "Count cap: removed %s (cap=%d, total was %d)",
                archive.name,
                max_archives,
                total,
            )
        except FileNotFoundError:
            # Autre processus a supprimé entre-temps — idempotent
            pass
        except OSError as exc:
            logger.warning("Impossible de supprimer %s : %s", archive.name, exc)
    return deleted


def _rotate_if_needed(log_path: pathlib.Path) -> None:
    """Vérifie la taille de ``log_path`` et le rotate s'il dépasse le cap.

    Rotation : ``llm_log.md`` → ``llm_log.YYYY-MM-DDTHHMMSS.md``. Le nouveau
    fichier est créé vide à l'écriture suivante (pas par cette fonction).

    Erreur : si ``stat`` ou ``rename`` échoue, on log un warning et on
    n'interrompt PAS l'écriture (le log doit toujours fonctionner — un
    fichier qui grossit est moins grave qu'un log silencieux). Anti-fallback
    silencieux : l'erreur est loggée explicitement.
    """
    try:
        if not log_path.exists():
            return
        size = log_path.stat().st_size
        if size <= _max_log_size_bytes():
            return
        timestamp = clock.now().strftime("%Y-%m-%dT%H%M%S")
        archive = log_path.with_name(f"{log_path.stem}.{timestamp}{log_path.suffix}")
        log_path.rename(archive)
        logger.info(
            "Rotated %s → %s (size=%.1f MB)",
            log_path.name,
            archive.name,
            size / (1024 * 1024),
        )
    except OSError as exc:
        # Permissions, disk full, etc. — on log mais on ne bloque pas.
        logger.warning("Rotation %s a échoué : %s", log_path.name, exc)
        return

    # Après une rotation réussie, applique le cap par nombre d'archives.
    # Évite la croissance non bornée même si le cleanup TTL quotidien
    # (APScheduler 03:45) n'a pas encore tourné — burst de rotations
    # successives sur la même journée. ``try/except Exception`` :
    # le log doit toujours pouvoir s'écrire, même si le cap crashe
    # (cohérent avec l'invariant "log silencieux pire que log qui grossit"
    # plus haut). On capture aussi les non-OSError (MemoryError, etc.).
    try:
        _enforce_max_archives_cap(log_path)
    except Exception:
        logger.exception("Cap par nombre d'archives a échoué (ignoré)")


def cleanup_old_rotated_logs(
    log_path: pathlib.Path | None = None,
    retention_days: int | None = None,
    max_archives: int | None = None,
) -> int:
    """Supprime les fichiers de rotation au-delà du TTL ET du cap par nombre.

    Deux mécanismes composables (defense-in-depth) :
    - **TTL** : archives plus âgées que ``retention_days`` (défaut 14)
    - **Count cap** : au-delà de ``max_archives`` (défaut 5), les plus
      anciennes sont supprimées indépendamment de l'âge

    Cible : ``llm_log.YYYY-MM-DDTHHMMSS.md`` (le fichier actif
    ``llm_log.md`` est protégé par un pattern strict + check
    ``resolve()``).

    À appeler depuis un scheduler (ex: APScheduler quotidien). Idempotent.

    Args:
        log_path: chemin du fichier actif (défaut : ``LOG_PATH`` au moment
            de l'appel — pas figé à l'import, donc compatible avec un
            ``patch.object`` sur le module).
        retention_days: âge max des archives en jours (défaut env/14).
        max_archives: nombre max d'archives (défaut env/5).

    Returns:
        Nombre total de fichiers supprimés (TTL + count cap).
    """
    if log_path is None:
        log_path = LOG_PATH
    if retention_days is None:
        retention_days = _retention_days()

    cutoff = clock.now() - datetime.timedelta(days=retention_days)
    deleted = 0

    # Phase 1 : TTL — supprime les archives plus âgées que ``retention_days``.
    # Utilise ``_list_archives`` (pattern strict + protection actif partagés).
    for archive in _list_archives(log_path):
        try:
            mtime = datetime.datetime.fromtimestamp(
                archive.stat().st_mtime, tz=datetime.timezone.utc
            )
            if mtime < cutoff:
                archive.unlink()
                deleted += 1
                logger.info(
                    "Cleanup TTL: removed %s (age=%d days)",
                    archive.name,
                    (clock.now() - mtime).days,
                )
        except FileNotFoundError:
            pass  # autre processus l'a supprimé entre temps — idempotent
        except OSError as exc:
            logger.warning("Impossible de supprimer %s : %s", archive.name, exc)

    # Phase 2 : count cap — defense-in-depth si TTL n'a pas suffi
    # (ex : burst de rotations sur la même semaine, toutes récentes).
    deleted += _enforce_max_archives_cap(log_path, max_archives=max_archives)

    return deleted


# Modèles considérés comme "utilitaires/enrichissement" pour le filtrage de logs.
# Dynamique : le modèle configuré comme utility est résolu au runtime via get_utility_model().
# Ce set est un hint pour le logger — s'il ne contient pas le modèle utilisé,
# le log passe quand même (pas de blocage).
_ENRICHMENT_MODELS: frozenset[str] = frozenset()


def _truncate(obj: Any, max_str_len: int = 500, max_list_items: int = 5) -> Any:
    """Passthrough function. Returns obj unchanged (no truncation)."""
    return obj


def _is_enrichment_exchange(data: dict) -> bool:
    """Détecte si un échange est un appel d'enrichissement (vs conversation).

    Heuristiques :
    - Modèle Haiku (utilisé exclusivement pour l'enrichissement)
    - System prompt court contenant des marqueurs d'enrichissement et "JSON"
    - Pas de tools (l'enrichissement n'utilise pas de tools)
    """
    model = data.get("model", "")
    if model in _ENRICHMENT_MODELS:
        # Vérifier : pas de tools = enrichissement
        if not data.get("tools"):
            return True
    # Vérifier le system prompt pour les non-stream responses
    system = data.get("system", "")
    if isinstance(system, str) and len(system) < 500:
        if "JSON" in system and ("descriptions métier" in system or "rôle métier" in system):
            return True
    return False


def log_llm_exchange(direction: str, data: dict) -> None:
    """Append un échange lisible dans le fichier log approprié.

    Route automatiquement vers le log enrichissement ou conversation
    en fonction du contenu de l'échange.

    Args:
        direction: 'request' ou 'response'.
        data: Le payload complet (sans clé API — elle est dans les headers HTTP).
    """
    global _exchange_counter

    is_enrichment = direction == "request" and _is_enrichment_exchange(data)
    if direction == "response" and not data.get("tools"):
        model = data.get("model", "")
        if model in _ENRICHMENT_MODELS:
            is_enrichment = True

    _exchange_counter += 1
    counter = _exchange_counter
    tag = "ENRICHMENT" if is_enrichment else "CONVERSATION"

    now = clock.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    arrow = "➡️  REQUEST" if direction == "request" else "⬅️  RESPONSE"

    lines = []

    if direction == "request":
        lines.append(f"---\n\n## #{counter} [{tag}] — {arrow} — {now}\n")
        lines.append(f"**Modèle** : `{data.get('model', '?')}`\n")
        lines.append(
            f"**Max tokens** : {data.get('max_tokens', '?')} | "
            f"**Température** : {data.get('temperature', '?')}"
        )
        if data.get("stream"):
            lines.append(" | **Stream** : oui")
        lines.append("\n")

        # System prompt — supporte format Anthropic (champ ``system``) ET
        # OpenAI (1er message avec role=system). LOT 7 : lisible cross-provider.
        system = data.get("system", "")
        if not system:
            for msg in data.get("messages", []) or []:
                if isinstance(msg, dict) and msg.get("role") == "system":
                    system = msg.get("content", "")
                    if isinstance(system, list):
                        # OpenAI peut envoyer system comme list of {type, text}
                        system = "\n".join(
                            b.get("text", "")
                            for b in system
                            if isinstance(b, dict) and b.get("type") == "text"
                        )
                    break
        if system:
            lines.append(f"\n### System prompt ({len(system)} chars)\n")
            lines.append(f"```\n{system}\n```\n")

        # Tools — supporte format Anthropic (``name`` direct) et OpenAI
        # (``function.name`` imbriqué). Sans ce dual-read, sur OpenAI le log
        # affichait des "?" partout.
        tools = data.get("tools", [])
        if tools:
            tool_names = []
            for t in tools:
                if not isinstance(t, dict):
                    continue
                # OpenAI : tools[*].function.name
                fn = t.get("function")
                if isinstance(fn, dict) and fn.get("name"):
                    tool_names.append(fn["name"])
                # Anthropic : tools[*].name
                elif t.get("name"):
                    tool_names.append(t["name"])
                else:
                    tool_names.append("?")
            lines.append(f"\n### Outils ({len(tools)})\n")
            lines.append(f"`{'`, `'.join(tool_names)}`\n")

        # Messages — contenu COMPLET de chaque bloc
        messages = data.get("messages", [])
        if messages:
            lines.append(f"\n### Messages ({len(messages)})\n")
            for i, msg in enumerate(messages):
                role = msg.get("role", "?")
                content = msg.get("content", "")
                if isinstance(content, str):
                    lines.append(f"- **{role}** : {content}\n")
                elif isinstance(content, list):
                    lines.append(f"- **{role}** :\n")
                    for block in content:
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type", "?")
                        if btype == "text":
                            text = block.get("text", "")
                            lines.append(f"  > {text}\n")
                        elif btype == "tool_use":
                            tool_name = block.get("name", "?")
                            tool_input = block.get("input", {})
                            formatted = json.dumps(
                                tool_input, indent=2, default=str, ensure_ascii=False
                            )
                            lines.append(f"  **Tool call** : `{tool_name}`\n")
                            lines.append(f"  ```json\n  {formatted}\n  ```\n")
                        elif btype == "tool_result":
                            tool_id = block.get("tool_use_id", "?")
                            result_content = block.get("content", "")
                            is_error = block.get("is_error", False)
                            err_tag = " ❌" if is_error else ""
                            if isinstance(result_content, str):
                                lines.append(
                                    f"  **Tool result**{err_tag} (`{tool_id}`) :\n"
                                    f"  > {result_content}\n"
                                )
                            elif isinstance(result_content, list):
                                # Multi-block tool result
                                for rb in result_content:
                                    if isinstance(rb, dict) and rb.get("type") == "text":
                                        lines.append(
                                            f"  **Tool result**{err_tag} (`{tool_id}`) :\n"
                                            f"  > {rb.get('text', '')}\n"
                                        )
                                    else:
                                        lines.append(
                                            f"  **Tool result**{err_tag} (`{tool_id}`) : "
                                            f"{json.dumps(rb, default=str, ensure_ascii=False)}\n"
                                        )
                        elif btype == "thinking":
                            # Extended thinking (Anthropic). Log FULL (pas
                            # tronqué) pour audit post-run — permet de voir
                            # ce que le LLM a "pensé" pendant les gros turns
                            # silencieux. Coûte de l'espace disque mais est
                            # indispensable quand on diagnostique un run
                            # avec du thinking improductif (ex: 51k tokens
                            # de thinking caché dans stress_noisy).
                            thinking_text = block.get("thinking", "")
                            signature = block.get("signature", "")
                            lines.append(f"  **thinking** :\n")
                            lines.append(f"  > {thinking_text}\n")
                            if signature:
                                # Signature courte — 80 chars suffit pour
                                # corréler les blocs sans gonfler le log.
                                lines.append(f"  _(signature: {signature[:80]}…)_\n")
                        else:
                            # Autres types de blocs (image, etc.)
                            lines.append(
                                f"  **{btype}** : "
                                f"{json.dumps(block, default=str, ensure_ascii=False)[:500]}\n"
                            )

    else:  # response
        lines.append(f"\n### #{counter} [{tag}] — {arrow} — {now}\n")

        # Stream events
        if "stream_events" in data:
            events = data["stream_events"]
            lines.append(f"**Stream** : {len(events)} events\n")
            # Extraire le texte, le thinking et les tool_use du stream
            text_parts = []
            thinking_parts = []
            tool_uses = []
            for evt in events:
                evt_type = evt.get("type", "")
                if evt_type == "content_block_delta":
                    delta = evt.get("delta", {})
                    if delta.get("type") == "text_delta":
                        text_parts.append(delta.get("text", ""))
                    elif delta.get("type") == "thinking_delta":
                        # Extended thinking streamé : on concatène pour log
                        # FULL (audit gros turns silencieux).
                        thinking_parts.append(delta.get("thinking", ""))
                    elif delta.get("type") == "input_json_delta":
                        pass  # tool input streaming
                elif evt_type == "content_block_start":
                    cb = evt.get("content_block", {})
                    if cb.get("type") == "tool_use":
                        tool_uses.append(cb.get("name", "?"))
                elif evt_type == "message_delta":
                    stop = evt.get("delta", {}).get("stop_reason")
                    usage = evt.get("usage", {})
                    if stop:
                        lines.append(f"**Stop reason** : `{stop}`\n")
                    if usage:
                        lines.append(f"**Tokens** : {usage.get('output_tokens', '?')} output\n")

            full_thinking = "".join(thinking_parts)
            if full_thinking:
                lines.append(f"\n**thinking** :\n> {full_thinking}\n")
            full_text = "".join(text_parts)
            if full_text:
                lines.append(f"\n**Réponse texte** :\n> {full_text}\n")
            if tool_uses:
                lines.append(f"\n**Tools appelés** : `{'`, `'.join(tool_uses)}`\n")
        else:
            # Non-stream response
            stop_reason = data.get("stop_reason", "?")
            usage = data.get("usage", {})
            lines.append(f"**Stop reason** : `{stop_reason}`\n")
            if usage:
                lines.append(
                    f"**Tokens** : {usage.get('input_tokens', '?')} in / "
                    f"{usage.get('output_tokens', '?')} out\n"
                )

            # Content blocks
            content_blocks = data.get("content", [])
            for block in content_blocks:
                btype = block.get("type", "?")
                if btype == "text":
                    text = block.get("text", "")
                    lines.append(f"\n**Texte** :\n> {text}\n")
                elif btype == "thinking":
                    # Extended thinking — log FULL pour audit des gros turns
                    # silencieux (voir note dans la branche des messages
                    # request). Auparavant non-loggé dans la response non-
                    # stream → 51k tokens de thinking invisible à l'audit.
                    thinking_text = block.get("thinking", "")
                    lines.append(f"\n**thinking** :\n> {thinking_text}\n")
                elif btype == "tool_use":
                    tool_name = block.get("name", "?")
                    tool_input = block.get("input", {})
                    truncated_input = _truncate(tool_input)
                    formatted = json.dumps(
                        truncated_input, indent=2, default=str, ensure_ascii=False
                    )
                    lines.append(f"\n**Tool** : `{tool_name}`\n")
                    lines.append(f"```json\n{formatted}\n```\n")

    # FIX M1 (review adversariale) : le lock couvre UNIQUEMENT le
    # check-size + rename. Le ``write`` append POSIX est atomique pour
    # des blocs courts (PIPE_BUF) — hors lock, on accepte qu'un autre
    # thread rotate entre notre _rotate_if_needed() et notre open(). Dans
    # ce cas, notre write tombe sur le NOUVEAU fichier (vide) ou sur
    # l'ancien (rename pas encore commit côté kernel). Pas de perte —
    # éventuellement une entrée split sur 2 fichiers, acceptable.
    # Garder le write sous le lock bloquerait l'event-loop Tornado sur
    # I/O disque saturé.
    with _rotation_lock:
        _rotate_if_needed(LOG_PATH)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
