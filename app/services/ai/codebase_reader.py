"""Lecture sécurisée du code source de Komptia pour la casquette
"agent Komptia" d'Iris.

Cette casquette permet à Iris de répondre aux questions des utilisateurs
sur l'application elle-même (architecture, fonctionnement, fichiers, etc.)
en lisant son propre code source. Elle ne donne JAMAIS accès aux données
runtime : classeurs (.afz.json), BDD locale (komptia.db), logs PII
(llm_log.md), secrets (.env, fernet), résultats pipeline (outputs/), règles
RLS persistées (configurées via /admin/data-access), ni la config/doctrine
interne Claude Code (CLAUDE.md, .claude/).

Doctrine sénior :

1. **Open-by-default + denylist multi-couches (modèle réel depuis 2026-05-21).**
   Tout le repo est lisible par défaut, SAUF ce que la denylist bloque. La
   SEULE source de vérité du gate est ``is_path_safe`` ; il refuse : les
   répertoires top-level sensibles (``_DENY_TOP_LEVEL_DIRS`` : outputs/,
   backups/, _trash/, venv/, .git/, .claude/…), ``data/`` (user-scoped — seul
   ``data/{datastore,uploads}/<user.id>/`` passe), les substrings de chemin,
   extensions, noms de fichiers exacts et patterns. Toute couche suffit à
   bloquer. (Avant 2026-05-21 : allowlist stricte ``ALLOWED_ROOTS`` ; abandonnée
   car chaque nouveau dossier devait être ajouté à la main pour devenir lisible.
   ``ALLOWED_ROOTS`` ci-dessous est désormais INFORMATIF, pas un gate.)

2. **Realpath avant les checks (anti-symlink).** ``Path.resolve()`` suit les
   liens symboliques, puis on vérifie que le résultat reste dans
   ``PROJECT_ROOT`` ; le symlink brut est en plus refusé (anti-TOCTOU). Sans
   ça, un symlink ``app/foo -> /etc/passwd`` ouvrirait /etc/passwd.

3. **Ordre des checks de ``is_path_safe`` (fail-closed).** (a) type/NUL/chemin
   absolu/``..`` brut, (b) resolve + dans PROJECT_ROOT, (c) refus symlink,
   (d) répertoire top-level denylisté, (e) ``data/`` user-scoped, (f) substring
   de chemin, (g) extension, (h) nom de fichier exact, (i) pattern de nom.
   Toute couche suffit à bloquer.

4. **Hard caps déterministes.** MAX_FILE_BYTES, MAX_LINES_PER_READ,
   MAX_GREP_MATCHES, MAX_GREP_MATCHES_PER_FILE — pas de "best effort".
   Le caller reçoit toujours un dict avec ``truncated`` et un ``notice``
   actionnable s'il veut paginer.

5. **Pas de scrubbing ici.** Cette couche s'occupe d'autoriser/refuser
   les chemins et de lire. Le scrubbing des secrets éventuels qui
   traîneraient dans le code (clés API en commentaire, etc.) est la
   responsabilité de ``code_secret_scrubber.scrub()`` appelé par
   l'agent_tools handler avant injection LLM.

6. **Aucun chemin n'est construit côté caller.** Le caller passe un path
   relatif au projet (str). Le module résout en absolu via PROJECT_ROOT.
   Cela évite les ``os.path.join`` aléatoires côté handlers qui
   pourraient introduire des bugs cross-OS (Windows séparateurs).

Références :
- OWASP File Path Traversal Prevention Cheat Sheet
- CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- CWE-200 (Exposure of Sensitive Information)
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Constantes — chemins et limites
# ---------------------------------------------------------------------------

# Racine du projet : <repo>/  (codebase_reader.py est dans
# app/services/ai/ → 3 parents).
PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[3]

# Racines source conventionnelles du projet — ⚠️ INFORMATIF, PAS un gate de
# sécurité. Depuis 2026-05-21 le gate (``is_path_safe``) est open-by-default +
# denylist : cette liste ne restreint plus RIEN au runtime. Elle sert de repère
# (navigation, assertions de tests). Y ajouter/retirer une racine n'ouvre ni ne
# ferme aucun accès — pour bloquer un dossier, l'ajouter à la denylist
# (``_DENY_TOP_LEVEL_DIRS`` / ``DENY_PATH_SUBSTRINGS``).
ALLOWED_ROOTS: Final[tuple[str, ...]] = (
    "app",
    "static",
    "templates",
    "tests",
    "scripts",
    "docs",
    "alembic",
    # Documentation knowledge graph (utile à l'agent pour répondre aux
    # questions d'architecture). Le SOUS-DOSSIER ``cache/`` est
    # explicitement denylisté plus bas (regenerable, gros volume).
    "graphify-out",
)

# (L'ancienne ``ALLOWED_ROOT_FILES`` — whitelist de fichiers racine lisibles —
# a été retirée le 2026-06-01 : code mort depuis le passage open-by-default
# du 2026-05-21, jamais lue par ``is_path_safe``. Les fichiers racine sensibles
# sont protégés par la denylist ci-dessous : ``.env`` via DENY_PATH_SUBSTRINGS,
# ``CLAUDE.md`` via DENY_FILENAMES, etc.)

# --- DENYLIST exhaustive : tout ce qui peut contenir des données privées,
# des secrets, des résultats utilisateur, des logs PII, ou des artefacts
# regenerables qui exploseraient le budget tokens. La liste cumule le
# .gitignore actuel + les patterns observés en runtime.

# Substring matchés dans le path absolu après resolve. CASE-INSENSITIVE.
# Les patterns sont conservés en str pour faciliter la lecture ; la
# comparaison utilise ``str.lower()``.
DENY_PATH_SUBSTRINGS: Final[tuple[str, ...]] = (
    # --- Données utilisateur ---
    # ``/data/`` est traité SÉPARÉMENT par ``_check_data_path_user_scoped``
    # (cf. ``is_path_safe``) : interdit par défaut SAUF
    # ``data/datastore/<user_id>/`` et ``data/uploads/<user_id>/`` pour
    # l'utilisateur courant. On ne le met PLUS dans cette liste pour ne pas
    # bloquer les paths user-scoped légitimes.
    "/backups/",
    # --- Pipeline outputs (run.json 50 MB, traces, sessions Q/A) ---
    "/outputs/",
    "/_debug_traces/",
    # --- Secrets, locaux, et configs sensibles ---
    "/.env",  # .env, .env.before-restore-*, .env.local, etc.
    "/.git/",
    "/.komptia-tmp.",
    "/.fernet_salt",
    "/.fernet_key",
    "/.schema_sync.lock",
    # --- Caches regenerables / volumineux ---
    "/__pycache__/",
    "/.pytest_cache/",
    "/.mypy_cache/",
    "/.ruff_cache/",
    "/htmlcov/",
    "/.coverage",
    "/node_modules/",
    "/venv/",
    "/.venv/",
    "/env/",
    "/graphify-out/cache/",
    # --- Logs PII (prompts utilisateur, requêtes SQL en clair) ---
    "/llm_log.",  # llm_log.md, llm_log.YYYY-MM-DDTHHMMSS.md (rotated)
    "/logs/",
    # --- Trash / dossiers archivés (peuvent contenir secrets historiques) ---
    "/_trash/",
    # --- Privé local Claude (sessions, prompts, output) ---
    # ⚠️ Redondant depuis 2026-06-01 : ``.claude`` est dans _DENY_TOP_LEVEL_DIRS
    # → le check top-level (étape 4) bloque DÉJÀ tout ``.claude/...`` avant
    # d'arriver ici. Conservé en défense-en-profondeur (si la denylist
    # top-level était modifiée par erreur, ces substrings restent un filet).
    "/.claude/output/",
    "/.claude/anon-impl-loop/",
    "/.claude/projects/",
    # --- macOS / IDE noise ---
    "/.DS_Store",
    "/.idea/",
    "/.vscode/",
)

# Extensions interdites — données binaires, BDD, exports, archives, certs.
DENY_FILE_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        # --- BDD ---
        ".db",
        ".sqlite",
        ".sqlite3",
        ".db-shm",
        ".db-wal",
        ".db-journal",
        # --- Données utilisateur ---
        ".afz.json",  # classeurs Komptia (multi-onglets)
        # --- Exports utilisateur ---
        ".xlsx",
        ".xls",
        ".csv",
        ".tsv",
        ".parquet",
        ".feather",
        ".pdf",  # rapports générés
        # --- Backups / archives ---
        ".bak",
        ".backup",
        ".old",
        ".tar",
        ".gz",
        ".zip",
        ".7z",
        ".rar",
        ".tgz",
        ".xz",
        # --- Certs / clés ---
        ".pem",
        ".key",
        ".crt",
        ".cer",
        ".p12",
        ".pfx",
        ".jks",
        # --- Binaires / images / vidéos ---
        ".pyc",
        ".pyo",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".svg",  # peut contenir du code mais souvent gros & bruit
        ".ico",
        ".mp3",
        ".mp4",
        ".mov",
        ".webm",
        # --- Fonts ---
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
    }
)

# Filenames exacts interdits (toutes localisations).
DENY_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.development",
        ".env.test",
        ".envrc",
        "secrets.json",
        "secrets.yaml",
        "credentials.json",
        "service-account.json",
        "id_rsa",
        "id_ed25519",
        "id_dsa",
        "known_hosts",
        "authorized_keys",
        "llm_log.md",
        "llm_log.md.backup",
        "user_qa_session.json",
        "run.json",
        "run.sql",
        "run.md",
        "run.log",
        # Doctrine/config dev interne des assistants IA de code — confidentiel,
        # ne JAMAIS exposer via Iris (instructions dev, infos client, stratégie
        # projet). On bloque la CLASSE entière (pas seulement CLAUDE.md) car ces
        # fichiers servent tous le même rôle ; ajouter un nouvel assistant ne
        # doit pas rouvrir la fuite. Comparaison via ``.lower()`` → casse
        # indifférente. ``.claude/`` (répertoire) est bloqué séparément via
        # _DENY_TOP_LEVEL_DIRS.
        "CLAUDE.md",
        "AGENTS.md",
        "GEMINI.md",
        ".cursorrules",
        ".windsurfrules",
        "copilot-instructions.md",
        ".fernet_salt",
        ".fernet_key",
        ".schema_sync.lock",
    }
)

# Pattern fichiers (regex) — couvre les rotations / variantes.
DENY_FILENAME_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    # llm_log.YYYY-MM-DDTHHMMSS.md (rotation logger LLM)
    re.compile(r"^llm_log\.[0-9T:-]+\.md(?:\.backup)?$"),
    # Copies/variantes manuelles : "llm_log copy.md", "llm_log_readable.md",
    # "llm_log copilot_agent_*.md" (espace ou underscore après llm_log → PII en
    # clair). L'exact "llm_log.md" reste couvert par la deny-list de noms.
    re.compile(r"^llm_log[ _].+\.md$"),
    # appfazia.db.old, komptia.db.corrupted, komptia.db.corrupted-shm, etc.
    re.compile(r"^(?:appfazia|komptia|sage_copy)\.db.*$"),
    # Backups produits par make backup (timestamp dans le nom)
    re.compile(r"^.*\.before-restore-[0-9].*$"),
    # Exports Iris/Komptia (datés)
    re.compile(r"^komptia_(?:iris|export)_.+\.(?:xlsx|xls|csv|json)$"),
    # Backups automation/datastore (timestamp dans le nom)
    re.compile(r"^automation_(?:legacy_backup|purge_phase[0-9]+)_[0-9]+\.json$"),
)

# --- Hard caps ---

# Taille max par fichier lu (octets). Au-delà → tronqué + notice.
MAX_FILE_BYTES: Final[int] = 200 * 1024  # 200 KB

# Max lignes par appel ``read_file_paginated`` (caller doit paginer).
MAX_LINES_PER_READ: Final[int] = 2000

# Total max grep matches par appel.
MAX_GREP_MATCHES: Final[int] = 200

# Max grep matches par fichier (anti-bruit + équité entre fichiers).
MAX_GREP_MATCHES_PER_FILE: Final[int] = 25

# Total max fichiers retournés par ``list_files``.
MAX_LIST_FILES: Final[int] = 200

# Budget total de lignes lues par session conversationnelle (cap soft que
# l'agent_tools handler doit suivre via context dict).
SESSION_LINES_BUDGET: Final[int] = 10_000

# Pattern minimum pour ``grep_codebase`` (anti-DOS : refuser pattern vide
# ou ``.``/``.*`` qui matchent tout le code).
_MIN_GREP_PATTERN_LEN: Final[int] = 2
_FORBIDDEN_GREP_PATTERNS: Final[frozenset[str]] = frozenset(
    {".", "..", ".*", ".+", "^", "$", "^.*$", "^.+$"}
)


# ---------------------------------------------------------------------------
# Datatypes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GrepMatch:
    """Une occurrence trouvée par ``grep_codebase`` (sérialisable JSON)."""

    file: str  # path relatif au projet
    line: int
    snippet: str  # ligne complète (tronquée à 500 chars max)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

# Dossiers top-level entièrement interdits (refus dès que ``rel_parts[0]``
# matche, sans dépendre du slash final dans la deny substring).
# Couvre les cas où l'ancien ``ALLOWED_ROOTS`` whitelist bloquait
# implicitement ces dossiers ; le passage à open-by-default exige un
# deny explicite. ``data/`` est traité SÉPARÉMENT (cf. ``_check_data_path_user_scoped``).
_DENY_TOP_LEVEL_DIRS: Final[frozenset[str]] = frozenset(
    {
        "outputs",      # pipeline outputs : run.json (50 MB), SQL/PII en clair
        "backups",      # backups historiques
        "_trash",       # code archivé
        "node_modules", # dépendances JS
        "venv",
        ".venv",
        "env",          # virtualenv local
        "htmlcov",      # coverage HTML
        ".git",
        ".idea",
        ".vscode",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        # Config/doctrine/tooling interne Claude Code (rules, skills, settings,
        # prod-loop, output, projects) — confidentiel, rien d'utile à l'agent
        # pour répondre « comment marche l'app ». Englobe les sous-chemins déjà
        # listés en DENY_PATH_SUBSTRINGS (.claude/output|projects|…), gardés en
        # défense-en-profondeur.
        ".claude",
    }
)


# Préfixes user-scoped autorisés dans ``data/``.
# Pattern : ``data/<root>/<user_id>/...`` où ``<user_id>`` est l'id de
# l'user qui appelle l'outil. Tout autre chemin sous ``data/`` (komptia.db,
# .fernet_salt, automation_reports/, fichiers d'un autre user_id, etc.)
# est refusé. Source : ``_user_dir(user_id)`` dans ``app/handlers/datastore.py``
# pour ``datastore`` ; ``UPLOAD_DIR / str(user_id)`` côté upload handlers.
_USER_SCOPED_DATA_ROOTS: Final[tuple[str, ...]] = ("datastore", "uploads")


def _check_data_path_user_scoped(rel_parts: tuple[str, ...], user: Any) -> bool:
    """Vérifie qu'un chemin sous ``data/`` appartient à l'user courant.

    Si ``rel_parts`` ne commence pas par ``data/``, retourne ``True``
    (out of scope — laisse passer pour les autres checks).

    Si ``rel_parts`` commence par ``data/``, autorise UNIQUEMENT les
    chemins de la forme ``data/<root>/<user.id>/...`` avec ``<root>``
    dans ``_USER_SCOPED_DATA_ROOTS``. Tout autre cas → refus.

    ``user=None`` (anonyme/script) + path dans ``data/`` → refus
    (fail-closed). Note : ``user.id == 0`` est autorisé (edge case
    rare mais valide — la comparaison explicite à ``None`` ne tombe
    PAS dans le piège ``if not user_id`` qui rejetterait 0).
    """
    if not rel_parts or rel_parts[0] != "data":
        return True
    user_id = getattr(user, "id", None) if user is not None else None
    if user_id is None:
        return False
    # ``data/<root>/<user_id>/...`` minimum 3 parts.
    if len(rel_parts) < 3:
        return False
    # ``.lower()`` pour cohérence cross-OS (sur Windows FS case-insensitive,
    # un user pourrait passer "Datastore" et matcher l'allowlist).
    if rel_parts[1].lower() not in _USER_SCOPED_DATA_ROOTS:
        return False
    if rel_parts[2] != str(user_id):
        return False
    return True


def is_path_safe(rel_path: str, user: Any = None) -> Path | None:
    """Résout un path relatif au projet et vérifie sa licéité.

    Retourne le ``Path`` absolu canonisé si tous les checks passent,
    sinon ``None`` (et logue WARNING avec la raison du refus).

    Workflow de vérification (fail-closed) — l'ordre reflète le corps :
        1. Type/contenu : str non vide, pas de NUL byte, pas de chemin
           absolu, pas de ``..`` dans la string brute (refus précoce —
           défense en profondeur même si realpath aurait neutralisé).
        2. Résolution réelle : ``Path.resolve()`` suit les symlinks ; si le
           résultat sort de PROJECT_ROOT, refus.
        3. Refus symlink brut : si le chemin tel que passé EST un lien
           symbolique, refus (réduit la fenêtre TOCTOU entre resolve() et
           open() côté caller — cf. adversarial #2/#3).
        4. Répertoire top-level denylisté : ``rel_parts[0]`` pas dans
           ``_DENY_TOP_LEVEL_DIRS`` (outputs/, backups/, venv/, .git/,
           .claude/…).
        5. ``data/`` user-scoped : si le path est sous ``data/``, autoriser
           UNIQUEMENT ``data/datastore/<user.id>/...`` ou
           ``data/uploads/<user.id>/...``. Tout autre cas (BDD, secrets,
           autres user_ids, sous-dossiers système) → refus.
        6. Denylist substring : aucun motif de DENY_PATH_SUBSTRINGS.
        7. Denylist extension : aucun ``.suffix`` (composés inclus) dans
           DENY_FILE_EXTENSIONS, + marqueur ``.afz.`` testé sur ``.name``.
        8. Denylist filename exact : ``.name`` (lower) pas dans DENY_FILENAMES.
        9. Denylist filename pattern : aucun match dans
           DENY_FILENAME_PATTERNS.

    Au-delà de ces checks, **tout le repo est lisible par défaut**
    (changement 2026-05-21 — avant : allowlist stricte ALLOWED_ROOTS).
    L'inversion deny-by-default → ouvert-sauf-deny simplifie l'évolution
    (un nouveau dossier ajouté = automatiquement lisible) et reste sûr car
    la denylist couvre les zones sensibles (data/ user-scoped, secrets, BDD,
    logs PII, caches, extensions binaires).

    Args:
        rel_path: chemin relatif au projet à vérifier.
        user: objet user (ORM ``User`` ou stub avec ``.id``). Requis pour
            tout path sous ``data/`` ; ignoré ailleurs. ``None`` + path
            sous ``data/`` → refus.

    Le caller reçoit ``None`` quel que soit la raison ; le détail va dans
    les logs (admin debugging) — ne pas exfiltrer les motifs de refus à
    l'agent LLM, qui pourrait alors itérer pour contourner.
    """
    if not isinstance(rel_path, str) or not rel_path.strip():
        logger.warning("is_path_safe: rejected empty/invalid path")
        return None

    # Bloque les bytes NUL, traversal explicite, et chemins absolus
    if "\x00" in rel_path:
        logger.warning("is_path_safe: rejected NUL byte in path")
        return None

    # Refus précoce : path absolu interdit (force tout en relatif au projet).
    # Sur Windows, "C:\..." matche aussi.
    if os.path.isabs(rel_path):
        logger.warning("is_path_safe: rejected absolute path: %s", rel_path[:80])
        return None

    # Refus précoce : présence de ``..`` dans le path brut. Défense en
    # profondeur — `resolve()` suivrait le ``..`` mais on veut bloquer
    # avant.
    parts = Path(rel_path).parts
    if any(p == ".." for p in parts):
        logger.warning("is_path_safe: rejected '..' traversal in: %s", rel_path[:80])
        return None

    # Construction du chemin candidat puis résolution réelle (suit symlinks)
    candidate = (PROJECT_ROOT / rel_path).resolve(strict=False)

    # Sortie du projet ? (cas d'un symlink dans un répertoire allowlisté)
    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError:
        logger.warning("is_path_safe: resolved path outside project root: %s", str(candidate)[:120])
        return None

    # Defense-in-depth symlink : on a déjà ``resolve()`` qui suit le lien,
    # mais on refuse explicitement les paths qui SONT eux-mêmes des symlinks
    # pour limiter la fenêtre TOCTOU entre ``resolve()`` et ``open()``
    # côté caller. Un user qui crée un symlink dans son dossier datastore
    # et le change entre les 2 appels pourrait sinon faire lire un fichier
    # hors projet. Cf. adversarial #2/#3.
    # Note : ``lstat`` car ``Path.is_symlink`` du chemin BRUT (avant resolve)
    # est plus pertinent ici — on regarde si le path tel que passé est un lien.
    raw_candidate = PROJECT_ROOT / rel_path
    try:
        if raw_candidate.is_symlink():
            logger.warning("is_path_safe: rejected symlink: %s", rel_path[:120])
            return None
    except OSError:
        # Permissions ou path inexistant : on laisse passer, le caller
        # gérera (read_file_paginated/list_files vérifient existence ensuite).
        pass

    # Détermination du path relatif AU projet pour les checks
    rel_to_root = candidate.relative_to(PROJECT_ROOT)
    rel_str = str(rel_to_root)
    rel_parts = rel_to_root.parts

    # Refus top-level (outputs/, backups/, _trash/, venv/, .git/, etc.).
    # Couvre les cas où l'ancien ALLOWED_ROOTS strict bloquait implicitement
    # ces dossiers ; le passage à open-by-default exige un deny explicite.
    if rel_parts and rel_parts[0] in _DENY_TOP_LEVEL_DIRS:
        logger.warning(
            "is_path_safe: top-level dir denied: %s", rel_str[:120]
        )
        return None

    # Check ``data/`` user-scoped : si le path est sous ``data/``, n'accepter
    # QUE ``data/datastore/<user.id>/...`` ou ``data/uploads/<user.id>/...``.
    # Tout autre cas (BDD système, autres user_ids, sous-dossiers système)
    # → refus. Hors de ``data/`` → laisse passer pour les autres checks.
    if not _check_data_path_user_scoped(rel_parts, user):
        logger.warning(
            "is_path_safe: data/ path refused (user=%s, parts=%s): %s",
            getattr(user, "id", None) if user is not None else None,
            rel_parts[:3],
            rel_str[:120],
        )
        return None

    # Denylist substring (case-insensitive). On compare sur "/" préfixés
    # (les substrings dans DENY_PATH_SUBSTRINGS commencent toutes par "/")
    # pour matcher des composants de chemin entiers et pas des préfixes
    # arbitraires (anti-faux-positif "data" qui matcherait "data_access").
    candidate_lower = "/" + str(candidate).replace(os.sep, "/").lower().lstrip("/")
    for substr in DENY_PATH_SUBSTRINGS:
        if substr.lower() in candidate_lower:
            logger.warning(
                "is_path_safe: denylist substring '%s' matched: %s", substr, rel_str[:120]
            )
            return None

    # Denylist extensions — vérifier TOUS les suffixes composés
    # (``.tar.gz``, ``.afz.json``, ``foo.db.txt``…) pas seulement le dernier.
    # ``Path("foo.afz.json.txt").suffixes`` → ``[".afz", ".json", ".txt"]``.
    # On bloque dès qu'un de ces composants est dans la denylist.
    name_lower = candidate.name.lower()
    suffixes_lower = [s.lower() for s in candidate.suffixes]
    for suffix in suffixes_lower:
        if suffix in DENY_FILE_EXTENSIONS:
            logger.warning(
                "is_path_safe: denylist extension '%s' in '%s': %s",
                suffix,
                candidate.name,
                rel_str[:120],
            )
            return None
    # Composé .afz.json explicite — refusé partout, même renommé en
    # foo.afz.json.txt (le `.afz.` reste discriminant et signal qu'il
    # s'agit d'un classeur utilisateur).
    if ".afz." in name_lower or name_lower.endswith(".afz"):
        logger.warning("is_path_safe: denylist .afz marker: %s", rel_str[:120])
        return None

    # Denylist filename exact
    if name_lower in {n.lower() for n in DENY_FILENAMES}:
        logger.warning("is_path_safe: denylist filename '%s': %s", name_lower, rel_str[:120])
        return None

    # Denylist filename pattern
    for pattern in DENY_FILENAME_PATTERNS:
        if pattern.match(candidate.name):
            logger.warning(
                "is_path_safe: denylist pattern '%s' matched %s: %s",
                pattern.pattern,
                candidate.name,
                rel_str[:120],
            )
            return None

    return candidate


def _to_relative(abs_path: Path) -> str:
    """Convertit un Path absolu canonisé en chemin relatif au projet
    (str). Suppose que ``abs_path`` est sous PROJECT_ROOT (vérifié en
    amont par ``is_path_safe``)."""
    return str(abs_path.relative_to(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# list_files
# ---------------------------------------------------------------------------


def list_files(
    directory: str, glob_pattern: str = "*", user: Any = None
) -> dict[str, Any]:
    """Liste les fichiers d'un répertoire autorisé.

    Args:
        directory: Path relatif au projet (str). Doit pointer sur un
            dossier accessible (cf. ``is_path_safe`` workflow).
        glob_pattern: Glob standard (ex: ``*.py``, ``**/*.html``). Limité
            à 200 fichiers retournés (cap MAX_LIST_FILES).
        user: objet user pour autoriser ``data/datastore/<id>/`` et
            ``data/uploads/<id>/`` (cf. ``is_path_safe``). ``None`` →
            pas d'accès dans ``data/``.

    Returns:
        Dict avec :
            - ``directory`` : path relatif demandé
            - ``files`` : list[str] de paths relatifs (max 200)
            - ``total`` : nombre total trouvé (pré-cap)
            - ``truncated`` : bool — True si total > 200
            - ``notice`` : str ou None — message de pagination/avertissement
            - ``error`` : str ou None — message si refus
    """
    safe = is_path_safe(directory, user=user)
    if safe is None:
        return {
            "directory": directory,
            "files": [],
            "total": 0,
            "truncated": False,
            "notice": None,
            "error": "Accès refusé : chemin invalide ou interdit.",
        }

    if not safe.is_dir():
        return {
            "directory": directory,
            "files": [],
            "total": 0,
            "truncated": False,
            "notice": None,
            "error": "Le chemin n'est pas un dossier.",
        }

    # Glob via pathlib. ``glob`` ne suit pas les symlinks par défaut hors
    # ``rglob`` ; on utilise ``rglob`` si ``**`` dans le pattern.
    use_recursive = "**" in glob_pattern

    try:
        if use_recursive:
            # Anchor pattern : ``**/foo.py`` → on glob depuis safe
            # directement. ``glob_pattern`` peut commencer par ``**/``.
            iterator = safe.glob(glob_pattern)
        else:
            iterator = safe.glob(glob_pattern)
    except (OSError, ValueError) as exc:
        logger.warning("list_files: glob error %r: %s", glob_pattern, exc)
        return {
            "directory": directory,
            "files": [],
            "total": 0,
            "truncated": False,
            "notice": None,
            "error": "Pattern glob invalide.",
        }

    matched: list[str] = []
    total = 0
    for entry in iterator:
        if not entry.is_file():
            continue
        # Re-vérifier chaque entrée via is_path_safe — un fichier dans un
        # sous-dossier denylisté (data/, .env*, .afz.json…) doit rester
        # invisible même listé.
        sub_rel = str(entry.resolve().relative_to(PROJECT_ROOT))
        if is_path_safe(sub_rel, user=user) is None:
            continue
        total += 1
        if len(matched) < MAX_LIST_FILES:
            matched.append(sub_rel)

    truncated = total > MAX_LIST_FILES
    notice = None
    if truncated:
        notice = (
            f"Résultats tronqués à {MAX_LIST_FILES} fichiers sur {total} "
            "trouvés. Affinez le glob_pattern pour réduire le set."
        )

    return {
        "directory": _to_relative(safe),
        "files": matched,
        "total": total,
        "truncated": truncated,
        "notice": notice,
        "error": None,
    }


# ---------------------------------------------------------------------------
# read_file_paginated
# ---------------------------------------------------------------------------


def read_file_paginated(
    rel_path: str,
    offset: int = 0,
    limit: int | None = None,
    user: Any = None,
) -> dict[str, Any]:
    """Lit un fichier de la codebase avec hard cap et pagination.

    Args:
        rel_path: Path relatif au projet (str).
        offset: 1-indexed line offset (1 = première ligne). Si <= 0,
            normalisé à 1.
        limit: Nombre de lignes à lire (cap MAX_LINES_PER_READ). None =
            MAX_LINES_PER_READ.
        user: objet user pour autoriser ``data/datastore/<id>/`` et
            ``data/uploads/<id>/`` (cf. ``is_path_safe``). ``None`` →
            pas d'accès dans ``data/``.

    Returns:
        Dict avec :
            - ``path`` : path relatif (canonisé)
            - ``content`` : str — contenu des lignes lues
            - ``offset`` : int — première ligne incluse (1-indexed)
            - ``line_count`` : int — nombre de lignes retournées
            - ``total_lines`` : int — total dans le fichier
            - ``size_bytes`` : int — taille fichier complète
            - ``truncated`` : bool — True si fin du fichier non atteinte
              ou si fichier > MAX_FILE_BYTES
            - ``notice`` : str ou None — message de pagination/avertissement
            - ``error`` : str ou None — message si refus
    """
    safe = is_path_safe(rel_path, user=user)
    if safe is None:
        return {
            "path": rel_path,
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": 0,
            "truncated": False,
            "notice": None,
            "error": "Accès refusé : chemin invalide ou interdit.",
        }

    if not safe.is_file():
        return {
            "path": rel_path,
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": 0,
            "truncated": False,
            "notice": None,
            "error": "Le chemin n'est pas un fichier.",
        }

    try:
        size_bytes = safe.stat().st_size
    except OSError as exc:
        logger.warning("read_file_paginated: stat error %s", exc)
        return {
            "path": _to_relative(safe),
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": 0,
            "truncated": False,
            "notice": None,
            "error": "Erreur lecture fichier.",
        }

    # Détection rudimentaire de binaire — refuser si NUL byte dans les
    # 4 KB d'entête.
    try:
        with safe.open("rb") as fh:
            head = fh.read(4096)
    except OSError as exc:
        logger.warning("read_file_paginated: open error %s", exc)
        return {
            "path": _to_relative(safe),
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": size_bytes,
            "truncated": False,
            "notice": None,
            "error": "Erreur lecture fichier.",
        }
    if b"\x00" in head:
        return {
            "path": _to_relative(safe),
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": size_bytes,
            "truncated": False,
            "notice": None,
            "error": "Fichier binaire (lecture refusée).",
        }

    # Normalisation de l'offset/limit
    if offset is None or offset < 1:
        offset = 1
    if limit is None or limit > MAX_LINES_PER_READ:
        limit = MAX_LINES_PER_READ
    if limit < 1:
        limit = 1

    # Cap taille fichier en plus de cap lignes — protège un fichier d'1
    # ligne de 10 MB (binaire ou minified).
    file_truncated_by_size = size_bytes > MAX_FILE_BYTES
    bytes_to_read = min(size_bytes, MAX_FILE_BYTES)

    try:
        with safe.open("r", encoding="utf-8", errors="replace") as fh:
            # On lit au max MAX_FILE_BYTES puis on splite en lignes.
            buf = fh.read(bytes_to_read)
    except OSError as exc:
        logger.warning("read_file_paginated: read error %s", exc)
        return {
            "path": _to_relative(safe),
            "content": "",
            "offset": 0,
            "line_count": 0,
            "total_lines": 0,
            "size_bytes": size_bytes,
            "truncated": False,
            "notice": None,
            "error": "Erreur lecture fichier.",
        }

    all_lines = buf.splitlines()
    total_lines_in_buffer = len(all_lines)

    # Slice 1-indexed
    start_idx = max(0, offset - 1)
    end_idx = min(total_lines_in_buffer, start_idx + limit)
    selected = all_lines[start_idx:end_idx]
    content = "\n".join(selected)

    # Diagnostic truncation
    truncated = file_truncated_by_size or end_idx < total_lines_in_buffer
    notice = None
    if truncated:
        if file_truncated_by_size:
            notice = (
                f"Fichier > {MAX_FILE_BYTES // 1024} KB. Lecture limitée aux "
                f"premiers {MAX_FILE_BYTES // 1024} KB ({total_lines_in_buffer} "
                "lignes). Le contenu complet n'est pas accessible via cet outil."
            )
        else:
            next_offset = end_idx + 1
            notice = (
                f"Lignes {offset}-{end_idx} sur {total_lines_in_buffer}. "
                f"Pour la suite : appelle read_code_file avec offset={next_offset}."
            )

    return {
        "path": _to_relative(safe),
        "content": content,
        "offset": offset,
        "line_count": len(selected),
        "total_lines": total_lines_in_buffer,
        "size_bytes": size_bytes,
        "truncated": truncated,
        "notice": notice,
        "error": None,
    }


# ---------------------------------------------------------------------------
# grep_codebase
# ---------------------------------------------------------------------------


def _ripgrep_available() -> bool:
    """Détecte si ``rg`` est dans le PATH."""
    return shutil.which("rg") is not None


def _grep_with_ripgrep(
    pattern: str,
    file_glob: str | None,
    max_matches: int,
    user: Any = None,
) -> tuple[list[GrepMatch], int]:
    """Lance ripgrep sur PROJECT_ROOT et retourne les matches filtrés.

    Retourne ``(matches, total_pre_cap)`` ; ``total_pre_cap`` peut excéder
    ``max_matches`` si ripgrep a trouvé plus que demandé (utile pour le
    flag ``truncated`` côté caller).
    """
    cmd = [
        "rg",
        "--color=never",
        "--with-filename",
        "--line-number",
        "--no-heading",
        # Respecte .gitignore (couvre déjà data/, outputs/, backups/, etc.).
        "--no-messages",
        # Limite matches par fichier (surcouche en plus de notre own cap)
        "--max-count",
        str(MAX_GREP_MATCHES_PER_FILE),
    ]
    # Exclusion forte de ``data/`` au niveau ripgrep — défense en profondeur
    # en plus de la deny logique côté ``is_path_safe``. Si user fourni, on
    # **ré-include** ses sous-dossiers user-scoped (``data/datastore/<id>``
    # et ``data/uploads/<id>``) — ripgrep applique les `--glob` séquentiellement,
    # le `!` exclut d'abord, l'inclusion ensuite ré-autorise.
    cmd.extend(["--glob", "!data/**"])
    user_id = getattr(user, "id", None) if user is not None else None
    if user_id is not None:
        cmd.extend(["--glob", f"data/datastore/{user_id}/**"])
        cmd.extend(["--glob", f"data/uploads/{user_id}/**"])
    if file_glob:
        cmd.extend(["--glob", file_glob])
    cmd.append(pattern)
    # Scope : tout le repo. Les exclusions ``--glob !data/**`` + le filtrage
    # post-processing via ``is_path_safe`` couvrent les paths sensibles.
    cmd.append("--")
    cmd.append(str(PROJECT_ROOT))

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(PROJECT_ROOT),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("grep_codebase: ripgrep failed %s", exc)
        return [], 0

    matches: list[GrepMatch] = []
    total = 0
    per_file: dict[str, int] = {}
    for raw_line in proc.stdout.splitlines():
        # Format : path:line:content (paths absolus car on a passé des
        # paths absolus en argument).
        parts = raw_line.split(":", 2)
        if len(parts) < 3:
            continue
        abs_path_str, line_str, snippet = parts
        try:
            line_no = int(line_str)
        except ValueError:
            continue
        # Re-vérification : chaque match doit passer is_path_safe (defense
        # in depth — un symlink corrompu, un fichier dans un sous-dossier
        # sensible, un path qui passerait ripgrep mais devrait être deny).
        try:
            rel = str(Path(abs_path_str).resolve().relative_to(PROJECT_ROOT))
        except (ValueError, OSError):
            continue
        if is_path_safe(rel, user=user) is None:
            continue
        # Cap par fichier (au cas où rg en aurait laissé passer plus)
        per_file[rel] = per_file.get(rel, 0) + 1
        if per_file[rel] > MAX_GREP_MATCHES_PER_FILE:
            continue
        total += 1
        if len(matches) < max_matches:
            matches.append(GrepMatch(file=rel, line=line_no, snippet=snippet[:500]))
    return matches, total


def _grep_python_fallback(
    pattern: str,
    file_glob: str | None,
    max_matches: int,
    user: Any = None,
) -> tuple[list[GrepMatch], int]:
    """Fallback grep en Python pur (pas de ripgrep installé).

    Walk PROJECT_ROOT en sautant ``data/`` (sauf les sous-dossiers
    user-scoped si ``user`` fourni). Le filtrage final passe par
    ``is_path_safe`` — défense en profondeur.
    """
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        logger.warning("grep_codebase: invalid regex %r: %s", pattern, exc)
        return [], 0

    matches: list[GrepMatch] = []
    total = 0
    per_file: dict[str, int] = {}

    glob_pat = file_glob or "**/*"
    user_id = getattr(user, "id", None) if user is not None else None

    # Walk tout le repo. Skip rapide des dossiers évidents pour la perf —
    # ``is_path_safe`` reste l'autorité finale.
    for entry in PROJECT_ROOT.glob(glob_pat):
        if not entry.is_file():
            continue
        try:
            rel = str(entry.resolve().relative_to(PROJECT_ROOT))
        except (ValueError, OSError):
            continue
        # Skip court-circuit perf : sauter rapidement les top-level deny
        # et tout sous data/ qui n'est pas user-scoped. Le check complet
        # is_path_safe reste l'autorité finale, mais ces skip évitent
        # de scanner des dizaines de milliers de fichiers system.
        rel_parts = Path(rel).parts
        if rel_parts and rel_parts[0] in _DENY_TOP_LEVEL_DIRS:
            continue
        if rel_parts and rel_parts[0] == "data":
            if user_id is None:
                continue
            if (
                len(rel_parts) < 3
                or rel_parts[1].lower() not in _USER_SCOPED_DATA_ROOTS
                or rel_parts[2] != str(user_id)
            ):
                continue
        if is_path_safe(rel, user=user) is None:
            continue
        # Defense-in-depth symlink : on a déjà `resolve()` via is_path_safe,
        # mais on refuse explicitement les symlinks pour limiter le TOCTOU
        # entre resolve et open (un user qui change le symlink entre les
        # deux pourrait pointer vers /etc). Cf. adversarial #2.
        if entry.is_symlink():
            continue
        try:
            with entry.open("r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
                if "\x00" in head:
                    continue
                fh.seek(0)
                for line_no, line in enumerate(fh, start=1):
                    if not regex.search(line):
                        continue
                    per_file[rel] = per_file.get(rel, 0) + 1
                    if per_file[rel] > MAX_GREP_MATCHES_PER_FILE:
                        break
                    total += 1
                    if len(matches) < max_matches:
                        matches.append(
                            GrepMatch(file=rel, line=line_no, snippet=line.rstrip("\n")[:500])
                        )
                    # Pas de break global — on continue à compter pour
                    # fournir un total exact (plafond max_matches absorbe
                    # les retours mais l'agent voit "truncated").
        except OSError:
            continue

    return matches, total


def grep_codebase(
    pattern: str,
    file_glob: str | None = None,
    max_matches: int = MAX_GREP_MATCHES,
    user: Any = None,
) -> dict[str, Any]:
    """Recherche un pattern dans la codebase (ripgrep si dispo, sinon Python).

    Args:
        pattern: Regex (compatible Python ``re``). Refusé si trop court
            ou trivial (``.``/``.*``).
        file_glob: Glob (ex: ``*.py``, ``**/*.html``). None = tous fichiers.
        max_matches: Total matches retournés (cap MAX_GREP_MATCHES).
        user: objet user pour autoriser les paths ``data/datastore/<id>/``
            et ``data/uploads/<id>/`` (cf. ``is_path_safe``). ``None`` →
            aucun match dans ``data/``.

    Returns:
        Dict avec :
            - ``pattern`` : pattern utilisé
            - ``file_glob`` : glob utilisé
            - ``matches`` : list[dict] (file, line, snippet) max max_matches
            - ``total`` : nombre total trouvé pré-cap
            - ``truncated`` : bool — True si total > max_matches
            - ``notice`` : str ou None
            - ``error`` : str ou None
    """
    if not isinstance(pattern, str) or len(pattern.strip()) < _MIN_GREP_PATTERN_LEN:
        return {
            "pattern": pattern,
            "file_glob": file_glob,
            "matches": [],
            "total": 0,
            "truncated": False,
            "notice": None,
            "error": (
                f"Pattern trop court (min {_MIN_GREP_PATTERN_LEN} caractères). "
                "Précise davantage la recherche."
            ),
        }
    if pattern.strip() in _FORBIDDEN_GREP_PATTERNS:
        return {
            "pattern": pattern,
            "file_glob": file_glob,
            "matches": [],
            "total": 0,
            "truncated": False,
            "notice": None,
            "error": "Pattern trivial (matche tout). Précise davantage la recherche.",
        }

    if max_matches < 1:
        max_matches = 1
    if max_matches > MAX_GREP_MATCHES:
        max_matches = MAX_GREP_MATCHES

    if _ripgrep_available():
        matches, total = _grep_with_ripgrep(pattern, file_glob, max_matches, user=user)
    else:
        matches, total = _grep_python_fallback(pattern, file_glob, max_matches, user=user)

    truncated = total > len(matches)
    notice = None
    if truncated:
        notice = (
            f"{total} matches trouvés, {len(matches)} retournés. Affine le "
            "pattern ou ajoute un file_glob pour réduire."
        )

    return {
        "pattern": pattern,
        "file_glob": file_glob,
        "matches": [{"file": m.file, "line": m.line, "snippet": m.snippet} for m in matches],
        "total": total,
        "truncated": truncated,
        "notice": notice,
        "error": None,
    }


__all__ = [
    "PROJECT_ROOT",
    "ALLOWED_ROOTS",
    "DENY_PATH_SUBSTRINGS",
    "DENY_FILE_EXTENSIONS",
    "DENY_FILENAMES",
    "DENY_FILENAME_PATTERNS",
    "MAX_FILE_BYTES",
    "MAX_LINES_PER_READ",
    "MAX_GREP_MATCHES",
    "MAX_GREP_MATCHES_PER_FILE",
    "MAX_LIST_FILES",
    "SESSION_LINES_BUDGET",
    "GrepMatch",
    "is_path_safe",
    "list_files",
    "read_file_paginated",
    "grep_codebase",
]
