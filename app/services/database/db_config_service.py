"""Service de gestion des connexions BDD admin (CRUD + chiffrement + test).

Vue d'ensemble :

* **Chiffrement mot de passe** — :class:`cryptography.fernet.MultiFernet`
  avec clé primaire dérivée via PBKDF2-HMAC-SHA256 (600 000 itérations,
  recommandation OWASP Password Storage 2025) + salt persisté dans
  ``data/.fernet_salt``. La clé legacy (SHA-256 brut, ancien format)
  reste **active en lecture** pour décrypter les passwords stockés
  avant la migration de cryptographie ; toute écriture ré-encrypte avec
  la primary, donc le rotate est progressif et transparent.
* **Activation atomique** — :func:`activate_connection` exécute UN seul
  ``UPDATE`` (``is_active = (id = :target)``) pour éviter la fenêtre où
  zéro connexion serait active (race condition entre désactivation et
  activation). Le ``invalidate_version_cache`` est appelé pour forcer
  le rechargement du label SQL Server.
* **TOCTOU sur ``name`` unique** — la vérification pré-INSERT a été
  retirée : on attaque directement, et on traduit ``IntegrityError`` →
  ``DuplicateConnectionError`` (HTTP 409 côté handler). Pas de fenêtre
  où deux requêtes concurrentes voient ``existing is None`` puis
  insèrent toutes les deux.
* **Test de connexion** — :func:`test_connection` est décomposé en 4
  helpers privés (driver discovery, conn-string, SSRF check, test).
  Le ``ThreadPoolExecutor`` per-call (fuite mémoire à chaque call) est
  remplacé par :func:`asyncio.to_thread` (gère le pool partagé).

Cf. :file:`app/handlers/db_config.py` pour la couche HTTP, et
:file:`app/utils/network_safety.py` pour la défense SSRF.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, Final, Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.database import get_session
from app.core.exceptions import ConfigurationError
from app.models.db_config import DatabaseConnection, DatabaseType
from app.utils.logger import get_logger
from app.utils.network_safety import UnsafeHostError, assert_safe_host

# Eager-import pyodbc à hauteur module pour éviter le coût d'import dans
# chaque test. PYODBC_AVAILABLE flag pour l'absence (ex : CI Linux sans
# unixODBC). _PYODBC_IMPORT_ERROR garde le détail pour le log.
try:
    import pyodbc

    PYODBC_AVAILABLE: Final[bool] = True
    _PYODBC_IMPORT_ERROR: Final[str] = ""
except ImportError as _exc:
    pyodbc = None  # type: ignore[assignment]
    PYODBC_AVAILABLE = False
    _PYODBC_IMPORT_ERROR = str(_exc)


logger = get_logger(__name__)


# --- Constantes module (pas de magic number éparpillé) -------------------

# PBKDF2 itérations — OWASP Password Storage Cheat Sheet 2025 :
# 600 000 itérations PBKDF2-HMAC-SHA256 = ~150 ms sur CPU 2025, suffisant
# pour ralentir un attaquant offline qui aurait dump la BDD + le salt.
_PBKDF2_ITERATIONS: Final[int] = 600_000

# Salt persisté pour reproductibilité d'une exécution à l'autre. 16 octets
# (NIST SP 800-132) = 128 bits, largement assez face à une rainbow-table.
_SALT_FILENAME: Final[str] = ".fernet_salt"
_SALT_LENGTH_BYTES: Final[int] = 16

# Timeout test de connexion — borne haute pour ne pas laisser un test
# bloquer un thread > 30s (un admin qui tape un mauvais host doit être
# débloqué vite ; l'erreur réseau remonte typiquement en < 10s).
_DEFAULT_TEST_TIMEOUT_S: Final[int] = 10
_MAX_TEST_TIMEOUT_S: Final[int] = 30

# Driver ODBC : Driver 18 préféré (TLS 1.2 par défaut, sécurité OWASP),
# fallback Driver 17 si 18 absent (le serveur SQL Server peut refuser
# TLS 1.2 sur version ancienne ; documenté côté front-end UX).
_DRIVER_18: Final[str] = "ODBC Driver 18 for SQL Server"
_DRIVER_17: Final[str] = "ODBC Driver 17 for SQL Server"

# Mapping compatibility_level → version marketing SQL Server, utilisé
# par parse_sql_server_version_label (label injecté dans le prompt LLM).
_COMPAT_LEVEL_TO_VERSION: Final[dict[int, str]] = {
    80: "2000",
    90: "2005",
    100: "2008",
    110: "2012",
    120: "2014",
    130: "2016",
    140: "2017",
    150: "2019",
    160: "2022",
}

# Mapping inverse pour parser un label stocké.
_VERSION_TO_COMPAT_LEVEL: Final[dict[str, int]] = {
    v: k for k, v in _COMPAT_LEVEL_TO_VERSION.items()
}

# Capabilities SQL Server qui ont un compat_level minimum requis.
# Sert au feature #7 (auto-refactor SQL stockés quand la BDD change de
# version) : si la nouvelle compat est < min_required ET l'ancienne
# était >= min_required, la capability est "broken" pour les paires
# stockées qui l'utilisaient → LLM rewrite.
#
# Source : Microsoft Docs (T-SQL Reference, "Compatibility certification")
# https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-compatibility-level
#
# Liste NON exhaustive — couvre les patterns les plus courants vus dans
# les paires Q/SQL générées par les LLM modernes sur serveurs récents.
# Ajouter au besoin (le system tolère des capabilities non listées —
# elles passent juste invisibles dans le delta).
_CAPABILITY_MIN_COMPAT: Final[dict[str, int]] = {
    # SQL Server 2012+
    "IIF": 110,
    "OFFSET_FETCH": 110,
    "TRY_CONVERT": 110,
    "CONCAT": 110,
    # SQL Server 2016+
    "STRING_SPLIT": 130,
    "OPENJSON": 130,
    "JSON_VALUE": 130,
    "JSON_QUERY": 130,
    # SQL Server 2017+
    "STRING_AGG": 140,
    "STRING_AGG_WITHIN_GROUP": 140,
    "TRIM": 140,
    "TRANSLATE": 140,
    # SQL Server 2022+
    "GREATEST_LEAST": 160,
    "DATE_BUCKET": 160,
}


# --- Exceptions du domaine ------------------------------------------------


class DuplicateConnectionError(ValueError):
    """Levée quand un nom de connexion entre en collision avec une existante.

    Sous-classe de ``ValueError`` pour rester compatible avec les tests
    legacy qui catchent ``ValueError`` ; le handler peut catcher la
    classe précise pour répondre 409.
    """


class ConnectionInUseError(ValueError):
    """Levée quand on tente de supprimer une connexion encore active."""


# --- Crypto layer ---------------------------------------------------------


def _data_dir() -> Path:
    """Retourne le dossier ``data/`` (où vit la BDD locale et le salt).

    Calculé à la demande pour ne pas bloquer l'import si l'utilisateur
    a redirigé ``DATA_DIR`` après le chargement de la config.
    """
    from app.config import DATA_DIR

    return DATA_DIR


def _load_or_create_salt() -> bytes:
    """Charge le salt PBKDF2 depuis ``data/.fernet_salt``, ou le génère.

    Le salt est lié à l'installation, pas au secret. On peut le commit
    dans le backup (pas un secret en soi — le secret reste FERNET_KEY /
    SECRET_KEY), mais sans lui le rotate de clé deviendrait impossible.

    Permissions : 0600 (lecture/écriture proprio uniquement) — défense
    en profondeur si le serveur partage le filesystem.

    Raises
    ------
    ConfigurationError
        Si le salt ne peut être ni lu ni persisté (dossier ``data/`` en
        lecture seule / disque plein). On préfère échouer franchement
        plutôt que retomber sur un salt constant global qui affaiblirait
        la crypto de toutes les installs R/O à l'identique.
    """
    salt_path = _data_dir() / _SALT_FILENAME
    if salt_path.exists():
        try:
            data = salt_path.read_bytes()
            if len(data) == _SALT_LENGTH_BYTES:
                return data
            # Salt corrompu (mauvaise longueur) — fallback sur dérivation
            # déterministe à partir du SECRET_KEY pour rester décryptable.
            logger.warning(
                "Salt Fernet de longueur inattendue (%d octets), fallback déterministe",
                len(data),
            )
        except OSError:
            logger.warning("Impossible de lire le salt Fernet, fallback déterministe")

    # Génération d'un nouveau salt — secrets.token_bytes utilise CSPRNG.
    new_salt = secrets.token_bytes(_SALT_LENGTH_BYTES)
    try:
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(new_salt)
        try:
            os.chmod(salt_path, 0o600)
        except OSError:
            # Filesystems exotiques (FAT/NTFS via WSL) refusent chmod ;
            # on continue, la défense de fond reste FERNET_KEY.
            pass
        return new_salt
    except OSError as exc:
        # Disque plein / R/O : impossible de persister un salt aléatoire.
        # On NE retombe PAS sur un salt constant global, ce qui serait :
        #   (1) une faiblesse crypto — toutes les installs sur disque R/O
        #       partageraient le MÊME salt → un attaquant peut précalculer
        #       des rainbow tables réutilisables d'une installation à l'autre,
        #       le PBKDF2 ne protège alors plus que par le SECRET_KEY ;
        #   (2) une bombe à retardement — si le disque redevient writable, le
        #       prochain boot génère un salt aléatoire → les secrets chiffrés
        #       avec le salt constant deviennent indéchiffrables (InvalidToken
        #       silencieux sur le mot de passe SQL et les clés API LLM).
        # data/ DOIT de toute façon être writable (la BDD SQLite y vit) : un
        # data/ en lecture seule = app déjà non-fonctionnelle. On échoue donc
        # franchement avec un message admin actionnable plutôt que de dégrader
        # silencieusement la crypto.
        logger.error("Impossible de persister le salt Fernet (%s) — fail-fast", exc)
        raise ConfigurationError(
            f"Impossible de persister le salt de chiffrement dans {salt_path.parent} "
            f"({exc}). Le dossier data/ doit être accessible en écriture "
            "(il contient aussi la base SQLite locale). Vérifiez les permissions "
            "du volume puis redémarrez.",
            context={"salt_dir": str(salt_path.parent)},
        ) from exc


def _derive_primary_key(raw_key: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 → 32 octets → base64-urlsafe (format Fernet).

    Pas de cache — l'opération coûte ~150 ms mais est appelée 1x par
    process via :func:`_get_multifernet` (mémoïsé).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    derived = kdf.derive(raw_key.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _derive_legacy_key(raw_key: str) -> bytes:
    """SHA-256 brut → 32 octets base64 (format historique Komptia).

    Conservé en LECTURE pour décrypter les passwords stockés avant la
    migration PBKDF2. **Ne jamais** utiliser pour encrypt — le
    MultiFernet primary l'écrase à la première update.
    """
    digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


# Cache mémoïsé du MultiFernet (process-level). Recyclage explicite via
# :func:`reset_crypto_cache` (utile pour les tests qui patchent
# l'environnement).
_cached_multifernet: Optional[MultiFernet] = None


def build_multifernet(raw_key: str) -> MultiFernet:
    """Construit un MultiFernet ``[primary PBKDF2(raw_key, salt), legacy
    SHA-256(raw_key)]`` — API PUBLIQUE partagée (SSoT crypto). Le caller gère
    son propre cache (la dérivation PBKDF2 coûte ~150ms). Utilisé par
    :func:`_get_multifernet` (mot de passe SQL Server) ET par ``config_service``
    (clé API LLM) — pas de duplication de la composition primary+legacy ni
    d'import de symboles privés cross-module.

    Ordre : primary EN PREMIER → encryption avec primary, decryption essaie
    primary puis legacy (cf. doc cryptography.fernet.MultiFernet).
    """
    salt = _load_or_create_salt()
    primary = Fernet(_derive_primary_key(raw_key, salt))
    legacy = Fernet(_derive_legacy_key(raw_key))
    return MultiFernet([primary, legacy])


def _get_multifernet() -> MultiFernet:
    """Construit (ou retourne le cache du) MultiFernet primary+legacy."""
    global _cached_multifernet
    if _cached_multifernet is not None:
        return _cached_multifernet

    raw_key = os.getenv("FERNET_KEY") or config.security.secret_key
    _cached_multifernet = build_multifernet(raw_key)
    return _cached_multifernet


def _get_fernet() -> MultiFernet:
    """Compat : alias historique. ``MultiFernet`` est duck-typé Fernet.

    Conservé pour les tests qui importent ``_get_fernet`` directement.
    Le ``MultiFernet`` expose ``.encrypt()`` et ``.decrypt()`` avec la
    même signature que ``Fernet`` — tests round-trip passent.
    """
    return _get_multifernet()


def reset_crypto_cache() -> None:
    """Vide le cache MultiFernet (pour les tests qui patchent l'env)."""
    global _cached_multifernet
    _cached_multifernet = None


def encrypt_password(plain_password: str) -> str:
    """Chiffre un mot de passe via la primary key (PBKDF2)."""
    f = _get_multifernet()
    return f.encrypt(plain_password.encode("utf-8")).decode("utf-8")


def decrypt_password(encrypted_password: str) -> str:
    """Déchiffre un mot de passe (primary puis legacy via MultiFernet).

    Lève ``ValueError`` (message neutre, FR) si aucune clé ne décrypte —
    le message ne révèle pas la cause précise pour ne pas faciliter
    une attaque par oracle.
    """
    try:
        f = _get_multifernet()
        return f.decrypt(encrypted_password.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError(
            "Impossible de déchiffrer le mot de passe. Recréez la connexion "
            "avec le mot de passe original."
        ) from exc


# --- ODBC connection-string helpers --------------------------------------


def _sanitize_conn_value(value: str) -> str:
    """Échappe une valeur arbitraire pour l'inclusion dans une conn-string ODBC.

    Stratégie défensive : on encadre TOUJOURS de ``{}`` et on double les
    ``}`` internes (spec Microsoft ODBC). Aucun caractère de contrôle
    (CRLF, NUL) n'est laissé passer — protection contre l'injection
    de paramètres ODBC supplémentaires (CWE-91).
    """
    text = str(value)
    if "\x00" in text or "\r" in text or "\n" in text:
        raise ValueError("Caractère de contrôle interdit dans les paramètres de connexion.")
    return "{" + text.replace("}", "}}") + "}"


# --- Lectures ------------------------------------------------------------


async def list_connections() -> list[dict[str, Any]]:
    """Liste toutes les configurations de connexion (sans mot de passe)."""
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection).order_by(DatabaseConnection.created_at.desc())
        )
        connections = result.scalars().all()
        return [conn.to_dict() for conn in connections]


async def get_connection(conn_id: int) -> Optional[DatabaseConnection]:
    """Récupère une configuration par ID (detached from session)."""
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
        )
        conn = result.scalar_one_or_none()
        if conn is not None:
            session.expunge(conn)
        return conn


def _active_connection_order_by() -> tuple:
    """Clause d'ordre SSoT pour désigner LA connexion active gagnante.

    Utilisée par ``get_active_connection`` ET
    ``get_sql_server_version_label_sync`` : les deux lecteurs DOIVENT
    désigner la même ligne quand l'invariant « une seule active » est
    cassé, sinon split-brain silencieux (SQL exécuté sur la connexion A
    avec les garde-fous compat-level de la connexion B).
    Règle : dernière activée explicitement d'abord (une ligne jamais
    passée par ``activate_connection`` a ``last_activated_at`` NULL et ne
    gagne jamais contre une ligne activée), départage par id croissant.
    """
    return (
        DatabaseConnection.last_activated_at.desc().nullslast(),
        DatabaseConnection.id.asc(),
    )


async def get_active_connection() -> Optional[DatabaseConnection]:
    """Récupère la connexion active (detached from session).

    Robuste à un invariant cassé : si PLUSIEURS lignes sont ``is_active``
    (insertion hors-service — script, sqlite manuel, restore — l'app n'en
    produit jamais deux via ``activate_connection`` qui est atomique), on
    NE lève PAS ``MultipleResultsFound``. Incident 2026-06-12 : cette
    exception remontait dans le ``except Exception`` fail-closed de
    ``init_sage_from_db_config`` → ``mark_unconfigured()`` → message
    « Aucune connexion configurée » MENSONGER (le vrai problème était
    l'inverse : deux actives) et SQL refusé à tort sur toute l'app.
    À la place : gagnante DÉTERMINISTE = dernière activée explicitement
    (``last_activated_at`` DESC, NULLS LAST — une ligne jamais passée par
    ``activate_connection`` ne gagne jamais contre une ligne activée),
    départage par id. + log ERROR actionnable : réactiver la bonne
    connexion via /admin/database répare les lignes (UPDATE exclusif).
    """
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection)
            .where(DatabaseConnection.is_active.is_(True))
            .order_by(*_active_connection_order_by())
        )
        rows = list(result.scalars().all())
        if len(rows) > 1:
            logger.error(
                "Invariant cassé : %d connexions actives simultanément (%s). "
                "Gagnante déterministe : « %s » (dernière activée). Réactivez "
                "la connexion voulue via /admin/database pour réparer.",
                len(rows),
                ", ".join(f"#{c.id} {c.name}" for c in rows),
                rows[0].name,
            )
        conn = rows[0] if rows else None
        if conn is not None:
            session.expunge(conn)
        return conn


# --- Version SQL Server (BDD = Single Source of Truth) -----------------
#
# Mystère B (2026-05-26) : il y avait un ``_cached_version_label`` module-
# level qui mémorisait la valeur entre les calls. Le cache était vide au
# boot du process et seulement peuplé quand un ``schema_sync`` ou
# ``activate_connection`` tournait. Symptôme : après chaque restart
# serveur (avant le 1er sync), tous les garde-fous compat-level
# downstream (``deja_vu_prefetch._resolve_active_compat_level``,
# ``copilot_agent``, prompts ``{sql_server_version}``) tombaient sur le
# fallback ``"SQL Server"`` sans année — fail-open silencieux.
#
# Le fix : **la BDD est la seule source de vérité**.
# * ``database_connections.server_version`` (colonne ``TEXT``) est écrite
#   par ``schema_sync._detect_and_store_server_version`` à chaque sync.
# * ``get_sql_server_version_label()`` async ET
#   ``get_sql_server_version_label_sync()`` lisent la BDD à chaque appel.
# * ``invalidate_version_cache(...)`` est conservée comme no-op pour la
#   rétro-compat des callers existants — annotée ``deprecated``. Aucune
#   logique nouvelle ne devrait l'appeler.
#
# Performances : la lecture est un SELECT mono-ligne sur une colonne
# courte d'une table de < 10 lignes (indexée implicitement par
# ``is_active``). < 1 ms en cold cache, sub-ms en warm cache SQLite.
# Volume d'appels typique : 3-5 par requête utilisateur → impact total
# négligeable. Pas de micro-cache nécessaire.

# Lazy-init du sync engine pour ne pas créer d'engine au boot du module
# (économie de ressources si le code n'est jamais appelé en sync).
_sync_engine_holder: Optional[Any] = None


def _get_sync_engine():
    """Retourne le sync SQLAlchemy engine, lazy-init au premier appel.

    Wire le hook ``setup_encryption`` pour supporter les BDD chiffrées
    SQLCipher (sinon le 1er SELECT échoue avec "file is not a database"
    quand ``SQLCIPHER_KEY`` est configuré). Aucun PRAGMA d'optimisation
    additionnel : ce sync engine ne sert qu'à des lectures ponctuelles
    de ``database_connections``, pas à des workloads.
    """
    global _sync_engine_holder
    if _sync_engine_holder is None:
        from app.core.database import make_sync_engine

        # SSoT : make_sync_engine pose PRAGMA key (SQLCipher) + PRAGMAs perf sur
        # chaque connexion. Sans clé → no-op (base claire).
        _sync_engine_holder = make_sync_engine()
    return _sync_engine_holder


def parse_sql_server_version_label(raw_version: str) -> str:
    """Extrait un label court depuis le résultat brut de ``@@VERSION``.

    Exemples :
        "Microsoft SQL Server 2016 (SP3) - 13.0.6300.2 ..." → "SQL Server 2016"
        "Microsoft SQL Server 2019 (RTM-CU18) ..."          → "SQL Server 2019"
    """
    match = re.search(r"Microsoft SQL Server (\d{4})", raw_version)
    if match:
        return f"SQL Server {match.group(1)}"
    return "SQL Server"


def parse_compat_level_from_label(label: Optional[str]) -> Optional[int]:
    """Inverse de :func:`build_server_version_label` — extrait le
    compatibility_level numérique d'un label stocké.

    Gère les deux formes :
    * ``"SQL Server 2019 (compatibilité 130 = syntaxe SQL Server 2016)"``
      → 130 (compat explicite domine).
    * ``"SQL Server 2014"`` (sans parens) → 120 (compat = version moteur).
    * ``"SQL Server"`` (générique fallback) ou None → None.

    Sert au feature #7 (auto-refactor SQL) pour calculer le delta de
    capabilities entre l'ancien et le nouveau label au moment d'un sync.
    """
    if not label:
        return None
    # Cas 1 : mention explicite ``compatibilité NNN`` (FR ou ``compatibility level NNN`` EN).
    m = re.search(r"\bcompatibilit[éey]+\s*(?:level\s+)?(\d{2,3})", label, re.IGNORECASE)
    if m:
        try:
            return int(m.group(1))
        except ValueError:  # pragma: no cover — regex garantit \d
            return None
    # Cas 2 : label sans suffix compat → compat = version moteur.
    year_m = re.search(r"SQL Server\s+(\d{4})", label, re.IGNORECASE)
    if year_m:
        return _VERSION_TO_COMPAT_LEVEL.get(year_m.group(1))
    return None


def compute_capability_delta(old_label: Optional[str], new_label: Optional[str]) -> Dict[str, Any]:
    """Compute le delta de capabilities SQL Server entre 2 labels.

    Utilisé par ``schema_sync._detect_and_store_server_version`` (au
    moment d'un sync) pour décider si certaines paires Q/SQL stockées
    doivent être réécrites par le LLM (feature #7).

    Args:
        old_label: Label avant le sync (``database_connections.server_version``
            actuel). ``None`` = pas de sync précédent connu → pas de
            delta calculable, retourne broken_capabilities vide.
        new_label: Label après le sync (calculé via
            :func:`build_server_version_label` sur les valeurs live).

    Returns:
        Dict avec :

        * ``old_label`` (str|None), ``new_label`` (str|None)
        * ``old_compat`` (int|None), ``new_compat`` (int|None)
        * ``version_changed`` (bool) : True si labels différents
        * ``compat_changed`` (bool) : True si compat_level différent
        * ``downgrade`` (bool) : True si nouveau compat < ancien compat
        * ``broken_capabilities`` (list[str]) : capabilities qui marchaient
          dans l'ancien compat mais pas dans le nouveau. Vide si pas de
          downgrade ou pas de capability impactée.
        * ``new_capabilities`` (list[str]) : capabilities qui marchent dans
          le nouveau mais pas dans l'ancien (upgrade). Informatif — pas
          d'action automatique (les paires existantes restent valides).
    """
    old_compat = parse_compat_level_from_label(old_label)
    new_compat = parse_compat_level_from_label(new_label)

    delta: Dict[str, Any] = {
        "old_label": old_label,
        "new_label": new_label,
        "old_compat": old_compat,
        "new_compat": new_compat,
        "version_changed": old_label != new_label,
        "compat_changed": old_compat != new_compat,
        "downgrade": False,
        "broken_capabilities": [],
        "new_capabilities": [],
    }

    # Si on n'a pas les deux compat, pas de calcul de delta capability fiable.
    if old_compat is None or new_compat is None:
        return delta

    delta["downgrade"] = new_compat < old_compat
    upgrade = new_compat > old_compat

    if delta["downgrade"]:
        # Capability cassée : était dispo dans old_compat mais plus dans new_compat.
        delta["broken_capabilities"] = sorted(
            [
                cap
                for cap, min_required in _CAPABILITY_MIN_COMPAT.items()
                if old_compat >= min_required and new_compat < min_required
            ]
        )
    elif upgrade:
        # Nouvelle capability dispo (informatif, pas d'action automatique).
        delta["new_capabilities"] = sorted(
            [
                cap
                for cap, min_required in _CAPABILITY_MIN_COMPAT.items()
                if old_compat < min_required and new_compat >= min_required
            ]
        )

    return delta


def build_server_version_label(raw_version: str, compat_level: Optional[int] = None) -> str:
    """Construit le label complet pour les prompts LLM (version + compat)."""
    base = parse_sql_server_version_label(raw_version)

    if compat_level is None:
        return base

    compat_version = _COMPAT_LEVEL_TO_VERSION.get(compat_level)
    if compat_version is None:
        return base

    if base == f"SQL Server {compat_version}":
        return base

    return f"{base} (compatibilité {compat_level} = syntaxe SQL Server {compat_version})"


async def get_sql_server_version_label() -> str:
    """Lit le label de version SQL Server depuis la BDD (async, SSoT).

    La valeur vient de ``database_connections.server_version`` (écrit par
    ``schema_sync._detect_and_store_server_version`` à chaque sync). Pas
    de cache module-level : ce serait fragile (vidé au restart process,
    invalidé à chaque mutation, désynchronisable). La BDD locale est
    suffisamment rapide pour une lecture par appel (< 1 ms typique).

    Fallback ``"SQL Server"`` (sans année) si la BDD est indisponible ou
    si aucune connexion active n'a encore de ``server_version`` rempli
    (= 1er boot avant le 1er sync). Ce fallback est sûr : il signale
    aux garde-fous downstream qu'il n'y a pas d'info fiable, et ils
    doivent se rabattre sur leur logique safe (ex: STRING_AGG WITHIN GROUP
    guard fail-CLOSED quand compat unknown).
    """
    try:
        active = await get_active_connection()
        if active and active.server_version:
            return active.server_version
    except SQLAlchemyError:
        logger.warning("Lecture async connexion active impossible, fallback label générique")
    return "SQL Server"


def get_sql_server_version_label_sync() -> str:
    """Lit le label depuis la BDD synchrone (SSoT, sans cache mémoire).

    Utilisé par les call-sites qui n'ont pas d'event loop (formatage de
    prompt dans ``agent_roles``, ``copilot_agent``, ``iris_oneshot``,
    ``deja_vu_prefetch._resolve_active_compat_level``,
    ``result_assistant``). Le sync engine est lazy-init avec hook
    SQLCipher pour supporter les BDD chiffrées.

    Fallback ``"SQL Server"`` (sans année) :
    * BDD indisponible (process tué pendant une lecture, fichier corrompu)
    * Pas de connexion active configurée
    * Connexion active sans ``server_version`` (sync jamais joué)

    Ce fallback est sûr — voir docstring de ``get_sql_server_version_label``
    (async) pour le contrat fail-closed downstream.
    """
    try:
        from sqlalchemy import select as _select

        engine = _get_sync_engine()
        with engine.connect() as conn:
            # MÊME clause d'ordre que get_active_connection (SSoT) : si
            # l'invariant « une seule active » est cassé, ce lecteur doit
            # désigner la MÊME gagnante que le connecteur — sinon le label
            # de version/compat-level viendrait d'une autre BDD que celle
            # réellement exécutée (mismatch de dialecte silencieux).
            row = conn.execute(
                _select(DatabaseConnection.server_version)
                .where(DatabaseConnection.is_active.is_(True))
                .order_by(*_active_connection_order_by())
            ).first()
            if row and row[0]:
                return row[0]
    except SQLAlchemyError as exc:
        logger.warning(
            "Lecture sync connexion active impossible (%s), fallback label générique",
            type(exc).__name__,
        )
    except Exception as exc:  # noqa: BLE001 — file missing, FS issue, etc.
        logger.warning(
            "Lecture sync version SQL Server échouée (%s), fallback label générique",
            type(exc).__name__,
        )
    return "SQL Server"


def invalidate_version_cache(new_label: Optional[str] = None) -> None:
    """No-op rétro-compatible. **Le cache mémoire a été supprimé** (Mystère B
    2026-05-26) : la BDD ``database_connections.server_version`` est la
    seule source de vérité, lue à chaque appel par
    ``get_sql_server_version_label[_sync]()``.

    Cette fonction est conservée pour ne pas casser les call-sites existants
    (handlers, sync, helpers d'activation) qui l'appelaient pour signaler
    un changement de label. La nouvelle architecture n'a plus besoin de
    cette invalidation explicite — l'écriture en BDD est immédiatement
    visible au prochain getter.

    Args:
        new_label: Ignoré (préservé pour la signature historique).

    .. deprecated:: post-mystère-B-2026-05-26
        À supprimer dans une future passe de nettoyage une fois que tous
        les call-sites auront été enlevés.
    """
    # Volontairement no-op. Le call-site historique est conservé sans
    # effet de bord pour la transition.
    return None


# --- Mutations -----------------------------------------------------------


async def create_connection(
    name: str,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    timeout: int = 30,
    max_rows: int = 1000,
    created_by: Optional[int] = None,
) -> DatabaseConnection:
    """Crée une nouvelle configuration de connexion.

    Lève :class:`DuplicateConnectionError` si le nom existe déjà
    (catché via ``IntegrityError`` SQLAlchemy — pas de TOCTOU).
    """
    encrypted = encrypt_password(password)

    async with get_session() as session:
        conn = DatabaseConnection(
            name=name,
            db_type=DatabaseType.SQLSERVER,
            host=host,
            port=port,
            database=database,
            username=username,
            encrypted_password=encrypted,
            timeout=timeout,
            max_rows=max_rows,
            is_active=False,
            created_by=created_by,
            updated_by=created_by,
        )
        session.add(conn)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise DuplicateConnectionError(f"Une connexion nommée '{name}' existe déjà.") from exc
        await session.refresh(conn)

        logger.info(
            "Connexion BDD créée: %s (%s:%s/%s)",
            name,
            host,
            port,
            database,
            extra={"connection_id": conn.id, "created_by": created_by},
        )
        return conn


async def update_connection(
    conn_id: int,
    name: Optional[str] = None,
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: Optional[int] = None,
    max_rows: Optional[int] = None,
    updated_by: Optional[int] = None,
) -> Optional[DatabaseConnection]:
    """Met à jour une configuration existante.

    Retourne ``None`` si l'ID est introuvable. Lève
    :class:`DuplicateConnectionError` (409) sur collision de nom.
    """
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
        )
        conn = result.scalar_one_or_none()
        if not conn:
            return None

        # Détecter un changement de CIBLE avant d'écraser les valeurs : la
        # version SQL Server dépend du serveur (host + port). Si host/port
        # change, la connexion peut pointer vers un autre serveur/instance →
        # la version détectée (``server_version``) devient potentiellement
        # périmée et ne doit plus être injectée dans les prompts LLM. On inclut
        # ``database`` par prudence (reset = re-détection sûre, jamais une
        # fausse version).
        host_changed = host is not None and host != conn.host
        port_changed = port is not None and port != conn.port
        db_changed = database is not None and database != conn.database
        username_changed = username is not None and username != conn.username
        # Un password fourni (non-None) = intention de le changer : le handler
        # ne l'inclut dans le payload que si l'admin a saisi une valeur
        # (``_coerce_password(required=False)``). On ne peut pas comparer le
        # clair à l'``encrypted_password`` sans déchiffrer → reset prudent.
        password_provided = password is not None

        if name is not None:
            conn.name = name
        if host is not None:
            conn.host = host
        if port is not None:
            conn.port = port
        if database is not None:
            conn.database = database
        if username is not None:
            conn.username = username
        if password is not None:
            conn.encrypted_password = encrypt_password(password)
        if timeout is not None:
            conn.timeout = timeout
        if max_rows is not None:
            conn.max_rows = max_rows
        if updated_by is not None:
            conn.updated_by = updated_by

        if host_changed or port_changed or db_changed:
            # Reset → les getters (``get_sql_server_version_label[_sync]``)
            # tombent sur le fallback sûr "SQL Server" au lieu d'une fausse
            # année, jusqu'au prochain ``schema_sync`` qui re-détecte la vraie
            # version du nouveau serveur cible.
            conn.server_version = None

        # B3-F2 (données fausses) : ``last_test_success`` / ``last_test_message``
        # / ``last_tested_at`` reflètent un test de connexion avec les paramètres
        # EXACTS d'avant. Tout changement d'identité de connexion (host, port,
        # database, username, password) périme ce résultat — sans ce reset, la
        # liste ``/admin/database`` afficherait « ✓ testé OK » sur une cible
        # jamais testée, induisant l'admin à activer une connexion non vérifiée.
        # (``timeout`` / ``max_rows`` / ``name`` ne changent pas la joignabilité,
        # donc ne périment pas le test.)
        if host_changed or port_changed or db_changed or username_changed or password_provided:
            conn.last_test_success = None
            conn.last_test_message = None
            conn.last_tested_at = None

        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise DuplicateConnectionError("Une connexion avec ce nom existe déjà.") from exc
        await session.refresh(conn)

        # Note (Mystère B 2026-05-26) : avant on appelait
        # ``invalidate_version_cache()`` ici quand l'utilisateur changeait
        # la connexion active (host/port/db). Le cache mémoire a été
        # supprimé — la BDD est la SSoT et chaque getter la relit. Plus
        # rien à invalider explicitement.

        logger.info(
            "Connexion BDD mise à jour: %s",
            conn.name,
            extra={"connection_id": conn.id, "updated_by": updated_by},
        )

    # Hors session : si la connexion modifie est ACTIVE, recharger le
    # singleton SageConnector pour que le nouveau ``max_rows`` /
    # ``timeout`` / host / etc. prennent effet IMMEDIATEMENT, sans
    # redmarrage. Sans ce reload, l'admin met 5000 dans le form, voit
    # "OK", mais le runtime continue avec l'ancienne valeur jusqu'au
    # prochain restart -- contrat "source de vrit unique" cass car
    # le runtime est en retard sur la BDD.
    if conn.is_active:
        await _reload_sage_connector(conn)
        logger.info(
            "Singleton Sage recharg post-update : plafond %d lignes",
            conn.max_rows or 1000,
            extra={"connection_id": conn.id},
        )

    return conn


async def delete_connection(conn_id: int) -> bool:
    """Supprime une configuration. Refuse si la connexion est active."""
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
        )
        conn = result.scalar_one_or_none()
        if not conn:
            return False

        if conn.is_active:
            raise ConnectionInUseError(
                "Impossible de supprimer la connexion active. Désactivez-la d'abord."
            )

        name = conn.name
        await session.delete(conn)

        logger.info("Connexion BDD supprimée: %s", name, extra={"connection_id": conn_id})
        return True


async def activate_connection(
    conn_id: int, activated_by: Optional[int] = None
) -> DatabaseConnection:
    """Active une connexion (et désactive toutes les autres) — atomique.

    Un seul ``UPDATE`` ``is_active = (id = :target)`` :
    * AUCUNE fenêtre où zéro connexion serait active (la désactivation
      des autres et l'activation de la cible se font en une transaction).
    * Pas besoin du double SELECT précédent.

    Lève ``ValueError`` si l'ID est introuvable.
    """
    now = clock.now()

    async with get_session() as session:
        # Vérifier l'existence d'abord pour pouvoir lever 404 propre.
        exists = await session.execute(
            select(DatabaseConnection.id).where(DatabaseConnection.id == conn_id)
        )
        if exists.scalar_one_or_none() is None:
            raise ValueError("Connexion introuvable")

        # UPDATE unique : passe is_active=True sur la cible, False ailleurs.
        await session.execute(
            update(DatabaseConnection).values(
                is_active=(DatabaseConnection.id == conn_id),
                last_activated_at=DatabaseConnection.last_activated_at,
            )
        )
        # Set audit fields on the target only.
        await session.execute(
            update(DatabaseConnection)
            .where(DatabaseConnection.id == conn_id)
            .values(last_activated_at=now, last_activated_by=activated_by)
        )
        await session.flush()

        # Re-lire la connexion pour la retourner detached.
        result = await session.execute(
            select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
        )
        conn = result.scalar_one()
        session.expunge(conn)

    # Mystère B 2026-05-26 : avant on appelait
    # ``invalidate_version_cache(new_label=conn.server_version or None)``
    # ici pour peupler le cache mémoire avec la valeur déjà connue. Le
    # cache a été supprimé — la BDD est SSoT. Le sync getter relira
    # automatiquement la nouvelle ``server_version`` de la connexion
    # qu'on vient d'activer.

    logger.info(
        "Connexion BDD activée: %s",
        conn.name,
        extra={"connection_id": conn.id, "activated_by": activated_by},
    )

    # Recharger le connecteur Sage global hors-session (pas de risque
    # de double-réservation de la connexion BDD locale).
    await _reload_sage_connector(conn)

    return conn


async def deactivate_connection(conn_id: int) -> bool:
    """Désactive une connexion BDD.

    Aprs déactivation, AUCUNE connexion n'est active : l'exécution SQL
    sera refusée jusqu'à ce qu'une connexion soit (re)activée via
    /admin/database. Pas de fallback silencieux sur les variables .env
    (cf. doctrine "source de vérité unique" dans sage_connector).
    """
    async with get_session() as session:
        result = await session.execute(
            select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
        )
        conn = result.scalar_one_or_none()
        if not conn:
            return False

        conn.is_active = False
        await session.flush()

    # Mystère B 2026-05-26 : pas d'invalidation cache à faire (cache
    # supprimé). Les prochains getters verront simplement "pas de
    # connexion active" et tomberont sur le fallback ``"SQL Server"``.

    logger.info(
        "Connexion BDD désactivée: %s — exécution SQL désactivée jusqu'à "
        "(ré)activation via /admin/database",
        conn.name,
        extra={"connection_id": conn_id},
    )

    await _reload_sage_connector(None)
    return True


# --- Test de connexion (split en helpers testables) ----------------------


def _get_pyodbc_module() -> Any:
    """Lookup pyodbc dynamiquement (permet aux tests de le patcher via ``sys.modules``)."""
    import sys

    return sys.modules.get("pyodbc", pyodbc)


def _discover_driver() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """[LEGACY] Conserv pour compat tests existants. Le code prod doit
    utiliser :func:`sage_connector.discover_sage_odbc_driver` (UN SEUL
    discovery dans toute l'app, prfre Driver 17 pour compat large).
    Returns (driver_name, encrypt_option, error_message).
    """
    # Réutilise le helper OS-adaptatif de sage_connector (single source of truth
    # pour le conseil d'installation — pas de duplication du « brew vs apt »).
    from app.services.database.sage_connector import driver_install_hint

    pyodbc_mod = _get_pyodbc_module()
    if pyodbc_mod is None:
        return (
            None,
            None,
            "Le module Python pyodbc n'est pas disponible sur le serveur "
            f"applicatif Komptia. {driver_install_hint()}",
        )

    available = pyodbc_mod.drivers()
    if _DRIVER_18 in available:
        return _DRIVER_18, "Optional", None
    if _DRIVER_17 in available:
        return _DRIVER_17, "no", None
    return (
        None,
        None,
        "Aucun driver ODBC SQL Server installé sur le serveur applicatif Komptia. "
        f"{driver_install_hint()}",
    )


def _build_connection_string(
    driver: str,
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    timeout: int,
    encrypt_option: str,
) -> str:
    """[DEPRECATED] Conserv pour compat ascendante des tests existants.

    Le BUILDER REL est :func:`sage_connector.build_sage_connection_string`
    -- une seule source de vrit pour TOUTE l'app (test admin et excution
    Iris/datastore utilisent le mme builder, donc le bouton "Tester" est
    fiable). Ce wrapper ignore les params ``driver`` et ``encrypt_option``
    et dlgue au builder canonique (qui re-discover lui-mme).
    """
    from app.services.database.sage_connector import build_sage_connection_string

    return build_sage_connection_string(
        host=host,
        port=port,
        database=database,
        username=username,
        password=password,
        timeout=timeout,
    )


def _translate_pyodbc_error(raw_msg: str, host: str, port: int, driver: str) -> str:
    """Mappe une erreur pyodbc brute vers un message FR user-friendly."""
    if "Login failed" in raw_msg:
        return "Échec d'authentification : identifiants incorrects."
    if "Cannot open database" in raw_msg:
        return f"Base de données introuvable sur le serveur {host}:{port}."
    if "TCP Provider" in raw_msg or "Named Pipes Provider" in raw_msg:
        return f"Serveur {host}:{port} injoignable — vérifiez l'adresse et le port."
    if "Communication link failure" in raw_msg:
        return f"Serveur {host}:{port} injoignable — échec de communication."
    if "Can't open lib" in raw_msg or "Data source name not found" in raw_msg:
        return f"Driver ODBC {driver} non trouvé sur ce système."
    if "SSL Provider" in raw_msg or "SSL routines" in raw_msg:
        return (
            f"Erreur SSL/TLS — le serveur {host}:{port} ne supporte pas le protocole "
            f"TLS requis par {driver}."
        )
    if "Timeout expired" in raw_msg or "timeout" in raw_msg.lower():
        return f"Timeout — le serveur {host}:{port} ne répond pas dans le délai imparti."
    return f"Échec de connexion au serveur {host}:{port}. " "Vérifiez les paramètres de connexion."


def _run_test_query_LEGACY_DEAD_CODE(connection_string: str, timeout: int) -> int:
    """[DEAD CODE] Plus appel depuis avril 2026. Conserv temporairement
    pour viter de casser un import imprvu -- supprimer au prochain
    refactor. Le test de connexion utilise dsormais ``SageConnector``
    phmre (mme code path qu'Iris/datastore).
    """
    pyodbc_mod = _get_pyodbc_module()
    if pyodbc_mod is None:
        raise RuntimeError("pyodbc indisponible")

    conn = pyodbc_mod.connect(connection_string, timeout=timeout, autocommit=True)
    try:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT 1")
            cursor.execute(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES " "WHERE TABLE_TYPE = 'BASE TABLE'"
            )
            row = cursor.fetchone()
            return int(row[0]) if row else 0
        finally:
            cursor.close()
    finally:
        conn.close()


async def test_connection(
    host: str,
    port: int,
    database: str,
    username: str,
    password: str,
    timeout: int = _DEFAULT_TEST_TIMEOUT_S,
    conn_id: Optional[int] = None,
    enforce_ssrf_guard: bool = True,
) -> dict[str, Any]:
    """Teste une connexion en utilisant EXACTEMENT la mme mthode que
    le runtime (Iris/datastore).

    UN SEUL CHEMIN DE CODE : on cre une instance phmre de
    ``SageConnector`` avec les params voulus et on appelle ses propres
    ``connect()`` + ``execute()``. Ce sont les MMES mthodes qui tournent
    en production. Si le test passe, le runtime passera ; si le test
    choue, le runtime aurait chou avec le mme message ODBC.

    Plus de duplication ``pyodbc.connect()`` / ``_run_test_query`` /
    ``_build_connection_string`` / ``_discover_driver`` locale au service
    -- tout passe par ``SageConnector``.

    Si ``conn_id`` est fourni, persiste le résultat dans la BDD.
    Si ``enforce_ssrf_guard`` est True (dfaut, mais le handler admin
    le passe  False), refuse les hosts privs/rservs. Le SSRF guard
    n'est pas appliqu par ``SageConnector`` lui-mme -- il reste utile
    pour les endpoints externes (webhooks) o un user non-admin
    contrle le host.
    """
    from app.services.database.sage_connector import (
        SageConnector,
        SageConnectionError as _SageConnError,
    )

    timeout = max(1, min(int(timeout), _MAX_TEST_TIMEOUT_S))

    # SSRF guard — pour les call-sites externes (non-admin). Le handler
    # /admin/database passe ``False`` car la BDD source est par
    # construction sur le reseau interne du client.
    # Par dfaut on connecte avec le host fourni. Quand le SSRF guard est
    # actif (call-sites externes / host user-controlled), on PIN l'IP
    # publique rsolue par ``assert_safe_host`` et on la passe au driver --
    # sinon DNS rebinding : le host re-rsout (TTL=0) vers une IP diffrente
    # entre le check et le connect, ce qui bypasse le garde (cf.
    # ``resolve_host_safely`` qui documente « l'appelant doit utiliser cette
    # IP, pas le hostname »). Pin sr ici : ``TrustServerCertificate`` dfaut
    # 'yes' (sage_connector) -> le driver ne valide pas le hostname du
    # certificat, donc connecter par IP ne casse pas TLS. Si un dploiement
    # impose TrustServerCertificate=no AVEC un caller externe, ce pin
    # privilgie la protection SSRF (host non fiable) sur la vrif de nom.
    connect_host = host
    if enforce_ssrf_guard:
        try:
            connect_host = assert_safe_host(host, port)
        except UnsafeHostError as exc:
            result = {"success": False, "message": str(exc), "tables_count": 0}
            if conn_id:
                await _save_test_result(conn_id, result)
            return result

    # Une instance phmre, totalement isole du singleton runtime
    # (``_is_singleton=False`` -> guard ``[CONFIG_MANQUANTE]`` n'est
    # pas appliqu, et close() ne touche pas au singleton).
    test_connector = SageConnector(
        host=connect_host,
        port=port,
        database=database,
        username=username,
        password=password,
        timeout=timeout,
    )

    result: dict[str, Any]
    try:
        # connect() = exactement le mme code path que Iris.
        # Si a passe ici, a passera en production.
        await test_connector.connect()

        # Preuve fonctionnelle : on compte les tables BASE TABLE
        # comme avant. ``bypass_admin_cap=True`` car c'est un check
        # admin-internal (pas une query user-visible) et ``max_rows=1``
        # car on attend une seule row de COUNT.
        count_result = await test_connector.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES " "WHERE TABLE_TYPE = 'BASE TABLE'",
            max_rows=1,
            bypass_admin_cap=True,
        )
        tables_count = (
            int(count_result.rows[0][0]) if count_result.rows and count_result.rows[0] else 0
        )
        result = {
            "success": True,
            "message": f"Connexion russie  {tables_count} tables dtectes.",
            "tables_count": tables_count,
        }
    except _SageConnError as exc:
        # Mme classe d'erreur que le runtime -- mme message remontant.
        # Pas de divergence possible entre ce que voit l'admin (test) et
        # ce que verrait Iris (runtime).
        logger.warning(
            "Test connexion chou",
            extra={"host": host, "port": port, "exc_type": type(exc).__name__},
        )
        result = {"success": False, "message": str(exc), "tables_count": 0}
    except Exception as exc:  # noqa: BLE001 -- safety net last resort
        # Cas exotique non typ par SageConnector (driver natif qui
        # lve un OSError, etc.). On sanitize pour ne pas leaker la
        # stack ODBC brute  l'utilisateur.
        logger.error(
            "Erreur inattendue test connexion",
            exc_info=True,
            extra={"host": host, "port": port, "exc_type": type(exc).__name__},
        )
        result = {
            "success": False,
            "message": f"chec de connexion au serveur {host}:{port}.",
            "tables_count": 0,
        }
    finally:
        # Toujours fermer la connexion phmre (vite le leak de
        # connexions ODBC ouvertes ct serveur Sage).
        try:
            await test_connector.close()
        except Exception:  # noqa: BLE001 -- close best-effort
            pass

    if conn_id:
        await _save_test_result(conn_id, result)

    return result


async def _save_test_result(conn_id: int, result: dict[str, Any]) -> None:
    """Persiste le résultat d'un test (last_tested_at + status + message)."""
    try:
        async with get_session() as session:
            db_conn = await session.execute(
                select(DatabaseConnection).where(DatabaseConnection.id == conn_id)
            )
            conn = db_conn.scalar_one_or_none()
            if conn:
                conn.last_tested_at = clock.now()
                conn.last_test_success = bool(result.get("success", False))
                conn.last_test_message = str(result.get("message", ""))[:500]
                await session.flush()
    except (SQLAlchemyError, OperationalError):
        # Persistance best-effort — un échec de log ne doit pas masquer
        # le résultat du test que l'utilisateur attend.
        logger.warning("Impossible de persister le résultat du test", exc_info=True)


# --- Wiring sage_connector -----------------------------------------------


async def _reload_sage_connector(db_conn: Optional[DatabaseConnection]) -> None:
    """Recharge le connecteur Sage global avec la nouvelle config.

    Si ``db_conn`` est ``None`` (déactivation, ou aucune config active),
    on marque le connecteur comme NON configuré -- l'exécution SQL
    refusera tout call jusqu'à activation d'une connexion via
    /admin/database. AUCUN fallback sur ``.env`` : la page admin est
    l'unique source de vérité.
    """
    from app.services.database.sage_connector import (
        _reset_sage_connector,
        close_sage_connector,
        mark_unconfigured,
    )

    await close_sage_connector()

    if db_conn is None:
        mark_unconfigured()
        return

    try:
        password = decrypt_password(db_conn.encrypted_password)
    except ValueError:
        logger.error(
            "Impossible de déchiffrer le mot de passe pour rechargement Sage. "
            "Connecteur marqu non configur -- l'admin doit ré-éditer/recréer "
            "la connexion via /admin/database.",
            extra={"connection_id": db_conn.id},
        )
        # Pas de fallback .env : on fail-closed pour ne pas laisser
        # tourner une connexion non maîtrisée par l'admin.
        mark_unconfigured()
        return

    # ``db_conn.max_rows or 1000`` : si la BDD a une valeur NULL pour une
    # raison X (legacy, migration, INSERT raw), on force un default 1000
    # explicite -- on NE doit PAS retomber sur ``config.sage.max_rows``
    # (env), sinon le contrat "DBConfig = unique source de vrit" est
    # cass silencieusement. Le default 1000 est cohrent avec la BDD
    # (default SQLAlchemy + form admin).
    effective_max_rows = db_conn.max_rows or 1000
    effective_timeout = db_conn.timeout or 30
    _reset_sage_connector(
        host=db_conn.host,
        port=db_conn.port,
        database=db_conn.database,
        username=db_conn.username,
        password=password,
        timeout=effective_timeout,
        max_rows=effective_max_rows,
    )
    logger.info(
        "Connecteur Sage rechargé avec config GUI: %s (plafond %d lignes)",
        db_conn.name,
        effective_max_rows,
        extra={"connection_id": db_conn.id},
    )


__all__ = [
    "ConnectionInUseError",
    "DuplicateConnectionError",
    "PYODBC_AVAILABLE",
    "activate_connection",
    "build_server_version_label",
    "compute_capability_delta",
    "create_connection",
    "deactivate_connection",
    "decrypt_password",
    "delete_connection",
    "encrypt_password",
    "get_active_connection",
    "get_connection",
    "get_sql_server_version_label",
    "get_sql_server_version_label_sync",
    "invalidate_version_cache",
    "list_connections",
    "parse_compat_level_from_label",
    "parse_sql_server_version_label",
    "reset_crypto_cache",
    "test_connection",
    "update_connection",
]
