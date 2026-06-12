"""Connexion SQLAlchemy 2.0 asynchrone à la base SQLite locale.

Responsabilités de ce module :

* Construire les URL de connexion (``get_database_url`` async via ``aiosqlite``
  et ``get_db_url`` synchrone pour APScheduler).
* Initialiser l'engine et la factory de sessions (``init_database``) une seule
  fois par processus (pool borné + verrou ``asyncio`` pour garantir
  l'idempotence même sous appels concurrents).
* Brancher les *connection hooks* dans le bon ordre : chiffrement SQLCipher →
  chargement optionnel de ``sqlite-vec`` → PRAGMA WAL/foreign_keys/cache/
  busy_timeout. L'ordre est **critique** : le PRAGMA key doit être posé avant
  toute autre requête, sinon la base chiffrée apparaît comme "fichier invalide".
* Exécuter les migrations incrémentales idempotentes (ajouts de colonnes /
  index) via introspection ``PRAGMA table_info`` — aucune dépendance au texte
  des messages d'erreur SQLite, dont le libellé varie selon la version.
* Fournir ``get_session`` (async context manager avec commit/rollback
  automatique) et ``execute_raw`` (helper ponctuel, voir son avertissement).

Conventions :
    - Aucun side-effect à l'import — toute ouverture de connexion passe par
      ``init_database`` (vérifié par ``tests/unit/test_app_core_init.py``).
    - Aucun nom de BDD source ni nom d'organisation cliente dans ce
      module — Komptia doit tourner sur n'importe quelle installation.
"""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
import sys
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Final, Mapping, Sequence

from sqlalchemy import Engine, Row, create_engine, event, text
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import AsyncAdaptedQueuePool

from app.config import config
from app.utils.json_safe import dumps_safe
from app.utils.logger import get_logger

logger = get_logger(__name__)


class Base(DeclarativeBase):
    """Classe de base déclarative pour tous les modèles SQLAlchemy."""


# --- Constantes techniques du module -------------------------------------
# Valeurs invariantes liées à SQLite/SQLCipher. Ne pas rendre configurables :
# ce sont des choix de fiabilité/compatibilité du driver, pas des paramètres
# de déploiement (voir `app/config.py` pour la config par installation).

# Cache SQLite en KiB (valeur négative = KiB selon la spec PRAGMA cache_size).
_CACHE_SIZE_KIB: Final[int] = 16_000  # 16 MiB en mémoire par connexion

# Durée d'attente sur verrou d'écriture (ms). Les sauvegardes de tours de
# conversation exécutent plusieurs flushes dans une même transaction et
# peuvent conserver le write lock plusieurs secondes sur disque chargé.
_BUSY_TIMEOUT_MS: Final[int] = 30_000

# mmap_size : surface mémoire mappée par connexion. Avec ``NullPool`` chaque
# session ouvre une connexion, donc cette valeur n'est PAS multipliée par
# le nombre de coroutines actives — c'est un cap par-conn que l'OS gère
# en demand-paging (pages physiques allouées paresseusement). Sur Komptia
# avec une BDD locale de 15 GB et une recherche RAG intensive (29 M lignes
# value_mapping + FTS5 trigram), 1 GiB de mmap réduit drastiquement les
# round-trips disque pour les SELECT random-access. ``0`` (défaut SQLite)
# = pas de mmap → chaque SELECT relit le disque → contention I/O ajoute
# de la latence aux writes qui prennent le verrou exclusive.
#
# SQLCipher compat : sur les versions compilées sans
# ``SQLITE_ENABLE_MEMORY_MANAGEMENT``, PRAGMA mmap_size est silencieusement
# no-op (pas une erreur). Inoffensif si la version embarquée ne le
# supporte pas. Pour désactiver explicitement : mettre à 0.
_MMAP_SIZE_BYTES: Final[int] = 1_073_741_824  # 1 GiB

# wal_autocheckpoint : nombre de pages WAL avant déclenchement automatique
# du checkpoint. Défaut SQLite = 1000 pages (~4 MiB sur page_size=4096).
# Sur une instance active (Iris + automations + sync schéma concurrents)
# le WAL atteint vite 89 MB observé en prod 2026-05-20 — un reader long
# (SSE long-poll, sync 14 s, etc.) bloque le truncate au checkpoint et le
# WAL grossit en attendant. Passer à 5000 pages (~20 MiB) réduit la
# fréquence des checkpoints synchrones (qui sont des writes courts mais
# contribuent à la contention) tout en bornant le WAL à un palier
# acceptable pour le crash recovery. Le cron quotidien
# ``cleanup_db_retention_job`` exécute aussi un ``wal_checkpoint(TRUNCATE)``
# pour rapatrier la taille fichier après les pics.
_WAL_AUTOCHECKPOINT_PAGES: Final[int] = 5000

# ID négatif improbable utilisé pour la sonde de dimensions des tables
# vectorielles — aucune donnée réelle n'utilise d'ID négatif.
_DIM_PROBE_ID: Final[int] = -999

# Tables virtuelles sqlite-vec utilisées par la recherche RAG. Les noms sont
# gelés par l'application (pas d'entrée utilisateur) — leur présence ici est
# volontaire pour autoriser l'introspection et la migration automatique.
_VEC_TABLE_NAMES: Final[tuple[str, ...]] = (
    "vec_ddl",
    "vec_documentation",
    "vec_question_sql",
)

# Identifiants SQLite valides pour les noms de tables (défense en profondeur
# contre une évolution future du module qui injecterait des noms dynamiques).
_SQLITE_IDENT_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Messages d'erreur SQLite indiquant que l'extension ``vec0`` n'est pas chargée.
# Conservés en minuscules pour comparaison insensible à la casse.
_VEC_MISSING_MARKERS: Final[tuple[str, ...]] = ("no such module: vec0",)


# --- État module (singleton par processus) -------------------------------
# Exposés explicitement (et non encapsulés dans une classe) pour rester
# compatibles avec les 120+ consommateurs qui utilisent
# ``from app.core.database import get_session``. Tout changement vers une
# classe casserait l'API publique documentée dans ``app/core/__init__.py``.

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None

# Override per-contexte de la factory de sessions, posé par
# ``dedicated_session_scope`` pour le code lancé via ``asyncio.run`` sur un
# thread (jobs APScheduler). Ces jobs tournent sur une boucle asyncio DÉDIÉE et
# ne doivent PAS réutiliser l'engine global (dont le pool est lié à la boucle
# Tornado — une connexion poolée porte un thread aiosqlite + des futures liés à
# SA boucle). ``ContextVar`` est isolé par thread ET par contexte ``asyncio.run``,
# donc l'override n'affecte jamais la boucle Tornado.
_session_factory_override: ContextVar["async_sessionmaker[AsyncSession] | None"] = ContextVar(
    "_session_factory_override", default=None
)

# Cache du résultat du test d'import/chargement de ``sqlite-vec`` : ``None``
# tant que la tentative n'a pas eu lieu, ``True``/``False`` ensuite. Inutile de
# retenter un import défaillant à chaque nouvelle connexion physique.
_sqlite_vec_available: bool | None = None

# Verrou asyncio pour sérialiser les appels concurrents à ``init_database`` ;
# créé paresseusement dans l'event loop courant (éviter la création au module
# scope, qui lie l'instance à une loop qui pourrait être différente).
_init_lock: asyncio.Lock | None = None

# Strong-ref aux tasks fire-and-forget lancées au boot (ex: auto-sync LiteLLM).
# Sans ce conteneur référent, ``asyncio.create_task`` n'est tenu que par une
# weak-ref du loop (Python 3.12+) → GC silencieux possible AVANT complétion de
# la coroutine. Pour l'auto-sync pricing, un GC prématuré laisserait le registre
# à pricing=0.0 → le dashboard /admin/usage afficherait $0 indéfiniment (pas
# seulement la 1ère minute) = donnée fausse silencieuse. Cf. règle mémoire
# ``feedback_asyncio_create_task_strong_ref``. Le ``done_callback(discard)``
# libère la ref dès la fin pour éviter toute fuite.
_BOOT_BACKGROUND_TASKS: "set[asyncio.Task[Any]]" = set()


def _get_init_lock() -> asyncio.Lock:
    """Retourne le ``Lock`` d'init, créé paresseusement dans la loop courante."""
    global _init_lock
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    return _init_lock


# --- Construction des URL et répertoires ----------------------------------


def _ensure_db_dir(db_path: str) -> None:
    """Crée le répertoire parent de ``db_path`` s'il manque.

    Tolère un chemin déjà dans le cwd (``dirname`` vide) pour ne pas échouer
    quand l'utilisateur configure une base relative sans sous-dossier.
    """
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def get_database_url() -> str:
    """URL de connexion asynchrone (driver ``aiosqlite``)."""
    db_path = config.database.path
    _ensure_db_dir(db_path)
    return f"sqlite+aiosqlite:///{db_path}"


def get_db_url() -> str:
    """URL de connexion synchrone (APScheduler, scripts ponctuels).

    APScheduler repose sur SQLAlchemy synchrone pour son jobstore ; cette
    variante évite d'instancier ``aiosqlite`` dans un thread hors boucle.
    """
    db_path = config.database.path
    _ensure_db_dir(db_path)
    return f"sqlite:///{db_path}"


# --- Activation SQLCipher (chiffrement at-rest, conditionnel) -------------


def _bind_sqlcipher_if_configured() -> None:
    """Redirige le DBAPI SQLite (pysqlite sync + aiosqlite async) vers
    ``sqlcipher3`` SI une clé de chiffrement est configurée ET ``sqlcipher3``
    importable. **No-op total en mode clair** (pas de ``SQLCIPHER_KEY``) :
    ``sqlite3`` stdlib reste intact → dev/tests inchangés.

    Appelée au **call-time** (début de ``init_database`` et ``make_sync_engine``),
    donc AVANT toute création d'engine mais APRÈS le chargement complet de la
    config — aucune ouverture de connexion à l'import (cf. convention du module).
    Idempotente : un second appel est un no-op.

    Mécanisme : on substitue ``sys.modules['sqlite3']`` AVANT que SQLAlchemy
    n'importe ``aiosqlite`` (aucun import top-level d'aiosqlite dans ``app/`` —
    vérifié) ; ainsi ``aiosqlite.core`` fera ``import sqlite3`` et capturera
    ``sqlcipher3`` (sa ``sqlite_version`` reflète alors le vrai moteur). On
    re-pointe aussi ``aiosqlite.core.sqlite3`` par défense-en-profondeur si le
    module est déjà importé.
    """
    if not config.database.encryption_key:
        return  # mode clair : sqlite3 stdlib intact (dev/tests non cassés)

    try:
        import sqlcipher3.dbapi2 as _sqlcipher_dbapi2  # type: ignore[import-untyped]
    except ImportError:
        # sqlcipher3 absent : on NE patche PAS et on ne masque rien. Le garde
        # fail-closed de setup_encryption (``cipher_version`` vide) refusera le
        # boot avec un message actionnable plutôt que chiffrer « pour de faux ».
        logger.warning(
            "SQLCIPHER_KEY définie mais sqlcipher3 non importable — binding "
            "ignoré ; le boot échouera au garde fail-closed setup_encryption "
            "(installer sqlcipher3==0.6.2)."
        )
        return

    if sys.modules.get("sqlite3") is _sqlcipher_dbapi2:
        return  # déjà bindé (idempotence)

    sys.modules["sqlite3"] = _sqlcipher_dbapi2
    sys.modules["sqlite3.dbapi2"] = _sqlcipher_dbapi2
    # CRUCIAL pour le chemin SYNC (jobstore APScheduler) : le dialecte pysqlite de
    # SQLAlchemy fait littéralement ``from sqlite3 import dbapi2 as sqlite`` dans
    # ``import_dbapi``. Or ``_sqlcipher_dbapi2`` est un MODULE (pas un package, pas
    # de ``__path__``) dont ``__name__`` vaut ``"sqlcipher3.dbapi2"`` : sans cet
    # attribut, Python tente d'importer le sous-module ``sqlcipher3.dbapi2.dbapi2``
    # → ``ImportError: cannot import name 'dbapi2' from 'sqlcipher3.dbapi2'`` et
    # TOUT engine sync crashe (vu en prod sur ``GET /automations``). On expose donc
    # un attribut ``dbapi2`` auto-référent : ``from sqlite3 import dbapi2`` résout
    # alors directement sur le module bindé (la stdlib expose de même ``sqlite3``
    # comme package + sous-module ``dbapi2``). Le chemin async (aiosqlite,
    # ``import sqlite3``) n'est pas affecté.
    _sqlcipher_dbapi2.dbapi2 = _sqlcipher_dbapi2  # type: ignore[attr-defined]
    try:
        import aiosqlite.core as _aio_core

        _aio_core.sqlite3 = _sqlcipher_dbapi2  # type: ignore[attr-defined]
    except ImportError:
        pass  # aiosqlite pas encore importé : la substitution sys.modules suffira
    logger.info("SQLCipher bindé (aiosqlite + pysqlite) — chiffrement at-rest actif")


def _sqlite_error_types() -> tuple[type[BaseException], ...]:
    """Classes d'erreur DBAPI à catcher : ``sqlite3.Error`` stdlib + le DBAPI
    SQLCipher actif si bindé.

    ``sqlcipher3.dbapi2.Error`` n'hérite PAS de ``sqlite3.Error`` stdlib (modules
    distincts). Sans cet élargissement, une erreur SQLCipher dans
    ``setup_sqlite_vec`` ne serait pas catchée et deviendrait FATALE au boot au
    lieu de dégrader proprement en TF-IDF. Résolu au call-time : ``sys.modules``
    reflète déjà le binding quand les hooks s'exécutent.
    """
    live = sys.modules.get("sqlite3")
    live_err = getattr(live, "Error", None)
    if isinstance(live_err, type) and live_err is not sqlite3.Error:
        return (sqlite3.Error, live_err)
    return (sqlite3.Error,)


def make_sync_engine(url: str | None = None, **engine_kwargs: Any) -> Engine:
    """Crée un engine SQLAlchemy **synchrone** câblé avec les mêmes hooks de
    connexion critiques que l'engine async (``PRAGMA key`` + PRAGMAs perf).

    Source unique de vérité pour TOUT call-site sync (jobstore APScheduler, jobs
    de cleanup, branding, delivery dashboards, onboarding…). Avant cette factory,
    ~29 call-sites faisaient ``create_engine(get_db_url())`` brut SANS ``PRAGMA
    key`` → la base chiffrée leur apparaissait « file is not a database » dès que
    SQLCipher est actif (crash APScheduler au boot). Passer par ici garantit que
    la clé est posée sur chaque connexion.

    ``url`` permet de surcharger l'URL (ex. jobstore APScheduler avec une base
    de test isolée) ; par défaut ``get_db_url()``. Appelle
    ``_bind_sqlcipher_if_configured`` en premier (idempotent) pour couvrir les
    entry-points sync qui n'ont jamais appelé ``init_database``.
    """
    _bind_sqlcipher_if_configured()
    # Sérialiseur JSON tolérant (SSoT app/utils/json_safe) : sans lui, une
    # colonne JSON recevant un ``datetime``/``Decimal`` (rows SQL Server via
    # pyodbc) crashe l'INSERT — incident F_STEP_EXECUTION 2026-06-12 où une
    # exécution RÉUSSIE était requalifiée en échec par son propre journal.
    # ``setdefault`` : un caller peut surcharger explicitement.
    engine_kwargs.setdefault("json_serializer", dumps_safe)
    engine = create_engine(url or get_db_url(), **engine_kwargs)

    @event.listens_for(engine, "connect")
    def _on_sync_connect(dbapi_connection: Any, connection_record: Any) -> None:
        # Ordre critique : PRAGMA key AVANT toute autre requête (sinon base
        # chiffrée = « fichier invalide »), puis PRAGMAs perf. Pas de sqlite-vec
        # sur les engines sync (jobstore/cleanup ne font pas de recherche
        # vectorielle).
        setup_encryption(dbapi_connection, connection_record)
        setup_pragmas(dbapi_connection, connection_record)

    return engine


def make_async_engine(**engine_kwargs: Any) -> AsyncEngine:
    """Crée un engine SQLAlchemy **async** câblé avec les mêmes hooks de
    connexion critiques que l'engine principal (``PRAGMA key`` SQLCipher +
    sqlite-vec + PRAGMAs perf).

    Pour les rares call-sites async qui DOIVENT créer leur propre engine plutôt
    que réutiliser celui d'``init_database`` — typiquement un job APScheduler qui
    tourne dans un thread avec sa propre boucle ``asyncio`` (un ``AsyncEngine``
    ne se partage pas entre boucles). Sans ces hooks, une base chiffrée serait
    illisible (« file is not a database »).
    """
    _bind_sqlcipher_if_configured()
    # Même sérialiseur JSON tolérant que l'engine principal : les jobs
    # PLANIFIÉS (APScheduler, thread + boucle dédiée) écrivent eux aussi
    # F_STEP_EXECUTION — sans ça, le fix de l'incident 2026-06-12 ne
    # couvrirait que les exécutions manuelles.
    engine_kwargs.setdefault("json_serializer", dumps_safe)
    engine = create_async_engine(get_database_url(), **engine_kwargs)
    _register_connection_hooks(engine)
    return engine


def open_local_sqlite_connection(timeout: float = 30.0, **connect_kwargs: Any) -> Any:
    """Ouvre une connexion DBAPI **synchrone brute** sur la BDD LOCALE avec le
    ``PRAGMA key`` SQLCipher posé AVANT toute autre requête.

    SSoT pour les rares accès DBAPI bruts (hors SQLAlchemy) à la base locale —
    aujourd'hui ``schema_loader`` et ``sql_validator``. Sans le ``PRAGMA key``,
    une base chiffrée apparaît « file is not a database » dès la 1re requête (le
    binding a fait de ``sqlite3`` un ``sqlcipher3`` process-wide, mais la clé
    doit être posée PAR CONNEXION). No-op (base claire) si pas de clé ;
    fail-closed si clé posée mais moteur non-SQLCipher.

    ⚠️ NE PAS utiliser pour la BDD **source Sage** (``sqlite_sage_connector``) :
    base distincte, jamais chiffrée par ``SQLCIPHER_KEY``.
    """
    _bind_sqlcipher_if_configured()
    import sqlite3 as _sqlite3  # résolu au call-time → sqlcipher3 si bindé

    conn = _sqlite3.connect(config.database.path, timeout=timeout, **connect_kwargs)
    # PRAGMA key AVANT toute autre requête. setup_encryption tolère une connexion
    # DBAPI brute (il n'utilise que .cursor()/.execute()).
    setup_encryption(conn, None)
    return conn


# --- Hooks de connexion (ordre critique) ---------------------------------


# Une clé SQLCipher en hex brut est utilisée TELLE QUELLE (aucune dérivation
# PBKDF2) : 64 caractères = 32 octets de clé (le salt est lu dans l'en-tête de
# la base), 96 = 32 octets de clé + 16 octets de salt explicite. Toute autre
# forme est traitée comme une passphrase (dérivée via PBKDF2). C'est la
# convention de SQLCipher lui-même (cf. _build_pragma_key_hex).
_RAW_KEY_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}|[0-9a-f]{96}", re.IGNORECASE)


def _build_pragma_key_hex(encryption_key: str) -> str:
    """Construit les chiffres hex à injecter dans ``PRAGMA key = "x'<hex>'"``.

    Deux chemins, choisis automatiquement d'après la forme de la clé (c'est la
    convention de SQLCipher lui-même) :

    * **Raw key** — clé déjà en hex brut (64 ou 96 caractères) : renvoyée telle
      quelle (en minuscules). SQLCipher l'utilise directement comme clé de
      chiffrement → **aucune dérivation PBKDF2**. C'est le format produit par
      ``openssl rand -hex 32`` / ``secrets.token_hex(32)`` (cf. ``make
      first-run``), donc le cas par défaut d'un déploiement Komptia.
    * **Passphrase** — toute autre forme (phrase humaine, longueur ≠ 64/96, ou
      caractères non-hex) : hex de l'UTF-8, puis SQLCipher dérive la clé via
      PBKDF2 (256k itérations par défaut). Indispensable pour étirer un secret
      à faible entropie.

    Sécurité : passer une clé de 256 bits aléatoires en raw key n'enlève AUCUNE
    garantie. PBKDF2 ne fait que ralentir le brute-force d'un secret *devinable*
    ; une clé aléatoire de 32 octets ne l'est pas. Le gain est purement de la
    performance — la dérivation par connexion (~250 ms sur un petit CPU,
    multipliée par requête avec ``NullPool``) disparaît. La détection
    ``fullmatch`` réserve le raw key aux chaînes hex de longueur EXACTE → une
    passphrase humaine conserve toujours son PBKDF2.

    ⚠️ Changer la forme de clé d'une base EXISTANTE la rend illisible (« file is
    not a database ») car la clé effective diffère : c'est un échec BRUYANT au
    boot (jamais de données fausses silencieuses), pas une corruption.
    """
    if _RAW_KEY_HEX_RE.fullmatch(encryption_key):
        # .lower() OBLIGATOIRE : la garde aval ``re.fullmatch(r"[0-9a-f]+", …)``
        # de setup_encryption est sans IGNORECASE → une clé hex en MAJUSCULES y
        # serait rejetée (ValueError au boot) sans cette normalisation.
        return encryption_key.lower()
    return encryption_key.encode("utf-8").hex()


def setup_encryption(
    dbapi_connection: DBAPIConnection,
    connection_record: Any,  # sqlalchemy.pool._ConnectionRecord (non exporté publiquement)
) -> None:
    """Active SQLCipher via ``PRAGMA key`` si une clé est configurée.

    Doit être le **premier** hook exécuté sur une nouvelle connexion : toute
    requête antérieure au ``PRAGMA key`` verrait la base comme un fichier non
    SQLite ("file is not a database").

    Le littéral hex injecté est construit par :func:`_build_pragma_key_hex`
    (raw key sans PBKDF2 si la clé est déjà en hex 64/96, sinon passphrase
    dérivée). SQLCipher n'accepte pas le binding ``?`` sur les PRAGMA, d'où
    l'injection d'un littéral ``x'...'``. Une validation regex
    défense-en-profondeur garantit que la chaîne injectée ne contient que des
    caractères hex.
    """
    encryption_key = config.database.encryption_key
    if not encryption_key:
        return

    cursor = dbapi_connection.cursor()
    try:
        hex_key = _build_pragma_key_hex(encryption_key)
        if not re.fullmatch(r"[0-9a-f]+", hex_key):
            raise ValueError("Invalid encryption key format")
        cursor.execute(f"PRAGMA key = \"x'{hex_key}'\"")
        # Toute lecture post-PRAGMA valide la clé : échoue "file is not a
        # database" si la clé est mauvaise (vrai moteur SQLCipher).
        cursor.execute("SELECT count(*) FROM sqlite_master")
        # ⚠️ Fail-fast anti faux-chiffrement : sur sqlite3 standard (sqlcipher3
        # absent / non compilé), ``PRAGMA key`` est un NO-OP SILENCIEUX et le
        # SELECT ci-dessus réussit sur une base EN CLAIR — on logguerait alors
        # "chiffrement activé" pour une base non chiffrée (faux sentiment de
        # sécurité). ``PRAGMA cipher_version`` ne retourne une valeur que sous
        # un vrai moteur SQLCipher ; vide/absent ⇒ la clé ne chiffre RIEN.
        cursor.execute("PRAGMA cipher_version")
        _cv_row = cursor.fetchone()
        cipher_version = _cv_row[0] if _cv_row else None
        if not cipher_version:
            _msg = (
                "SQLCIPHER_KEY est définie mais le moteur SQLite n'est PAS "
                "SQLCipher (sqlcipher3 absent / non compilé) : la base "
                "démarrerait EN CLAIR malgré la clé. Installez sqlcipher3 "
                "(cf. §7.1 de la doc technique) OU retirez SQLCIPHER_KEY et "
                "chiffrez le volume au niveau OS (LUKS/BitLocker)."
            )
            # Fail-closed (2026-05-31, review adversariale du snapshot 20b8902) :
            # on REFUSE de démarrer dans TOUS les environnements. On n'atteint
            # cette branche QUE si SQLCIPHER_KEY est définie (sinon ``return``
            # plus haut) = intention explicite de chiffrer ; un moteur qui ne
            # chiffre pas = configuration cassée. Avant, on ne levait que si
            # ``is_production()`` ; or ``environment`` vaut "development" par
            # défaut quand ENVIRONMENT est absent (config.py) → un déploiement
            # prod qui oublie la variable démarrait EN CLAIR avec un simple
            # warning. Un dev qui veut tourner sans chiffrement ne définit
            # simplement pas SQLCIPHER_KEY.
            logger.critical(_msg)
            raise RuntimeError(_msg)
        else:
            logger.debug("Chiffrement SQLCipher activé (cipher_version=%s)", cipher_version)
    except (*_sqlite_error_types(), UnicodeEncodeError, ValueError) as exc:
        # On ne log pas la clé elle-même, seulement le type d'erreur.
        logger.error("Erreur configuration chiffrement: %s", type(exc).__name__)
        raise
    finally:
        cursor.close()


def setup_sqlite_vec(
    dbapi_connection: DBAPIConnection,
    connection_record: Any,
) -> None:
    """Charge l'extension ``sqlite-vec`` si disponible.

    Doit passer **après** ``setup_encryption`` (sinon PRAGMA key refuserait de
    s'exécuter) et **avant** ``setup_pragmas`` (les PRAGMAs d'optimisation
    n'ont pas d'ordre strict vis-à-vis de l'extension, mais on respecte le
    principe "toutes les mutations de config avant toute requête métier").

    Le résultat (``True``/``False``) est caché dans ``_sqlite_vec_available`` :
    ``NullPool`` ouvre une connexion par session, il est inutile de retenter
    l'import à chaque fois. La fermeture via ``close_database`` réinitialise
    ce cache pour permettre un hot-reload de l'extension.
    """
    global _sqlite_vec_available

    if _sqlite_vec_available is False:
        return

    try:
        import sqlite_vec  # noqa: F401  # présence = test, usage réel via .load()

        dbapi_connection.enable_load_extension(True)
        sqlite_vec.load(dbapi_connection)
        dbapi_connection.enable_load_extension(False)
        _sqlite_vec_available = True
    except ImportError:
        _sqlite_vec_available = False
        logger.warning("sqlite-vec non installé — recherche vectorielle désactivée")
    except AttributeError as exc:
        # ``AsyncAdapt_aiosqlite_connection`` ne proxifie pas
        # ``enable_load_extension`` — dépendant de la version aiosqlite.
        _sqlite_vec_available = False
        logger.warning(
            "sqlite-vec indisponible via ce driver (%s) — recherche vectorielle désactivée",
            exc,
        )
    except _sqlite_error_types() as exc:
        _sqlite_vec_available = False
        logger.warning("Erreur SQLite au chargement de sqlite-vec: %s", exc)


def setup_pragmas(
    dbapi_connection: DBAPIConnection,
    connection_record: Any,
) -> None:
    """Positionne les PRAGMA de performance et d'intégrité.

    Ordre après ``setup_encryption`` (clé déjà posée) et ``setup_sqlite_vec``
    (extension chargée si dispo). Ces PRAGMA sont idempotents et
    per-connection : comme ``NullPool`` crée une connexion par session, ils
    s'appliquent systématiquement.
    """
    cursor = dbapi_connection.cursor()
    try:
        # WAL : lectures concurrentes + un seul writer. Le write lock peut
        # être tenu plusieurs secondes pendant les flushes batch, d'où
        # ``busy_timeout`` généreux ci-dessous.
        cursor.execute("PRAGMA journal_mode = WAL")
        # Valeur négative = budget mémoire en KiB (spec SQLite PRAGMA).
        cursor.execute(f"PRAGMA cache_size = -{_CACHE_SIZE_KIB}")
        # NORMAL : fsync au checkpoint, pas à chaque commit — bon compromis
        # perf/durabilité pour une app desktop chiffrée (crash = perte du
        # dernier commit, pas de corruption).
        cursor.execute("PRAGMA synchronous = NORMAL")
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        # mmap_size : 1 GiB sur DB locale 15 GB pour éviter le round-trip
        # disque sur les SELECT random-access intensifs (RAG sur 29 M
        # lignes value_mapping + FTS5). Cf. _MMAP_SIZE_BYTES pour le
        # raisonnement complet et la note SQLCipher.
        try:
            cursor.execute(f"PRAGMA mmap_size = {_MMAP_SIZE_BYTES}")
        except _sqlite_error_types() as exc:
            # SQLCipher sans memory-mapping compilé : on log et on continue
            # (PRAGMA mmap_size renvoie 0 silencieusement sur la plupart
            # des builds, mais on protège contre une variante stricte).
            logger.warning(
                "PRAGMA mmap_size non supporté (%s) — fallback I/O direct, "
                "perf SELECT dégradée mais correctness intacte",
                exc,
            )
        # wal_autocheckpoint : 5000 pages (~20 MiB) au lieu du défaut 1000
        # pour réduire la contention sur les writes pendant les
        # checkpoints automatiques. Cf. _WAL_AUTOCHECKPOINT_PAGES pour
        # le raisonnement.
        cursor.execute(f"PRAGMA wal_autocheckpoint = {_WAL_AUTOCHECKPOINT_PAGES}")
    finally:
        cursor.close()


def _register_connection_hooks(engine: AsyncEngine) -> None:
    """Enchaîne les hooks ``on_connect`` dans l'ordre critique.

    L'ordre ``encryption → sqlite_vec → pragmas`` doit être strictement
    respecté (voir docstrings de chaque hook). On capture l'engine par
    argument explicite plutôt que par fermeture sur le global ``_engine``
    pour faciliter les tests.
    """

    @event.listens_for(engine.sync_engine, "connect")
    def _on_connect(dbapi_connection: DBAPIConnection, connection_record: Any) -> None:
        setup_encryption(dbapi_connection, connection_record)
        setup_sqlite_vec(dbapi_connection, connection_record)
        setup_pragmas(dbapi_connection, connection_record)


# --- Migrations incrémentales idempotentes -------------------------------


@dataclass(frozen=True, slots=True)
class _Migration:
    """Migration additive idempotente (ajout de colonne, d'index ou
    correction de données).

    ``kind``:
        - ``"column"`` → ``name`` est un nom de colonne à ajouter via ALTER
          TABLE. L'idempotence repose sur ``PRAGMA table_info``.
        - ``"index"`` → ``name`` est le nom d'index à créer. La requête
          porte elle-même ``CREATE INDEX IF NOT EXISTS`` (idempotent natif
          SQLite depuis toujours).
        - ``"data"`` → ``sql`` est un UPDATE/INSERT que **l'auteur garantit
          self-idempotent** (typiquement via une clause ``WHERE`` qui ne
          matche aucune row au 2ᵉ run). Ré-exécuté à chaque boot — si la
          clause WHERE est correcte, c'est un no-op après la 1ʳᵉ exécution.
          Cas typique : backfill de valeur d'enum suite à une migration de
          casse (``UPDATE users SET role=UPPER(role) WHERE role IN (...)``).

          Pour les migrations one-shot dont la sentinelle est détectable en
          O(1) (typiquement un ``archive_reason`` indexé), passer
          ``idempotency_check_sql`` : un ``SELECT`` qui retourne ≥ 1 row si
          la migration a déjà tourné. Le pre-check court-circuite
          l'exécution de ``sql`` au 2ᵉ boot et tous les suivants — utile
          quand ``sql`` ferait un scan O(N) au boot pour produire 0
          insertion (ex: ``INSERT ... SELECT ... FROM huge_table WHERE NOT
          EXISTS (...)`` avec sous-requête évaluée par row).
        - ``"drop_table"`` → drop d'une table devenue obsolete. ``table``
          est la table a dropper, ``name`` un identifiant lisible (ex
          "drop_legacy_v1"), ``sql`` typiquement ``DROP TABLE IF EXISTS
          <table>``. L'idempotence repose sur l'absence de la table (si
          elle n'existe plus → migration deja appliquee). Note : ``IF
          EXISTS`` est aussi natif SQLite → double protection.
        - ``"drop_column"`` → drop d'une colonne devenue obsolete.
          ``table`` est la table cible, ``name`` est le nom de la colonne
          à supprimer (utilisé pour le check d'idempotence via
          ``PRAGMA table_info``), ``sql`` typiquement
          ``ALTER TABLE <table> DROP COLUMN <name>``. Requiert SQLite
          ≥ 3.35 (2021-03). L'idempotence repose sur l'absence de la
          colonne — si elle n'existe plus, la migration est sautée.
    """

    table: str
    name: str
    sql: str
    kind: str  # "column" | "index" | "data" | "drop_table" | "drop_column"
    idempotency_check_sql: str | None = None
    # Optionnel : nom de la table SOURCE pour les ``data`` migrations qui
    # font ``INSERT INTO <table> SELECT ... FROM <source_table>``. Si
    # cette table source n'existe pas (boot frais sur BDD partielle, table
    # supprimée manuellement), la migration est skippée pour éviter
    # ``OperationalError: no such table``. None = pas de check source.
    source_table: str | None = None


# ``value_mapping_archive`` (snapshot legacy task #18) + sa constante
# ``_VALUE_MAPPING_ARCHIVE_INITIAL_REASON`` : SUPPRIMÉS 2026-06-11 sur demande
# utilisateur (David) — plus aucun lecteur runtime, aucune FK. Cf. la migration
# ``drop_value_mapping_archive_2026_06_11`` plus bas qui DROP la table.


_MIGRATIONS: Final[tuple[_Migration, ...]] = (
    # llm_models.context_window_verified (2026-06-03) : distingue une fenêtre
    # CONFIRMÉE (LiteLLM / override / seed) d'une valeur PROVISOIRE (défaut
    # 200_000 posé par sync_from_provider quand l'API provider n'expose pas la
    # fenêtre, avant que l'enrich LiteLLM ne confirme). L'indicateur /iris lit
    # ce flag pour ne pas afficher un chiffre faux. Cf. bug « 200K peu importe
    # le modèle » : un modèle choisi depuis la dropdown live mais jamais enrichi.
    _Migration(
        "llm_models",
        "context_window_verified",
        "ALTER TABLE llm_models ADD COLUMN context_window_verified BOOLEAN DEFAULT FALSE",
        "column",
    ),
    # Back-fill : les modèles DÉJÀ en base au moment de cette migration viennent
    # du seed (valeurs code fiables) — ``last_synced_at IS NULL`` les distingue
    # des modèles découverts par sync_from_provider (qui portent un timestamp et
    # une fenêtre 200K provisoire à confirmer). Sans ce back-fill, des modèles
    # corrects (haiku=200K, opus=1M) seraient marqués « à confirmer » à tort.
    # Self-idempotent : au 2ᵉ boot, ces rows ont verified=TRUE → WHERE ne matche
    # plus rien ; les modèles synced (last_synced_at NOT NULL) ne sont jamais
    # touchés (ils dépendent de l'enrich pour passer verified).
    _Migration(
        "llm_models",
        "backfill_context_window_verified",
        "UPDATE llm_models SET context_window_verified = TRUE "
        "WHERE context_window_verified = FALSE AND last_synced_at IS NULL",
        "data",
    ),
    _Migration(
        "search_history",
        "feedback_status",
        "ALTER TABLE search_history ADD COLUMN feedback_status VARCHAR(20) DEFAULT 'new'",
        "column",
    ),
    _Migration(
        "search_history",
        "feedback_resolved_by",
        "ALTER TABLE search_history ADD COLUMN feedback_resolved_by "
        "INTEGER REFERENCES users(id)",
        "column",
    ),
    _Migration(
        "search_history",
        "feedback_resolved_at",
        "ALTER TABLE search_history ADD COLUMN feedback_resolved_at DATETIME",
        "column",
    ),
    _Migration(
        "search_history",
        "ix_search_history_feedback_status",
        "CREATE INDEX IF NOT EXISTS ix_search_history_feedback_status "
        "ON search_history(feedback_status)",
        "index",
    ),
    _Migration(
        "training_data",
        "metadata",
        "ALTER TABLE training_data ADD COLUMN metadata JSON",
        "column",
    ),
    # Phase 1.4 (#16) — Colonne ``depends_on`` pour le closure transitif
    # du mode invisible (vues/fonctions/synonymes qui référencent d'autres
    # objets BDD). Stockée comme JSON array de noms canoniques.
    _Migration(
        "training_data",
        "depends_on",
        "ALTER TABLE training_data ADD COLUMN depends_on JSON",
        "column",
    ),
    # Backfill : les SYNONYM persistés AVANT cette migration stockent leur
    # cible dans ``extra_metadata['target']``. On promeut vers la colonne
    # dédiée ``depends_on`` pour homogénéiser. Self-idempotent : la clause
    # ``WHERE depends_on IS NULL`` ne matche aucune row au 2e run après
    # backfill réussi. Sqlite's json_array(scalar) crée ``["scalar"]``.
    #
    # ⚠️ Casse : SQLAlchemy ``Enum(TrainingDataType)`` stocke le NOM du
    # membre (``'SYNONYM'`` majuscule), pas sa value (``'synonym'``). La
    # 1ʳᵉ version de cette migration comparait la value → NO-OP silencieux
    # à chaque boot (0 row backfillée). Corrigé 2026-06-09 ; le ``IN``
    # couvre les deux casses par défense (rows écrites en raw SQL).
    _Migration(
        "training_data",
        "backfill_synonym_depends_on",
        "UPDATE training_data "
        "SET depends_on = json_array(json_extract(metadata, '$.target')) "
        "WHERE data_type IN ('SYNONYM', 'synonym') "
        "  AND depends_on IS NULL "
        "  AND json_extract(metadata, '$.target') IS NOT NULL",
        "data",
    ),
    # Phase 1.6 (#43) — Backfill : re-classifier les vues stockées comme
    # ``data_type='DDL'`` en ``data_type='VIEW'``. Pré-Phase 1.6, le sync
    # stockait les vues via ``add_ddl()`` (legacy). Maintenant qu'on a
    # ``add_view()`` avec ``depends_on``, on migre pour homogénéiser et
    # permettre au closure transitif (Phase 2.1) de les distinguer des
    # tables physiques. Détection : ``source LIKE 'auto_sync_view%'``
    # — c'est le marqueur déposé par schema_sync (cf. ligne ~890).
    # Self-idempotent : ``WHERE data_type IN (...)`` ne matche plus après
    # le 1er run.
    #
    # ⚠️ Casse : comme ci-dessus, le stockage est le NOM du membre enum
    # (``'DDL'``/``'VIEW'`` MAJUSCULES). La 1ʳᵉ version comparait/écrivait
    # les values minuscules → double no-op : WHERE jamais matché, et le
    # SET aurait écrit ``'view'`` que l'ORM ne sait pas relire
    # (``LookupError`` au SELECT). Conséquence avant correction : chaque
    # vue existait EN DOUBLE (legacy ``DDL/auto_sync_view`` + ``VIEW``
    # du add_view actuel). Corrigé 2026-06-09 ; la migration suivante
    # (``dedup_active_view_rows``) résorbe le double stockage — elle est
    # OBLIGATOIRE car ``add_view`` upserte via ``scalar_one_or_none()``
    # qui lèverait ``MultipleResultsFound`` avec 2 rows VIEW actives de
    # même ``table_name``.
    _Migration(
        "training_data",
        "reclassify_views_from_ddl",
        "UPDATE training_data "
        "SET data_type = 'VIEW' "
        "WHERE data_type IN ('DDL', 'ddl') "
        "  AND source LIKE 'auto_sync_view%'",
        "data",
    ),
    # Dédup post-reclassification : garde UNE seule row VIEW active par
    # ``table_name`` (la plus récente = MAX(id), c'est la forme écrite par
    # ``add_view`` après la forme legacy), désactive les autres
    # (``is_active=0`` — on ne supprime JAMAIS, cf. doctrine « ne pas
    # delete l'existant »). Sur une BDD legacy-only (jamais re-syncée
    # depuis Phase 1.6), il n'y a qu'une row par vue → no-op. Les rows
    # sans ``table_name`` sont exclues (GROUP BY NULL fusionnerait tout).
    # Self-idempotent : au 2ᵉ run chaque table_name n'a plus qu'une row
    # active → ``NOT IN`` ne matche rien.
    #
    # HYPOTHÈSE keeper = MAX(id) (revue adv. 2026-06-10) : valable parce
    # qu'aujourd'hui SEUL ``training_store.add_view`` écrit des rows VIEW
    # (en upsert) — la row au plus grand id est donc toujours la plus
    # récente écriture du sync. Si un jour des rows VIEW « manuelles »
    # coexistent (import/restore/UI d'édition), ajouter un tie-breaker
    # ``updated_at``/``source`` AVANT de compter sur cette migration.
    #
    # EFFET DE BORD assumé (fail-closed, doctrine mode invisible) : les
    # rows legacy reclassées ont ``depends_on`` NULL → la closure
    # transitive les traite en « dépendances inconnues » et les CACHE aux
    # users restreints jusqu'à la prochaine sync schéma (qui re-peuple
    # depends_on via add_view). ACTION POST-DEPLOY : lancer une sync
    # après le 1er boot (déjà dans la checklist déploiement du fix vues).
    # Les admins ne sont jamais filtrés — seuls les users à règles
    # data-access sont concernés, et dans le sens sûr (cacher trop).
    _Migration(
        "training_data",
        "dedup_active_view_rows",
        "UPDATE training_data "
        "SET is_active = 0 "
        "WHERE data_type = 'VIEW' "
        "  AND is_active = 1 "
        "  AND table_name IS NOT NULL "
        "  AND id NOT IN ("
        "    SELECT MAX(id) FROM training_data "
        "    WHERE data_type = 'VIEW' AND is_active = 1 "
        "      AND table_name IS NOT NULL "
        "    GROUP BY table_name"
        "  )",
        "data",
    ),
    _Migration(
        "conversation_messages",
        "turn_events",
        "ALTER TABLE conversation_messages ADD COLUMN turn_events TEXT",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "is_template",
        "ALTER TABLE F_DASHBOARD ADD COLUMN is_template BOOLEAN DEFAULT FALSE",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "template_description",
        "ALTER TABLE F_DASHBOARD ADD COLUMN template_description TEXT",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_enabled",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_enabled BOOLEAN DEFAULT FALSE",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_type",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_type VARCHAR(20)",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_config",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_config JSON",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_recipients",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_recipients JSON",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_period_days",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_period_days INTEGER DEFAULT 30",
        "column",
    ),
    _Migration(
        "F_DASHBOARD",
        "schedule_last_sent_at",
        "ALTER TABLE F_DASHBOARD ADD COLUMN schedule_last_sent_at DATETIME",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "notify_on_failure",
        "ALTER TABLE F_AUTOMATION ADD COLUMN notify_on_failure BOOLEAN DEFAULT TRUE",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "notify_on_success",
        "ALTER TABLE F_AUTOMATION ADD COLUMN notify_on_success BOOLEAN DEFAULT FALSE",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "notification_emails",
        "ALTER TABLE F_AUTOMATION ADD COLUMN notification_emails JSON",
        "column",
    ),
    _Migration(
        "database_connections",
        "server_version",
        "ALTER TABLE database_connections ADD COLUMN server_version TEXT",
        "column",
    ),
    _Migration(
        "database_connections",
        "created_by",
        "ALTER TABLE database_connections ADD COLUMN created_by INTEGER",
        "column",
    ),
    _Migration(
        "database_connections",
        "updated_by",
        "ALTER TABLE database_connections ADD COLUMN updated_by INTEGER",
        "column",
    ),
    _Migration(
        "database_connections",
        "last_activated_by",
        "ALTER TABLE database_connections ADD COLUMN last_activated_by INTEGER",
        "column",
    ),
    _Migration(
        "database_connections",
        "last_activated_at",
        "ALTER TABLE database_connections ADD COLUMN last_activated_at DATETIME",
        "column",
    ),
    _Migration(
        "conversations",
        "discoveries",
        "ALTER TABLE conversations ADD COLUMN discoveries TEXT",
        "column",
    ),
    # --- Branding dynamique : nom d'entreprise (au lieu de "Cabinet X"
    # hardcodé). Permet le déploiement chez un autre client sans patcher
    # les templates d'email.
    _Migration(
        "smtp_global_config",
        "company_name",
        "ALTER TABLE smtp_global_config ADD COLUMN company_name VARCHAR(255)",
        "column",
    ),
    # --- Email destinataire des signalements (= aussi l'approbateur
    # Iris-DBA-write, SSoT partagé). Configurable via /admin/smtp-config.
    # NULL = fallback ``config.support_email`` (vide par défaut, aucun
    # hardcode d'adresse).
    _Migration(
        "smtp_global_config",
        "support_email",
        "ALTER TABLE smtp_global_config ADD COLUMN support_email VARCHAR(255)",
        "column",
    ),
    # --- Display name d'expéditeur SMTP (``From: <Nom> <email>``).
    # Configurable via /admin/smtp-config. NULL = fallback
    # ``config.app_name`` (cohérent avec ``smtp_factory`` et ``branding``).
    # La colonne existe déjà dans le modèle SQLAlchemy depuis longtemps,
    # mais aucune migration ne la garantissait : une BDD créée avant
    # l'ajout du champ dans le modèle se retrouvait sans la colonne au
    # premier boot d'une version récente, sans erreur visible (les écrits
    # planteraient seulement à l'instant d'un UPDATE).
    _Migration(
        "smtp_global_config",
        "from_name",
        "ALTER TABLE smtp_global_config ADD COLUMN from_name VARCHAR(255)",
        "column",
    ),
    # --- Conversation.summary : résumé fin-de-run pour mémoire cross-conv
    # (P2.1, parité avec ``copilot_memory``). Persisté pour relecture au
    # rechargement de conversation.
    _Migration(
        "conversations",
        "summary",
        "ALTER TABLE conversations ADD COLUMN summary TEXT",
        "column",
    ),
    # --- Conversation.last_input_tokens : dernière taille de contexte
    # envoyée au LLM. Persisté à chaque ``done`` event de l'agent pour
    # restaurer la barre context-window au reload (sans ça, l'estimation
    # heuristique sous-évalue de ~30k car elle ne voit pas le system
    # prompt + tools + RAG ré-envoyés à chaque tour).
    _Migration(
        "conversations",
        "last_input_tokens",
        "ALTER TABLE conversations ADD COLUMN last_input_tokens INTEGER",
        "column",
    ),
    # --- users.role : index pour rendre la migration data ci-dessous
    # bornée (sans index, scan complet à chaque boot dès que la table
    # contient quelques milliers d'utilisateurs). Posé AVANT la data
    # migration pour qu'elle bénéficie de l'index dès la 1ʳᵉ exécution.
    _Migration(
        "users",
        "ix_users_role",
        "CREATE INDEX IF NOT EXISTS ix_users_role ON users(role)",
        "index",
    ),
    # --- users.role : normalisation de casse pour matcher l'enum Python
    # ``UserRole`` (NAMES en majuscule : ADMIN, USER). Des rows legacy
    # contiennent les VALUES en minuscule ('admin', 'user') — probablement
    # créés par un script ad-hoc qui a utilisé ``UserRole.ADMIN.value``
    # au lieu de ``.name``. SQLAlchemy stocke par défaut le NAME, mais
    # ne sait pas désérialiser un VALUE en minuscule contre les NAMES,
    # ce qui crashait ``get_users_overview`` (LookupError 'admin' is not
    # among the defined enum values).
    #
    # ⚠️ Synchronisation avec ``UserRole`` : la WHERE liste les valeurs
    # exactes à corriger ('admin','user'). Si un nouveau rôle est ajouté
    # à l'enum (ex. READER='reader'), il faut **soit** mettre à jour
    # cette WHERE, **soit** générer la migration depuis l'enum. Un test
    # de garde (``test_normalize_role_migration_covers_all_user_roles``
    # dans ``tests/unit/test_migration_role_case.py``) fail si l'enum
    # évolue sans que la migration soit synchronisée — c'est le filet
    # de sécurité.
    #
    # WHERE clause restrictive : pas de risque de toucher d'autres rôles
    # si le champ évolue. Self-idempotent : après la 1ʳᵉ exécution, plus
    # aucune row ne matche.
    _Migration(
        "users",
        "normalize_role_case",
        "UPDATE users SET role = UPPER(role) WHERE role IN ('admin', 'user')",
        "data",
    ),
    # --- users.email : index UNIQUE COLLATE NOCASE (ASCII defense-in-depth) ---
    # Depuis 2026-05-11, l'identifiant de login est ``email`` (et plus
    # ``username``). La normalisation case-insensitive Unicode-aware est
    # faite côté Python (cf. ``_normalize_users_email_case_insensitive``
    # appelée par ``_run_migrations``). Cet index NOCASE est une protection
    # ADDITIONNELLE ASCII contre tout INSERT qui court-circuiterait la
    # normalisation Python (régression future, migration manuelle). Il NE
    # remplace PAS le folding Python (SQLite NOCASE est ASCII-only ⇒ ne
    # couvre pas ß, İ, sigma grec, etc. — ces cas sont gérés par le
    # casefold Python avant insert/lookup).
    _Migration(
        "users",
        "ix_users_email_nocase",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_nocase " "ON users(email COLLATE NOCASE)",
        "index",
    ),
    # --- Phase 1 DAG : colonnes layout + input_policy sur AutomationStep ---
    _Migration(
        "F_AUTOMATION_STEP",
        "layout_x",
        "ALTER TABLE F_AUTOMATION_STEP ADD COLUMN layout_x INTEGER",
        "column",
    ),
    _Migration(
        "F_AUTOMATION_STEP",
        "layout_y",
        "ALTER TABLE F_AUTOMATION_STEP ADD COLUMN layout_y INTEGER",
        "column",
    ),
    _Migration(
        "F_AUTOMATION_STEP",
        "input_policy",
        "ALTER TABLE F_AUTOMATION_STEP ADD COLUMN input_policy JSON",
        "column",
    ),
    # --- Phase 2 DAG : observabilite sur F_STEP_EXECUTION ---
    _Migration(
        "F_STEP_EXECUTION",
        "trace_id",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN trace_id VARCHAR(36)",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "ix_step_execution_trace_id",
        "CREATE INDEX IF NOT EXISTS ix_step_execution_trace_id " "ON F_STEP_EXECUTION(trace_id)",
        "index",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "step_input",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN step_input JSON",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "step_output",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN step_output JSON",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "config_snapshot",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN config_snapshot JSON",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "sql_executed",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN sql_executed TEXT",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "spill_parquet_path",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN spill_parquet_path TEXT",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "llm_tokens_in",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN llm_tokens_in INTEGER",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "llm_tokens_out",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN llm_tokens_out INTEGER",
        "column",
    ),
    _Migration(
        "F_STEP_EXECUTION",
        "llm_cost_eur",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN llm_cost_eur FLOAT",
        "column",
    ),
    # --- P5.5 (audit 2026-05-26) : error_class pour auto-pause RLS ---
    # Sans cette colonne, le check
    # ``getattr(s, "error_class", None) == "DataAccessDeniedError"`` dans
    # ``executor.py::execute_automation`` (ligne ~422) retournait TOUJOURS
    # ``None`` après reload BDD → la branche auto-pause sur
    # DataAccessDeniedError ne se déclenchait JAMAIS (bug latent DAG ET legacy).
    # Fix : on ajoute la colonne + on propage le field dans le persister.
    _Migration(
        "F_STEP_EXECUTION",
        "error_class",
        "ALTER TABLE F_STEP_EXECUTION ADD COLUMN error_class VARCHAR(80)",
        "column",
    ),
    # --- Phase 2 DAG : fail_policy au niveau Automation ---
    _Migration(
        "F_AUTOMATION",
        "fail_policy",
        "ALTER TABLE F_AUTOMATION ADD COLUMN fail_policy VARCHAR(20) DEFAULT 'abort'",
        "column",
    ),
    # --- Phase 2b DAG : trace du declencheur sur F_EXECUTION ---
    _Migration(
        "F_EXECUTION",
        "trigger_source",
        "ALTER TABLE F_EXECUTION ADD COLUMN trigger_source VARCHAR(20) DEFAULT 'manual'",
        "column",
    ),
    _Migration(
        "F_EXECUTION",
        "triggered_by_user_id",
        "ALTER TABLE F_EXECUTION ADD COLUMN triggered_by_user_id INTEGER REFERENCES users(id)",
        "column",
    ),
    _Migration(
        "F_EXECUTION",
        "trigger_payload",
        "ALTER TABLE F_EXECUTION ADD COLUMN trigger_payload JSON",
        "column",
    ),
    # Phase 2c DAG : checkpoint pour resume après step waiting (cf. modèle
    # ``Execution.wait_checkpoint`` ligne 109). Snapshot des step_outputs
    # posé quand le DAG hit un step "waiting" — au resume on rehydrate
    # depuis ce checkpoint sans re-exec les steps déjà faits.
    _Migration(
        "F_EXECUTION",
        "wait_checkpoint",
        "ALTER TABLE F_EXECUTION ADD COLUMN wait_checkpoint JSON",
        "column",
    ),
    # --- Phase 2d DAG : circuit-breaker par workflow ---
    _Migration(
        "F_AUTOMATION",
        "max_llm_cost_eur",
        "ALTER TABLE F_AUTOMATION ADD COLUMN max_llm_cost_eur FLOAT",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "max_total_rows",
        "ALTER TABLE F_AUTOMATION ADD COLUMN max_total_rows INTEGER",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "max_duration_seconds",
        "ALTER TABLE F_AUTOMATION ADD COLUMN max_duration_seconds INTEGER",
        "column",
    ),
    # --- T28 : snapshot pipeline gzippé pour reproductibilité.
    # Capturé à la création de l'automation, stocké en BLOB (bytes). Lu
    # par ``app.services.automation.snapshot_service.replay_automation``
    # pour détecter le drift (schéma BDD, modèle LLM, SQL généré).
    _Migration(
        "F_AUTOMATION",
        "snapshot_json",
        "ALTER TABLE F_AUTOMATION ADD COLUMN snapshot_json BLOB",
        "column",
    ),
    # --- Registre LLM (LOT 0.2 + 8.12) ---
    # ``llm_models`` créé via ``Base.metadata.create_all`` au boot — tous les
    # champs initiaux y figurent (cf. ``app/models/llm_model.py``). Les
    # AJOUTS FUTURS de colonnes (provider_endpoint_url, supports_streaming,
    # supports_vision, ...) DOIVENT s'ajouter ici suivant le pattern :
    #     _Migration(
    #         "llm_models",
    #         "<nom_colonne>",
    #         "ALTER TABLE llm_models ADD COLUMN <nom_colonne> <SQL_TYPE> [DEFAULT ...]",
    #         "column",
    #     ),
    # Sans cette ligne, sur une BDD existante (déployée avant le nouveau
    # champ), le démarrage crashera avec ``OperationalError: no such
    # column``. ``create_all`` ne crée que les TABLES manquantes, jamais
    # les colonnes manquantes.
    _Migration(
        "llm_models",
        "timeout_seconds",
        "ALTER TABLE llm_models ADD COLUMN timeout_seconds INTEGER",
        "column",
    ),
    _Migration(
        "llm_models",
        "is_utility",
        "ALTER TABLE llm_models ADD COLUMN is_utility BOOLEAN DEFAULT 0 NOT NULL",
        "column",
    ),
    # Pricing 3-tiers Anthropic (cache_read = 10% du input, cache_creation
    # = 125% du input). Sans ces colonnes, ``_compute_cost_snapshot``
    # appliquait le prix INPUT à tous les tokens (cache_read sur-facturé,
    # cache_creation ignoré). Cf. fix 2026-05-05.
    _Migration(
        "llm_models",
        "cache_read_price_per_mtok_usd",
        "ALTER TABLE llm_models ADD COLUMN cache_read_price_per_mtok_usd "
        "FLOAT NOT NULL DEFAULT 0.0",
        "column",
    ),
    _Migration(
        "llm_models",
        "cache_creation_price_per_mtok_usd",
        "ALTER TABLE llm_models ADD COLUMN cache_creation_price_per_mtok_usd "
        "FLOAT NOT NULL DEFAULT 0.0",
        "column",
    ),
    # --- Capability flags multi-provider (plan dynamicité 2026-05-14) ---
    # Source unique de vérité pour la dynamicité : le code applicatif lit
    # ces flags au lieu de comparer ``provider_name``. Ajouter un nouveau
    # provider/modèle = remplir ces flags dans le seed initial OU via UI
    # ``/admin/ai-models``, et tous les call sites s'adaptent.
    _Migration(
        "llm_models",
        "supports_reasoning_effort",
        "ALTER TABLE llm_models ADD COLUMN supports_reasoning_effort " "BOOLEAN DEFAULT 0 NOT NULL",
        "column",
    ),
    _Migration(
        "llm_models",
        "supports_parallel_tool_calls",
        "ALTER TABLE llm_models ADD COLUMN supports_parallel_tool_calls "
        "BOOLEAN DEFAULT 0 NOT NULL",
        "column",
    ),
    _Migration(
        "llm_models",
        "supports_streaming",
        "ALTER TABLE llm_models ADD COLUMN supports_streaming " "BOOLEAN DEFAULT 1 NOT NULL",
        "column",
    ),
    _Migration(
        "llm_models",
        "supports_vision",
        "ALTER TABLE llm_models ADD COLUMN supports_vision " "BOOLEAN DEFAULT 0 NOT NULL",
        "column",
    ),
    _Migration(
        "llm_models",
        "supports_strict_json",
        "ALTER TABLE llm_models ADD COLUMN supports_strict_json " "BOOLEAN DEFAULT 0 NOT NULL",
        "column",
    ),
    # Format de tool calls par défaut "openai" car c'est le format
    # universel OpenAI-compatible (Mistral, Groq, DeepSeek, Together,
    # Gemini /v1/chat). Anthropic override à "anthropic" via le seed.
    _Migration(
        "llm_models",
        "tool_call_format",
        "ALTER TABLE llm_models ADD COLUMN tool_call_format "
        "VARCHAR(20) NOT NULL DEFAULT 'openai'",
        "column",
    ),
    _Migration(
        "llm_models",
        "system_prompt_format",
        "ALTER TABLE llm_models ADD COLUMN system_prompt_format "
        "VARCHAR(20) NOT NULL DEFAULT 'string'",
        "column",
    ),
    _Migration(
        "llm_models",
        "cache_ttl_options",
        "ALTER TABLE llm_models ADD COLUMN cache_ttl_options JSON",
        "column",
    ),
    # Phase 2 — accounting BDD unifié : ``db_bytes_used`` complète
    # ``quota_used`` (fichiers seulement) avec les bytes occupés en BDD
    # par les tables user-scoped. Cf. ``app/services/db_usage.py``.
    _Migration(
        "user_storage",
        "db_bytes_used",
        "ALTER TABLE user_storage ADD COLUMN db_bytes_used BIGINT DEFAULT 0 NOT NULL",
        "column",
    ),
    # ── Contacts : index sur la jointure ``distribution_list_id`` ──
    # La PK composite ``(contact_id, distribution_list_id)`` ne sert pas
    # un filtre par ``distribution_list_id`` seul (préfixe = contact_id).
    # Sans cet index : full-scan O(n) sur ``get_distribution_list`` et
    # ``batch_add_members`` dès quelques milliers d'associations.
    _Migration(
        "contact_list_association",
        "ix_assoc_distribution_list_id",
        "CREATE INDEX IF NOT EXISTS ix_assoc_distribution_list_id "
        "ON contact_list_association(distribution_list_id)",
        "index",
    ),
    # ── Single source of truth — accounting LLM ──
    # Le hook central ``llm_call_tracker`` écrit une ligne par appel LLM
    # (Iris, sync, copilote, automations, anonymizer, etc.). Avant ces
    # colonnes, seul ~5% du trafic réel était capturé (cf. dashboard qui
    # affichait des chiffres divisés par 10× la facture Anthropic réelle).
    _Migration(
        "ai_performance_logs",
        "cache_read_tokens",
        "ALTER TABLE ai_performance_logs ADD COLUMN cache_read_tokens INTEGER",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "cache_creation_tokens",
        "ALTER TABLE ai_performance_logs ADD COLUMN cache_creation_tokens INTEGER",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "thinking_tokens",
        "ALTER TABLE ai_performance_logs ADD COLUMN thinking_tokens INTEGER",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "cost_usd_snapshot",
        "ALTER TABLE ai_performance_logs ADD COLUMN cost_usd_snapshot FLOAT",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "caller",
        "ALTER TABLE ai_performance_logs ADD COLUMN caller VARCHAR(64)",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "conversation_id",
        "ALTER TABLE ai_performance_logs ADD COLUMN conversation_id VARCHAR(64)",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "request_id",
        "ALTER TABLE ai_performance_logs ADD COLUMN request_id VARCHAR(64)",
        "column",
    ),
    _Migration(
        "ai_performance_logs",
        "idx_perf_caller_date",
        "CREATE INDEX IF NOT EXISTS idx_perf_caller_date "
        "ON ai_performance_logs(caller, created_at)",
        "index",
    ),
    _Migration(
        "ai_performance_logs",
        "idx_perf_conversation",
        "CREATE INDEX IF NOT EXISTS idx_perf_conversation "
        "ON ai_performance_logs(conversation_id)",
        "index",
    ),
    # --- Extension anonymization_terms (page /data/privacy SoT, 2026-05-06) ---
    # Ajoute 8 colonnes pour piloter la page Confidentialité utilisateur :
    # category sémantique, source d'extraction, last_seen_at pour TTL,
    # usage_count pour heat, auto_proposed pour distinguer manuel/Ollama,
    # risk_level pour le badge global, replacement_strategy pour la sub.
    _Migration(
        "anonymization_terms",
        "category",
        "ALTER TABLE anonymization_terms ADD COLUMN category VARCHAR(50) "
        "NOT NULL DEFAULT 'unclassified'",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "source",
        "ALTER TABLE anonymization_terms ADD COLUMN source VARCHAR(50) "
        "NOT NULL DEFAULT 'manual'",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "source_ref",
        "ALTER TABLE anonymization_terms ADD COLUMN source_ref VARCHAR(200)",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "last_seen_at",
        "ALTER TABLE anonymization_terms ADD COLUMN last_seen_at DATETIME",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "usage_count",
        "ALTER TABLE anonymization_terms ADD COLUMN usage_count INTEGER " "NOT NULL DEFAULT 0",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "auto_proposed",
        "ALTER TABLE anonymization_terms ADD COLUMN auto_proposed BOOLEAN "
        "NOT NULL DEFAULT FALSE",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "risk_level",
        "ALTER TABLE anonymization_terms ADD COLUMN risk_level VARCHAR(20) "
        "NOT NULL DEFAULT 'low'",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "replacement_strategy",
        "ALTER TABLE anonymization_terms ADD COLUMN replacement_strategy VARCHAR(50) "
        "NOT NULL DEFAULT 'pseudo'",
        "column",
    ),
    # task #20 — Origines du token (classeur + colonne) sérialisées en JSON
    # texte pour rester agnostique du dialect (SQLite/PostgreSQL). Nullable
    # car les rows historiques pré-task #20 et les ajouts manuels n'ont pas
    # de provenance par colonne.
    #
    # **Rollback (task #27)** : cette migration est **forward-only** sur
    # SQLite < 3.35.0. SQLite a introduit ``ALTER TABLE DROP COLUMN``
    # uniquement en 3.35.0 (2021-03). Pour un rollback complet sur des
    # versions antérieures il faudrait recréer la table sans la colonne
    # (CREATE TABLE new + INSERT SELECT + DROP + RENAME). Komptia déploie
    # généralement sur Python 3.10+ avec sqlite3 ≥ 3.36 (CPython
    # vendored) ⇒ ``DROP COLUMN`` est dispo. Documenter ici si déploiement
    # sur stack plus vieille.
    _Migration(
        "anonymization_terms",
        "origins",
        "ALTER TABLE anonymization_terms ADD COLUMN origins VARCHAR(5000)",
        "column",
    ),
    # Indexes pour les filtres de la page (catégorie, risque, récence).
    _Migration(
        "anonymization_terms",
        "ix_anon_term_user_category",
        "CREATE INDEX IF NOT EXISTS ix_anon_term_user_category "
        "ON anonymization_terms(user_id, category)",
        "index",
    ),
    _Migration(
        "anonymization_terms",
        "ix_anon_term_user_risk",
        "CREATE INDEX IF NOT EXISTS ix_anon_term_user_risk "
        "ON anonymization_terms(user_id, risk_level)",
        "index",
    ),
    _Migration(
        "anonymization_terms",
        "ix_anon_term_user_last_seen",
        "CREATE INDEX IF NOT EXISTS ix_anon_term_user_last_seen "
        "ON anonymization_terms(user_id, last_seen_at)",
        "index",
    ),
    _Migration(
        "anonymization_terms",
        "ix_anon_term_user_source",
        "CREATE INDEX IF NOT EXISTS ix_anon_term_user_source "
        "ON anonymization_terms(user_id, source)",
        "index",
    ),
    # Critical #37 review : index pour le gate 409 ANON_PENDING_REVIEW
    # (``WHERE user_id = ? AND confirmed = ?``) — lecture chaude.
    _Migration(
        "anonymization_terms",
        "ix_anonymization_term_user_confirmed",
        "CREATE INDEX IF NOT EXISTS ix_anonymization_term_user_confirmed "
        "ON anonymization_terms(user_id, confirmed)",
        "index",
    ),
    # Defense-in-depth dédup case-insensitive (vision DYNAMIQUE "aucun
    # duplicate"). La dédup principale tourne en Python NFKC casefold dans
    # ``upsert_terms`` (Unicode-aware, indispensable pour ``É`` → ``é``,
    # ligatures, etc.). Cet index BDD est un FILET DE SÉCURITÉ contre :
    # (a) un INSERT direct SQL qui contournerait le repository, (b) un
    # bug futur dans la normalisation Python. ``lower()`` SQLite est
    # ASCII-naïf — il ne couvre pas tous les cas Unicode mais bloque les
    # 99% pratiques (DUPONT/Dupont/dupont). Les variantes Unicode pures
    # restent gérées exclusivement côté Python.
    #
    # Pré-requis : pas de doublons existants en BDD case-insensitive.
    # La migration ``data`` ci-dessous (cleanup_term_lower_dedup)
    # nettoie les doublons (garde le row id le plus ancien par groupe
    # ``(user_id, lower(term))``) AVANT que cette index ne soit créée.
    # L'ordre d'exécution est garanti par l'ordre du tuple ``_MIGRATIONS``.
    _Migration(
        "anonymization_terms",
        "cleanup_term_lower_dedup",
        # Supprime tous les rows qui ne sont PAS le MIN(id) de leur
        # groupe ``(user_id, lower(term))``. Garde donc UN row par
        # paire user/term-case-insensitive — celui inséré en premier.
        # Idempotent : 2ème run ne supprime plus rien (chaque groupe
        # n'a qu'un row).
        "DELETE FROM anonymization_terms WHERE id NOT IN ("
        "  SELECT MIN(id) FROM anonymization_terms "
        "  GROUP BY user_id, lower(term)"
        ")",
        "data",
        # Skip si l'index UNIQUE en aval existe déjà — preuve que le
        # cleanup a déjà tourné (sinon la création de l'index aurait
        # échoué). Court-circuite l'O(N) du DELETE à chaque boot.
        idempotency_check_sql=(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='index' AND name='uq_anon_term_user_term_lower'"
        ),
    ),
    _Migration(
        "anonymization_terms",
        "uq_anon_term_user_term_lower",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_anon_term_user_term_lower "
        "ON anonymization_terms(user_id, lower(term))",
        "index",
    ),
    # --- saved_queries : table droppee (cf. decision utilisateur 2026-05-05).
    # La SSoT pour les requetes Iris est le datastore filesystem (.sql files
    # dans la dir utilisateur, exposes via /api/datastore/sql/*). La table
    # SavedQuery n'avait aucun caller frontend (verifie grep) et 0 row en
    # BDD locale au moment du drop. Le modele, le handler et les 4 routes
    # /api/saved-queries* ont ete retires en meme temps.
    _Migration(
        "saved_queries",
        "drop_saved_queries_2026_05",
        "DROP TABLE IF EXISTS saved_queries",
        "drop_table",
    ),
    # --- Désimplantation du partage cross-user des dashboards (tâche #29) ---
    # Vision produit : aucun partage cross-user. Chaque user voit uniquement
    # ses propres dashboards. La table F_DASHBOARD_PERMISSION et la colonne
    # F_DASHBOARD.is_shared sont supprimées pour ne pas laisser de surface
    # backend exploitable par curl alors que l'UI est désactivée.
    _Migration(
        "F_DASHBOARD_PERMISSION",
        "drop_dashboard_permission_2026_05",
        "DROP TABLE IF EXISTS F_DASHBOARD_PERMISSION",
        "drop_table",
    ),
    _Migration(
        "F_DASHBOARD",
        "is_shared",
        "ALTER TABLE F_DASHBOARD DROP COLUMN is_shared",
        "drop_column",
    ),
    # ── Phase 2.5.6.ter (#100) — Traçabilité auto-pause des automations ──
    # Le ``__tablename__`` du modèle ``Automation`` est ``F_AUTOMATION`` :
    # toute migration sur ``"automations"`` est silencieusement skip par
    # ``_migration_already_applied`` (table introuvable) — cf. test de garde
    # ``tests/unit/test_migrations_table_name_consistency.py``.
    _Migration(
        "F_AUTOMATION",
        "paused_reason",
        "ALTER TABLE F_AUTOMATION ADD COLUMN paused_reason TEXT",
        "column",
    ),
    _Migration(
        "F_AUTOMATION",
        "paused_at",
        "ALTER TABLE F_AUTOMATION ADD COLUMN paused_at DATETIME",
        "column",
    ),
    # ── Phase 2.5.6.bis (#99) — Compteur d'échecs consécutifs non-RLS ──
    _Migration(
        "F_AUTOMATION",
        "consecutive_failure_count",
        "ALTER TABLE F_AUTOMATION ADD COLUMN consecutive_failure_count "
        "INTEGER NOT NULL DEFAULT 0",
        "column",
    ),
    # ── Phase 2.5.quinquies (#98) — Compteur de refus data_access par conv ──
    _Migration(
        "conversations",
        "consecutive_denied_count",
        "ALTER TABLE conversations ADD COLUMN consecutive_denied_count "
        "INTEGER NOT NULL DEFAULT 0",
        "column",
    ),
    # ── 2026-05-21 — Séparation conv widget vs conv page /iris ──
    # Avant : ``get_or_create_active_conversation`` retournait la seule conv
    # ``is_active=True`` de l'user pour le rôle ``iris``. Conséquence : les
    # messages envoyés via le floating widget polluaient la conversation
    # principale de la page ``/iris`` (et inversement). Le nouveau champ
    # ``source`` discrimine les deux entry points (cf. enum
    # ``ConversationSource`` dans ``app/models/conversation.py``).
    # Default ``'page'`` : les rows pré-migration s'auto-classent comme
    # « page » — la sémantique cohérente puisque le widget n'était utilisable
    # avant le fix qu'en parasitant la conv de la page.
    _Migration(
        "conversations",
        "source",
        "ALTER TABLE conversations ADD COLUMN source VARCHAR(20) " "NOT NULL DEFAULT 'page'",
        "column",
    ),
    _Migration(
        "conversations",
        "ix_conversations_source",
        "CREATE INDEX IF NOT EXISTS ix_conversations_source " "ON conversations(source)",
        "index",
    ),
    # **Partial unique index** ``(user_id, agent_role, source)`` limité aux
    # rows ``is_active = 1``. Ferme la race TOCTOU dans le SSOT
    # ``get_or_create_active_conversation`` : sans cet index, deux WS
    # concurrents du même user passant le SELECT à vide créeraient 2 conv
    # actives pour le même scope. Avec, l'INSERT concurrent perd lève
    # ``IntegrityError`` et le SSOT re-SELECT (cf. fix adversarial #1 du
    # 2026-05-21).
    _Migration(
        "conversations",
        "uq_conversations_active_scope",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_conversations_active_scope "
        "ON conversations(user_id, agent_role, source) "
        "WHERE is_active = 1",
        "index",
    ),
    # Index composite ``(agent_role, created_at)`` pour la query
    # d'agrégat d'``IrisUsageStatsAPIHandler`` (task #17). Sans cet
    # index, le filtre ``WHERE created_at >= since AND agent_role = ?``
    # force un full-table scan O(N) qui peut bloquer la boucle event
    # Tornado mono-process à 100k+ rows (adversarial #4 BLOCKING).
    # Composite (role, created_at) couvre aussi les futures queries qui
    # filtrent par rôle puis date.
    _Migration(
        "conversations",
        "ix_conversations_role_created",
        "CREATE INDEX IF NOT EXISTS ix_conversations_role_created "
        "ON conversations(agent_role, created_at)",
        "index",
    ),
    # **P0 (#125)** — Anti-doublon silencieux sur ``data_access_rules``.
    # Dédup AVANT la création de l'index, sinon échec sur doublons existants.
    # On garde le MIN(id) de chaque groupe (la règle la plus ancienne,
    # historique préservé).
    _Migration(
        "data_access_rules",
        "_dedupe_before_uq_dar",
        "DELETE FROM data_access_rules WHERE id NOT IN ("
        " SELECT MIN(id) FROM data_access_rules "
        " GROUP BY user_id, scope_type, table_name, "
        "  COALESCE(column_name, ''), effect"
        ")",
        "data",  # type "data" = exécution best-effort (idempotent via WHERE)
    ),
    _Migration(
        "data_access_rules",
        "uq_dar_user_scope_table_col_effect",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_dar_user_scope_table_col_effect "
        "ON data_access_rules(user_id, scope_type, table_name, "
        "COALESCE(column_name, ''), effect)",
        "index",
    ),
    # **#139 — Toast undo post-delete : soft-delete via ``deleted_at``**.
    # Un DELETE actuel est destructif et irréversible — un admin qui clique
    # sur la mauvaise règle perd la config (avec potentiellement W3 textarea
    # à 500 valeurs ressaisies). Le soft-delete + endpoint /restore + toast
    # "Annuler" 8s permet de récupérer la suppression dans la fenêtre UX
    # standard. ``deleted_at`` NULL = active ; non NULL = supprimée (filtrée
    # à la lecture). Indexé pour scan rapide ``WHERE deleted_at IS NULL``.
    _Migration(
        "data_access_rules",
        "deleted_at",
        "ALTER TABLE data_access_rules ADD COLUMN deleted_at DATETIME",
        "column",
    ),
    _Migration(
        "data_access_rules",
        "ix_data_access_rules_deleted_at",
        "CREATE INDEX IF NOT EXISTS ix_data_access_rules_deleted_at "
        "ON data_access_rules(deleted_at)",
        "index",
    ),
    # task #82 (adversarial fix CRITICAL #6) — migration défensive pour la
    # colonne `block_all_views` du modèle `PipelineRun`. Crée par
    # `Base.metadata.create_all` au boot frais ; pour les déploiements
    # existants où la colonne aurait pu être absente (BDD pré-feature ou
    # restore partielle), cet ALTER TABLE garantit son existence. Default
    # `0` (False) aligné avec le nouveau default Python.
    _Migration(
        "pipeline_runs",
        "block_all_views",
        "ALTER TABLE pipeline_runs ADD COLUMN block_all_views BOOLEAN NOT NULL DEFAULT 0",
        "column",
    ),
    # ── 2026-05-22 — /data-privacy = seule source de vérité (anonymisation) ──
    # Suppression du système d'anonymisation parallèle ``value_mapping``
    # (algorithme suppression-voyelles dans ``schema_enricher._anonymize_value``).
    # La table ``value_mapping`` reste comme cache des vraies valeurs Sage
    # (résolution de termes utilisateur), mais sa colonne ``anonymized_value``
    # disparaît. Les pseudonymes runtime sont désormais gérés exclusivement par
    # ``anonymization_terms`` (/data-privacy) + le ``Pseudonymizer``.
    #
    # 1a. DROP INDEX idx_vm_anon AVANT le drop_column : SQLite refuse
    #     ``DROP COLUMN`` si un index référence encore la colonne (erreur
    #     « error in index idx_vm_anon after drop column »). ``IF EXISTS``
    #     rend l'opération idempotente nativement. Le ``idempotency_check_sql``
    #     court-circuite en O(1) au 2ᵉ boot : ``SELECT 1 WHERE NOT EXISTS
    #     (... idx_vm_anon ...)`` retourne 1 row si l'index a déjà été
    #     droppé (= migration applied) ; 0 row sinon (= à exécuter).
    _Migration(
        "value_mapping",
        "drop_idx_vm_anon_2026_05_22",
        "DROP INDEX IF EXISTS idx_vm_anon",
        "data",
        idempotency_check_sql=(
            "SELECT 1 WHERE NOT EXISTS ("
            "SELECT 1 FROM sqlite_master "
            "WHERE type='index' AND name='idx_vm_anon'"
            ")"
        ),
    ),
    # 1b. DROP COLUMN value_mapping.anonymized_value (≥ 29 M lignes possibles ;
    #     SQLite 3.35+ requis — détection via _migration_already_applied).
    _Migration(
        "value_mapping",
        "anonymized_value",
        "ALTER TABLE value_mapping DROP COLUMN anonymized_value",
        "drop_column",
    ),
    # 2. value_mapping_archive : snapshot legacy SUPPRIMÉ 2026-06-11 sur demande
    #    utilisateur (David). C'était un snapshot one-shot de l'ancien cache
    #    ``value_mapping`` (système d'anonymisation lossy pré-2026-05-22, retiré).
    #    Plus AUCUN lecteur runtime (modèle + audit script + tests retirés ;
    #    aucune FK ni dépendance). DROP pour libérer l'espace (~Go : snapshot
    #    d'un value_mapping à 29M+ rows) en dev ET prod au prochain boot.
    #    ``IF EXISTS`` natif → idempotent.
    _Migration(
        "value_mapping_archive",
        "drop_value_mapping_archive_2026_06_11",
        "DROP TABLE IF EXISTS value_mapping_archive",
        "drop_table",
    ),
    # 3. DROP des 5 tables FTS5 dérivées de value_mapping (orphelines après
    #    suppression de anonymized_value — les triggers FTS pointaient sur
    #    cette colonne). Tables virtuelles SQLite ; ``IF EXISTS`` natif.
    _Migration(
        "value_mapping_fts",
        "drop_value_mapping_fts_2026_05_22",
        "DROP TABLE IF EXISTS value_mapping_fts",
        "drop_table",
    ),
    _Migration(
        "value_mapping_fts_config",
        "drop_value_mapping_fts_config_2026_05_22",
        "DROP TABLE IF EXISTS value_mapping_fts_config",
        "drop_table",
    ),
    _Migration(
        "value_mapping_fts_data",
        "drop_value_mapping_fts_data_2026_05_22",
        "DROP TABLE IF EXISTS value_mapping_fts_data",
        "drop_table",
    ),
    _Migration(
        "value_mapping_fts_docsize",
        "drop_value_mapping_fts_docsize_2026_05_22",
        "DROP TABLE IF EXISTS value_mapping_fts_docsize",
        "drop_table",
    ),
    _Migration(
        "value_mapping_fts_idx",
        "drop_value_mapping_fts_idx_2026_05_22",
        "DROP TABLE IF EXISTS value_mapping_fts_idx",
        "drop_table",
    ),
    # 4. Recréer FTS5 trigram sur ``real_value`` (sans anonymized_value).
    #    Sans cette FTS5, ``orchestrator_search`` retombe sur OR LIKE direct
    #    sur 29M+ rows → recherche `contains` qui prend ~8min (vs <2s avec
    #    FTS5). Détecté en runtime, fix appliqué le 2026-05-22.
    #
    #    On crée la table virtuelle FTS5 + 3 triggers (insert/delete/update)
    #    qui synchronisent automatiquement value_mapping ↔ FTS5. Le content
    #    table='value_mapping' évite la duplication des données (FTS5 ne
    #    stocke qu'un index trigram, pas les valeurs).
    #
    #    Idempotence : ``CREATE ... IF NOT EXISTS`` natif SQLite. La sentinelle
    #    O(1) court-circuite quand la table existe déjà.
    _Migration(
        "value_mapping",
        "create_value_mapping_fts_real_2026_05_22",
        (
            "CREATE VIRTUAL TABLE IF NOT EXISTS value_mapping_fts "
            "USING fts5(real_value_lower, content='value_mapping', "
            "content_rowid='id', tokenize='trigram')"
        ),
        "data",
        idempotency_check_sql=(
            "SELECT 1 FROM sqlite_master " "WHERE type='table' AND name='value_mapping_fts'"
        ),
        source_table="value_mapping",
    ),
    # Backfill : indexer toutes les lignes existantes de value_mapping dans
    # FTS5. Au 1er run après création de la table, FTS5 est vide. Le INSERT
    # SELECT remplit l'index ; sur 29M lignes, prend ~1-2 minutes mais une
    # seule fois. La sentinelle ``SELECT COUNT(*) FROM value_mapping_fts > 0``
    # court-circuite ensuite. Si jamais l'index est vidé manuellement, le
    # backfill se relance automatiquement au prochain boot.
    _Migration(
        "value_mapping_fts",
        "backfill_value_mapping_fts_2026_05_22",
        (
            "INSERT INTO value_mapping_fts(rowid, real_value_lower) "
            "SELECT id, real_value_lower FROM value_mapping"
        ),
        "data",
        idempotency_check_sql=("SELECT 1 FROM value_mapping_fts LIMIT 1"),
        source_table="value_mapping_fts",
    ),
    # Triggers de sync value_mapping → FTS5. Permettent à FTS5 de rester à
    # jour quand le sync programmatique INSERT/DELETE des rows. Idempotent
    # via ``CREATE ... IF NOT EXISTS``.
    _Migration(
        "value_mapping",
        "create_vm_fts_trigger_ai_2026_05_22",
        (
            "CREATE TRIGGER IF NOT EXISTS vm_fts_ai AFTER INSERT ON value_mapping "
            "BEGIN INSERT INTO value_mapping_fts(rowid, real_value_lower) "
            "VALUES (new.id, new.real_value_lower); END"
        ),
        "data",
        idempotency_check_sql=(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='vm_fts_ai'"
        ),
        source_table="value_mapping",
    ),
    _Migration(
        "value_mapping",
        "create_vm_fts_trigger_ad_2026_05_22",
        (
            "CREATE TRIGGER IF NOT EXISTS vm_fts_ad AFTER DELETE ON value_mapping "
            "BEGIN INSERT INTO value_mapping_fts(value_mapping_fts, rowid, real_value_lower) "
            "VALUES ('delete', old.id, old.real_value_lower); END"
        ),
        "data",
        idempotency_check_sql=(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='vm_fts_ad'"
        ),
        source_table="value_mapping",
    ),
    _Migration(
        "value_mapping",
        "create_vm_fts_trigger_au_2026_05_22",
        (
            "CREATE TRIGGER IF NOT EXISTS vm_fts_au AFTER UPDATE ON value_mapping "
            "BEGIN INSERT INTO value_mapping_fts(value_mapping_fts, rowid, real_value_lower) "
            "VALUES ('delete', old.id, old.real_value_lower); "
            "INSERT INTO value_mapping_fts(rowid, real_value_lower) "
            "VALUES (new.id, new.real_value_lower); END"
        ),
        "data",
        idempotency_check_sql=(
            "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name='vm_fts_au'"
        ),
        source_table="value_mapping",
    ),
    # --- Mémoire Iris user-scoped (parité ``copilot_memory`` côté workbook) ---
    # 1 string consolidée par user, injectée inconditionnellement dans le
    # system prompt de toutes les conversations Iris de ce user. Auto-mise
    # à jour fin-de-run via fusion LLM (cf. ``app/services/ai/iris_user_memory.py``).
    # Cap ≤ 2000 chars (cf. ``IRIS_USER_MEMORY_MAX_OUTPUT_CHARS``) — l'ALTER
    # n'impose pas la longueur côté SQLite (TEXT n'a pas de cap natif), mais
    # la sanitization runtime + l'écriture via service garantissent le cap.
    _Migration(
        "users",
        "iris_memory",
        "ALTER TABLE users ADD COLUMN iris_memory TEXT",
        "column",
    ),
    # Désactiver les anciennes entries ``user_preference`` du module
    # ``agent_memory`` (catégorie supprimée le 2026-05-22 — remplacée par
    # ``User.iris_memory``). Les rows restent en BDD pour traçabilité audit
    # (``is_active=False`` au lieu d'un DELETE). Self-idempotent : la clause
    # WHERE ne matche plus aucune row au 2ᵉ run (effet du UPDATE précédent).
    _Migration(
        "training_data",
        "deactivate_legacy_agent_memory_user_preference",
        (
            "UPDATE training_data SET is_active = 0 "
            "WHERE source = 'iris_memory' "
            "  AND category = 'user_preference' "
            "  AND is_active = 1"
        ),
        "data",
    ),
    # Cluster-N 2026-05-26 — Multi-tab optimistic concurrency.
    # Colonne `version` pour optimistic locking via header `If-Match` /
    # ETag. Évite la perte silencieuse de données quand 2 onglets éditent
    # la même automation : 2ᵉ PUT reçoit 409 Conflict. Default 1 pour
    # les rows existantes (legacy autos ré-utilisent le compteur à 1).
    _Migration(
        "F_AUTOMATION",
        "version",
        "ALTER TABLE F_AUTOMATION ADD COLUMN version INTEGER NOT NULL DEFAULT 1",
        "column",
    ),
    # 2026-05-26 — Étend la session quand "Garder ma session ouverte" coché
    # (bug user-reported : checkbox "Se souvenir de moi" sans effet sur la
    # session BDD, qui plafonnait à 8h). La colonne pilote la durée dans
    # ``Session.refresh()`` et ``SessionManager.create_session(remember_me)``.
    # Default 0 = false (sessions legacy gardent le comportement 8h actuel).
    _Migration(
        "sessions",
        "remember_me",
        "ALTER TABLE sessions ADD COLUMN remember_me BOOLEAN NOT NULL DEFAULT 0",
        "column",
    ),
    # 2026-05-28 — Suppression de la feature "Exercice fiscal" (page admin
    # /admin/fiscal-period). La config singleton n'était plus consommée que
    # par sa propre page admin depuis le 2026-05-22 (task #90, retrait de
    # l'injection LLM du jargon sectoriel). Drop de la table orpheline.
    _Migration(
        "fiscal_period_config",
        "drop_fiscal_period_config_2026_05_28",
        "DROP TABLE IF EXISTS fiscal_period_config",
        "drop_table",
    ),
    # 2026-05-28 — Index composite pour le scope non-admin de /email-history
    # (``WHERE sent_by_user_id = ? ORDER BY sent_at DESC``). Sans lui, chaque
    # page de l'historique fait un full scan d'une table à TTL long → lent en
    # multi-user. ``automation_id``/``execution_id``/``sent_at`` étaient déjà
    # indexés, mais pas ``sent_by_user_id`` (le filtre du scope user).
    _Migration(
        "email_logs",
        "ix_email_logs_sender_sent",
        "CREATE INDEX IF NOT EXISTS ix_email_logs_sender_sent "
        "ON email_logs(sent_by_user_id, sent_at)",
        "index",
    ),
    # Feature « arrêt de la pipeline à une phase choisie » (preview Iris —
    # docs/design/iris_stop_at_phase.md). Colonne ADD-only : NULL = run
    # complet (rétro-compat). Le statut STOPPED_EARLY ajouté à l'enum
    # PipelineRunStatus n'exige PAS de migration (SQLEnum sans CHECK sur
    # SQLite — create_constraint=False par défaut → VARCHAR libre).
    _Migration(
        "pipeline_runs",
        "stop_after_phase",
        "ALTER TABLE pipeline_runs ADD COLUMN stop_after_phase VARCHAR(20)",
        "column",
    ),
    # B6 (bug hunt) — idempotence resume : lien preview→continuation pour
    # refuser un 2e resume tant qu'un enfant non-terminal existe. Colonne
    # ADD-only + index (fresh DB l'a via le modèle ; existante via ces 2
    # migrations). NULL = run normal (pas une continuation).
    _Migration(
        "pipeline_runs",
        "resumed_from_run_id",
        "ALTER TABLE pipeline_runs ADD COLUMN resumed_from_run_id INTEGER",
        "column",
    ),
    _Migration(
        "pipeline_runs",
        "ix_pipeline_runs_resumed_from",
        "CREATE INDEX IF NOT EXISTS ix_pipeline_runs_resumed_from "
        "ON pipeline_runs(resumed_from_run_id)",
        "index",
    ),
    # anonymization_terms.term_canonical (2026-06-09) : clé canonique NFKD
    # strip-accents + casefold, pour les lectures scopées case/accent-
    # insensibles (copilot scope + strategies proper-noun lookup). La colonne
    # est ajoutée ici (vide), puis BACKFILLÉE en Python au boot
    # (``_backfill_anonymization_term_canonical``) — le canonical ne peut PAS
    # être calculé en SQL (NFKD n'existe pas côté SQLite). Les écritures
    # ultérieures peuplent via ``repository.upsert_terms``.
    _Migration(
        "anonymization_terms",
        "term_canonical",
        "ALTER TABLE anonymization_terms ADD COLUMN term_canonical VARCHAR(500)",
        "column",
    ),
    _Migration(
        "anonymization_terms",
        "ix_anonymization_term_user_canonical",
        "CREATE INDEX IF NOT EXISTS ix_anonymization_term_user_canonical "
        "ON anonymization_terms(user_id, term_canonical)",
        "index",
    ),
    # F_WEBHOOK_TRIGGER.hmac_secret (FAILLE 2, 2026-06-12) : secret partagé
    # HMAC-SHA256 par webhook (signature X-Komptia-Signature sur l'inbound).
    # NULL = compat token-seul (webhooks existants inchangés) ; le secret est
    # généré côté serveur à la création (``require_signature: true``) ou à la
    # rotation. Fresh DB : colonne créée via le modèle ; existante : ici.
    _Migration(
        "F_WEBHOOK_TRIGGER",
        "hmac_secret",
        "ALTER TABLE F_WEBHOOK_TRIGGER ADD COLUMN hmac_secret VARCHAR(128)",
        "column",
    ),
)


async def _table_exists(conn: AsyncConnection, table: str) -> bool:
    """Vrai si ``table`` figure dans ``sqlite_master`` (vue ou table)."""
    result = await conn.execute(
        text("SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') AND name = :name"),
        {"name": table},
    )
    return result.scalar() is not None


async def _column_exists(conn: AsyncConnection, table: str, column: str) -> bool:
    """Vrai si ``column`` existe déjà sur ``table`` (via ``PRAGMA table_info``)."""
    if not _SQLITE_IDENT_RE.fullmatch(table):
        # Défense en profondeur : PRAGMA ne supporte pas le binding ``?``,
        # donc on doit valider le nom. ``_MIGRATIONS`` contient des litéraux,
        # mais un futur contributeur pourrait étendre la liste.
        raise ValueError(f"Nom de table invalide: {table!r}")
    result = await conn.execute(text(f"PRAGMA table_info({table})"))
    return any(row[1] == column for row in result.fetchall())


async def _migration_already_applied(conn: AsyncConnection, migration: _Migration) -> bool:
    """Détecte si une migration a déjà été appliquée, sans l'exécuter.

    Approche déterministe basée sur l'introspection du schéma — évite de
    reposer sur le texte des messages d'erreur SQLite, qui varie selon la
    version et peut masquer des erreurs réelles (table absente, contrainte
    violée, etc.).
    """
    if migration.kind == "column":
        if not await _table_exists(conn, migration.table):
            # La table n'existe pas encore : ``create_all`` la créera avec le
            # schéma courant (incluant la colonne). La migration est alors
            # sans objet ; marquer "applied" pour la sauter.
            return True
        return await _column_exists(conn, migration.table, migration.name)
    if migration.kind == "index":
        # ``CREATE INDEX IF NOT EXISTS`` est idempotent nativement ; on exécute
        # toujours, la requête ne lève pas si l'index existe.
        return False
    if migration.kind == "data":
        # Si la table cible n'existe pas (boot frais), il n'y a rien à
        # corriger ; on saute pour éviter "no such table" à la 1ʳᵉ
        # initialisation. Une fois ``create_all`` exécuté, la table existe
        # et la migration data tournera au prochain boot.
        if not await _table_exists(conn, migration.table):
            return True
        # Idem pour la table SOURCE quand la migration fait un INSERT...SELECT
        # FROM source_table. Sans ce check, un boot avec ``value_mapping``
        # absent (BDD partielle, table supprimée manuellement) crashait sur
        # ``no such table: value_mapping`` au lieu de skipper proprement.
        if migration.source_table and not await _table_exists(conn, migration.source_table):
            return True
        # Pre-check optionnel : pour les migrations one-shot avec sentinelle
        # indexable, ``idempotency_check_sql`` permet de court-circuiter en
        # O(1) au lieu de réexécuter ``sql`` (qui peut être O(N) sur la
        # source même quand la WHERE NOT EXISTS rend l'effet nul). Si le
        # SELECT retourne ≥ 1 row, la migration est considérée déjà
        # appliquée. Toute exception est laissée remonter — un check
        # cassé est un bug d'auteur, pas un cas runtime.
        if migration.idempotency_check_sql is not None:
            result = await conn.execute(text(migration.idempotency_check_sql))
            if result.scalar() is not None:
                return True
        # ``data`` migrations doivent être self-idempotentes (WHERE clause
        # qui ne matche plus rien après la 1ʳᵉ exécution). On les exécute
        # à chaque boot — c'est volontaire, pour rattraper les rows
        # corrompues qui pourraient apparaître hors-migration (script
        # ad-hoc, INSERT direct, restore d'un dump ancien).
        return False
    if migration.kind == "drop_table":
        # Migration appliquee = la table n'existe plus (ou n'a jamais
        # existe sur ce deploiement). On saute le DROP dans les deux cas.
        return not await _table_exists(conn, migration.table)
    if migration.kind == "drop_column":
        # Migration appliquee = la colonne n'existe plus. Si la table elle-meme
        # est absente (boot frais sans la colonne), on saute aussi : ``create_all``
        # a deja produit le schema courant (sans la colonne).
        if not await _table_exists(conn, migration.table):
            return True
        if await _column_exists(conn, migration.table, migration.name):
            # La colonne est encore presente — il faudra DROP. Verifier la
            # version SQLite AVANT pour donner un message actionnable a
            # l'admin (la stack ``OperationalError: near DROP`` n'aide pas).
            if sqlite3.sqlite_version_info < (3, 35, 0):
                raise RuntimeError(
                    f"Migration drop_column {migration.table}.{migration.name} "
                    f"requiert SQLite >= 3.35.0 pour ALTER TABLE DROP COLUMN. "
                    f"Version detectee: {sqlite3.sqlite_version}. "
                    f"Mettez a jour SQLite ou utilisez un script rebuild-table manuel."
                )
            return False
        return True
    raise ValueError(f"Kind de migration inconnu: {migration.kind!r}")


async def _normalize_users_email_case_insensitive(engine: AsyncEngine) -> None:
    """Normalise ``users.email`` en casefold Python ET détecte les doublons.

    Remplace l'ancienne migration SQL ``UPDATE email = LOWER(email)`` qui
    était ASCII-only (SQLite ``LOWER()`` ne folde pas ß, İ, sigma grec,
    accents Unicode). Au lieu de ça, on lit toutes les rows en Python,
    on applique :func:`casefold_email` (Unicode-aware), on détecte les
    doublons post-casefold, puis on UPDATE par id.

    **Fail-fast** si doublons détectés : le système ne peut pas choisir
    laquelle des rows fusionner. Un admin doit nettoyer manuellement.
    L'env var ``KOMPTIA_SKIP_EMAIL_DEDUP_CHECK=1`` court-circuite le check
    (loggé CRITICAL) — escape-hatch pour débloquer un boot d'urgence et
    nettoyer ensuite via ``/admin/users``.

    Idempotente : sur 2ᵉ run, toutes les rows sont déjà casefoldées →
    aucune UPDATE émise. Skippée silencieusement si la table ``users``
    n'existe pas (boot frais avant ``create_all``).
    """
    from app.core.constants_auth import casefold_email

    skip_check = os.environ.get("KOMPTIA_SKIP_EMAIL_DEDUP_CHECK", "").lower() in (
        "1",
        "true",
        "yes",
    )

    async with engine.begin() as conn:
        # Skip si table absente (boot frais — la table sera créée par
        # ``Base.metadata.create_all`` juste après).
        check = await conn.execute(
            text("SELECT name FROM sqlite_master " "WHERE type='table' AND name='users'")
        )
        if check.first() is None:
            return

        # Lecture en Python pour casefold Unicode-aware (≠ SQLite LOWER()).
        rows = (await conn.execute(text("SELECT id, email FROM users"))).fetchall()
        if not rows:
            return

        # Détection doublons post-casefold.
        seen: dict[str, list[tuple[int, str]]] = {}
        for row_id, email in rows:
            if not isinstance(email, str):
                continue
            folded = casefold_email(email)
            if not folded:
                continue
            seen.setdefault(folded, []).append((row_id, email))

        dupes = {k: v for k, v in seen.items() if len(v) > 1}
        if dupes and not skip_check:
            details = "\n".join(
                f"  - casefold={k!r} → ids={[r[0] for r in v]}, raw={[r[1] for r in v]}"
                for k, v in dupes.items()
            )
            raise RuntimeError(
                "Doublons case-insensitive (Unicode casefold) détectés sur "
                "``users.email`` :\n"
                f"{details}\n"
                "Depuis 2026-05-11, l'email est l'identifiant de login. "
                "L'unicité doit être case-insensitive Unicode-aware. Avant "
                "le prochain boot, un admin doit fusionner ou désambiguïser "
                "ces comptes manuellement (le système ne peut pas choisir "
                "lequel conserver à votre place).\n"
                "Escape-hatch : ``KOMPTIA_SKIP_EMAIL_DEDUP_CHECK=1`` permet "
                "de booter quand même (la normalisation casefold sera quand "
                "même appliquée — le 1er email rencontré pour chaque casefold "
                "écrasera les autres en cas de conflit)."
            )
        if dupes and skip_check:
            logger.critical(
                "KOMPTIA_SKIP_EMAIL_DEDUP_CHECK actif — doublons email "
                "ignorés au boot : %s. Action admin URGENTE requise.",
                list(dupes.keys()),
            )

        # UPDATE par id pour les rows dont l'email diffère de sa version
        # casefoldée. Self-idempotent : au 2ᵉ boot, toutes égales → 0 UPDATE.
        updated = 0
        for row_id, email in rows:
            if not isinstance(email, str):
                continue
            folded = casefold_email(email)
            if folded and folded != email:
                await conn.execute(
                    text("UPDATE users SET email = :email WHERE id = :id"),
                    {"email": folded, "id": row_id},
                )
                updated += 1
        if updated:
            logger.info(
                "users.email normalisé (Unicode casefold) : %d row(s) corrigée(s).",
                updated,
            )


async def _backfill_anonymization_term_canonical(engine: AsyncEngine) -> None:
    """Backfille ``anonymization_terms.term_canonical`` pour les rows legacy.

    Le canonical (NFKD strip-accents + casefold) ne peut PAS être calculé en
    SQL : SQLite n'a ni NFKD ni casefold Unicode-aware (son ``LOWER()`` est
    ASCII-only et ne retire pas les accents). On lit donc en Python les rows
    où ``term_canonical IS NULL`` et on applique
    :func:`app.services.anonymization.repository._canonical_key` — **SSoT**
    avec l'écrit (``upsert_terms``) et les lectures (``get_state_for_user``,
    ``strategies``). UPDATE par id en batches.

    Idempotente : au 2ᵉ boot, plus aucune row NULL → SELECT vide → no-op.
    Skippée si la table OU la colonne n'existe pas encore (boot frais avant
    ``create_all``, ou avant la migration ADD COLUMN — d'où l'appel APRÈS la
    boucle de migrations SQL).
    """
    # SSoT : la MÊME clé de match (case+accent+whitespace) que l'écrit
    # (``upsert_terms``) et les lectures scopées. ``""`` possible pour un terme
    # dégénéré (marques combinantes only) — stocké tel quel (non-NULL → pas
    # re-traité ; les lectures filtrent les clés vides).
    from app.services.anonymization.repository import _canonical_match_key

    async with engine.begin() as conn:
        check = await conn.execute(
            text(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='anonymization_terms'"
            )
        )
        if check.first() is None:
            return
        cols = (await conn.execute(text("PRAGMA table_info(anonymization_terms)"))).fetchall()
        if not any(c[1] == "term_canonical" for c in cols):
            return

        rows = (
            await conn.execute(
                text("SELECT id, term FROM anonymization_terms WHERE term_canonical IS NULL")
            )
        ).fetchall()
        if not rows:
            return

        update_sql = text(
            "UPDATE anonymization_terms SET term_canonical = :canon WHERE id = :cid"
        )
        updated = 0
        batch: list[dict[str, Any]] = []
        for row_id, term in rows:
            if not isinstance(term, str):
                # ``term`` est NOT NULL str ; un non-str = corruption → laissé
                # NULL et signalé par le WARNING post-backfill ci-dessous.
                continue
            batch.append({"cid": row_id, "canon": _canonical_match_key(term)})
            if len(batch) >= 500:
                await conn.execute(update_sql, batch)
                updated += len(batch)
                batch = []
        if batch:
            await conn.execute(update_sql, batch)
            updated += len(batch)
        if updated:
            logger.info(
                "Backfill anonymization_terms.term_canonical : %d row(s) legacy peuplée(s)",
                updated,
            )
        # Observabilité (review migration finding #8) : un reliquat NULL après
        # backfill = rows ``term`` non-str/corrompues, exclues des lectures
        # scopées. Visible plutôt que silencieux.
        remaining = (
            await conn.execute(
                text("SELECT COUNT(*) FROM anonymization_terms WHERE term_canonical IS NULL")
            )
        ).scalar()
        if remaining:
            logger.warning(
                "Backfill term_canonical : %d row(s) restent NULL (term non-str/corrompu ?) "
                "— exclues des lectures scopées copilot/strategies",
                remaining,
            )


async def _run_migrations(engine: AsyncEngine) -> None:
    """Applique les migrations additives définies dans ``_MIGRATIONS``.

    Chaque migration est idempotente (vérifiée via introspection avant
    exécution). Une erreur sur une migration interrompt la chaîne et est
    remontée — pas de fallback silencieux.

    Lance d'abord ``_normalize_users_email_case_insensitive`` qui :
    1. Détecte les doublons case-insensitive Unicode-aware (fail-fast,
       escape-hatch ``KOMPTIA_SKIP_EMAIL_DEDUP_CHECK=1``).
    2. Normalise ``users.email`` en casefold Python — bloque les migrations
       suivantes pour éviter qu'un ``CREATE UNIQUE INDEX ... NOCASE`` rate
       avec un message obscure SQLite (``UNIQUE constraint failed``) sur
       des doublons ASCII non encore nettoyés.
    """
    await _normalize_users_email_case_insensitive(engine)

    async with engine.begin() as conn:
        for migration in _MIGRATIONS:
            if await _migration_already_applied(conn, migration):
                continue
            try:
                result = await conn.execute(text(migration.sql))
                # Pour les ``data`` migrations, on logue le rowcount —
                # critique pour distinguer un no-op (déjà migré) d'un
                # backfill qui touche 100k rows. ``rowcount`` peut être
                # -1 sur certains drivers (inconnu) ; on n'affiche que
                # les valeurs positives. Skip le log si rowcount=0
                # (no-op silencieux pour ne pas polluer les logs à
                # chaque boot).
                if migration.kind == "data":
                    affected = getattr(result, "rowcount", -1)
                    if affected > 0:
                        logger.info(
                            "Migration data appliquée : %s.%s — %d row(s) corrigée(s)",
                            migration.table,
                            migration.name,
                            affected,
                        )
                    # rowcount == 0 ou -1 → no-op silencieux (cas attendu
                    # à chaque boot après la 1ʳᵉ exécution).
                else:
                    logger.info(
                        "Migration appliquée : %s.%s (%s)",
                        migration.table,
                        migration.name,
                        migration.kind,
                    )
            except Exception:
                logger.error(
                    "Échec migration %s.%s (%s)",
                    migration.table,
                    migration.name,
                    migration.kind,
                    exc_info=True,
                )
                raise

    # Backfill Python POST-migrations (la colonne term_canonical existe
    # désormais) — calcul du canonical impossible en SQL (NFKD/casefold).
    # FAIL-SOFT (review migration finding #2) : le backfill est idempotent et
    # ré-essayé au prochain boot ; une erreur transitoire (lock, I/O) ne doit
    # PAS bricker le boot. En cas d'échec, les rows non backfillées restent à
    # ``term_canonical=NULL`` → exclues des lectures scopées copilot/strategies
    # (PAS pire que l'état PRÉ-migration qui ratait déjà ces variantes ; le
    # path Iris principal scope=None n'est de toute façon pas concerné). Les
    # écritures ultérieures (``upsert_terms``) auto-réparent les rows touchées.
    try:
        await _backfill_anonymization_term_canonical(engine)
    except Exception:
        logger.warning(
            "Backfill anonymization_terms.term_canonical échoué (non-bloquant, "
            "ré-essai au prochain boot ; rows non backfillées exclues des "
            "lectures scopées d'ici là)",
            exc_info=True,
        )


# --- Tables vectorielles (sqlite-vec) ------------------------------------


async def _drop_vec_table(conn: AsyncConnection, name: str) -> None:
    """Supprime une table virtuelle ``vec0`` (utilisé en cas de migration de dimensions)."""
    if not _SQLITE_IDENT_RE.fullmatch(name):
        raise ValueError(f"Nom de table vectorielle invalide: {name!r}")
    await conn.execute(text(f"DROP TABLE IF EXISTS {name}"))


async def _create_vec_table(conn: AsyncConnection, name: str, dims: int) -> None:
    """Crée une table virtuelle ``vec0`` avec les dimensions voulues."""
    if not _SQLITE_IDENT_RE.fullmatch(name):
        raise ValueError(f"Nom de table vectorielle invalide: {name!r}")
    create_sql = (
        f"CREATE VIRTUAL TABLE IF NOT EXISTS {name} "
        f"USING vec0(id INTEGER PRIMARY KEY, embedding float[{int(dims)}])"
    )
    await conn.execute(text(create_sql))


def _is_vec_module_missing(exc: Exception) -> bool:
    """Vrai si ``exc`` signale l'absence du module ``vec0``."""
    msg = str(exc).lower()
    return any(marker in msg for marker in _VEC_MISSING_MARKERS)


def _is_dimension_mismatch(exc: Exception) -> bool:
    """Vrai si ``exc`` ressemble à une incompatibilité de dimensions vectorielles."""
    msg = str(exc).lower()
    return "dimension" in msg or "size" in msg or "mismatch" in msg


async def _probe_vec_table_dimensions(conn: AsyncConnection, name: str, expected_dims: int) -> bool:
    """Teste si la table ``name`` accepte des vecteurs de ``expected_dims`` dimensions.

    Retourne ``True`` si la dimension correspond (ou si l'erreur est non
    liée à la dimension — on conserve la table par prudence).
    Retourne ``False`` si la dimension ne correspond pas et que la table
    doit être recréée.
    """
    import numpy as np  # import local : numpy n'est nécessaire qu'ici

    test_vec = np.zeros(int(expected_dims), dtype=np.float32)
    try:
        await conn.execute(
            text(f"INSERT INTO {name}(id, embedding) VALUES (:tid, :emb)"),
            {"tid": _DIM_PROBE_ID, "emb": test_vec.tobytes()},
        )
    except Exception as exc:
        if _is_dimension_mismatch(exc):
            logger.warning(
                "Table vectorielle %s : dimensions incompatibles — recréation à %d",
                name,
                expected_dims,
            )
            return False
        logger.warning(
            "Table vectorielle %s : erreur inattendue (%s: %s) — recréation par sécurité",
            name,
            type(exc).__name__,
            exc,
        )
        return False
    # Nettoyer la ligne sonde (ID hors plage utilisée par l'application).
    await conn.execute(
        text(f"DELETE FROM {name} WHERE id = :tid"),
        {"tid": _DIM_PROBE_ID},
    )
    return True


async def _init_vector_tables(engine: AsyncEngine) -> None:
    """Crée (ou recrée) les tables virtuelles ``vec0`` pour les embeddings.

    Gère la migration des dimensions (ex : 1536 → 384) en testant une
    insertion sonde ; si la dimension ne correspond pas, la table est
    recréée. Si l'extension ``sqlite-vec`` n'est pas disponible, la fonction
    se termine proprement sans erreur.
    """
    from app.constants_ai import EMBEDDING_DIMENSIONS

    if not isinstance(EMBEDDING_DIMENSIONS, int) or EMBEDDING_DIMENSIONS < 1:
        logger.error(
            "EMBEDDING_DIMENSIONS invalide: %r — tables vectorielles non créées",
            EMBEDDING_DIMENSIONS,
        )
        return

    async with engine.begin() as conn:
        for name in _VEC_TABLE_NAMES:
            # 1) Table déjà présente ? Vérifier la dimension, sinon dropper.
            try:
                await conn.execute(text(f"SELECT embedding FROM {name} LIMIT 0"))
            except Exception as exc:
                if _is_vec_module_missing(exc):
                    logger.info("sqlite-vec indisponible — tables vectorielles non créées")
                    return
                # Table absente : on la créera plus bas.
            else:
                if not await _probe_vec_table_dimensions(conn, name, EMBEDDING_DIMENSIONS):
                    await _drop_vec_table(conn, name)

            # 2) Création (ou recréation si drop ci-dessus).
            try:
                await _create_vec_table(conn, name, EMBEDDING_DIMENSIONS)
            except Exception as exc:
                if _is_vec_module_missing(exc):
                    logger.info("sqlite-vec indisponible — tables vectorielles non créées")
                    return
                if "already exists" in str(exc).lower():
                    continue
                logger.warning("Création table vectorielle %s échouée: %s", name, exc)


# --- Cycle de vie de l'engine --------------------------------------------


def _local_engine_pool_kwargs() -> dict[str, Any]:
    """Kwargs de pool pour le moteur SQLite LOCAL async (lus depuis la config).

    Pool BORNÉ (``AsyncAdaptedQueuePool``) au lieu de ``NullPool`` : réutilise
    les connexions chaudes — les hooks ``connect`` (PRAGMA key + PRAGMAs) ne
    rejouent que sur une connexion physique NEUVE, pas à chaque session — et
    PLAFONNE la concurrence (``NullPool`` ouvrait une connexion + un thread
    aiosqlite par session, sans borne → explosion possible sous pic ou boucle).

    Tailles lues dans ``config.database.local_*`` — knobs DÉDIÉS, distincts de
    ``config.database.pool_size`` (executor de threads Sage). Les rares sessions
    tenues pendant un ``await`` long (sync registre Ollama, ingestion
    d'embeddings) sont des opérations à concurrence ≈ 1 → aucun risque
    d'épuisement avec ces bornes.
    """
    return {
        "poolclass": AsyncAdaptedQueuePool,
        "pool_size": config.database.local_pool_size,
        "max_overflow": config.database.local_max_overflow,
        "pool_timeout": config.database.local_pool_timeout,
    }


async def init_database() -> AsyncEngine:
    """Initialise l'engine, la factory de sessions et applique les migrations.

    Idempotent et safe sous appels concurrents (verrou asyncio) — toute
    séquence ``init_database() … init_database()`` retourne le même engine.
    Le moteur utilise un pool borné (``AsyncAdaptedQueuePool``, cf.
    ``_local_engine_pool_kwargs``) : les connexions chaudes sont réutilisées et
    la concurrence est plafonnée. Une connexion poolée est détenue par UNE seule
    session à la fois (jamais partagée entre coroutines), puis rendue au pool ;
    l'engine ne sert que la boucle Tornado (les jobs ont des engines séparés via
    ``make_sync_engine`` / ``make_async_engine``).
    """
    global _engine, _session_factory

    # Fast path sans lock : le cas commun après le premier init.
    if _engine is not None:
        return _engine

    async with _get_init_lock():
        # Double-check après lock : un autre appelant peut avoir init entretemps.
        if _engine is not None:
            return _engine

        database_url = get_database_url()
        logger.info("Initialisation base de données: %s", config.database.path)

        if not config.database.encryption_key:
            logger.warning("⚠️ Pas de clé de chiffrement configurée (SQLCIPHER_KEY)")

        # Active SQLCipher (no-op si pas de clé) AVANT create_async_engine, pour
        # que l'import d'aiosqlite déclenché par SQLAlchemy capture le DBAPI
        # sqlcipher3 (sinon la base chiffrée serait illisible).
        _bind_sqlcipher_if_configured()

        engine = create_async_engine(
            database_url,
            echo=config.database.echo,
            # Sérialiseur JSON tolérant (SSoT json_safe) — cf. make_sync_engine.
            json_serializer=dumps_safe,
            **_local_engine_pool_kwargs(),
        )
        _register_connection_hooks(engine)

        session_factory = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

        # Import tardif : enregistrer tous les modèles pour ``Base.metadata``
        # avant ``create_all``. Charger ``app.models`` au top-level créerait
        # un cycle d'import (models → database).
        import app.models  # noqa: F401

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        await _run_migrations(engine)
        await _init_vector_tables(engine)

        # Garde d'identité de déploiement (#8) : refuse le boot si la BDD locale
        # a été initialisée pour une AUTRE source SQL Server (volume/BDD partagé
        # par erreur entre 2 déploiements → corruption silencieuse des singletons).
        # Placé APRÈS les migrations idempotentes mais AVANT les seeds (écritures
        # singleton). La DeploymentIdentityError est PROPAGÉE volontairement (hors
        # try/except fail-soft) → boot refusé proprement par _init_database_blocking.
        # Reconfiguration légitime de la source : override KOMPTIA_ALLOW_DEPLOYMENT_REASSIGN.
        from app.services.deployment_identity import verify_deployment_identity

        verify_deployment_identity()

        _engine = engine
        _session_factory = session_factory

        # Seed initial du registre des modèles LLM. Idempotent : ne ré-insère
        # pas un modèle déjà présent. Permet à la table ``llm_models`` d'avoir
        # les modèles "connus" au premier démarrage, sans attendre que l'admin
        # déclenche une sync. Les sync API ultérieures viennent compléter /
        # actualiser depuis ``provider.list_models()``.
        try:
            from app.services.ai.llm_model_registry import get_llm_model_registry

            registry = get_llm_model_registry()
            async with session_factory() as session:
                added = await registry.seed_from_constants(session)
                if added:
                    logger.info("Registre LLM : %d modèles seedés depuis constants_ai", added)
        except Exception as exc:
            # Non-bloquant : le fallback ``constants_ai._MODELS`` reste utilisé
            # tant que la BDD n'a pas été peuplée. Ne pas crasher l'init pour
            # un seed best-effort.
            logger.warning("Seed du registre LLM a échoué (non-bloquant): %s", exc)

        # Ré-chiffrement one-shot des passwords SMTP legacy stockés en clair (#5c).
        # Idempotent (un password déjà chiffré est laissé intact) + fail-soft : ne
        # bloque jamais le boot ; un échec laisse le legacy lisible (decrypt_smtp_
        # password_lenient) + ré-chiffrable au prochain enregistrement admin (5b).
        try:
            from app.services.email.smtp_factory import reencrypt_legacy_smtp_passwords

            async with session_factory() as session:
                reenc = await reencrypt_legacy_smtp_passwords(session)
                if reenc:
                    logger.info("SMTP : %d password(s) legacy ré-chiffré(s) at-rest", reenc)
        except Exception as exc:  # noqa: BLE001 — non-bloquant
            logger.warning("Ré-chiffrement SMTP legacy a échoué (non-bloquant): %s", exc)

        # Auto-sync LiteLLM au 1er boot — plan dynamicité 2026-05-14.
        # Le seed `_MODELS` insère pricing=0.0 (placeholder), donc tant
        # qu'aucune sync n'a tourné, le dashboard /admin/usage affiche $0.
        # **Background non-bloquant** (asyncio.create_task) : sans ça le
        # boot Tornado serait bloqué jusqu'à 10s si LiteLLM/GitHub est
        # lent (review adversariale 2026-05-14 BLOCKING #3). Le healthcheck
        # /api/system/events doit répondre immédiatement, même si la sync
        # n'est pas finie. La 1ère minute, le dashboard cost montrera $0
        # — c'est explicite dans les logs ("Auto-sync LiteLLM en
        # arrière-plan…") + le warning [BILLING] alerte si appel LLM
        # arrive avant la fin de la sync.
        try:
            _boot_task = asyncio.create_task(
                _trigger_litellm_autosync_if_needed(session_factory),
                name="litellm_autosync_at_boot",
            )
            # Strong-ref + auto-release : empêche le GC silencieux de la task
            # avant la fin de la sync (sinon pricing resterait à $0). Cf.
            # ``_BOOT_BACKGROUND_TASKS`` ci-dessus.
            _BOOT_BACKGROUND_TASKS.add(_boot_task)
            _boot_task.add_done_callback(_BOOT_BACKGROUND_TASKS.discard)
        except Exception as exc:  # noqa: BLE001 — schedule create_task ne devrait jamais lever
            logger.warning(
                "Schedule auto-sync LiteLLM au boot a échoué (non-bloquant): %s",
                exc,
                exc_info=True,
            )

        logger.info("✅ Base de données initialisée")
        return engine


async def _trigger_litellm_autosync_if_needed(session_factory: Any) -> None:
    """Déclenche ``enrich_models_from_litellm`` en background si le registre
    n'a aucun modèle avec pricing non-zéro (= sync jamais réussie).

    Scheduled via ``asyncio.create_task`` au boot (non-bloquant). Best-
    effort : si fetch LiteLLM échoue (réseau, registre GitHub down), le
    boot continue. L'admin peut déclencher manuellement via le bouton
    dans ``/admin/ai-config``.

    **Force refresh** = True : au 1er boot, on accepte le coût d'un fetch
    HTTP (1 round-trip GitHub raw) pour garantir des prix frais — un
    cache disque hérité d'un build précédent serait potentiellement
    périmé sur les nouveaux modèles (review adversariale CRITICAL #12).
    """
    from sqlalchemy import func, select

    from app.models.llm_model import LlmModel
    from app.services.ai.litellm_registry_sync import enrich_models_from_litellm

    try:
        async with session_factory() as session:
            # Compte total de modèles + ceux avec pricing > 0
            total_result = await session.execute(select(func.count(LlmModel.id)))
            total_count = int(total_result.scalar() or 0)
            priced_result = await session.execute(
                select(func.count(LlmModel.id)).where(LlmModel.input_price_per_mtok_usd > 0.0)
            )
            priced_count = int(priced_result.scalar() or 0)

        if total_count == 0:
            # BDD vide depuis le plan dynamicité radical 2026-05-14 :
            # plus de seed `_MODELS`. L'auto-sync LiteLLM ne fait que
            # ENRICHIR les modèles existants, elle n'en CRÉE pas. Donc
            # tant qu'aucun admin n'a saisi une clé + cliqué "Tester"
            # (qui déclenche `sync_from_provider` → `provider.list_models()`
            # → insertion BDD), rien à enrichir. Logger explicitement
            # pour que l'opérateur sache qu'il faut une action admin.
            logger.info(
                "Auto-sync LiteLLM SKIP au boot : BDD `llm_models` vide. "
                "L'admin doit saisir une clé API dans /admin/ai-config et "
                "cliquer 'Tester' pour déclencher sync_from_provider et "
                "ajouter les modèles. L'auto-sync LiteLLM se redéclenchera "
                "au prochain boot pour enrichir."
            )
            return

        if total_count == priced_count:
            # 100% des modèles ont un pricing > 0 → sync complète, rien à
            # faire. L'admin peut forcer un refresh via /admin/ai-config
            # bouton "Mettre à jour fenêtres & tarifs".
            return

        # Au moins un modèle a pricing=0 → enrichissement nécessaire.
        # Couvre 2 cas : (a) BDD totalement non-priced (1ère sync provider
        # native sans avoir encore tourné LiteLLM) ; (b) BDD partiellement
        # priced (legacy seed avec quelques modèles non couverts par le
        # registre LiteLLM, ou modèle ajouté admin manuellement). Cf.
        # review adversariale 2026-05-14 BLOCKING #3 — avant ce fix,
        # ``priced_count > 0`` short-circuitait le cas (b) silencieusement.
        unpriced_count = total_count - priced_count
        logger.info(
            "Auto-sync LiteLLM en arrière-plan : %d/%d modèle(s) sans "
            "pricing > 0 détecté, fetch initial pour alimenter le "
            "dashboard cost. Le warning [BILLING] s'allume sur les "
            "appels LLM tant que la sync n'est pas finie.",
            unpriced_count,
            total_count,
        )
        async with session_factory() as session:
            stats = await enrich_models_from_litellm(
                session, force_refresh=True, allow_regression=False
            )
            logger.info(
                "Auto-sync LiteLLM terminée: %d modèles mis à jour sur %d scannés",
                stats.get("updated", 0),
                stats.get("scanned", 0),
            )
        # Le pricing vient d'être renseigné au boot → purger le throttle de
        # warning [BILLING] pour qu'un modèle 0/0 désormais tarifé soit
        # ré-évalué (sinon warning muet à vie après réparation — CRIT3 étendu
        # au path enrich). Best-effort, non-bloquant.
        try:
            from app.services.ai.llm_call_tracker import clear_pricing_warning_cache

            clear_pricing_warning_cache(None)
        except Exception:  # noqa: BLE001
            pass
    except Exception as exc:  # noqa: BLE001 — task scheduled, ne doit jamais cracher le worker
        logger.warning(
            "Auto-sync LiteLLM au boot a échoué (type=%s, non-bloquant) : %s — "
            "admin peut sync manuellement via /admin/ai-config",
            type(exc).__name__,
            exc,
            exc_info=True,
        )


async def close_database() -> None:
    """Dispose l'engine et réinitialise l'état module.

    Idempotent : safe à appeler plusieurs fois ou avant ``init_database``.
    Réinitialise également ``_sqlite_vec_available`` pour autoriser un
    hot-reload de l'extension dans un même processus (cas tests).
    """
    global _engine, _session_factory, _sqlite_vec_available

    if _engine is None:
        return

    # Annule + draine les tasks fire-and-forget de boot encore en vol AVANT de
    # disposer l'engine : depuis qu'elles sont strong-référencées, elles
    # survivent désormais de façon fiable à un close (utile surtout au cycle
    # close→init des tests / hot-reload) et tourneraient sinon contre un
    # ``session_factory`` disposé. ``_trigger_litellm_autosync_if_needed``
    # n'attrape que ``Exception`` (pas ``CancelledError`` = BaseException) →
    # l'annulation remonte proprement dans le ``gather(return_exceptions=True)``.
    pending_boot = list(_BOOT_BACKGROUND_TASKS)
    if pending_boot:
        for task in pending_boot:
            task.cancel()
        await asyncio.gather(*pending_boot, return_exceptions=True)

    engine_to_dispose = _engine
    _engine = None
    _session_factory = None
    _sqlite_vec_available = None
    await engine_to_dispose.dispose()
    logger.info("Base de données fermée")


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Retourne la factory de sessions active pour le contexte courant.

    Honore un override posé par ``dedicated_session_scope`` (jobs lancés via
    ``asyncio.run`` sur un thread → engine dédié à leur boucle). Sinon retourne
    la factory globale d'``init_database`` (boucle Tornado) ; échoue si l'init
    n'a pas eu lieu.
    """
    override = _session_factory_override.get()
    if override is not None:
        return override
    if _session_factory is None:
        raise RuntimeError("Base de données non initialisée. Appelez init_database() d'abord.")
    return _session_factory


@asynccontextmanager
async def dedicated_session_scope() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Engine async DÉDIÉ pour un job lancé via ``asyncio.run`` sur un thread.

    Les jobs APScheduler tournent dans un thread worker, sur une boucle asyncio
    NEUVE créée par ``asyncio.run``. L'engine global (``init_database``) a un pool
    lié à la boucle Tornado : une connexion poolée porte un thread aiosqlite + des
    futures liés à SA boucle → la réutiliser depuis la boucle du job lèverait
    ``RuntimeError: got Future attached to a different loop`` (ou corromprait la
    session). Ce scope crée un engine dédié à la boucle courante, fait que
    ``get_session`` / ``get_session_factory`` l'utilisent pour la durée du job
    (via ``_session_factory_override``), puis le dispose à la sortie.

    SSoT du pattern (avant : dupliqué inline dans ``run_daily_triggers_sync``).

    ⚠️ Invariant : tout ce que le job ``await`` — y compris les tasks différées
    qu'il planifie (ex. l'audit ``EmailLog`` de ``run_then_drain_email_log``) —
    doit s'exécuter DANS ce scope. Une task créée dans le contexte du scope hérite
    de l'override ; une planifiée hors scope retomberait sur l'engine global
    (cross-loop). Le wrapping enveloppe le job entier précisément pour cette raison.

    Usage::

        async def _job():
            async with dedicated_session_scope():
                await ...  # tout get_session() ici cible l'engine dédié
        asyncio.run(_job())
    """
    engine = make_async_engine()
    factory = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    token = _session_factory_override.set(factory)
    try:
        yield factory
    finally:
        # reset AVANT dispose : l'override est restauré même si dispose lève.
        _session_factory_override.reset(token)
        try:
            await engine.dispose()
        except Exception:  # noqa: BLE001 — ne JAMAIS masquer l'exception du job
            logger.warning(
                "dedicated_session_scope: engine.dispose() a échoué (ressources "
                "aiosqlite potentiellement non libérées)",
                exc_info=True,
            )


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Session ORM async avec commit/rollback/close automatiques.

    Usage::

        async with get_session() as session:
            result = await session.execute(select(User))

    Un commit est émis à la sortie normale ; toute exception déclenche un
    rollback et est ré-émise au caller.
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def execute_raw(
    sql: str,
    params: Mapping[str, Any] | None = None,
) -> Sequence[Row[Any]]:
    """Exécute une requête SQL brute et retourne les lignes.

    ⚠️ Helper bas niveau : ``sql`` est exécuté tel quel (pas de validation).
    Tout contenu utilisateur **doit** être passé via ``params`` (bindings
    nommés), jamais interpolé dans ``sql``. Réservé aux scripts
    d'administration et aux diagnostics — les handlers applicatifs passent
    par l'ORM ou par ``get_session`` directement.

    Example:
        >>> await execute_raw("SELECT id FROM users WHERE email = :email",
        ...                   {"email": "a@b.c"})
    """
    async with get_session() as session:
        result = await session.execute(text(sql), dict(params) if params else {})
        return result.fetchall()


__all__ = [
    "Base",
    "init_database",
    "close_database",
    "get_session",
    "get_session_factory",
    "dedicated_session_scope",
    "get_database_url",
    "get_db_url",
    "make_sync_engine",
    "make_async_engine",
    "open_local_sqlite_connection",
    "execute_raw",
]
