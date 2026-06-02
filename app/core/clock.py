"""Komptia — horloge centralisée. **SOURCE DE VÉRITÉ UNIQUE du temps.**

Toute lecture de « quelle heure est-il ? » dans Komptia DOIT passer par ce
module. La source est l'horloge de la **machine hôte** (l'OS sur lequel l'app
tourne), quelle que soit la plateforme, en dev comme en prod. Aucune source
externe (NTP, API web), aucune horloge falsifiée hors tests.

Pourquoi ce module existe
=========================
Avant centralisation, « maintenant » était copié-collé ~300 fois sous la forme
``datetime.now(timezone.utc)``, plus une quinzaine de ``datetime.now()`` naïfs,
quelques ``datetime.utcnow()`` (déprécié 3.12+), des ``func.now()`` SQL-side et
une résolution de timezone dupliquée (``_get_default_timezone`` dans la config,
``_resolve_scheduler_tz`` dans le scheduler). Impossible de changer la
convention en un seul endroit, impossible de figer l'horloge pour les tests, et
le mélange aware/naïf a déjà causé des incidents (cf. scheduler DST, fallback
``datetime.now()`` naïf). Ce module supprime cette dispersion.

Convention (décision produit « Option A », 2026-06-01)
======================================================
- :func:`now` retourne un ``datetime`` **AWARE en UTC**, dérivé de l'horloge
  machine. C'est le **drop-in exact** de l'ancien ``datetime.now(timezone.utc)``.
  Le stockage BDD reste en UTC (zéro migration, zéro corruption) ; l'affichage
  reste l'heure locale du navigateur (cf. ``static/js/local-datetime.js``).
- :func:`now_local` / :func:`today` exposent le **même instant** dans la TZ de
  la machine, pour l'affichage et les logs console qui veulent l'heure locale.
- Les mesures de **DURÉE** (elapsed) n'utilisent PAS ce module : ``time.monotonic()``
  / ``time.perf_counter()`` restent l'outil correct (monotones, insensibles aux
  sauts d'horloge). On ne mesure JAMAIS une durée avec :func:`now`.

Le SQL-side reste un miroir, pas un concurrent
==============================================
Les valeurs par défaut ORM ``func.now()`` (``CURRENT_TIMESTAMP`` côté SQLite)
sont conservées telles quelles : SQLite calcule ``CURRENT_TIMESTAMP`` en UTC
**sur la même horloge machine** que ce module. C'est donc le *miroir SQL-side*
de :func:`now`, pas une source concurrente. On ne les bascule pas vers
``default=clock.now`` pour ne pas changer la sémantique de stockage
(aware↔naïf) de dizaines de tables sans bénéfice.

Mockabilité (tests)
===================
Les helpers internes appellent :func:`now` par son **nom public** : un test peut
donc figer l'horloge globalement avec ``monkeypatch.setattr(clock, "now",
lambda: fixed)`` et :func:`now_local` / :func:`today` suivront. Ne pas introduire
de machinerie d'override en production (chemin chaud appelé des centaines de
fois) — le monkeypatch suffit côté tests.
"""

from __future__ import annotations

import time as _time
from datetime import date, datetime, timezone, tzinfo
from typing import Optional

__all__ = [
    "now",
    "now_local",
    "today",
    "timestamp",
    "machine_tz",
    "machine_tz_name",
    "from_timestamp",
    "local_from_timestamp",
    "naive_utc",
    "ensure_utc",
    "resolve_machine_tz_name",
]


# ---------------------------------------------------------------------------
# Instant courant (horloge machine)
# ---------------------------------------------------------------------------
def now() -> datetime:
    """Instant courant, **AWARE UTC**, lu sur l'horloge de la machine hôte.

    Drop-in exact de ``datetime.now(timezone.utc)`` : c'est l'instant canonique
    de tout Komptia (stockage, comparaisons d'expiration, horodatage).
    """
    return datetime.now(timezone.utc)


def now_local() -> datetime:
    """Instant courant **AWARE dans la TZ de la machine hôte**.

    Pour l'affichage / les logs console qui veulent l'heure locale du serveur.
    Appelle :func:`now` par son nom public pour rester mockable.
    """
    return now().astimezone(machine_tz())


def today() -> date:
    """Date courante dans la TZ de la machine hôte.

    Remplace ``date.today()`` / ``datetime.now().date()`` : la date est calculée
    dans la TZ machine (et non la TZ système ambiante du process, qui peut
    différer derrière un conteneur ``TZ=UTC``).
    """
    return now_local().date()


def timestamp() -> float:
    """Epoch POSIX (secondes, float) sur l'horloge machine.

    Drop-in de ``time.time()`` **quand il sert d'HORODATAGE** (token TTL, mtime,
    epoch stocké). NE PAS confondre avec une mesure de durée : pour mesurer un
    elapsed, utiliser ``time.monotonic()`` directement (ce module ne l'enveloppe
    pas volontairement, pour ne pas suggérer qu'on peut soustraire deux
    :func:`timestamp`).
    """
    return _time.time()


# ---------------------------------------------------------------------------
# Conversions epoch <-> datetime
# ---------------------------------------------------------------------------
def from_timestamp(epoch: float) -> datetime:
    """Epoch POSIX → ``datetime`` **AWARE UTC**."""
    return datetime.fromtimestamp(epoch, timezone.utc)


def local_from_timestamp(epoch: float) -> datetime:
    """Epoch POSIX → ``datetime`` **AWARE dans la TZ machine** (affichage humain).

    Remplace ``datetime.fromtimestamp(epoch)`` sans ``tz=`` — qui produisait
    silencieusement un naïf dans la TZ ambiante du process. Ici la TZ machine
    est explicite et centralisée.
    """
    return datetime.fromtimestamp(epoch, machine_tz())


def naive_utc() -> datetime:
    """:func:`now` en ``datetime`` **NAÏF** (``tzinfo`` retiré, valeur UTC).

    Pour les rares colonnes ORM ``DateTime`` sans ``timezone=True`` qui
    comparent en UTC naïf (ex. ``AIPerformanceLog.created_at``). Préférable au
    ``datetime.utcnow()`` déprécié, et passe par la même source que :func:`now`.
    """
    return now().replace(tzinfo=None)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Garantit qu'un ``datetime`` est aware UTC (ajoute UTC si naïf).

    SQLite renvoie des ``datetime`` naïfs (colonnes ``DateTime`` non-aware) :
    ce helper les normalise avant comparaison avec :func:`now`. Source unique —
    ``app.models.base.ensure_utc`` réexporte cette implémentation.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Résolution de la timezone machine (SSOT)
# ---------------------------------------------------------------------------
def resolve_machine_tz_name() -> str:
    """Retourne le nom IANA de la TZ locale de la **machine hôte**.

    Ex. ``Europe/Paris``, ``America/Guadeloupe``, ``UTC``. **Lecture OS pure** :
    aucune dépendance à ``app.config`` (cette fonction est appelée *pendant* le
    chargement de la config comme ``default_factory`` — elle doit donc rester
    sans cycle d'import).

    Stratégie de résolution (ordre de priorité) :

    1. ``tzlocal.get_localzone_name()`` — lib dédiée, IANA canonique. Chemin
       recommandé sur Linux/macOS modernes.
    2. Lecture du symlink ``/etc/localtime`` (UNIX) → suffixe sous
       ``/zoneinfo/`` (ex. ``Europe/Paris``).
    3. ``time.tzname[0]`` (legacy) — peut retourner un alias court non-IANA.
    4. ``UTC`` — fallback ultime (aucun crash au boot).

    Important : APScheduler (``CronTrigger`` / ``DateTrigger``) exige un IANA via
    ``zoneinfo.ZoneInfo`` pour localiser correctement les datetimes naïfs. La
    priorité 1 (tzlocal) règle ça pour la plupart des déploiements.
    """
    # Priorité 1 : tzlocal — recommandé pour IANA correct
    try:
        import tzlocal

        zone = tzlocal.get_localzone_name()
        if zone:
            return zone
    except Exception:
        pass
    # Priorité 2 : symlink /etc/localtime
    try:
        import os

        if os.path.islink("/etc/localtime"):
            target = os.readlink("/etc/localtime")
            marker = "/zoneinfo/"
            idx = target.find(marker)
            if idx != -1:
                start = idx + len(marker)
                return target[start:]
    except Exception:
        pass
    # Priorité 3 : time.tzname[0] (legacy, peut être un alias court)
    try:
        local_tz = _time.tzname[0] if _time.tzname else None
        if local_tz:
            return local_tz
    except Exception:
        pass
    # Priorité 4 : UTC fail-safe
    return "UTC"


def machine_tz_name() -> str:
    """Nom de la TZ machine **effective** (override admin honoré).

    Lit ``config.server.timezone`` (qui peut être surchargé via ``config.yaml``)
    et retombe sur :func:`resolve_machine_tz_name` si la config n'est pas
    chargeable. Import de la config **paresseux** (runtime) pour éviter tout
    cycle au chargement du module.
    """
    try:
        from app.config import config

        name = config.server.timezone
        if name:
            return name
    except Exception:
        pass
    return resolve_machine_tz_name()


def machine_tz() -> tzinfo:
    """Objet ``tzinfo`` de la machine hôte — **SSOT runtime de la TZ machine**.

    Construit un ``ZoneInfo`` à partir de :func:`machine_tz_name` ; retombe sur
    ``pytz`` (présence garantie via APScheduler 3.x) puis sur ``timezone.utc``
    si le nom est un alias non résoluble.

    Note — divergence volontaire avec le scheduler : ``automation/scheduler.
    _resolve_scheduler_tz`` NE délègue PAS ici. Il garde sa propre construction
    ``ZoneInfo`` qui laisse **remonter** une TZ invalide (fail-fast au boot du
    scheduler) au lieu de retomber silencieusement sur UTC — un décalage
    silencieux mis-schedulerait les automations. Les deux lisent néanmoins la
    **même** TZ machine (``config.server.timezone`` ← :func:`resolve_machine_tz_name`).
    """
    name = machine_tz_name()
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception:
        try:
            import pytz

            return pytz.timezone(name)
        except Exception:
            return timezone.utc
