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
from typing import Final, Optional, Union

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
    # Formatage FR locale-indépendant (SSoT — cf. plus bas)
    "MONTHS_FR",
    "MONTHS_FR_ABBR",
    "WEEKDAYS_FR",
    "WEEKDAYS_FR_ABBR",
    "strftime_fr",
    "format_date_fr",
    "format_local_fr",
    "to_local",
    "iso_utc",
]

#: Garde-fou one-shot : True une fois que :func:`machine_tz` a dû retomber sur
#: UTC faute de fuseau résoluble (évite de spammer le chemin chaud du warning).
_machine_tz_fallback_warned = False


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


# ---------------------------------------------------------------------------
# Formatage FR locale-indépendant — SOURCE DE VÉRITÉ UNIQUE des noms FR
# ---------------------------------------------------------------------------
# Pourquoi ici : l'image de prod (python:slim) n'embarque AUCUNE locale système
# (`fr_FR.UTF-8`), donc ``strftime("%B")`` rend « June » au lieu de « juin »
# (rapports, contexte date envoyé au LLM). Plutôt que d'ajouter le paquet
# ``locales`` + hardcoder ``fr_FR`` dans l'image (anti-générique, casserait un
# futur client non-FR), on substitue les noms FR EN CODE, indépendamment de l'OS.
# Komptia est une app francophone (UI FR, front ``toLocaleDateString('fr-FR')``).
# Ces tables remplacent les listes dupliquées (``iris_oneshot._MONTHS_FR``).

#: Mois en français — index = ``datetime.month - 1`` (0 = janvier).
MONTHS_FR: Final[tuple[str, ...]] = (
    "janvier",
    "février",
    "mars",
    "avril",
    "mai",
    "juin",
    "juillet",
    "août",
    "septembre",
    "octobre",
    "novembre",
    "décembre",
)

#: Mois abrégés (pour ``%b``). « mars / mai / juin » n'ont pas d'abréviation.
MONTHS_FR_ABBR: Final[tuple[str, ...]] = (
    "janv.",
    "févr.",
    "mars",
    "avr.",
    "mai",
    "juin",
    "juil.",
    "août",
    "sept.",
    "oct.",
    "nov.",
    "déc.",
)

#: Jours de la semaine — index = ``datetime.weekday()`` (0 = lundi).
WEEKDAYS_FR: Final[tuple[str, ...]] = (
    "lundi",
    "mardi",
    "mercredi",
    "jeudi",
    "vendredi",
    "samedi",
    "dimanche",
)

#: Jours abrégés (pour ``%a``).
WEEKDAYS_FR_ABBR: Final[tuple[str, ...]] = (
    "lun.",
    "mar.",
    "mer.",
    "jeu.",
    "ven.",
    "sam.",
    "dim.",
)


def strftime_fr(dt: Union[datetime, date], fmt: str) -> str:
    """``strftime`` localisé FR, **INDÉPENDANT de la locale système**.

    Substitue les codes locale-dépendants (``%A`` jour, ``%a`` jour abrégé,
    ``%B`` mois, ``%b`` mois abrégé) par leurs valeurs françaises AVANT de
    déléguer le reste (``%Y``, ``%d``, ``%H``…) à :meth:`datetime.strftime`.
    Garantit un rendu FR identique sur tout OS sans dépendre d'un paquet
    ``locales`` dans l'image (python:slim n'en livre aucune).

    Les ``%%`` littéraux sont préservés. Les noms FR injectés ne contiennent
    aucun ``%`` → ils traversent ``strftime`` inchangés.

    PORTÉE : seuls ``%A``/``%a``/``%B``/``%b`` sont garantis FR. Les codes
    COMPOSITES locale-dépendants ``%c`` (date+heure), ``%x`` (date), ``%X``
    (heure), ``%p`` (AM/PM) NE sont PAS neutralisés → ils restent rendus par la
    locale système (anglais sur python:slim). Ne pas les utiliser dans les
    ``format_string`` de templates si un rendu FR est attendu (préférer
    ``%d/%m/%Y %H:%M``). Aucun call-site Komptia ne les emploie aujourd'hui.

    ``fmt=None`` lève ``TypeError`` (comme :meth:`datetime.strftime`) plutôt
    qu'un ``AttributeError`` opaque — les appelants qui catchent déjà
    ``TypeError`` (ex. template_manager) gardent leur fallback. ``fmt=""``
    retourne ``""``. Un ``\\x00`` dans ``fmt`` (config/template corrompu) lève
    ``ValueError`` (le sentinel interne est un NUL → on refuse toute collision).
    """
    if fmt is None:
        raise TypeError("strftime_fr: le format strftime ne peut pas être None")
    sentinel = "\x00"  # protège les '%%' littéraux d'une ré-interprétation
    if sentinel in fmt:
        raise ValueError("strftime_fr: caractère NUL interdit dans le format strftime")
    out = (
        fmt.replace("%%", sentinel)
        .replace("%A", WEEKDAYS_FR[dt.weekday()])
        .replace("%a", WEEKDAYS_FR_ABBR[dt.weekday()])
        .replace("%B", MONTHS_FR[dt.month - 1])
        .replace("%b", MONTHS_FR_ABBR[dt.month - 1])
        .replace(sentinel, "%%")
    )
    return dt.strftime(out)


def format_date_fr(dt: Union[datetime, date], *, with_time: bool = False) -> str:
    """Date française lisible : « 2 juin 2026 » (ou « …, 14:30 » si ``with_time``).

    Helper de confort au-dessus de :data:`MONTHS_FR` pour le cas le plus courant
    (jour mois année). ``with_time`` n'ajoute l'heure que pour un ``datetime``.
    """
    base = f"{dt.day} {MONTHS_FR[dt.month - 1]} {dt.year}"
    if with_time and isinstance(dt, datetime):
        base += f", {dt.strftime('%H:%M')}"
    return base


def to_local(value: Union[datetime, str, None]) -> Optional[datetime]:
    """Convertit un **instant** UTC (``datetime`` ou ISO 8601) en ``datetime``
    **aware dans la TZ serveur** (``config.server.timezone`` via :func:`machine_tz`).

    Brique bas-niveau partagée par les formateurs serveur (``format_local_fr`` +
    les call-sites à format custom). Un ``datetime`` naïf est interprété UTC
    (convention de stockage Komptia, cf. :func:`ensure_utc`) ; le suffixe ``Z``
    des chaînes est toléré. Retourne ``None`` si la valeur est absente/illisible.

    ⚠️ Pour un **instant** uniquement : une chaîne date-nue (``"2026-04-19"``)
    serait lue à minuit UTC et basculerait d'un jour vers un fuseau en retard sur
    UTC. Les call-sites qui affichent une date nue doivent la détecter en amont
    (cf. :func:`format_local_fr`).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt: Optional[datetime] = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        # ``fromisoformat`` (py3.10) ne parse pas le suffixe « Z » → on le mappe
        # (ancré en FIN uniquement : un « Z » au milieu = corruption → le parse
        # échoue → None, fail-safe).
        iso = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            dt = datetime.fromisoformat(iso)
        except ValueError:
            return None
    else:
        return None
    aware_utc = ensure_utc(dt)  # naïf → aware UTC ; aware → inchangé
    if aware_utc is None:
        return None
    return aware_utc.astimezone(machine_tz())


def iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """ISO 8601 **horodaté** (offset explicite) d'un instant stocké, pour ÉMISSION
    au FRONTEND (JS).

    Pourquoi : un ISO **naïf** (``"2026-06-08T17:40:00"``) est mal-parsé par
    ``new Date()`` côté navigateur — interprété comme heure LOCALE du visiteur, pas
    UTC → décalage silencieux (ex. +4h pour ``America/Guadeloupe``). On garantit
    donc l'offset (``+00:00`` pour un naïf, convention de stockage Komptia = UTC)
    pour que le JS reconvertisse correctement vers le fuseau du navigateur.

    ``None`` → ``None``. Un ``datetime`` aware conserve son offset (déjà parsable).
    """
    aware = ensure_utc(dt)  # naïf → aware UTC ; aware → inchangé
    return aware.isoformat() if aware is not None else None


def format_local_fr(value: Union[datetime, date, str, None], *, with_time: bool = False) -> str:
    """Formate un instant UTC stocké en date FR dans la **TZ serveur configurée**.

    SOURCE DE VÉRITÉ UNIQUE de l'affichage daté **côté serveur** (SSR). Accepte :

    * un ``datetime`` (naïf ⇒ interprété UTC par convention Komptia, ou aware),
    * une chaîne ISO 8601 (``"2026-06-08T17:40:00"``, avec/sans fuseau, ``Z`` ok),
    * une **date nue** (``date`` ou ``"2026-06-08"``) ⇒ reformatée SANS conversion
      de fuseau (une date n'a pas d'heure à convertir).

    Convertit l'instant vers :func:`machine_tz` (``config.server.timezone``) puis
    rend en français **locale-indépendant** (``JJ/MM/AAAA`` ± ``HH:MM``).

    Pourquoi : les colonnes ORM ``DateTime`` (sans ``timezone=True``) stockent
    l'UTC en naïf ; un rendu par découpage de la chaîne ISO afficherait l'heure
    UTC brute (ex. +4h pour ``America/Guadeloupe`` = UTC−4). Ce helper centralise
    la conversion pour que TOUT rendu serveur partage le même fuseau (cf.
    :func:`now_local`).

    Fail-safe : ``None`` / vide / illisible / type non géré ⇒ ``"-"`` (un
    timestamp corrompu ne doit jamais casser un template admin). :func:`machine_tz`
    retombe elle-même sur UTC si ``config.server.timezone`` est invalide.
    """
    if value is None:
        return "-"
    # Date nue (objet ``date`` non-datetime, ou ``"YYYY-MM-DD"``) : pas de
    # conversion TZ. NB : ``datetime`` est sous-classe de ``date`` → on teste
    # ``datetime`` AVANT (plus bas) ; ici on n'attrape que les vraies ``date``.
    if isinstance(value, date) and not isinstance(value, datetime):
        return f"{value.day:02d}/{value.month:02d}/{value.year}"
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return "-"
        if "T" not in raw and ":" not in raw:  # chaîne date-nue
            try:
                d = datetime.fromisoformat(raw)
            except ValueError:
                return "-"
            return f"{d.day:02d}/{d.month:02d}/{d.year}"

    local = to_local(value)
    if local is None:
        return "-"
    return strftime_fr(local, "%d/%m/%Y %H:%M" if with_time else "%d/%m/%Y")


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
            # Fuseau non résoluble (nom invalide / alias non IANA). On retombe sur
            # UTC pour ne pas crasher, MAIS on l'annonce une seule fois (chemin
            # chaud) : sinon l'affichage des dates repasse en UTC EN SILENCE — le
            # bug « +4h » revient sans le moindre signal (donnée fausse masquée).
            global _machine_tz_fallback_warned
            if not _machine_tz_fallback_warned:
                _machine_tz_fallback_warned = True
                import logging

                logging.getLogger(__name__).warning(
                    "Fuseau horaire %r non résoluble → dates affichées EN UTC. "
                    "Corrigez `config.server.timezone` / la variable d'env TZ "
                    "(nom IANA, ex. America/Guadeloupe) puis redémarrez.",
                    name,
                )
            return timezone.utc
