"""
Helper unifié pour le statut santé de la BDD source (Sage / SQL Server).

Avant ce module, **trois implémentations distinctes** déterminaient le
statut de la BDD source :

* :func:`app.services.dashboard.admin_monitoring.AdminMonitoringService._check_sage_status`
  — 4 états (``unconfigured``/``untested``/``connected``/``disconnected``)
  pour le dashboard admin (UI).
* :func:`app.services.diagnostics._check_sage_config` — boolean (config
  credentials uniquement, pas de connexion réseau) pour le startup
  diagnostic.
* :func:`app.services.diagnostics._check_sage_connection` — vraie
  tentative ``SELECT 1`` avec timeout pour ``/health/detailed``.

Conséquence : trois vocabulaires différents pour la même question.
Le dashboard pouvait afficher "connected" alors que ``/health/detailed``
indiquait "warning timeout 10s". Source unique de divergence silencieuse.

Ce module expose :class:`SageHealthSnapshot` qui centralise les **signaux
bruts** (sans interprétation). Chaque caller mappe ensuite vers son propre
vocabulaire local, mais la SOURCE est identique.

Cf. review adversariale finding #39.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass(frozen=True)
class SageHealthSnapshot:
    """Signaux bruts du statut de la BDD source.

    Chaque caller mappe ensuite vers son propre format. Frozen dataclass
    pour éviter les mutations accidentelles entre callers concurrents.

    Attributes
    ----------
    is_unconfigured:
        ``True`` si aucune connexion n'est définie/activée via
        ``/admin/database`` — l'exécution SQL est explicitement désactivée.
        Distinct de "disconnected" car ce n'est pas une panne, c'est un
        état de configuration.
    has_credentials:
        ``True`` si un username Sage est défini dans la config courante.
        Pas de garantie que le mot de passe est valide — juste qu'on a
        de quoi tenter une connexion.
    is_connected:
        ``True`` si le connecteur a réussi au moins une requête récente
        (property ``SageConnector.is_connected``). ``False`` au boot
        avant le premier ping.
    circuit_breaker_failures:
        Nombre d'échecs de connexion enregistrés par le circuit breaker
        depuis le boot. ``0`` = jamais tenté ou jamais échoué. ``> 0``
        = tentative(s) infructueuse(s).
    pyodbc_available:
        ``True`` si le driver ODBC Python est installé. Important sur
        des images Docker minimalistes où pyodbc peut manquer.
    """

    is_unconfigured: bool
    has_credentials: bool
    is_connected: bool
    circuit_breaker_failures: int
    pyodbc_available: bool

    @property
    def state(self) -> str:
        """Mapping helper vers les 4 états utilisés par le dashboard admin.

        - ``"unconfigured"`` : aucune connexion activée (UI demande
          d'aller sur ``/admin/database``).
        - ``"connected"``    : ``is_connected`` vrai (ping récent OK).
        - ``"disconnected"`` : tentative passée + au moins 1 échec circuit
          breaker. Distinct de "untested".
        - ``"untested"``     : config présente mais aucun ping tenté.
          Pas une panne — juste un boot frais.
        """
        if self.is_unconfigured:
            return "unconfigured"
        if self.is_connected:
            return "connected"
        if self.circuit_breaker_failures > 0:
            return "disconnected"
        return "untested"


def get_sage_health_snapshot() -> SageHealthSnapshot:
    """Retourne un :class:`SageHealthSnapshot` synchrone (sans I/O réseau).

    Lit uniquement des attributs en mémoire — pas de tentative de
    connexion. Pour une vraie health-check via ``SELECT 1`` (avec timeout),
    cf. :func:`app.services.diagnostics._check_sage_connection`.

    **Fail-CLOSED par design** (review adversariale R2-A1) : tous les
    fallbacks ``getattr`` utilisent une valeur **prudente** (assume le
    pire), pas une valeur optimiste. Si une fonction/attribut du
    ``sage_connector`` est renommée/supprimée par un refactor futur, on
    rapporte ``unconfigured`` / ``pyodbc_unavailable`` plutôt que de
    silencieusement faire croire à l'admin que tout va bien. Mieux vaut
    un faux positif (alerte injustifiée) qu'un faux négatif (panne masquée).
    """
    try:
        from app.services.database import sage_connector as sage_mod

        # is_unconfigured : fallback ``True`` (pas False) — sans la fonction,
        # on n'a pas de garantie que la BDD source est configurée. Mieux
        # vaut afficher "unconfigured" que "tout va bien" silencieusement.
        is_unconfigured = bool(getattr(sage_mod, "is_unconfigured", lambda: True)())
        connector = sage_mod.get_sage_connector()
        has_credentials = bool(connector and getattr(connector, "username", ""))
        is_connected = bool(connector and getattr(connector, "is_connected", False))
        cb_failures = _get_circuit_breaker_failures(sage_mod)
        # pyodbc_available : fallback ``False`` (pas True). Sans le flag,
        # on ne peut pas garantir que le driver est dispo. Si l'attribut
        # est renommé, l'admin doit voir un avertissement.
        pyodbc_available = bool(getattr(sage_mod, "PYODBC_AVAILABLE", False))
        return SageHealthSnapshot(
            is_unconfigured=is_unconfigured,
            has_credentials=has_credentials,
            is_connected=is_connected,
            circuit_breaker_failures=cb_failures,
            pyodbc_available=pyodbc_available,
        )
    except (ImportError, AttributeError) as exc:
        logger.debug("get_sage_health_snapshot: connector indisponible (%s)", exc)
        return SageHealthSnapshot(
            is_unconfigured=True,
            has_credentials=False,
            is_connected=False,
            circuit_breaker_failures=0,
            pyodbc_available=False,
        )


def _get_circuit_breaker_failures(sage_mod) -> int:
    """Compteur d'échecs du circuit breaker côté ``sage_connector``.

    Tente d'abord une fonction publique ``get_circuit_breaker_failures()``
    (à exposer dans ``sage_connector``). Fallback sur l'attribut
    module-private ``_cb_failure_count`` pour compat ascendante. Si aucun
    des deux n'existe (refactor ayant cassé les deux), retourne 0 mais
    log un debug pour audit (le snapshot reste cohérent : ``state`` sera
    ``untested`` au lieu de ``disconnected``, ce qui est moins alarmiste
    mais évite les faux positifs ; le bandeau "Sage déconnectée" peut
    être manquant le temps que l'on rebrancher l'attribut).
    """
    pub = getattr(sage_mod, "get_circuit_breaker_failures", None)
    if callable(pub):
        try:
            return int(pub() or 0)
        except (TypeError, ValueError):
            pass
    raw = getattr(sage_mod, "_cb_failure_count", None)
    if raw is None:
        logger.debug(
            "sage_health: ni get_circuit_breaker_failures() ni _cb_failure_count "
            "trouvés sur sage_connector — état 'untested' par défaut."
        )
        return 0
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


__all__ = ["SageHealthSnapshot", "get_sage_health_snapshot"]
