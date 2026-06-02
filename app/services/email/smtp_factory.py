"""Factory centralisée pour construire un :class:`SMTPClient` à partir
de la configuration globale enregistrée par l'admin
(:class:`SMTPGlobalConfig`).

Pourquoi ce module
------------------
Avant LOGIN-E5, ``SMTPClient(...)`` était instancié manuellement dans
8+ endroits du codebase (admin_smtp, reports, dashboard.delivery_service,
agent_tools_app, executor ×3, feedback_service). Ajouter un nouveau
champ à :class:`SMTPGlobalConfig` (par exemple ``use_ssl`` ou
``connection_timeout``) imposait de modifier les 8 call-sites — drift
garanti à la moindre évolution.

Ce module expose une fonction unique :func:`build_smtp_client_from_db`
qui charge la dernière config activée en BDD et construit un
:class:`SMTPClient` configuré. Les nouveaux call-sites doivent passer
par cette fonction. Les anciens peuvent migrer progressivement (le
factory est pleinement compatible avec leurs usages).

Choix de design
---------------
* Pas de cache : la config SMTP change rarement (admin uniquement) mais
  doit être re-lue à chaque envoi pour qu'une mise à jour admin prenne
  effet immédiatement. Le coût du SELECT (1 ligne, primary key) est
  négligeable comparé au coût d'un envoi SMTP (≥ 100 ms).
* Pas d'exception levée si SMTP non configuré : on retourne ``None``,
  le caller décide quoi faire (envoyer, fallback fichier, ignorer).
* Aucun nom hardcodé d'utilisateur final ou de cabinet — la config
  vient à 100 % de la BDD.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


def decrypt_smtp_password_lenient(stored: Optional[str]) -> Optional[str]:
    """Déchiffre un mot de passe SMTP stocké en BDD, AVEC compat ascendante (#5).

    - Token Fernet (password chiffré at-rest, nouveau format) → déchiffré.
    - Valeur en clair (déploiement legacy : le password SMTP était historiquement
      stocké non chiffré) ou vide/None → retournée telle quelle.

    Permet d'introduire le chiffrement-at-rest du password SMTP (parité avec la
    connexion Sage `encrypted_password`) SANS casser les déploiements existants :
    un password legacy en clair reste lisible, et sera ré-chiffré au prochain
    enregistrement admin (5b) ou par la migration dédiée (5c).

    NB : à n'appliquer qu'aux valeurs venant de la BDD (`SMTPGlobalConfig`), PAS
    au fallback `.env` (`config.smtp.password`) qui est du clair par nature.
    """
    if not stored:
        return stored
    from app.services.database.db_config_service import decrypt_password

    try:
        return decrypt_password(stored)
    except ValueError:
        # InvalidToken → valeur non-Fernet (legacy clair) : on la rend telle quelle.
        return stored


def reencrypt_one(stored: Optional[str]) -> Optional[str]:
    """Version CHIFFRÉE d'un password SMTP s'il est en clair (legacy), sinon ``None`` (5c).

    ``None`` = rien à faire (déjà un token Fernet → decrypt OK ; vide ; None).
    Pur (réutilise `encrypt_password`/`decrypt_password`), donc testable hors BDD.
    """
    if not stored:
        return None
    from app.services.database.db_config_service import decrypt_password, encrypt_password

    try:
        decrypt_password(stored)
        return None  # déjà chiffré → ne pas re-chiffrer (anti double-chiffrement)
    except ValueError:
        return encrypt_password(stored)  # clair legacy → chiffrer at-rest


async def reencrypt_legacy_smtp_passwords(session) -> int:
    """Ré-chiffre at-rest les passwords SMTP legacy en clair (5c, one-shot boot).

    **Idempotent** : un password déjà chiffré (decrypt OK) ou vide est laissé
    intact → sûr à ré-exécuter à chaque boot. Retourne le nombre de lignes
    ré-chiffrées. ORM async safe : mutation in-place puis commit unique.
    """
    from sqlalchemy import select

    from app.models.smtp_global_config import SMTPGlobalConfig

    rows = (await session.execute(select(SMTPGlobalConfig))).scalars().all()
    count = 0
    for row in rows:
        new_pw = reencrypt_one(row.password)
        if new_pw is not None:
            row.password = new_pw
            count += 1
    if count:
        await session.commit()
    return count


def build_smtp_client_from_dict(
    cfg: Mapping[str, Any],
    *,
    from_name_override: Optional[str] = None,
    max_retries_override: Optional[int] = None,
    retry_delay_override: Optional[int] = None,
):
    """Construit un :class:`SMTPClient` depuis un dict de config déjà chargé.

    Utilisé par les call sites qui ont déjà chargé la config SMTP en amont
    (exécution d'automatisation, agent_tools, dashboard delivery, reports,
    test SMTP admin) — tous partagent la même forme de dict (issue de
    ``SMTPGlobalConfig.to_dict()`` ou variantes legacy).

    Centralise la liste des champs requis : si on ajoute ``connection_timeout``
    à :class:`SMTPClient`, on n'a qu'un site à modifier.

    Args:
        cfg: Mapping avec au minimum ``host``, ``port``, ``username``,
            ``password``, ``use_tls``, ``from_email``. Optionnels :
            ``from_name``, ``max_retries``, ``retry_delay``.
        from_name_override: Si fourni, écrase ``cfg["from_name"]``. Utile
            pour formats type ``f"{username} via {from_name}"`` (reports)
            ou pour brancher un helper de branding (dashboard).
        max_retries_override: Force un nombre de retries. Cas usage :
            test SMTP admin (1 retry, pas 3).
        retry_delay_override: Force un délai. Cas usage : test SMTP
            admin (0 sec, pas 5).

    Returns:
        Une instance :class:`SMTPClient` configurée. Lève ``KeyError`` si
        un champ requis manque (fail-fast côté caller — un dict mal formé
        est un bug, pas un fallback silencieux).

    Raises:
        KeyError: Si ``host``, ``port``, ``username`` ou ``password``
            manque dans ``cfg``. ``use_tls`` et ``from_email`` ont des
            valeurs par défaut sûres (False / username).
    """
    from app.services.email.smtp_client import SMTPClient

    # Fail-fast sur les 4 champs strictement requis (pas de fallback dangereux
    # comme host="" qui causerait un timeout silencieux). Les autres champs
    # (use_tls, from_email, from_name, retries) ont des défauts sûrs.
    # Adversarial cycle 15 #10 : valeur None ou "" est aussi rejetée — sinon
    # SMTPClient.__init__ lèverait AttributeError cryptique (`.strip()` sur None).
    for required in ("host", "port", "username", "password"):
        if required not in cfg:
            raise KeyError(
                f"build_smtp_client_from_dict: champ requis '{required}' "
                f"manquant dans cfg (clés présentes: {list(cfg.keys())})"
            )
        val = cfg[required]
        if val is None or (isinstance(val, str) and not val.strip()):
            raise ValueError(
                f"build_smtp_client_from_dict: champ requis '{required}' "
                f"vide ou None (cfg['{required}']={val!r}). Configurer "
                f"l'admin SMTP (/admin/smtp) avant d'envoyer un email."
            )

    # Adversarial cycle 19 #8 : `int()` lèverait ValueError/TypeError cryptique
    # si port="abc" / port=None. On valide en amont avec un message clair.
    try:
        port_int = int(cfg["port"])
    except (ValueError, TypeError) as e:
        raise ValueError(
            f"build_smtp_client_from_dict: port invalide "
            f"(cfg['port']={cfg['port']!r}, type={type(cfg['port']).__name__}). "
            f"Doit être un entier (ex: 587 pour TLS, 465 pour SSL, 25 pour relay)."
        ) from e
    if port_int < 1 or port_int > 65535:
        raise ValueError(
            f"build_smtp_client_from_dict: port hors plage TCP "
            f"(cfg['port']={port_int}). Doit être entre 1 et 65535."
        )

    # Adversarial cycle 19 #7 : `use_tls=None` était silencieusement traité
    # comme `False` (bool(None)). C'est un piège : un admin qui a mis null
    # pensait peut-être désactiver explicitement, mais le résultat (TLS off
    # sur port 587) ouvre une fuite passwd en clair sur le réseau. On loggue
    # un WARNING explicite pour qu'un dashboard d'observabilité signale
    # le foot-gun.
    use_tls_raw = cfg.get("use_tls")
    if use_tls_raw is None and "use_tls" in cfg:
        logger.warning(
            "build_smtp_client_from_dict: use_tls=None explicite — TLS "
            "désactivé silencieusement. Si vous voulez désactiver TLS, "
            "mettez False ; si vous voulez l'activer, mettez True. "
            "Risque de fuite credentials en clair sur le réseau (port=%d).",
            port_int,
        )
    use_tls_resolved = bool(use_tls_raw) if use_tls_raw is not None else False

    from_name_resolved = (
        from_name_override if from_name_override is not None else cfg.get("from_name")
    )

    return SMTPClient(
        host=cfg["host"],
        port=port_int,
        username=cfg["username"],
        password=cfg["password"],
        use_tls=use_tls_resolved,
        from_email=cfg.get("from_email") or cfg["username"],
        from_name=from_name_resolved,
        max_retries=int(
            max_retries_override if max_retries_override is not None else cfg.get("max_retries", 3)
        ),
        retry_delay=int(
            retry_delay_override if retry_delay_override is not None else cfg.get("retry_delay", 5)
        ),
    )


async def load_smtp_config_dict(
    session=None,
) -> Optional[dict]:
    """Charge la config SMTP active sous forme de dict (priorité BDD, fallback env).

    Adversarial cycle 16 #12 : avant ce helper, 4 sites (executor, reports,
    delivery_service, agent_tools_app) dupliquaient la même logique de
    chargement (SELECT SMTPGlobalConfig + fallback config.smtp). Si l'admin
    ajoutait un champ (timeout, ssl_context...), il fallait modifier 4
    endroits — drift garanti. Cette factorisation centralise la lecture
    pour que tous les call-sites (loaders + builders) passent par UN seul
    site.

    Args:
        session: Session SQLAlchemy async optionnelle. Si fournie, utilise
            celle-ci (cohérent avec le pattern executor/reports qui ont
            déjà une session ouverte). Sinon, ouvre une session courte
            via ``get_session()``.

    Returns:
        Un dict avec les mêmes clés que les call-sites legacy (host, port,
        username, password, use_tls, from_email, from_name, max_retries,
        retry_delay) ou ``None`` si aucune config active n'existe.

        IMPORTANT : ne lève jamais d'exception — le caller assume None ou
        fallback fichier. Cohérent avec ``build_smtp_client_from_db``.
    """
    from sqlalchemy import select

    from app.config import config
    from app.core.database import get_session
    from app.models.smtp_global_config import SMTPGlobalConfig

    smtp_row: Optional[SMTPGlobalConfig] = None
    try:
        if session is not None:
            result = await session.execute(
                select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
            )
            smtp_row = result.scalar_one_or_none()
        else:
            async with get_session() as db:
                result = await db.execute(
                    select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
                )
                smtp_row = result.scalar_one_or_none()
    except Exception:  # noqa: BLE001 — fail-safe : le caller décide
        logger.warning(
            "load_smtp_config_dict: lecture SMTPGlobalConfig échouée",
            exc_info=True,
        )
        smtp_row = None

    # Priorité 0 : admin a explicitement désactivé en BDD — on NE fallback PAS
    # sur .env. Sinon un admin qui appuie sur « désactiver SMTP » pour stopper
    # une fuite d'emails (mode incident) verrait ses automations continuer à
    # partir via la config .env héritée du setup initial — brisant le contrat
    # *single source of truth* (axe 7 CLAUDE.md). Pattern aligné sur
    # ``build_smtp_client_from_db`` (L287-299) pour garantir la parité de
    # comportement entre les 2 helpers de chargement SMTP.
    if smtp_row is not None and not smtp_row.enabled:
        logger.warning(
            "SMTPGlobalConfig présente mais enabled=False — "
            "aucun mail ne partira jusqu'à réactivation (load_smtp_config_dict)",
            extra={"host": smtp_row.host, "username": smtp_row.username},
        )
        return None

    # Priorité 1 : config BDD active (admin a explicitement configuré)
    if smtp_row is not None and smtp_row.enabled:
        return {
            "host": smtp_row.host,
            "port": smtp_row.port,
            "username": smtp_row.username,
            "password": decrypt_smtp_password_lenient(smtp_row.password),
            "use_tls": smtp_row.use_tls,
            "from_email": smtp_row.from_email,
            "from_name": smtp_row.from_name,
            "max_retries": smtp_row.max_retries,
            "retry_delay": smtp_row.retry_delay,
        }

    # Priorité 2 : fallback .env (mode dev / pas encore d'admin SMTP)
    if config.smtp.host and config.smtp.username:
        return {
            "host": config.smtp.host,
            "port": config.smtp.port,
            "username": config.smtp.username,
            "password": config.smtp.password,
            "use_tls": config.smtp.use_tls,
            "from_email": config.smtp.from_email,
            "from_name": config.smtp.from_name,
            "max_retries": 3,
            "retry_delay": 5,
        }

    # Priorité 3 : pas de config — caller décide quoi faire
    return None


async def build_smtp_client_from_db(
    *,
    fallback_from_name: Optional[str] = None,
):
    """Retourne un :class:`SMTPClient` configuré depuis ``SMTPGlobalConfig``,
    ou ``None`` si aucune config activée n'existe.

    Args:
        fallback_from_name: Nom expéditeur à utiliser si la config BDD
            n'en a pas. Si ``None``, on prend ``config.app_name``.

    Returns:
        Une instance de :class:`SMTPClient` prête à l'emploi, ou ``None``
        si la config est manquante / désactivée / incomplète.
    """
    from sqlalchemy import select

    from app.config import config
    from app.core.database import get_session
    from app.models.smtp_global_config import SMTPGlobalConfig
    from app.services.email.smtp_client import SMTPClient

    try:
        async with get_session() as db:
            result = await db.execute(
                select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
            )
            cfg = result.scalar_one_or_none()
    except Exception:  # noqa: BLE001 — fail-safe : le caller décide
        logger.warning(
            "build_smtp_client_from_db : lecture SMTPGlobalConfig échouée",
            exc_info=True,
        )
        return None

    if cfg is None:
        return None
    # ADV-S14 : si la config existe mais que ``enabled=False``, c'est un
    # signal explicite "admin a désactivé temporairement". On loggue
    # WARNING (pas INFO) pour qu'un dashboard d'observabilité signale
    # le foot-gun (debug + oubli de réactiver = mails users disparaissent).
    if not cfg.enabled:
        logger.warning(
            "SMTPGlobalConfig présente mais enabled=False — "
            "aucun mail ne partira jusqu'à réactivation",
            extra={"host": cfg.host, "username": cfg.username},
        )
        return None
    if not cfg.host or not cfg.username:
        return None

    return SMTPClient(
        host=cfg.host,
        port=int(cfg.port),
        username=cfg.username,
        password=decrypt_smtp_password_lenient(cfg.password),
        use_tls=bool(cfg.use_tls),
        from_email=cfg.from_email or cfg.username,
        from_name=cfg.from_name or fallback_from_name or config.app_name,
        max_retries=int(cfg.max_retries),
        retry_delay=int(cfg.retry_delay),
    )


__all__ = (
    "build_smtp_client_from_db",
    "build_smtp_client_from_dict",
    "load_smtp_config_dict",
)
