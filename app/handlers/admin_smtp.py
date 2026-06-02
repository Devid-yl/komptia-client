"""Handlers pour la configuration SMTP globale (réservés au rôle ``ADMIN``).

Trois surfaces :

* :class:`AdminSMTPConfigHandler` — rendu de la page HTML ``admin/smtp_config``
  (GET only, vue admin).
* :class:`AdminSMTPConfigAPIHandler` — CRUD JSON de l'unique ligne
  ``smtp_global_config`` (GET lit la dernière ; POST upsert avec validation
  partielle). Expose la provenance effective de la configuration (``db`` /
  ``env`` / ``none``) pour que l'UI affiche un bandeau d'état.
* :class:`AdminSMTPTestHandler` — envoi d'un email de test avec soit les
  valeurs du formulaire (non encore enregistrées, cas « j'essaie avant de
  sauvegarder »), soit la configuration enregistrée. Rate-limité par
  utilisateur pour éviter l'exfiltration massive de tests.

Choix de design (décisions d'équipe, pas triviales) :

* La regex email, le nettoyage NBSP et la coercition booléenne stricte
  vivent dans :mod:`app.utils.validators` — un seul endroit à faire évoluer.
* Tous les noms d'affichage publicitaires (``From: … via Komptia``) tirent
  de :mod:`app.config`, pas de hardcoding. Komptia-le-produit peut être
  renommé en une ligne.
* Validation partielle : le POST accepte un sous-ensemble des champs
  (upsert incrémental, aligné avec l'UX du formulaire). Les champs non
  fournis ne sont pas remis à zéro — c'est voulu.
* Après insertion, on **purge** les anciennes lignes : la table
  ``smtp_global_config`` est conceptuellement un singleton, et laisser
  croître l'historique en BDD ne sert qu'à dupliquer ce que
  ``updated_at`` / ``updated_by`` tracent déjà.
"""

from __future__ import annotations

import html
import os
import re
import smtplib
from typing import Any, Mapping

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import config
from app.core.database import get_session
from app.handlers.base import BaseHandler, admin_required
from app.models.smtp_global_config import SMTPGlobalConfig
from app.services.database.db_config_service import encrypt_password
from app.services.email.smtp_factory import decrypt_smtp_password_lenient
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.validators import (
    MAX_EMAIL_LENGTH,
    assert_no_crlf,
    clean_input,
    is_valid_email,
    strict_bool,
)

logger = get_logger(__name__)


# ── Limites applicatives ─────────────────────────────────────────
# Les valeurs ci-dessous bornent ce que l'admin peut soumettre via le
# formulaire. Elles doublent les bornes HTML (``min``/``max`` sur
# ``<input type="number">``) pour fail-closed côté serveur : un client
# qui bypasse le front (curl, Postman, ingéré via un script) ne doit
# pas pouvoir provoquer un comportement dégénéré (1000 retries qui
# saturent le pool SMTP par ex).

#: Nombre max de tentatives SMTP autorisé par l'UI (aligné sur
#: ``<input max="10">`` dans ``admin/smtp_config.html``).
_MAX_RETRIES_CAP: int = 10

#: Délai max entre tentatives en secondes (aligné sur
#: ``<input max="60">``).
_MAX_RETRY_DELAY_CAP: int = 60

#: Les champs du formulaire qu'un POST peut modifier. L'ordre n'a pas
#: d'importance fonctionnelle ; l'ensemble sert de garde contre
#: l'affectation d'attributs inattendus (par ex. ``id`` ou
#: ``created_at``).
_MUTABLE_FIELDS: frozenset[str] = frozenset(
    {
        "host",
        "port",
        "username",
        "password",
        "use_tls",
        "from_email",
        "max_retries",
        "retry_delay",
        "enabled",
        # 2026-05-19 — Email destinataire des signalements (override
        # config.support_email). NULL/vide = utilise le default config.py.
        "support_email",
        # Display name SMTP (``From: <Nom> <email>``). NULL/vide = fallback
        # ``config.app_name`` (cf. smtp_factory + branding). La colonne
        # existait sur le modèle mais n'était pas exposée ici → l'admin ne
        # pouvait pas configurer le nom visible côté inbox client.
        "from_name",
    }
)

#: Nombre de tests SMTP max par utilisateur par fenêtre. L'envoi d'un
#: email coûte (réputation SMTP, risque greylisting) — même un admin
#: légitime n'a aucune raison d'en lancer 100 à la seconde. Une valeur
#: usuelle (10 / 5 min) permet un debug confortable sans ouvrir la porte
#: à l'exfiltration via boucle.
_TEST_RATE_LIMIT_COUNT: int = 10
_TEST_RATE_LIMIT_WINDOW_SECONDS: int = 300

_test_rate_limiter: RateLimiter = RateLimiter()

#: Réponse retournée quand l'admin teste sans config enregistrée NI
#: remplissage du formulaire. Centralisée pour garder un message unique.
_ERR_NO_CONFIG_AVAILABLE: str = (
    "Aucune configuration SMTP enregistrée. Veuillez remplir le formulaire."
)

#: Borne sur ``from_name`` en OCTETS UTF-8 (pas en code points). La
#: VARCHAR(255) du modèle est un cap CODE POINT, mais un display name
#: avec emojis 4 octets (``🏛️`` = 4 octets utf-8) peut dépasser la borne
#: pratique des serveurs SMTP (RFC 5322 section 2.1.1 limite à 998
#: octets par ligne, mais en pratique les MUA tronquent bien avant).
#: 255 octets = 255 chars ASCII OU ~63 chars emoji (4 octets) = plus
#: strict en faveur du serveur MX. Aligné sur la VARCHAR(255) pour que
#: la BDD reste capable de stocker tout ce que le coerce accepte.
_FROM_NAME_MAX_UTF8_BYTES: int = 255

#: Regex de caractères de contrôle ASCII interdits dans un display name
#: SMTP. CR/LF est déjà géré par ``assert_no_crlf``. On ajoute ici tous
#: les autres contrôles (\x00 NUL, \x0b VT, \x0c FF, \x1b ESC, etc.)
#: SAUF \t qui est légitime (tabulation dans un libellé ne casse pas
#: MIME). Defense-in-depth : un NUL peut couper un C-string côté MTA,
#: un ESC peut injecter des séquences ANSI dans un log structuré.
_CONTROL_CHARS_PATTERN: re.Pattern[str] = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


# ── Helpers DB ──────────────────────────────────────────────────


async def _get_latest_config(session: AsyncSession) -> SMTPGlobalConfig | None:
    """Retourne la config SMTP enregistrée (la plus récente s'il y en a plusieurs)."""
    result = await session.execute(
        select(SMTPGlobalConfig).order_by(SMTPGlobalConfig.id.desc()).limit(1)
    )
    return result.scalar_one_or_none()


async def _purge_older_configs(session: AsyncSession, keep_id: int) -> None:
    """Supprime toutes les lignes ``smtp_global_config`` sauf ``keep_id``.

    La table est logiquement un singleton (« la » configuration SMTP de
    l'instance). Historiser chaque POST en BDD dupliquerait ce que
    ``updated_at`` / ``updated_by`` capturent déjà, et une fuite SQL
    exposerait plusieurs mots de passe là où un seul devrait exister.
    """
    await session.execute(delete(SMTPGlobalConfig).where(SMTPGlobalConfig.id != keep_id))


# ── Validation ───────────────────────────────────────────────────


def _validate_smtp_data(data: Mapping[str, Any]) -> dict[str, str]:
    """Valide les champs SMTP présents dans ``data``. Retourne les erreurs par champ.

    Convention : seuls les champs **présents** sont validés. L'appelant
    décide si l'absence d'un champ est acceptable (upsert incrémental)
    ou non (création initiale) — cette fonction ne présume pas.
    """
    errors: dict[str, str] = {}

    if "host" in data:
        host = clean_input(data["host"])
        if not isinstance(host, str) or not host:
            errors["host"] = "Le serveur SMTP est requis"
        else:
            try:
                assert_no_crlf(host, "host")
            except ValueError:
                errors["host"] = "Le serveur SMTP contient un caractère invalide"

    if "port" in data:
        try:
            port = int(data["port"])
            if not 1 <= port <= 65535:
                errors["port"] = "Le port doit être entre 1 et 65535"
        except (ValueError, TypeError):
            errors["port"] = "Le port doit être un nombre valide"

    if "from_email" in data:
        email_raw = clean_input(data["from_email"])
        if not isinstance(email_raw, str) or not email_raw:
            errors["from_email"] = "L'email expéditeur est requis"
        elif not is_valid_email(email_raw):
            errors["from_email"] = "Format d'email invalide"

    # support_email est OPTIONNEL : NULL/vide = fallback config.support_email.
    # Si fourni, valider format email + taille (cohérent from_email).
    if "support_email" in data:
        support_raw = clean_input(data["support_email"])
        if isinstance(support_raw, str) and support_raw:
            if len(support_raw) > 254:
                errors["support_email"] = "L'email support est trop long (max 254 chars)"
            elif not is_valid_email(support_raw):
                errors["support_email"] = "Format d'email invalide"

    # from_name est OPTIONNEL : NULL/vide = fallback config.app_name.
    # Display name visible côté inbox (``From: <Nom> <email>``). Pas un
    # email — on ne valide pas le format, seulement la sécurité (CRLF
    # + autres chars de contrôle = header injection) et la taille (en
    # OCTETS UTF-8, pas code points, cf. ``_FROM_NAME_MAX_UTF8_BYTES``).
    if "from_name" in data:
        from_name_raw = data["from_name"]
        # NULL / vide / whitespace-only sont valides (fallback config).
        # On ne rejette que les types incompatibles ou les chaînes
        # explicitement malformées.
        if from_name_raw is None:
            pass  # null JSON → fallback
        elif not isinstance(from_name_raw, str):
            # Type inattendu (int, list, dict, bool) — fail-fast côté
            # validate pour produire une erreur ciblée sur le champ
            # plutôt qu'un message générique côté coerce (clé ``"_"``).
            errors["from_name"] = "Le nom expéditeur doit être une chaîne"
        elif from_name_raw.strip():
            cleaned = clean_input(from_name_raw)
            if not isinstance(cleaned, str):
                errors["from_name"] = "Le nom expéditeur doit être une chaîne"
            elif len(cleaned.encode("utf-8")) > _FROM_NAME_MAX_UTF8_BYTES:
                errors["from_name"] = (
                    f"Le nom expéditeur est trop long "
                    f"(max {_FROM_NAME_MAX_UTF8_BYTES} octets UTF-8)"
                )
            elif _CONTROL_CHARS_PATTERN.search(cleaned):
                # Chars de contrôle ASCII (NUL, VT, FF, ESC, DEL...) =
                # header injection / log forging / encodage cassé.
                errors["from_name"] = "Le nom expéditeur contient un caractère de contrôle interdit"
            else:
                try:
                    assert_no_crlf(cleaned, "from_name")
                except ValueError:
                    errors["from_name"] = "Le nom expéditeur contient un caractère invalide (CR/LF)"

    if "username" in data:
        username = clean_input(data["username"])
        if not isinstance(username, str) or not username:
            errors["username"] = "L'utilisateur SMTP est requis"
        elif len(username) > 255:
            errors["username"] = "L'utilisateur SMTP est trop long"

    return errors


def _coerce_field(field: str, value: Any) -> Any:
    """Convertit la valeur brute d'un champ vers le type attendu par la BDD.

    Lève ``ValueError`` pour signaler une valeur malformée (le handler
    remontera un 400). C'est ici qu'on force :py:func:`strict_bool` —
    un JSON ``"false"`` envoyé comme string truanderait ``bool()``.
    """
    if field in {"use_tls", "enabled"}:
        return strict_bool(value, field)
    if field == "port":
        port_int = int(value)
        if not 1 <= port_int <= 65535:
            raise ValueError("port hors plage 1..65535")
        return port_int
    if field == "max_retries":
        retries = int(value)
        if not 0 < retries <= _MAX_RETRIES_CAP:
            raise ValueError(f"max_retries hors plage 1..{_MAX_RETRIES_CAP}")
        return retries
    if field == "retry_delay":
        delay = int(value)
        if not 0 <= delay <= _MAX_RETRY_DELAY_CAP:
            raise ValueError(f"retry_delay hors plage 0..{_MAX_RETRY_DELAY_CAP}")
        return delay
    if field in {"host", "from_email", "username"}:
        cleaned = clean_input(value)
        if not isinstance(cleaned, str):
            raise ValueError(f"{field} doit être une string")
        return assert_no_crlf(cleaned, field)
    if field == "support_email":
        # Nullable : "" / None → NULL en BDD (fallback config.support_email).
        if value is None or value == "":
            return None
        cleaned = clean_input(value)
        if not isinstance(cleaned, str) or not cleaned:
            return None
        # Fix #2 review 2026-05-19 — defense in depth : recheck taille
        # ici (déjà bornée par _validate_smtp_data mais SQLite ignore les
        # VARCHAR(N) caps, et un caller bypass-amont insérerait un email
        # de 10K chars sans erreur. Cohérent avec le ceinture+bretelles
        # déjà appliqué sur from_email/username via assert_no_crlf).
        if len(cleaned) > 254:
            raise ValueError("support_email dépasse 254 caractères (RFC 5321)")
        # Anti-CRLF defense in depth (header injection ``Bcc:`` etc.).
        return assert_no_crlf(cleaned, "support_email")
    if field == "from_name":
        # Nullable : "" / None / whitespace-only → NULL en BDD (fallback
        # ``config.app_name``). Cohérent avec ``support_email`` mais sans
        # validation de format email (c'est un display name, pas une
        # adresse). Le caller décide ensuite si NULL = ``app_name`` ou
        # ``branding.get_smtp_from_name()``.
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise ValueError("from_name doit être une chaîne")
        cleaned = clean_input(value)
        if not isinstance(cleaned, str) or not cleaned:
            return None
        # Defense in depth : la BDD a une VARCHAR(255) en CODE POINTS,
        # mais les MUA/serveurs SMTP raisonnent en OCTETS (RFC 5322).
        # Un display name `"🏛️" * 70` = 70 code points (passerait < 255)
        # mais ~280 octets utf-8 (dépasserait la borne MTA en pratique).
        # On borne en octets pour fail-fast AVANT l'envoi.
        if len(cleaned.encode("utf-8")) > _FROM_NAME_MAX_UTF8_BYTES:
            raise ValueError(f"from_name dépasse {_FROM_NAME_MAX_UTF8_BYTES} octets UTF-8")
        # Chars de contrôle (NUL, VT, FF, ESC, DEL...) = header
        # injection / parsing cassé côté MTA. CR/LF est attrapé en
        # second par ``assert_no_crlf`` (kept for message specificity).
        if _CONTROL_CHARS_PATTERN.search(cleaned):
            raise ValueError("from_name contient un caractère de contrôle interdit")
        # Anti-CRLF : ``from_name`` est sérialisé dans le header SMTP
        # ``From:`` via ``f"{self.from_name} <{self.from_email}>"``.
        # Un CRLF interne casserait MIME et permettrait l'ajout
        # d'en-têtes arbitraires (``Bcc:``, ``Reply-To:``).
        return assert_no_crlf(cleaned, "from_name")
    if field == "password":
        # Le password peut contenir des caractères spéciaux (mots de passe
        # d'application Gmail = 16 caractères aléatoires). On ne trim QUE
        # les NBSP et espaces extrêmes pour ne pas altérer un password
        # légitime qui commencerait/finirait par un espace.
        if not isinstance(value, str):
            raise ValueError("password doit être une string")
        return value.replace("\xa0", " ")
    return value


# ── Helpers Test SMTP ───────────────────────────────────────────


async def _resolve_test_config(
    data: Mapping[str, Any], session: AsyncSession
) -> tuple[dict[str, Any] | None, str | None]:
    """Résout la config à utiliser pour un test SMTP.

    Deux modes :

    * L'UI envoie ``host`` + ``port`` (l'admin teste avant sauvegarde) →
      on nettoie les valeurs et on complète le password manquant depuis
      la BDD (pour ne pas forcer l'admin à re-saisir).
    * L'UI n'envoie rien → on lit la config enregistrée (test à froid).

    Retourne ``(config_dict, None)`` en cas de succès, ou
    ``(None, message_erreur)`` si pas de config utilisable.
    """
    if "host" in data and "port" in data:
        # Si le formulaire fournit un ``from_name``, on l'utilise pour le
        # test (preview avant sauvegarde — sinon impossible de valider le
        # rendu visible côté inbox sans commit). Sinon fallback app_name
        # (rétro-compat : un client legacy peut ne pas envoyer le champ).
        form_from_name = data.get("from_name")
        if isinstance(form_from_name, str) and form_from_name.strip():
            resolved_from_name: Any = clean_input(form_from_name)
        else:
            resolved_from_name = config.app_name
        base: dict[str, Any] = {
            "host": clean_input(data.get("host", "")),
            "port": data.get("port"),
            "username": clean_input(data.get("username", "")),
            "password": clean_input(data.get("password", "")),
            "use_tls": data.get("use_tls", True),
            "from_email": clean_input(data.get("from_email", "")),
            "from_name": resolved_from_name,
        }
        if not base["password"]:
            existing = await _get_latest_config(session)
            if existing is None or not existing.password:
                return None, "Mot de passe requis pour le test"
            base["password"] = decrypt_smtp_password_lenient(existing.password)
        return base, None

    existing = await _get_latest_config(session)
    if existing is None:
        return None, _ERR_NO_CONFIG_AVAILABLE
    return {
        "host": existing.host,
        "port": existing.port,
        "username": existing.username,
        "password": decrypt_smtp_password_lenient(existing.password),
        "use_tls": existing.use_tls,
        "from_email": existing.from_email,
        "from_name": existing.from_name or config.app_name,
    }, None


def _build_test_email_html(
    *,
    host: str,
    port: int,
    username: str,
    use_tls: bool,
    tested_by_email: str,
    product_name: str,
) -> str:
    """Construit le corps HTML du mail de test. Toutes les valeurs sont échappées.

    Isolée pour que la Phase 12 puisse tester l'échappement XSS en
    unité, sans monter un serveur SMTP de bout en bout.
    """
    tls_label = "Oui" if use_tls else "Non"
    esc = html.escape
    return (
        "<html>"
        "<body>"
        "<h2>Test de configuration SMTP</h2>"
        "<p>Ce message confirme que la configuration SMTP fonctionne "
        "correctement.</p>"
        f"<p><strong>Serveur :</strong> {esc(host)}:{port}</p>"
        f"<p><strong>Utilisateur :</strong> {esc(username)}</p>"
        f"<p><strong>TLS :</strong> {tls_label}</p>"
        f"<p><strong>Testé par :</strong> {esc(tested_by_email)}</p>"
        "<hr>"
        f"<p><em>{esc(product_name)} — Test automatique</em></p>"
        "</body>"
        "</html>"
    )


# ── Handlers ────────────────────────────────────────────────────


class AdminSMTPConfigHandler(BaseHandler):
    """Page de configuration SMTP pour les admins (HTML)."""

    @admin_required
    async def get(self) -> None:
        """Affiche la page de configuration SMTP."""
        self.render("admin/smtp_config.html", page_title="Configuration SMTP")


class AdminSMTPConfigAPIHandler(BaseHandler):
    """API JSON pour lire / modifier la configuration SMTP globale."""

    @admin_required
    async def get(self) -> None:
        """Retourne la configuration active avec la provenance (``db`` / ``env`` / ``none``)."""
        async with get_session() as session:
            smtp_config = await _get_latest_config(session)

            if smtp_config is None:
                smtp_config = SMTPGlobalConfig()
                session.add(smtp_config)
                await session.commit()
                await session.refresh(smtp_config)

            # Capture avant sortie de session pour éviter MissingGreenlet.
            response = smtp_config.to_dict(include_password=False)
            is_db_configured = bool(
                smtp_config.enabled and smtp_config.host and smtp_config.username
            )

        env_configured = bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER"))

        if is_db_configured:
            config_source = "db"
        elif env_configured:
            config_source = "env"
        else:
            config_source = "none"

        response["config_source"] = config_source
        response["env_configured"] = env_configured

        self.write_json(response)

    @admin_required
    async def post(self) -> None:
        """Upsert la configuration SMTP. Validation partielle, champs non fournis préservés."""
        user = self.current_user
        data = self.get_json_body()

        errors = _validate_smtp_data(data)
        if errors:
            self.write_json({"success": False, "errors": errors}, 400)
            return

        async with get_session() as session:
            smtp_config = await _get_latest_config(session)

            if smtp_config is None:
                smtp_config = SMTPGlobalConfig()
                session.add(smtp_config)

            try:
                for field in _MUTABLE_FIELDS:
                    if field not in data:
                        continue
                    if field == "password":
                        if not data[field]:
                            # Convention UX : password vide = « ne pas modifier »
                            # (le formulaire pré-rempli le laisse vide pour ne pas
                            # exposer l'existant → on garde la valeur stockée,
                            # déjà chiffrée ou legacy en clair).
                            continue
                        # Chiffrement at-rest (parité connexion Sage) : on stocke un
                        # token Fernet, jamais le mot de passe en clair. La lecture
                        # (smtp_factory) déchiffre via decrypt_smtp_password_lenient.
                        setattr(
                            smtp_config,
                            "password",
                            encrypt_password(_coerce_field("password", data[field])),
                        )
                        continue
                    setattr(smtp_config, field, _coerce_field(field, data[field]))
            except (TypeError, ValueError) as exc:
                logger.warning("Rejet POST SMTP de %s : %s", user.email, exc)
                self.write_json({"success": False, "errors": {"_": str(exc)}}, 400)
                return

            smtp_config.updated_by = user.email

            await session.flush()  # assigne un id avant purge si création
            await _purge_older_configs(session, keep_id=smtp_config.id)
            await session.commit()
            await session.refresh(smtp_config)

            config_dict = smtp_config.to_dict(include_password=False)

            logger.info("Configuration SMTP globale mise à jour par %s", user.email)

        # Propage immédiatement le changement aux call-sites de branding
        # (templates email, PDF, SMTP from_header). Sans cette invalidation,
        # le cache 60s de ``app.services.branding`` continuerait à servir
        # l'ancien ``from_name``/``company_name`` — un admin qui sauvegarde
        # et envoie un mail dans la foulée verrait l'ancien nom pendant
        # ~1 min, ce qui ferait croire à un bug.
        try:
            from app.services.branding import invalidate_company_name_cache

            invalidate_company_name_cache()
        except Exception:  # noqa: BLE001 — invalidation best-effort
            logger.warning(
                "Invalidation cache branding échouée après save SMTP",
                exc_info=True,
            )

        self.write_json({"success": True, "config": config_dict})


class AdminSMTPTestHandler(BaseHandler):
    """Déclenche un envoi de test SMTP (configuration volatile ou enregistrée)."""

    @admin_required
    async def post(self) -> None:
        user = self.current_user
        data = self.get_json_body()

        rate_key = f"smtp-test:user:{user.id}"
        if not _test_rate_limiter.check(
            rate_key, _TEST_RATE_LIMIT_COUNT, _TEST_RATE_LIMIT_WINDOW_SECONDS
        ):
            logger.warning("Rate-limit atteint pour test SMTP par %s", user.email)
            self.write_json(
                {
                    "success": False,
                    "error": ("Trop de tests SMTP consécutifs. Réessayez dans quelques minutes."),
                },
                429,
            )
            return

        provided_keys = {"host", "port", "from_email", "username"}
        if provided_keys & data.keys():
            errors = _validate_smtp_data(data)
            if errors:
                self.write_json({"success": False, "errors": errors}, 400)
                return

        async with get_session() as session:
            config_data, err = await _resolve_test_config(data, session)

        if config_data is None:
            # `err` is always set when config_data is None.
            assert err is not None
            self.write_json({"success": False, "error": err}, 400)
            return

        raw_test_email = clean_input(data.get("test_email", user.email))
        if not isinstance(raw_test_email, str) or not is_valid_email(raw_test_email):
            self.write_json({"success": False, "error": "Adresse email de test invalide"}, 400)
            return
        if len(raw_test_email) > MAX_EMAIL_LENGTH:
            self.write_json({"success": False, "error": "Adresse email de test trop longue"}, 400)
            return

        try:
            product_name = config.app_name
            sender_username = assert_no_crlf(
                clean_input(user.username) if isinstance(user.username, str) else "",
                "from_name.username",
            )
            from_name_base = assert_no_crlf(
                str(config_data["from_name"] or product_name), "from_name"
            )
            from_name = f"Test par {sender_username} via {from_name_base}"
        except ValueError:
            logger.warning("Rejet test SMTP (CRLF détecté) par %s", user.email)
            self.write_json(
                {
                    "success": False,
                    "error": "Un champ contient un caractère invalide (CR/LF)",
                },
                400,
            )
            return

        # Q2 cycle 15 : factory unique. retries=1/delay=0 = sémantique "test
        # immédiat", l'admin veut un retour rapide même en cas d'échec réseau.
        from app.services.email.smtp_factory import build_smtp_client_from_dict

        smtp_client = build_smtp_client_from_dict(
            config_data,
            from_name_override=from_name,
            max_retries_override=1,
            retry_delay_override=0,
        )

        body_html = _build_test_email_html(
            host=str(config_data["host"]),
            port=int(config_data["port"]),
            username=str(config_data["username"]),
            use_tls=bool(config_data["use_tls"]),
            tested_by_email=user.email,
            product_name=product_name,
        )

        try:
            # ``audit_log=False`` : c'est un test de connectivité SMTP, pas
            # un envoi métier. On ne pollue pas ``/email-history`` avec
            # les tests de l'admin (seul opt-out légitime du flag d'audit
            # centralisé — cf. ``services/email/smtp_client.py``).
            result = await smtp_client.send_email(
                to_emails=[raw_test_email],
                subject=f"Test de configuration SMTP - {product_name}",
                body_html=body_html,
                reply_to=user.email,
                audit_log=False,
            )
        except smtplib.SMTPAuthenticationError:
            logger.error("Échec authentification SMTP lors du test", exc_info=True)
            self.write_json(
                {
                    "success": False,
                    "error": "Échec d'authentification SMTP (vérifiez identifiants)",
                },
                500,
            )
            return
        except (smtplib.SMTPException, OSError) as exc:
            logger.error("Erreur lors du test SMTP", exc_info=True)
            self.write_json(
                {
                    "success": False,
                    "error": f"Échec connexion SMTP ({type(exc).__name__})",
                },
                500,
            )
            return

        if result.get("success"):
            logger.info("Test SMTP réussi par %s, email envoyé à %s", user.email, raw_test_email)
            self.write_json(
                {"success": True, "message": f"Email de test envoyé à {raw_test_email}"}
            )
            return

        # L'envoi a échoué sans exception → message générique côté client
        # (le détail est déjà loggé côté SMTPClient).
        logger.warning("Test SMTP : envoi en échec pour %s", user.email)
        self.write_json(
            {
                "success": False,
                "error": "L'envoi de l'email de test a échoué. Vérifiez la configuration SMTP.",
            },
            500,
        )
