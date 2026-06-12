"""
Service de configuration IA centralisée.

Gère la lecture/écriture de la configuration IA depuis la BDD.
Permet la mise à jour dynamique depuis l'interface GUI.

Doctrine sécurité :

- ``ENCRYPTED_KEYS`` est un **alias ré-exporté** de ``SECRET_CONFIG_KEYS``
  (défini dans ``app.models.ai_config``) — aucune duplication. L'ajout d'un
  secret futur au modèle propage automatiquement le chiffrement Fernet, le
  masquage display, et l'exclusion de l'export.
- ``export_config`` exclut systématiquement les clés secrètes (Defense in
  Depth : le modèle redacte déjà ``to_dict``, mais l'export ne doit même pas
  inclure une entrée "api_key" avec ``"***"`` — cf. OWASP Secrets Management
  Cheat Sheet §"Never include secrets in exports").
- ``_NON_PRINTABLE_ASCII`` compile le regex de sanitisation une seule fois
  (évite la recompilation à chaque ``set`` ou ``set_many``).
"""

import logging
import os
import re
from typing import Any, Dict, Final, List, Optional

from cryptography.fernet import InvalidToken, MultiFernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.database import get_session
from app.models.ai_config import (
    AIConfig,
    AIConfigKey,
    DEFAULT_AI_CONFIG,
    SECRET_CONFIG_KEYS,
)

logger = logging.getLogger(__name__)


# Fallback ultime de l'endpoint LLM local (Ollama), AVANT toute config admin.
# Source unique de vérité : tous les call-sites (runtime fallback, handlers
# admin, sync registre) passent par ce helper au lieu de hardcoder l'URL.
# Dérivé de l'environnement (``OLLAMA_BASE_URL``) → le ``docker-compose.yml``
# pose ``http://ollama:11434/v1`` (DNS du sidecar) sur le service app, tandis
# qu'en dev bare-metal (variable absente) on retombe sur ``localhost``. Aucun
# hardcode spécifique au déploiement dans le code métier (cf. règle GÉNÉRICITÉ).
_LOCAL_LLM_BASE_URL_FALLBACK: Final[str] = "http://localhost:11434/v1"


def default_local_llm_base_url() -> str:
    """Endpoint LLM local par défaut (env ``OLLAMA_BASE_URL`` sinon localhost).

    Utilisé UNIQUEMENT quand l'admin n'a pas configuré ``local_llm_base_url``
    en BDD (la valeur BDD reste prioritaire). Lu dynamiquement à chaque appel
    pour rester cohérent si l'environnement change entre deux requêtes.
    """
    return (os.getenv("OLLAMA_BASE_URL") or _LOCAL_LLM_BASE_URL_FALLBACK).strip()


# Alias rétro-compatible — la source de vérité reste ``SECRET_CONFIG_KEYS``
# défini côté modèle (importé par ``to_dict``, ``is_secret_key``, etc.).
# Un futur ajout de secret se fait EXCLUSIVEMENT en étendant le frozenset
# du modèle : chiffrement + masquage + redaction + exclusion d'export
# basculent ensemble, jamais en dérive.
ENCRYPTED_KEYS: Final[frozenset[str]] = SECRET_CONFIG_KEYS

# Validation de format des clés API
_API_KEY_FORMATS: Final[dict[str, dict[str, Any]]] = {
    AIConfigKey.API_KEY.value: {
        "prefix": "",
        "min_length": 10,
        "label": "Provider LLM",
    },
}

# Regex compilé une seule fois au chargement du module :
# supprime tout caractère non-imprimable ASCII (artefacts de copier-coller
# depuis le web — zero-width space, BOM, etc.) d'une clé API entrée par l'user.
_NON_PRINTABLE_ASCII: Final[re.Pattern[str]] = re.compile(r"[^\x20-\x7E]")


def _sanitize_secret_value(value: Any) -> str:
    """Strip les caractères non-imprimables ASCII (zero-width space, BOM d'un
    copier-coller web) d'un secret. SSoT du sanitize : partagé par
    ``_validate_value`` (mesure de longueur) et ``set``/``set_many`` (stockage)
    pour que la longueur VALIDÉE soit exactement celle STOCKÉE."""
    return _NON_PRINTABLE_ASCII.sub("", str(value)).strip()


# MultiFernet de la clé API, mémoïsé (PBKDF2 ~150ms). Reset via
# _reset_api_fernet_cache (tests qui patchent secret_key).
_cached_api_fernet: Optional[MultiFernet] = None


def _reset_api_fernet_cache() -> None:
    """Vide le cache MultiFernet de la clé API."""
    global _cached_api_fernet
    _cached_api_fernet = None


def _get_fernet() -> MultiFernet:
    """MultiFernet pour la clé API : clé PRIMARY dérivée via PBKDF2-HMAC-SHA256
    (600k itérations + salt persisté) + clé LEGACY ``SHA-256(secret_key)``
    conservée en LECTURE pour décrypter les clés stockées AVANT cette migration.

    SSoT crypto : réutilise les helpers de dérivation de ``db_config_service``
    (mêmes PBKDF2/salt que le mot de passe SQL Server) au lieu du SHA-256 brut
    historique (KDF faible, pas de rotation). La clé API migre vers PRIMARY au
    prochain ``set`` (MultiFernet chiffre toujours avec la 1ʳᵉ clé). Mémoïsé.

    On dérive depuis ``secret_key`` (PAS ``FERNET_KEY``) : les clés API
    historiques étaient chiffrées avec ``SHA-256(secret_key)``, donc la legacy
    DOIT utiliser ``secret_key`` pour rester déchiffrable.
    """
    global _cached_api_fernet
    if _cached_api_fernet is not None:
        return _cached_api_fernet
    # Import tardif : évite tout cycle au chargement (config_service est importé
    # tôt). Réutilise l'API crypto PUBLIQUE SSoT de db_config_service (mêmes
    # PBKDF2/salt que le mot de passe SQL Server).
    from app.services.database.db_config_service import build_multifernet

    _cached_api_fernet = build_multifernet(config.security.secret_key)
    return _cached_api_fernet


def encrypt_api_key(plain_key: str) -> str:
    """Chiffre une clé API avec Fernet."""
    if not plain_key:
        return ""
    f = _get_fernet()
    return f.encrypt(plain_key.encode("utf-8")).decode("utf-8")


def decrypt_api_key(encrypted_key: str) -> str:
    """Déchiffre une clé API."""
    if not encrypted_key:
        return ""
    try:
        f = _get_fernet()
        return f.decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
    except (InvalidToken, SQLAlchemyError, OSError, ValueError, ImportError) as e:
        # InvalidToken : le ciphertext ne se déchiffre pas (SECRET_KEY ayant
        # tourné, valeur corrompue en app_settings). MRO = InvalidToken→Exception,
        # donc PAS rattrapé par ValueError/OSError — il faut l'expliciter, sinon
        # il se propage et fait crasher TOUT _load_cache (primary_model inclus).
        # ImportError : si la SSoT crypto db_config_service casse/est renommée.
        # Dans tous ces cas on fail-closed (clé absente) plutôt que crasher le
        # path lecture — l'admin re-saisit la clé. NB : ConfigurationError
        # (crypto non initialisable, ex. data/ R/O) n'est volontairement PAS
        # rattrapée ici → elle se propage en 500 actionnable (cf. finding #22).
        logger.error("Erreur déchiffrement clé API: %s", e)
        return ""


def mask_api_key(api_key: str) -> str:
    """
    Masque une clé API pour affichage sécurisé.
    Format: sk-ant-***...***xyz (4 premiers + 3 derniers caractères)
    """
    if not api_key or len(api_key) < 10:
        return ""

    prefix = api_key[:7] if api_key.startswith("sk-") else api_key[:4]
    suffix = api_key[-3:]
    return f"{prefix}***...***{suffix}"


class AIConfigService:
    """
    Service de gestion de la configuration IA.

    Features:
    - Lecture avec cache mémoire
    - Écriture avec validation
    - Initialisation des valeurs par défaut
    - Export/import de la config
    """

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._cache_loaded = False

    async def _ensure_defaults(self, session: AsyncSession):
        """S'assure que toutes les clés par défaut existent.

        Upsert : insère les nouvelles clés, et met à jour les métadonnées
        (description, allowed_values, etc.) des clés existantes sans écraser
        la valeur configurée par l'utilisateur.
        """
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        for key_enum, cfg in DEFAULT_AI_CONFIG.items():
            key = key_enum.value
            stmt = (
                sqlite_insert(AIConfig)
                .values(
                    key=key,
                    value=cfg["value"],
                    description=cfg.get("description"),
                    category=cfg.get("category"),
                    value_type=cfg.get("value_type"),
                    min_value=cfg.get("min_value"),
                    max_value=cfg.get("max_value"),
                    allowed_values=cfg.get("allowed_values"),
                )
                .on_conflict_do_update(
                    index_elements=["key"],
                    set_={
                        "description": cfg.get("description"),
                        "category": cfg.get("category"),
                        "value_type": cfg.get("value_type"),
                        "min_value": cfg.get("min_value"),
                        "max_value": cfg.get("max_value"),
                        "allowed_values": cfg.get("allowed_values"),
                    },
                )
            )
            await session.execute(stmt)

        await session.commit()

    async def _load_cache(self):
        """Charge toute la configuration en mémoire."""
        if self._cache_loaded:
            return

        async with get_session() as session:
            await self._ensure_defaults(session)

            result = await session.execute(select(AIConfig))
            configs = result.scalars().all()

            for cfg in configs:
                # Déchiffrer les clés sensibles
                if cfg.key in ENCRYPTED_KEYS and cfg.value:
                    self._cache[cfg.key] = decrypt_api_key(cfg.value)
                else:
                    self._cache[cfg.key] = cfg.value

        self._cache_loaded = True
        logger.debug("Configuration IA chargée: %s clés", len(self._cache))

    def invalidate_cache(self):
        """Invalide le cache pour forcer un rechargement."""
        self._cache = {}
        self._cache_loaded = False

    async def get(self, key: AIConfigKey | str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration.

        Args:
            key: Clé de configuration (enum ou string)
            default: Valeur par défaut si non trouvée

        Returns:
            Valeur de la configuration
        """
        await self._load_cache()

        key_str = key.value if isinstance(key, AIConfigKey) else key
        return self._cache.get(key_str, default)

    def get_cached_sync(self, key: AIConfigKey | str, default: Any = None) -> Any:
        """Lecture SYNCHRONE du cache en mémoire — pour les chemins qui ne
        peuvent PAS ``await`` (code exécuté dans ``asyncio.to_thread``).

        Ne déclenche PAS de chargement BDD : si le cache n'est pas encore
        chargé (boot à froid, avant la 1ʳᵉ lecture async), retourne ``default``.
        Le cache étant peuplé au démarrage et à chaque requête config, le cas
        « non chargé » est marginal — et le ``default`` reste un fallback sûr.
        À n'utiliser QUE lorsque ``await get(...)`` est impossible ; sinon
        préférer la version async (toujours à jour).
        """
        if not self._cache_loaded:
            return default
        key_str = key.value if isinstance(key, AIConfigKey) else key
        return self._cache.get(key_str, default)

    async def get_all(self) -> Dict[str, Any]:
        """Retourne toute la configuration."""
        await self._load_cache()
        return self._cache.copy()

    async def get_all_for_display(self) -> Dict[str, Any]:
        """
        Retourne toute la configuration avec les clés sensibles masquées.
        Utilisé pour l'affichage dans l'interface admin.
        """
        await self._load_cache()
        config = self._cache.copy()

        # Masquer les clés sensibles
        for key in ENCRYPTED_KEYS:
            if key in config and config[key]:
                config[key] = mask_api_key(config[key])

        return config

    async def get_by_category(self, category: str) -> Dict[str, Any]:
        """Retourne la configuration d'une catégorie."""
        async with get_session() as session:
            result = await session.execute(select(AIConfig).where(AIConfig.category == category))
            configs = result.scalars().all()
            return {c.key: c.value for c in configs}

    async def get_full_config(self) -> List[Dict]:
        """Retourne toute la configuration avec métadonnées."""
        async with get_session() as session:
            await self._ensure_defaults(session)

            result = await session.execute(select(AIConfig))
            configs = result.scalars().all()
            return [c.to_dict() for c in configs]

    async def set(self, key: AIConfigKey | str, value: Any, user_id: Optional[int] = None) -> bool:
        """
        Met à jour une valeur de configuration.

        Args:
            key: Clé de configuration
            value: Nouvelle valeur
            user_id: ID utilisateur qui fait la modification

        Returns:
            True si succès

        Raises:
            ValueError: Si la valeur est invalide
        """
        key_str = key.value if isinstance(key, AIConfigKey) else key

        async with get_session() as session:
            result = await session.execute(select(AIConfig).where(AIConfig.key == key_str))
            config = result.scalar_one_or_none()

            if not config:
                raise ValueError(f"Clé de configuration inconnue: {key_str}")

            # Validation
            self._validate_value(config, value)

            # Chiffrer les clés sensibles avant stockage
            stored_value = value
            if key_str in ENCRYPTED_KEYS and value:
                value = _sanitize_secret_value(value)
                stored_value = encrypt_api_key(value)
                logger.debug("Clé API chiffrée: %s", key_str)

            # Audit : capturer l'ancienne valeur avant modification
            old_value = config.value
            is_sensitive = key_str in ENCRYPTED_KEYS

            # Mise à jour
            config.value = stored_value
            config.updated_by = user_id
            config.updated_at = clock.now()

            await session.commit()

        # Mettre à jour le cache avec la valeur déchiffrée
        self._cache[key_str] = value

        # Audit structuré
        audit_extra = {
            "action": "ai_config_update",
            "config_key": key_str,
            "user_id": user_id,
            "changed_at": clock.now().isoformat(),
        }
        if is_sensitive:
            audit_extra["old_value"] = "***" if old_value else "(vide)"
            audit_extra["new_value"] = f"{str(value)[:4]}***" if value else "(vide)"
        else:
            audit_extra["old_value"] = old_value
            audit_extra["new_value"] = value
        logger.info(
            f"[AUDIT] Config IA modifiée: {key_str} par user={user_id}",
            extra=audit_extra,
        )
        return True

    async def set_many(self, updates: Dict[str, Any], user_id: Optional[int] = None) -> int:
        """
        Met à jour plusieurs valeurs de configuration.

        Args:
            updates: Dictionnaire clé -> valeur
            user_id: ID utilisateur

        Returns:
            Nombre de clés mises à jour
        """
        count = 0

        async with get_session() as session:
            for key, value in updates.items():
                key_str = key.value if isinstance(key, AIConfigKey) else key

                result = await session.execute(select(AIConfig).where(AIConfig.key == key_str))
                config = result.scalar_one_or_none()

                if config:
                    try:
                        self._validate_value(config, value)

                        old_value = config.value
                        is_sensitive = key_str in ENCRYPTED_KEYS

                        # Chiffrer les clés sensibles avant stockage
                        stored_value = value
                        if is_sensitive and value:
                            value = _sanitize_secret_value(value)
                            stored_value = encrypt_api_key(value)

                        config.value = stored_value
                        config.updated_by = user_id
                        config.updated_at = clock.now()
                        # Cache avec valeur déchiffrée
                        self._cache[key_str] = value
                        count += 1

                        # Audit
                        logger.info(
                            f"[AUDIT] Config IA modifiée: {key_str} par user={user_id}",
                            extra={
                                "action": "ai_config_update",
                                "config_key": key_str,
                                "user_id": user_id,
                                "old_value": "***" if is_sensitive and old_value else old_value,
                                "new_value": (
                                    f"{str(value)[:4]}***" if is_sensitive and value else value
                                ),
                            },
                        )
                    except ValueError as e:
                        logger.warning("Valeur invalide ignorée pour %s: %s", key_str, e)

            await session.commit()

        logger.info("Configuration: %s clés mises à jour par user=%s", count, user_id)
        return count

    def _validate_value(self, config: AIConfig, value: Any):
        """Valide une valeur selon les contraintes."""
        # Type
        if config.value_type == "int" and not isinstance(value, int):
            try:
                value = int(value)
            except (ValueError, TypeError):
                raise ValueError("Valeur doit être un entier")

        if config.value_type == "float" and not isinstance(value, (int, float)):
            try:
                value = float(value)
            except (ValueError, TypeError):
                raise ValueError("Valeur doit être un nombre")

        if config.value_type == "bool" and not isinstance(value, bool):
            if isinstance(value, str):
                value = value.lower() in ("true", "1", "yes", "on")
            else:
                raise ValueError("Valeur doit être un booléen")

        # Min/Max (uniquement pour les types numériques)
        if config.min_value is not None and isinstance(value, (int, float)):
            if value < config.min_value:
                raise ValueError(f"Valeur minimum: {config.min_value}")

        if config.max_value is not None and isinstance(value, (int, float)):
            if value > config.max_value:
                raise ValueError(f"Valeur maximum: {config.max_value}")

        # Allowed values
        if config.allowed_values and value not in config.allowed_values:
            raise ValueError(f"Valeurs autorisées: {config.allowed_values}")

        # Validation format clés API
        if config.key in _API_KEY_FORMATS and value:
            fmt = _API_KEY_FORMATS[config.key]
            # Sanitize AVANT la mesure de longueur : des caractères invisibles
            # (zero-width space, BOM d'un copier-coller web) gonflent la
            # longueur brute, passeraient `min_length`, puis seraient strippés
            # au stockage (set/set_many) → clé tronquée SOUS le minimum, échec
            # silencieux au 1er appel LLM. On valide la longueur RÉELLE
            # post-sanitisation (même regex que le stockage).
            key_str = _sanitize_secret_value(value)
            if len(key_str) < fmt["min_length"]:
                raise ValueError(
                    f"Clé API {fmt['label']} trop courte (min {fmt['min_length']} caractères)"
                )
            if not key_str.startswith(fmt["prefix"]):
                raise ValueError(
                    f"Clé API {fmt['label']} invalide — doit commencer par '{fmt['prefix']}'"
                )

    async def export_config(self) -> Dict:
        """Exporte toute la configuration pour backup/restore.

        **Sécurité (OWASP Secrets Management Cheat Sheet §"Never include secrets
        in exports")** : les clés de ``SECRET_CONFIG_KEYS`` sont exclues
        intégralement — l'export ne contient aucune entrée ``api_key`` (pas même
        avec valeur redactée). L'opérateur qui restaure un backup doit
        re-saisir la clé API via l'UI admin dédiée.

        Defense-in-depth : ``AIConfig.to_dict`` redacte déjà la valeur côté
        modèle (``"***"``) mais ici on supprime l'entrée entière pour éviter
        qu'un import naïf écrase une clé réelle par ``"***"``.
        """
        configs = await self.get_full_config()
        safe_configs = [c for c in configs if c.get("key") not in SECRET_CONFIG_KEYS]
        return {
            "version": "1.0",
            "exported_at": clock.now().isoformat(),
            # L'export EXCLUT la clé API (SECRET_CONFIG_KEYS) mais inclut les
            # URLs de connexion (api_base_url, local_llm_base_url) = config
            # d'infra potentiellement sensible. On le signale dans le fichier.
            "_note": (
                "Ne contient PAS la cle API. Contient les URLs de connexion "
                "(api_base_url, local_llm_base_url) — config d'infra, ne pas "
                "partager publiquement sans revue."
            ),
            "config": safe_configs,
        }

    async def import_config(self, data: Dict, user_id: Optional[int] = None) -> int:
        """Importe une configuration exportée."""
        if "config" not in data:
            raise ValueError("Format d'import invalide")

        updates = {}
        for item in data["config"]:
            key = item.get("key")
            value = item.get("value")
            if key and value is not None:
                updates[key] = value

        return await self.set_many(updates, user_id)

    # Clés préservées au reset — ce sont des choix admin spécifiques au
    # déploiement qu'un reset config ne doit JAMAIS écraser :
    # - ``api_key`` / ``api_base_url`` : clé Anthropic propre à l'admin
    # - ``primary_provider`` / ``primary_model`` : choix admin de provider/modèle
    # - ``local_llm_*`` (sauf params de tuning) : URL/modèle Ollama propres au déploiement
    # - ``schema_sync_last_run`` : timestamp interne, écrit par le scheduler
    # - ``embedding_model`` : modèle local sentence-transformers spécifique
    _PRESERVE_ON_RESET: frozenset[str] = frozenset(
        {
            AIConfigKey.API_KEY.value,
            AIConfigKey.API_BASE_URL.value,
            AIConfigKey.PRIMARY_PROVIDER.value,
            AIConfigKey.PRIMARY_MODEL.value,
            AIConfigKey.FALLBACK_PROVIDER.value,
            AIConfigKey.FALLBACK_MODEL.value,
            AIConfigKey.LOCAL_LLM_ENABLED.value,
            AIConfigKey.LOCAL_LLM_BASE_URL.value,
            AIConfigKey.LOCAL_LLM_MODEL.value,
            AIConfigKey.SCHEMA_SYNC_LAST_RUN.value,
            AIConfigKey.EMBEDDING_MODEL.value,
        }
    )

    async def reset_to_defaults(self, user_id: Optional[int] = None) -> int:
        """Réinitialise les paramètres de tuning aux valeurs par défaut.

        Préserve les choix admin sensibles (clé API, modèle primary, URL/modèle
        Ollama) — cf. ``_PRESERVE_ON_RESET``. Sans cette protection, un reset
        casserait le provider configuré (api_key écrasée → vide) et obligerait
        l'admin à tout reconfigurer.
        """
        updates = {}
        for key_enum, cfg in DEFAULT_AI_CONFIG.items():
            if key_enum.value in self._PRESERVE_ON_RESET:
                continue
            updates[key_enum.value] = cfg["value"]

        self.invalidate_cache()
        return await self.set_many(updates, user_id)

    async def get_generator_config(self) -> Dict[str, Any]:
        """
        Retourne la configuration formatée pour VannaEnhancedGenerator.
        """
        await self._load_cache()

        return {
            "primary_provider": self._cache.get(AIConfigKey.PRIMARY_PROVIDER.value),
            "primary_model": self._cache.get(AIConfigKey.PRIMARY_MODEL.value),
            "fallback_provider": self._cache.get(AIConfigKey.FALLBACK_PROVIDER.value),
            "fallback_model": self._cache.get(AIConfigKey.FALLBACK_MODEL.value),
            "temperature": self._cache.get(AIConfigKey.TEMPERATURE.value, 0.1),
            "max_retries": self._cache.get(AIConfigKey.MAX_RETRIES.value, 3),
            "max_results": self._cache.get(AIConfigKey.MAX_RESULTS.value, 100),
            "timeout_seconds": self._cache.get(AIConfigKey.TIMEOUT_SECONDS.value, 120),
            "use_rag": self._cache.get(AIConfigKey.USE_RAG.value, True),
            "use_cache": self._cache.get(AIConfigKey.USE_CACHE.value, True),
            "log_performance": self._cache.get(AIConfigKey.LOG_PERFORMANCE.value, True),
            "auto_learn": self._cache.get(AIConfigKey.AUTO_LEARN.value, True),
            # Aligné avec ``_DEFAULT_CONFIGS[CONFIDENCE_THRESHOLD]`` (0.02) et
            # ``constants_ai.RAG_QUESTION_SQL_THRESHOLD``. Anti-divergence
            # SSoT (adversarial review 2026-05-27) : avant le fix, le
            # fallback ici était 0.7 ce qui rendait le RAG vide en pratique
            # quand l'admin n'avait pas seedé encore.
            "confidence_threshold": self._cache.get(AIConfigKey.CONFIDENCE_THRESHOLD.value, 0.02),
        }


# Singleton
_config_service: Optional[AIConfigService] = None


def get_ai_config_service() -> AIConfigService:
    """Retourne l'instance singleton du service de configuration."""
    global _config_service
    if _config_service is None:
        _config_service = AIConfigService()
    return _config_service


async def get_max_upload_size_bytes() -> int:
    """SSoT : taille maximale d'UN fichier uploadé (en octets).

    Lit ``AIConfigKey.MAX_UPLOAD_SIZE_BYTES`` (configurable par l'admin via
    ``/admin/performance``), avec fallback sur la valeur par défaut de
    ``DEFAULT_AI_CONFIG`` — source unique, pas de nombre magique — si le
    service est indisponible ou la valeur corrompue.

    **Single source of truth** : les points de RÉCEPTION d'upload utilisateur
    (trombone Iris, datastore, upload de rapport, réponse de collaborateur
    wait_response) DOIVENT passer par ce helper. Aucune constante hardcodée
    divergente, aucun cap caché en aval qui masquerait la config admin
    (cf. doctrine « admin source unique » — feedback_no_double_cap).

    Exclusions volontaires (limites dédiées distinctes) : fichiers générés en
    interne (rapports), pièces jointes des mails sortants (limite SMTP), import
    CSV de contacts (limite métier testée), import de configuration d'automation,
    et le parsing openpyxl/CSV en RAM (protection anti-DoS de workbooks.py).
    """
    from app.models.ai_config import AIConfigKey, DEFAULT_AI_CONFIG

    try:
        svc = get_ai_config_service()
        value = await svc.get(AIConfigKey.MAX_UPLOAD_SIZE_BYTES)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning(
            "Lecture max_upload_size échouée (fallback DEFAULT_AI_CONFIG) : %s",
            exc,
        )
    fallback = DEFAULT_AI_CONFIG[AIConfigKey.MAX_UPLOAD_SIZE_BYTES]["value"]
    return int(fallback)
