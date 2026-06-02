"""Crée le premier compte administrateur Komptia (idempotent).

Exécution : ``python -m scripts.seed_admin`` (cf. ``make db-seed-admin``).

Sources de configuration (par priorité décroissante) :

1. Arguments CLI : ``--username``, ``--email``, ``--password``.
2. Variables d'environnement : ``KOMPTIA_ADMIN_USERNAME``,
   ``KOMPTIA_ADMIN_EMAIL``, ``KOMPTIA_ADMIN_PASSWORD``.
3. Saisie interactive (``input`` + ``getpass``) — uniquement si stdin
   est attaché à un terminal (TTY).

Idempotence :

* Si un compte ``role=admin`` existe déjà, le script refuse la création
  avec un message clair, code de sortie ``0``. La chaîne ``make
  db-bootstrap`` reste donc rejouable sans dommage.
* Le drapeau ``--force`` permet de créer un admin **supplémentaire**
  (onboarding multi-administrateurs). Le script refuse toujours de
  remplacer / réécrire un admin existant — la modification de mot de
  passe passe par l'écran ``/settings`` ou par le DBA.

Sécurité :

* Le mot de passe est hashé via :class:`PasswordHasher` (bcrypt avec les
  ``rounds`` configurés dans :class:`SecurityConfig`).
* Aucun mot de passe n'est jamais affiché ni loggé en clair.
* Validation stricte côté script (avant insertion BDD) : longueur, format
  email, charset username — fail-fast pour éviter de polluer la BDD.
* La génération du mot de passe (mode ``--generate-password``) utilise
  :mod:`secrets` (CSPRNG) avec un alphabet sécurisé.
"""

from __future__ import annotations

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import argparse
import asyncio
import getpass
import os
import re
import secrets
import string
import sys
from typing import Final, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.core.database import get_session, init_database
from app.models.user import User, UserRole
from app.services.auth.password_hasher import get_password_hasher
from app.utils.logger import AppLogger, get_logger

logger = get_logger(__name__)


# ── Constantes de validation (alignées BDD + OWASP ASVS V6) ─────────────
_USERNAME_MIN_LENGTH: Final[int] = 3
_USERNAME_MAX_LENGTH: Final[int] = 50  # = `String(50)` sur ``users.username``
_USERNAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._-]+$")
_EMAIL_MAX_LENGTH: Final[int] = 254  # = `String(254)` sur ``users.email`` (RFC 5321)
_EMAIL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
)
_PASSWORD_MIN_LENGTH: Final[int] = 12  # OWASP ASVS V6.1.2 : min 12 chars
_GENERATED_PASSWORD_LENGTH: Final[int] = 24
#: Alphabet de génération (ADV-S26) — alphanum + ``-`` ``_`` uniquement.
#: Avant : ``_-.@!`` qui pouvait causer des collisions shell (``!``
#: déclenche l'expansion historique en bash) si l'utilisateur copie-colle
#: le mdp dans un terminal interactif. Le mix lettres+chiffres seul donne
#: déjà ~143 bits d'entropie sur 24 chars, largement suffisant.
_GENERATED_PASSWORD_ALPHABET: Final[str] = string.ascii_letters + string.digits + "-_"
#: Nombre max d'essais pour générer un mdp OWASP-compliant. 1 sur 100k
#: rounds en moyenne sur 24 chars purement alphanum, donc 50 essais
#: rendent une faille (~1e-50) plus improbable qu'une collision SHA-256.
_GENERATED_PASSWORD_MAX_ATTEMPTS: Final[int] = 50


# ── Codes de sortie ─────────────────────────────────────────────────────
_EXIT_OK: Final[int] = 0
_EXIT_VALIDATION_ERROR: Final[int] = 1
_EXIT_DB_ERROR: Final[int] = 2
_EXIT_NOT_INTERACTIVE: Final[int] = 3
_EXIT_ABORTED: Final[int] = 130  # Ctrl+C convention POSIX


# ── Validation pure (testable sans DB) ──────────────────────────────────


def _validate_username(value: str) -> Optional[str]:
    """Retourne ``None`` si valide, sinon un message d'erreur explicite."""
    if not value:
        return "Le nom d'utilisateur ne peut pas être vide."
    if len(value) < _USERNAME_MIN_LENGTH:
        return f"Le nom d'utilisateur doit faire au moins {_USERNAME_MIN_LENGTH} caractères."
    if len(value) > _USERNAME_MAX_LENGTH:
        return f"Le nom d'utilisateur ne peut pas dépasser {_USERNAME_MAX_LENGTH} caractères."
    if not _USERNAME_PATTERN.match(value):
        return "Le nom d'utilisateur ne peut contenir que lettres, chiffres, '.', '_' et '-'."
    return None


def _validate_email(value: str) -> Optional[str]:
    if not value:
        return "L'email ne peut pas être vide."
    if len(value) > _EMAIL_MAX_LENGTH:
        return f"L'email ne peut pas dépasser {_EMAIL_MAX_LENGTH} caractères."
    if not _EMAIL_PATTERN.match(value):
        return "L'email ne semble pas valide (format attendu : nom@domaine.tld)."
    return None


def _validate_password(value: str) -> Optional[str]:
    if not value:
        return "Le mot de passe ne peut pas être vide."
    if len(value) < _PASSWORD_MIN_LENGTH:
        return (
            f"Le mot de passe doit faire au moins {_PASSWORD_MIN_LENGTH} caractères "
            "(recommandation OWASP ASVS V6.1.2)."
        )
    # bcrypt tronque silencieusement à 72 bytes : on coupe avant pour éviter
    # l'illusion d'un mdp long alors que seuls les 72 premiers comptent.
    if len(value.encode("utf-8")) > 72:
        return "Le mot de passe ne peut pas dépasser 72 octets (limite bcrypt)."
    return None


def _has_required_classes(value: str) -> bool:
    """True si le mdp contient au moins 1 lettre minuscule, 1 majuscule
    et 1 chiffre — exigence OWASP ASVS V6 pour les mdp générés."""
    return (
        any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
    )


def _generate_password() -> str:
    """Génère un mot de passe aléatoire fort (CSPRNG) OWASP-compliant.

    ADV-C10 : avant, ``secrets.choice`` sur l'alphabet pouvait produire
    1 fois sur ~100k un mdp 24 chars sans aucun chiffre ou sans aucune
    majuscule (purement minuscules) — non conforme OWASP ASVS V6 qui
    exige le mix de classes. On boucle jusqu'à obtenir un mdp valide
    (en pratique 1-3 essais maximum).
    """
    for _ in range(_GENERATED_PASSWORD_MAX_ATTEMPTS):
        candidate = "".join(
            secrets.choice(_GENERATED_PASSWORD_ALPHABET)
            for _ in range(_GENERATED_PASSWORD_LENGTH)
        )
        if _has_required_classes(candidate):
            return candidate
    # Quasi-impossible (probabilité < 1e-50) — fallback verbeux pour
    # garantir le mix : on injecte 1 char de chaque classe en positions
    # aléatoires.
    base = list(
        "".join(secrets.choice(_GENERATED_PASSWORD_ALPHABET) for _ in range(_GENERATED_PASSWORD_LENGTH - 3))
    )
    for forced in (secrets.choice(string.ascii_lowercase),
                   secrets.choice(string.ascii_uppercase),
                   secrets.choice(string.digits)):
        base.insert(secrets.randbelow(len(base) + 1), forced)
    return "".join(base)


# ── Sources de configuration ────────────────────────────────────────────


def _from_env() -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Lit les vars d'env. Vide → ``None`` (pas un str vide)."""
    return (
        os.environ.get("KOMPTIA_ADMIN_USERNAME") or None,
        os.environ.get("KOMPTIA_ADMIN_EMAIL") or None,
        os.environ.get("KOMPTIA_ADMIN_PASSWORD") or None,
    )


def _prompt_value(label: str, validator) -> str:
    """Boucle de saisie d'un champ visible jusqu'à validation."""
    while True:
        value = input(f"{label} : ").strip()
        err = validator(value)
        if err is None:
            return value
        sys.stderr.write(f"  ⚠ {err}\n")


def _prompt_password() -> str:
    """Saisie cachée + confirmation."""
    while True:
        pw = getpass.getpass("Mot de passe (≥12 caractères) : ")
        err = _validate_password(pw)
        if err is not None:
            sys.stderr.write(f"  ⚠ {err}\n")
            continue
        confirm = getpass.getpass("Confirmer le mot de passe : ")
        if pw != confirm:
            sys.stderr.write("  ⚠ Les mots de passe ne correspondent pas.\n")
            continue
        return pw


# ── Logique BDD ─────────────────────────────────────────────────────────


async def _admin_exists() -> Optional[str]:
    """Retourne le username du premier admin trouvé, ou ``None``."""
    async with get_session() as db:
        result = await db.execute(
            select(User.username).where(User.role == UserRole.ADMIN).limit(1)
        )
        row = result.scalar_one_or_none()
    return row


async def _check_username_email_available(
    *, username: str, email: str
) -> Optional[str]:
    """ADV-C12 : pré-vérifie en SELECT si username OU email sont déjà
    pris. Retourne un message d'erreur **précis** (lequel des deux) ou
    ``None`` si tout est libre. Avant : on relayait l'``IntegrityError``
    générique sans dire à l'admin lequel des deux modifier."""
    async with get_session() as db:
        from sqlalchemy import or_

        result = await db.execute(
            select(User.username, User.email).where(
                or_(User.username == username, User.email == email)
            )
        )
        rows = result.all()
        for row_username, row_email in rows:
            if row_username == username:
                return f"L'identifiant {username!r} est déjà utilisé."
            if row_email == email:
                return f"L'email {email!r} est déjà utilisé."
    return None


async def _create_admin(*, username: str, email: str, password: str) -> int:
    """Insère l'admin et retourne son id.

    Pré-vérifie les conflits (cf. :func:`_check_username_email_available`)
    pour donner un message précis. ``IntegrityError`` reste possible en
    cas de race (deux ``seed_admin`` concurrents) — le caller la traite.
    """
    hasher = get_password_hasher()
    password_hash = hasher.hash_password(password)
    async with get_session() as db:
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            role=UserRole.ADMIN,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user.id


# ── Orchestration ───────────────────────────────────────────────────────


def _resolve_inputs(
    args: argparse.Namespace,
) -> tuple[str, str, str]:
    """Combine CLI > env > prompt interactif. Lève SystemExit si non-tty.

    ADV-C11 : ``--no-prompt`` force le mode non-interactif quel que soit
    l'état du TTY (utile en CI / Docker exec interactif). ADV-S25 :
    ``--generate-password`` fonctionne aussi en mode non-interactif —
    le mdp est écrit sur stdout (l'utilisateur capture la sortie).
    """
    env_user, env_email, env_password = _from_env()

    username = args.username or env_user
    email = args.email or env_email
    password = args.password or env_password

    # ADV-S25 : générer le password AVANT de tester ``needs_prompt``
    # quand --generate-password est explicite. Permet le mode CI :
    # ``python -m scripts.seed_admin --username x --email y --generate-password``.
    if args.generate_password and not password:
        password = _generate_password()
        sys.stdout.write(
            "\n⚠ Mot de passe généré (à conserver en lieu sûr — il ne sera "
            "PAS réaffiché) :\n"
        )
        sys.stdout.write(f"  {password}\n\n")
        sys.stdout.write(
            "  ⚠ Si vous avez redirigé stdout vers un fichier (CI), le mot de "
            "passe est désormais persisté en clair. Sécurisez/effacez ce "
            "fichier après usage.\n\n"
        )

    needs_prompt = not (username and email and password)

    if needs_prompt:
        # ADV-C11 : --no-prompt force le rejet non-interactif quel que
        # soit le TTY (CI Docker exec -it qui ne veut PAS d'interactivité).
        is_interactive = sys.stdin.isatty() and not getattr(args, "no_prompt", False)
        if not is_interactive:
            sys.stderr.write(
                "Mode non-interactif (TTY absent ou --no-prompt) avec arguments "
                "incomplets. Fournissez --username, --email et --password "
                "(ou --generate-password) ou les vars d'env KOMPTIA_ADMIN_*.\n"
            )
            raise SystemExit(_EXIT_NOT_INTERACTIVE)

        sys.stdout.write("\n=== Komptia — Création du premier administrateur ===\n\n")

        if not username:
            username = _prompt_value("Identifiant (3-50 car., [A-Za-z0-9._-])", _validate_username)
        if not email:
            email = _prompt_value("Email", _validate_email)
        if not password:
            password = _prompt_password()

    # Validation finale (CLI/env n'ont pas de boucle de saisie).
    for label, value, validator in (
        ("--username", username, _validate_username),
        ("--email", email, _validate_email),
        ("--password", password, _validate_password),
    ):
        err = validator(value)
        if err is not None:
            sys.stderr.write(f"❌ {label} invalide : {err}\n")
            raise SystemExit(_EXIT_VALIDATION_ERROR)

    return username, email, password


async def _run(args: argparse.Namespace) -> int:
    """Logique principale. Retourne le code de sortie."""
    await init_database()

    existing = await _admin_exists()
    if existing and not args.force:
        sys.stdout.write(
            f"\nℹ Un administrateur existe déjà : {existing!r}.\n"
            "  Aucune action prise (idempotent).\n"
            "  Pour créer un admin supplémentaire, relancez avec --force.\n"
            "  Pour réinitialiser un mot de passe, passez par /settings ou par le DBA.\n\n"
        )
        return _EXIT_OK

    username, email, password = _resolve_inputs(args)

    # ADV-C12 : pré-check précis avant l'INSERT pour donner un message
    # actionnable (lequel des deux est en conflit). L'IntegrityError
    # reste catchée en backup pour le cas race.
    conflict = await _check_username_email_available(username=username, email=email)
    if conflict is not None:
        sys.stderr.write(f"❌ {conflict}\n")
        return _EXIT_DB_ERROR

    try:
        user_id = await _create_admin(username=username, email=email, password=password)
    except IntegrityError:
        sys.stderr.write(
            "❌ Conflit username/email (race avec un autre process ?). Réessayez.\n"
        )
        return _EXIT_DB_ERROR
    except SQLAlchemyError:
        logger.critical("Échec création admin (BDD)", exc_info=True)
        sys.stderr.write("❌ Erreur base de données — voir les logs serveur pour le détail.\n")
        return _EXIT_DB_ERROR

    sys.stdout.write(
        f"\n✅ Administrateur créé : {username!r} (id={user_id}).\n"
        f"   Identifiant de connexion : {email}\n"
        "   Connectez-vous maintenant sur /login (la casse de l'email n'a pas d'importance).\n\n"
    )
    return _EXIT_OK


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="seed_admin",
        description=(
            "Crée le premier compte administrateur Komptia. Idempotent : "
            "ne fait rien si un admin existe déjà (sauf --force)."
        ),
        epilog=(
            "Exemples :\n"
            "  python -m scripts.seed_admin                       # mode interactif\n"
            "  python -m scripts.seed_admin --username admin \\\n"
            "      --email admin@local --password 'MdpFort123!'   # mode CI\n"
            "  KOMPTIA_ADMIN_USERNAME=ops KOMPTIA_ADMIN_EMAIL=ops@x \\\n"
            "      KOMPTIA_ADMIN_PASSWORD=... python -m scripts.seed_admin\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--username", help="Nom d'utilisateur (3-50 car., [A-Za-z0-9._-]).")
    parser.add_argument("--email", help="Email administrateur.")
    parser.add_argument("--password", help="Mot de passe (≥12 caractères).")
    parser.add_argument(
        "--generate-password",
        action="store_true",
        help=(
            "Génère un mot de passe fort (24 chars alphanum mixés, OWASP-compliant) "
            "et l'affiche UNE FOIS. Fonctionne en interactif ET non-interactif "
            "(stdout — capturer le mdp dans la sortie)."
        ),
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help=(
            "Force le mode non-interactif : si les arguments/env sont incomplets, "
            "on échoue (exit 3) au lieu de prompter. Utile en CI où un TTY peut "
            "être attaché par accident (docker exec -it)."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Crée l'admin même si un autre admin existe déjà.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """Point d'entrée CLI (testable : passer ``argv``)."""
    AppLogger.setup("INFO")
    args = _parse_args(argv)
    try:
        return asyncio.run(_run(args))
    except KeyboardInterrupt:
        sys.stderr.write("\n⚠ Annulé par l'utilisateur.\n")
        return _EXIT_ABORTED
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else _EXIT_VALIDATION_ERROR


if __name__ == "__main__":
    sys.exit(main())
