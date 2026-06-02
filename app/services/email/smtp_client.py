"""
Client SMTP pour envoi d'emails avec support TLS et pièces jointes.
"""

import asyncio
import re
import smtplib
import logging
import tempfile
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.image import MIMEImage
from email import policy
from email.utils import format_datetime, make_msgid
from pathlib import Path
from typing import Any, Dict, Final, List, Optional, Sequence, Tuple, Union

from app.constants import SMTP_TIMEOUT_SECONDS, SMTP_TEST_TIMEOUT_SECONDS
from app.core import clock
from app.core.database import get_session
from app.utils.validators import is_valid_email

logger = logging.getLogger(__name__)

# Taille max d'une pièce jointe (50 Mo)
_MAX_ATTACHMENT_SIZE = 50 * 1024 * 1024
# Cap du TOTAL des pièces jointes d'un message (anti-OOM). Le cap par-pièce
# ci-dessus ne borne PAS la somme : N fichiers (chacun < 50 Mo) sont tous lus
# en mémoire + encodés base64 dans UN MIME avant l'envoi → OOM pendant le build
# (indispo serveur, pas seulement pour l'expéditeur) AVANT que le SMTP ne puisse
# rejeter. Garde partagée par TOUS les chemins d'envoi (contacts, rapports,
# automations — le handler /reports pré-vérifie en plus pour un 400 fast-fail).
# 50 Mo : un message au-delà est de toute façon rejeté par la plupart des SMTP.
_MAX_TOTAL_ATTACHMENT_SIZE = 50 * 1024 * 1024


def _resolve_allowed_attachment_roots() -> Tuple[Path, ...]:
    """Renvoie les répertoires racines autorisés pour les pièces jointes.

    Sandbox de defense-in-depth (axe 8 CLAUDE.md) : ``_add_attachments``
    rejette tout fichier dont le chemin résolu n'est pas sous l'une de
    ces racines, pour empêcher l'exfiltration arbitraire de fichiers
    serveur (`/etc/passwd`, clés SSH, secrets) si un call-site future
    accepte un path user-controlled.

    Roots autorisées :
    - ``DATA_DIR`` (rapports, exports, sage_copy.db, datastore…) — la
      surface persistante de Komptia est entièrement sous cette racine.
    - ``tempfile.gettempdir()`` — pour les tempfiles légitimes créés
      par le flow ``dashboard/delivery_service.py:_send_dashboard_email``
      (mkstemp .csv/.xlsx) et autres pipelines reporting.

    Lazy import de ``DATA_DIR`` car ``db_config_service`` peut le
    rediriger en runtime ; un cache module-level masquerait la
    redirection.
    """
    from app.config import DATA_DIR

    roots: List[Path] = [Path(DATA_DIR).resolve()]
    sys_tmp = Path(tempfile.gettempdir()).resolve()
    if sys_tmp not in roots:
        roots.append(sys_tmp)
    return tuple(roots)


def _is_under_allowed_root(resolved: Path, roots: Tuple[Path, ...]) -> bool:
    """True si ``resolved`` est sous (ou égal à) au moins une root.

    Utilise ``Path.relative_to`` (Python 3.10+ comportement stable) avec
    fallback try/except pour rester compatible si une root n'est pas un
    parent (renvoie ``ValueError``).
    """
    for root in roots:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _attachment_skip_reason(filepath: Path) -> Tuple[Optional[str], int]:
    """Prédicat UNIQUE « faut-il skipper cette pièce jointe ? » — zéro lecture
    de contenu (uniquement stat/path).

    Source de vérité PARTAGÉE par la pré-passe anti-OOM de ``_add_attachments``
    (qui ne doit compter dans le total QUE les pièces réellement incluses dans
    le MIME) ET la passe principale (skip + log). Avant cette unification, les
    deux passes divergeaient : la pré-passe ne reflétait que le cap par-taille,
    donc une pièce symlink/hors-sandbox/'..' (skippée par la passe principale)
    comptait quand même dans le total → faux refus (#50).

    Retourne ``(None, taille)`` si la pièce sera INCLUSE, sinon ``(raison, 0)``.
    Ordre des prédicats = ordre historique de la passe principale (symlink →
    '..' → hors-sandbox → inexistant → trop volumineuse) pour un diagnostic
    loggé cohérent.
    """
    try:
        if filepath.is_symlink():
            return "symlink", 0
        if ".." in str(filepath):
            return "path traversal ('..')", 0
        resolved = filepath.resolve()
        if not _is_under_allowed_root(resolved, _resolve_allowed_attachment_roots()):
            return "hors sandbox autorisée (data/ ou tempfile.gettempdir)", 0
        if not resolved.exists():
            return "fichier introuvable", 0
        size = resolved.stat().st_size
        if size > _MAX_ATTACHMENT_SIZE:
            return f"trop volumineuse ({size} octets > {_MAX_ATTACHMENT_SIZE})", 0
        return None, size
    except OSError as exc:
        # Inaccessible (permissions, FS) → skip propre, ne compte pas.
        return f"inaccessible ({exc})", 0


def _sanitize_header(value: str) -> str:
    """Rejette les en-têtes contenant des caractères CRLF (prévention injection)."""
    if "\r" in value or "\n" in value:
        raise ValueError("Caractère interdit (CR/LF) détecté dans l'en-tête email")
    return value


def _normalize_recipient_arg(value: object) -> Optional[List[object]]:
    """Convertit l'argument destinataire en liste, ou retourne None si type incompatible.

    Accepte :
    - ``str`` → ``[value]``
    - ``list`` / ``tuple`` / ``set`` / ``frozenset`` → ``list(value)``
    - ``None`` ou autre type non-iterable utile → ``None`` (le caller décide
      si c'est un refus dur ou un fallback à liste vide).

    On exclut ``dict`` et ``bytes`` même si itérables : leur itération ne
    donne pas ce qu'attend un appelant qui passe « des emails ».
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return None


# ── Bornes anti-DoS pour l'audit ─────────────────────────────────────────

#: Longueur max d'un ``error_message`` persisté en audit. EmailLog.error_message
#: est ``Text`` (pas de limite SQL) — sans cap applicatif, un traceback SMTP
#: de 100k chars partirait dans l'API ``/api/email-history`` à chaque page.
#: Croissance non-bornée (axe Komptia 21).
_AUDIT_ERROR_MESSAGE_MAX: Final[int] = 1000

#: Longueur max d'un nom de pièce jointe affiché en audit. ``Text`` non-borné
#: dans le modèle ; sans cap, un caller passant ``["x"*1_000_000]`` ferait un
#: write 1MB par envoi. 255 = limite filesystem standard, suffit largement.
_AUDIT_ATTACHMENT_NAME_MAX: Final[int] = 255

#: Nombre max d'attachments loggés. Cap sur la longueur de la liste pour
#: empêcher ``attachments=["foo.txt"] * 10_000``. 50 = nettement plus que
#: ce qu'un mail réel transporte.
_AUDIT_ATTACHMENT_COUNT_MAX: Final[int] = 50

#: Pattern email (RFC 5322 simplifié) pour scrubbing PII des error_message.
#: Les serveurs SMTP renvoient parfois des bannières contenant l'adresse
#: refusée ou même le username d'auth (ex: ``535 5.7.0 authentication
#: failed for alice@cabinet.fr``). On ne veut pas les persister en clair
#: dans la BDD d'audit (RGPD + leak admin).
_AUDIT_PII_EMAIL_PATTERN: Final = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _clean_emails_for_audit(values: Sequence[object]) -> List[str]:
    """Strip + filter valides, SANS log (vs ``_filter_valid_emails``).

    Utilisé exclusivement par le chemin d'audit ``send_email`` pour ne
    pas double-logger les destinataires invalides : ``_send_email_sync``
    a déjà émis le warning côté envoi.
    """
    out: List[str] = []
    for raw in values:
        if not isinstance(raw, str):
            continue
        candidate = raw.replace("\xa0", " ").strip()
        if is_valid_email(candidate):
            out.append(candidate)
    return out


def _scrub_audit_error_message(message: Optional[str]) -> Optional[str]:
    """Tronque + scrub les emails PII d'un ``error_message`` pour audit.

    Cas d'usage : un ``smtplib.SMTPException`` peut contenir une bannière
    serveur (``550 No such user: alice@cabinet.fr``) qui leak l'adresse
    du destinataire OU un username d'auth (``535 5.7.0 authentication
    failed for admin@cabinet.fr``) — la persister en clair dans la BDD
    violerait l'anti-PII policy (cf. ``_filter_valid_emails``).

    Algorithme : on remplace chaque email match par ``<email-redacted>``,
    puis on tronque à ``_AUDIT_ERROR_MESSAGE_MAX`` chars.
    """
    if not message:
        return message
    scrubbed = _AUDIT_PII_EMAIL_PATTERN.sub("<email-redacted>", message)
    return scrubbed[:_AUDIT_ERROR_MESSAGE_MAX]


def _extract_attachment_names(
    attachments: Optional[Sequence[Union[str, Path, Dict]]],
) -> List[str]:
    """Extrait les noms de fichiers depuis le paramètre ``attachments``.

    Mirror de la logique de ``_add_attachments`` (qui choisit
    ``attachment["filename"]`` sinon ``Path(path).name``). Utilisé pour
    peupler ``EmailLog.attachment_names`` sans toucher au flux d'envoi.

    Garde-fous :
    - ``None`` / item invalide ignoré (vs. placeholder ``"fichier"`` qui
      mentait sur ``attachment_count`` côté UI).
    - Cap par-nom à ``_AUDIT_ATTACHMENT_NAME_MAX`` chars.
    - Cap total à ``_AUDIT_ATTACHMENT_COUNT_MAX`` entrées.

    Pas de side-effect (pas de lecture disque).
    """
    if not attachments:
        return []
    names: List[str] = []
    for item in attachments:
        if item is None:
            continue
        try:
            if isinstance(item, dict):
                path_str = str(item.get("path") or "")
                name = item.get("filename") or Path(path_str).name
            else:
                name = Path(item).name
        except (TypeError, ValueError):
            # Attachment malformé : on skip plutôt que de fabriquer un faux nom.
            continue
        if not name:
            continue
        names.append(str(name)[:_AUDIT_ATTACHMENT_NAME_MAX])
        if len(names) >= _AUDIT_ATTACHMENT_COUNT_MAX:
            break
    return names


def _build_audit_payload(
    *,
    send_result: Optional[Dict[str, Any]],
    send_exception: Optional[BaseException],
    to_emails: Any,
    cc_emails: Any,
    bcc_emails: Any,
    subject: str,
    attachments: Optional[Sequence[Union[str, Path, Dict]]],
    audit_attachment_names: Optional[Sequence[str]],
    automation_id: Optional[int],
    execution_id: Optional[int],
    sent_by_user_id: Optional[int],
    template_name: Optional[str],
) -> Dict[str, Any]:
    """Assemble la payload ``EmailLog`` à partir d'un résultat OU d'une exception.

    Single source of truth pour la collecte des métadonnées d'audit. Le
    chemin succès et le chemin on-raise convergent ici — plus de duplication
    entre les deux blocs de ``send_email`` (cf. revue clean-code 2026-05-22).

    Règles métier :
    - Si l'envoi a complètement échoué (``success=False`` ET ``recipients=[]``
      ET pas ``partial_success``), aucun mail n'est sorti : on **n'enregistre
      pas** cc/bcc — les loguer mentirait sur ce qui a quitté la machine.
    - On filtre symétriquement to/cc/bcc via ``_clean_emails_for_audit`` —
      l'invariant audit doit être respecté quelle que soit la confiance du
      caller (résultat de mock, sous-classe, etc.).
    - ``error_message`` est scrubbé (PII emails) + tronqué dans tous les cas.
    """
    if send_exception is not None:
        # Audit-on-raise : on ne sait pas si le mail est parti. ``str(exc)``
        # peut contenir un payload utilisateur (CRLF injection rejetée par
        # ``_sanitize_header`` = la valeur subject sensible) ou un user/host
        # SMTP. On limite au type d'exception pour la BDD ; la stack complète
        # va dans le log serveur (admin-only, rotation TTL).
        success = False
        message_id_val: Optional[str] = None
        error_message = _scrub_audit_error_message(
            f"{type(send_exception).__name__}: {send_exception}"
        )
        envelope_dispatched = False  # exception avant envoi probable
    else:
        result = send_result or {}
        success = bool(result.get("success"))
        message_id_val = result.get("message_id") if success else None
        if success:
            error_message = None
        else:
            raw_error = result.get("error") or result.get("message")
            # ``refused_recipients`` complète le message d'erreur pour
            # diagnostic /email-history (sinon l'admin voit "Echec" sans
            # savoir QUELS destinataires ont bouncé).
            refused = result.get("refused_recipients") or []
            if refused:
                raw_error = (
                    f"{raw_error or 'Envoi partiel'}"
                    f" — refusé(s) : {', '.join(str(r) for r in refused)}"
                )
            error_message = _scrub_audit_error_message(raw_error)
        # « envelope dispatched » = un MAIL FROM/RCPT TO a touché le serveur SMTP.
        # Critère : recipients non vide OU partial_success. Si tout est vide
        # ET pas partial_success → aucun mail n'est sorti, donc on ne logue
        # ni cc ni bcc.
        envelope_dispatched = bool(result.get("recipients") or result.get("partial_success"))

    # Normalisation des destinataires. Symétrie : on applique
    # ``_clean_emails_for_audit`` à to/cc/bcc même si ``_send_email_sync``
    # a déjà filtré côté envoi (defense-in-depth + protection contre les
    # mocks de test qui passeraient des chaînes invalides).
    to_raw = _normalize_recipient_arg(to_emails) or []
    to_list = _clean_emails_for_audit(to_raw)
    if envelope_dispatched:
        cc_raw = _normalize_recipient_arg(cc_emails) if cc_emails else []
        bcc_raw = _normalize_recipient_arg(bcc_emails) if bcc_emails else []
        cc_list = _clean_emails_for_audit(cc_raw or [])
        bcc_list = _clean_emails_for_audit(bcc_raw or [])
    else:
        # Aucune enveloppe SMTP n'est partie → cc/bcc n'ont vu personne.
        cc_list = []
        bcc_list = []

    if audit_attachment_names is not None:
        # Caller fournit explicitement les noms : on applique le cap par-nom
        # et le cap total (defense-in-depth).
        attachment_names = [
            str(n)[:_AUDIT_ATTACHMENT_NAME_MAX]
            for n in list(audit_attachment_names)[:_AUDIT_ATTACHMENT_COUNT_MAX]
        ]
    else:
        attachment_names = _extract_attachment_names(attachments)

    return {
        "to_list": to_list,
        "cc_list": cc_list,
        "bcc_list": bcc_list,
        "subject": subject,
        "template_name": template_name,
        "success": success,
        "message_id": message_id_val,
        "error_message": error_message,
        "attachment_names": attachment_names,
        "automation_id": automation_id,
        "execution_id": execution_id,
        "sent_by_user_id": sent_by_user_id,
    }


async def _write_email_log_async(
    *,
    to_list: List[str],
    cc_list: List[str],
    bcc_list: List[str],
    subject: str,
    template_name: Optional[str],
    success: bool,
    message_id: Optional[str],
    error_message: Optional[str],
    attachment_names: List[str],
    automation_id: Optional[int],
    execution_id: Optional[int],
    sent_by_user_id: Optional[int],
) -> None:
    """Insère une entrée ``EmailLog`` (best-effort, jamais propagé).

    Centralisé pour qu'AUCUN site d'envoi ne soit oublié dans l'audit
    ``/email-history`` (cause racine générique vs N patchs case-by-case —
    cf. mémoire ``feedback_generic_root_cause_not_specific_patch``).

    L'audit ne bloque JAMAIS la délivrance : DB lock / session corrompue
    / FK invalide → warning log, return silencieux. Le mail est déjà
    parti (ou a déjà échoué) au moment où on arrive ici.

    Toutes les bornes applicatives (subject, message_id, error_message,
    attachment_names) sont appliquées ici, source unique. Aucun caller
    ne doit re-truncer en amont — sinon double-cap silencieux.
    """
    try:
        import json as _json

        from app.models.email_log import EmailLog
        from app.core.db_retry import retry_on_locked

        async def _persist() -> None:
            async with get_session() as session:
                log = EmailLog(
                    automation_id=automation_id,
                    execution_id=execution_id,
                    recipients=_json.dumps(to_list, ensure_ascii=False),
                    cc_recipients=(_json.dumps(cc_list, ensure_ascii=False) if cc_list else None),
                    bcc_recipients=(
                        _json.dumps(bcc_list, ensure_ascii=False) if bcc_list else None
                    ),
                    subject=(subject or "")[:500],
                    template_name=(template_name or None),
                    success=bool(success),
                    message_id=((message_id or "")[:200] or None),
                    # Cap centralisé (cf. _AUDIT_ERROR_MESSAGE_MAX). Le caller
                    # peut avoir déjà appliqué le scrub PII via
                    # ``_scrub_audit_error_message``, on tronque ici par sécurité.
                    error_message=(
                        ((error_message or "")[:_AUDIT_ERROR_MESSAGE_MAX] or None)
                        if error_message
                        else None
                    ),
                    attachment_count=len(attachment_names),
                    attachment_names=(
                        _json.dumps(attachment_names, ensure_ascii=False)
                        if attachment_names
                        else None
                    ),
                    sent_by_user_id=sent_by_user_id,
                )
                session.add(log)
                await session.commit()

        await retry_on_locked(_persist, operation_name="email_log_audit")
    except Exception as exc:  # noqa: BLE001 — best-effort, ne propage pas
        logger.warning("EmailLog audit failed (envoi non bloqué): %s", exc)


_EMAIL_LOG_TASKS: "set[asyncio.Task[None]]" = set()
#: Tours max de drain (cf. drain_email_log_tasks) — borne anti boucle infinie.
_DRAIN_MAX_ROUNDS: Final[int] = 5


def _schedule_email_log_write(payload: Dict[str, Any]) -> None:
    """Planifie l'audit EmailLog SANS bloquer le retour de send_email (#48).
    Fallback sans event-loop (contexte sync rare) : log + skip (best-effort)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.warning("EmailLog audit ignoré : aucun event-loop courant")
        return
    task = loop.create_task(_write_email_log_async(**payload))
    _EMAIL_LOG_TASKS.add(task)
    task.add_done_callback(_EMAIL_LOG_TASKS.discard)


async def drain_email_log_tasks() -> None:
    """Attend les écritures EmailLog en vol SUR LA BOUCLE COURANTE uniquement.
    Loop-scoped : le set est partagé entre les threads asyncio.run des
    automatisations ; gather de tâches cross-loop lèverait une erreur.

    Drain jusqu'à stabilité : une tâche planifiée APRÈS le 1er snapshot (step
    tardif / tâche de fond qui envoie un mail) serait sinon jamais attendue →
    annulée au teardown de la boucle. Borné par ``_DRAIN_MAX_ROUNDS`` : les
    audits n'en planifient pas d'autres → converge en 1-2 tours ; la borne
    évite une boucle infinie pathologique."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    for _ in range(_DRAIN_MAX_ROUNDS):
        mine = [t for t in list(_EMAIL_LOG_TASKS) if t.get_loop() is loop and not t.done()]
        if not mine:
            return
        await asyncio.gather(*mine, return_exceptions=True)


async def run_then_drain_email_log(coro):
    """Wrapper pour les coroutines passées à asyncio.run() dans les threads
    worker : exécute coro puis draine les audits EmailLog AVANT que la boucle
    jetable ne soit détruite (sinon les tâches fire-and-forget sont annulées)."""
    try:
        return await coro
    finally:
        await drain_email_log_tasks()


def _filter_valid_emails(values: List[object], field_name: str) -> List[str]:
    """Filtre une liste de destinataires : strip, NBSP, ne garde que les emails valides.

    Defense-in-depth côté client SMTP : sans ce filtre, ``to_emails=['']`` ou
    ``['not-an-email']`` partaient au serveur, qui soit silencieusement
    n'envoyait rien (smtplib accepte ``to_addrs=[]``), soit retournait un 501
    obscur après 3×5 s de retry.

    Anti-PII : on logge **uniquement le compte** des rejets et le **type** des
    entrées non-string (jamais la valeur en clair). Un email rejeté reste une
    donnée personnelle ; pas question de la persister dans les logs serveur
    (RGPD + politique Komptia logs sans PII non-anonymisée).

    Anti-log-bombing : si une requête contient ``["bad"]*10_000``, on émet
    UN warning agrégé, pas 10 000.
    """
    cleaned: List[str] = []
    rejected_count = 0
    rejected_non_string_types: List[str] = []
    for raw in values:
        if not isinstance(raw, str):
            rejected_count += 1
            type_name = type(raw).__name__
            if type_name not in rejected_non_string_types:
                rejected_non_string_types.append(type_name)
            continue
        candidate = raw.replace("\xa0", " ").strip()
        if is_valid_email(candidate):
            cleaned.append(candidate)
        else:
            rejected_count += 1
    if rejected_count:
        if rejected_non_string_types:
            logger.warning(
                "SMTP : %d destinataire(s) rejeté(s) dans le champ '%s' "
                "(types non-string observés : %s)",
                rejected_count,
                field_name,
                ", ".join(rejected_non_string_types),
            )
        else:
            logger.warning(
                "SMTP : %d destinataire(s) rejeté(s) dans le champ '%s' "
                "(format email invalide — valeurs non loggées : PII)",
                rejected_count,
                field_name,
            )
    return cleaned


class SMTPClient:
    """
    Client SMTP robuste avec retry, logging et support pièces jointes.

    Attributs:
        host: Serveur SMTP
        port: Port SMTP (587 pour TLS, 465 pour SSL)
        username: Identifiant SMTP
        password: Mot de passe SMTP
        use_tls: Utiliser STARTTLS
        use_ssl: Utiliser SSL/TLS direct
        from_email: Email expéditeur par défaut
        from_name: Nom expéditeur par défaut
        max_retries: Nombre de tentatives en cas d'erreur
        retry_delay: Délai entre tentatives (secondes)
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        use_tls: bool = True,
        use_ssl: bool = False,
        from_email: Optional[str] = None,
        from_name: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: int = 5,
    ):
        """
        Initialise le client SMTP.

        Args:
            host: Serveur SMTP (ex: smtp.gmail.com)
            port: Port SMTP (587 pour TLS, 465 pour SSL, 25 non sécurisé)
            username: Identifiant SMTP
            password: Mot de passe ou token SMTP
            use_tls: True pour STARTTLS (défaut), False sinon
            use_ssl: True pour SSL/TLS direct, False sinon
            from_email: Email expéditeur (par défaut = username)
            from_name: Nom affiché expéditeur (ex: nom du cabinet/entreprise)
            max_retries: Nombre max de tentatives (défaut 3)
            retry_delay: Délai entre tentatives en secondes (défaut 5)
        """
        self.host = host.strip().replace("\xa0", " ").replace(" ", "")
        self.port = port
        self.username = username.strip().replace("\xa0", "")
        self.password = password.replace("\xa0", " ")
        self.use_tls = use_tls
        self.use_ssl = use_ssl
        self.from_email = (from_email or username).strip().replace("\xa0", "")
        self.from_name = from_name.replace("\xa0", " ") if from_name else from_name
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        logger.info(
            f"SMTPClient initialisé: {self.host}:{self.port} (TLS={use_tls}, SSL={use_ssl})"
        )

    async def send_email(
        self,
        to_emails: Union[str, List[str]],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        cc_emails: Optional[Union[str, List[str]]] = None,
        bcc_emails: Optional[Union[str, List[str]]] = None,
        attachments: Optional[List[Union[str, Path, Dict]]] = None,
        reply_to: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        *,
        audit_log: bool = True,
        automation_id: Optional[int] = None,
        execution_id: Optional[int] = None,
        sent_by_user_id: Optional[int] = None,
        template_name: Optional[str] = None,
        audit_attachment_names: Optional[Sequence[str]] = None,
    ) -> Dict[str, any]:
        """Envoie un email de manière async + audit ``EmailLog`` (centralisé).

        L'audit est activé par défaut (fail-closed : si un dev oublie de
        spécifier ``audit_log``, l'envoi est tracé). Seul cas légitime
        d'opt-out : test SMTP admin (``/admin/smtp`` "Tester la connexion").
        On utilise une comparaison ``is not False`` plutôt que truthy :
        ``audit_log=None`` ou ``audit_log=0`` (caller buggué) ne désactivera
        PAS l'audit — fail-closed.

        Toute la pipeline email Komptia (contacts, reports, automations
        DAG, legacy pipeline, notifications exécution, wait_resume,
        outil Iris) passe par cette méthode — c'est ici la **single
        source of truth** de l'audit ``/email-history``.

        Args (en plus des args SMTP existants) :
            audit_log: ``False`` (strictement) pour skipper l'audit.
                Tout autre valeur = audit activé. Défaut ``True``.
            automation_id, execution_id, sent_by_user_id, template_name:
                Métadonnées d'audit. Le SMTPClient ne connaît pas ces
                concepts métier ; les call-sites les fournissent.
            audit_attachment_names: Noms à logger en audit si différent
                des fichiers attachés (cas rare — usage : rapport généré
                dynamiquement avec un autre libellé d'affichage). Défaut
                = extraction depuis ``attachments``.
        """
        send_result: Optional[Dict[str, Any]] = None
        send_exception: Optional[BaseException] = None
        try:
            send_result = await asyncio.to_thread(
                self._send_email_sync,
                to_emails=to_emails,
                subject=subject,
                body_html=body_html,
                body_text=body_text,
                cc_emails=cc_emails,
                bcc_emails=bcc_emails,
                attachments=attachments,
                reply_to=reply_to,
                custom_headers=custom_headers,
            )
        except Exception as exc:
            # ``_send_email_sync`` catche déjà ``SMTPException``/``OSError``
            # en interne (cf. retry-loop) et retourne ``success=False``.
            # Mais un mock test ou une sous-classe peut propager → on garde
            # quand même la trace d'audit avant de re-raise.
            send_exception = exc

        # Fail-closed sur le flag : seul ``audit_log is False`` désactive.
        if audit_log is not False:
            try:
                payload = _build_audit_payload(
                    send_result=send_result,
                    send_exception=send_exception,
                    to_emails=to_emails,
                    cc_emails=cc_emails,
                    bcc_emails=bcc_emails,
                    subject=subject,
                    attachments=attachments,
                    audit_attachment_names=audit_attachment_names,
                    automation_id=automation_id,
                    execution_id=execution_id,
                    sent_by_user_id=sent_by_user_id,
                    template_name=template_name,
                )
                _schedule_email_log_write(payload)
            except Exception as audit_exc:  # noqa: BLE001 — best-effort
                logger.warning(
                    "EmailLog audit prep failed (envoi non bloqué): %s",
                    audit_exc,
                )

        if send_exception is not None:
            raise send_exception
        assert send_result is not None  # mypy/pylance: garantit par try/except
        return send_result

    def _send_email_sync(
        self,
        to_emails: Union[str, List[str]],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        cc_emails: Optional[Union[str, List[str]]] = None,
        bcc_emails: Optional[Union[str, List[str]]] = None,
        attachments: Optional[List[Union[str, Path, Dict]]] = None,
        reply_to: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, any]:
        """
        Envoie un email avec support HTML, texte alternatif et pièces jointes.

        Args:
            to_emails: Email(s) destinataire(s) (str ou liste)
            subject: Sujet de l'email
            body_html: Corps de l'email en HTML
            body_text: Corps alternatif en texte brut (optionnel)
            cc_emails: Email(s) en copie (optionnel)
            bcc_emails: Email(s) en copie cachée (optionnel)
            attachments: Liste de pièces jointes. Chaque élément peut être:
                - str/Path: Chemin vers fichier
                - dict: {"path": str, "filename": str, "content_type": str}
            reply_to: Email de réponse (optionnel)
            custom_headers: En-têtes personnalisés (optionnel)

        Returns:
            Dict avec statut:
            {
                "success": bool,
                "message": str,
                "recipients": list,
                "message_id": str (si succès),
                "error": str (si échec)
            }
        """
        # Normaliser les destinataires : str → [str], iterable (list/tuple/set) → list,
        # autres types → None pour déclencher la garde fail-closed ci-dessous.
        to_list = _normalize_recipient_arg(to_emails)
        cc_list = _normalize_recipient_arg(cc_emails) if cc_emails else []
        bcc_list = _normalize_recipient_arg(bcc_emails) if bcc_emails else []

        # Refus immédiat sur ``to`` mal typé (None, int, dict, ...). Sans cette
        # garde, ``to_list + cc_list + bcc_list`` provoquait un ``TypeError``
        # non-géré qui remontait en 500 cryptique au caller.
        if to_list is None:
            logger.warning(
                "SMTP : 'to_emails' invalide (type %s) — envoi refusé",
                type(to_emails).__name__,
            )
            return {
                "success": False,
                "message": "Aucun destinataire valide",
                "recipients": [],
                "refused_recipients": [],
                "error": "Aucun destinataire fourni (to_emails None ou type invalide).",
            }
        # Symétrie cc/bcc : un mauvais type ne doit jamais crasher l'envoi,
        # mais on logue + on traite comme « pas de cc/bcc » plutôt que de
        # laisser passer (defense-in-depth, axe Komptia 5b).
        if cc_list is None:
            logger.warning(
                "SMTP : 'cc_emails' invalide (type %s) — ignoré",
                type(cc_emails).__name__,
            )
            cc_list = []
        if bcc_list is None:
            logger.warning(
                "SMTP : 'bcc_emails' invalide (type %s) — ignoré",
                type(bcc_emails).__name__,
            )
            bcc_list = []

        # Filtrage anti-silent-loss : avant le fix, ``to_emails=[]`` ou
        # ``['']`` donnait ``success=True, recipients=[]`` côté EmailLog alors
        # qu'aucun mail ne quittait la machine.
        to_list = _filter_valid_emails(to_list, "to")
        cc_list = _filter_valid_emails(cc_list, "cc") if cc_list else []
        bcc_list = _filter_valid_emails(bcc_list, "bcc") if bcc_list else []

        if not to_list:
            logger.warning("SMTP : aucun destinataire 'to' valide après filtrage — envoi refusé")
            return {
                "success": False,
                "message": "Aucun destinataire valide après filtrage",
                "recipients": [],
                "refused_recipients": [],
                "error": "Tous les destinataires fournis sont invalides ou vides.",
            }

        all_recipients = to_list + cc_list + bcc_list

        # Garde fail-closed : pas de destinataire = pas d'envoi (sinon SMTP
        # lèverait, mais on ne veut surtout pas un mock qui retourne {} faire
        # croire à un succès silencieux côté audit).
        if not all_recipients:
            logger.error("Aucun destinataire fourni — envoi refusé")
            return {
                "success": False,
                "message": "Aucun destinataire fourni",
                "recipients": [],
                "refused_recipients": [],
                "error": "Aucun destinataire fourni",
            }

        logger.info("Préparation email: '%s' → %s destinataire(s)", subject, len(all_recipients))

        # Message créé UNE seule fois, HORS de la boucle retry : le
        # ``Message-ID`` reste donc STABLE entre les tentatives. Si un retry
        # re-livre un message déjà accepté par le serveur (échec post-DATA,
        # ex. connexion coupée pendant le QUIT), un MTA conforme dédoublonne
        # sur ce ``Message-ID`` identique. Contrat assumé : envoi
        # *at-least-once*. Bonus : les pièces jointes ne sont plus relues du
        # disque à chaque tentative.
        msg = self._create_message(
            to_list=to_list,
            cc_list=cc_list,
            subject=subject,
            body_html=body_html,
            body_text=body_text,
            reply_to=reply_to,
            custom_headers=custom_headers,
        )
        if attachments:
            self._add_attachments(msg, attachments)

        # Tenter l'envoi avec retry
        for attempt in range(1, self.max_retries + 1):
            try:
                # Envoyer via SMTP — récupère aussi le dict des destinataires refusés
                # par le serveur (RCPT refused). Voir smtplib.SMTP.send_message().
                message_id, refused = self._send_via_smtp(msg, all_recipients)

                # Cas 1 : tous OK — aucun refus
                if not refused:
                    logger.info(
                        "✅ Email envoyé avec succès (tentative %s/%s)",
                        attempt,
                        self.max_retries,
                    )
                    logger.info("   Message-ID: %s", message_id)
                    logger.info("   Destinataires: %s", ", ".join(to_list))

                    return {
                        "success": True,
                        "message": "Email envoyé avec succès",
                        "recipients": to_list,
                        "message_id": message_id,
                        "refused_recipients": [],
                    }

                # Cas 2 et 3 : refus partiel ou total. RCPT refused n'est pas un transient
                # error → on ne retry pas (sinon les destinataires OK reçoivent N fois).
                refused_list = list(refused.keys())

                if len(refused) >= len(all_recipients):
                    # Cas 3 : tous refusés
                    logger.error(
                        "Tous les destinataires ont été refusés par le serveur SMTP : %s",
                        ", ".join(refused_list),
                    )
                    return {
                        "success": False,
                        "message": "Tous les destinataires ont été refusés par le serveur SMTP",
                        "recipients": to_list,
                        "refused_recipients": refused_list,
                    }

                # Cas 2 : refus partiel — message_id existe (au moins 1 destinataire OK)
                logger.warning(
                    "Envoi SMTP partiel : %s destinataire(s) refusé(s) sur %s : %s",
                    len(refused),
                    len(all_recipients),
                    ", ".join(refused_list),
                )
                return {
                    "success": False,
                    "partial_success": True,
                    "message": (
                        f"Envoi partiel : {len(refused)} destinataire(s) refusé(s) "
                        f"par le serveur SMTP"
                    ),
                    "recipients": to_list,
                    "message_id": message_id,
                    "refused_recipients": refused_list,
                }

            except (smtplib.SMTPException, OSError):
                # Log full details server-side, never expose str(e) to user
                logger.warning("Échec tentative %d/%d", attempt, self.max_retries, exc_info=True)

                if attempt < self.max_retries:
                    logger.info("Nouvelle tentative dans %ss...", self.retry_delay)
                    import time

                    time.sleep(self.retry_delay)

        # Toutes les tentatives ont échoué — generic message for user
        logger.error("Échec définitif après %d tentatives", self.max_retries)
        return {
            "success": False,
            "message": f"Échec après {self.max_retries} tentatives",
            "recipients": to_list,
            "refused_recipients": [],
            "error": "L'envoi a échoué après plusieurs tentatives. Vérifiez la configuration SMTP.",
        }

    def _create_message(
        self,
        to_list: List[str],
        cc_list: List[str],
        subject: str,
        body_html: str,
        body_text: Optional[str],
        reply_to: Optional[str],
        custom_headers: Optional[Dict[str, str]],
    ) -> MIMEMultipart:
        """Crée le message MIME avec encodage UTF-8."""
        # Utiliser la politique SMTP pour un encodage UTF-8 correct
        msg = MIMEMultipart("alternative", policy=policy.SMTP)

        # Sanitiser tous les en-têtes contre l'injection CRLF
        from_header = f"{self.from_name} <{self.from_email}>" if self.from_name else self.from_email
        msg["From"] = _sanitize_header(from_header)
        # ``Message-ID`` stable : ``smtplib.send_message`` n'en génère pas, donc
        # sans ça l'audit ``EmailLog.message_id`` reste "unknown" et le
        # dédoublonnage MTA sur retry est impossible. Domaine dérivé
        # dynamiquement de l'adresse d'envoi (aucun hardcode).
        msg_domain = (
            self.from_email.rsplit("@", 1)[-1]
            if self.from_email and "@" in self.from_email
            else None
        )
        msg["Message-ID"] = make_msgid(domain=msg_domain)
        # ``Date`` explicite via la source unique du temps : ``clock.now_local()``
        # = heure de la machine hôte (avec offset). Sans ce header, ``smtplib.
        # send_message`` le génère implicitement via ``email.utils.localtime()``
        # (même horloge machine, mais hors SSOT et non testable). RFC 5322
        # §3.6.1 rend ``Date`` obligatoire — on le pose donc explicitement.
        msg["Date"] = format_datetime(clock.now_local())
        msg["To"] = _sanitize_header(", ".join(to_list))
        if cc_list:
            msg["Cc"] = _sanitize_header(", ".join(cc_list))
        msg["Subject"] = _sanitize_header(subject)

        if reply_to:
            msg["Reply-To"] = _sanitize_header(reply_to)

        # En-têtes personnalisés — sanitiser clé ET valeur
        if custom_headers:
            for key, value in custom_headers.items():
                msg[_sanitize_header(key)] = _sanitize_header(value)

        # Corps du message (texte puis HTML)
        if body_text:
            msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        return msg

    def _add_attachments(self, msg: MIMEMultipart, attachments: List[Union[str, Path, Dict]]):
        """Ajoute les pièces jointes au message."""
        # Garde agrégat anti-OOM : on borne le TOTAL des pièces AVANT d'en lire
        # une seule en mémoire. ``stat().st_size`` uniquement (zéro lecture de
        # contenu). On échoue tout le build si la somme dépasse le cap — un
        # ``raise`` ici (hors du ``try`` par-pièce ci-dessous) remonte à
        # ``send_email`` qui audite ``success=False`` puis propage au caller
        # (contacts/rapports/automations gèrent l'échec) → pas d'OOM.
        # On ne compte QUE les pièces réellement incluses dans le MIME : le
        # prédicat ``_attachment_skip_reason`` (source unique, partagé avec la
        # passe principale) écarte symlink / '..' / hors-sandbox / inexistant /
        # > cap par-pièce. Une pièce skippée ne contribue pas à l'OOM du build,
        # donc ne doit pas faire échouer l'envoi via le cap TOTAL.
        _total_attachment_bytes = 0
        for _att in attachments:
            try:
                _att_path = Path(_att["path"]) if isinstance(_att, dict) else Path(_att)
            except (KeyError, TypeError):
                # Entrée malformée (dict sans "path", type inattendu) : ignorée
                # ici — la passe principale gère/skip de la même façon.
                continue
            _skip, _size = _attachment_skip_reason(_att_path)
            if _skip is None:
                _total_attachment_bytes += _size
        if _total_attachment_bytes > _MAX_TOTAL_ATTACHMENT_SIZE:
            raise ValueError(
                f"Total des pièces jointes ({_total_attachment_bytes} octets) dépasse la "
                f"limite anti-OOM de {_MAX_TOTAL_ATTACHMENT_SIZE} octets — envoi refusé"
            )

        for attachment in attachments:
            try:
                # Extraire infos du fichier
                if isinstance(attachment, dict):
                    filepath = Path(attachment["path"])
                    filename = attachment.get("filename", filepath.name)
                    content_type = attachment.get("content_type")
                else:
                    filepath = Path(attachment)
                    filename = filepath.name
                    content_type = None

                # Prédicat de skip UNIQUE (cf. _attachment_skip_reason) :
                # symlink / '..' / hors-sandbox (defense-in-depth axe 8 :
                # empêche l'exfiltration de /etc/passwd, clés SSH…) / inexistant
                # / > cap par-pièce. MÊME logique que la pré-passe anti-OOM →
                # single source of truth, les deux passes ne divergent jamais.
                _skip_reason, _ = _attachment_skip_reason(filepath)
                if _skip_reason is not None:
                    logger.warning("Pièce jointe ignorée (%s): %s", _skip_reason, filepath)
                    continue

                with open(filepath, "rb") as f:
                    file_data = f.read()

                # Déterminer le type MIME
                if content_type:
                    maintype, subtype = content_type.split("/", 1)
                    if maintype == "image":
                        part = MIMEImage(file_data, _subtype=subtype)
                    else:
                        part = MIMEApplication(file_data, _subtype=subtype)
                else:
                    # Par défaut: application/octet-stream
                    part = MIMEApplication(file_data)

                # Sanitize filename to prevent header injection
                safe_filename = filename.replace('"', "").replace("\\", "")
                part.add_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
                msg.attach(part)

                logger.debug("Pièce jointe ajoutée: %s (%s octets)", filename, len(file_data))

            except (OSError, ValueError) as e:
                logger.error("Erreur ajout pièce jointe %s: %s", attachment, e)

    def _send_via_smtp(
        self, msg: MIMEMultipart, recipients: List[str]
    ) -> Tuple[str, Dict[str, Tuple[int, bytes]]]:
        """Envoie le message via SMTP. Retourne (Message-ID, refused_dict).

        `refused_dict` est le dict retourné par `smtplib.SMTP.send_message` :
        clé = email refusé au niveau RCPT, valeur = (code SMTP, raison bytes).
        Vide si tous les destinataires ont été acceptés. Garanti non-None.
        """
        smtp = None
        try:
            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=SMTP_TIMEOUT_SECONDS)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=SMTP_TIMEOUT_SECONDS)
                smtp.ehlo()

                if self.use_tls:
                    smtp.starttls()
                    smtp.ehlo()

            smtp.login(self.username, self.password)

            # send_message retourne un dict des destinataires refusés au RCPT.
            # `or {}` protège contre l'éventuel None d'un client custom non-conforme.
            refused = smtp.send_message(msg, to_addrs=recipients) or {}

            message_id = msg.get("Message-ID", "unknown")

            return message_id, refused
        finally:
            if smtp:
                try:
                    smtp.quit()
                except Exception:
                    pass

    async def test_connection(self) -> Dict[str, any]:
        """
        Teste la connexion SMTP sans envoyer d'email (async, non-bloquant).

        Returns:
            Dict avec statut: {"success": bool, "message": str}
        """
        return await asyncio.to_thread(self._test_connection_sync)

    def _test_connection_sync(self) -> Dict[str, any]:
        """Teste la connexion SMTP (synchrone, exécuté dans un thread)."""
        smtp = None
        try:
            logger.info("Test connexion SMTP: %s:%s...", self.host, self.port)

            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=SMTP_TEST_TIMEOUT_SECONDS)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=SMTP_TEST_TIMEOUT_SECONDS)
                smtp.ehlo()
                if self.use_tls:
                    smtp.starttls()
                    smtp.ehlo()

            smtp.login(self.username, self.password)

            logger.info("✅ Connexion SMTP réussie")
            return {"success": True, "message": "Connexion SMTP réussie"}

        except smtplib.SMTPAuthenticationError:
            logger.error("Échec authentification SMTP", exc_info=True)
            return {
                "success": False,
                "message": "Échec d'authentification SMTP (vérifiez identifiants)",
            }
        except (smtplib.SMTPException, OSError) as e:
            logger.error("Échec connexion SMTP", exc_info=True)
            # Message générique — ne pas exposer les détails réseau/serveur
            return {"success": False, "message": f"Échec connexion SMTP ({type(e).__name__})"}
        finally:
            if smtp:
                try:
                    smtp.quit()
                except Exception:
                    pass
