"""**Phase α.8 (#74) — Notification email à l'utilisateur quand ses règles
d'accès changent.**

Surface : ``app.services.data_access.notifier.notify_user_rules_changed``.

Appelé en **fire-and-forget** depuis les handlers admin
(``DataAccessRuleAPIHandler.post/put/delete``, ``DataAccessRulesAPIHandler.put``,
``DataAccessCopyRulesAPIHandler.post``) après une modification réussie de
règles, pour prévenir l'utilisateur concerné par email.

## Contraintes architecturales

1. **Mode invisible préservé** : le mail NE mentionne JAMAIS le nom des
   tables/colonnes/valeurs touchées. Il dit juste « vos accès ont été
   modifiés par votre administrateur ». L'utilisateur peut demander des
   détails à son admin (qui, lui, sait).

2. **Fail-safe** : si SMTP n'est pas configuré, indisponible, ou si
   l'utilisateur n'a pas d'email, la fonction retourne ``False`` sans
   lever d'exception. Le handler caller continue normalement (la
   modification de règle est déjà persistée).

3. **Throttle** : pour éviter le spam quand un admin enchaîne 10
   modifications rapides (cas typique : bulk-delete, copy-rules), on
   limite à **1 mail par user toutes les ``THROTTLE_SECONDS`` secondes**.
   Les modifications dans la fenêtre sont silencieusement ignorées (mais
   l'user verra l'état final via son prochain login Komptia).

4. **Non-bloquant** : le caller doit utiliser ``asyncio.create_task`` pour
   ne pas bloquer la réponse HTTP. Cette fonction prend ~50–200 ms en
   prod (résolution SMTP + send) — multiplié par bulk-delete de 100 →
   inacceptable en sync.

## Pourquoi pas de notif à l'admin ?

L'admin vient de poser la règle. Lui notifier serait redondant. Si plus
tard un usage justifie une notif admin (audit, secondary admin), créer
une fonction séparée ``notify_admins_rule_changed``.
"""

from __future__ import annotations

import asyncio
import html
import re
import time
from typing import Any, Optional

from app.utils.logger import get_logger

logger = get_logger(__name__)


# Strong reference set pour les tasks fire-and-forget créées par
# ``schedule_notification``. Bug 2026-05-26 (Agent 4 DA-M10) + mémoire
# ``feedback_asyncio_create_task_strong_ref.md`` : Python 3.12+ peut GC
# une task créée via ``loop.create_task(...)`` SANS référence forte
# AVANT que la coroutine n'ait pu s'exécuter — la notification est
# perdue silencieusement. Pattern correct : stocker dans un set
# module-level + ``done_callback(set.discard)`` pour libérer à la fin.
_PENDING_NOTIFICATION_TASKS: set["asyncio.Task[Any]"] = set()


#: Délai minimum (secondes) entre 2 mails envoyés au MÊME user. Limite le
#: spam en cas de modifications rapides successives (bulk-delete, copy).
THROTTLE_SECONDS: int = 60

#: Dict en mémoire ``{user_id: timestamp_dernier_envoi}``. Single-process
#: only (cf. #37 multi-process safe, non implémenté V1). En multi-worker,
#: chaque worker a son propre dict → l'user peut recevoir N mails en
#: parallèle. Acceptable V1 (N typiquement = 1-2 workers).
#:
#: **Purge auto** : à chaque ``_check_throttle``, on supprime les entries
#: plus anciennes que ``THROTTLE_SECONDS * 2``. Évite la croissance non
#: bornée (cf. adversarial review #74 MEDIUM #3 + axe 21 du contrat).
_last_sent_at: dict = {}

#: Fenêtre au-delà de laquelle une entry est considérée comme expirée et
#: peut être purgée du dict (anti croissance non bornée).
_PURGE_AGE_SECONDS: int = THROTTLE_SECONDS * 2

#: Whitelist de caractères autorisés dans ``admin_username`` injecté dans
#: le mail. Tout caractère hors whitelist déclenche fallback vers le
#: label générique "votre administrateur". Anti HTML/XSS injection +
#: anti leak de nom denied via le username (un admin qui aurait pour
#: nom d'utilisateur un nom de table interdite).
_SAFE_LABEL_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_\-.@ ]{1,40}$")


def _purge_expired_throttle_entries() -> None:
    """Supprime les entries du dict throttle plus anciennes que
    ``_PURGE_AGE_SECONDS``. Appelé à chaque ``_check_throttle``.

    Borné en O(N) où N = nb d'entries. Pour Komptia (≤100 users) c'est
    négligeable. Si l'app évolue vers du SaaS multi-organisation 10k+ users,
    remplacer par ``cachetools.TTLCache``.
    """
    cutoff = time.time() - _PURGE_AGE_SECONDS
    expired = [uid for uid, ts in _last_sent_at.items() if ts < cutoff]
    for uid in expired:
        _last_sent_at.pop(uid, None)


def _check_throttle(user_id: int) -> bool:
    """Retourne True si on peut envoyer. False si on est encore dans la
    fenêtre de throttle.

    **Note importante** : NE marque PAS le timestamp ici. Le caller doit
    appeler ``_mark_throttle_sent(user_id)`` UNIQUEMENT après succès SMTP.
    Si on marquait avant l'envoi et que le SMTP fail, l'user serait
    throttlé 60s sans avoir reçu le mail (cf. adversarial #74 MEDIUM #2).
    """
    _purge_expired_throttle_entries()
    now = time.time()
    last = _last_sent_at.get(user_id, 0.0)
    return (now - last) >= THROTTLE_SECONDS


def _mark_throttle_sent(user_id: int) -> None:
    """Marque qu'un mail a été effectivement envoyé. Appeler APRÈS succès
    SMTP uniquement."""
    _last_sent_at[user_id] = time.time()


def _sanitize_admin_label(raw: Optional[str]) -> Optional[str]:
    """Filtre l'``admin_username`` pour l'injection mail :

    - ``None`` → ``None`` (le helper utilisera le label générique).
    - Match whitelist ``_SAFE_LABEL_RE`` → autorisé.
    - Tout autre → ``None`` (fallback) + WARNING log.

    Couvre 2 risques :
    - **XSS HTML** dans body_html via un username contenant ``<script>``.
    - **Leak mode invisible** via un username qui serait un nom de table
      denied (admin créatif qui aurait pour username "F_SALAIRES" — rare
      mais le code applicatif ne doit JAMAIS faire confiance à un input
      arbitraire).
    """
    if raw is None:
        return None
    if not isinstance(raw, str):
        logger.warning(
            "notifier: admin_label type inattendu (%s) — fallback générique",
            type(raw).__name__,
        )
        return None
    if not _SAFE_LABEL_RE.match(raw):
        logger.warning(
            "notifier: admin_label rejeté par whitelist (len=%d, "
            "premier_char=%r) — fallback générique",
            len(raw),
            raw[:1] if raw else "",
        )
        return None
    return raw


def _build_email_body(action: str, admin_label: Optional[str]) -> tuple[str, str, str]:
    """Construit (subject, body_text, body_html) **sans révéler le détail**.

    Le contenu est volontairement générique. Mode invisible préservé.

    ``admin_label`` est filtré par ``_sanitize_admin_label`` (whitelist
    stricte) ET HTML-escapé dans ``body_html`` pour défense-en-profondeur
    contre XSS via username inattendu.
    """
    safe_label = _sanitize_admin_label(admin_label)
    actor = safe_label or "votre administrateur"
    actor_html = html.escape(actor, quote=True)
    subject = "Komptia — vos accès aux données ont été modifiés"

    body_text = (
        f"Bonjour,\n\n"
        f"{actor} vient de modifier vos droits d'accès aux données dans Komptia. "
        f"Vous remarquerez peut-être des changements dans les requêtes Iris, "
        f"les dashboards, ou les automatisations que vous utilisez.\n\n"
        f"Si vous avez des questions ou si un accès dont vous avez besoin "
        f"a été retiré par erreur, contactez directement votre administrateur.\n\n"
        f"— L'équipe Komptia"
    )

    body_html = (
        '<div style="font-family: -apple-system, system-ui, Segoe UI, sans-serif; '
        "max-width: 560px; margin: 0 auto; padding: 16px; color: #1f2937; "
        'line-height: 1.5;">'
        "<p>Bonjour,</p>"
        f"<p><strong>{actor_html}</strong> vient de modifier vos droits d'accès aux "
        "données dans Komptia. Vous remarquerez peut-être des changements dans les "
        "requêtes Iris, les dashboards, ou les automatisations que vous utilisez.</p>"
        "<p>Si vous avez des questions ou si un accès dont vous avez besoin a été "
        "retiré par erreur, contactez directement votre administrateur.</p>"
        '<p style="color: #6b7280; font-size: 13px; margin-top: 24px;">'
        "— L'équipe Komptia"
        "</p>"
        "</div>"
    )

    return subject, body_text, body_html


async def notify_user_rules_changed(
    user_id: int,
    *,
    admin_username: Optional[str] = None,
    action: str = "modified",
) -> bool:
    """Envoie un mail à l'utilisateur ``user_id`` pour le prévenir.

    Args:
        user_id : ID de l'utilisateur dont les règles ont changé.
        admin_username : label affiché dans le mail (par exemple
            ``"@boss"``). Si ``None`` → mail générique « votre admin ».
        action : ``"added"``, ``"modified"``, ``"deleted"``, ``"replaced"``,
            ``"copied"``. Aujourd'hui le contenu du mail est le même pour
            tous (mode invisible). L'argument est gardé pour faciliter
            l'évolution future si on veut différencier (l'enum permettra
            de filtrer les opt-ins user-side par type).

    Returns:
        ``True`` si le mail a été envoyé (SMTP a accepté).
        ``False`` si :
        - throttle actif sur ce user,
        - SMTP non configuré ou désactivé,
        - utilisateur sans email,
        - utilisateur introuvable,
        - exception SMTP.

        Dans TOUS les cas ``False``, un ``logger.warning`` est posé.
        La fonction NE LÈVE JAMAIS — c'est un fire-and-forget côté
        caller.
    """
    if not _check_throttle(user_id):
        logger.info(
            "notify_user_rules_changed: throttle actif user=%s "
            "(< %ds depuis dernier mail) — skip",
            user_id,
            THROTTLE_SECONDS,
        )
        return False

    try:
        # Charge le destinataire (email)
        from app.core.database import get_session
        from app.models.user import User

        async with get_session() as session:
            user = await session.get(User, user_id)
            if user is None:
                logger.warning(
                    "notify_user_rules_changed: user_id=%s introuvable — skip",
                    user_id,
                )
                return False
            recipient_email = user.email

        if not recipient_email or "@" not in recipient_email:
            logger.warning(
                "notify_user_rules_changed: user_id=%s sans email valide — skip",
                user_id,
            )
            return False

        # Charge le client SMTP (None si SMTP désactivé / non configuré)
        from app.services.email.smtp_factory import build_smtp_client_from_db

        smtp = await build_smtp_client_from_db()
        if smtp is None:
            logger.info(
                "notify_user_rules_changed: SMTP non configuré — skip "
                "user=%s (modification de règle bien persistée par ailleurs)",
                user_id,
            )
            return False

        subject, body_text, body_html = _build_email_body(action, admin_username)

        from app.services.email.template_names import EmailTemplate

        # ``sent_by_user_id=None`` : c'est une notification SYSTÈME (un admin a
        # changé les règles de ``user_id``), PAS un email que ``user_id`` a
        # envoyé. L'attribuer à ``user_id`` la ferait apparaître dans SON
        # /email-history (scope non-admin = ``WHERE sent_by_user_id = viewer``)
        # comme un envoi qui n'est pas le sien → confusion d'ownership + fuite
        # de l'activité admin. À ``None``, elle n'est visible que des admins
        # (scope see-all). Le ``template_name`` identifie déjà la nature.
        result = await smtp.send_email(
            to_emails=recipient_email,
            subject=subject,
            body_html=body_html,
            body_text=body_text,
            sent_by_user_id=None,
            template_name=EmailTemplate.DATA_ACCESS_RULES_CHANGED.value,
        )

        # SMTPClient retourne un dict. On considère succès si pas d'erreur.
        if isinstance(result, dict) and result.get("success"):
            # **Adversarial #74 MEDIUM #2 fix** : marquer le throttle
            # APRÈS succès SMTP. Si on marquait avant, un SMTP qui fail
            # bloquerait l'user 60s sans qu'il reçoive le mail.
            _mark_throttle_sent(user_id)
            logger.info(
                "notify_user_rules_changed: mail envoyé user=%s action=%s",
                user_id,
                action,
            )
            return True
        else:
            logger.warning(
                "notify_user_rules_changed: SMTP a refusé l'envoi " "user=%s result=%s",
                user_id,
                result,
            )
            return False

    except Exception:  # noqa: BLE001 — fire-and-forget : on swallow
        logger.warning(
            "notify_user_rules_changed: exception inattendue user=%s — "
            "modification bien persistée, juste l'email a échoué",
            user_id,
            exc_info=True,
        )
        return False


def schedule_notification(
    user_id: int,
    *,
    admin_username: Optional[str] = None,
    action: str = "modified",
) -> None:
    """Helper fire-and-forget : crée une task asyncio pour notifier sans
    bloquer le caller.

    À utiliser dans les handlers admin **après** la confirmation que la
    modification de règle est bien persistée (et avant le ``write_json``
    du handler).

    No-op si aucune event loop active (par exemple appels depuis tests
    sync purs — la notif n'a aucun sens dans ces cas-là).
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        logger.debug(
            "schedule_notification: pas de loop active — skip user=%s",
            user_id,
        )
        return

    # Strong reference indispensable : sans ça, Python 3.12+ peut GC la
    # task AVANT que ``notify_user_rules_changed`` n'ait pu s'exécuter
    # (Bug 2026-05-26 DA-M10). Le ``done_callback`` libère l'entrée du
    # set à la fin pour ne pas accumuler les tasks complétées en mémoire.
    task = loop.create_task(
        notify_user_rules_changed(user_id, admin_username=admin_username, action=action)
    )
    _PENDING_NOTIFICATION_TASKS.add(task)
    task.add_done_callback(_PENDING_NOTIFICATION_TASKS.discard)
