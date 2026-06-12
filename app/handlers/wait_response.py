"""Endpoints publics (sans auth) pour la reponse aux steps ``email_wait_response``.

Architecture
------------

Les destinataires externes (typiquement des comptables clients qui ne sont
PAS users Komptia) recoivent un mail avec un lien :

    ``https://komptia.tld/automations/wait/{token}``

Ce module expose 2 endpoints publics :

- ``GET /automations/wait/{token}`` → page HTML simple (form de reponse)
- ``POST /automations/wait/{token}`` → submit + reprise de l'execution

Securite
--------

* **Pas d'auth user requise** : le destinataire externe n'a pas de compte.
  Le token HMAC dans l'URL fait foi.
* **CSRF naturellement immunise** : pas de cookie de session sur ces
  endpoints, le token n'est pas dans un cookie. Un site tiers ne peut
  pas forger une requete avec le bon token sans l'avoir capture
  (ex: depuis le mail de la victime).
* **XSRF Tornado desactive** sur ces 2 endpoints (sinon impossible
  d'utiliser sans cookie XSRF). L'auth-via-token-dans-URL remplace.
* **Rate limiting** par IP : 30 GET/min, 5 POST/min — eviter le scan
  + brute-force d'UUIDs (deja protege par HMAC mais defense en
  profondeur).
* **Upload** : taille max 50 Mo, MIME validation csv/xlsx, sanitization
  filename anti path-traversal, stockage isole par token_hash.
* **Idempotence** : une fois le WaitToken resolved, les submits
  ulterieurs renvoient une page "deja repondu" (pas d'ecrasement).

Suite (Phase 4)
---------------

Apres POST reussi, on declenche la reprise de l'execution via
``app.services.automation.executor.resume_automation`` (cf. Phase 4).
La reprise rehydrate le checkpoint et relance le DAG depuis le step
waiting (devenu success grace a la reponse stockee).
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.config import config
from app.core import clock
from app.core.database import get_session
from app.handlers.base import BaseHandler
from app.models.base import ensure_utc
from app.models.execution import Execution
from app.models.wait_token import WaitToken
from app.services.branding import get_company_name
from app.utils.client_ip import client_ip_for_rate_limit
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter
from app.utils.wait_token_codec import parse_and_verify

logger = get_logger(__name__)

# ── Constantes ──

#: Taille max de la reponse texte.
MAX_RESPONSE_TEXT_LEN: int = 50_000

#: Extensions acceptees selon file_format.
_ALLOWED_EXTENSIONS: Dict[str, set] = {
    "csv": {".csv"},
    "xlsx": {".xlsx"},
    "both": {".csv", ".xlsx"},
}

#: Caracteres safe pour filename (anti path-traversal + encodage URL).
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")

#: Rate-limiters par IP (defense en profondeur — le HMAC fait deja le gros).
_GET_RATE_LIMITER: RateLimiter = RateLimiter()
_GET_RATE_MAX: int = 30
_GET_RATE_WINDOW_S: int = 60

_POST_RATE_LIMITER: RateLimiter = RateLimiter()
_POST_RATE_MAX: int = 5
_POST_RATE_WINDOW_S: int = 60

# Cluster-31 2026-05-26 — Limiteur composite (ip, token_hash) + global
# per-token. Le limiter principal `_POST_RATE_LIMITER` ne tape que sur
# l'IP, ce qui permet :
#  - CGNAT / proxy partagé : 100 clients legit derrière une seule IP
#    bruteforce un token concurremment → l'IP est blacklist → DoS du
#    legit client.
#  - Attaquant via Tor / VPN rotatifs : chaque IP a un quota frais → il
#    peut bruteforcer N tokens en parallèle sans jamais hit le limiter.
#
# Solution : 2 limiters supplémentaires.
#  1. `(ip, token_hash)` — limite stricte un user+token spécifique.
#  2. `token_hash` global — cap absolu N POST/h par token quel que soit
#     l'IP source. Coupe les attaques distribuées sur un token donné.
_POST_RATE_LIMITER_IP_TOKEN: RateLimiter = RateLimiter()
_POST_RATE_IP_TOKEN_MAX: int = 5
_POST_RATE_IP_TOKEN_WINDOW_S: int = 60

_POST_RATE_LIMITER_TOKEN_GLOBAL: RateLimiter = RateLimiter()
_POST_RATE_TOKEN_GLOBAL_MAX: int = 20  # 20 POST/heure max par token
_POST_RATE_TOKEN_GLOBAL_WINDOW_S: int = 3600


def _wait_uploads_dir() -> Path:
    """Racine des uploads de reponse. Creee a la demande."""
    # AppConfig n'a pas d'attribut `.storage` → `getattr(config.storage, ...)`
    # évaluait `config.storage` EN PREMIER et levait AttributeError au runtime
    # (upload de réponse wait-token → 500, fichier jamais écrit). On lit
    # directement `config.data_dir` (= data/, sous le volume Docker).
    base = config.data_dir
    root = base / "wait_uploads"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _sanitize_filename(name: str, max_len: int = 100) -> str:
    """Filename safe pour le filesystem (anti path-traversal + special chars)."""
    if not name:
        return "upload"
    # Garde le basename uniquement (anti path-traversal Windows + Unix)
    name = os.path.basename(name).strip()
    if not name:
        return "upload"
    # Strip caracteres bizarres
    safe = _SAFE_FILENAME_RE.sub("_", name)
    # Plusieurs underscores → un seul
    safe = re.sub(r"_+", "_", safe).strip("._-")
    if not safe:
        return "upload"
    # Truncate en preservant l'extension
    if len(safe) > max_len:
        ext = ""
        if "." in safe:
            stem, ext = safe.rsplit(".", 1)
            ext = "." + ext[:10]  # cap extension
        else:
            stem = safe
        safe = stem[: max_len - len(ext)] + ext
    return safe


# SSoT IP rate-limit : cf. app/utils/client_ip.py.
_client_ip = client_ip_for_rate_limit


async def _load_token_row(token_hash: str) -> Optional[WaitToken]:
    """Lookup sur token_hash. Retourne None si introuvable."""
    async with get_session() as session:
        result = await session.execute(select(WaitToken).where(WaitToken.token_hash == token_hash))
        return result.scalars().first()


def _expires_local(wait_row: WaitToken) -> str:
    """Format human-readable de l'expiration (UTC pour cross-tz)."""
    if not wait_row.expires_at:
        return "—"
    dt = ensure_utc(wait_row.expires_at)
    return dt.strftime("%d/%m/%Y a %H:%M UTC")


# ──────────────────────────────────────────────────────────────────
# GET handler — affiche le form
# ──────────────────────────────────────────────────────────────────


class WaitResponseHandler(BaseHandler):
    """``GET/POST /automations/wait/{token}`` — page publique de reponse.

    Pas d'auth user. Validation token HMAC + lookup BDD + check status.
    Render le template ``wait_response.html`` avec un ``state`` qui
    indique au template quoi afficher (form / expired / cancelled / etc.).

    GET = render le form. POST = submit la reponse + declenche la reprise
    de l'execution (Phase 4 : ``resume_automation_job``).
    """

    # XSRF desactive : pas de cookie de session, pas applicable ici.
    def check_xsrf_cookie(self) -> None:  # type: ignore[override]
        return None

    def get_current_user(self) -> None:  # type: ignore[override]
        # Endpoint public — aucun user attendu.
        return None

    async def get(self, token: str) -> None:
        # Rate-limit par IP
        ip = _client_ip(self)
        if not _GET_RATE_LIMITER.check(f"wait_get:{ip}", _GET_RATE_MAX, _GET_RATE_WINDOW_S):
            self.set_status(429)
            self.write("Trop de requetes, reessayez dans 1 minute.")
            return

        # Validation HMAC (rejette les tokens forges sans connaitre la cle)
        token_hash = parse_and_verify(token)
        if token_hash is None:
            await self._render_state("invalid")
            return

        wait_row = await _load_token_row(token_hash)
        if wait_row is None:
            await self._render_state("invalid")
            return

        # Verif statut
        if wait_row.status == "resolved":
            resolved_local = ""
            if wait_row.resolved_at:
                dt = ensure_utc(wait_row.resolved_at)
                resolved_local = dt.strftime("%d/%m/%Y a %H:%M UTC")
            await self._render_state(
                "resolved", wait_row=wait_row, resolved_at_local=resolved_local
            )
            return
        if wait_row.status == "cancelled":
            await self._render_state(
                "cancelled",
                wait_row=wait_row,
                cancellation_reason=wait_row.cancellation_reason or "",
            )
            return
        if wait_row.status == "expired" or wait_row.is_expired_now:
            await self._render_state("expired", wait_row=wait_row)
            return

        # Pending → afficher le form
        # Recuperer les metas de l'execution + step pour afficher le contexte
        async with get_session() as session:
            exec_row = await session.get(Execution, wait_row.execution_id)
            automation_name = ""
            if exec_row is not None:
                from app.models.automation import Automation as _Auto

                auto = await session.get(_Auto, exec_row.automation_id)
                if auto is not None:
                    automation_name = auto.name or ""

            from app.models.automation_step import AutomationStep as _Step

            step = await session.get(_Step, wait_row.step_id)
            step_cfg = (step.config if step else {}) or {}

        subject = step_cfg.get("subject") or "Reponse demandee"
        body = step_cfg.get("body") or ""
        await self._render_state(
            "pending",
            wait_row=wait_row,
            automation_name=automation_name,
            subject=subject,
            body=body,
        )

    async def _render_state(
        self,
        state: str,
        *,
        wait_row: Optional[WaitToken] = None,
        automation_name: str = "",
        subject: str = "",
        body: str = "",
        resolved_at_local: str = "",
        cancellation_reason: str = "",
    ) -> None:
        ctx: Dict[str, Any] = {
            "state": state,
            "page_title": "Repondre - Komptia",
            "company_name": get_company_name(),
            "automation_name": automation_name,
            "subject": subject,
            "body": body,
            "response_kind": (wait_row.response_kind if wait_row else "text"),
            "file_format": (wait_row.file_format if wait_row else "both"),
            "expires_local": _expires_local(wait_row) if wait_row else "—",
            "resolved_at_local": resolved_at_local,
            "cancellation_reason": cancellation_reason,
        }
        self.render("wait_response.html", **ctx)

    # ─── POST : submit reponse ───
    async def post(self, token: str) -> None:
        ip = _client_ip(self)
        # Couche 1 — Rate-limit par IP (déjà existant).
        if not _POST_RATE_LIMITER.check(f"wait_post:{ip}", _POST_RATE_MAX, _POST_RATE_WINDOW_S):
            self.set_status(429)
            self.write("Trop de soumissions, reessayez dans 1 minute.")
            return

        token_hash = parse_and_verify(token)
        if token_hash is None:
            self.set_status(400)
            self._render_simple("Lien invalide.", "invalid")
            return

        # Cluster-31 2026-05-26 — Couche 2 et 3 : rate-limits composites
        # par (IP, token) + global per token.
        #
        # Couche 2 : (ip, token_hash) — défense en profondeur. Si IP unique
        # tente N fois le même token, escalade plus rapide que le limiter IP
        # générique (qui permet 5 POST/min toutes routes confondues).
        # Couche 3 : token_hash global — coupe les attaques distribuées
        # (Tor / VPN rotatifs) sur un token donné. Quel que soit l'IP source,
        # un token ne peut pas recevoir plus de 20 POST/heure (≈ 1 toutes
        # les 3 min — largement au-dessus du legit + assez court pour
        # bruteforce inefficace).
        if not _POST_RATE_LIMITER_IP_TOKEN.check(
            f"wait_post_ip_tok:{ip}:{token_hash[:16]}",
            _POST_RATE_IP_TOKEN_MAX,
            _POST_RATE_IP_TOKEN_WINDOW_S,
        ):
            self.set_status(429)
            self.write("Trop de soumissions sur ce lien depuis votre adresse.")
            return
        if not _POST_RATE_LIMITER_TOKEN_GLOBAL.check(
            f"wait_post_tok:{token_hash[:16]}",
            _POST_RATE_TOKEN_GLOBAL_MAX,
            _POST_RATE_TOKEN_GLOBAL_WINDOW_S,
        ):
            self.set_status(429)
            self.write(
                "Trop de tentatives sur ce lien. "
                "Reessayez dans une heure ou contactez l'expediteur."
            )
            return

        wait_row = await _load_token_row(token_hash)
        if wait_row is None:
            self.set_status(400)
            self._render_simple("Lien invalide.", "invalid")
            return

        # Statut
        if wait_row.status == "resolved":
            self._render_simple("Reponse deja enregistree.", "resolved")
            return
        if wait_row.status == "cancelled":
            self._render_simple("Demande annulee.", "cancelled")
            return
        if wait_row.status == "expired" or wait_row.is_expired_now:
            self._render_simple("Lien expire.", "expired")
            return

        # Parse body
        response_text_raw = self.get_argument("response_text", default="")
        response_text = (response_text_raw or "").strip()
        if len(response_text) > MAX_RESPONSE_TEXT_LEN:
            self.set_status(413)
            self._render_simple(
                f"Reponse texte trop longue (max {MAX_RESPONSE_TEXT_LEN} caracteres).",
                "pending",
            )
            return

        # Fichier upload (optionnel selon response_kind)
        uploaded_file = self.request.files.get("response_file") or []
        upload_obj = uploaded_file[0] if uploaded_file else None

        # Validation selon response_kind
        kind = wait_row.response_kind
        if kind == "text" and not response_text:
            self.set_status(400)
            self._render_simple("Une reponse texte est requise.", "pending")
            return
        if kind == "file" and not upload_obj:
            self.set_status(400)
            self._render_simple("Un fichier est requis.", "pending")
            return
        if kind == "both" and not response_text and not upload_obj:
            self.set_status(400)
            self._render_simple(
                "Au moins une reponse texte OU un fichier est requis.",
                "pending",
            )
            return

        # Validation fichier si present
        saved_file_path: Optional[str] = None
        saved_file_name: Optional[str] = None
        saved_file_size: Optional[int] = None
        if upload_obj:
            file_body: bytes = upload_obj.get("body") or b""
            file_name_raw = upload_obj.get("filename") or "upload"
            # Taille max = SSoT admin (/admin/performance), identique à tous les
            # autres uploads utilisateur. Ici le collaborateur DÉPOSE un fichier
            # via le lien public d'une étape wait_response : c'est une RÉCEPTION
            # d'upload (pas un envoi SMTP). Avant : cap figé 50 Mo hors config.
            from app.services.ai.config_service import get_max_upload_size_bytes

            max_upload = await get_max_upload_size_bytes()
            if len(file_body) > max_upload:
                self.set_status(413)
                self._render_simple(
                    f"Fichier trop volumineux (max {max_upload // (1024 * 1024)} Mo).",
                    "pending",
                )
                return
            allowed_exts = _ALLOWED_EXTENSIONS.get(wait_row.file_format, {".csv", ".xlsx"})
            ext = os.path.splitext(file_name_raw)[1].lower()
            if ext not in allowed_exts:
                self.set_status(400)
                self._render_simple(
                    f"Extension non acceptee (attendu : {', '.join(sorted(allowed_exts))}).",
                    "pending",
                )
                return
            # Sanitize filename + stockage isole par token_hash
            safe_name = _sanitize_filename(file_name_raw)
            # Suffixe random pour eviter collision (cas tres rare)
            unique_prefix = secrets.token_hex(4)
            stored_name = f"{unique_prefix}_{safe_name}"
            target_dir = _wait_uploads_dir() / token_hash[:16]
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / stored_name
            # Defense en profondeur post-resolve
            try:
                if not target_path.resolve().is_relative_to(_wait_uploads_dir().resolve()):
                    raise ValueError("path traversal detecté")
            except (OSError, RuntimeError, ValueError):
                self.set_status(400)
                self._render_simple("Chemin de fichier invalide.", "pending")
                return
            try:
                target_path.write_bytes(file_body)
            except OSError:
                logger.exception("wait_submit: ecriture fichier echec")
                self.set_status(500)
                self._render_simple("Erreur d'enregistrement du fichier.", "pending")
                return
            saved_file_path = str(target_path)
            saved_file_name = file_name_raw[:200]
            saved_file_size = len(file_body)

        # Persistance : marque WaitToken resolved + StepExecution success
        # Cluster-V 2026-05-26 — Atomic CAS pour single-use replay protection.
        # Avant ce fix : 2 POSTs concurrents → 2 read pending → 2 mark_resolved
        # → double-resolution (le 2e écrase ou commit après le 1er). Maintenant
        # SQL UPDATE WHERE status='pending' AND expires_at > now → rowcount=1
        # ou 0. Si 0, le token est déjà résolu / expiré / annulé.
        try:
            async with get_session() as session:
                from sqlalchemy import update as _sa_update_v

                now_utc = clock.now()

                # Atomic CAS UPDATE — single round trip. Si rowcount=0, le
                # token n'est plus utilisable (resolved par autre POST,
                # expired entre check et write, cancelled par helper).
                update_stmt = (
                    _sa_update_v(WaitToken)
                    .where(
                        WaitToken.id == wait_row.id,
                        WaitToken.status == "pending",
                        WaitToken.expires_at > now_utc,
                    )
                    .values(
                        status="resolved",
                        response_text=response_text or None,
                        response_file_path=saved_file_path,
                        response_file_name=saved_file_name,
                        response_file_size=saved_file_size,
                        resolved_at=now_utc,
                        resolved_from_ip=ip,
                    )
                )
                update_result = await session.execute(update_stmt)
                if (update_result.rowcount or 0) != 1:
                    # CAS failed : 2e POST concurrent OU expiré entre temps
                    # OU annulé. Re-fetch pour message précis.
                    await session.rollback()
                    # #28 fix 2026-06-11 — le fichier réponse a été écrit sur
                    # disque AVANT le CAS (L433). Sur échec CAS (token déjà
                    # résolu/expiré/annulé par un POST concurrent), il n'est
                    # référencé par AUCUN token → ORPHELIN (fuite disque non
                    # bornée, non rattrapée par la rétention qui suit les
                    # références). Cleanup best-effort (ne bloque pas la réponse).
                    if saved_file_path:
                        try:
                            os.remove(saved_file_path)
                        except OSError:
                            logger.warning(
                                "wait_submit: cleanup fichier orphelin echoue (%s)",
                                saved_file_path,
                            )
                    refreshed = await _load_token_row(token_hash)
                    if refreshed and refreshed.status == "resolved":
                        self._render_simple(
                            "Reponse deja enregistree.",
                            "resolved",
                        )
                    elif refreshed and refreshed.status == "expired":
                        self._render_simple("Lien expire.", "expired")
                    elif refreshed and refreshed.status == "cancelled":
                        self._render_simple("Demande annulee.", "cancelled")
                    else:
                        self._render_simple(
                            "Statut a change pendant la soumission. Rechargez la page.",
                            "invalid",
                        )
                    return
                await session.commit()
                exec_id = wait_row.execution_id
                step_id = wait_row.step_id
                wait_token_id = wait_row.id
        except SQLAlchemyError:
            logger.exception("wait_submit: erreur BDD")
            self.set_status(500)
            self._render_simple("Erreur serveur lors de l'enregistrement.", "pending")
            return

        logger.info(
            "wait_submit: token #%d resolved (exec=%d, step=%d, ip=%s)",
            wait_token_id,
            exec_id,
            step_id,
            ip,
        )

        # Phase 4 — Declencher la reprise de l'execution.
        # On schedule un job APScheduler one-shot immediate. Si APScheduler
        # n'est pas dispo, on log un warning mais on retourne quand meme
        # success a l'user (sa reponse est sauvee, l'admin pourra trigger
        # le resume manuellement).
        try:
            from app.services.automation.scheduler import get_scheduler

            sched = get_scheduler()
            if sched is not None and sched.scheduler is not None:
                from app.services.automation.executor import resume_automation_job

                sched.scheduler.add_job(
                    resume_automation_job,
                    "date",
                    run_date=clock.now(),
                    args=[exec_id, step_id, wait_token_id],
                    id=f"resume_exec_{exec_id}",
                    replace_existing=True,
                    misfire_grace_time=300,
                )
                logger.info("wait_submit: resume_automation scheduled (exec=%d)", exec_id)
        except Exception:  # noqa: BLE001 — best-effort
            logger.warning(
                "wait_submit: scheduling resume echec (exec=%d) — admin doit "
                "trigger manuellement",
                exec_id,
                exc_info=True,
            )

        self._render_simple("", "submitted")

    def _render_simple(self, message: str, state: str) -> None:
        """Render minimal pour les cas d'erreur ou success."""
        self.render(
            "wait_response.html",
            state=state,
            page_title="Reponse - Komptia",
            company_name=get_company_name(),
            automation_name="",
            subject=message or "",
            body="",
            response_kind="text",
            file_format="both",
            expires_local="",
            resolved_at_local="",
            cancellation_reason=message if state == "cancelled" else "",
        )
