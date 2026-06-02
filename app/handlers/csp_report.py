"""Handler ``POST /api/csp-report`` — réception des violations CSP navigateur.

Pourquoi cet endpoint
---------------------
La directive ``Content-Security-Policy: ... ; report-uri /api/csp-report``
demande au navigateur de POSTer **automatiquement** un rapport JSON dès
qu'il bloque une ressource (script inline sans nonce, ressource externe
hors allowlist, etc.). Le rapport contient la directive violée, l'URI
bloqué et le contexte (line_number, source_file).

Sans ce endpoint, les violations sont **invisibles** côté serveur — le
bug se manifeste seulement comme "rien ne marche" côté utilisateur, sans
trace exploitable. Avec, on a un audit-trail complet :

* Détecter les régressions CSP en prod (un script ajouté sans nonce).
* Détecter les tentatives d'injection XSS (la CSP les bloque, le rapport
  remonte le ``blocked-uri`` injecté).
* Vérifier la couverture allowlist des CDN tiers (un nouveau CDN bloqué).

Particularités sécurité
-----------------------
1. **Pas de XSRF** — le navigateur émet un POST automatique sans
   token XSRF. Override de ``check_xsrf_cookie`` pour passer à travers
   (sinon 403 sur **toutes** les violations, le canal est mort).
2. **Pas d'authentification** — un anonyme sur ``/login`` doit pouvoir
   reporter une violation. La page de login est notamment celle où on
   a le plus de risque CSP (premiers scripts, premiers nonces).
3. **Rate-limit IP** — un attaquant pourrait flooder l'endpoint pour
   saturer le disque (audit JSONL). 60/min par IP suffit largement
   pour une page bourrée de violations légitimes.
4. **Body cap 16 KB** — un rapport CSP standard fait < 2 KB ; au-delà
   c'est un payload abusif, on rejette en 413.
5. **Logs structurés** — chaque violation logguée en ``warning`` avec
   les champs CSP standardisés (parseable Datadog/Loki).
6. **JSONL audit-trail** — `data/logs/csp_violations_YYYY-MM-DD.jsonl`
   avec rotation quotidienne, même pattern que feedback_audit.

Format des rapports
-------------------
Deux formats coexistent (W3C CSP3) :

* **Legacy `report-uri`** : `Content-Type: application/csp-report` ; le
  body contient un objet ``{"csp-report": {…}}``.
* **Reporting API `report-to`** : `Content-Type: application/reports+json`
  ; le body est une **liste** ``[{"type": "csp-violation", "body": {…}}]``.

On accepte les deux. Si ni l'un ni l'autre, log debug + 204 (silencieux,
pas d'erreur — le client n'a pas à se réessayer).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final, Optional

import tornado.web

from app.config import config
from app.core import clock
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ── Limites défensives ───────────────────────────────────────────────────

#: Body max accepté (16 KB). Un rapport CSP standard fait < 2 KB ; au-delà
#: = payload abusif (DoS sur le disque audit). 413 plutôt que de logger.
_MAX_BODY_BYTES: Final[int] = 16 * 1024

#: Rate-limit par IP. 60/min absorbe une page lourde de violations
#: légitimes (un dashboard avec 20 widgets, chacun pouvant déclencher une
#: violation au load). Au-delà = bot/attaque, on coupe en 429.
_RATE_LIMIT_PER_MIN: Final[int] = 60
_RATE_LIMIT_WINDOW_S: Final[int] = 60

#: Cap rotation par jour, aligné sur ``feedback_audit`` (50 MB). À ce
#: volume on a un signal de bug systémique (10K violations / jour) ;
#: la rotation .old évite la saturation disque.
_AUDIT_FILE_MAX_BYTES: Final[int] = 50 * 1024 * 1024
_AUDIT_FILENAME_PREFIX: Final[str] = "csp_violations_"

#: Champs gardés du rapport (allow-list explicite) — un attaquant
#: pourrait injecter des champs additionnels dans le JSON pour polluer
#: notre audit. On ne persiste que la liste blanche.
_ALLOWED_FIELDS: Final[tuple[str, ...]] = (
    "blocked-uri",
    "blockedURL",
    "blocked-url",
    "document-uri",
    "documentURL",
    "document-url",
    "effective-directive",
    "effectiveDirective",
    "violated-directive",
    "violatedDirective",
    "original-policy",
    "originalPolicy",
    "referrer",
    "source-file",
    "sourceFile",
    "line-number",
    "lineNumber",
    "column-number",
    "columnNumber",
    "status-code",
    "statusCode",
    "script-sample",
    "sample",
    "disposition",
)

#: Tronque toute valeur string à cette longueur — défense contre un
#: rapport gonflé artificiellement (URL de 100 KB, etc.).
_MAX_FIELD_LENGTH: Final[int] = 2000


# ── Rate limiter (process-local) ──────────────────────────────────────

_rate_limiter: RateLimiter = RateLimiter()


def reset_csp_report_rate_limiter() -> None:
    """Recrée le rate limiter (pour les tests qui partagent un process)."""
    global _rate_limiter
    _rate_limiter = RateLimiter()


# ── Helpers purs ──────────────────────────────────────────────────────


def _audit_file_path() -> Path:
    """Retourne le chemin du fichier audit JSONL du jour."""
    today = clock.now().strftime("%Y-%m-%d")
    return config.logs_dir / f"{_AUDIT_FILENAME_PREFIX}{today}.jsonl"


def _rotate_if_too_large(path: Path) -> None:
    """Renomme ``path`` en ``.old`` s'il dépasse le cap. Best-effort."""
    try:
        if path.exists() and path.stat().st_size >= _AUDIT_FILE_MAX_BYTES:
            old = path.with_suffix(path.suffix + ".old")
            try:
                if old.exists():
                    old.unlink()
            except OSError:
                pass
            path.rename(old)
    except OSError as exc:
        logger.warning("CSP audit: rotation impossible: %s", exc)


def _truncate(value: Any) -> Any:
    """Tronque les strings à _MAX_FIELD_LENGTH ; passe les autres types."""
    if isinstance(value, str) and len(value) > _MAX_FIELD_LENGTH:
        return value[:_MAX_FIELD_LENGTH] + "…"
    return value


def _pick_allowed(report: dict[str, Any]) -> dict[str, Any]:
    """Retourne uniquement les champs allowlisted, troncés.

    Un rapport CSP "trusted" venant du navigateur ne contient que des
    champs standards, mais un attaquant peut envoyer un faux rapport
    avec des clés exotiques pour polluer notre audit (champs énormes,
    keys avec ``\\n``, etc.). On se protège avec une allow-list stricte.
    """
    return {k: _truncate(v) for k, v in report.items() if k in _ALLOWED_FIELDS}


def _normalize_legacy(payload: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Format legacy ``{"csp-report": {…}}``."""
    inner = payload.get("csp-report")
    if isinstance(inner, dict):
        return _pick_allowed(inner)
    return None


def _normalize_reporting_api(payload: list[Any]) -> list[dict[str, Any]]:
    """Format Reporting API ``[{"type": "csp-violation", "body": {…}}]``.

    Filtre uniquement les rapports de type ``csp-violation`` — un client
    pourrait envoyer d'autres types (deprecation, intervention) qu'on
    ignore car hors scope.
    """
    out: list[dict[str, Any]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") not in ("csp-violation", "csp"):
            continue
        body = entry.get("body")
        if isinstance(body, dict):
            out.append(_pick_allowed(body))
    return out


# ── Handler ───────────────────────────────────────────────────────────


class CSPReportHandler(tornado.web.RequestHandler):
    """``POST /api/csp-report`` — endpoint pour les rapports navigateur.

    N'hérite **pas** de ``BaseHandler`` : on n'a besoin ni de
    ``current_user`` (le navigateur poste sans cookie pertinent), ni
    du middleware de sécurité (les headers anti-cache/anti-frame ne
    s'appliquent pas à un endpoint de télémetrie). On garde la classe
    minimale pour couper la surface d'attaque.
    """

    def check_xsrf_cookie(self) -> None:
        """Le navigateur ne propage pas le token XSRF sur un report-uri.

        Override no-op — sans ça, **tous** les rapports recevraient 403.
        Sécurité : le risque CSRF sur cet endpoint est minime (il écrit
        un audit-trail, pas une mutation user/business). Le rate-limit
        par IP couvre l'abus.
        """
        return None

    async def prepare(self) -> None:
        """Cap body size avant lecture (anti DoS mémoire)."""
        try:
            content_length = int(self.request.headers.get("Content-Length") or "0")
        except ValueError:
            content_length = 0
        if content_length > _MAX_BODY_BYTES:
            raise tornado.web.HTTPError(413, "CSP report too large")

    async def post(self) -> None:
        client_ip = self.request.remote_ip or "unknown"

        # 1. Rate-limit par IP avant tout I/O.
        if not _rate_limiter.check(
            f"csp:{client_ip}",
            max_requests=_RATE_LIMIT_PER_MIN,
            window_seconds=_RATE_LIMIT_WINDOW_S,
        ):
            self.set_status(429)
            self.set_header("Retry-After", str(_RATE_LIMIT_WINDOW_S))
            self.finish()
            return

        # 2. Re-check body size (le Content-Length peut mentir).
        body_bytes = self.request.body or b""
        if len(body_bytes) > _MAX_BODY_BYTES:
            raise tornado.web.HTTPError(413, "CSP report too large")

        # 3. Parsing JSON tolérant (ne JAMAIS leaker l'exception au client
        #    — le navigateur ne sait pas quoi faire d'une 400 ici, on
        #    retourne 204 silencieux pour ne pas le faire retry).
        try:
            payload = json.loads(body_bytes or b"{}")
        except json.JSONDecodeError:
            logger.debug("CSP report: JSON invalide (ip=%s, len=%d)", client_ip, len(body_bytes))
            self.set_status(204)
            self.finish()
            return

        # 4. Normalisation des deux formats CSP3.
        violations: list[dict[str, Any]] = []
        if isinstance(payload, dict):
            single = _normalize_legacy(payload)
            if single is not None:
                violations.append(single)
        elif isinstance(payload, list):
            violations.extend(_normalize_reporting_api(payload))

        if not violations:
            # Format inconnu — on ignore silencieusement (pas un bug user).
            self.set_status(204)
            self.finish()
            return

        # 5. Persist + log pour chaque violation.
        for violation in violations:
            await self._persist_and_log(violation, client_ip)

        # 204 No Content : le navigateur n'attend pas de body.
        self.set_status(204)
        self.finish()

    async def _persist_and_log(self, violation: dict[str, Any], client_ip: str) -> None:
        """Logue + persiste UN rapport CSP."""
        # Champs alignés sur le format legacy pour homogénéiser logs.
        directive = (
            violation.get("violated-directive")
            or violation.get("violatedDirective")
            or violation.get("effective-directive")
            or violation.get("effectiveDirective")
            or "?"
        )
        blocked = (
            violation.get("blocked-uri")
            or violation.get("blockedURL")
            or violation.get("blocked-url")
            or "?"
        )

        logger.warning(
            "CSP violation",
            extra={
                "ip": client_ip,
                "directive": str(directive),
                "blocked_uri": str(blocked),
                "document": str(
                    violation.get("document-uri")
                    or violation.get("documentURL")
                    or violation.get("document-url")
                    or "?"
                ),
                "source_file": str(
                    violation.get("source-file") or violation.get("sourceFile") or ""
                ),
            },
        )

        record = {
            "timestamp": clock.now().isoformat(),
            "ip": client_ip,
            **violation,
        }

        # Écriture JSONL fail-safe : un échec disque n'empêche pas le
        # logger.warning ci-dessus, donc on a au minimum la trace logs.
        try:
            config.logs_dir.mkdir(parents=True, exist_ok=True)
            path = _audit_file_path()
            _rotate_if_too_large(path)
            line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    # fsync peut échouer sur tmpfs / NFS — on garde la
                    # ligne en buffer OS, c'est un best-effort.
                    pass
        except OSError as exc:
            logger.warning("CSP audit-trail write failed: %s", exc)
