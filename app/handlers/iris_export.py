"""Handler POST /api/iris/export-xlsx-full — export Excel complet serveur.

Pendant le scénario "Piste 3" : l'utilisateur clique sur "Excel (.xlsx) —
version complète (serveur)" dans le menu d'export d'Iris. Le frontend
sérialise le classeur (forme ``GridTabManager.serialize()``) et envoie le
payload à cet endpoint. Le serveur réexécute les requêtes SQL avec un cap
élevé (100k lignes par défaut), reconstruit les détails de cellules à partir
des données fraîches, et renvoie le ``.xlsx`` en streaming attachment.

Différences avec l'export client-side existant :
- Pas de cap à 500 lignes par onglet (cap configurable, default 100k)
- Détails de cellules calculés sur les données complètes, pas le snapshot
- RLS appliquée à la réexécution (chaque user n'exporte que ce qu'il peut voir)
- Latence de quelques secondes pour les gros classeurs (acceptable pour
  un export "définitif" destiné à transmission/diffusion)
"""

from __future__ import annotations

import json
from typing import Final

import tornado.web

from app.handlers.base import BaseHandler, authenticated
from app.models.audit import AuditAction, AuditLog
from app.core import clock
from app.core.database import get_session
from app.services.export.iris_xlsx_builder import build_iris_xlsx
from app.utils.logger import get_logger
from app.utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# ── Rate limit ───────────────────────────────────────────────────────────
RATE_LIMIT_EXPORT_FULL: Final[tuple[int, int]] = (5, 60)
"""5 exports complets par minute par utilisateur. Cap intentionnellement
bas : un export complet réexécute toutes les SQL du classeur avec un gros
cap, ça consomme de la BDD source — pas un endpoint à spammer."""

_export_full_limiter = RateLimiter()


def _check_rate_limit(
    limiter: RateLimiter, user_id: int, max_requests: int, window_seconds: int
) -> None:
    """Lève ``HTTPError(429)`` si quota dépassé."""
    key = f"user:{user_id}"
    if not limiter.check(key, max_requests=max_requests, window_seconds=window_seconds):
        raise tornado.web.HTTPError(
            429,
            "Trop d'exports rapprochés. Patientez quelques secondes.",
        )


# ── Constantes ────────────────────────────────────────────────────────────

_MAX_PAYLOAD_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MiB
"""Cap de la taille du payload accepté. Un classeur normal pèse <5 MiB ;
50 MiB couvre les cas extrêmes (gros snapshot frontend) sans ouvrir un
DoS via JSON géant."""

_DEFAULT_MAX_ROWS_PER_TAB: Final[int] = 100_000
"""Cap par défaut. Le client peut demander moins (jamais plus côté serveur)."""

_HARD_CAP_MAX_ROWS_PER_TAB: Final[int] = 200_000
"""Plafond absolu — un classeur dont chaque onglet retourne 200k lignes
représenterait un export ingérable (200 MB+ de XLSX). Refus ferme."""


class IrisExportXlsxFullHandler(BaseHandler):
    """POST /api/iris/export-xlsx-full

    Body JSON (forme ``GridTabManager.serialize()`` côté frontend) :

    .. code-block:: json

        {
          "version": 1,
          "app": "komptia",
          "tabs": [
            {"label": "...", "sql": "...", "columns": [...], "rows": [...],
             "cellDetails": {...}, "merges": [...], ...},
            ...
          ],
          "max_rows_per_tab": 100000   // optionnel — override du cap
        }

    Response : binaire XLSX (Content-Type
    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet)
    avec ``Content-Disposition: attachment; filename="..."``.

    En-têtes ajoutés pour signaler les warnings non-bloquants :
    - ``X-Iris-Export-Warnings`` : JSON-encoded liste de strings (URL-safe)
    - ``X-Iris-Export-Stats`` : JSON-encoded stats (tabs_count, sql_re_executed, …)
    """

    @authenticated
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_export_full_limiter, user.id, *RATE_LIMIT_EXPORT_FULL)

        # Garde-fou taille payload — Tornado lit déjà tout en mémoire selon
        # ``max_body_size`` global, mais on double-check (pas de surprise).
        body = self.request.body
        if not body:
            return self.write_json({"success": False, "error": "Payload vide"}, 400)
        if len(body) > _MAX_PAYLOAD_BYTES:
            return self.write_json(
                {
                    "success": False,
                    "error": f"Payload trop gros (>{_MAX_PAYLOAD_BYTES // 1024 // 1024} MiB)",
                },
                413,
            )

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self.write_json({"success": False, "error": f"JSON invalide: {exc}"}, 400)

        if not isinstance(payload, dict):
            return self.write_json(
                {"success": False, "error": "Payload doit être un objet JSON"}, 400
            )

        # Cap par onglet : client peut demander moins (≥1) ; sinon default.
        # Plafond absolu côté serveur — refus si > _HARD_CAP_MAX_ROWS_PER_TAB.
        client_cap = payload.get("max_rows_per_tab")
        if isinstance(client_cap, int) and 1 <= client_cap <= _HARD_CAP_MAX_ROWS_PER_TAB:
            max_rows = client_cap
        elif client_cap is not None:
            return self.write_json(
                {
                    "success": False,
                    "error": (
                        f"max_rows_per_tab doit être entier entre 1 et "
                        f"{_HARD_CAP_MAX_ROWS_PER_TAB}"
                    ),
                },
                400,
            )
        else:
            max_rows = _DEFAULT_MAX_ROWS_PER_TAB

        # Mode anonymisé (« valeurs anonymisées ») vs clair (default). Le
        # frontend envoie ``anonymize: true`` quand l'utilisateur a basculé le
        # toggle. Tout ce qui n'est pas strictement ``true`` = clair (default
        # sûr : on n'anonymise jamais par accident, mais surtout on n'expose
        # jamais en clair un export que l'utilisateur croyait anonymisé — le
        # fail-closed côté builder garantit ce dernier point).
        anonymize = payload.get("anonymize") is True

        # Construction du XLSX. Toutes les erreurs métier (RLS, SQL invalide
        # sur un onglet) sont remontées en warnings non-bloquants — le builder
        # ne lève QUE pour les erreurs de payload structurel.
        try:
            result = await build_iris_xlsx(
                payload, user, max_rows_per_tab=max_rows, executor=None, anonymize=anonymize
            )
        except ValueError as exc:
            return self.write_json({"success": False, "error": str(exc)}, 400)
        except RuntimeError:
            # Fail-closed anonymisation : un terme /data/privacy configuré n'a
            # pas pu être appliqué (collision de pseudonyme). On refuse de
            # livrer un fichier partiellement anonymisé. Message actionnable.
            logger.warning(
                "iris_export_xlsx_full: anonymisation fail-closed",
                extra={"user_id": user.id},
                exc_info=True,
            )
            return self.write_json(
                {
                    "success": False,
                    "error": (
                        "Export anonymisé impossible : un terme configuré sur "
                        "/data/privacy n'a pas pu être appliqué (conflit de "
                        "pseudonyme). Corrigez le conflit puis réessayez, ou "
                        "exportez en clair."
                    ),
                },
                422,
            )
        except Exception:  # noqa: BLE001 — robustesse export
            logger.exception(
                "iris_export_xlsx_full: échec inattendu",
                extra={"user_id": user.id},
            )
            return self.write_json(
                {"success": False, "error": "Erreur interne lors de la génération du fichier"},
                500,
            )

        content: bytes = result["content"]
        stats: dict = result["stats"]
        warnings: list = result["warnings"]

        # Audit log — non-bloquant si BDD down (logger seulement).
        try:
            async with get_session() as session:
                session.add(
                    AuditLog.log_action(
                        action=AuditAction.FILE_SEARCH_EXPORT,
                        user_id=user.id,
                        entity_type="iris_workbook",
                        entity_id=None,
                        details={
                            "kind": "iris_xlsx_full",
                            "tabs_count": stats.get("tabs_count"),
                            "total_rows": stats.get("total_rows"),
                            "sql_re_executed": stats.get("sql_re_executed"),
                            "sql_skipped_count": len(stats.get("sql_skipped") or []),
                            "detail_sheets_count": stats.get("detail_sheets_count"),
                            "size_bytes": len(content),
                            "anonymized": anonymize,
                        },
                        ip_address=self.request.remote_ip,
                    )
                )
        except Exception:  # noqa: BLE001 — audit best-effort
            logger.warning(
                "iris_export_xlsx_full: audit log échoué",
                extra={"user_id": user.id},
                exc_info=True,
            )

        # Filename — timestamp + suffixe ``_anonymise`` en mode anonymisé pour
        # que l'utilisateur distingue d'un coup d'œil un fichier anonymisé d'un
        # fichier en clair (évite un envoi externe du mauvais fichier).
        ts = clock.now().strftime("%Y-%m-%dT%H-%M-%S")
        suffix = "_anonymise" if anonymize else ""
        filename = f"komptia_iris_{ts}{suffix}.xlsx"

        # Headers de réponse binaire.
        self.set_header(
            "Content-Type",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        # ``filename*=UTF-8''…`` est l'encodage RFC5987 — supporté par tous les
        # navigateurs récents pour les caractères non-ASCII. Pour notre
        # filename ASCII pur, le simple ``filename="..."`` suffit, mais on
        # garde le pattern propre pour le futur.
        self.set_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.set_header("Content-Length", str(len(content)))
        # Évite que les proxies cachent le résultat (par user / par instant).
        self.set_header("Cache-Control", "no-store")

        # Warnings et stats en headers — JSON-encoded, base64 pas nécessaire
        # tant qu'on n'a pas de retours-chariot dans les chaînes (les warnings
        # sont des messages courts en français, pas de \n attendu).
        # On limite la taille pour ne pas exploser la table de headers HTTP.
        try:
            warnings_json = json.dumps(warnings, ensure_ascii=True)
            if len(warnings_json) <= 4096:
                self.set_header("X-Iris-Export-Warnings", warnings_json)
        except (TypeError, ValueError):
            pass
        try:
            stats_json = json.dumps(stats, ensure_ascii=True, default=str)
            if len(stats_json) <= 4096:
                self.set_header("X-Iris-Export-Stats", stats_json)
        except (TypeError, ValueError):
            pass

        self.write(content)

    def write_error(self, status_code: int, **kwargs) -> None:
        """Override pour retourner JSON sur erreur (et pas la page HTML par
        défaut de Tornado, qui casserait l'orchestration côté JS qui s'attend
        à du binaire ou du JSON erreur)."""
        self.set_header("Content-Type", "application/json")
        reason = self._reason if hasattr(self, "_reason") else "Erreur"
        self.write(
            json.dumps(
                {"success": False, "error": reason, "status": status_code},
                ensure_ascii=False,
            )
        )


# ── Anonymize-tabs (export « valeurs anonymisées », formatage côté client) ──

RATE_LIMIT_ANON_TABS: Final[tuple[int, int]] = (30, 60)
"""30 appels/min/user. Plus permissif que l'export complet : c'est une
transformation in-memory légère (aucune réexécution SQL), appelée juste avant
un export CSV / copie presse-papier anonymisé côté client."""

_anonymize_tabs_limiter = RateLimiter()

_MAX_TABS_ANON: Final[int] = 200
"""Garde-fou cohérent avec ``_MAX_TABS_PER_EXPORT`` du builder XLSX."""


class IrisAnonymizeTabsHandler(BaseHandler):
    """POST /api/iris/anonymize-tabs

    Reçoit ``{tabs: [{columns, rows, label?, cellDetails?}, ...]}`` et renvoie
    ``{success: true, tabs: [...]}`` où les **valeurs de cellules** configurées
    par l'utilisateur sur ``/data/privacy`` sont remplacées par leur pseudonyme
    propre. La **sérialisation finale** (CSV, presse-papier) reste côté client —
    le format du fichier est donc strictement identique à l'export en clair,
    seules les valeurs changent.

    Pourquoi serveur et pas un applicateur JS : l'anonymisation doit être
    **fail-closed** et s'appuyer sur la SEULE source de vérité (table
    ``anonymization_terms`` via ``export_filter``). Un applicateur côté client
    risquerait une fuite silencieuse en cas de divergence avec le backend
    (matching casse/espaces, substring). Voir ``app/services/anonymization/
    export_filter.py``.

    Fail-closed : 422 si un terme configuré ne peut être appliqué (collision de
    pseudonyme) — on refuse plutôt que de renvoyer des valeurs partiellement
    anonymisées que le client exporterait en croyant qu'elles sont masquées.
    """

    @authenticated
    async def post(self) -> None:
        user = self.current_user
        _check_rate_limit(_anonymize_tabs_limiter, user.id, *RATE_LIMIT_ANON_TABS)

        body = self.request.body
        if not body:
            return self.write_json({"success": False, "error": "Payload vide"}, 400)
        if len(body) > _MAX_PAYLOAD_BYTES:
            return self.write_json(
                {
                    "success": False,
                    "error": f"Payload trop gros (>{_MAX_PAYLOAD_BYTES // 1024 // 1024} MiB)",
                },
                413,
            )
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return self.write_json({"success": False, "error": f"JSON invalide: {exc}"}, 400)
        if not isinstance(payload, dict):
            return self.write_json(
                {"success": False, "error": "Payload doit être un objet JSON"}, 400
            )
        tabs = payload.get("tabs")
        if not isinstance(tabs, list):
            return self.write_json({"success": False, "error": "tabs doit être une liste"}, 400)
        if len(tabs) > _MAX_TABS_ANON:
            return self.write_json(
                {"success": False, "error": f"Trop d'onglets (>{_MAX_TABS_ANON})"}, 400
            )

        from app.services.anonymization.export_filter import anonymize_tabs_for_export_meta

        try:
            anon = await anonymize_tabs_for_export_meta(user.id, tabs)
        except RuntimeError:
            # Fail-closed : un terme configuré n'a pas pu être appliqué. On ne
            # renvoie JAMAIS de tabs en clair sur un appel d'anonymisation.
            logger.warning(
                "iris_anonymize_tabs: anonymisation fail-closed",
                extra={"user_id": user.id},
                exc_info=True,
            )
            return self.write_json(
                {
                    "success": False,
                    "error": (
                        "Anonymisation impossible : un terme configuré sur "
                        "/data/privacy n'a pas pu être appliqué (conflit de "
                        "pseudonyme). Corrigez le conflit puis réessayez, ou "
                        "exportez en clair."
                    ),
                },
                422,
            )
        except Exception:  # noqa: BLE001 — robustesse
            logger.exception(
                "iris_anonymize_tabs: échec inattendu",
                extra={"user_id": user.id},
            )
            return self.write_json(
                {"success": False, "error": "Erreur interne lors de l'anonymisation"},
                500,
            )

        # ``term_count == 0`` → l'utilisateur n'a aucun terme configuré sur
        # /data/privacy : le fichier sera identique au clair. On le renvoie pour
        # que le client puisse avertir (anti fausse-impression de sécurité).
        return self.write_json(
            {"success": True, "tabs": anon["tabs"], "term_count": anon["term_count"]}
        )
