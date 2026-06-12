"""Handlers HTTP pour la liste d'anonymisation pilotée utilisateur.

Endpoints
---------

**Liste (panneau)** :

* ``GET  /api/anonymization/terms`` — état complet (``anon_terms`` v1).
* ``PUT  /api/anonymization/terms`` — replace state (upsert+delete absents).

**Détail / opérations granulaires** :

* ``DELETE /api/anonymization/terms/:id`` — supprime UN terme (audit log).
* ``GET /api/anonymization/terms/:id/coverage`` — où apparaît ce terme.

**Audit / données** :

* ``GET  /api/anonymization/audit`` — historique paginé des modifications.
* ``GET  /api/anonymization/export`` — export complet des données du user (JSON).
* ``POST /api/anonymization/wipe`` — suppression totale termes + audit, double-confirm.

**Stats / proposition** :

* ``GET  /api/anonymization/stats`` — agrégats (badge global).
* ``POST /api/anonymization/auto-classify`` — proposition LLM local (chunked).
* ``POST /api/anonymization/auto-classify/probe`` — calibration LLM local.
* ``POST /api/anonymization/auto-classify/regex`` — fallback regex (sans LLM).
* ``POST /api/anonymization/scan`` — scan datastore en streaming SSE.

Sécurité transverse :

1. ``@authenticated`` + ``@require_role(USER, ADMIN)`` — fail-closed.
2. Rate-limit par scope (write léger / scan lourd / wipe critique).
3. Ownership 404 pour les ressources de detail (pas 403, pour ne pas
   leak l'existence).
4. Body cap 2 Mo (anti-DoS RAM). Pré-check ``Content-Length``.
5. ``Content-Type: application/json`` pour les exports avec
   ``Content-Disposition: attachment``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Final, List, Optional, Set

from tornado.iostream import StreamClosedError

from app.core import clock
from app.core.db_retry import retry_on_locked
from app.handlers.base import BaseHandler, authenticated, require_role
from app.models.user import UserRole
from app.services.anonymization import api_service as anon_api
from app.services.anonymization import audit as anon_audit_module
from app.services.anonymization import extract as anon_terms
from app.services.anonymization import repository as anon_repo
from app.services.anonymization.locks import acquire_user_anon_lock
from app.utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)


#: Taille max du body PUT — la sémantique ``replace`` envoie l'INTÉGRALITÉ
#: du state à chaque save (panneau, toggle, debounce). Avec
#: ``BYTES_PER_TERM_ESTIMATE`` ≈ 200 bytes/terme, un user qui vient de
#: scanner son datastore (``scan-datastore`` → "Scanner mes données" peut
#: insérer 40-50K termes en une fois) génère un body de l'ordre de 8-10 Mo.
#: Le cap de 2 Mo historique (10K termes) rejetait ces saves en 413 et
#: l'UI affichait « Échec enregistrement » sans recours.
#:
#: 25 Mo couvre ~125K termes (≈ 3× la taille d'un scan complet typique)
#: avec une marge raisonnable. Surface DoS reste contenue par
#: :data:`_PUT_RATE_MAX` (30 PUT/min/user authentifié, scope == ses propres
#: termes) et par le quota disque dynamique (``UserStorage.quota_limit``
#: via ``get_user_term_cap``) qui plafonne la croissance côté BDD.
#:
#: Refactor long-terme à envisager : PATCH différentiel (n'envoyer que les
#: termes mutés) — supprimerait ce trade-off entièrement. Hors scope ici.
_BODY_MAX_BYTES: Final[int] = 25 * 1024 * 1024

#: Rate-limit PUT : 30 req/min/user. Sauvegarde panneau = 1-2/session
#: normalement ; 30 couvre l'usage actif + une marge pour la reprise
#: après erreur réseau. Floodeur = signal anormal.
_PUT_RATE_MAX: Final[int] = 30
_PUT_RATE_WINDOW_S: Final[int] = 60

_put_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limit auto-classify (review LOW #5 DoS) : un classeur de 50K
#: tokens = 250 chunks. À 60 req/min, 250 chunks tiennent en ~4-5 min.
#: Limite raisonnable : un user fait 1 run d'analyse à la fois.
_AUTO_CLASSIFY_RATE_MAX: Final[int] = 300
_AUTO_CLASSIFY_RATE_WINDOW_S: Final[int] = 60

_auto_classify_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Probe : 1 par 10s/user (calibration ne devrait jamais être appelée
#: en boucle).
_PROBE_RATE_MAX: Final[int] = 6
_PROBE_RATE_WINDOW_S: Final[int] = 60

_probe_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Rate-limits supplémentaires pour les nouveaux endpoints (tâche #10).
#: Aligne write / read / heavy selon la sévérité de l'opération.

#: DELETE term : 30/min — un user peut faire plusieurs deletes successifs
#: dans le panneau (tri, nettoyage manuel).
_DELETE_TERM_RATE_MAX: Final[int] = 30
_DELETE_TERM_RATE_WINDOW_S: Final[int] = 60
_delete_term_rate_limiter: Final[RateLimiter] = RateLimiter()

#: COVERAGE : 20/min — opération coûteuse (scan disque cross-classeurs).
_COVERAGE_RATE_MAX: Final[int] = 20
_COVERAGE_RATE_WINDOW_S: Final[int] = 60
_coverage_rate_limiter: Final[RateLimiter] = RateLimiter()

#: AUDIT listing : 60/min — lecture pure, alignée sur EmailHistory.
_AUDIT_RATE_MAX: Final[int] = 60
_AUDIT_RATE_WINDOW_S: Final[int] = 60
_audit_rate_limiter: Final[RateLimiter] = RateLimiter()

#: EXPORT données : 5 / 5min — gros payload, pas spammable. L'utilisateur
#: télécharge 1× par check de conformité (pas en boucle).
_EXPORT_RATE_MAX: Final[int] = 5
_EXPORT_RATE_WINDOW_S: Final[int] = 300
_export_rate_limiter: Final[RateLimiter] = RateLimiter()

#: WIPE données : 3 / heure — opération destructive irréversible.
_WIPE_RATE_MAX: Final[int] = 3
_WIPE_RATE_WINDOW_S: Final[int] = 3600
_wipe_rate_limiter: Final[RateLimiter] = RateLimiter()

#: STATS : 60/min — badge global, refresh fréquent côté UI accepté.
_STATS_RATE_MAX: Final[int] = 60
_STATS_RATE_WINDOW_S: Final[int] = 60
_stats_rate_limiter: Final[RateLimiter] = RateLimiter()

#: SCAN SSE : 3 / 5min — scan disque coûteux (parser JSON × N classeurs).
_SCAN_RATE_MAX: Final[int] = 3
_SCAN_RATE_WINDOW_S: Final[int] = 300
_scan_rate_limiter: Final[RateLimiter] = RateLimiter()

#: SCAN-WORKBOOK live : 60/min — frontend appelle avec debounce 2-3s à chaque
#: changement workbook. 60/min = un user actif sur 1-2 changements/s en pointe.
_SCAN_WORKBOOK_RATE_MAX: Final[int] = 60
_SCAN_WORKBOOK_RATE_WINDOW_S: Final[int] = 60
_scan_workbook_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Regex auto-format pour identifier les pseudos auto-générés (à
#: ré-améliorer) vs les vrais customs user-saisis (à préserver). Compilée
#: au module-level pour ne pas re-compiler à chaque requête HTTP. Le suffix
#: doit être hex lowercase 3-8 chars ET hasher exactement le term — cf.
#: ``_is_auto_pseudo_format`` dans ``AnonymizationImprovePseudoAPIHandler``.
import re as _re_anon

_AUTO_PSEUDO_FMT_RE: Final = _re_anon.compile(r"^[A-Z][A-Z0-9_]*_([a-f0-9]+)$")

#: ADD-MANUAL : 10/min — l'user saisit un terme à la fois dans le modal
#: ``/data/privacy``. 10/min couvre largement l'usage normal. Au-delà =
#: spam/script anormal.
_ADD_MANUAL_RATE_MAX: Final[int] = 10
_ADD_MANUAL_RATE_WINDOW_S: Final[int] = 60
_add_manual_rate_limiter: Final[RateLimiter] = RateLimiter()

#: Cap de tokens insérés par requête manuelle. Un usage humain typique
#: tape 1-3 termes ("DUPONT Marie", "marie@dupont.com", un identifiant
#: client). Au-delà = paste accidentel d'une phrase entière ou attaque
#: DoS (épuisement RAM via SELECT all-terms à chaque upsert). Cap dur
#: à 20 — l'user qui veut ajouter plus passe par plusieurs requêtes
#: (rate-limit 10/min × 20 tokens = 200 termes/min, suffisant). Cf.
#: review adversariale 2026-05-19 finding #2.
_ADD_MANUAL_MAX_TOKENS_PER_REQ: Final[int] = 20

#: SSE heartbeat — ping commentaire toutes les N secondes pour empêcher
#: les proxies (nginx, cloudflare) de fermer la connexion idle.
_SSE_HEARTBEAT_S: Final[float] = 15.0

_ALLOWED_ROLES = frozenset({UserRole.ADMIN, UserRole.USER})


# ─── Helpers handlers ──────────────────────────────────────────────────────


def _set_no_store_headers(handler: BaseHandler) -> None:
    """Force ``Cache-Control: no-store`` sur les réponses contenant des PII.

    Les endpoints qui retournent des termes utilisateur en clair (terms,
    audit, coverage, stats) ne doivent JAMAIS être mis en cache disque
    par le navigateur. Sur un poste partagé après logout, le cache HTTP
    pourrait exposer les PII au prochain utilisateur (anti-pattern PII
    caching connu).
    """
    handler.set_header("Cache-Control", "no-store, max-age=0, private")
    handler.set_header("Pragma", "no-cache")


def _check_rate(limiter: RateLimiter, key: str, max_req: int, window_s: int) -> bool:
    """Wrapper concis. Retourne True si l'appel est autorisé."""
    return limiter.check(key, max_req, window_s)


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse un timestamp ISO 8601 → datetime aware UTC.

    Retourne ``None`` si invalide / absent. Permissif sur le format
    (``Z``, offset, sans offset → assume UTC).
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class AnonymizationTermsAPIHandler(BaseHandler):
    """Ressource unique ``/api/anonymization/terms`` — state du user courant."""

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def get(self) -> None:
        """Retourne l'état d'anonymisation complet du user.

        Shapes de sortie selon ``?detailed`` :

        * Sans ``?detailed=1`` (défaut, panneau iris-grid) ::

              {"anonymization_state": {"version": 1, "terms": {token: {...}}}}

        * Avec ``?detailed=1`` (page ``/data/privacy``) ::

              {"anonymization_state": {"version": 1, "terms": [{...}, ...]}}

          Liste ordonnée (par ``term`` asc), chaque entrée expose le
          ``to_dict()`` complet (id, category, risk_level, source,
          last_seen_at, ...).

        **Note confidentialité** : cet endpoint expose les ``term`` en
        clair (cleartext issus du classeur de l'utilisateur). C'est
        volontaire — le frontend a besoin de les afficher dans le panneau
        pour que l'utilisateur tranche. L'auth garantit que SEUL le
        propriétaire des termes y accède.
        """
        user_id = self.current_user.id
        # Mode "detailed" pour la page /data/privacy : retourne to_dict()
        # complet plutôt que la version minimale runtime. Param accepté
        # uniquement en GET, ne change PAS la sémantique du PUT.
        detailed = self.get_argument("detailed", "0").strip() in ("1", "true", "yes")
        async with self.db_session() as session:
            if detailed:
                state = await anon_repo.get_detailed_state_for_user(session, user_id)
            else:
                state = await anon_repo.get_state_for_user(session, user_id)
            # Jeton de révision pour le verrou optimiste du PUT (fix lost
            # update 2026-06-10) — le client le renvoie en
            # ``expected_revision`` ; mismatch ⇒ 409 STATE_REVISION_MISMATCH.
            revision = await anon_repo.get_state_revision(session, user_id)
        _set_no_store_headers(self)
        self.write_json({"anonymization_state": state, "revision": revision})

    @authenticated
    @require_role(UserRole.ADMIN, UserRole.USER)
    async def put(self) -> None:
        """Remplace le state d'anonymisation du user par le body fourni.

        Body attendu ::

            {"anonymization_state": {"version": 1, "terms": {...}}}

        Semantique ``replace`` : les termes absents du body sont supprimés
        de la BDD. Pour ajouter, le client fait ``GET`` → merge → ``PUT``.

        Erreurs possibles :

        * ``400 ANON_STATE_INVALID`` — shape ou contenu invalide (pseudo
          en collision, sentinelle ``§`` dans middle, etc.). Le body
          retourne la liste structurée ``state_errors``.
        * ``413 BODY_TOO_LARGE`` — body > ``_BODY_MAX_BYTES``.
        * ``429`` — rate limit.
        """
        user_id = self.current_user.id

        # Rate-limit avant parse (un attaquant spam ne nous coûte pas le
        # temps de parser son JSON).
        if not _put_rate_limiter.check(f"anon-put:{user_id}", _PUT_RATE_MAX, _PUT_RATE_WINDOW_S):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        # Pré-check Content-Length pour éviter de matérialiser un body
        # pathologique. Header malformé : on laisse le parse trancher.
        # En cas de dépassement on inclut le ``limit_bytes`` pour que le
        # frontend puisse afficher un message actionnable
        # ("dictionnaire de X Mo, max Y Mo — utilisez « Vider » sur
        # /data/privacy") au lieu d'un opaque « trop volumineux ».
        cl_raw = self.request.headers.get("Content-Length")
        if cl_raw:
            try:
                body_size = int(cl_raw)
            except ValueError:
                body_size = -1
            if body_size > _BODY_MAX_BYTES:
                self.write_json(
                    {
                        "error": (
                            f"Dictionnaire d'anonymisation trop volumineux "
                            f"({body_size // (1024 * 1024)} Mo). Maximum "
                            f"autorisé : {_BODY_MAX_BYTES // (1024 * 1024)} Mo. "
                            "Allez sur /data/privacy pour purger les termes "
                            "inutiles ou contactez votre administrateur."
                        ),
                        "error_code": "STATE_TOO_LARGE",
                        "body_size": body_size,
                        "limit_bytes": _BODY_MAX_BYTES,
                    },
                    413,
                )
                return

        # ``json.loads`` est synchrone et bloque l'event-loop Tornado. Sur un
        # body de 25 Mo (~125K termes) ça peut prendre 200-500 ms — pendant
        # ce temps aucun autre handler ne tourne. On offload sur le thread
        # pool : un user qui save son dictionnaire ne bloque plus les autres.
        # Seuil empirique 256 Ko : en-dessous, le parse est trop rapide pour
        # justifier le coût du context-switch thread.
        raw_body = self.request.body
        try:
            if len(raw_body) > 256 * 1024:
                body = await asyncio.to_thread(json.loads, raw_body)
            else:
                body = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            logger.info(
                "anonymization PUT JSON invalide",
                extra={
                    "request_id": getattr(self, "request_id", "?"),
                    "err_class": exc.__class__.__name__,
                },
            )
            self.write_json({"error": "JSON invalide."}, 400)
            return

        if not isinstance(body, dict):
            self.write_json({"error": "JSON doit être un objet."}, 400)
            return

        state = body.get("anonymization_state")
        if not isinstance(state, dict):
            self.write_json(
                {"error": "Champ `anonymization_state` manquant ou invalide."},
                400,
            )
            return

        # Sanitize au lieu de rejeter (review 2026-04-26) : un terme
        # corrompu (pseudo invalide, type mismatch) est stripé silencieusement
        # plutôt que de bloquer tout le state. Évite qu'une vieille entrée
        # historique bloque l'utilisateur jusqu'à correction manuelle.
        # Les erreurs sont logguées pour audit.
        #
        # **Exposition au client (fix CRITICAL adversarial 2026-05-20)** : on
        # remonte aussi ``state_errors`` dans la response 200 (en plus du
        # sanitize) pour que le frontend puisse afficher un toast warning à
        # l'utilisateur ("3 termes ignorés car invalides"). Avant ce fix, le
        # client ne savait jamais que ses pseudonymes en collision /
        # invalides avaient été silencieusement strippés — UX trompeuse,
        # "save success" alors qu'une partie est perdue. Cap à 10 erreurs
        # (premier signal suffit ; au-delà l'user doit aller sur /data/privacy).
        sanitization_errors: list = []
        sanitization_errors_total: int = 0
        errors = anon_terms.validate_state(state)
        if errors:
            sanitization_errors = errors[:10]
            sanitization_errors_total = len(errors)
            logger.warning(
                "anonymization PUT %s : %d erreurs sanitizées (state=%d termes)",
                user_id,
                sanitization_errors_total,
                len((state.get("terms") or {})) if isinstance(state, dict) else 0,
                extra={"state_errors": sanitization_errors},
            )
            state = anon_terms.sanitize_state(state)

        # **Garde anti mass-delete** (incident 2026-05-20 : un PUT a purgé
        # 89785 termes sur 90135 en 13 secondes). Le client doit envoyer
        # ``confirm_mass_delete: true`` au top-level du body pour valider
        # une purge >1000 termes ET >50% du before. Sans flag, on raise
        # ``MassDeleteRefused`` → 409 actionnable côté UI.
        confirm_mass_delete = bool(body.get("confirm_mass_delete", False))

        # **Périmètre de suppression** (fix 2026-06-10, bug vécu en prod) :
        # le panneau iris-grid charge le GET NON-détaillé (filtré — les
        # désactivés+confirmés en sont exclus depuis le fix perf 2026-06-09)
        # puis PUT son état en replace. Sans déclaration de périmètre, les
        # ~85k termes invisibles du client étaient comptés comme suppressions
        # → 409 MASS_DELETE_REFUSED systématique (gros dico) ou purge
        # silencieuse (dico sous les seuils). Contrat : le client qui a
        # chargé l'état COMPLET (``?detailed=1``, ex. /data/privacy) déclare
        # ``state_scope: "full"`` ; tout le reste (défaut FAIL-CLOSED) ne
        # peut supprimer que les termes du périmètre actif qu'il a vus.
        # ``state_scope == "full"`` est une DÉCLARATION client non vérifiée
        # serveur — acceptable (verdict tâche #25) car : (1) le périmètre ne
        # porte que sur les termes DU user authentifié, un client menteur
        # n'obtient rien de plus que ce que /data/privacy (?detailed=1) lui
        # permet déjà légitimement ; (2) la garde mass-delete ci-dessus reste
        # active quel que soit le scope (>1000 ET >50% ⇒ 409 sans
        # confirmation explicite) ; (3) le défaut reste FAIL-CLOSED pour
        # tous les clients qui ne le déclarent pas.
        delete_scope = (
            anon_repo.DELETE_SCOPE_FULL
            if body.get("state_scope") == "full"
            else anon_repo.DELETE_SCOPE_ACTIVE_STATE
        )

        # **Verrou optimiste** (fix lost update 2026-06-10) : le client
        # renvoie la ``revision`` reçue au GET ; si l'état a changé
        # entre-temps (autre onglet, /data/privacy, scan de classeur), le
        # replace-state écraserait silencieusement ces modifications →
        # refus 409 STATE_REVISION_MISMATCH, le client re-fetch. Optionnel
        # (None = legacy last-writer-wins) pour compat clients non migrés.
        expected_revision = body.get("expected_revision")
        if expected_revision is not None and not isinstance(expected_revision, str):
            expected_revision = None
        # Cap défensif (eXamine 2026-06-10) : le jeton réel fait < 60 chars —
        # une string géante ne sert qu'à polluer logs/mémoire. Sur-longueur =
        # jeton forcément invalide → on le garde tel quel serait inutile,
        # on le tronque à une valeur qui mismatch proprement.
        if expected_revision is not None and len(expected_revision) > 128:
            expected_revision = expected_revision[:128]

        # **Write-then-read dans la même session** (fix review 2026-04-23) :
        # deux sessions consécutives ouvraient une fenêtre où un autre PUT
        # ou le cleanup job pouvait s'insérer entre le write et le read.
        # Le client recevait alors un état qui N'EST PAS le résultat de son
        # propre write. Une seule session garantit la cohérence en lecture
        # immédiate après commit.
        try:
            # **Lock per-user AUTOUR de la transaction ENTIÈRE, commit inclus**
            # (eXamine 2026-06-10 BLOQUANT) : le check de révision dans
            # replace_state tourne sous ce lock, mais le COMMIT arrive à la
            # sortie de db_session — s'il était hors lock, un writer
            # concurrent lisait l'ancienne révision (WAL snapshot isolation),
            # matchait son jeton périmé et écrasait quand même : le verrou
            # optimiste était une fausse garantie. En tenant le lock jusqu'au
            # commit, check+write+commit sont atomiques vis-à-vis des autres
            # PUT du même user. L'acquire interne de replace_state est
            # réentrant (ContextVar, cf. locks.py) → no-op ici.
            async with acquire_user_anon_lock(user_id):
                async with self.db_session() as session:
                    stats = await anon_repo.replace_state(
                        session,
                        user_id,
                        state,
                        confirm_mass_delete=confirm_mass_delete,
                        delete_scope=delete_scope,
                        expected_revision=expected_revision,
                    )
                    await session.flush()
                    normalized = await anon_repo.get_state_for_user(session, user_id)
                    # Nouvelle révision post-write : le client l'adopte pour son
                    # prochain PUT (sinon il 409-erait sur sa propre écriture).
                    new_revision = await anon_repo.get_state_revision(session, user_id)
        except anon_repo.StaleStateRefused as exc:
            logger.info(
                "anonymization PUT user=%s: révision périmée (client=%s, bdd=%s) "
                "— réponse 409 STATE_REVISION_MISMATCH.",
                user_id,
                exc.expected,
                exc.current,
            )
            self.write_json(
                {
                    "error": (
                        "Vos termes ont été modifiés entre-temps (autre onglet, "
                        "page Confidentialité ou scan de classeur). Rien n'a été "
                        "enregistré — rechargez la liste puis réappliquez vos "
                        "modifications."
                    ),
                    "error_code": "STATE_REVISION_MISMATCH",
                    "current_revision": exc.current,
                },
                409,
            )
            return
        except anon_repo.MassDeleteRefused as exc:
            logger.warning(
                "anonymization PUT user=%s: mass-delete refusé "
                "(%d/%d termes, %.1f%%) — réponse 409.",
                user_id,
                exc.count_delete,
                exc.count_before,
                exc.ratio * 100,
            )
            self.write_json(
                {
                    "error": (
                        f"Cette action supprimerait {exc.count_delete} "
                        f"termes sur {exc.count_before} en BDD "
                        f"({exc.ratio:.0%}). Si c'est intentionnel, "
                        "renvoyez avec « confirm_mass_delete: true ». "
                        "Sinon, rechargez la page — votre liste affichée "
                        "est probablement incomplète."
                    ),
                    "error_code": "MASS_DELETE_REFUSED",
                    "count_before": exc.count_before,
                    "count_delete": exc.count_delete,
                    "ratio": exc.ratio,
                    "absolute_threshold": exc.absolute_threshold,
                    "ratio_threshold": exc.ratio_threshold,
                },
                409,
            )
            return

        logger.info(
            "anonymization PUT %s: upserted=%d deleted=%d",
            user_id,
            stats.get("upserted", 0),
            stats.get("deleted", 0),
        )
        response_body: dict = {
            "success": True,
            "anonymization_state": normalized,
            "stats": stats,
            # Révision post-write : le client l'adopte pour son prochain
            # ``expected_revision`` (sans ça il 409-erait sur sa propre écriture).
            "revision": new_revision,
        }
        # Inclure ``state_errors`` UNIQUEMENT si la sanitization a strippé
        # des termes — pas de clé vide en response normale. Le frontend
        # check ``Array.isArray(state_errors) && length > 0`` pour décider
        # d'afficher un toast warning. Format inchangé depuis le docstring
        # ligne 281 (``[{type, term?, pseudo?, count?}]``).
        #
        # ``state_errors_truncated_count`` = N restants après cap à 10.
        # Permet au frontend d'afficher "(+N autres tronquées)" pour que
        # l'user sache qu'il y en a plus à corriger (R3 MED 2026-05-20 —
        # avant ce signal, l'user croyait avoir corrigé toutes les erreurs
        # alors qu'il en restait des dizaines invisibles).
        if sanitization_errors:
            response_body["state_errors"] = sanitization_errors
            if sanitization_errors_total > len(sanitization_errors):
                response_body["state_errors_truncated_count"] = sanitization_errors_total - len(
                    sanitization_errors
                )
        self.write_json(response_body)


class AnonymizationAutoClassifyAPIHandler(BaseHandler):
    """Endpoint ``POST /api/anonymization/auto-classify`` — classe **un
    chunk** de tokens via le LLM local.

    **Stateless / chunked** : pour traiter un classeur de taille infinie,
    le frontend envoie les tokens par paquets de ≤200 (cap serveur via
    ``_AUTO_ANON_BATCH_SIZE``). Chaque requête HTTP = 1 chunk.
    Avantages :
    - Progression en temps réel (1 progress update par chunk).
    - Annulation utilisateur instantanée (le frontend stop la boucle).
    - Pas de stateful backend (pas de redis/job queue à maintenir).
    - Robustesse aux déconnexions (chaque chunk est indépendant).

    **Réponses** :
    - 200 + ``{"flagged": [...], "checked": N, "duration_ms": X}``
    - 503 + ``{"error": "local_llm_not_configured"}`` (admin doit config)
    - 200 + ``{"flagged": []}`` si LLM down (le frontend continue, le
      chunk est juste "raté", l'utilisateur peut relancer ou faire manuel)

    **Ce endpoint NE persiste rien** — c'est une suggestion, l'utilisateur
    DISPOSE via le bouton "Enregistrer" qui appelle ``PUT /terms``.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        if len(self.request.body or b"") > _BODY_MAX_BYTES:
            self.set_status(413)
            self.write_json(
                {"error": "Body trop gros (max %d bytes)" % _BODY_MAX_BYTES},
                413,
            )
            return
        user_id = self.current_user.id  # type: ignore[union-attr]

        # Rate-limit (review LOW #5 DoS) : un classeur géant = 250 chunks ;
        # 300/min permet 1 run complet sans hoquet, bloque les boucles
        # malicieuses qui satureraient le LLM local pour les autres.
        if not _auto_classify_rate_limiter.check(
            f"anon-auto:{user_id}",
            _AUTO_CLASSIFY_RATE_MAX,
            _AUTO_CLASSIFY_RATE_WINDOW_S,
        ):
            self.set_status(429)
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide"}, 400)
            return
        tokens_raw = body.get("tokens", [])
        if not isinstance(tokens_raw, list):
            self.write_json(
                {"error": "Champ `tokens` doit être une liste de strings"},
                400,
            )
            return
        # Filter + dédup côté serveur (sécurité : un token n'est jamais
        # plus long que MAX_VALUE_LEN, sinon il a déjà été rejeté côté
        # extract_terms et ne devrait pas atteindre cet endpoint).
        candidate_tokens = {
            str(t)[: anon_terms.MAX_VALUE_LEN]
            for t in tokens_raw
            if isinstance(t, str) and t.strip()
        }
        if not candidate_tokens:
            self.write_json({"flagged": [], "checked": 0, "duration_ms": 0})
            return

        # Vérifier que le LLM local est configuré AVANT de tenter l'appel
        from app.services.ai.llm_providers import (
            ensure_providers_from_db,
            get_llm_manager,
        )

        await ensure_providers_from_db()
        manager = get_llm_manager()
        if manager.get_local_fallback() is None:
            self.set_status(503)
            self.write_json(
                {
                    "error": "local_llm_not_configured",
                    "message": (
                        "Aucun LLM local configuré. Activer dans "
                        "/admin/ai-config → Connexion et modèle → "
                        "« LLM local »."
                    ),
                },
                503,
            )
            return

        from app.services.anonymization.auto_classify import (
            _AUTO_ANON_BATCH_SIZE,
            auto_classify_chunk,
        )
        import time as _time

        # Cap chunk côté serveur (sécurité : le frontend doit respecter
        # mais on ne fait pas confiance aveuglément).
        if len(candidate_tokens) > _AUTO_ANON_BATCH_SIZE:
            logger.warning(
                "auto-classify user=%s : chunk %d > batch_size=%d, troncature",
                user_id,
                len(candidate_tokens),
                _AUTO_ANON_BATCH_SIZE,
            )
            candidate_tokens = set(list(candidate_tokens)[:_AUTO_ANON_BATCH_SIZE])

        start = _time.monotonic()
        result = await auto_classify_chunk(candidate_tokens)
        duration_ms = int((_time.monotonic() - start) * 1000)
        logger.info(
            "anonymization auto-classify user=%s checked=%d flagged=%d status=%s (%.0fms)",
            user_id,
            len(candidate_tokens),
            len(result.flagged),
            result.status,
            duration_ms,
        )
        response_body = {
            "flagged": sorted(result.flagged),
            "checked": len(candidate_tokens),
            "duration_ms": duration_ms,
            "batch_size": _AUTO_ANON_BATCH_SIZE,
            "status": result.status,
        }
        # Propager le message d'erreur pour notification UI (task #10) —
        # le frontend affichera un toast non-bloquant. PAS de 4xx/5xx :
        # auto-classify est best-effort, l'app continue normalement.
        if result.message:
            response_body["error_message"] = result.message
        self.write_json(response_body)


class AnonymizationAutoClassifyProbeAPIHandler(BaseHandler):
    """Endpoint ``POST /api/anonymization/auto-classify/probe`` — calibration.

    Lance UN appel LLM local sur 10 tokens factices et retourne ``duration_ms``.
    Permet au frontend d'estimer le temps total avant de lancer le run :
    ``estimated_total_ms = duration_ms × ceil(N_tokens / batch_size)``.

    Garantit aussi que le modèle est warmed-up dans Ollama (le 1er appel
    après un cold start est ~3-5× plus lent que les suivants).

    **Réponses** :
    - 200 + ``{"duration_ms": X, "batch_size": N}`` — calibration OK.
    - 503 + ``{"error": "local_llm_not_configured"}``.
    - 200 + ``{"duration_ms": null, "error": "..."}`` — LLM configuré mais
      down/timeout. Le frontend peut afficher "LLM local injoignable".
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        # Rate-limit (review LOW #5 DoS) : 6/min suffit pour un usage
        # normal (probe = init du panel). Au-delà : signal de boucle.
        if not _probe_rate_limiter.check(
            f"anon-probe:{user_id}",
            _PROBE_RATE_MAX,
            _PROBE_RATE_WINDOW_S,
        ):
            self.set_status(429)
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        from app.services.ai.llm_providers import (
            ensure_providers_from_db,
            get_llm_manager,
        )

        await ensure_providers_from_db()
        manager = get_llm_manager()
        if manager.get_local_fallback() is None:
            self.set_status(503)
            self.write_json(
                {
                    "error": "local_llm_not_configured",
                    "message": (
                        "Aucun LLM local configuré. Activer dans "
                        "/admin/ai-config → Connexion et modèle → "
                        "« LLM local »."
                    ),
                },
                503,
            )
            return

        from app.services.anonymization.auto_classify import (
            _AUTO_ANON_BATCH_SIZE,
            probe_local_llm,
        )

        duration_ms = await probe_local_llm()
        if duration_ms is None:
            # 503 plutôt que 200+error (review BLOCKING #3) — sémantique
            # HTTP correcte : "service local upstream indisponible".
            # Le frontend gère déjà 503 via le même chemin que
            # local_llm_not_configured.
            self.set_status(503)
            self.write_json(
                {
                    "error": "probe_failed",
                    "message": (
                        "Le LLM local est configuré mais ne répond pas "
                        "correctement (timeout, erreur, ou format de "
                        "réponse non conforme). Vérifier le service "
                        "Ollama et le modèle choisi."
                    ),
                    "batch_size": _AUTO_ANON_BATCH_SIZE,
                },
                503,
            )
            return
        self.write_json(
            {
                "duration_ms": int(duration_ms),
                "batch_size": _AUTO_ANON_BATCH_SIZE,
            }
        )


# ───────────────────────────────────────────────────────────────────────────
# Améliorer l'anonymisation — LLM local enrichit les pseudonymes
# (décision user 2026-05-19, fix #1 contrat V6 "seule limite = arrêt user")
# ───────────────────────────────────────────────────────────────────────────


class AnonymizationImprovePseudoProbeAPIHandler(BaseHandler):
    """Endpoint ``POST /api/anonymization/improve-pseudo/probe`` — calibration.

    Retourne le ``batch_size`` adapté au LLM local configuré et le nom du
    modèle. Le frontend l'utilise pour chunker la liste de termes avant
    d'appeler l'endpoint principal.

    **PAS de rate-limit** : cohérent avec le contrat V6 (« seule limite =
    arrêt user »). Le probe est léger (lecture config + registre, pas
    d'appel LLM lourd).

    **Réponses** :
    - 200 + ``{"batch_size": N, "model_name": "..."}``
    - 503 + ``{"error": "local_llm_not_configured"}``
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        from app.services.ai.llm_providers import (
            ensure_providers_from_db,
            get_llm_manager,
        )

        await ensure_providers_from_db()
        manager = get_llm_manager()
        if manager.get_local_fallback() is None:
            self.set_status(503)
            self.write_json(
                {
                    "error": "local_llm_not_configured",
                    "message": (
                        "Aucun LLM local configuré. Activer dans "
                        "/admin/ai-config → Connexion et modèle → "
                        "« LLM local »."
                    ),
                },
                503,
            )
            return

        from app.services.anonymization.improve_pseudo import (
            compute_dynamic_batch_size_async,
        )

        batch_size, model_name = await compute_dynamic_batch_size_async()
        self.write_json(
            {
                "batch_size": batch_size,
                "model_name": model_name,
            }
        )


class AnonymizationImprovePseudoAPIHandler(BaseHandler):
    """Endpoint ``POST /api/anonymization/improve-pseudo`` — améliore les
    pseudonymes d'un chunk de termes via le LLM local.

    Body : ``{"tokens": ["DUPONT", "jean@example.org", ...]}``

    Flow :

    1. Filtre les termes : ne traite QUE ceux avec ``enabled=true`` ET
       ``pseudo_middle IS NULL`` (préservation des customs user, fix #3
       validé via brainstorm 2026-05-19).
    2. Appelle ``improve_pseudos_chunk`` (LLM local).
    3. Valide chaque label suggéré via ``validate_suggested_label``
       (anti-hallucination LLM, fix #5).
    4. Update ``pseudo_middle = "{label}_{md5[:4]}"`` en BDD pour chaque
       terme amélioré.

    **PAS de rate-limit** : contrat V6 (« seule limite = arrêt user »). Le
    LLM local est local, aucun risque d'abus externe. Le bouton « Arrêter »
    côté frontend abort l'AbortController qui annule les chunks restants —
    c'est l'unique mécanisme de stop.

    **Réponses** :
    - 200 + ``{"updated": [...], "skipped_custom": N, "skipped_disabled": N,
      "skipped_invalid_label": N, "skipped_unknown": N, "status": "ok|...",
      "model_name": "..."}``
    - 503 + ``{"error": "local_llm_not_configured"}``
    - 200 + ``{"status": "timeout|error|not_configured", "updated": []}``
      (best-effort : le frontend peut afficher un toast et continuer).
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        if len(self.request.body or b"") > _BODY_MAX_BYTES:
            self.set_status(413)
            self.write_json(
                {"error": "Body trop gros (max %d bytes)" % _BODY_MAX_BYTES},
                413,
            )
            return
        user_id = self.current_user.id  # type: ignore[union-attr]

        # PAS DE RATE-LIMIT (fix #1 — contrat V6). Le LLM local est local,
        # le bouton Arrêter côté frontend est l'unique stop.

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide"}, 400)
            return
        tokens_raw = body.get("tokens", [])
        if not isinstance(tokens_raw, list):
            self.write_json(
                {"error": "Champ `tokens` doit être une liste de strings"},
                400,
            )
            return
        # Dédup + filtre côté serveur (sécurité). Pas d'overflow MAX_VALUE_LEN
        # car les termes BDD sont déjà bornés au scan.
        candidate_tokens: Set[str] = {
            str(t)[: anon_terms.MAX_VALUE_LEN]
            for t in tokens_raw
            if isinstance(t, str) and t.strip()
        }
        # Fix #20 (review 2026-05-19) — cap dur SUR LE SELECT BDD pour éviter
        # une query monstrueuse (SQLite max compound parameters ≈ 999). Le
        # frontend respecte normalement le batch_size du /probe (≤ 1000), un
        # dépassement signale un bug client. On tronque silencieusement à
        # 2× le hard cap pour rester gracieux, en log warning audit-ready.
        _SERVER_CHUNK_SAFETY_CAP = 2000
        if len(candidate_tokens) > _SERVER_CHUNK_SAFETY_CAP:
            logger.warning(
                "improve-pseudo user=%s chunk=%d > %d — tronqué pour éviter "
                "saturation BDD. Le frontend doit respecter batch_size du probe.",
                user_id,
                len(candidate_tokens),
                _SERVER_CHUNK_SAFETY_CAP,
            )
            candidate_tokens = set(list(candidate_tokens)[:_SERVER_CHUNK_SAFETY_CAP])
        if not candidate_tokens:
            self.write_json(
                {
                    "updated": [],
                    "skipped_custom": 0,
                    "skipped_disabled": 0,
                    "skipped_invalid_label": 0,
                    "skipped_unknown": 0,
                    "status": "ok",
                }
            )
            return

        # Vérifie LLM local AVANT de toucher la BDD.
        from app.services.ai.llm_providers import (
            ensure_providers_from_db,
            get_llm_manager,
        )

        await ensure_providers_from_db()
        manager = get_llm_manager()
        if manager.get_local_fallback() is None:
            self.set_status(503)
            self.write_json(
                {
                    "error": "local_llm_not_configured",
                    "message": (
                        "Aucun LLM local configuré. Activer dans "
                        "/admin/ai-config → Connexion et modèle → "
                        "« LLM local »."
                    ),
                },
                503,
            )
            return

        # Étape 1 — Filtrer côté serveur (2026-05-19, fix David) :
        # éligible si ``enabled=True`` ET (``pseudo_middle IS NULL`` OU
        # format auto-généré ``^[A-Z][A-Z0-9_]*_[a-f0-9]{3,8}$``). Les
        # vrais customs user-saisis (qui ne matchent PAS ce format) sont
        # PRÉSERVÉS. Avant : strict `pseudo_middle IS NULL` → le bouton
        # refusait de s'exécuter dès que l'user avait un seul terme avec
        # un pseudo, ce qui était une fausse limitation (cf. msg user :
        # « le bouton ne doit JAMAIS refuser de s'exécuter »).
        from app.core.database import get_session
        from app.models.anonymization_term import AnonymizationTerm
        from sqlalchemy import select
        import hashlib as _hashlib

        # Format auto-généré : ``^[A-Z][A-Z0-9_]*_([a-f0-9]+)$``. **MAIS**
        # validation forte (review adversariale BLOCKING C, 2026-05-19) :
        # un terme dont le `pseudo_middle` matche structurellement le format
        # n'est éligible à la ré-amélioration QUE SI le suffix hex
        # correspond EXACTEMENT à ``md5(term)[:len(suffix)]``. Sinon
        # c'est un custom user-saisi qui ressemble fortuitement au format
        # (ex: ``CLIENT_abc``, ``KEY_face``, ``MYTERM_def`` — `abc/face/def`
        # sont valides hex mais ne hashent pas vers le term original).
        # Cette validation par hash exact protège contre les faux positifs
        # qui auraient écrasé silencieusement le travail de l'utilisateur.

        def _is_auto_pseudo_format(term: str, value: object) -> bool:
            """``value`` est-il un pseudo AUTO posé par le système pour ce ``term`` ?

            Vrai si et seulement si la chaîne matche ``^[A-Z][A-Z0-9_]*_([a-f0-9]+)$``
            ET que le suffix hex est exactement le préfixe (de la même longueur)
            de ``md5(term).hexdigest()``. Tout autre cas → custom user à préserver.
            """
            if not isinstance(value, str) or not value:
                return False
            m = _AUTO_PSEUDO_FMT_RE.fullmatch(value)
            if m is None:
                return False
            suffix = m.group(1)
            # Sanity guard sur la longueur du suffix (cohérent avec les
            # formats ``md5[:4]`` produits par ``_auto_pseudo_middle`` et
            # ``improve-pseudo`` actuels, mais on tolère 3..8 hex pour
            # compat futures évolutions).
            if not (3 <= len(suffix) <= 8):
                return False
            expected = _hashlib.md5(term.encode("utf-8")).hexdigest()[: len(suffix)]
            return suffix == expected

        # Filtre pré-LLM : un terme purement numérique (1790, 79280.49,
        # 0.514736…) n'a aucune sémantique à améliorer — le label est
        # trivialement AMOUNT/NUMBER. Avant ce filtre (fix logs 2026-05-20),
        # 36s de qwen2.5:3b CPU pour 0 amélioration.
        #
        # Single source of truth : :func:`anonymization.extract.is_numeric_like`
        # encapsule la regex ``_NUMERIC_LIKE_RE`` partagée avec
        # ``extract.is_auto_decidable`` ET le frontend ``tokenizer.js``
        # (constante ``NUMERIC_LIKE_RE``). Pas de regex dupliquée ici —
        # toute évolution de la définition "purement numérique" se fait
        # dans ``extract.py``.
        from app.services.anonymization.extract import is_numeric_like

        skipped_numeric = 0
        non_numeric_candidates: Set[str] = set()
        for tok in candidate_tokens:
            if is_numeric_like(tok):
                skipped_numeric += 1
            else:
                non_numeric_candidates.add(tok)
        candidate_tokens = non_numeric_candidates

        eligible_tokens: Set[str] = set()
        # Pour l'UPDATE atomique en étape 3, on note la valeur courante de
        # ``pseudo_middle`` au moment du SELECT. L'UPDATE WHERE clause
        # exigera l'identité avec cette valeur — un autre client qui
        # modifie le pseudo entre étape 1 et étape 3 ne sera donc PAS
        # écrasé (rowcount=0 → comptabilisé en skipped_custom).
        eligible_current_pseudo: Dict[str, Optional[str]] = {}
        skipped_disabled = 0
        skipped_custom = 0
        skipped_state_changed = 0
        skipped_unknown = 0
        # Pré-charge l'état des termes en BDD pour le user.
        async with get_session() as session:
            rows = (
                await session.scalars(
                    select(AnonymizationTerm).where(
                        AnonymizationTerm.user_id == user_id,
                        AnonymizationTerm.term.in_(list(candidate_tokens)),
                    )
                )
            ).all()
            by_term = {r.term: r for r in rows}

            for token in candidate_tokens:
                row = by_term.get(token)
                if row is None:
                    skipped_unknown += 1
                    continue
                if not row.enabled:
                    skipped_disabled += 1
                    continue
                current = row.pseudo_middle
                # Vide ('') traité comme NULL — le repository normalise déjà
                # (PUT panneau strip empty), mais defense in depth.
                if current == "":
                    current = None
                if current is not None and not _is_auto_pseudo_format(token, current):
                    # Custom user-saisi → préservé (validation hash exacte :
                    # un faux positif comme ``CLIENT_abc`` qui matche le
                    # format structurellement mais dont ``abc`` ≠
                    # ``md5("CLIENT")[:3]`` est rejeté).
                    skipped_custom += 1
                    continue
                eligible_tokens.add(token)
                eligible_current_pseudo[token] = current

        if not eligible_tokens:
            self.write_json(
                {
                    "updated": [],
                    "skipped_custom": skipped_custom,
                    "skipped_disabled": skipped_disabled,
                    "skipped_invalid_label": 0,
                    "skipped_unknown": skipped_unknown,
                    "skipped_numeric": skipped_numeric,
                    "status": "ok",
                }
            )
            return

        # Étape 2 — Appel LLM local sur les termes éligibles.
        from app.services.anonymization.improve_pseudo import improve_pseudos_chunk
        import hashlib
        import time as _time

        start = _time.monotonic()
        result = await improve_pseudos_chunk(eligible_tokens)
        duration_ms = int((_time.monotonic() - start) * 1000)

        if result.status != "ok":
            # Best-effort : on retourne le statut sans 4xx/5xx. Le frontend
            # gère via la taxonomie 4-cas (fix #3).
            logger.info(
                "improve-pseudo user=%s status=%s (%dms) — chunk de %d termes",
                user_id,
                result.status,
                duration_ms,
                len(eligible_tokens),
            )
            self.write_json(
                {
                    "updated": [],
                    "skipped_custom": skipped_custom,
                    "skipped_disabled": skipped_disabled,
                    "skipped_invalid_label": len(result.invalid_labels),
                    "skipped_unknown": skipped_unknown,
                    "skipped_numeric": skipped_numeric,
                    "status": result.status,
                    "message": result.message,
                    "duration_ms": duration_ms,
                }
            )
            return

        # Étape 3 — Update BDD avec les nouveaux pseudo_middle.
        # Format final : ``{LABEL}_{md5[:4]}`` (cohérent avec _auto_pseudo_middle).
        #
        # Fix #4 (review adversariale 2026-05-19) — UPDATE atomique : la clause
        # ``WHERE ... AND pseudo_middle IS NULL`` garantit qu'on n'écrase pas
        # un pseudo personnalisé si un autre client (tab ou requête concurrente
        # PUT /terms) en a saisi un entre l'étape 1 et l'étape 3. SQLAlchemy
        # core ``update().values().where()`` exécute l'UPDATE atomique côté
        # DB — pas de read-modify-write en Python qui perdrait la race.
        from sqlalchemy import or_ as sql_or, update as sql_update

        updated: List[Dict[str, str]] = []
        async with get_session() as session:
            for term, label in result.improved.items():
                h = hashlib.md5(term.encode("utf-8")).hexdigest()[:4]
                new_pseudo_middle = f"{label}_{h}"
                # Defense in depth : la sentinelle ne doit jamais atterrir
                # dans pseudo_middle (validate_suggested_label l'a déjà
                # rejetée mais on garde l'assert pour les évolutions futures).
                if "§" in new_pseudo_middle:
                    logger.warning(
                        "improve-pseudo user=%s — label avec sentinelle "
                        "rejeté en garde-fou: term ignoré",
                        user_id,
                    )
                    continue
                # UPDATE atomique avec garde anti-race : on n'écrase que si
                # ``pseudo_middle`` est resté soit NULL soit la valeur AUTO
                # exacte qu'on a lue en étape 1. Si un autre client (autre
                # tab, autre requête PUT /terms) a saisi un custom entre
                # étape 1 et étape 3, ``rowcount=0`` → comptabilisé en
                # ``skipped_custom`` (préservation correcte).
                #
                # Si le terme avait déjà un ``pseudo_middle`` (auto-format
                # comme ``TXT_4b3a``) et qu'on l'améliore (ex: vers
                # ``NOM_FAMILLE_4b3a``), c'est une ré-amélioration légitime.
                current_at_select = eligible_current_pseudo.get(term)
                if current_at_select is None:
                    pseudo_guard = AnonymizationTerm.pseudo_middle.is_(None)
                else:
                    pseudo_guard = sql_or(
                        AnonymizationTerm.pseudo_middle.is_(None),
                        AnonymizationTerm.pseudo_middle == current_at_select,
                    )
                stmt = (
                    sql_update(AnonymizationTerm)
                    .where(
                        AnonymizationTerm.user_id == user_id,
                        AnonymizationTerm.term == term,
                        AnonymizationTerm.enabled.is_(True),
                        pseudo_guard,
                    )
                    .values(pseudo_middle=new_pseudo_middle)
                )
                result_stmt = await session.execute(stmt)
                if result_stmt.rowcount and result_stmt.rowcount > 0:
                    updated.append(
                        {
                            "term": term,
                            "new_pseudo_middle": new_pseudo_middle,
                        }
                    )
                else:
                    # 0 rows touchées → race condition multi-tab : un autre
                    # client (autre onglet, PUT replace-state concurrent) a
                    # changé le state entre étape 1 (SELECT) et étape 3
                    # (UPDATE). On comptabilise séparément de ``skipped_custom``
                    # qui désigne uniquement les vrais customs user-saisis
                    # préservés (validation hash à l'étape 1).
                    skipped_state_changed += 1
            await session.commit()

        logger.info(
            "improve-pseudo user=%s updated=%d skipped_custom=%d "
            "skipped_state_changed=%d skipped_disabled=%d skipped_invalid=%d "
            "skipped_unknown=%d skipped_numeric=%d (%dms)",
            user_id,
            len(updated),
            skipped_custom,
            skipped_state_changed,
            skipped_disabled,
            len(result.invalid_labels),
            skipped_unknown,
            skipped_numeric,
            duration_ms,
        )
        self.write_json(
            {
                "updated": updated,
                "skipped_custom": skipped_custom,
                "skipped_state_changed": skipped_state_changed,
                "skipped_disabled": skipped_disabled,
                "skipped_invalid_label": len(result.invalid_labels),
                "skipped_unknown": skipped_unknown,
                "skipped_numeric": skipped_numeric,
                # #97/D6-F2 — termes non traités (budget LLM épuisé) : remontés
                # pour que le frontend cesse d'afficher « Terminé » à tort et
                # invite l'user à relancer (anti données-fausses silencieuses).
                "skipped_unprocessed": len(result.unprocessed),
                # Propage le VRAI statut du chunk (ok/timeout/error/not_configured)
                # au lieu d'un « ok » en dur : le frontend en a besoin pour afficher
                # la vraie cause des termes non traités (timeout vs rejet
                # anti-hallucination) — cf. improve-pseudos.js. Avant ce fix, le
                # frontend affichait « budget du modèle local atteint » dans tous
                # les cas, ce qui était trompeur (le statut réel était écrasé).
                "status": result.status,
                "duration_ms": duration_ms,
            }
        )


# ───────────────────────────────────────────────────────────────────────────
# Handlers étendus (tâche #10) — DELETE / coverage / audit / export / wipe /
# stats / regex fallback / scan SSE.
# ───────────────────────────────────────────────────────────────────────────


class AnonymizationTermDeleteAPIHandler(BaseHandler):
    """``DELETE /api/anonymization/terms/(\\d+)`` — supprime UN terme + audit.

    Sémantique : suppression définitive d'une row de
    ``anonymization_terms`` après vérification d'ownership user. Une row
    audit ``triggered_by="user_panel", action="delete"`` est insérée AVANT
    le DELETE pour préserver la traçabilité.

    Réponses :

    * ``200 + {"success": true, "deleted": {"id", "term", "audited"}}``
    * ``404`` — terme inexistant ou appartenant à un autre user (volontaire :
      ne pas distinguer pour ne pas leak l'existence).
    * ``429`` — rate limit dépassé.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def delete(self, term_id: str) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _delete_term_rate_limiter,
            f"anon-del:{user_id}",
            _DELETE_TERM_RATE_MAX,
            _DELETE_TERM_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return
        try:
            tid = int(term_id)
        except (TypeError, ValueError):
            self.write_json({"error": "term_id invalide."}, 400)
            return
        if tid <= 0:
            self.write_json({"error": "term_id invalide."}, 400)
            return

        async with self.db_session() as session:
            result = await anon_api.delete_term_for_user(
                session,
                user_id=user_id,
                term_id=tid,
                triggered_by_user_id=user_id,
                reason="user-driven delete via API",
            )

        if result is None:
            self.write_json({"error": "Terme introuvable."}, 404)
            return

        logger.info(
            "anon DELETE term user=%s id=%s audited=%s",
            user_id,
            tid,
            result.get("audited"),
        )
        self.write_json({"success": True, "deleted": result})


class AnonymizationTermCoverageAPIHandler(BaseHandler):
    """``GET /api/anonymization/terms/(\\d+)/coverage`` — où apparaît ce terme.

    Scanne le datastore du user (cap ``SCAN_MAX_FILES``) et retourne :

    * la liste des classeurs où le terme apparaît
    * le total d'occurrences (groupé par classeur)
    * les 10 dernières actions audit pour ce terme

    Coûteux (lecture disque). Rate-limit 20/min.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def get(self, term_id: str) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _coverage_rate_limiter,
            f"anon-cov:{user_id}",
            _COVERAGE_RATE_MAX,
            _COVERAGE_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return
        try:
            tid = int(term_id)
        except (TypeError, ValueError):
            self.write_json({"error": "term_id invalide."}, 400)
            return
        if tid <= 0:
            self.write_json({"error": "term_id invalide."}, 400)
            return

        async with self.db_session() as session:
            result = await anon_api.coverage_for_term(session, user_id=user_id, term_id=tid)

        if result is None:
            self.write_json({"error": "Terme introuvable."}, 404)
            return

        _set_no_store_headers(self)
        self.write_json(result)


class AnonymizationAuditAPIHandler(BaseHandler):
    """``GET /api/anonymization/audit`` — historique paginé des actions du user.

    Query params :

    * ``page`` (default 1, clamp [1, 10000])
    * ``per_page`` (default 25, clamp [1, 100])
    * ``action`` ∈ {insert, update, delete} (filtre)
    * ``triggered_by`` ∈ {user_panel, copilot, auto_classifier, system_cleanup,
      system_migration, proxy} (filtre)
    * ``term_contains`` — substring case-insensitive (ILIKE)
    * ``since`` / ``until`` — ISO datetime range
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def get(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _audit_rate_limiter,
            f"anon-audit:{user_id}",
            _AUDIT_RATE_MAX,
            _AUDIT_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        try:
            page_raw = self.get_argument("page", "1")
            per_page_raw = self.get_argument("per_page", str(anon_api.AUDIT_PER_PAGE_DEFAULT))
            page = int(page_raw) if page_raw else 1
            per_page = int(per_page_raw) if per_page_raw else anon_api.AUDIT_PER_PAGE_DEFAULT
        except (TypeError, ValueError):
            self.write_json({"error": "page / per_page invalides."}, 400)
            return

        action = self.get_argument("action", "").strip() or None
        if action and action not in anon_api.AUDIT_ACTION_VALUES:
            self.write_json(
                {
                    "error": "action filter invalide",
                    "allowed": sorted(anon_api.AUDIT_ACTION_VALUES),
                },
                400,
            )
            return

        triggered_by = self.get_argument("triggered_by", "").strip() or None
        if triggered_by and triggered_by not in anon_audit_module.TRIGGERED_BY_VALUES:
            self.write_json(
                {
                    "error": "triggered_by filter invalide",
                    "allowed": sorted(anon_audit_module.TRIGGERED_BY_VALUES),
                },
                400,
            )
            return

        term_contains = self.get_argument("term_contains", "").strip() or None
        if term_contains and len(term_contains) > 200:
            self.write_json({"error": "term_contains trop long (max 200 chars)."}, 400)
            return
        since = _parse_iso_datetime(self.get_argument("since", None))
        until = _parse_iso_datetime(self.get_argument("until", None))

        async with self.db_session() as session:
            payload = await anon_api.list_audit(
                session,
                user_id=user_id,
                page=page,
                per_page=per_page,
                action_filter=action,
                triggered_by_filter=triggered_by,
                term_contains=term_contains,
                since=since,
                until=until,
            )

        _set_no_store_headers(self)
        self.write_json(payload)


class AnonymizationExportAPIHandler(BaseHandler):
    """``GET /api/anonymization/export`` — (droit d'accès).

    Retourne un JSON downloadable contenant TOUS les termes du user, son
    audit complet, et les stats. ``Content-Disposition: attachment`` avec
    nom de fichier daté.

    Rate-limit strict : 5 / 5min. L'utilisateur n'a pas besoin d'exporter
    en boucle.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def get(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _export_rate_limiter,
            f"anon-export:{user_id}",
            _EXPORT_RATE_MAX,
            _EXPORT_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        # Critical #37 review : atomicité audit-export données garantie via
        # 2 sessions séparées. La précédente version mettait audit+export
        # dans la même session — si le SELECT export crashait avec une
        # SQLAlchemyError, le rollback annulait l'audit, contredisant la
        # promesse "tout export données est tracé". Désormais l'audit est
        # commit indépendamment AVANT l'export, donc même si l'export
        # échoue ensuite, la trace persiste.
        async with self.db_session() as audit_session:
            await anon_audit_module.log_audit_action(
                audit_session,
                user_id=user_id,
                term="<export>",
                action="update",
                triggered_by="user_panel",
                triggered_by_user_id=user_id,
                reason="user_data_export",
            )
            # Le context manager db_session commit en sortie. L'audit
            # est désormais persisté en BDD, indépendamment de ce qui
            # se passe ensuite côté export.

        async with self.db_session() as export_session:
            payload = await anon_api.export_user_data(export_session, user_id=user_id)

        ts = clock.now().strftime("%Y%m%dT%H%M%SZ")
        filename = f"anonymization-export-user{user_id}-{ts}.json"
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.set_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.set_header("X-Content-Type-Options", "nosniff")
        # Anti-cache disque : l'export données contient des PII en clair, on ne
        # veut pas qu'un poste partage cache le download.
        self.set_header("Cache-Control", "no-store, max-age=0, private")
        self.set_header("Pragma", "no-cache")
        # Pas de write_json (qui setterait Content-Type=application/json sans
        # charset précis). On veut le download propre.
        self.write(json.dumps(payload, ensure_ascii=False, default=str, indent=2))

        logger.info(
            "anon EXPORT user=%s terms=%d audit=%d",
            user_id,
            len(payload.get("terms", [])),
            len(payload.get("audit", [])),
        )


class AnonymizationWipeAPIHandler(BaseHandler):
    """``POST /api/anonymization/wipe`` — (droit à l'effacement).

    Body attendu (DOUBLE confirmation) ::

        {
          "confirmation_phrase": "DELETE ALL MY ANONYMIZATION DATA",
          "expected_count": <int>
        }

    Le user copie la phrase exacte (anti-typo, anti-CSRF — un attaquant
    n'a pas la phrase exacte). ``expected_count`` est le nombre de termes
    actuellement dans la BDD ; un mismatch (état modifié entre /stats et
    /wipe) → 409 Conflict (refus du wipe). L'utilisateur doit re-confirmer
    après refresh.

    Une seule row d'audit ``term="<wipe>"`` est conservée pour traçabilité
    légale ; tout le reste de l'audit du user est purgé.

    Rate-limit dur : 3 / heure.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]

        if not _check_rate(
            _wipe_rate_limiter,
            f"anon-wipe:{user_id}",
            _WIPE_RATE_MAX,
            _WIPE_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        # Pré-check Content-Length (cf. PUT).
        cl_raw = self.request.headers.get("Content-Length")
        if cl_raw:
            try:
                if int(cl_raw) > _BODY_MAX_BYTES:
                    self.write_json({"error": "Body trop volumineux."}, 413)
                    return
            except ValueError:
                pass

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide."}, 400)
            return
        if not isinstance(body, dict):
            self.write_json({"error": "JSON doit être un objet."}, 400)
            return

        phrase = body.get("confirmation_phrase")
        if phrase != anon_api.WIPE_CONFIRMATION_PHRASE:
            # BLOCKING #9 review : NE PAS retourner ``expected_phrase`` dans
            # la réponse — un attaquant CSRF pourrait la lire dans la 400 et
            # la soumettre. La phrase est dans le template HTML côté client
            # (constante côté frontend), pas via API.
            self.write_json(
                {"error": "Phrase de confirmation incorrecte."},
                400,
            )
            return
        expected_count = body.get("expected_count")
        # FIX review H6 : `bool` est instance de `int` en Python (True == 1).
        # Refuser explicitement bool pour empêcher un bypass de la double-confirmation
        # via {"expected_count": true} qui serait accepté pour un user à 1 terme.
        if (
            isinstance(expected_count, bool)
            or not isinstance(expected_count, int)
            or expected_count < 0
        ):
            self.write_json({"error": "expected_count manquant ou invalide (entier ≥ 0)."}, 400)
            return

        # Vérification du count avant action (sérialisé par session BDD).
        async with self.db_session() as session:
            current_count = await anon_repo.count_terms_for_user(session, user_id)
            if current_count != expected_count:
                self.write_json(
                    {
                        "error": "État modifié — le nombre de termes a changé. "
                        "Rechargez la page et reconfirmez.",
                        "actual_count": current_count,
                        "expected_count": expected_count,
                    },
                    409,
                )
                return

            result = await anon_api.wipe_user_data(
                session,
                user_id=user_id,
                triggered_by_user_id=user_id,
                reason="wipe via /api/anonymization/wipe",
            )

        logger.warning(
            "anon WIPE user=%s deleted_terms=%d deleted_audit=%d wipe_audit_id=%s",
            user_id,
            result.get("deleted_terms", 0),
            result.get("deleted_audit", 0),
            result.get("wipe_audit_id"),
        )
        self.write_json({"success": True, **result})


class AnonymizationStatsAPIHandler(BaseHandler):
    """``GET /api/anonymization/stats`` — agrégats pour badge global / page.

    Léger (1 SELECT). Rate-limit 60/min — UI peut refresh fréquemment.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def get(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _stats_rate_limiter,
            f"anon-stats:{user_id}",
            _STATS_RATE_MAX,
            _STATS_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        async with self.db_session() as session:
            stats = await anon_api.stats_for_user(session, user_id=user_id)
        _set_no_store_headers(self)
        self.write_json({"stats": stats})


class AnonymizationScanWorkbookAPIHandler(BaseHandler):
    """``POST /api/anonymization/scan-workbook`` — scan live du state d'un
    classeur côté frontend, alimente ``anonymization_terms`` en temps réel.

    Appelé par ``static/js/iris-grid.js`` à chaque changement de workbook
    (debounce 2-3s côté client). Couvre ~80% des cas de "changement de
    classeur" : edit cellule, paste, add tab, import xlsx/csv en preview
    avant save, etc. — sans avoir à hooker N endpoints serveur.

    **Auto-catégorisation PII** : appliquée par ``upsert_terms`` (commit
    00ab3c8 #11) — emails, SIRET+Luhn, IBAN+MOD-97, phone FR, amount €
    sont auto-catégorisés et auto-enabled à l'INSERT initial. Les autres
    tokens (noms, codes métier) sont insérés ``enabled=False`` — l'user
    décide via ``/data/privacy``.

    **Body** : ``{"tabs_context": [...], "sheet_content": [...]}`` (shape
    ``extract_terms``). Both optionnels (None = pas de scan sur ce
    champ — au moins un des deux requis pour faire qqch).

    **Réponse** : ``{"scanned": N, "added": M}`` — ``N`` tokens uniques
    extraits, ``M`` rows nouvellement insérées (rows existantes préservées
    et non comptées dans ``added``).

    **Rate-limit** : 60/min — un user qui modifie son workbook rapidement
    peut envoyer 1-2 POST/s en pointe (debounce 2s minimum).
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]

        if len(self.request.body or b"") > _BODY_MAX_BYTES:
            self.write_json({"error": "Body trop volumineux."}, 413)
            return

        if not _check_rate(
            _scan_workbook_rate_limiter,
            f"anon-scan-wb:{user_id}",
            _SCAN_WORKBOOK_RATE_MAX,
            _SCAN_WORKBOOK_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide."}, 400)
            return
        if not isinstance(body, dict):
            self.write_json({"error": "JSON doit être un objet."}, 400)
            return

        tabs_context = body.get("tabs_context")
        sheet_content = body.get("sheet_content")
        # Validation laxiste : les types attendus sont des lists. Si l'user
        # envoie autre chose, on traite comme None — pas de crash, juste
        # un no-op de scan.
        if not isinstance(tabs_context, list):
            tabs_context = None
        if not isinstance(sheet_content, list):
            sheet_content = None
        # classeur_ref : nom du classeur (sans path) si le workbook est
        # déjà nommé (workbook chargé depuis /datastore). Utilisé pour le
        # groupement par classeur dans /data/privacy (task #15). Cap +
        # validation côté service.
        classeur_ref = body.get("classeur_ref")
        if not isinstance(classeur_ref, str):
            classeur_ref = None

        # scan_context (optionnel, 2026-05-19) : indique d'où vient le scan
        # pour différencier la source dans ``anonymization_terms`` :
        #   - ``"datastore"`` ou absent → source="workbook" (comportement
        #     historique préservé pour les classeurs ouverts dans iris-grid)
        #   - ``"iris"`` → source="sql_result", source_ref="iris:<context_id>"
        #     (résultats SQL d'Iris affichés à l'user dans la page /iris)
        #   - ``"automation_preview"`` → source="sql_result",
        #     source_ref="automation:<context_id>" (preview /automations/N/edit)
        #
        # **Fail-closed sur valeur inconnue** : un client qui envoie un
        # ``scan_context`` hors whitelist (typo, futur context non câblé,
        # tentative d'injection arbitraire) retombe sur le default
        # "workbook". Garantit que la CHECK constraint BDD
        # ``ck_anon_term_source`` ne crash JAMAIS le scan.
        scan_context_raw = body.get("scan_context")
        context_id_raw = body.get("context_id")
        source: str = "workbook"
        # source_ref par défaut = classeur_ref (comportement historique).
        # Override possible si scan_context iris/automation.
        _VALID_SCAN_CTXS = ("iris", "automation_preview", "datastore")
        scan_context: Optional[str] = None
        if isinstance(scan_context_raw, str):
            scan_context = scan_context_raw.strip()
            # Fallback LOGUÉ (review adversariale CRITICAL #5 — 2026-05-19) :
            # un client qui envoie une valeur non whitelist sera diagnosticable
            # via les logs plutôt que de voir ses scans arriver silencieusement
            # comme source="workbook" (= bug masqué jusqu'au prochain audit).
            if scan_context and scan_context not in _VALID_SCAN_CTXS:
                logger.warning(
                    "anonymization scan-workbook user=%s: scan_context invalide "
                    "%r — fallback workbook. Bug client (typo / divergence) ?",
                    user_id,
                    scan_context_raw,
                )
                scan_context = None

        if scan_context in ("iris", "automation_preview"):
            # Sanitize context_id : str-able, cap longueur, alphanum + tiret
            # + ``_`` UNIQUEMENT (review adversariale BLOCKING #1 — 2026-05-19).
            # Le ``:`` est INTERDIT côté input : il est RÉSERVÉ au préfixe que
            # le SERVEUR pose lui-même (``iris:`` / ``automation:``). Sinon un
            # attaquant qui envoie ``context_id="42:fake"`` produirait
            # ``source_ref="iris:42:fake"`` que privacy-page.js parserait avec
            # un label trompeur — vecteur de spoofing UX.
            context_id_str: Optional[str] = None
            if context_id_raw is not None:
                context_id_str = str(context_id_raw).strip()
                # Cap conservateur 100 chars (la colonne source_ref tolère
                # 200, marge pour le préfixe ``iris:`` etc.).
                context_id_str = context_id_str[:100]
                import re as _re

                if not _re.fullmatch(r"[A-Za-z0-9_\-]+", context_id_str):
                    logger.warning(
                        "anonymization scan-workbook user=%s: context_id invalide "
                        "%r (whitelist [A-Za-z0-9_-]+ violée, attention au ``:``) "
                        "— fallback sans id.",
                        user_id,
                        context_id_raw,
                    )
                    context_id_str = None

            if scan_context == "iris":
                source = "sql_result"
                # ``source_ref`` prend la précédence sur ``classeur_ref``
                # quand on est sur /iris (le user n'a pas de classeur
                # ouvert, classeur_ref est de toute façon None côté
                # frontend dans ce cas).
                classeur_ref = f"iris:{context_id_str}" if context_id_str else "iris"
            else:  # "automation_preview"
                source = "sql_result"
                classeur_ref = f"automation:{context_id_str}" if context_id_str else "automation"

        # Retry sur ``database is locked`` : ``upsert_terms`` est idempotent
        # (ON CONFLICT DO UPDATE sur la contrainte unique ``(user_id, term)``)
        # donc safe à rejouer. La session est re-créée FRESH à chaque
        # tentative (cf. ``db_session`` context manager) — un retry sur la
        # même session ne marcherait pas car SQLAlchemy laisse la
        # transaction en état "rollback only" après ``OperationalError``.
        #
        # ``max_attempts=5`` : couvre des verrous tenus jusqu'à
        # ~base_delay × (2^4) × jitter = ~3.2 s en cumulé, ce qui est
        # confortable pour les contentions transitoires du WAL (sync
        # programmatique, checkpoint, autre upsert). Au-delà, l'utilisateur
        # voit une 500 — c'est le signal que la cause racine est ailleurs.
        async def _do_scan() -> dict:
            async with self.db_session() as session:
                return await anon_api.scan_workbook_terms(
                    session,
                    user_id=user_id,
                    tabs_context=tabs_context,
                    sheet_content=sheet_content,
                    classeur_ref=classeur_ref,
                    source=source,
                )

        result = await retry_on_locked(
            _do_scan,
            max_attempts=5,
            base_delay_s=0.2,
            max_delay_s=2.0,
            operation_name=f"anonymization scan-workbook user={user_id}",
        )

        logger.debug(
            "anonymization scan-workbook user=%s scanned=%d added=%d",
            user_id,
            result["scanned"],
            result["added"],
        )
        self.write_json(result)


class AnonymizationAutoClassifyRegexAPIHandler(BaseHandler):
    """``POST /api/anonymization/auto-classify/regex`` — fallback sans LLM local.

    Reçoit ``{"tokens": [...]}`` (≤ ``_AUTO_ANON_BATCH_SIZE`` tokens) et
    retourne les tokens identifiés par les regex PII built-in (EMAIL,
    PHONE, AMOUNT, SIRET, SIREN, IBAN). Pas d'appel LLM, pas de dépendance
    Ollama. Toujours disponible.

    Stateless : ne persiste rien — c'est une suggestion, l'utilisateur
    DISPOSE via ``PUT /terms``.

    Réponse ``{"flagged": [...], "by_type": {...}, "checked": N}``.
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]

        if len(self.request.body or b"") > _BODY_MAX_BYTES:
            self.write_json({"error": "Body trop volumineux."}, 413)
            return

        # Réutilise le rate-limit auto-classify (même usage : un user fait
        # 1 run d'analyse cohérent).
        if not _check_rate(
            _auto_classify_rate_limiter,
            f"anon-auto-regex:{user_id}",
            _AUTO_CLASSIFY_RATE_MAX,
            _AUTO_CLASSIFY_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide."}, 400)
            return
        tokens_raw = body.get("tokens", []) if isinstance(body, dict) else []
        if not isinstance(tokens_raw, list):
            self.write_json({"error": "Champ `tokens` doit être une liste de strings."}, 400)
            return

        # Cap côté serveur (sécurité regex catastrophique).
        from app.services.anonymization.auto_classify import _AUTO_ANON_BATCH_SIZE

        tokens_clean = [t for t in tokens_raw if isinstance(t, str)]
        if len(tokens_clean) > _AUTO_ANON_BATCH_SIZE:
            tokens_clean = tokens_clean[:_AUTO_ANON_BATCH_SIZE]

        result = anon_api.classify_with_regex(tokens_clean)
        result["batch_size"] = _AUTO_ANON_BATCH_SIZE
        result["mode"] = "regex"
        self.write_json(result)


class AnonymizationScanAPIHandler(BaseHandler):
    """``POST /api/anonymization/scan`` — SSE streaming du scan datastore.

    Itère le datastore du user, extrait les tokens via
    ``extract_terms`` cross-classeurs et yield des événements SSE.

    Événements :

    * ``data: {"step":"start","total_files":N}``
    * ``data: {"step":"file","filename":...,"processed":k,"total":N,``
      ``"new_tokens_count":K,"tokens_so_far":T}``
    * ``data: {"step":"complete","tokens_found":[...],"stats":{...},``
      ``"truncated":bool}``

    Heartbeat (``: heartbeat\\n\\n``) toutes les 15s pour garder la
    connexion idle ouverte côté proxy. ``on_connection_close`` arrête
    l'itération si le client déconnecte.

    Rate-limit dur : 3 / 5min.
    """

    def initialize(self) -> None:  # type: ignore[override]
        self._connection_closed = False
        self._cancel_event: Optional[asyncio.Event] = None

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]
        if not _check_rate(
            _scan_rate_limiter,
            f"anon-scan:{user_id}",
            _SCAN_RATE_MAX,
            _SCAN_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        self._cancel_event = asyncio.Event()
        self._configure_sse_headers()
        await self._safe_sse_write("retry: 5000\n\n")

        heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        try:
            async for event in anon_api.scan_datastore_tokens(user_id=user_id):
                if self._connection_closed:
                    break
                payload = json.dumps(event, ensure_ascii=False, default=str)
                await self._safe_sse_write(f"data: {payload}\n\n")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — on ne veut PAS crash le worker
            logger.exception("anon scan SSE: erreur user=%s", user_id)
            await self._safe_sse_write('data: {"step":"error","error":"internal"}\n\n')
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    def _configure_sse_headers(self) -> None:
        self.set_header("Content-Type", "text/event-stream; charset=UTF-8")
        self.set_header("Cache-Control", "no-cache")
        self.set_header("Connection", "keep-alive")
        # Désactive le buffering nginx (cf. ai_config.py).
        self.set_header("X-Accel-Buffering", "no")

    async def _heartbeat_loop(self) -> None:
        try:
            while not self._connection_closed:
                await asyncio.sleep(_SSE_HEARTBEAT_S)
                if self._connection_closed:
                    return
                await self._safe_sse_write(": heartbeat\n\n")
        except asyncio.CancelledError:
            raise

    async def _safe_sse_write(self, data: str) -> None:
        if self._connection_closed:
            return
        try:
            self.write(data)
            await self.flush()
        except StreamClosedError:
            self._connection_closed = True
            if self._cancel_event is not None:
                self._cancel_event.set()
        except Exception:  # noqa: BLE001
            logger.debug("anon scan SSE write inattendu", exc_info=True)
            self._connection_closed = True
            if self._cancel_event is not None:
                self._cancel_event.set()

    def on_connection_close(self) -> None:
        self._connection_closed = True
        if self._cancel_event is not None:
            self._cancel_event.set()


class AnonymizationAddManualAPIHandler(BaseHandler):
    """``POST /api/anonymization/terms/manual`` — ajout volontaire d'un
    terme à anonymiser depuis la page ``/data/privacy``.

    Body : ``{"value": "<chaîne saisie par l'utilisateur>"}``

    Comportement :

    - Si la valeur strippée matche un pattern PII (email, SIRET+Luhn,
      IBAN+MOD-97, téléphone FR, montant €) via
      :func:`anon_patterns.detect_pii_category`, on insère **un seul
      terme** = la valeur strippée, avec catégorie PII auto-détectée.
      Évite le fragmentage par le tokenizer (un email scindé sur ``@``
      perdrait sa sémantique).
    - Sinon on applique :func:`anon_extract._tokenize_value` : la valeur
      est splittée comme une cellule de classeur. Chaque token est
      inséré individuellement. L'user qui saisit ``"DUPONT Marie"``
      obtient 2 termes (``"DUPONT"`` + ``"Marie"``).

    Tous les termes insérés ont ``source="user_added"``, ``enabled=True``,
    ``confirmed=True`` — c'est un acte explicite de l'user, pas du pending
    à reviewer. Le cleanup nightly ne les purgera jamais
    (cf. ``cleanup_job._delete_missing_for_user`` skip ``user_added``).

    Réponses :

    - ``200 {added: N, terms: [...], message: "..."}``
    - ``400 {error: "Body invalide"}``
    - ``400 {error: "Valeur vide"}``
    - ``400 {error: "Valeur trop longue (max %d chars)"}``
    - ``400 {error: "Aucun terme exploitable"}`` (tokenization → 0 token)
    - ``413 BODY_TOO_LARGE``
    - ``429`` rate-limit
    """

    @authenticated
    @require_role(*_ALLOWED_ROLES)
    async def post(self) -> None:
        user_id = self.current_user.id  # type: ignore[union-attr]

        if not _check_rate(
            _add_manual_rate_limiter,
            f"anon-add-manual:{user_id}",
            _ADD_MANUAL_RATE_MAX,
            _ADD_MANUAL_RATE_WINDOW_S,
        ):
            self.write_json({"error": "Trop de requêtes, patientez."}, 429)
            return

        if len(self.request.body or b"") > _BODY_MAX_BYTES:
            self.write_json({"error": "Body trop volumineux."}, 413)
            return

        try:
            body = json.loads(self.request.body or b"{}")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            self.write_json({"error": "JSON invalide."}, 400)
            return
        if not isinstance(body, dict):
            self.write_json({"error": "JSON doit être un objet."}, 400)
            return

        value = body.get("value")
        if not isinstance(value, str):
            self.write_json({"error": "Champ `value` manquant ou non-string."}, 400)
            return

        stripped = value.strip()
        if not stripped:
            self.write_json({"error": "Valeur vide."}, 400)
            return

        # Cap aligné sur MAX_VALUE_LEN du tokenizer pour rester cohérent
        # avec le tokenizer auto (un terme > MAX_VALUE_LEN serait skip
        # silencieusement par _tokenize_value, ce qui produirait 0 ajout
        # côté backend mais un POST 200 trompeur).
        if len(stripped) > anon_terms.MAX_VALUE_LEN:
            self.write_json(
                {"error": (f"Valeur trop longue (max {anon_terms.MAX_VALUE_LEN} caractères).")},
                400,
            )
            return

        # Détection PII en amont : si la valeur ENTIÈRE matche un pattern
        # PII (email/SIRET/IBAN/phone/montant), on l'insère telle quelle.
        # Sinon on passe par le tokenizer pour splitter sur les délimiteurs.
        from app.models.anonymization_term import ANONYMIZATION_SOURCES_BY_NAME
        from app.services.anonymization import patterns as anon_patterns

        pii_category = anon_patterns.detect_pii_category(stripped)
        if pii_category is not None:
            tokens_to_insert: list[str] = [stripped]
        else:
            raw_tokens = anon_terms._tokenize_value(stripped)
            # Dédup intra-input (case-insensitive) tout en gardant l'ordre
            # de première apparition pour stabilité du log.
            seen_canonical: set[str] = set()
            tokens_to_insert = []
            for tok in raw_tokens:
                canonical = anon_repo._canonical_key(tok)
                if canonical not in seen_canonical:
                    seen_canonical.add(canonical)
                    tokens_to_insert.append(tok)

        if not tokens_to_insert:
            self.write_json(
                {
                    "error": (
                        "Aucun terme exploitable. La valeur a été filtrée "
                        "par le tokenizer (binaire, GUID, longueur < 2 caractères, "
                        "ou délimitée par espaces/virgules/points-virgules sans "
                        "extraction utile)."
                    )
                },
                400,
            )
            return

        # Cap dur du nombre de tokens insérés par requête (cf. review
        # adversariale 2026-05-19 finding #2 — DoS via paste géant qui
        # ferait 100+ INSERTs via une seule requête, multiplié par le
        # rate-limit 10/min = 1000 INSERTs/min épuisant RAM via le
        # SELECT all-terms du upsert. Cap humain raisonnable : 20.
        if len(tokens_to_insert) > _ADD_MANUAL_MAX_TOKENS_PER_REQ:
            self.write_json(
                {
                    "error": (
                        f"Trop de termes extraits ({len(tokens_to_insert)} > "
                        f"{_ADD_MANUAL_MAX_TOKENS_PER_REQ}). Saisissez les "
                        f"termes un à un, ou par petits groupes."
                    )
                },
                400,
            )
            return

        # Construction du dict terms attendu par upsert_terms.
        # enabled=True, confirmed=True : l'user a fait un choix explicite,
        # pas de pending review.
        terms_payload = {t: {"enabled": True, "confirmed": True} for t in tokens_to_insert}

        # Le ``db_session()`` context manager commit en sortie (cf.
        # ``base.py:748``). Pas de ``session.commit()`` explicite ici
        # — aligne sur le pattern des autres handlers du fichier (PUT
        # ligne 323, DELETE ligne 611, etc.). Cf. review adversariale
        # 2026-05-19 finding #3.
        async with self.db_session() as session:
            await anon_repo.upsert_terms(
                session,
                user_id,
                terms_payload,
                source=ANONYMIZATION_SOURCES_BY_NAME["user_added"],
                source_ref=None,
            )

        logger.info(
            "anonymization add-manual user=%s tokens=%d pii=%s",
            user_id,
            len(tokens_to_insert),
            pii_category or "no",
        )

        _set_no_store_headers(self)
        self.write_json(
            {
                "added": len(tokens_to_insert),
                "terms": tokens_to_insert,
                "pii_category": pii_category,
                "message": (
                    f"{len(tokens_to_insert)} terme(s) ajouté(s)."
                    if len(tokens_to_insert) > 1 or pii_category
                    else "1 terme ajouté."
                ),
            }
        )
