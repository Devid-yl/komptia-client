"""Service métier pour l'API étendue ``/api/anonymization/*``.

Ce module factorise toute la logique métier des endpoints :

* :func:`delete_term_for_user` — suppression unitaire avec audit.
* :func:`coverage_for_term` — où apparaît un terme (cross-classeurs + audit).
* :func:`list_audit` — liste paginée de l'audit du user.
* :func:`export_user_data` — bundle JSON utilisateur.
* :func:`wipe_user_data` — utilisateur, suppression totale terms + audit.
* :func:`stats_for_user` — agrégats (badge global + filtres).
* :func:`classify_with_regex` — fallback sans LLM, regex PII built-in.
* :func:`scan_datastore_tokens` — itère le datastore user en streaming.

**Règles transverses** :

- Toutes les fonctions prennent une session async explicite (sauf la
  variante synchrone-pure :func:`classify_with_regex` et
  :func:`scan_datastore_tokens` qui scanne le disque).
- **Ownership 404, pas 403** — un terme appartenant à un autre user
  retourne ``None`` (le handler renvoie 404). Ne pas révéler l'existence.
- **Audit fail-soft** — un échec d'insert audit log un WARNING mais ne
  bloque pas l'action métier (cohérent avec :mod:`audit`).
- **Pas de hardcode BDD source** — le scan utilise
  ``classeur.reader.list_classeurs_sync`` qui parse n'importe quel
  ``.afz.json`` (générique).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Final, List, Optional, Set, Tuple

from sqlalchemy import and_, case, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import clock
from app.models.anonymization_audit import AnonymizationAudit
from app.models.anonymization_term import AnonymizationTerm
from app.services.anonymization import audit as anon_audit
from app.services.anonymization import extract as anon_extract
from app.services.anonymization import patterns as anon_patterns
from app.services.anonymization.user_id_guard import is_valid_user_id

logger = logging.getLogger(__name__)


# ─── Limites ───────────────────────────────────────────────────────────────

#: Cap nombre de fichiers scannés en un seul run /scan. Au-delà : DoS disque.
#: 5000 = un datastore très garni reste scannable, au-delà l'utilisateur a
#: probablement un problème de housekeeping.
SCAN_MAX_FILES: Final[int] = 5000

# Pas de cap arbitraire sur le nombre de tokens uniques retournés par le
# scan : la seule limite légitime est le quota disque user (``UserStorage.
# quota_limit``) qui borne implicitement la taille du datastore source.
# Un cap output statique tronquait la vérité user sans bénéfice concret
# (le ``Set[str]`` en mémoire serveur reste trivialement borné par la
# taille des classeurs scannés). Cf. décision 2026-05-19.

#: Pagination audit — bornes communes
AUDIT_PER_PAGE_DEFAULT: Final[int] = 25
AUDIT_PER_PAGE_MIN: Final[int] = 1
AUDIT_PER_PAGE_MAX: Final[int] = 100
AUDIT_PAGE_MAX: Final[int] = 10_000

#: Phrase exacte de confirmation pour wipe — case-sensitive volontaire
#: (anti-typo défensif). Le user copie-colle depuis l'UI.
WIPE_CONFIRMATION_PHRASE: Final[str] = "DELETE ALL MY ANONYMIZATION DATA"

#: Filtres autorisés pour list_audit — fail-closed contre paramètres libres.
AUDIT_ACTION_VALUES: Final[frozenset[str]] = frozenset({"insert", "update", "delete"})

#: Plage maximale d'un range ``since`` / ``until`` (anti-DoS index scan).
#: 1 an de profondeur couvre largement l'usage (article 30 du registre
#: des activités de traitement, conservé typiquement 1 an).
AUDIT_RANGE_MAX_DAYS: Final[int] = 365

#: Cap dur sur le nombre de rows exportées (anti-OOM serveur). 100K rows
#: × ~500 bytes JSON ≈ 50 MB, gérable en mémoire. Au-delà → ``truncated=True``
#: dans la réponse, le user export par tranches via ``/api/anonymization/audit``
#: paginé. Couvre 99.99% des cas (un user actif a ~1500-3000 audit/mois).
EXPORT_AUDIT_MAX_ROWS: Final[int] = 100_000


# ─── Helpers internes ──────────────────────────────────────────────────────


def _term_to_dict(row: AnonymizationTerm) -> Dict[str, Any]:
    """Sérialise un :class:`AnonymizationTerm` pour les payloads API.

    Utilise ``to_dict`` du modèle (déjà implémenté) mais ajoute le
    ``auto_pseudo`` calculé pour cohérence avec le reste de l'API.
    """
    d = row.to_dict()
    # ``auto_pseudo`` au format ``{LABEL}_{md5[:4]}`` — porte la catégorie
    # au LLM (ex: ``EMAIL_4b3a``). Aligne le placeholder panneau avec le
    # token effectivement substitué côté Pseudonymizer (single source).
    d["auto_pseudo"] = anon_extract._auto_pseudo_middle(row.term, row.category)
    return d


def _audit_to_dict(row: AnonymizationAudit) -> Dict[str, Any]:
    """Sérialise un :class:`AnonymizationAudit`."""
    return {
        "id": row.id,
        "term": row.term,
        "action": row.action,
        "triggered_by": row.triggered_by,
        "triggered_by_user_id": row.triggered_by_user_id,
        "category": row.category,
        "risk_level": row.risk_level,
        "enabled": row.enabled,
        "confirmed": row.confirmed,
        "changed_fields": row.changed_fields,
        "reason": row.reason,
        "classeur_ref": row.classeur_ref,
        "anonymization_term_id": row.anonymization_term_id,
        "created_at": (
            row.created_at.replace(tzinfo=timezone.utc).isoformat()
            if row.created_at and row.created_at.tzinfo is None
            else (row.created_at.isoformat() if row.created_at else None)
        ),
    }


# ─── DELETE single term ────────────────────────────────────────────────────


async def delete_term_for_user(
    session: AsyncSession,
    user_id: int,
    term_id: int,
    *,
    triggered_by_user_id: Optional[int] = None,
    reason: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Supprime un terme d'anonymisation **du user courant** + audit.

    Retourne ``None`` si le terme n'existe pas ou n'appartient pas au user
    (le handler renvoie 404 — ne pas leak l'existence cross-user).
    Retourne ``{"id", "term", "audited": bool}`` sinon.

    L'audit est créé AVANT le DELETE (pour pouvoir référencer l'id du
    terme avant disparition). Fail-soft : si l'audit échoue,
    on logge et on supprime quand même.
    """
    if not is_valid_user_id(user_id):
        return None
    if not isinstance(term_id, int) or term_id <= 0:
        return None

    stmt = select(AnonymizationTerm).where(
        AnonymizationTerm.id == term_id,
        AnonymizationTerm.user_id == user_id,
    )
    row = await session.scalar(stmt)
    if row is None:
        # Soit n'existe pas, soit autre user → 404 indistingable.
        return None

    # Snapshot avant delete (pour audit).
    term_value = row.term
    enabled_before = bool(row.enabled)
    confirmed_before = bool(row.confirmed)
    category_before = row.category
    risk_level_before = row.risk_level

    audit_id = await anon_audit.log_audit_action(
        session,
        user_id=user_id,
        term=term_value,
        anonymization_term_id=term_id,
        action="delete",
        triggered_by="user_panel",
        triggered_by_user_id=triggered_by_user_id,
        category=category_before,
        risk_level=risk_level_before,
        enabled=enabled_before,
        confirmed=confirmed_before,
        changed_fields={
            "enabled": [enabled_before, None],
            "confirmed": [confirmed_before, None],
        },
        reason=reason or "user-driven delete via /api/anonymization/terms/:id",
    )

    # Critical #37 review : DELETE conditionnel + check rowcount.
    # SQLite ne supporte pas SELECT FOR UPDATE, mais on peut détecter une
    # race (un autre DELETE concurrent a déjà fait le travail) via le
    # rowcount du DELETE. Si rowcount=0, le terme a déjà été supprimé →
    # on retourne ``already_deleted=True`` au lieu d'un faux ``success``.
    result = await session.execute(
        delete(AnonymizationTerm).where(
            AnonymizationTerm.id == term_id,
            AnonymizationTerm.user_id == user_id,
        )
    )
    rowcount = getattr(result, "rowcount", -1)

    return {
        "id": term_id,
        "term": term_value,
        "audited": audit_id is not None,
        "already_deleted": rowcount == 0,
    }


# ─── GET coverage for term ─────────────────────────────────────────────────


async def coverage_for_term(
    session: AsyncSession,
    user_id: int,
    term_id: int,
) -> Optional[Dict[str, Any]]:
    """Indique où apparaît un terme dans le datastore + audit récent.

    Retourne ``None`` si le terme n'existe pas ou n'appartient pas au user.

    Sortie ::

        {
          "term": "...",
          "id": 42,
          "classeurs": [
             {"filename": "compta.afz.json", "present": true},
             ...
          ],
          "classeurs_count": 47,    # nb classeurs où le terme apparaît
          "audit_recent": [...],    # 10 dernières actions sur ce terme
          "scan_truncated": false   # True si on a stoppé à SCAN_MAX_FILES
        }

    **Concurrence (fix review C6)** : la session SQLAlchemy est UTILISÉE
    pour les SELECT BDD courts mais N'EST PAS conservée pendant le scan
    disque (qui peut durer 30s sur un gros datastore). Le caller fait
    deux SELECT séparés (term + audit) avec le scan disque ENTRE les
    deux, mais on n'envoie pas de query pendant le scan — la session
    reste active mais idle. L'invariant "ne pas tenir la session
    pendant un long blocking I/O" est respecté car ``await asyncio.to_thread``
    libère l'event loop.
    """
    if not is_valid_user_id(user_id):
        return None
    if not isinstance(term_id, int) or term_id <= 0:
        return None

    # Étape 1 : SELECT court (term existe + ownership).
    stmt = select(AnonymizationTerm).where(
        AnonymizationTerm.id == term_id,
        AnonymizationTerm.user_id == user_id,
    )
    row = await session.scalar(stmt)
    if row is None:
        return None
    term_value = row.term

    # Étape 2 : audit récent (SELECT court avant le scan, pour minimiser
    # le temps de session ouverte).
    audit_stmt = (
        select(AnonymizationAudit)
        .where(
            AnonymizationAudit.user_id == user_id,
            AnonymizationAudit.term == term_value,
        )
        .order_by(AnonymizationAudit.created_at.desc())
        .limit(10)
    )
    audit_rows = (await session.scalars(audit_stmt)).all()
    audit_dicts = [_audit_to_dict(r) for r in audit_rows]

    # Étape 3 : scan disque — SANS query SQL pendant ce temps. Le caller
    # peut commit la session avant si désiré.
    classeurs, classeurs_count, truncated = await asyncio.to_thread(
        _scan_term_in_datastore_sync, user_id, term_value
    )

    return {
        "id": term_id,
        "term": term_value,
        "classeurs": classeurs,
        "classeurs_count": classeurs_count,
        "audit_recent": audit_dicts,
        "scan_truncated": truncated,
    }


def _resolve_user_dir(user_id: int) -> Path:
    """Wrapper module-level pour le résolveur de user_dir.

    L'import de ``app.handlers.datastore`` est tardif (dans cette fonction)
    pour éviter de polluer ``dir(app.handlers)`` au load — invariant
    ``test_app_handlers_init.py``. Les tests qui veulent injecter un
    user_dir alternatif patchent directement ce helper module-level via
    ``monkeypatch.setattr(api_service, "_resolve_user_dir", ...)`` plutôt
    que d'importer ``app.handlers.datastore`` (ce qui casserait l'invariant
    "pay-for-what-you-use" du package handlers).
    """
    from app.handlers.datastore import _user_dir

    return _user_dir(user_id)


def _scan_term_in_datastore_sync(
    user_id: int, term_value: str
) -> Tuple[List[Dict[str, Any]], int, bool]:
    """Compte la présence de ``term_value`` dans chaque classeur du datastore.

    Retourne ``(per_classeur, classeurs_count, truncated)``. Le contrat
    est : booléen "présent dans ce classeur" (pas un comptage exact des
    occurrences — pour ça il faudrait re-tokenizer sans dédup, coût ×N).

    Cap à ``SCAN_MAX_FILES`` (5000). Au-delà, ``truncated=True``.

    **Ne lit QUE des fichiers** — pas de BDD. Appelé via ``asyncio.to_thread``.
    """
    # Single source of truth pour la lecture des ``.afz.json`` (gère gzip
    # transparent via magic byte 0x1f 0x8b). Sans ça, les classeurs gzippés
    # étaient silencieusement skippés et l'utilisateur voyait "0 classeurs"
    # pour un terme pourtant présent — fix 2026-05-19, même cause que
    # ``_extract_tabs_from_file_sync``.
    from app.services.classeur.reader import _load_json_sync, list_classeurs_sync

    user_dir = _resolve_user_dir(user_id)
    if not user_dir.exists():
        return [], 0, False

    classeurs_meta = list_classeurs_sync(user_dir)
    per_classeur: List[Dict[str, Any]] = []
    classeurs_count = 0
    truncated = False

    for i, meta in enumerate(classeurs_meta):
        if i >= SCAN_MAX_FILES:
            truncated = True
            break
        fname = meta.get("filename") if isinstance(meta, dict) else None
        if not fname:
            continue
        path = user_dir / fname
        try:
            if not path.resolve().is_relative_to(user_dir.resolve()):
                continue
            raw = _load_json_sync(path)
            tabs = raw.get("tabs") if isinstance(raw, dict) else None
            if not isinstance(tabs, list):
                continue
            tokens = anon_extract.extract_terms(tabs)
            if term_value in tokens:
                per_classeur.append({"filename": fname, "present": True})
                classeurs_count += 1
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("coverage scan: classeur %s ignoré (%s)", fname, exc)

    return per_classeur, classeurs_count, truncated


# ─── GET audit list ────────────────────────────────────────────────────────


async def list_audit(
    session: AsyncSession,
    user_id: int,
    *,
    page: int = 1,
    per_page: int = AUDIT_PER_PAGE_DEFAULT,
    action_filter: Optional[str] = None,
    triggered_by_filter: Optional[str] = None,
    term_contains: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Liste paginée de l'audit d'un user.

    Tous les filtres sont optionnels. Pagination 1-indexed (page=1, page=2).
    Le caller (handler) clamp ``per_page`` dans ``[1, AUDIT_PER_PAGE_MAX]``
    et ``page`` dans ``[1, AUDIT_PAGE_MAX]``.
    """
    if not is_valid_user_id(user_id):
        return {"items": [], "total": 0, "page": page, "per_page": per_page}

    # Clamp défensif (defense-in-depth).
    page = max(1, min(int(page), AUDIT_PAGE_MAX))
    per_page = max(AUDIT_PER_PAGE_MIN, min(int(per_page), AUDIT_PER_PAGE_MAX))

    base_where = [AnonymizationAudit.user_id == user_id]
    if action_filter and action_filter in AUDIT_ACTION_VALUES:
        base_where.append(AnonymizationAudit.action == action_filter)
    if triggered_by_filter and triggered_by_filter in anon_audit.TRIGGERED_BY_VALUES:
        base_where.append(AnonymizationAudit.triggered_by == triggered_by_filter)
    if term_contains and isinstance(term_contains, str) and term_contains.strip():
        # ILIKE bindé via SQLAlchemy — pas d'injection.
        like_pattern = f"%{term_contains.strip()}%"
        base_where.append(AnonymizationAudit.term.ilike(like_pattern))

    # FIX review H1 : clamp range since/until à AUDIT_RANGE_MAX_DAYS pour
    # éviter un FULL SCAN sur l'index created_at (un user qui pose
    # since=0001-01-01 sur 100K rows audit consomme ~CPU sur chaque request).
    now = clock.now()
    max_range = timedelta(days=AUDIT_RANGE_MAX_DAYS)
    earliest = now - max_range
    if since is not None:
        # Normalise en UTC aware si naive (defense-in-depth).
        s = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        if s < earliest:
            s = earliest
        base_where.append(AnonymizationAudit.created_at >= s)
    if until is not None:
        u = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
        # Cap dans le futur à +1 jour (clock skew tolérance).
        if u > now + timedelta(days=1):
            u = now + timedelta(days=1)
        base_where.append(AnonymizationAudit.created_at <= u)

    where_clause = and_(*base_where)

    total_stmt = select(func.count(AnonymizationAudit.id)).where(where_clause)
    total = int((await session.scalar(total_stmt)) or 0)

    offset = (page - 1) * per_page
    items_stmt = (
        select(AnonymizationAudit)
        .where(where_clause)
        .order_by(AnonymizationAudit.created_at.desc(), AnonymizationAudit.id.desc())
        .limit(per_page)
        .offset(offset)
    )
    rows = (await session.scalars(items_stmt)).all()

    return {
        "items": [_audit_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "filters": {
            "action": action_filter if action_filter in AUDIT_ACTION_VALUES else None,
            "triggered_by": (
                triggered_by_filter
                if triggered_by_filter in anon_audit.TRIGGERED_BY_VALUES
                else None
            ),
            "term_contains": term_contains.strip() if isinstance(term_contains, str) else None,
        },
    }


# ─── GET export (utilisateur) ──────────────────────────────────────────


async def export_user_data(
    session: AsyncSession,
    user_id: int,
) -> Dict[str, Any]:
    """Export utilisateur — tout ce que la table d'anonymisation sait du user.

    Retourne une structure JSON sérialisable contenant :

    - ``terms`` : tous les termes avec champs étendus
    - ``audit`` : tout l'historique (cap mais lisible)
    - ``stats`` : agrégats (cohérence avec /stats)
    - ``exported_at`` : timestamp UTC ISO
    - ``user_id`` : identifiant pour traçabilité

    Pas de pagination — c'est un export. Pour des users très gros (>10k
    audit rows) cela peut produire un blob de plusieurs MB ; le handler
    expose en ``Content-Disposition: attachment`` pour téléchargement
    direct.
    """
    if not is_valid_user_id(user_id):
        return {
            "user_id": user_id,
            "exported_at": clock.now().isoformat(),
            "terms": [],
            "audit": [],
            "stats": _empty_stats(),
        }

    terms_stmt = (
        select(AnonymizationTerm)
        .where(AnonymizationTerm.user_id == user_id)
        .order_by(AnonymizationTerm.term.asc())
    )
    terms_rows = (await session.scalars(terms_stmt)).all()

    # FIX review H3 : cap dur sur le nombre de rows audit exportées
    # (anti-OOM). Au-delà du cap, ``truncated=True`` et l'utilisateur peut
    # paginer via ``/api/anonymization/audit``. On retourne en priorité les
    # rows les plus récentes (utiles pour répondre à une demande utilisateur).
    audit_count_stmt = select(func.count(AnonymizationAudit.id)).where(
        AnonymizationAudit.user_id == user_id
    )
    audit_total = int((await session.scalar(audit_count_stmt)) or 0)
    audit_truncated = audit_total > EXPORT_AUDIT_MAX_ROWS

    audit_stmt = (
        select(AnonymizationAudit)
        .where(AnonymizationAudit.user_id == user_id)
        .order_by(AnonymizationAudit.created_at.desc(), AnonymizationAudit.id.desc())
        .limit(EXPORT_AUDIT_MAX_ROWS)
    )
    audit_rows = (await session.scalars(audit_stmt)).all()

    stats = await stats_for_user(session, user_id)

    return {
        "user_id": user_id,
        "exported_at": clock.now().isoformat(),
        "schema_version": 1,
        "terms": [_term_to_dict(r) for r in terms_rows],
        "audit": [_audit_to_dict(r) for r in audit_rows],
        "audit_total": audit_total,
        "audit_truncated": audit_truncated,
        "stats": stats,
    }


# ─── POST wipe (utilisateur) ───────────────────────────────────────────


async def wipe_user_data(
    session: AsyncSession,
    user_id: int,
    *,
    triggered_by_user_id: Optional[int] = None,
    reason: str = "user_wipe",
) -> Dict[str, Any]:
    """Supprime TOUS les termes d'anonymisation + l'audit historique du user.

    Conserve UNIQUEMENT la row d'audit "wipe" pour traçabilité légale.
    L'audit row du wipe utilise ``term="<wipe>"`` (placeholder sans PII).

    Retourne ``{"deleted_terms": N, "deleted_audit": M, "wipe_audit_id": id}``.

    **Idempotence** : un wipe sur un user vide ne produit pas d'erreur,
    juste 0 termes supprimés. La row d'audit "wipe" est tout de même créée
    (trace que l'utilisateur a explicitement demandé l'effacement).
    """
    if not is_valid_user_id(user_id):
        return {"deleted_terms": 0, "deleted_audit": 0, "wipe_audit_id": None}

    # 1. Comptage avant pour stats (et pour la row de wipe).
    count_terms_stmt = select(func.count(AnonymizationTerm.id)).where(
        AnonymizationTerm.user_id == user_id
    )
    count_audit_stmt = select(func.count(AnonymizationAudit.id)).where(
        AnonymizationAudit.user_id == user_id
    )
    count_terms_before = int((await session.scalar(count_terms_stmt)) or 0)
    count_audit_before = int((await session.scalar(count_audit_stmt)) or 0)

    # 2. Audit row "wipe" AVANT delete — utilise placeholder ``<wipe>`` (pas de PII).
    wipe_audit_id = await anon_audit.log_audit_action(
        session,
        user_id=user_id,
        term="<wipe>",
        action="delete",
        triggered_by="user_panel",
        triggered_by_user_id=triggered_by_user_id,
        changed_fields={
            "wipe_count_terms": [count_terms_before, 0],
            "wipe_count_audit": [count_audit_before, 0],
        },
        reason=reason[:200] if reason else "user_wipe",
    )

    # FIX review C3 : si l'audit log échoue (BDD locked, schema corrompu),
    # ABORT le wipe plutôt que de purger sans traçabilité. La traçabilité
    # légale utilisateur est l'invariant non-négociable du wipe ; pas de wipe
    # silencieux possible.
    if wipe_audit_id is None:
        raise RuntimeError(
            "Wipe utilisateur aborté : impossible d'enregistrer la trace d'audit. "
            "Vérifier l'état de la BDD anonymization_audit."
        )

    # 3. Delete tous les termes du user.
    deleted_terms_result = await session.execute(
        delete(AnonymizationTerm).where(AnonymizationTerm.user_id == user_id)
    )
    deleted_terms = int(deleted_terms_result.rowcount or 0)

    # 4. Delete tout l'audit du user, SAUF la row "wipe" qu'on vient de créer.
    deleted_audit_stmt = delete(AnonymizationAudit).where(
        AnonymizationAudit.user_id == user_id,
        AnonymizationAudit.id != wipe_audit_id,
    )
    deleted_audit_result = await session.execute(deleted_audit_stmt)
    deleted_audit = int(deleted_audit_result.rowcount or 0)

    return {
        "deleted_terms": deleted_terms,
        "deleted_audit": deleted_audit,
        "wipe_audit_id": wipe_audit_id,
    }


# ─── GET stats (badge global) ──────────────────────────────────────────────


def _empty_stats() -> Dict[str, Any]:
    return {
        "total": 0,
        "enabled": 0,
        "disabled": 0,
        "confirmed": 0,
        "pending_review": 0,
        "by_category": {},
        "by_risk": {},
        "by_source": {},
        "critical_visible": 0,
        "last_updated_at": None,
    }


async def stats_for_user(
    session: AsyncSession,
    user_id: int,
) -> Dict[str, Any]:
    """Agrégats utilisés par le badge global et la page /data/privacy.

    ``critical_visible`` = nb termes ``risk_level='critical'`` ET
    ``enabled=False`` — ce sont les termes qui partent EN CLAIR aux LLMs,
    le compteur d'alerte de la page.

    **Perf** (refactor 2026-05-19) : 4 requêtes SQL agrégées au lieu d'un
    full scan + agrégation Python. Sur 53k rows mesurées prod, le coût
    cœur passe de ~250ms (ORM hydratation + boucle O(N)) à ~50ms
    (4 ``COUNT(*)`` indexés). RAM constante au lieu de O(N) row objects.
    Indispensable parce que ``/api/anonymization/stats`` est pollé par
    ``privacy-badge.js`` toutes les 30s sur toutes les pages — un full
    scan en multi-onglets saturait le CPU.

    Contrat de retour identique à la version Python pour back-compat
    (badge JS, page privacy, scripts admin).
    """
    if not is_valid_user_id(user_id):
        return _empty_stats()

    # 1. Compteurs scalaires + dernière activité — UNE seule requête.
    # ``SUM(CASE WHEN ... THEN 1 ELSE 0 END)`` portable SQLite ≥3.7 et
    # PostgreSQL (équivalent ``COUNT(*) FILTER (WHERE ...)`` mais sans
    # exiger SQLite ≥3.30 ni dialect-specific FILTER).
    scalars_stmt = select(
        func.count(AnonymizationTerm.id).label("total"),
        func.coalesce(
            func.sum(case((AnonymizationTerm.enabled.is_(True), 1), else_=0)),
            0,
        ).label("enabled_count"),
        func.coalesce(
            func.sum(case((AnonymizationTerm.confirmed.is_(True), 1), else_=0)),
            0,
        ).label("confirmed_count"),
        func.coalesce(
            func.sum(
                case(
                    (
                        and_(
                            AnonymizationTerm.risk_level == "critical",
                            AnonymizationTerm.enabled.is_(False),
                        ),
                        1,
                    ),
                    else_=0,
                )
            ),
            0,
        ).label("critical_visible_count"),
        # ``COALESCE(updated_at, created_at)`` : updated_at reste NULL tant
        # qu'aucun UPDATE n'a eu lieu (TimestampMixin onupdate uniquement).
        # Sémantique métier : "dernière activité" = max(updated, created).
        func.max(func.coalesce(AnonymizationTerm.updated_at, AnonymizationTerm.created_at)).label(
            "last_activity"
        ),
    ).where(AnonymizationTerm.user_id == user_id)

    scalars_row = (await session.execute(scalars_stmt)).first()
    if scalars_row is None or (scalars_row.total or 0) == 0:
        return _empty_stats()

    total = int(scalars_row.total or 0)
    enabled = int(scalars_row.enabled_count or 0)
    confirmed = int(scalars_row.confirmed_count or 0)
    critical_visible = int(scalars_row.critical_visible_count or 0)
    pending_review = total - confirmed

    last_updated_at: Optional[datetime] = None
    last_activity_raw = scalars_row.last_activity
    if last_activity_raw is not None:
        # SQLite stocke en string ; SQLAlchemy convertit en datetime selon le
        # type Column. Normaliser en UTC-aware (cf. note TimestampMixin).
        if isinstance(last_activity_raw, datetime):
            last_updated_at = (
                last_activity_raw
                if last_activity_raw.tzinfo
                else last_activity_raw.replace(tzinfo=timezone.utc)
            )

    # 2. Group by category — COALESCE pour gérer NULL → 'unclassified'.
    cat_stmt = (
        select(
            func.coalesce(AnonymizationTerm.category, "unclassified").label("k"),
            func.count(AnonymizationTerm.id).label("n"),
        )
        .where(AnonymizationTerm.user_id == user_id)
        .group_by(func.coalesce(AnonymizationTerm.category, "unclassified"))
    )
    by_category: Dict[str, int] = {
        row.k: int(row.n) for row in (await session.execute(cat_stmt)).all()
    }

    # 3. Group by risk_level — COALESCE NULL → 'low'.
    risk_stmt = (
        select(
            func.coalesce(AnonymizationTerm.risk_level, "low").label("k"),
            func.count(AnonymizationTerm.id).label("n"),
        )
        .where(AnonymizationTerm.user_id == user_id)
        .group_by(func.coalesce(AnonymizationTerm.risk_level, "low"))
    )
    by_risk: Dict[str, int] = {
        row.k: int(row.n) for row in (await session.execute(risk_stmt)).all()
    }

    # 4. Group by source — COALESCE NULL → 'manual'.
    src_stmt = (
        select(
            func.coalesce(AnonymizationTerm.source, "manual").label("k"),
            func.count(AnonymizationTerm.id).label("n"),
        )
        .where(AnonymizationTerm.user_id == user_id)
        .group_by(func.coalesce(AnonymizationTerm.source, "manual"))
    )
    by_source: Dict[str, int] = {
        row.k: int(row.n) for row in (await session.execute(src_stmt)).all()
    }

    return {
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "confirmed": confirmed,
        "pending_review": pending_review,
        "by_category": by_category,
        "by_risk": by_risk,
        "by_source": by_source,
        "critical_visible": critical_visible,
        "last_updated_at": (last_updated_at.isoformat() if last_updated_at is not None else None),
    }


# ─── POST auto-classify/regex (fallback sans LLM local) ────────────────────


def classify_with_regex(tokens: List[str]) -> Dict[str, Any]:
    """Classe une liste de tokens via regex PII built-in (pas de LLM).

    Pour chaque token, on vérifie si :func:`apply_builtin_pii` l'identifie
    comme un type built-in (EMAIL, PHONE, AMOUNT, SIRET, SIREN, IBAN). Si
    oui → flagged + type associé. Sinon → laissé tel quel.

    Retourne ::

        {"flagged": ["a@b.fr", "01 23 45 67 89"],
         "by_type": {"EMAIL": ["a@b.fr"], "PHONE": ["01 23 45 67 89"]},
         "checked": 42}

    **Stateless / pure** — pas de session, pas de side-effect.
    """
    if not isinstance(tokens, list):
        return {"flagged": [], "by_type": {}, "checked": 0}

    flagged: List[str] = []
    by_type: Dict[str, List[str]] = {}
    checked = 0
    seen: Set[str] = set()

    for tok in tokens:
        if not isinstance(tok, str):
            continue
        # Cap à MAX_VALUE_LEN pour cohérence avec le tokenizer (sécurité regex).
        s = tok[: anon_extract.MAX_VALUE_LEN]
        if not s.strip():
            continue
        if s in seen:
            continue
        seen.add(s)
        checked += 1

        # Apply patterns sur le token isolé. Si le token MATCHE un pattern
        # ET le pattern couvre TOUTE la string (pas un sous-match), on flag.
        # Sinon, un mot anodin contenant un sous-pattern produirait un faux
        # positif.
        anonymized, mapping, _counters = anon_patterns.apply_builtin_pii(s)
        if not mapping:
            continue
        # Le token est flagged si le résultat anonymisé est juste un placeholder
        # (i.e. la regex a matché toute la string). Sinon le pattern n'a matché
        # qu'une sous-partie — on ne flag pas pour éviter les faux positifs.
        if anonymized.startswith("[") and anonymized.endswith("]") and "_" in anonymized:
            # Ex: "[EMAIL_1]". Extrait le type.
            inner = anonymized[1:-1]
            type_name = inner.rsplit("_", 1)[0]
            flagged.append(s)
            by_type.setdefault(type_name, []).append(s)

    return {
        "flagged": sorted(flagged),
        "by_type": {k: sorted(v) for k, v in by_type.items()},
        "checked": checked,
    }


# ─── POST scan (SSE — itère datastore en streaming) ────────────────────────


async def scan_datastore_tokens(
    user_id: int,
) -> AsyncIterator[Dict[str, Any]]:
    """Async generator qui itère le datastore d'un user et yield des
    événements SSE-friendly :

    * ``{"step": "start", "total_files": N}`` — au début
    * ``{"step": "file", "filename": ..., "processed": k, "total": N,``
      ``"new_tokens_count": K, "tokens_so_far": T}`` — pour chaque fichier
    * ``{"step": "complete", "tokens_found": [...], "stats": {...},``
      ``"truncated": bool}`` — à la fin

    **Best-effort sur les classeurs corrompus** : ils sont skippés avec
    un log debug, l'itération continue.

    **Caps** :
    - ``SCAN_MAX_FILES`` fichiers max (anti-DoS disque)
    - Pas de cap tokens : la taille du datastore source borne implicitement
      l'output, et le quota disque user (``UserStorage.quota_limit``) reste
      le vrai gardefou en amont.
    """
    if not is_valid_user_id(user_id):
        yield {"step": "error", "error": "invalid_user_id"}
        return

    # Import tardif (ne tire pas ``app.services.classeur`` au top-level
    # de ``api_service``).
    from app.services.classeur.reader import list_classeurs_sync

    user_dir = _resolve_user_dir(user_id)
    if not user_dir.exists():
        yield {
            "step": "complete",
            "tokens_found": [],
            "stats": {"files_scanned": 0, "tokens_unique": 0},
            "truncated": False,
        }
        return

    classeurs_meta = await asyncio.to_thread(list_classeurs_sync, user_dir)
    total_files = min(len(classeurs_meta), SCAN_MAX_FILES)

    yield {"step": "start", "total_files": total_files}

    all_tokens: Set[str] = set()
    files_truncated = len(classeurs_meta) > SCAN_MAX_FILES
    files_processed = 0

    # 2026-05-19 — Le bouton "Scanner mes données" alimente RÉELLEMENT
    # ``anonymization_terms`` via ``scan_workbook_terms`` (qui upsert
    # avec ``source="workbook"`` + ``source_ref=<filename>`` + origines).
    # Avant, ``scan_datastore_tokens`` ne faisait qu'un comptage SSE
    # sans persister — l'user croyait alimenter la liste de /data/privacy
    # alors qu'il ne se passait rien côté BDD. Cohérent avec le scan
    # ``addTab`` côté frontend : un classeur visible → ses termes en BDD.
    from app.core.database import get_session as _get_scan_session

    total_added = 0

    for i, meta in enumerate(classeurs_meta):
        if i >= SCAN_MAX_FILES:
            break
        fname = meta.get("filename") if isinstance(meta, dict) else None
        if not fname:
            continue
        path = user_dir / fname
        new_tokens_count = 0
        added_in_file = 0
        try:
            if not path.resolve().is_relative_to(user_dir.resolve()):
                continue
            # Extraire les tabs (lecture fichier en thread, non-bloquante).
            tabs = await asyncio.to_thread(_extract_tabs_from_file_sync, path)
            if tabs:
                # 1. Comptage informatif pour la progress bar SSE.
                tokens = anon_extract.extract_terms(tabs)
                before_size = len(all_tokens)
                all_tokens.update(tokens)
                new_tokens_count = len(all_tokens) - before_size

                # 2. Upsert RÉEL en BDD : alimente anonymization_terms
                #    avec source="workbook" + source_ref=<filename>.
                #    Réutilise ``scan_workbook_terms`` (même pipeline que
                #    le scan-workbook frontend) → single source of truth
                #    pour la logique d'extraction + auto-PII + origines.
                try:
                    async with _get_scan_session() as scan_session:
                        scan_result = await scan_workbook_terms(
                            scan_session,
                            user_id=user_id,
                            tabs_context=tabs,
                            sheet_content=None,
                            classeur_ref=fname,
                        )
                        await scan_session.commit()
                    added_in_file = int(scan_result.get("added", 0) or 0)
                    total_added += added_in_file
                except Exception:  # noqa: BLE001 — un classeur en erreur
                    # ne bloque pas le scan global ; on log + continue.
                    logger.warning(
                        "scan_datastore: upsert classeur %s échoué (skip)",
                        fname,
                        exc_info=True,
                    )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.debug("scan_datastore: classeur %s ignoré (%s)", fname, exc)

        files_processed += 1
        yield {
            "step": "file",
            "filename": fname,
            "processed": files_processed,
            "total": total_files,
            "new_tokens_count": new_tokens_count,
            "added_in_file": added_in_file,
            "tokens_so_far": len(all_tokens),
            "added_so_far": total_added,
        }

    # ─────────────────────────────────────────────────────────────────────
    # Phase 2 (ajout 2026-05-20) — scan des dashboards user.
    # ─────────────────────────────────────────────────────────────────────
    # Étend la "source de vérité" /data/privacy aux champs textuels admin-
    # éditables des dashboards (nom, description, titres widgets, labels
    # filtres, sujets/messages des envois email). Cf.
    # ``extract_dashboard_terms_with_origin`` pour la liste exhaustive.
    # Best-effort : une erreur sur un dashboard ne bloque pas le scan
    # global (idem boucle classeurs ci-dessus).
    dashboards_processed = 0
    dashboards_added = 0
    try:
        async for dash_event in _scan_user_dashboards_streaming(user_id):
            if dash_event.get("step") == "dashboard":
                dashboards_processed += 1
                dashboards_added += int(dash_event.get("added_in_dashboard", 0) or 0)
                total_added += int(dash_event.get("added_in_dashboard", 0) or 0)
                # Mettre à jour all_tokens pour le set final retourné.
                new_tokens_event = dash_event.get("tokens_in_dashboard") or []
                for t in new_tokens_event:
                    all_tokens.add(t)
            yield dash_event
    except Exception:  # noqa: BLE001
        logger.warning(
            "scan_datastore: phase dashboards échouée (skip, scan global continue)",
            exc_info=True,
        )

    # ─────────────────────────────────────────────────────────────────────
    # Phase 3 (ajout 2026-05-20) — scan des automations user (sans ouverture).
    # ─────────────────────────────────────────────────────────────────────
    # Scanne les champs textuels + littéraux SQL des automations sans que
    # l'user ait à ouvrir /automations/N/edit. Source en BDD = "sql_result"
    # + source_ref="automation:<id>" (mêmes conventions que le scan-workbook
    # frontend avec scan_context="automation_preview").
    automations_processed = 0
    automations_added = 0
    try:
        async for auto_event in _scan_user_automations_streaming(user_id):
            if auto_event.get("step") == "automation":
                automations_processed += 1
                automations_added += int(auto_event.get("added_in_automation", 0) or 0)
                total_added += int(auto_event.get("added_in_automation", 0) or 0)
                new_tokens_event = auto_event.get("tokens_in_automation") or []
                for t in new_tokens_event:
                    all_tokens.add(t)
            yield auto_event
    except Exception:  # noqa: BLE001
        logger.warning(
            "scan_datastore: phase automations échouée (skip, scan global continue)",
            exc_info=True,
        )

    # ─────────────────────────────────────────────────────────────────────
    # Phase 4 (ajout 2026-05-20) — scan des messages Iris persistés.
    # ─────────────────────────────────────────────────────────────────────
    # Couvre les résultats SQL des conversations Iris sans que l'user
    # ait besoin de ré-ouvrir chaque conversation dans iris-grid. Cap
    # max_messages (200) borne la charge. Source en BDD = "sql_result"
    # + source_ref="iris:<conv_id>".
    iris_messages_processed = 0
    iris_messages_added = 0
    try:
        async for iris_event in _scan_user_iris_messages_streaming(user_id):
            if iris_event.get("step") == "iris_message":
                iris_messages_processed += 1
                iris_messages_added += int(iris_event.get("added_in_message", 0) or 0)
                total_added += int(iris_event.get("added_in_message", 0) or 0)
            yield iris_event
    except Exception:  # noqa: BLE001
        logger.warning(
            "scan_datastore: phase iris_messages échouée (skip, scan global continue)",
            exc_info=True,
        )

    yield {
        "step": "complete",
        "tokens_found": sorted(all_tokens),
        "stats": {
            "files_scanned": files_processed,
            "dashboards_scanned": dashboards_processed,
            "automations_scanned": automations_processed,
            "iris_messages_scanned": iris_messages_processed,
            "tokens_unique": len(all_tokens),
            "terms_added_to_bdd": total_added,
        },
        # ``truncated`` reflète uniquement le cap fichiers (``SCAN_MAX_FILES``).
        # Le cap tokens (``SCAN_MAX_TOKENS``) a été retiré le 2026-05-19 : seul
        # le quota disque user borne légitimement le nombre de tokens.
        "truncated": files_truncated,
    }


async def _scan_user_dashboards_streaming(
    user_id: int,
) -> AsyncIterator[Dict[str, Any]]:
    """Itère les dashboards non-template de l'user et yield des events SSE.

    Events :
    * ``{"step": "dashboards_start", "total": N}`` au début (si N > 0).
    * ``{"step": "dashboard", "name": str, "id": int, "added_in_dashboard": K,``
      ``"tokens_in_dashboard": [list]}`` pour chaque dashboard.
    * Pas d'event ``complete`` ici — l'appelant (``scan_datastore_tokens``)
      émet le ``complete`` final agrégeant fichiers + dashboards.

    Fail-safe : une erreur sur un dashboard donné est loggée et le
    streaming continue avec le suivant. Une erreur globale (BDD down,
    import circulaire) propage à l'appelant.
    """
    # Imports tardifs : éviter de tirer le module ``dashboard`` au top-level
    # de ``api_service`` (cycle potentiel — dashboard tire widget_planner
    # qui tire LLM qui... → top-level lourd).
    from sqlalchemy.orm import selectinload

    from app.core.database import get_session as _get_dash_session
    from app.models.dashboard import (
        Dashboard,
        DashboardSchedule,
    )

    async with _get_dash_session() as session:
        # Charge dashboards non-template avec widgets + filtres eager-loadés
        # pour éviter N+1 queries pendant l'itération.
        result = await session.execute(
            select(Dashboard)
            .where(Dashboard.user_id == user_id)
            .where(Dashboard.is_template.is_(False))
            .options(
                selectinload(Dashboard.widgets),
                selectinload(Dashboard.filters),
            )
        )
        dashboards = list(result.scalars().all())

    if not dashboards:
        return

    yield {"step": "dashboards_start", "total": len(dashboards)}

    for dash in dashboards:
        # Re-ouvrir une session par dashboard : (a) isole l'erreur, (b)
        # libère le lock SQLite entre dashboards (cohérent avec la boucle
        # classeurs ci-dessus qui re-ouvre par fichier).
        try:
            async with _get_dash_session() as scan_session:
                # Charger les schedules associés (pas de back_populates
                # côté Dashboard pour DashboardSchedule — query explicite).
                sched_result = await scan_session.execute(
                    select(DashboardSchedule).where(DashboardSchedule.dashboard_id == dash.id)
                )
                schedules = list(sched_result.scalars().all())

                payload: Dict[str, Any] = {
                    "id": dash.id,
                    "name": getattr(dash, "name", None),
                    "description": getattr(dash, "description", None),
                    "template_description": getattr(dash, "template_description", None),
                    "is_template": False,  # déjà filtré, garantie pour l'extracteur
                    "widgets": [
                        {
                            "id": w.id,
                            "title": getattr(w, "title", None),
                            "data_source_config": getattr(w, "data_source_config", None),
                        }
                        for w in (dash.widgets or [])
                    ],
                    "filters": [
                        {
                            "id": f.id,
                            "label": getattr(f, "label", None),
                            # Le discriminateur ``values_source`` est une
                            # colonne SQL séparée (cf. DashboardFilter
                            # ligne 450) — l'extracteur teste sur cette
                            # valeur, pas sur ``values_config.source``
                            # (bug initial CRITICAL #1 review 2026-05-20).
                            "values_source": getattr(f, "values_source", None),
                            "values_config": getattr(f, "values_config", None),
                        }
                        for f in (dash.filters or [])
                    ],
                    "schedules": [
                        {
                            "id": s.id,
                            "subject": getattr(s, "subject", None),
                            "message": getattr(s, "message", None),
                            # Emails destinataires — PII canoniques
                            # (ajout HIGH #9 review adversariale).
                            "recipients": getattr(s, "recipients", None),
                        }
                        for s in schedules
                    ],
                }

                scan_result = await scan_dashboard_terms(
                    scan_session,
                    user_id=user_id,
                    dashboard=payload,
                )
                await scan_session.commit()
                added_in_dashboard = int(scan_result.get("added", 0) or 0)
                scanned_in_dashboard = int(scan_result.get("scanned", 0) or 0)
                tokens_in_dashboard = scan_result.get("tokens") or []
        except Exception as exc:  # noqa: BLE001
            # Best-effort : une erreur sur 1 dashboard ne bloque pas le
            # scan global. MAIS : si c'est un ``CHECK constraint failed``
            # sur ck_anon_term_source, c'est la signature d'une BDD
            # pré-existante avant l'ajout de 'dashboard' au tuple
            # ANONYMIZATION_SOURCES. On émet un event SSE explicite pour
            # que l'UI affiche un message actionable, plutôt que le user
            # voie "0 dashboards scannés" silencieusement (review
            # adversariale 2026-05-20 CRITICAL #3).
            err_msg = str(exc).lower()
            is_migration_required = (
                "check constraint" in err_msg and "ck_anon_term_source" in err_msg
            )
            if is_migration_required:
                logger.error(
                    "scan_dashboards: CHECK constraint rejette source='dashboard'. "
                    "BDD pré-existante nécessite migration manuelle (cf. "
                    "anonymization_term.py __table_args__).",
                    exc_info=True,
                )
                yield {
                    "step": "migration_required",
                    "reason": "ck_anon_term_source",
                    "message": (
                        "Votre base de données nécessite une migration pour "
                        "scanner les tableaux de bord (CHECK constraint sur "
                        "la table anonymization_terms à mettre à jour). "
                        "Contactez votre administrateur — procédure dans "
                        "app/models/anonymization_term.py."
                    ),
                }
                # Stop la phase dashboards : tous les dashboards subiraient
                # la même erreur, inutile de continuer à les itérer.
                return
            logger.warning(
                "scan_dashboards: dashboard #%s (%r) échoué (skip)",
                getattr(dash, "id", "?"),
                getattr(dash, "name", "?"),
                exc_info=True,
            )
            continue

        yield {
            "step": "dashboard",
            "id": dash.id,
            "name": getattr(dash, "name", None) or f"#{dash.id}",
            "added_in_dashboard": added_in_dashboard,
            "scanned_in_dashboard": scanned_in_dashboard,
            # Liste des tokens extraits du dashboard. L'appelant
            # (``scan_datastore_tokens``) aggrège ces tokens dans
            # ``all_tokens`` pour que ``stats.tokens_unique`` final
            # reflète aussi les dashboards (sans ça, sous-comptage).
            "tokens_in_dashboard": list(tokens_in_dashboard),
        }



def _extract_tabs_from_file_sync(path: Path) -> Optional[List[Dict[str, Any]]]:
    """Lit un fichier ``.afz.json`` et retourne sa structure ``tabs``.

    **Transparent gzip + brut** : utilise :func:`classeur.reader._load_json_sync`
    qui détecte automatiquement les classeurs gzippés (magic bytes
    ``0x1f 0x8b``) et décompresse à la volée. Single source of truth pour la
    lecture des ``.afz.json`` — toute divergence avec le reader runtime =
    drift visible / non visible entre l'app et le scan datastore.

    **Bug fix 2026-05-19** : avant, ce helper ouvrait le fichier en mode
    ``"r"`` UTF-8 et tentait un ``json.load`` direct → ``UnicodeDecodeError``
    silencieuse sur les classeurs gzippés (magic byte ``\\x8b``) → fichier
    skippé sans bruit par la boucle du scan datastore. Conséquence pour
    l'utilisateur : un classeur entier (parfois plusieurs MB de données)
    n'était JAMAIS aspiré dans ``anonymization_terms``, et le user pensait
    que ses termes étaient déjà connus.

    Best-effort : un fichier non-JSON / sans ``tabs`` retourne ``None``.
    Le caller peut ensuite appeler ``scan_workbook_terms(tabs_context=tabs)``
    pour alimenter la BDD ``anonymization_terms``.
    """
    from app.services.classeur.reader import _load_json_sync

    raw = _load_json_sync(path)
    if not isinstance(raw, dict):
        return None
    tabs = raw.get("tabs")
    if not isinstance(tabs, list):
        return None
    return tabs


# ─── Scan workbook live (task #8 POINT 1) ─────────────────────────────────


async def scan_workbook_terms(
    session: AsyncSession,
    user_id: int,
    tabs_context: Optional[List[Dict[str, Any]]] = None,
    sheet_content: Optional[List[Dict[str, Any]]] = None,
    *,
    classeur_ref: Optional[str] = None,
    source: str = "workbook",
    commit_every_n_chunks: int = 5,
) -> Dict[str, int]:
    """Scanne le state d'un classeur côté serveur et alimente
    ``anonymization_terms`` avec les tokens détectés.

    Appelé par :class:`AnonymizationScanWorkbookAPIHandler` (endpoint
    ``POST /api/anonymization/scan-workbook``) à chaque changement de
    classeur côté frontend (debounce 2-3s côté ``iris-grid.js``). Couvre
    ~80% des cas de "changement de classeur" : edit cellule, paste,
    add tab, import xlsx/csv en preview avant save, etc.

    Les tokens détectés sont insérés via :func:`upsert_terms` qui applique
    automatiquement la catégorisation PII (commit 00ab3c8 #11) : un email
    / SIRET+Luhn / IBAN+MOD-97 / phone FR / amount € entrant est
    auto-catégorisé et auto-enabled. Les tokens non-PII (noms, codes
    métier) sont insérés ``enabled=False`` — l'user décide via
    ``/data/privacy``.

    **Idempotent** : re-scanner le même workbook n'insère pas de doublons
    (cf. ``upsert_terms`` ON CONFLICT DO UPDATE — les flags user existants
    sont préservés).

    Args:
        session: session async SQLAlchemy (fournie par le handler).
        user_id: identifiant user — doit être > 0 sinon no-op.
        tabs_context: structure ``tabs_context`` du classeur (cf.
            :func:`extract_terms` pour le shape exact).
        sheet_content: structure ``sheet_content`` (onglet actif sparse).
        classeur_ref: référence du classeur (filename) — exposée dans
            ``source_ref`` du record BDD pour permettre le groupement par
            classeur dans ``/data/privacy``. ``None`` autorisé (preview
            non-sauvegardé, résultat Iris sans classeur ouvert).
        source: catégorie de la source (cf. ``ANONYMIZATION_SOURCES``).
            ``"workbook"`` par défaut (datastore + classeur édité dans
            iris-grid). Le handler appelle avec :

            - ``"workbook"`` quand l'utilisateur est sur ``/datastore`` ou
              édite un classeur ``.afz.json`` existant ;
            - ``"sql_result"`` quand un résultat SQL Iris est affiché
              (page ``/iris``) ou un preview d'automation (page
              ``/automations/N/edit``) — ``source_ref`` préfixé
              ``"iris:<conv_id>"`` / ``"automation:<id>"`` permet le
              distingo en lecture (panneau ``/data/privacy``).

            Toute valeur hors ``ANONYMIZATION_SOURCES`` rejetée fail-closed
            par le CHECK constraint BDD ``ck_anon_term_source`` — le
            handler valide en amont pour éviter le crash 500 et fallback
            à ``"workbook"`` (cf. ``AnonymizationScanWorkbookAPIHandler``).

    Returns:
        Dict ``{"scanned": N, "added": M}`` :

        - ``scanned`` : nombre de tokens uniques extraits du workbook
        - ``added`` : nombre de rows nouvellement insérées (existantes
          updatées ne comptent pas).
    """
    if not is_valid_user_id(user_id):
        return {"scanned": 0, "added": 0}
    if not tabs_context and not sheet_content:
        return {"scanned": 0, "added": 0}

    # Import tardif pour éviter le cycle module-load (repository importe
    # extract qui importe... — protection contre les cycles).
    from app.services.anonymization import repository as anon_repo

    # task #20 : on utilise ``extract_terms_with_origin`` (au lieu de
    # ``extract_terms`` simple) pour récupérer la (ou les) colonne(s)
    # d'origine de chaque token. Le set de tokens est identique — la
    # garantie de consistance est testée dans
    # ``tests/unit/test_extract_terms_with_origin.py``.
    origins_by_token = anon_extract.extract_terms_with_origin(tabs_context, sheet_content)
    if not origins_by_token:
        return {"scanned": 0, "added": 0}

    # Compter avant pour calculer le delta "added".
    count_before = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    # Construire le state à upsert : tous tokens avec defaults
    # ``enabled=False, confirmed=False``. L'auto-catégorisation PII via
    # ``upsert_terms`` (commit 00ab3c8) auto-active les PII détectées.
    terms_state: Dict[str, Dict[str, Any]] = {
        token: {"enabled": False, "confirmed": False} for token in origins_by_token
    }
    # Borner classeur_ref à 200 chars (cap colonne source_ref dans le modèle).
    # Frontend envoie déjà juste le nom de fichier (pas le path absolu) — défense
    # en profondeur côté serveur. Cf. task #15 : permet le groupement par
    # classeur dans /data/privacy via le label "Classeur : <ref>".
    safe_ref: Optional[str] = None
    if isinstance(classeur_ref, str):
        trimmed = classeur_ref.strip()
        if trimmed:
            safe_ref = trimmed[:200]

    # task #20 : transformer ``origins_by_token`` (Dict[token, Set[col|None]])
    # en ``origins_map`` (Dict[token, List[{"classeur", "col"}]]) en
    # injectant le classeur_ref pour CHAQUE col observée. Un token vu dans
    # 2 cols différentes du même classeur ⇒ 2 entries dans le map.
    origins_map: Dict[str, List[Dict[str, Optional[str]]]] = {
        token: [{"classeur": safe_ref, "col": col} for col in cols]
        for token, cols in origins_by_token.items()
    }
    await anon_repo.upsert_terms(
        session,
        user_id,
        terms_state,
        source=source,
        source_ref=safe_ref,
        origins_map=origins_map,
        commit_every_n_chunks=commit_every_n_chunks,
    )

    count_after = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    return {"scanned": len(origins_by_token), "added": count_after - count_before}


async def scan_automation_terms(
    session: AsyncSession,
    user_id: int,
    automation: Dict[str, Any],
) -> Dict[str, int]:
    """Scanne une automation (champs textuels admin-éditables) et alimente
    ``anonymization_terms`` avec ``source="sql_result"`` et
    ``source_ref="automation:<id>"``.

    Symétrique de :func:`scan_dashboard_terms` mais pour les automations.
    Scopes : ``name``, ``description``, ``recipients``, ``notification_emails``,
    ``query_text`` (littéraux SQL ou texte NL selon ``query_type``),
    ``steps[].name``, ``steps[].config.*`` (valeurs string + littéraux SQL).

    **Pourquoi ``source="sql_result"`` et pas ``"automation"``** : le tuple
    ``ANONYMIZATION_SOURCES`` n'a pas de valeur dédiée ; on réutilise
    ``"sql_result"`` (déjà utilisé pour les previews) avec ``source_ref``
    préfixé ``automation:<id>`` (cf. handler scan-workbook
    ``scan_context="automation_preview"``). Permet le groupage par
    automation dans l'UI /data/privacy via le source_ref.

    Args:
        session: session async SQLAlchemy.
        user_id: identifiant user — must > 0.
        automation: dict shape ``{id, name, description, query_text,
            query_type, recipients, notification_emails, steps: [...]}``.

    Returns:
        ``{"scanned": N, "added": M, "tokens": [list]}``.
    """
    if not is_valid_user_id(user_id):
        return {"scanned": 0, "added": 0, "tokens": []}
    if not isinstance(automation, dict):
        return {"scanned": 0, "added": 0, "tokens": []}

    from app.services.anonymization import repository as anon_repo

    origins_by_token = anon_extract.extract_automation_terms_with_origin(automation)
    if not origins_by_token:
        return {"scanned": 0, "added": 0, "tokens": []}

    # source_ref = "automation:<id>" pour cohérence avec le scan-workbook
    # côté frontend (cf. anonymization handler scan_context).
    auto_id = automation.get("id")
    safe_ref: Optional[str] = None
    if auto_id is not None:
        safe_ref = f"automation:{auto_id}"[:200]

    count_before = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    terms_state: Dict[str, Dict[str, Any]] = {
        token: {"enabled": False, "confirmed": False} for token in origins_by_token
    }

    origins_map: Dict[str, List[Dict[str, Optional[str]]]] = {
        token: [{"classeur": safe_ref, "col": col} for col in cols]
        for token, cols in origins_by_token.items()
    }
    await anon_repo.upsert_terms(
        session,
        user_id,
        terms_state,
        source="sql_result",
        source_ref=safe_ref,
        origins_map=origins_map,
    )

    count_after = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    return {
        "scanned": len(origins_by_token),
        "added": count_after - count_before,
        "tokens": list(origins_by_token.keys()),
    }


async def _scan_user_automations_streaming(
    user_id: int,
) -> AsyncIterator[Dict[str, Any]]:
    """Itère les automations du user et yield des events SSE.

    Events :
    * ``{"step": "automations_start", "total": N}`` au début (si N > 0).
    * ``{"step": "automation", "id": int, "name": str,
        "added_in_automation": K, "tokens_in_automation": [list]}``
      pour chaque automation.

    Fail-safe : une erreur sur une automation donnée est loggée et le
    streaming continue avec la suivante.
    """
    from sqlalchemy.orm import selectinload

    from app.core.database import get_session as _get_auto_session
    from app.models.automation import Automation
    from app.models.automation_step import AutomationStep

    async with _get_auto_session() as session:
        result = await session.execute(
            select(Automation)
            .where(Automation.user_id == user_id)
            .options(selectinload(Automation.steps))
        )
        automations = list(result.scalars().all())

    if not automations:
        return

    yield {"step": "automations_start", "total": len(automations)}

    for auto in automations:
        try:
            async with _get_auto_session() as scan_session:
                # Reload steps explicit dans cette session pour éviter
                # MissingGreenlet (les relations chargées dans la 1ère
                # session ne sont pas portables).
                steps_result = await scan_session.execute(
                    select(AutomationStep)
                    .where(AutomationStep.automation_id == auto.id)
                    .order_by(AutomationStep.step_order)
                )
                steps = list(steps_result.scalars().all())

                payload: Dict[str, Any] = {
                    "id": auto.id,
                    "name": getattr(auto, "name", None),
                    "description": getattr(auto, "description", None),
                    "query_text": getattr(auto, "query_text", None),
                    "query_type": getattr(auto, "query_type", None),
                    "recipients": getattr(auto, "recipients", None),
                    "notification_emails": getattr(auto, "notification_emails", None),
                    "steps": [
                        {
                            "id": s.id,
                            "name": getattr(s, "name", None),
                            "config": getattr(s, "config", None),
                        }
                        for s in steps
                    ],
                }

                scan_result = await scan_automation_terms(
                    scan_session, user_id=user_id, automation=payload
                )
                await scan_session.commit()
                added_in_automation = int(scan_result.get("added", 0) or 0)
                tokens_in_automation = scan_result.get("tokens") or []
        except Exception:  # noqa: BLE001
            logger.warning(
                "scan_automations: automation #%s échouée (skip)",
                getattr(auto, "id", "?"),
                exc_info=True,
            )
            continue

        yield {
            "step": "automation",
            "id": auto.id,
            "name": getattr(auto, "name", None) or f"#{auto.id}",
            "added_in_automation": added_in_automation,
            "tokens_in_automation": list(tokens_in_automation),
        }


async def _scan_user_iris_messages_streaming(
    user_id: int,
    max_messages: int = 200,
) -> AsyncIterator[Dict[str, Any]]:
    """Itère les ConversationMessage du user avec ``tool_result`` non-null
    et yield des events SSE — alimente ``anonymization_terms`` à partir
    des résultats SQL d'Iris persistés en BDD, sans avoir besoin que
    l'utilisateur ouvre la conversation.

    **Cap ``max_messages``** (default 200) : les conversations longues
    ont jusqu'à plusieurs centaines de messages, le scan peut être lourd.
    On prend les messages les plus récents (DESC sur created_at). Le
    background ``cleanup`` purgera les anciens via gate d'âge.

    **Filtrage** : seuls les messages ayant un ``tool_result`` parseable
    contenant des ``rows`` (résultat SQL) sont scannés. Les messages user
    text / assistant text sont ignorés (pas de PII structurée).

    Events :
    * ``{"step": "iris_messages_start", "total": N}`` au début.
    * ``{"step": "iris_message", "id": int, "conv_id": int,
        "added_in_message": K, "tokens_in_message": [list]}`` par message.
    """
    from app.core.database import get_session as _get_iris_session
    from app.models.conversation import Conversation, ConversationMessage

    async with _get_iris_session() as session:
        # user_id vit sur Conversation, pas ConversationMessage — JOIN
        # nécessaire pour scoper aux conversations du user.
        result = await session.execute(
            select(ConversationMessage)
            .join(Conversation, ConversationMessage.conversation_id == Conversation.id)
            .where(Conversation.user_id == user_id)
            .where(ConversationMessage.tool_result.isnot(None))
            .order_by(ConversationMessage.created_at.desc())
            .limit(max_messages)
        )
        messages = list(result.scalars().all())

    if not messages:
        return

    yield {"step": "iris_messages_start", "total": len(messages)}

    for msg in messages:
        rows: Optional[List[Dict[str, Any]]] = None
        columns: Optional[List[str]] = None
        try:
            raw = msg.tool_result
            if isinstance(raw, str) and raw:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    rows_raw = parsed.get("rows")
                    cols_raw = parsed.get("columns")
                    if isinstance(rows_raw, list):
                        rows = [r for r in rows_raw if isinstance(r, dict)]
                    if isinstance(cols_raw, list):
                        columns = [str(c) for c in cols_raw if c is not None]
        except (json.JSONDecodeError, ValueError, TypeError):
            # Message avec tool_result mal-formé — on skip et continue.
            continue

        if not rows:
            continue

        # source_ref = "iris:<conv_id>" pour cohérence avec scan-workbook
        # `scan_context="iris"` (un seul groupage UI par conversation,
        # même si plusieurs messages contribuent — c'est volontaire).
        conv_id = getattr(msg, "conversation_id", None)
        if conv_id is None:
            continue
        source_ref = f"iris:{conv_id}"

        added_in_message = 0
        try:
            async with _get_iris_session() as scan_session:
                scan_result = await scan_sql_result_terms(
                    scan_session,
                    user_id=user_id,
                    rows=rows,
                    columns=columns,
                    source_ref=source_ref,
                )
                await scan_session.commit()
                added_in_message = int(scan_result.get("added", 0) or 0)
        except Exception:  # noqa: BLE001
            logger.warning(
                "scan_iris_messages: message #%s (conv=%s) échoué (skip)",
                getattr(msg, "id", "?"),
                conv_id,
                exc_info=True,
            )
            continue

        yield {
            "step": "iris_message",
            "id": msg.id,
            "conv_id": conv_id,
            "added_in_message": added_in_message,
            "tokens_in_message": [],  # liste non exposée (DoS payload UI)
        }


async def scan_dashboard_terms(
    session: AsyncSession,
    user_id: int,
    dashboard: Dict[str, Any],
) -> Dict[str, int]:
    """Scanne un dashboard (champs textuels admin-éditables) et alimente
    ``anonymization_terms`` avec ``source="dashboard"``.

    Symétrique de :func:`scan_workbook_terms` mais pour les dashboards :
    nom, description, titres widgets, labels filtres, sujets/messages des
    envois email planifiés. Cf. :func:`extract_dashboard_terms_with_origin`
    pour la liste exhaustive des champs scannés et les exclusions
    (notamment ``data_source_config.query`` — pas scanné, noms techniques
    SQL pas PII utilisateur).

    Pas scanné non plus si ``dashboard["is_template"] = True`` (modèle
    partagé, pas de PII user spécifique — l'extracteur retourne ``{}``).

    Args:
        session: session async SQLAlchemy (fournie par le caller, p.ex.
            :func:`scan_datastore_tokens`).
        user_id: identifiant user — must > 0 sinon no-op.
        dashboard: dict shape ``{id, name, description, is_template,
            widgets: [...], filters: [...], schedules: [...]}``. Les
            attributs absents sont tolérés (extracteur fail-safe).

    Returns:
        Dict ``{"scanned": N, "added": M}`` — même contrat que
        :func:`scan_workbook_terms`.
    """
    if not is_valid_user_id(user_id):
        return {"scanned": 0, "added": 0}
    if not isinstance(dashboard, dict):
        return {"scanned": 0, "added": 0}

    # Import tardif pour cohérence avec scan_workbook_terms (évite cycle).
    from app.services.anonymization import repository as anon_repo

    origins_by_token = anon_extract.extract_dashboard_terms_with_origin(dashboard)
    if not origins_by_token:
        return {"scanned": 0, "added": 0, "tokens": []}

    # ``source_ref`` = ``dashboard.name`` cap 200 chars. Fallback ``#{id}``
    # si name vide (cas dashboard fraîchement créé, attente de rename).
    # Deux dashboards du même user avec le même name → leurs termes
    # convergent vers le même source_ref. C'est OK car l'UI groupe par
    # (source, source_ref) — l'admin verra "Tableau de bord : X" avec
    # une union des termes des deux. Le cas dégénéré (homonymie pure)
    # est rare et bénin.
    raw_name = dashboard.get("name")
    safe_ref: Optional[str] = None
    if isinstance(raw_name, str):
        trimmed = raw_name.strip()
        if trimmed:
            safe_ref = trimmed[:200]
    if safe_ref is None:
        dash_id = dashboard.get("id")
        if dash_id is not None:
            safe_ref = f"#{dash_id}"[:200]

    # Compter avant pour calculer le delta "added".
    count_before = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    terms_state: Dict[str, Dict[str, Any]] = {
        token: {"enabled": False, "confirmed": False} for token in origins_by_token
    }

    # Le champ ``origins`` réutilise la structure ``{"classeur", "col"}``
    # existante (compat UI ``privacy-page.js._subGroupByColumn``). Pour
    # un dashboard, ``classeur`` = label du dashboard (= source_ref) et
    # ``col`` = label interne du champ (ex: ``widget_3.title``).
    origins_map: Dict[str, List[Dict[str, Optional[str]]]] = {
        token: [{"classeur": safe_ref, "col": col} for col in cols]
        for token, cols in origins_by_token.items()
    }
    await anon_repo.upsert_terms(
        session,
        user_id,
        terms_state,
        source="dashboard",
        source_ref=safe_ref,
        origins_map=origins_map,
    )

    count_after = int(
        (
            await session.scalar(
                select(func.count(AnonymizationTerm.id)).where(AnonymizationTerm.user_id == user_id)
            )
        )
        or 0
    )

    # ``tokens`` exposé pour permettre à l'appelant
    # (``_scan_user_dashboards_streaming``) d'aggréger le set global
    # ``all_tokens`` retourné dans ``stats.tokens_unique``. Sans cette
    # liste, le compteur global sous-évaluerait les tokens dashboards
    # (review interne 2026-05-20 #9).
    return {
        "scanned": len(origins_by_token),
        "added": count_after - count_before,
        "tokens": list(origins_by_token.keys()),
    }


async def scan_sql_result_terms(
    session: AsyncSession,
    user_id: int,
    rows: Optional[List[Dict[str, Any]]],
    columns: Optional[List[str]] = None,
    *,
    source_ref: Optional[str] = None,
    max_rows_scan: int = 1000,
) -> Dict[str, int]:
    """Scanne des rows SQL (résultat Iris ou preview automation) et alimente
    ``anonymization_terms`` avec les tokens détectés (task #8 POINT 2/3).

    Adapter le shape SQL (``List[Dict[col -> value]]``) vers le shape attendu
    par :func:`extract_terms` (``tabs_context`` avec ``rows`` à 2 dimensions).
    On construit un tab factice pour réutiliser le tokenizer existant.

    Cap ``max_rows_scan`` (par défaut 1000) — au-delà, on tronque pour éviter
    de bloquer le request thread sur un résultat géant. Le scan tourne en
    asyncio.create_task côté caller pour non-bloquant.

    Args:
        session: session async SQLAlchemy.
        user_id: identifiant user.
        rows: List[Dict] retourné par execute_sql / preview_step. Si vide
            ou None → no-op.
        columns: liste des noms de colonnes (utilisée pour label du tab
            factice, pas pour la tokenisation). Optionnel.
        source_ref: identifiant traçable (ex: ``"iris_sql:{search_id}"`` ou
            ``"automation_preview:{step_id}"``) — stocké dans
            ``anonymization_term.source_ref`` à l'insert (pas écrasé à
            l'update via ``upsert_terms``).
        max_rows_scan: cap performance.

    Returns:
        Dict ``{"scanned": N, "added": M}``.
    """
    if not is_valid_user_id(user_id):
        return {"scanned": 0, "added": 0}
    if not rows:
        return {"scanned": 0, "added": 0}

    # Cap : tronquer si trop de rows pour éviter coût excessif côté
    # tokenizer + DB upsert. Le scan est best-effort (background task).
    rows_to_scan = rows[:max_rows_scan]

    # Construire un tab factice. ``extract_terms`` attend
    # ``tab.rows = list[list]`` (2D : rows × cells). On extrait les
    # valeurs de chaque dict dans un ordre stable (columns si fournis,
    # sinon dict.values() qui est ordonné en Python 3.7+).
    #
    # **Filtrage à la SOURCE des valeurs non-métier** (fix bug David
    # 2026-05-18 : « récupérer au bon endroit ») :
    #
    # Les résultats pyodbc SQL Server peuvent contenir des colonnes
    # techniques (``uniqueidentifier``, ``varbinary``, ``rowversion``,
    # ``timestamp``) dont les valeurs n'ont AUCUNE sémantique métier.
    # Plutôt que de les tokeniser puis filtrer en aval, on les exclut
    # ICI au moment d'extraire — c'est leur emplacement naturel
    # (équivalent à "ne pas SELECT *  RowVersion, GUID" côté SQL).
    #
    # Types Python filtrés ⇒ remplacés par ``None`` (que ``_tokenize_value``
    # skip déjà) :
    #
    # - ``bytes``, ``bytearray``, ``memoryview``       → varbinary/rowversion
    # - ``uuid.UUID``                                  → uniqueidentifier raw
    # - str matching le pattern GUID 8-4-4-4-12        → uniqueidentifier formaté
    #
    # Helper extrait au module ``extract.py`` (2026-05-20) pour single
    # source of truth scan/cleanup (invariant cleanup⊆!scan).
    _scrub = anon_extract.scrub_pyodbc_technical

    if columns:
        flat_rows = [
            [_scrub(row.get(col)) for col in columns]
            for row in rows_to_scan
            if isinstance(row, dict)
        ]
    else:
        flat_rows = [
            [_scrub(v) for v in row.values()] for row in rows_to_scan if isinstance(row, dict)
        ]
    if not flat_rows:
        return {"scanned": 0, "added": 0}

    # task #20 : on injecte ``columns`` dans le tab factice — ainsi
    # ``extract_terms_with_origin`` (via scan_workbook_terms) capture les
    # noms de colonnes SQL comme origines.
    tabs_context = [
        {
            "label": source_ref or "sql_result",
            "columns": list(columns) if columns else [],
            "rows": flat_rows,
        }
    ]

    # Fix 2026-05-20 : on propage ``source_ref`` au caller `scan_workbook_terms`
    # via ``classeur_ref`` (mapping name historique). Sans ça, tous les
    # tokens issus de scans Iris/automation arrivaient en BDD avec
    # ``source_ref=NULL`` → ungroupable côté UI /data/privacy. ``source="sql_result"``
    # explicite pour distinguer des tokens classeur.
    return await scan_workbook_terms(
        session,
        user_id=user_id,
        tabs_context=tabs_context,
        sheet_content=None,
        classeur_ref=source_ref,
        source="sql_result",
    )
