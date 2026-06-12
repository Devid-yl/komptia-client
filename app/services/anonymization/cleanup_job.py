"""Job scheduler : nettoie les ``AnonymizationTerm`` obsolètes.

Tourne quotidiennement (wiring dans ``app/main.py``). Pour chaque user
qui a au moins une entrée en BDD :

1. Scanne son datastore ``data/datastore/<user_id>/`` via
   :func:`app.services.classeur.reader.list_classeurs_sync`.
2. Parse chaque classeur ``.afz.json`` et extrait les tokens via
   :func:`app.services.anonymization.extract.extract_terms`.
3. Supprime de la BDD les termes qui n'apparaissent plus dans AUCUN
   classeur de ce user (requête ``DELETE WHERE term NOT IN (...)``).

**Conformité avec la demande utilisateur** : les termes disparus
du datastore sont retirés *sans* demande de re-confirmation (même
pour les termes ``enabled=True, confirmed=True``). Si l'utilisateur
re-crée le terme plus tard dans un autre classeur, il re-apparaîtra
comme nouveau et passera par le gate normal.

**Concurrence** : pendant qu'on lit les classeurs sur disque, l'utilisateur
peut modifier son state via ``PUT /api/anonymization/terms``. Les deux
opérations sont sérialisées par le commit SQL (WAL + row-level locks).
Le pire cas : on supprime un terme que l'utilisateur vient de ré-activer
via le panneau sans l'avoir (encore) ajouté à un classeur. Cas acceptable
— l'utilisateur re-ouvre le panneau, réajoute, c'est fini.

**Pattern sync session** : comme les autres jobs dans
:mod:`app.services.automation.scheduler`, on crée un engine SQLAlchemy
*synchrone* local pour ne pas partager l'event-loop async de Tornado.
C'est la convention du projet (ligne 382 de ``scheduler.py``).
"""

from __future__ import annotations

import json
import logging
import unicodedata
from typing import Callable, List, Optional, Set, Tuple

from sqlalchemy import select, delete, update
from sqlalchemy.orm import Session

from app.core import clock

# get_db_url ré-exposé (et passé explicitement à make_sync_engine) pour rester
# monkeypatchable par les tests (qui redirigent la BDD via patch de
# ``cleanup_job.get_db_url``).
from app.core.database import get_db_url, make_sync_engine
from app.models.anonymization_term import AnonymizationTerm

logger = logging.getLogger(__name__)


#: Type alias d'un fournisseur de tokens "actifs" pour un user. Reçoit
#: l'``user_id``, retourne un ``Set[str]`` des tokens à considérer comme
#: vivants pour le cleanup. Doit être fail-soft (raise ⇒ provider skipé,
#: les autres providers continuent — voir :func:`_active_tokens_for_user`).
TokenProvider = Callable[[int], Set[str]]


def _scan_classeurs_for_user(user_id: int) -> Tuple[Set[str], Set[str], bool]:
    """Scanne UNE FOIS le datastore d'un user, retourne ``(tokens, refs, complete)``.

    Factorisé du précédent ``_classeur_token_provider`` pour permettre au
    job cleanup de récupérer EN PLUS la liste des ``classeur_refs`` (noms
    de fichiers) sans relire les classeurs sur disque deux fois. Task #24 :
    le job a besoin des refs pour purger les origines orphelines dans
    ``AnonymizationTerm.origins``.

    **``complete`` (anti-perte RGPD silencieuse)** : ``False`` dès qu'un
    classeur PRÉSENT sur disque n'a pas pu être lu (ex : trop volumineux à
    décompresser une fois > quota admin, ou corrompu). Dans ce cas le scan
    est INCOMPLET : on ne connaît pas les tokens de ce fichier, donc le
    caller (job cleanup) DOIT s'abstenir de purger (sinon les termes de ce
    fichier seraient supprimés comme « orphelins » alors qu'ils vivent
    toujours sur disque — fuite/perte de données confidentielles). Un échec
    ponctuel diffère la purge d'un cycle (auto-résolu : si le fichier est
    vraiment supprimé, il n'est plus listé au cycle suivant → ``complete``).

    **Ne lit QUE des fichiers** — ne touche PAS la BDD.

    Returns:
        Tuple ``(tokens, classeur_refs, complete)`` :

        - ``tokens`` : union des tokens détectés dans tous les classeurs LUS.
        - ``classeur_refs`` : noms de fichiers (basenames) des classeurs LUS.
        - ``complete`` : ``True`` ssi TOUS les classeurs listés ont été lus
          avec succès. ``False`` ⇒ purge à éviter (scan partiel).
    """
    from pathlib import Path

    from app.handlers.datastore import _user_dir
    from app.services.anonymization.extract import extract_terms

    # Single source of truth pour la lecture des ``.afz.json`` : gère gzip
    # transparent (magic byte ``0x1f 0x8b``) en plus du texte brut. Sans
    # ``_load_json_sync``, l'ancienne implémentation ouvrait en mode ``"r"``
    # UTF-8 → ``UnicodeDecodeError`` sur les classeurs gzippés → le classeur
    # était attrapé silencieusement (``except OSError``) → ses tokens
    # n'entraient PAS dans ``active_tokens``. Conséquence destructrice
    # 2026-05-19 : tokens issus d'un classeur gzippé étaient considérés
    # comme orphelins par le nightly TTL → purgés de la BDD malgré qu'ils
    # restaient présents sur disque.
    from app.services.classeur.reader import _load_json_sync, list_classeurs_sync

    user_dir = _user_dir(user_id)
    if not user_dir.exists():
        # Datastore vide/inaccessible = rien à scanner = scan COMPLET (aucun
        # fichier illisible) → la purge peut procéder normalement.
        return set(), set(), True

    # include_hidden : les classeurs internes des widgets grille (``.widgets/``)
    # contiennent aussi des tokens — les ignorer ferait purger leurs termes
    # comme orphelins (perte silencieuse de pseudonymisation).
    classeurs = list_classeurs_sync(user_dir, include_hidden=True)
    active_tokens: Set[str] = set()
    active_refs: Set[str] = set()
    scan_complete = True  # passe à False si un classeur PRÉSENT est illisible
    for meta in classeurs:
        fname = meta.get("filename") if isinstance(meta, dict) else None
        if not fname:
            continue
        try:
            path = user_dir / fname
            # Double-check défensif : ``Path.is_relative_to`` (Python 3.9+)
            # est le bon pattern. ``startswith`` matche ``/data/11`` contre
            # ``/data/1`` par prefix (faux positif). ``is_relative_to``
            # utilise les parts de chemin, fail-safe par construction.
            if not path.resolve().is_relative_to(user_dir.resolve()):
                continue
            raw = _load_json_sync(path)
            # On enregistre la ref MÊME si le tabs JSON est mal formé en
            # interne — tant que le fichier existe et est listé, il est
            # "vivant" pour le grouping origines. Sa pollution interne ne
            # doit pas faire disparaître ses origines associées.
            #
            # task #24 fix finding #1 review : ``list_classeurs_sync`` fait un
            # ``rglob`` récursif qui retourne le chemin relatif (ex:
            # ``subdir/B.afz.json``) tandis que le frontend ``iris-grid.js``
            # envoie le BASENAME (``B.afz.json``) à ``scan_workbook_terms``.
            # Sans normalisation, un classeur en sous-dossier verrait toutes
            # ses origines purgées dès le premier nightly. On normalise des
            # deux côtés au basename pour aligner.
            active_refs.add(Path(fname).name)
            tabs = raw.get("tabs") if isinstance(raw, dict) else None
            if isinstance(tabs, list):
                active_tokens |= extract_terms(tabs)
        except FileNotFoundError:
            # Fichier listé mais disparu entre list et open (race avec une
            # suppression) : il est GENUINEMENT parti → ses termes peuvent
            # légitimement être purgés. N'invalide PAS la complétude du scan.
            logger.debug(
                "cleanup: classeur %s disparu pendant le scan (race delete), skip",
                fname,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            # Classeur PRÉSENT mais illisible (trop volumineux à décompresser
            # > quota, gzip corrompu, JSON invalide). On ne connaît PAS ses
            # tokens → le scan est INCOMPLET. ``scan_complete=False`` fait que
            # le job s'abstient de purger ce user ce cycle : sinon les termes
            # de CE classeur (toujours vivant sur disque) seraient supprimés
            # comme orphelins = perte silencieuse de données confidentielles
            # (RGPD). WARNING (≠ debug) pour que l'admin voie un classeur
            # durablement illisible (ex : quota à relever).
            scan_complete = False
            logger.warning(
                "cleanup: classeur %s PRÉSENT mais illisible (%s) — scan marqué "
                "incomplet, purge des termes différée pour user=%s (anti-perte RGPD)",
                fname,
                f"{type(exc).__name__}: {exc}",
                user_id,
            )

    return active_tokens, active_refs, scan_complete


def _classeur_token_provider(user_id: int) -> Set[str]:
    """Wrapper rétro-compatible — n'expose que les tokens.

    Backward-compat avec l'API ``TokenProvider`` ``(user_id) -> Set[str]``.
    Le job cleanup interne préfère :func:`_scan_classeurs_for_user` qui
    retourne aussi les refs pour la purge orphan-origins (task #24).
    """
    tokens, _refs, _complete = _scan_classeurs_for_user(user_id)
    return tokens


def _dashboard_token_provider(user_id: int) -> Set[str]:
    """Tokens vivants depuis les dashboards non-template du user.

    **Invariant** : symétrie avec :func:`scan_datastore_tokens`. Le bouton
    "Scanner mes données" alimente ``anonymization_terms`` depuis 2 sources
    (classeurs + dashboards via ``_scan_user_dashboards_streaming``). Sans
    ce provider, le nightly cleanup purgerait tout terme ``source="dashboard"``
    qui n'apparaît dans aucun classeur — l'utilisateur verrait ses termes
    disparaître puis ré-apparaître à chaque scan manuel (churn).

    **Single source of truth d'extraction** : on délègue à
    :func:`extract_dashboard_terms_with_origin` (même fonction utilisée
    par ``scan_dashboard_terms`` côté handler). Le shape du dict passé
    en entrée doit rester aligné sur ``_scan_user_dashboards_streaming``
    pour garantir l'isomorphisme des tokens extraits.

    **Skip is_template=True** : les dashboards templates ne portent pas
    de PII user spécifique (cohérent avec l'extracteur qui retourne ``{}``).

    **Session SYNC** : le job tourne dans APScheduler hors event-loop ; on
    ouvre un engine SQLAlchemy synchrone local (pattern aligné sur
    :func:`cleanup_unused_anonymization_terms_job`).
    """
    # Import tardif pour éviter le cycle module-load (cleanup → dashboard →
    # widget_planner → llm → ... au top-level). Cohérent avec
    # ``_scan_user_dashboards_streaming`` qui fait pareil.
    from sqlalchemy.orm import selectinload

    from app.models.dashboard import Dashboard, DashboardSchedule
    from app.services.anonymization.extract import (
        extract_dashboard_terms_with_origin,
    )

    engine = make_sync_engine(get_db_url())
    tokens: Set[str] = set()
    try:
        with Session(engine) as session:
            dashboards = (
                session.execute(
                    select(Dashboard)
                    .where(Dashboard.user_id == user_id)
                    .where(Dashboard.is_template.is_(False))
                    .options(
                        selectinload(Dashboard.widgets),
                        selectinload(Dashboard.filters),
                    )
                )
                .scalars()
                .all()
            )

            for dash in dashboards:
                # Schedules : pas de back_populates côté Dashboard (cf.
                # ``_scan_user_dashboards_streaming`` ligne 1036) — requête
                # explicite par dashboard_id.
                schedules = (
                    session.execute(
                        select(DashboardSchedule).where(DashboardSchedule.dashboard_id == dash.id)
                    )
                    .scalars()
                    .all()
                )

                # Construction du payload : shape strictement identique à
                # ``_scan_user_dashboards_streaming`` (single source of
                # truth d'extraction). Si on diverge ici, on extraira des
                # tokens différents → l'invariant cleanup⊆!scan casse.
                payload: dict = {
                    "id": dash.id,
                    "name": getattr(dash, "name", None),
                    "description": getattr(dash, "description", None),
                    "template_description": getattr(dash, "template_description", None),
                    "is_template": False,
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
                            "recipients": getattr(s, "recipients", None),
                        }
                        for s in schedules
                    ],
                }

                origins = extract_dashboard_terms_with_origin(payload)
                tokens.update(origins.keys())
    finally:
        engine.dispose()
    return tokens


#: Liste par défaut des providers — ordre informationnel, l'union est
#: commutative. Architecture extensible : pour brancher ``sql_result``,
#: ``contact``, etc., il suffit d'ajouter un nouveau provider à cette
#: liste (ou de passer ``providers=...`` à
#: :func:`_active_tokens_for_user`). Aucun changement requis dans le
#: corps du job.
#:
#: ``_iris_message_token_provider`` a été retiré le 2026-05-17 : la
#: tokenisation des messages Iris n'a jamais été demandée par l'utilisateur
#: (cf. ``test_iris_messages_tokenisation_removed.py``).
#:
#: ``_dashboard_token_provider`` ajouté le 2026-05-20 (symétrie avec
#: l'extension du scan datastore aux dashboards le même jour). Sans ce
#: provider, les termes ``source="dashboard"`` étaient purgés à tort par
#: le nightly cleanup malgré leur présence dans un dashboard vivant.
#:
#: ``_automation_token_provider`` + ``_iris_messages_token_provider``
#: ajoutés le 2026-05-20 (extension scan complet sans ouverture). Symétrie
#: avec scan_datastore_tokens phases 3 + 4. Sans ces providers, les
#: termes ``source="sql_result"`` (avec source_ref ``automation:N`` ou
#: ``iris:N``) étaient purgés à tort.
def _automation_token_provider(user_id: int) -> Set[str]:
    """Tokens vivants depuis les automations du user.

    Symétrie avec :func:`_scan_user_automations_streaming` : single source
    of truth d'extraction via :func:`extract_automation_terms_with_origin`.
    """
    from sqlalchemy.orm import selectinload

    from app.models.automation import Automation
    from app.models.automation_step import AutomationStep
    from app.services.anonymization.extract import (
        extract_automation_terms_with_origin,
    )

    engine = make_sync_engine(get_db_url())
    tokens: Set[str] = set()
    try:
        with Session(engine) as session:
            automations = (
                session.execute(
                    select(Automation)
                    .where(Automation.user_id == user_id)
                    .options(selectinload(Automation.steps))
                )
                .scalars()
                .all()
            )

            for auto in automations:
                steps = (
                    session.execute(
                        select(AutomationStep)
                        .where(AutomationStep.automation_id == auto.id)
                        .order_by(AutomationStep.step_order)
                    )
                    .scalars()
                    .all()
                )

                payload: dict = {
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
                origins = extract_automation_terms_with_origin(payload)
                tokens.update(origins.keys())
    finally:
        engine.dispose()
    return tokens


def _iris_messages_token_provider(user_id: int) -> Set[str]:
    """Tokens vivants depuis les résultats SQL stockés des conversations
    Iris du user.

    Cap ``_IRIS_SCAN_MAX_MESSAGES`` (200) — symétrie avec
    :func:`_scan_user_iris_messages_streaming`. Au-delà du cap, les
    messages plus anciens ne sont pas protégés ; ils retomberont dans
    le filet ``_delete_missing_for_user`` >7j naturellement (l'invariant
    cleanup⊆!scan ne s'engage que sur les sources scannables, et le
    scan lui-même est cappé).

    Parse JSON best-effort : un ``tool_result`` mal-formé est skip sans
    bloquer les autres.
    """
    from app.models.conversation import Conversation, ConversationMessage

    # Imports en haut (hors boucle) pour éviter 2M lookups sys.modules
    # sur un corpus 200 messages × 1000 rows × 10 colonnes.
    # Le ``scrub_pyodbc_technical`` est appliqué pour garantir la même
    # filtration que scan_sql_result_terms (invariant cleanup⊆!scan,
    # cf. review adversariale 2026-05-20 BLOCKING #1).
    from app.services.anonymization.extract import (
        _tokenize_value,
        scrub_pyodbc_technical,
    )

    engine = make_sync_engine(get_db_url())
    tokens: Set[str] = set()
    try:
        with Session(engine) as session:
            messages = (
                session.execute(
                    select(ConversationMessage)
                    .join(Conversation, ConversationMessage.conversation_id == Conversation.id)
                    .where(Conversation.user_id == user_id)
                    .where(ConversationMessage.tool_result.isnot(None))
                    .order_by(ConversationMessage.created_at.desc())
                    .limit(_IRIS_SCAN_MAX_MESSAGES)
                )
                .scalars()
                .all()
            )

            for msg in messages:
                raw = msg.tool_result
                if not isinstance(raw, str) or not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(parsed, dict):
                    continue
                rows = parsed.get("rows")
                if not isinstance(rows, list):
                    continue
                for row in rows[:_IRIS_ROWS_PER_MESSAGE_CAP]:
                    if not isinstance(row, dict):
                        continue
                    for v in row.values():
                        scrubbed = scrub_pyodbc_technical(v)
                        if isinstance(scrubbed, str) and scrubbed:
                            for tok in _tokenize_value(scrubbed):
                                tokens.add(tok)
    finally:
        engine.dispose()
    return tokens


#: Cap nombre de messages Iris parcourus par le provider cleanup. Doit
#: être >= ``max_messages`` du scan SSE pour préserver l'invariant — sinon
#: certains termes scannés ne seront pas protégés au cleanup.
_IRIS_SCAN_MAX_MESSAGES = 200

#: Cap nombre de rows examinées par message Iris dans le provider. Garde
#: la passe rapide sur un résultat SQL géant (les premiers 1000 rows
#: suffisent à couvrir l'écrasante majorité des valeurs uniques d'une
#: table — au-delà c'est de la pollution).
_IRIS_ROWS_PER_MESSAGE_CAP = 1000


DEFAULT_TOKEN_PROVIDERS: List[TokenProvider] = [
    _classeur_token_provider,
    _dashboard_token_provider,
    _automation_token_provider,
    _iris_messages_token_provider,
]


class AllTokenProvidersFailed(RuntimeError):
    """Tous les providers de tokens ont levé pour ce user.

    Levée par :func:`_active_tokens_for_user` quand chaque provider de
    la liste effective a raise — distinguer ce cas de "le user n'a
    aucun classeur ni message Iris (set vide légitime)" est CRITIQUE :
    ne pas lever ferait passer le job en mode "purge tout" (cf.
    :func:`_delete_missing_for_user`), ce qui supprimerait silencieusement
    tous les termes >7j même quand l'erreur est transitoire (BDD
    momentanément lockée, OS error éphémère).

    Le caller :func:`cleanup_unused_anonymization_terms_job` catch
    cette exception et skip le user (per-user fail-soft existant).
    """


def _active_tokens_for_user(
    user_id: int,
    providers: Optional[List[TokenProvider]] = None,
) -> Set[str]:
    """Retourne l'union des tokens "actifs" pour un user, agrégés sur tous
    les providers (classeurs, messages Iris, …).

    **Architecture extensible (tâche #23)** : la fonction prend une liste
    de fournisseurs ``(user_id) -> Set[str]``. Default :
    :data:`DEFAULT_TOKEN_PROVIDERS`. Pour brancher une nouvelle source
    (sql_result, contact, …), ajouter un provider à la liste — pas
    besoin de toucher le job ``cleanup_unused_anonymization_terms_job``.

    **Fail-soft par provider** : si un provider raise, on logue + skip,
    et on continue avec les autres. Sinon une erreur ponctuelle (ex:
    table ``conversation_messages`` corrompue) ferait perdre TOUS les
    tokens classeur d'un user (= suppression silencieuse).

    **Garde-fou anti mass-purge** (review adversariale 2026-05-08) :
    si TOUS les providers ont raise (échec total), on lève
    :class:`AllTokenProvidersFailed` plutôt que de retourner ``set()``.
    Sinon le caller cleanup interpréterait le set vide comme "rien
    d'actif" et supprimerait l'intégralité des termes >7j du user
    (silent data corruption).
    """
    effective = DEFAULT_TOKEN_PROVIDERS if providers is None else providers
    if not effective:
        # Liste explicite vide (callers qui veulent "0 token actif"
        # intentionnel, ex: tests ciblés). Pas de levée — sémantique
        # différente de "tous fail" (ici aucun provider à exécuter).
        return set()
    out: Set[str] = set()
    failed = 0
    for provider in effective:
        try:
            out |= provider(user_id)
        except Exception:  # noqa: BLE001 — fail-soft inter-providers
            failed += 1
            logger.warning(
                "cleanup: token provider %s a levé pour user=%s, skip",
                getattr(provider, "__name__", repr(provider)),
                user_id,
                exc_info=True,
            )
    if failed == len(effective):
        # Tous les providers ont raise — refus de purge silencieuse.
        raise AllTokenProvidersFailed(
            f"tous les providers ({failed}/{len(effective)}) ont levé "
            f"pour user_id={user_id} — refus de purge silencieuse"
        )
    return out


#: Taille max de la liste ``NOT IN`` envoyée à SQLite par chunk. Historique
#: ``SQLITE_MAX_VARIABLE_NUMBER`` = 999 ; certains builds montent à 32766
#: mais on ne peut pas présumer. 500 = marge confortable qui évite
#: ``OperationalError: too many SQL variables`` sur n'importe quel build.
_DELETE_CHUNK_SIZE = 500

#: Âge minimum d'un terme pour qu'il soit éligible à la suppression. Évite
#: de supprimer un terme que l'utilisateur vient juste d'ajouter (via menu
#: contextuel ou panneau) mais qu'il n'a pas encore sauvegardé dans un
#: classeur sur disque. 7 jours = équilibre : assez long pour laisser
#: l'user créer son classeur après un ajout manuel, assez court pour
#: que le cleanup reste efficace sur le moyen terme.
_MIN_AGE_DAYS = 7

#: TTL pour les termes ``confirmed=0 AND enabled=0`` jamais décidés par l'user.
#: 30 jours = on laisse l'user largement le temps de revoir son panneau
#: ``/data/privacy`` ; au-delà c'est du bloat (par construction le copilot
#: anonymise par défaut tout ``pending``, donc l'user n'a pas un besoin
#: opérationnel de décider — la décision est différée jusqu'à ce qu'il
#: veuille laisser passer en clair). Sans ce TTL, un user accumule
#: indéfiniment (53k+ rows mesurées prod 2026-05-19 sur user=1) et
#: dégrade les perfs des endpoints ``/api/anonymization/*`` ET du
#: copilot (cf. axe 21 Komptia — croissance non bornée).
_UNCONFIRMED_BLOAT_MAX_DAYS = 30

#: TTL pour ``anonymization_audit``. 90 jours = couverture confortable
#: pour les investigations conformité GDPR + assez court pour borner la
#: croissance (24k+ rows mesurées prod 2026-05-19). Les anciens audits
#: sont définitivement perdus — c'est volontaire (rétention minimale,
#: principe RGPD § 5.1.e "limitation de la conservation").
_AUDIT_TTL_DAYS = 90


def _delete_missing_for_user(session: Session, user_id: int, active: set) -> int:
    """Supprime les termes du user absents de ``active``, vieux de plus
    de :data:`_MIN_AGE_DAYS` — chunked pour éviter la limite SQLite.

    **Guard race condition** (fix review v3 2026-04-23) : un terme ajouté
    dans le panneau (ou via le menu contextuel "anonymiser cette cellule")
    est en BDD mais peut ne pas être encore dans un classeur persisté sur
    disque (l'user n'a pas encore sauvegardé). Sans ce filtre d'âge, le
    cleanup nocturne le supprimerait silencieusement.

    Stratégie : on lit ``(id, term, updated_at)`` pour ce user, on filtre
    en Python ceux absents ET assez âgés, puis DELETE par chunks d'ID.
    Les termes récents absents du datastore sont gardés — ils seront
    re-évalués au prochain cleanup (dans 24h).

    **Audit (2026-05-06)** : chaque suppression produit une row dans
    ``anonymization_audit`` (triggered_by=system_cleanup). Fail-soft.
    """
    from datetime import timedelta, timezone

    from app.models.anonymization_audit import AnonymizationAudit

    cutoff = clock.now() - timedelta(days=_MIN_AGE_DAYS)
    stored = session.execute(
        select(
            AnonymizationTerm.id,
            AnonymizationTerm.term,
            AnonymizationTerm.created_at,
            AnonymizationTerm.updated_at,
            AnonymizationTerm.last_seen_at,
            AnonymizationTerm.enabled,
            AnonymizationTerm.confirmed,
            AnonymizationTerm.category,
            AnonymizationTerm.risk_level,
            AnonymizationTerm.source,
        ).where(AnonymizationTerm.user_id == user_id)
    ).all()
    to_delete: list[tuple] = []  # (id, term, enabled, confirmed, category, risk_level)
    skipped_recent = 0
    skipped_user_added = 0
    for (
        row_id,
        term,
        created_at,
        updated_at,
        last_seen_at,
        enabled,
        confirmed,
        category,
        risk_level,
        source,
    ) in stored:
        # 2026-05-19 : les termes ``source="user_added"`` sont les saisies
        # volontaires de l'utilisateur via l'endpoint
        # ``POST /api/anonymization/terms/manual``. Ils ne sont PAS dans
        # le datastore par définition (l'user les a entrés à la main, pas
        # vus dans un classeur). Sans ce skip, le cleanup nightly les
        # purgerait dès qu'ils dépassent le TTL — et la feature « Ajouts
        # manuels » deviendrait inutile au-delà de 7 jours. Distinction
        # avec ``source="manual"`` (placeholder default) qui reste
        # éligible à la purge — c'est du fantôme, pas un acte explicite.
        if source == "user_added":
            skipped_user_added += 1
            continue
        if term in active:
            continue  # présent dans un classeur → on garde
        # BLOCKING #3 review repository : utiliser MAX(created_at, updated_at,
        # last_seen_at) — un terme dont l'user a vu/saisi récemment dans un
        # message Iris (last_seen_at bumpé) ne doit PAS être supprimé juste
        # parce que ses flags n'ont pas changé depuis 7+ jours.
        # 2026-05-17 : ``created_at`` ajouté pour traiter les rows pathologiques
        # avec ``updated_at=last_seen_at=NULL`` (typiquement des termes insérés
        # par un path qui ne touche pas l'ORM TimestampMixin — observé en prod
        # avec 4647 orphelins binaires accumulés). Sans ce fallback, le cleanup
        # les skip indéfiniment et ils s'accumulent → liste /data/privacy
        # polluée. ``created_at`` est ``nullable=False`` (base.py:42) donc
        # toujours présent, garantit que ``candidates`` est non-vide.
        candidates = [created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)]
        if updated_at is not None:
            candidates.append(
                updated_at if updated_at.tzinfo else updated_at.replace(tzinfo=timezone.utc)
            )
        if last_seen_at is not None:
            candidates.append(
                last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=timezone.utc)
            )
        most_recent = max(candidates)
        if most_recent < cutoff:
            to_delete.append((row_id, term, bool(enabled), bool(confirmed), category, risk_level))
        else:
            skipped_recent += 1
    if skipped_recent:
        logger.debug(
            "cleanup user=%s: %d termes trop récents conservés (âge < %d jours)",
            user_id,
            skipped_recent,
            _MIN_AGE_DAYS,
        )
    if skipped_user_added:
        logger.debug(
            "cleanup user=%s: %d termes user_added préservés (saisie volontaire)",
            user_id,
            skipped_user_added,
        )
    if not to_delete:
        return 0
    # Audit AVANT delete — pour pouvoir référencer l'id du terme avant
    # qu'il ne disparaisse. Fail-soft : un échec n'empêche pas le delete.
    try:
        audit_rows = [
            AnonymizationAudit(
                user_id=user_id,
                anonymization_term_id=row_id,
                term=term[:500],
                category=category,
                risk_level=risk_level,
                enabled=enabled,
                confirmed=confirmed,
                triggered_by="system_cleanup",
                triggered_by_user_id=None,  # job système, pas d'acteur user
                action="delete",
                changed_fields={
                    "enabled": [enabled, None],
                    "confirmed": [confirmed, None],
                },
                reason="cleanup: term not in any active workbook",
            )
            for row_id, term, enabled, confirmed, category, risk_level in to_delete
        ]
        session.add_all(audit_rows)
        session.flush(audit_rows)
    except Exception:  # noqa: BLE001 — fail-soft
        logger.warning(
            "cleanup user=%s: audit insert échoué, le delete continue",
            user_id,
            exc_info=True,
        )

    deleted_total = 0
    to_delete_ids = [row_id for row_id, *_ in to_delete]
    for i in range(0, len(to_delete_ids), _DELETE_CHUNK_SIZE):
        chunk = to_delete_ids[i : i + _DELETE_CHUNK_SIZE]
        result = session.execute(delete(AnonymizationTerm).where(AnonymizationTerm.id.in_(chunk)))
        deleted_total += result.rowcount or 0
    return deleted_total


def _purge_orphan_origins_for_user(
    session: Session,
    user_id: int,
    active_classeur_refs: Set[str],
) -> int:
    """Purge les origines ``(classeur, col)`` orphelines des termes du user
    (task #24).

    Un classeur supprimé/renommé laisse ses origines dans la colonne JSON
    ``AnonymizationTerm.origins`` à perpétuité (cf. merge BDD+batch dans
    ``upsert_terms`` Phase 3/5 task #20). Sans purge :

    - Liste qui grossit indéfiniment (cap 5000 chars finit par tronquer
      les origines récentes alphabétiquement plus loin — finding #3
      review adversariale task #20).
    - UI ``/data/privacy`` qui affiche des sous-groupes "Classeur : X"
      qui n'existe plus du datastore.

    **Garde-fou anti mass-purge critique** : si ``active_classeur_refs``
    est vide (datastore vide OU `_scan_classeurs_for_user` retour set()
    pour une raison transitoire), on SKIP la purge — sinon on
    nullifierait toutes les origines workbook du user. Le caller doit
    donc passer un set vide UNIQUEMENT si le datastore est légitimement
    vide ; mais on couvre quand même côté défense-en-profondeur ici.

    Les origines avec ``classeur=None`` (tab label, drill-down, sql_result
    sans classeur) sont préservées — elles ne sont pas attribuées à un
    classeur identifiable.

    Si après purge un term n'a plus aucune origine, on UPDATE ``origins
    = NULL`` (libère 5000 char de stockage, frontend retombe sur le
    sous-groupe "Autres / sans colonne" du classeur courant).

    Args:
        session: session SQLAlchemy sync (caller commit en sortie).
        user_id: utilisateur cible.
        active_classeur_refs: set des basenames de classeurs vivants
            (cf. :func:`_scan_classeurs_for_user`).

    Returns:
        Nombre de termes dont les ``origins`` ont été modifiées.
    """
    # Import tardif pour briser le cycle module-load (repository importe
    # extract, qui peut être en cours d'import depuis cleanup).
    from app.services.anonymization.repository import (
        _parse_origins,
        _serialize_origins,
    )

    # Garde-fou anti mass-purge : datastore vide ⇒ ne pas nullifier les
    # origines workbook de l'user (l'absence de classeur peut être une
    # erreur transitoire OU un user légitimement vide ; dans les deux cas
    # on ne touche pas pour éviter une perte silencieuse).
    if not active_classeur_refs:
        logger.debug(
            "purge_orphan_origins user=%s: skip (active_classeur_refs vide)",
            user_id,
        )
        return 0

    # Ne charger QUE les termes avec origins non-NULL — limite la passe
    # aux candidats réels (rétro-compat : rows pré-task #20 ont origins
    # NULL, donc filtrées d'office). Lecture par lot mais one-shot ici :
    # même 50K termes × ~5KB origins = 250MB max RAM, acceptable pour un
    # job nightly. Si ça devenait un problème : streamer par batches via
    # ``yield_per``.
    rows = session.execute(
        select(AnonymizationTerm.id, AnonymizationTerm.origins).where(
            AnonymizationTerm.user_id == user_id,
            AnonymizationTerm.origins.isnot(None),
        )
    ).all()

    # task #29 — Comparaison case-insensitive Unicode-aware via NFKC
    # casefold. Pourquoi : un classeur stocké en BDD avec la casse
    # "Bilan.afz.json" mais renommé sur disque (via FS ou via l'app) en
    # "bilan.afz.json" apparaîtrait orphelin sur Linux Docker (case-sensitive
    # FS) alors qu'il est légitime. macOS APFS est case-insensitive par défaut
    # → divergence silencieuse entre dev (Mac) et prod (Docker Linux).
    # Pré-calcul une fois ; le casefold est ~O(n_chars) donc trivial.
    # NB : volontairement accent-SENSIBLE ici (≠ ``_canonical_key`` sur les
    # *termes*, devenu accent-insensible le 2026-06-09) — ce sont des NOMS DE
    # FICHIERS : fusionner "café.afz.json" et "cafe.afz.json" provoquerait une
    # fausse détection d'orphelin (deux fichiers distincts sur le FS).
    active_normalized = {
        unicodedata.normalize("NFKC", ref).casefold()
        for ref in active_classeur_refs
        if isinstance(ref, str)
    }

    updated = 0
    for row_id, origins_json in rows:
        # task #24 fix finding #6 review : distinguer JSON corrompu /
        # liste vide légitime ``"[]"`` / set vide après normalize. Tous
        # ces cas méritent ``origins=NULL`` (libère la colonne) mais
        # SEUL le cas "ce term avait des origines vraiment, on les a
        # purgées" compte comme ``updated``. Sinon les métriques nightly
        # gonflent artificiellement.
        raw_was_empty_list = False
        if isinstance(origins_json, str) and origins_json.strip() in ("[]", ""):
            raw_was_empty_list = True
        parsed = _parse_origins(origins_json)
        if not parsed:
            # Cas "rien à purger" : nullifier en silence (no metric).
            # On reste tolérant aux JSON corrompus historiques sans gonfler
            # le compteur ``origins_purged`` qui doit refléter de vraies
            # purges de classeurs orphelins.
            session.execute(
                update(AnonymizationTerm)
                .where(
                    AnonymizationTerm.id == row_id,
                    AnonymizationTerm.user_id == user_id,
                )
                .values(origins=None)
            )
            if not raw_was_empty_list:
                # JSON corrompu (différent d'un ``"[]"`` légitime) — on
                # compte comme purge "défensive" pour traçabilité log.
                updated += 1
            continue

        # Filtrage : on garde les origines avec ``classeur=None`` (jamais
        # orphelines par construction) OU dont le classeur est dans la
        # liste vivante (comparaison case-insensitive Unicode-aware,
        # task #29). On retire les orphelines.
        kept = {
            (classeur, col)
            for classeur, col in parsed
            if classeur is None
            or unicodedata.normalize("NFKC", classeur).casefold() in active_normalized
        }

        if kept == parsed:
            # Aucune origine orpheline pour ce term — pas d'UPDATE inutile.
            continue

        new_serialized = _serialize_origins(kept)  # None si kept est vide
        # task #24 fix finding #3 review : defense-in-depth ``user_id``
        # dans le WHERE de l'UPDATE — le SELECT filtre déjà mais une
        # collision d'``id`` future (restore partiel BDD, seed test
        # malicieux) écrirait sur un autre user. Axe Komptia 18
        # (isolation users) appliqué à chaque couche.
        session.execute(
            update(AnonymizationTerm)
            .where(
                AnonymizationTerm.id == row_id,
                AnonymizationTerm.user_id == user_id,
            )
            .values(origins=new_serialized)
        )
        updated += 1

    if updated:
        logger.debug(
            "purge_orphan_origins user=%s: %d termes modifiés (active_refs=%d)",
            user_id,
            updated,
            len(active_classeur_refs),
        )
    return updated


#: Termes structurellement invalides (impossibles à venir d'une cellule
#: métier légitime). Suppression SANS gate d'âge — ils ne peuvent jamais
#: être un "ajout manuel récent" légitime.
#:
#: - **GUID complet** (uniqueidentifier SQL Server 8-4-4-4-12) : technique.
#: - **Fragment hex** 8 ou 12 chars : reliquat d'un GUID fragmenté avant
#:   le fix tokenizer 2026-05-19.
#: - **Repr Python de bytes** : signature ``\\xHH`` littéral (4 chars
#:   backslash-x-hex-hex), issu d'un ``str(b'\\x..')`` dans
#:   ``handlers/iris.py:_json_safe_default`` (avant fix 2026-05-19).
#: - **Control C0/C1 chars** : bytes binaires mal-décodés (rare).
import re as _re

_INVALID_GUID_FULL_RE = _re.compile(
    r"^\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\s*$"
)
_INVALID_HEX_FRAGMENT_LENS = {8, 12}
_INVALID_HEX_FRAGMENT_RE = _re.compile(r"^[0-9a-fA-F]+$")
_INVALID_BACKSLASH_X_RE = _re.compile(r"\\x[0-9a-fA-F]{2}")


def _is_structurally_invalid_term(term: str) -> bool:
    """Retourne True si le terme est structurellement invalide (jamais
    légitime, indépendamment de son âge). Purge directe au cleanup."""
    if not isinstance(term, str) or not term:
        return True
    # Repr Python d'un bytes : la signature `\xHH` littérale (= 4 chars
    # backslash-x-hex-hex) prouve un str(b'...') quelque part en amont.
    if _INVALID_BACKSLASH_X_RE.search(term):
        return True
    # GUID complet : technique, jamais métier.
    if _INVALID_GUID_FULL_RE.match(term):
        return True
    # Fragment hex 8/12 chars (issu d'un GUID splitté pré-fix tokenizer).
    if len(term) in _INVALID_HEX_FRAGMENT_LENS and _INVALID_HEX_FRAGMENT_RE.match(term):
        return True
    # Control C0 (sauf tab/LF/CR) ou C1 — jamais en texte business.
    for ch in term:
        cp = ord(ch)
        if cp < 0x20 and cp not in (0x09, 0x0A, 0x0D):
            return True
        if 0x7F <= cp <= 0x9F:
            return True
    return False


def _purge_invalid_terms_for_user(
    session: Session,
    user_id: int,
    active_tokens: Optional[Set[str]] = None,
) -> int:
    """Purge SANS gate d'âge les termes structurellement invalides
    (GUID, repr bytes, fragments hex, control chars).

    Différent de :func:`_delete_missing_for_user` qui filtre par âge
    pour éviter de supprimer des termes fraîchement saisis par l'user
    et pas encore présents en classeur. Ici les termes invalides ne
    peuvent JAMAIS être une saisie légitime — la garde d'âge ne
    s'applique pas.

    **Exception ``source="user_added"``** : un identifiant client
    légitime peut avoir la FORME d'un GUID (ex: Stripe customer-id,
    object-id Microsoft Graph) ou d'un fragment hex 8 chars (commit
    SHA, code couleur). Si l'utilisateur l'a ajouté explicitement
    via le modal ``/data/privacy``, on respecte sa décision et on
    ne purge pas — sinon la feature « Ajouts manuels » serait
    incompatible avec les identifiants techniques sensibles.
    Cohérent avec ``_delete_missing_for_user`` qui skip aussi
    ``user_added``.

    **Invariant cleanup⊆!scan (2026-05-20)** : si ``active_tokens``
    est fourni et que le terme y figure, on le PRÉSERVE même s'il
    matche un pattern "invalide". Garantit que le bouton "Scanner
    mes données" et le nightly cleanup convergent vers le même set.
    Exemples concrets : un dashboard qui contient un commit SHA 8
    chars, un classeur avec un code couleur ``A1B2C3D4`` — patterns
    "hex 8 chars" mais légitimes si la source les contient. La purge
    structurelle ne s'applique alors qu'aux résidus historiques (BDD
    polluée par d'anciens bytes mal-décodés dont le classeur d'origine
    n'existe plus).

    ``active_tokens=None`` (legacy) ≡ ``set()`` : aucune protection
    par source, purge selon le seul critère structurel. Conservé pour
    rétro-compat des call sites isolés (tests, scripts ad-hoc) qui
    ne calculent pas les tokens vivants.

    Retourne le nombre de termes supprimés.
    """
    rows = session.execute(
        select(
            AnonymizationTerm.id,
            AnonymizationTerm.term,
            AnonymizationTerm.source,
        ).where(AnonymizationTerm.user_id == user_id)
    ).all()
    safe_active: Set[str] = active_tokens if active_tokens is not None else set()
    to_delete: list[int] = []
    for row_id, term, source in rows:
        if source == "user_added":
            continue
        if term in safe_active:
            # Invariant cleanup⊆!scan : la source contient encore ce
            # terme → on respecte le scan, peu importe la forme.
            continue
        if _is_structurally_invalid_term(term):
            to_delete.append(row_id)

    if not to_delete:
        return 0

    deleted_total = 0
    for i in range(0, len(to_delete), _DELETE_CHUNK_SIZE):
        chunk = to_delete[i : i + _DELETE_CHUNK_SIZE]
        result = session.execute(delete(AnonymizationTerm).where(AnonymizationTerm.id.in_(chunk)))
        deleted_total += result.rowcount or 0
    return deleted_total


def _purge_unconfirmed_bloat_for_user(
    session: Session,
    user_id: int,
    active_tokens: Optional[Set[str]] = None,
) -> int:
    """Purge les termes ``confirmed=0 AND enabled=0`` plus vieux que
    :data:`_UNCONFIRMED_BLOAT_MAX_DAYS` ET absents des sources vivantes.

    **Invariant cleanup⊆!scan (2026-05-20)** : si ``active_tokens`` est
    fourni et que le terme y figure, on le PRÉSERVE — peu importe son
    âge ou son état décisionnel. Le bouton "Scanner mes données" et le
    nightly cleanup doivent converger : si la source contient encore
    le terme, le scan le re-créerait immédiatement → churn nightly.

    **Compromis avec la croissance non bornée** : la doctrine "single
    source of truth = sources de données" l'emporte sur le bornage de
    taille de table. Si un user a 53k cellules dans un classeur ouvert,
    il aura 53k termes — la solution est d'optimiser les requêtes
    ``/data/privacy``, pas de purger silencieusement les termes encore
    visibles dans le classeur. Le bloat 30j ne s'active désormais que
    pour les termes qui ne sont **plus** dans les sources (cas
    indistinguable de ``_delete_missing_for_user`` >7j, donc la
    fonction devient un filet de sécurité — utile uniquement quand
    `_delete_missing_for_user` a été skippé pour une raison ou une
    autre, par ex. tous les providers ont raise).

    **Exception ``source="user_added"``** : saisie volontaire — exemptée
    comme pour les autres purges (cohérence avec
    :func:`_delete_missing_for_user` et :func:`_purge_invalid_terms_for_user`).

    **Audit trail** : chaque suppression produit une row
    ``anonymization_audit`` (triggered_by="system_cleanup_bloat_30d")
    AVANT delete. Explicabilité RGPD : un user qui se demande "où sont
    passés mes termes" peut retrouver la trace de chaque purge.
    Fail-soft (un échec audit n'empêche pas le delete).

    ``active_tokens=None`` (legacy) ≡ ``set()`` : aucune protection
    par source. Conservé pour rétro-compat des call sites isolés
    (tests, scripts ad-hoc).

    Retourne le nombre de termes supprimés.
    """
    from datetime import timedelta, timezone

    from app.models.anonymization_audit import AnonymizationAudit

    cutoff = clock.now() - timedelta(days=_UNCONFIRMED_BLOAT_MAX_DAYS)
    rows = session.execute(
        select(
            AnonymizationTerm.id,
            AnonymizationTerm.term,
            AnonymizationTerm.created_at,
            AnonymizationTerm.updated_at,
            AnonymizationTerm.last_seen_at,
            AnonymizationTerm.source,
            AnonymizationTerm.category,
            AnonymizationTerm.risk_level,
        )
        .where(AnonymizationTerm.user_id == user_id)
        .where(AnonymizationTerm.confirmed.is_(False))
        .where(AnonymizationTerm.enabled.is_(False))
    ).all()

    safe_active: Set[str] = active_tokens if active_tokens is not None else set()

    # Tuple complet pour pouvoir auditer chaque delete (cf. pattern
    # _delete_missing_for_user) : (id, term, category, risk_level).
    to_delete: list[tuple] = []
    for row_id, term, created_at, updated_at, last_seen_at, source, category, risk in rows:
        if source == "user_added":
            continue
        if term in safe_active:
            # Invariant cleanup⊆!scan : le terme est encore présent dans
            # une source vivante (classeur ou dashboard). Le scan le
            # re-créerait — on respecte la source de vérité.
            continue
        # Comme dans ``_delete_missing_for_user``, on prend MAX(created,
        # updated, last_seen) : un terme dont l'user vient juste de toucher
        # le ``last_seen`` ne doit pas être purgé même s'il est confirmed=0.
        candidates = [created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)]
        if updated_at is not None:
            candidates.append(
                updated_at if updated_at.tzinfo else updated_at.replace(tzinfo=timezone.utc)
            )
        if last_seen_at is not None:
            candidates.append(
                last_seen_at if last_seen_at.tzinfo else last_seen_at.replace(tzinfo=timezone.utc)
            )
        if max(candidates) < cutoff:
            to_delete.append((row_id, term, category, risk))

    if not to_delete:
        return 0

    # Audit AVANT delete (fail-soft, identique à _delete_missing_for_user).
    try:
        audit_rows = [
            AnonymizationAudit(
                user_id=user_id,
                anonymization_term_id=row_id,
                term=term[:500] if term else "",
                category=category,
                risk_level=risk,
                enabled=False,
                confirmed=False,
                triggered_by="system_cleanup_bloat_30d",
                triggered_by_user_id=None,
                action="delete",
                changed_fields={
                    "enabled": [False, None],
                    "confirmed": [False, None],
                },
                reason=(
                    "cleanup_bloat: term unconfirmed+disabled for "
                    f"more than {_UNCONFIRMED_BLOAT_MAX_DAYS}d"
                ),
            )
            for row_id, term, category, risk in to_delete
        ]
        session.add_all(audit_rows)
        session.flush(audit_rows)
    except Exception:  # noqa: BLE001 — fail-soft
        logger.warning(
            "cleanup bloat user=%s: audit insert échoué, le delete continue",
            user_id,
            exc_info=True,
        )

    deleted_total = 0
    to_delete_ids = [row_id for row_id, *_ in to_delete]
    for i in range(0, len(to_delete_ids), _DELETE_CHUNK_SIZE):
        chunk = to_delete_ids[i : i + _DELETE_CHUNK_SIZE]
        result = session.execute(delete(AnonymizationTerm).where(AnonymizationTerm.id.in_(chunk)))
        deleted_total += result.rowcount or 0
    return deleted_total


def _purge_old_audit_for_user(session: Session, user_id: int) -> int:
    """Purge les rows ``anonymization_audit`` plus vieilles que
    :data:`_AUDIT_TTL_DAYS` pour ce user.

    Bornes la croissance de la table audit (24k+ rows mesurées prod
    2026-05-19 sur user=1). Aligné sur le principe RGPD de limitation
    de la conservation (§ 5.1.e) : on garde 90 jours pour les
    investigations conformité, au-delà = supprimé.

    Pas d'exception ``user_added`` ici : l'audit est lui-même la trace
    de l'action user, on ne la classifie pas par source d'origine.

    Retourne le nombre de rows supprimées.
    """
    from datetime import timedelta

    from app.models.anonymization_audit import AnonymizationAudit

    cutoff = clock.now() - timedelta(days=_AUDIT_TTL_DAYS)
    result = session.execute(
        delete(AnonymizationAudit)
        .where(AnonymizationAudit.user_id == user_id)
        .where(AnonymizationAudit.created_at < cutoff)
    )
    return int(result.rowcount or 0)


def cleanup_unused_anonymization_terms_job() -> None:
    """Job scheduler — version SYNC, appelé par APScheduler.

    Flow :

    1. ``SELECT DISTINCT user_id FROM anonymization_terms`` — ne scanne
       que les users qui ont des termes, évite d'ouvrir le datastore de
       tous les users du système pour rien.
    2. Pour chaque user, dans UNE NOUVELLE SESSION (isolation):
       a. Calcule l'``active_tokens`` (lit les classeurs sur disque).
       b. ``DELETE WHERE id IN (...)`` par chunks (évite SQLite var limit).
       c. Commit par user — si le user N échoue, les users 0..N-1 sont
          déjà persistés, les users N+1..∞ s'exécuteront quand même.

    **Pourquoi une session par user** (fix 2026-04-23) : une session
    partagée avec ``session.rollback()`` sur échec d'un user annulerait
    TOUS les deletes des users précédents dans la même transaction. Bug
    de silent data corruption rattrapé en review adversariale.

    Silencieux sur erreur par user — un crash sur un user ne doit pas
    empêcher le cleanup des autres. Le log niveau ``error`` émet un
    snapshot exception pour investigation sans exposer de PII.
    """
    engine = make_sync_engine(get_db_url())
    total_deleted = 0
    users_scanned = 0
    users_skipped_incomplete = 0  # scan classeur partiel → purge différée (anti-perte RGPD)
    try:
        # Première session courte : juste pour lister les user_ids.
        with Session(engine) as session:
            user_ids = session.execute(select(AnonymizationTerm.user_id).distinct()).scalars().all()

        for uid in user_ids:
            users_scanned += 1
            # UNE session par user → commit / rollback indépendants. Fenêtre
            # de lock SQLite minimale, isolation entre users garantie.
            try:
                # task #24 : si la config de providers standard inclut
                # ``_classeur_token_provider``, on factorise le scan
                # disque pour récupérer aussi les ``classeur_refs`` (utiles
                # à la purge orphan-origins) sans relire 2× les classeurs.
                # Sinon (test patché / config custom) on respecte la liste
                # effective via ``_active_tokens_for_user`` — pas de purge
                # orphan dans ce cas (pas de refs fiables disponibles).
                classeur_refs: Set[str] = set()
                # ``scan_complete`` : si un classeur présent est illisible, le
                # scan est partiel → on s'abstient de purger ce user (anti-perte
                # RGPD). True par défaut pour le chemin sans scan classeur direct.
                scan_complete = True
                if _classeur_token_provider in DEFAULT_TOKEN_PROVIDERS:
                    tokens, classeur_refs, scan_complete = _scan_classeurs_for_user(int(uid))
                    extra_providers = [
                        p for p in DEFAULT_TOKEN_PROVIDERS if p is not _classeur_token_provider
                    ]
                    if extra_providers:
                        try:
                            tokens |= _active_tokens_for_user(int(uid), providers=extra_providers)
                        except AllTokenProvidersFailed:
                            # On a au moins ``_scan_classeurs_for_user`` ;
                            # extra providers tous KO = on continue avec
                            # ce qu'on a.
                            logger.debug(
                                "cleanup user=%s: extra providers tous KO, "
                                "on continue avec tokens classeur",
                                uid,
                            )
                else:
                    # ``AllTokenProvidersFailed`` remonte ici → caught par
                    # le ``except Exception`` du for loop → user skip
                    # (garde anti mass-purge préservée).
                    tokens = _active_tokens_for_user(int(uid))

                if not scan_complete:
                    # Scan classeur INCOMPLET (un fichier présent illisible) :
                    # on connaît un sous-ensemble seulement des tokens/refs actifs.
                    # Purger maintenant supprimerait les termes du fichier illisible
                    # comme orphelins = perte RGPD silencieuse. On DIFFÈRE toutes
                    # les purges basées sur tokens/refs pour ce user ce cycle.
                    # (Le purge d'audit, indépendant et borné par l'âge, n'est PAS
                    # concerné — mais par simplicité et prudence on skip tout le
                    # bloc de purge ; l'audit sera purgé au prochain cycle complet.)
                    logger.warning(
                        "cleanup user=%s: scan classeur incomplet (fichier illisible) "
                        "→ purge différée ce cycle (anti-perte RGPD)",
                        uid,
                    )
                    users_skipped_incomplete += 1
                    continue
                with Session(engine) as session_u:
                    deleted = _delete_missing_for_user(session_u, int(uid), tokens)
                    purged = _purge_orphan_origins_for_user(session_u, int(uid), classeur_refs)
                    # Invariant cleanup⊆!scan : on passe ``tokens`` aux
                    # 2 purges (invalid + bloat) pour qu'elles respectent
                    # la même règle que `_delete_missing_for_user` —
                    # ne pas supprimer un terme encore présent dans une
                    # source vivante (classeur ou dashboard).
                    invalid_purged = _purge_invalid_terms_for_user(
                        session_u, int(uid), active_tokens=tokens
                    )
                    bloat_purged = _purge_unconfirmed_bloat_for_user(
                        session_u, int(uid), active_tokens=tokens
                    )
                    audit_purged = _purge_old_audit_for_user(session_u, int(uid))
                    session_u.commit()
                total_deleted += deleted + invalid_purged + bloat_purged
                if deleted or purged or invalid_purged or bloat_purged or audit_purged:
                    logger.info(
                        "cleanup anonymization user=%s deleted=%d "
                        "origins_purged=%d invalid_purged=%d "
                        "bloat_purged=%d audit_purged=%d "
                        "(active_tokens=%d, classeurs=%d)",
                        uid,
                        deleted,
                        purged,
                        invalid_purged,
                        bloat_purged,
                        audit_purged,
                        len(tokens),
                        len(classeur_refs),
                    )
            except Exception:  # noqa: BLE001 — per-user fail-soft
                logger.error(
                    "cleanup anonymization user=%s: échec, skip",
                    uid,
                    exc_info=True,
                )
    except Exception:  # noqa: BLE001 — jamais de raise au scheduler
        logger.error("cleanup_unused_anonymization_terms_job: erreur globale", exc_info=True)
    finally:
        engine.dispose()

    logger.info(
        "cleanup_unused_anonymization_terms_job done: users=%d deleted=%d skipped_incomplete=%d",
        users_scanned,
        total_deleted,
        users_skipped_incomplete,
    )
