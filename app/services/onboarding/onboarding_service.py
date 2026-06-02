"""Service d'onboarding — UPSERT atomiques + lecture d'état + gestion du
singleton de setup admin.

Doctrine sénior :

1. **Concurrence multi-onglets**. Les écritures sur ``user_onboarding_progress``
   passent par ``sqlite_insert(...).on_conflict_do_update(...)`` qui est
   atomique au niveau de la row sur SQLite. Deux onglets du même utilisateur
   qui finissent simultanément le même tour produisent une seule ligne avec
   les deux horodatages cohérents — pas de doublon, pas d'``IntegrityError``
   propagée vers le handler.

2. **Préservation des champs existants au UPSERT**. ``start_tour`` ne met à
   jour que ``started_at`` ; il ne réinitialise pas ``last_step_seen`` ni
   n'écrase ``completed_at`` ou ``skipped_at``. Idem pour ``complete_tour``
   et ``skip_tour`` : chaque opération ne touche que son propre champ. Cela
   permet le rejouage idempotent et autorise les séquences inhabituelles
   (skip puis complete, etc.) sans perte d'historique.

3. **Lazy-create du résumé d'activité**. ``get_user_state`` retourne le
   résumé en le créant à la volée si absent. Pas de backfill au boot — le
   premier appel HTTP authentifié d'un user existant le matérialise. Coût :
   un INSERT + un SELECT, négligeable.

4. **Validation au boundary**. ``validate_tour_key`` / ``validate_step`` /
   ``validate_milestone`` sont les seuls points où on accepte du input
   utilisateur. Échec → ``OnboardingValidationError`` (mappée en HTTP 400
   par le handler). Aucune valeur arbitraire ne traverse vers SQL.

5. **Whitelist explicite pour ``milestone``**. Le mapping
   ``MILESTONE_TO_FIELD`` est la SEULE source de vérité pour traduire le
   nom de jalon (« database » côté UI) en nom de colonne SQL
   (« database_configured_at »). Tout milestone hors whitelist est refusé
   — défense en profondeur contre une injection de nom de colonne.

6. **Singleton tenant setup**. ``get_or_create_tenant_setup`` crée la
   ligne ``id=1`` à la première lecture (idempotent grâce à
   ``on_conflict_do_nothing``). La ``CheckConstraint("id = 1")`` côté
   schéma rejette tout id différent.
"""

from __future__ import annotations

import re
from datetime import datetime
from app.core import clock
from typing import Final, Mapping, Optional

from sqlalchemy import delete, func, literal, select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant_setup_progress import (
    SINGLETON_ROW_ID,
    TENANT_SETUP_MILESTONE_FIELDS,
    TenantSetupProgress,
)
from app.models.user_activity_summary import UserActivitySummary
from app.models.user_onboarding_progress import UserOnboardingProgress


class OnboardingValidationError(ValueError):
    """Erreur de validation des inputs onboarding — mappée en HTTP 400."""


# Longueur max alignée sur ``UserOnboardingProgress.tour_key`` (``String(64)``).
_TOUR_KEY_MAX_LEN: Final[int] = 64

# Caractères autorisés dans un ``tour_key`` : alphanumérique ASCII + underscore.
# Souple pour permettre l'ajout de tours sans toucher au code, strict pour
# bloquer toute injection (espaces, slashes, guillemets, ponctuation).
_TOUR_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_]{1,64}$")

# Borne haute sur ``last_step_seen``. Garde-fou contre un client buggué ou
# malveillant qui enverrait 999_999 — la valeur est purement informative,
# limiter à 100 reste très large par rapport aux tours réels (3-4 étapes).
_STEP_MAX: Final[int] = 100

#: Croissance bornée (axe 21) — cap du nombre de tours DISTINCTS par utilisateur.
#: ``tour_key`` est format-validé (ASCII/longueur) mais PAS membre d'une whitelist
#: (les tours sont définis côté JS ``onboarding-tour.js``, pas de SSoT backend —
#: ajouter une liste hardcodée violerait la généricité + dupliquerait le JS). Sans
#: cap, un utilisateur authentifié scripté pourrait créer N rows
#: ``user_onboarding_progress`` via N ``tour_key`` bidons. 50 >> les ~8 tours réels
#: (marge x6 pour les futurs tours), tout en bloquant la pollution de masse.
_MAX_DISTINCT_TOURS_PER_USER: Final[int] = 50

#: Mapping ``nom_milestone_externe`` → ``nom_colonne_BDD``. Whitelist stricte :
#: seuls ces noms sont acceptés par ``set_milestone``. L'ordre suit
#: ``TENANT_SETUP_MILESTONE_FIELDS`` (= ordre UI du bandeau).
MILESTONE_TO_FIELD: Final[Mapping[str, str]] = {
    "welcome": "welcome_seen_at",
    "database": "database_configured_at",
    "llm": "llm_configured_at",
    "smtp": "smtp_configured_at",
    "first_user": "first_user_invited_at",
}

# Garde de cohérence : si on ajoute un milestone côté modèle, on doit
# l'ajouter ici aussi. Une asymétrie casserait silencieusement
# ``is_complete`` (qui lit ``TENANT_SETUP_MILESTONE_FIELDS``).
# Vérification par ``raise`` plutôt que ``assert`` car ``python -O`` strippe
# les ``assert`` — silencieux en production stricte.
if set(MILESTONE_TO_FIELD.values()) != set(TENANT_SETUP_MILESTONE_FIELDS):
    raise RuntimeError(
        "MILESTONE_TO_FIELD désaligné de TENANT_SETUP_MILESTONE_FIELDS — "
        "ajouter le jalon manquant au mapping."
    )


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------


def validate_tour_key(value: object) -> str:
    """Valide et retourne un ``tour_key`` sain.

    Refuse : non-string, vide, > 64 chars, caractères hors ``[A-Za-z0-9_]``.
    """
    if not isinstance(value, str):
        raise OnboardingValidationError("tour_key doit être une chaîne")
    stripped = value.strip()
    if not stripped:
        raise OnboardingValidationError("tour_key vide")
    if len(stripped) > _TOUR_KEY_MAX_LEN:
        raise OnboardingValidationError(f"tour_key trop long (max {_TOUR_KEY_MAX_LEN} caractères)")
    if not _TOUR_KEY_PATTERN.match(stripped):
        raise OnboardingValidationError(
            "tour_key invalide (autorisé : lettres ASCII, chiffres, underscore)"
        )
    return stripped


def validate_step(value: object) -> int:
    """Valide et retourne un ``last_step_seen`` sain (entier 0..99)."""
    if isinstance(value, bool):  # bool est sous-classe de int — refus explicite.
        raise OnboardingValidationError("step doit être un entier")
    if not isinstance(value, int):
        raise OnboardingValidationError("step doit être un entier")
    if value < 0:
        raise OnboardingValidationError("step doit être positif ou nul")
    if value >= _STEP_MAX:
        raise OnboardingValidationError(f"step doit être inférieur à {_STEP_MAX}")
    return value


def validate_milestone(value: object) -> str:
    """Valide et retourne un nom de milestone sain (membre de la whitelist)."""
    if not isinstance(value, str):
        raise OnboardingValidationError("milestone doit être une chaîne")
    if value not in MILESTONE_TO_FIELD:
        allowed = ", ".join(sorted(MILESTONE_TO_FIELD))
        raise OnboardingValidationError(f"milestone inconnu (valeurs autorisées : {allowed})")
    return value


# -----------------------------------------------------------------------------
# Helpers internes
# -----------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Timestamp UTC-aware — partagé par les UPSERT pour cohérence intra-call.

    Délègue à la source unique :func:`app.core.clock.now` (alias local conservé,
    ~8 appelants dans ce module).
    """
    return clock.now()


def _coalesce_existing(column: str, new_value: datetime):
    """SQL ``COALESCE(<table>.<column>, <new_value>)`` pour preserves-on-conflict.

    Permet à ``set_=`` du UPSERT de ne mettre à jour la colonne QUE si elle
    est actuellement ``NULL`` côté BDD — sinon on conserve la valeur
    existante. Indispensable pour respecter le contrat d'idempotence
    (« premier complete gagne », « premier skip gagne »).
    """
    table = UserOnboardingProgress.__table__
    return func.coalesce(table.c[column], literal(new_value))


def _max_step(column: str, new_value: int):
    """SQL ``MAX(<table>.<column>, <new_value>)`` pour la monotonie du step.

    Utilisé dans ``record_step`` pour garantir que ``last_step_seen`` ne
    régresse jamais — un client qui renverrait un step inférieur (refresh
    navigateur, réinitialisation client, race condition d'envoi) ne doit
    pas faire perdre la progression. Toujours le MAX entre l'existant et
    la nouvelle valeur.
    """
    table = UserOnboardingProgress.__table__
    return func.max(table.c[column], literal(new_value))


async def _upsert_tour(
    session: AsyncSession,
    *,
    user_id: int,
    tour_key: str,
    insert_values: dict,
    update_set: dict,
) -> UserOnboardingProgress:
    """UPSERT atomique sur ``user_onboarding_progress``.

    ``insert_values`` est utilisé si la ligne n'existe pas. ``update_set``
    est appliqué si elle existe — il ne contient QUE les colonnes que
    l'opération courante doit toucher (preserves ``last_step_seen``,
    ``completed_at``, etc. selon l'opération).

    Croissance bornée (axe 21, C2-F1) : si ``tour_key`` n'existe pas encore
    pour cet utilisateur (ce serait un INSERT) ET qu'il a déjà atteint
    ``_MAX_DISTINCT_TOURS_PER_USER`` tours distincts, on refuse (400). Les
    tours existants (vrais) continuent à s'UPDATE sans limite. Borne soft :
    une légère course concurrente peut laisser passer quelques rows en plus,
    sans importance pour un garde anti-pollution.
    """
    already_exists = (
        await session.execute(
            select(UserOnboardingProgress.id).where(
                UserOnboardingProgress.user_id == user_id,
                UserOnboardingProgress.tour_key == tour_key,
            )
        )
    ).scalar_one_or_none()
    if already_exists is None:
        distinct_tours = (
            await session.execute(
                select(func.count())
                .select_from(UserOnboardingProgress)
                .where(UserOnboardingProgress.user_id == user_id)
            )
        ).scalar() or 0
        if distinct_tours >= _MAX_DISTINCT_TOURS_PER_USER:
            raise OnboardingValidationError(
                f"Trop de tours d'onboarding distincts " f"(max {_MAX_DISTINCT_TOURS_PER_USER})."
            )

    stmt = (
        sqlite_insert(UserOnboardingProgress)
        .values(user_id=user_id, tour_key=tour_key, **insert_values)
        .on_conflict_do_update(
            index_elements=["user_id", "tour_key"],
            set_=update_set,
        )
    )
    await session.execute(stmt)
    # ``populate_existing=True`` force SQLAlchemy à rafraîchir l'objet ORM
    # depuis la BDD plutôt que de retourner la version cachée dans l'identity
    # map — sans ce flag, un appel successif (start_tour puis record_step
    # dans la même session) verrait l'état stale du premier appel.
    result = await session.execute(
        select(UserOnboardingProgress)
        .where(
            UserOnboardingProgress.user_id == user_id,
            UserOnboardingProgress.tour_key == tour_key,
        )
        .execution_options(populate_existing=True)
    )
    row = result.scalar_one()
    return row


# -----------------------------------------------------------------------------
# API publique — tours utilisateur
# -----------------------------------------------------------------------------


async def start_tour(session: AsyncSession, user_id: int, tour_key: str) -> UserOnboardingProgress:
    """Pose ``started_at = NOW`` si pas déjà posé. Idempotent.

    Ne touche jamais ``completed_at``, ``skipped_at``, ``last_step_seen`` —
    seul le premier appel modifie ``started_at``. Permet de tracker quand
    l'utilisateur a vu le tour pour la première fois sans perdre cette
    information sur un re-trigger éventuel.
    """
    now = _utcnow()
    return await _upsert_tour(
        session,
        user_id=user_id,
        tour_key=tour_key,
        insert_values={"started_at": now, "last_step_seen": 0},
        # ON CONFLICT : ne modifie ``started_at`` que s'il est NULL.
        # ``COALESCE`` évite d'écraser un timestamp existant.
        update_set={
            "started_at": _coalesce_existing("started_at", now),
        },
    )


async def record_step(
    session: AsyncSession, user_id: int, tour_key: str, step: int
) -> UserOnboardingProgress:
    """Met à jour ``last_step_seen`` (monotone, jamais régressif).

    ``started_at`` est posé si absent. ``last_step_seen`` est mis à jour
    via ``MAX(existant, nouveau)`` pour ne JAMAIS faire reculer la
    progression — un client qui rejoue un step antérieur (refresh, race)
    ne perd pas ce qui a déjà été vu.
    """
    now = _utcnow()
    return await _upsert_tour(
        session,
        user_id=user_id,
        tour_key=tour_key,
        insert_values={"started_at": now, "last_step_seen": step},
        update_set={
            "last_step_seen": _max_step("last_step_seen", step),
            "started_at": _coalesce_existing("started_at", now),
        },
    )


async def complete_tour(
    session: AsyncSession, user_id: int, tour_key: str
) -> UserOnboardingProgress:
    """Pose ``completed_at = NOW``. Idempotent — n'écrase pas un completed_at
    existant (premier complete gagne)."""
    now = _utcnow()
    return await _upsert_tour(
        session,
        user_id=user_id,
        tour_key=tour_key,
        insert_values={
            "started_at": now,
            "completed_at": now,
            "last_step_seen": 0,
        },
        update_set={
            "completed_at": _coalesce_existing("completed_at", now),
            "started_at": _coalesce_existing("started_at", now),
        },
    )


async def skip_tour(session: AsyncSession, user_id: int, tour_key: str) -> UserOnboardingProgress:
    """Pose ``skipped_at = NOW``. N'écrase pas ``completed_at`` (priorité à
    complétion). Idempotent — premier skip gagne."""
    now = _utcnow()
    return await _upsert_tour(
        session,
        user_id=user_id,
        tour_key=tour_key,
        insert_values={
            "started_at": now,
            "skipped_at": now,
            "last_step_seen": 0,
        },
        update_set={
            "skipped_at": _coalesce_existing("skipped_at", now),
            "started_at": _coalesce_existing("started_at", now),
        },
    )


# -----------------------------------------------------------------------------
# API publique — état utilisateur
# -----------------------------------------------------------------------------


async def _get_or_create_activity_summary(
    session: AsyncSession, user_id: int
) -> UserActivitySummary:
    """Lazy-create du résumé d'activité — appelé par ``get_user_state``.

    Pattern SELECT-first : la ligne existe pour 99 %+ des appels (créée à
    la 1ʳᵉ visite, persiste ensuite). Sans SELECT-first, chaque GET
    ``/api/onboarding/state`` (déclenché sur quasi toutes les pages) émet
    un ``INSERT ON CONFLICT DO NOTHING`` qui acquiert le write lock SQLite
    le temps d'une décision triviale — sur DB chargée, ça empile la
    contention et finit en ``database is locked`` (cf. incident 2026-05-20
    où le commit datastore download / onboarding state failait à 30 s).

    Race-safe : deux requêtes concurrentes peuvent voir ``None`` au SELECT
    initial — chacune tente l'INSERT, ``on_conflict_do_nothing`` gère la
    collision sans erreur. Le re-SELECT post-INSERT retourne la ligne
    (un writer SQLite voit toujours l'état committé le plus récent). On
    utilise ``scalar_one_or_none()`` + fallback explicite plutôt que
    ``scalar_one()`` (défense contre une éventuelle staleness du snapshot
    de session repérée en review adversariale 2026-05-20).
    """
    existing = await session.execute(
        select(UserActivitySummary).where(UserActivitySummary.user_id == user_id)
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        return row
    stmt = (
        sqlite_insert(UserActivitySummary)
        .values(user_id=user_id)
        .on_conflict_do_nothing(index_elements=["user_id"])
    )
    await session.execute(stmt)
    # Flush garantit que le INSERT est envoyé à la connexion DB AVANT le
    # re-SELECT — sans ça SQLAlchemy peut différer l'INSERT et le SELECT
    # opérerait sur un état pré-INSERT.
    await session.flush()
    result = await session.execute(
        select(UserActivitySummary).where(UserActivitySummary.user_id == user_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        # Path adversarial : INSERT a fait no-op (autre tx a inséré) ET
        # notre snapshot ne voit pas la ligne. Force un commit pour
        # refresh le snapshot puis re-tente. Très rare en pratique (writer
        # SQLite voit le latest committed) mais défense en profondeur.
        await session.commit()
        result = await session.execute(
            select(UserActivitySummary).where(UserActivitySummary.user_id == user_id)
        )
        row = result.scalar_one()
    return row


async def get_user_state(session: AsyncSession, user_id: int) -> dict:
    """Retourne l'état d'onboarding complet de l'utilisateur.

    Contenu :

    - ``tours`` : dict ``tour_key -> dict`` (sérialisation ``to_dict``)
      pour tous les tours touchés par l'utilisateur.
    - ``activity`` : résumé d'activité (créé lazy si absent).

    Toujours filtré par ``user_id`` — owner-scope strict, jamais d'accès
    cross-user.
    """
    tours_result = await session.execute(
        select(UserOnboardingProgress).where(UserOnboardingProgress.user_id == user_id)
    )
    tours = {row.tour_key: row.to_dict() for row in tours_result.scalars().all()}

    activity = await _get_or_create_activity_summary(session, user_id)

    return {"tours": tours, "activity": activity.to_dict()}


# -----------------------------------------------------------------------------
# API publique — singleton tenant setup
# -----------------------------------------------------------------------------


async def get_or_create_tenant_setup(session: AsyncSession) -> TenantSetupProgress:
    """Retourne le singleton, le crée à la volée s'il n'existe pas.

    Ne pose AUCUN jalon à la création — la ligne est créée vierge.
    ``welcome_seen_at`` doit être posé explicitement via
    ``set_milestone(session, "welcome")`` au premier affichage du bandeau
    par un humain. Cela évite qu'un GET de monitoring/healthcheck pose
    un timestamp mensonger qui prétendrait que l'admin a vu le bandeau.

    SELECT-first : la ligne singleton existe à 99 %+ des appels (créée à
    la 1ʳᵉ visite admin, persiste ensuite). Sans SELECT-first, chaque
    rendering du bandeau d'onboarding (toutes les pages admin) émet un
    ``INSERT ON CONFLICT DO NOTHING`` qui prend le write lock — même
    problème que ``_get_or_create_activity_summary`` (cf. incident
    2026-05-20 ``database is locked``).

    ``scalar_one_or_none()`` + fallback commit explicite : défense en
    profondeur contre la staleness de snapshot (review adversariale
    2026-05-20). En pratique le writer SQLite voit le latest committed,
    donc le fallback ne se déclenche presque jamais.
    """
    existing = await session.execute(
        select(TenantSetupProgress).where(TenantSetupProgress.id == SINGLETON_ROW_ID)
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        return row
    stmt = (
        sqlite_insert(TenantSetupProgress)
        .values(id=SINGLETON_ROW_ID)
        .on_conflict_do_nothing(index_elements=["id"])
    )
    await session.execute(stmt)
    await session.flush()
    result = await session.execute(
        select(TenantSetupProgress).where(TenantSetupProgress.id == SINGLETON_ROW_ID)
    )
    row = result.scalar_one_or_none()
    if row is None:
        await session.commit()
        result = await session.execute(
            select(TenantSetupProgress).where(TenantSetupProgress.id == SINGLETON_ROW_ID)
        )
        row = result.scalar_one()
    return row


async def set_milestone(session: AsyncSession, milestone: str) -> TenantSetupProgress:
    """Pose le timestamp ``<milestone>_*_at`` à NOW si non encore franchi.

    ``milestone`` DOIT avoir été validé par ``validate_milestone`` avant
    appel. La whitelist ``MILESTONE_TO_FIELD`` est la seule source du nom
    de colonne SQL — pas d'interpolation de string utilisateur.
    """
    column_name = MILESTONE_TO_FIELD[milestone]
    row = await get_or_create_tenant_setup(session)
    # Premier franchissement gagne — on ne re-écrase pas un timestamp posé.
    if getattr(row, column_name) is None:
        setattr(row, column_name, _utcnow())
    # Si tous les jalons sont franchis, pose ``completed_at`` automatiquement.
    if row.is_complete and row.completed_at is None:
        row.completed_at = _utcnow()
    await session.flush()
    return row


async def dismiss_tenant_setup(session: AsyncSession) -> TenantSetupProgress:
    """Pose ``dismissed_at = NOW`` — masque le bandeau côté UI."""
    row = await get_or_create_tenant_setup(session)
    if row.dismissed_at is None:
        row.dismissed_at = _utcnow()
        await session.flush()
    return row


async def resume_tenant_setup(session: AsyncSession) -> TenantSetupProgress:
    """Réinitialise ``dismissed_at`` à NULL — le bandeau réapparaît si la
    checklist n'est pas complète. Idempotent."""
    row = await get_or_create_tenant_setup(session)
    if row.dismissed_at is not None:
        row.dismissed_at = None
        await session.flush()
    return row


# -----------------------------------------------------------------------------
# Reset administrateur (utilitaire test user)
# -----------------------------------------------------------------------------


async def reset_user_onboarding(
    session: AsyncSession,
    user_id: int,
    tour_key: Optional[str] = None,
) -> int:
    """Supprime les enregistrements ``UserOnboardingProgress`` pour ``user_id``.

    Si ``tour_key`` est fourni, ne supprime que ce tour. Sinon supprime
    TOUS les tours de l'utilisateur. Retourne le nombre de lignes
    supprimées.

    Réservé à l'admin (route protégée par ``@admin_required``). Permet à
    l'admin de réinitialiser l'onboarding d'un compte test (ou le sien)
    pour rejouer les tours comme un nouveau venu, sans recréer un user.

    ``user_activity_summary`` n'est PAS supprimé — c'est de la
    télémétrie (counters, last_seen), un reset polluerait les métriques.
    Pour effacer aussi l'activité, supprimer le user (CASCADE).
    """
    stmt = delete(UserOnboardingProgress).where(UserOnboardingProgress.user_id == user_id)
    if tour_key is not None:
        validated_key = validate_tour_key(tour_key)
        stmt = stmt.where(UserOnboardingProgress.tour_key == validated_key)
    result = await session.execute(stmt)
    await session.flush()
    return result.rowcount or 0


# -----------------------------------------------------------------------------
# Helpers extraction body JSON — utilisés par les handlers
# -----------------------------------------------------------------------------


def extract_tour_key(body: dict) -> str:
    """Extrait + valide ``tour_key`` depuis un body JSON. Lève
    ``OnboardingValidationError`` si invalide ou absent."""
    if "tour_key" not in body:
        raise OnboardingValidationError("tour_key obligatoire")
    return validate_tour_key(body["tour_key"])


def extract_step(body: dict) -> int:
    """Extrait + valide ``step`` depuis un body JSON. Obligatoire."""
    if "step" not in body:
        raise OnboardingValidationError("step obligatoire")
    return validate_step(body["step"])


def extract_milestone(body: dict) -> str:
    """Extrait + valide ``milestone`` depuis un body JSON."""
    if "milestone" not in body:
        raise OnboardingValidationError("milestone obligatoire")
    return validate_milestone(body["milestone"])
