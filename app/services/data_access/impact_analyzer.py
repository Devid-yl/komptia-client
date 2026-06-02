"""Calcule l'impact d'une règle ``DataAccessRule`` AVANT sa pose.

**Phase α.7 (#73)** — Garde-fou UX no-surprise : avant qu'un admin ne pose
une règle ``deny F_SALAIRES`` sur ``user_42``, on lui montre ce qui va
casser ou être impacté :

- **Automations** actives qui contiennent du SQL référençant la table/colonne
  → vont lever un ``DataAccessDeniedError`` à la prochaine exécution.
- **Dashboards** dont des widgets utilisent ce SQL → vont afficher une
  erreur au chargement pour cet user.
- **Paires Q/SQL d'apprentissage** dont le SQL référence la cible → vont
  être filtrées du contexte LLM par mode invisible (impact qualité
  réponses Iris).
- **Conversations passées** de cet user qui ont touché la table → trace
  d'utilisation historique (pas d'impact runtime, juste info).

L'impact se calcule par **match textuel sur les SQL persistés**. Pas
parfait (le SQL pourrait référencer la table via un alias ou un join
complexe que le LIKE rate), mais c'est défensif : on **surestime** légèrement
l'impact (faux positifs OK), on ne sous-estime pas (faux négatifs
interdits — l'admin doit voir tout ce qui va casser).

**Génériquement** : aucun nom de table hardcodé. Tout vient du paramètre.

**Architecture** : ce module est INDÉPENDANT de l'écriture de la règle.
Le caller (handler admin) appelle ``compute_impact()`` AVANT le POST,
affiche le résultat à l'utilisateur, et attend confirmation explicite
avant d'écrire la règle.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sqlalchemy import select

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types de retour
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ImpactedAutomation:
    """Une automation impactée par la règle proposée."""

    id: int
    name: str
    is_active: bool
    matching_step_count: int  # nb de steps qui mentionnent la table


@dataclass(frozen=True, slots=True)
class ImpactedDashboard:
    """Un dashboard avec au moins un widget impacté."""

    id: int
    name: str
    matching_widget_count: int


@dataclass(frozen=True, slots=True)
class ImpactedQSQLPair:
    """Une paire Q/SQL d'apprentissage qui référence la table."""

    id: int
    question_truncated: str  # ≤ 120 chars
    table_name_in_sql: bool  # True si la table apparaît littéralement


@dataclass(frozen=True, slots=True)
class ImpactReport:
    """Rapport complet d'impact d'une règle proposée."""

    user_id: int
    user_label: str
    scope: str  # "table" / "column" / "row"
    target_table: str
    target_column: Optional[str]

    automations: List[ImpactedAutomation]
    dashboards: List[ImpactedDashboard]
    training_pairs: List[ImpactedQSQLPair]
    conversation_count: int

    #: **P1 (#131)** — Closure transitive : noms des vues/fonctions/synonymes
    #: qui dépendent de la table denied et seront aussi cachés via la
    #: fermeture transitive (Phase 2.1 #44). Vide pour scope=column/row
    #: (la closure est au niveau table). Affiché côté admin avant pose
    #: de règle pour ne pas surprendre l'admin avec des objets cachés
    #: silencieusement.
    closure_extra: List[str] = field(default_factory=list)

    summary_fr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Sérialise pour API JSON."""
        return {
            "user_id": self.user_id,
            "user_label": self.user_label,
            "scope": self.scope,
            "target_table": self.target_table,
            "target_column": self.target_column,
            "automations": [
                {
                    "id": a.id,
                    "name": a.name,
                    "is_active": a.is_active,
                    "matching_step_count": a.matching_step_count,
                }
                for a in self.automations
            ],
            "dashboards": [
                {
                    "id": d.id,
                    "name": d.name,
                    "matching_widget_count": d.matching_widget_count,
                }
                for d in self.dashboards
            ],
            "training_pairs": [
                {
                    "id": p.id,
                    "question_truncated": p.question_truncated,
                    "table_name_in_sql": p.table_name_in_sql,
                }
                for p in self.training_pairs
            ],
            "conversation_count": self.conversation_count,
            # **P1 (#131)** — Closure transitive exposée côté frontend.
            "closure_extra": list(self.closure_extra),
            "summary_fr": self.summary_fr,
        }


# ---------------------------------------------------------------------------
# Helpers de matching
# ---------------------------------------------------------------------------


def _sql_references_table(sql: str, table_name: str) -> bool:
    """Heuristique : ``sql`` référence-t-il ``table_name`` ?

    Match textuel **insensible à la casse** sur le nom de table avec
    des **word boundaries** simulés (on évite que ``F_DOSSIER`` matche
    dans ``F_DOSSIER_HISTORIQUE``). Suffisant pour la V1 — un AST
    parser sqlglot serait plus précis mais coûteux à l'échelle (4
    sources de SQL × N entrées chacune).

    **Faux positifs acceptés** (ex: nom de table dans un commentaire) :
    l'admin verra l'item dans l'impact alors qu'il n'est pas vraiment
    impacté → bénin (surestimation).

    **Faux négatifs interdits** (ex: SQL qui passe par un alias) : V1
    accepte ce risque en assumant que la majorité des SQL persistés
    référencent les tables par leur nom direct (cas standard Komptia).
    Pour V2 : intégration sqlglot.
    """
    if not sql or not table_name:
        return False
    sql_upper = sql.upper()
    table_upper = table_name.strip().upper()
    if not table_upper:
        return False
    # Word boundary simple : avant et après le match, on veut un
    # caractère non-alphanumérique (ou bord de chaîne). Évite les
    # faux positifs entre F_X et F_X_HISTORIQUE.
    import re

    pattern = re.compile(
        r"(?:^|[^A-Z0-9_])" + re.escape(table_upper) + r"(?=[^A-Z0-9_]|$)",
        re.IGNORECASE,
    )
    return pattern.search(sql_upper) is not None


# ---------------------------------------------------------------------------
# Compute impact
# ---------------------------------------------------------------------------


async def compute_impact(
    user_id: int,
    scope: str,
    table_name: str,
    column_name: Optional[str] = None,
) -> ImpactReport:
    """Calcule l'impact d'une règle proposée AVANT sa pose.

    Args:
        user_id: ID de l'user cible de la règle.
        scope: "table" / "column" / "row" (cf. ``DataAccessScope``).
        table_name: table cible (UPPERCASE par convention).
        column_name: colonne cible (si ``scope`` ∈ {"column", "row"}).

    Returns:
        :class:`ImpactReport` avec listes détaillées + résumé FR.

    Le calcul est **read-only** — aucune modification BDD. Plusieurs
    requêtes en parallèle pour minimiser la latence (~200ms tout
    compris attendu sur BDD locale SQLite).
    """
    from app.core.database import get_session
    from app.models.automation import Automation
    from app.models.automation_step import AutomationStep
    from app.models.conversation import Conversation
    from app.models.dashboard import Dashboard, DashboardWidget
    from app.models.training_data import TrainingData, TrainingDataType
    from app.models.user import User

    table_upper = (table_name or "").strip().upper()
    if not table_upper:
        raise ValueError("compute_impact: table_name vide.")

    async with get_session() as session:
        # 0. Label user
        user_obj = await session.get(User, user_id)
        user_label = (
            f"{user_obj.email}"
            if user_obj and getattr(user_obj, "email", None)
            else f"user_{user_id}"
        )

        # 1. Automations + leurs steps qui contiennent du SQL
        # Chargement défensif : on liste TOUTES les automations + leurs
        # steps, puis filtrage en mémoire (le JSON peut être complexe,
        # pas trivial à filtrer en SQL pur). Une auto a son SQL principal
        # dans ``query_text`` ET potentiellement du SQL dans ses steps.
        autos_stmt = select(Automation)
        all_autos = (await session.execute(autos_stmt)).scalars().all()

        steps_stmt = select(AutomationStep)
        all_steps = (await session.execute(steps_stmt)).scalars().all()

        # Index step → automation
        steps_by_auto: Dict[int, List[AutomationStep]] = {}
        for step in all_steps:
            auto_id = getattr(step, "automation_id", None)
            if auto_id is None:
                continue
            steps_by_auto.setdefault(auto_id, []).append(step)

        # 2. Dashboards + widgets avec config JSON
        dashboards_stmt = select(Dashboard)
        all_dashboards = (await session.execute(dashboards_stmt)).scalars().all()

        widgets_stmt = select(DashboardWidget)
        all_widgets = (await session.execute(widgets_stmt)).scalars().all()

        widgets_by_dashboard: Dict[int, List[DashboardWidget]] = {}
        for w in all_widgets:
            dash_id = getattr(w, "dashboard_id", None)
            if dash_id is None:
                continue
            widgets_by_dashboard.setdefault(dash_id, []).append(w)

        # 3. Paires Q/SQL d'apprentissage actives
        qsql_stmt = select(TrainingData).where(
            TrainingData.data_type == TrainingDataType.QUESTION_SQL,
            TrainingData.is_active.is_(True),
        )
        all_qsql = (await session.execute(qsql_stmt)).scalars().all()

        # 4. Conversations de l'user qui ont touché la table
        # ``Conversation.discoveries`` est un JSON avec champ ``tables``.
        # On filtre en mémoire (volume modeste — quelques centaines max
        # par user).
        conv_stmt = select(Conversation.id, Conversation.discoveries).where(
            Conversation.user_id == user_id,
            Conversation.discoveries.isnot(None),
        )
        conv_rows = (await session.execute(conv_stmt)).all()

    # ── Calcul impacts (mémoire, pas de SQL supplémentaire) ──

    # Automations impactées
    impacted_autos: List[ImpactedAutomation] = []
    for auto in all_autos:
        matching_count = 0
        # 1) SQL principal de l'auto (champ ``query_text``)
        query_text = getattr(auto, "query_text", "") or ""
        if _sql_references_table(query_text, table_upper):
            matching_count += 1
        # 2) SQL dans les configs des steps
        steps = steps_by_auto.get(auto.id, [])
        for step in steps:
            config = getattr(step, "config", None)
            if not config:
                continue
            sql_candidates = _extract_sql_from_config(config)
            for sql in sql_candidates:
                if _sql_references_table(sql, table_upper):
                    matching_count += 1
                    break  # un step compte une fois
        if matching_count > 0:
            impacted_autos.append(
                ImpactedAutomation(
                    id=auto.id,
                    name=getattr(auto, "name", "") or f"automation_{auto.id}",
                    is_active=bool(getattr(auto, "is_active", False)),
                    matching_step_count=matching_count,
                )
            )

    # Dashboards impactés
    impacted_dashboards: List[ImpactedDashboard] = []
    for dash in all_dashboards:
        widgets = widgets_by_dashboard.get(dash.id, [])
        matching_widget_count = 0
        for w in widgets:
            config = getattr(w, "config", None)
            if not config:
                continue
            sql_candidates = _extract_sql_from_config(config)
            for sql in sql_candidates:
                if _sql_references_table(sql, table_upper):
                    matching_widget_count += 1
                    break
        if matching_widget_count > 0:
            impacted_dashboards.append(
                ImpactedDashboard(
                    id=dash.id,
                    name=getattr(dash, "name", "") or f"dashboard_{dash.id}",
                    matching_widget_count=matching_widget_count,
                )
            )

    # Paires Q/SQL
    impacted_qsql: List[ImpactedQSQLPair] = []
    for pair in all_qsql:
        sql_text = getattr(pair, "sql", "") or ""
        if _sql_references_table(sql_text, table_upper):
            q = (getattr(pair, "question", "") or "").strip()
            q_truncated = q if len(q) <= 120 else q[:117] + "..."
            impacted_qsql.append(
                ImpactedQSQLPair(
                    id=pair.id,
                    question_truncated=q_truncated,
                    table_name_in_sql=True,
                )
            )

    # Conversations passées
    conversation_count = 0
    for conv_id, discoveries in conv_rows:
        try:
            data = json.loads(discoveries) if isinstance(discoveries, str) else discoveries
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(data, dict):
            continue
        tables_in_conv = data.get("tables") or []
        if not isinstance(tables_in_conv, list):
            continue
        for t in tables_in_conv:
            if isinstance(t, str) and t.strip().upper() == table_upper:
                conversation_count += 1
                break

    # ── Construction du résumé FR ──
    parts: List[str] = []
    if impacted_autos:
        parts.append(
            f"{len(impacted_autos)} automation"
            f"{'s' if len(impacted_autos) > 1 else ''} lèveront un refus"
        )
    if impacted_dashboards:
        parts.append(
            f"{len(impacted_dashboards)} dashboard"
            f"{'s' if len(impacted_dashboards) > 1 else ''} afficheront une erreur"
        )
    if impacted_qsql:
        parts.append(
            f"{len(impacted_qsql)} exemple"
            f"{'s' if len(impacted_qsql) > 1 else ''} Q/SQL retiré"
            f"{'s' if len(impacted_qsql) > 1 else ''} du contexte Iris"
        )
    if conversation_count > 0:
        parts.append(
            f"{conversation_count} conversation"
            f"{'s' if conversation_count > 1 else ''} historique"
            f"{'s' if conversation_count > 1 else ''} mentionne"
            f"{'nt' if conversation_count > 1 else ''} déjà la table"
        )

    # **P1 (#131)** — Closure transitive : si scope=table, déterminer
    # les objets dérivés (vues/fonctions/synonymes) qui seront aussi
    # cachés via la fermeture transitive (Phase 2.1 #44). Affichage
    # côté admin pour ne pas surprendre.
    closure_extra: List[str] = []
    if scope == "table" and table_upper:
        try:
            from app.services.data_access.visible_schema import (
                _compute_transitive_closure,
            )

            closure_set = await _compute_transitive_closure({table_upper})
            # ``closure_set`` contient table_upper + tous les objets dérivés.
            # On veut juste les dérivés (les "EXTRA").
            closure_extra = sorted(closure_set - {table_upper})
        except Exception as exc:  # noqa: BLE001 — calcul best-effort
            logger.warning(
                "compute_impact: closure transitive failed for %s (best-effort skip): %s",
                table_upper,
                exc,
            )
            closure_extra = []

    if parts:
        summary_fr = "Impact estimé : " + " · ".join(parts) + "."
    else:
        summary_fr = "Aucun impact détecté : aucune automation, dashboard ou exemple Q/SQL ne référence cette cible."

    # Mention closure dans le summary FR (en plus de l'exposition structurée).
    if closure_extra:
        summary_fr += (
            f" La règle cachera aussi {len(closure_extra)} objet"
            f"{'s' if len(closure_extra) > 1 else ''} "
            f"dérivé{'s' if len(closure_extra) > 1 else ''} "
            "(vue/fonction/synonyme qui en dépend)."
        )

    target_col_disp = column_name.strip().upper() if column_name else None

    return ImpactReport(
        user_id=user_id,
        user_label=user_label,
        scope=scope,
        target_table=table_upper,
        target_column=target_col_disp,
        automations=impacted_autos,
        dashboards=impacted_dashboards,
        training_pairs=impacted_qsql,
        conversation_count=conversation_count,
        closure_extra=closure_extra,
        summary_fr=summary_fr,
    )


def _extract_sql_from_config(config: Any) -> List[str]:
    """Extrait les chaînes SQL plausibles d'un config JSON (récursif).

    Heuristique : on remonte toutes les valeurs string dont :
    - longueur > 20 chars (assez long pour être du SQL)
    - contiennent au moins un mot-clé SQL (SELECT/FROM/WHERE/JOIN)

    Suffisant pour ne pas rater du SQL planqué dans des configs imbriquées
    (steps de type extract_sql, widgets de type sql, etc.).
    """
    found: List[str] = []
    _SQL_KEYWORDS = ("SELECT", "FROM", "WHERE", "JOIN", "GROUP BY")

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            if len(node) > 20 and any(kw in node.upper() for kw in _SQL_KEYWORDS):
                found.append(node)
        elif isinstance(node, dict):
            for v in node.values():
                _walk(v)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item)

    _walk(config)
    return found
