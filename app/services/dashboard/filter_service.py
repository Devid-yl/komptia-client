"""
Service pour les filtres/slicers de Dashboard — Power BI style.

Gère le CRUD des filtres de tableaux de bord et la construction
de clauses SQL paramétrées pour le filtrage cross-widget.
"""

import logging
import re
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# #47 — borne de SÉCURITÉ PAR FILTRE pour les clauses IN. L'ancien cap silencieux
# à 50 AMPUTAIT la sélection user (un widget filtré sur 80 dossiers n'en gardait
# que 50 → agrégats FAUX présentés comme exhaustifs). On lie désormais TOUTES les
# valeurs (déjà bornées à ~100 par le dropdown, max_rows=100), et on lève une
# erreur LOUD au-delà de cette borne plutôt que de tronquer en silence.
# #47 review (Moyen) — 200 (≫ 100 réaliste) et PAS 1000 : la limite SQL Server
# est ~2100 params CUMULÉS sur tous les filtres ; à 200/filtre, même ~10 filtres
# multi-select restent sous le plafond (échec sinon LOUD au caller, pas de donnée
# fausse silencieuse — c'est le pire qu'on prévient).
_MAX_FILTER_IN_VALUES = 200

# Validation SELECT-only des sources de filtre SQL : déléguée au validateur
# SSoT ``app.services.ai.sql_validator.check_sql_dangerous`` (importé localement
# dans create_filter / _resolve_options). Même garde que les widgets dashboard
# (``_fetch_sql_data``) — couvre SELECT INTO / sp_ / BULK INSERT / OPENROWSET /
# commentaires, que l'ancien blacklist 11-mots inline laissait passer.


class DashboardFilterService:
    """Service pour gérer les filtres de dashboards."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def _check_dashboard_access(
        self, session: AsyncSession, dashboard_id: int, user_id: int
    ):  # -> Optional[Dashboard]
        """Vérifie l'accès au dashboard. Retourne le dashboard ou None.

        Accès **strict owner-only** : un dashboard n'appartenant pas à
        ``user_id`` retourne ``None`` (fail-closed). Il n'existe pas de partage
        cross-user (cf. dashboard_builder_service « aucun partage cross-user »).
        L'ancien paramètre ``owner_only`` était mort (jamais lu) — retiré pour
        éviter qu'un futur dev suppose qu'``owner_only=False`` relâche le contrôle
        et construise un partage qui ouvrirait une faille IDOR.
        """
        from app.models.dashboard import Dashboard

        stmt = select(Dashboard).where(Dashboard.id == dashboard_id)
        result = await session.execute(stmt)
        dashboard = result.scalar_one_or_none()
        if not dashboard:
            return None
        if dashboard.user_id != user_id:
            return None
        return dashboard

    async def list_filters(
        self, session: AsyncSession, dashboard_id: int, user_id: int
    ) -> Optional[list[dict]]:
        """Liste les filtres d'un dashboard (si accès autorisé)."""
        from app.models.dashboard import DashboardFilter

        dashboard = await self._check_dashboard_access(session, dashboard_id, user_id)
        if not dashboard:
            return None

        stmt = (
            select(DashboardFilter)
            .where(DashboardFilter.dashboard_id == dashboard_id)
            .order_by(DashboardFilter.position_order)
        )
        result = await session.execute(stmt)
        filters = result.scalars().all()
        return [f.to_dict() for f in filters]

    async def create_filter(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        data: dict,
    ) -> Optional[dict]:
        """Crée un filtre sur un dashboard (owner only)."""
        from app.models.dashboard import DashboardFilter

        dashboard = await self._check_dashboard_access(
            session, dashboard_id, user_id
        )
        if not dashboard:
            return None

        # Check parameter_name uniqueness within the dashboard
        param_name = data.get("parameter_name", "")
        existing_stmt = (
            select(func.count())
            .select_from(DashboardFilter)
            .where(
                DashboardFilter.dashboard_id == dashboard_id,
                DashboardFilter.parameter_name == param_name,
            )
        )
        existing_count = (await session.execute(existing_stmt)).scalar() or 0
        if existing_count > 0:
            raise ValueError(
                f"Un filtre avec le paramètre '{param_name}' existe déjà sur ce dashboard."
            )

        # Calculate next position_order
        count_stmt = (
            select(func.count())
            .select_from(DashboardFilter)
            .where(DashboardFilter.dashboard_id == dashboard_id)
        )
        next_order = (await session.execute(count_stmt)).scalar() or 0

        # Validate SQL query if values_source is sql
        values_source = data.get("values_source", "static")
        values_config = data.get("values_config")
        if values_source == "sql" and values_config:
            query = (values_config.get("query") or "").strip()
            if query:
                from app.services.ai.sql_validator import check_sql_dangerous

                upper = query.upper()
                if not upper.startswith("SELECT") and not upper.startswith("WITH"):
                    raise ValueError("Seules les requêtes SELECT sont autorisées pour les filtres.")
                if check_sql_dangerous(query):
                    raise ValueError("Seules les requêtes SELECT sont autorisées pour les filtres.")

        new_filter = DashboardFilter(
            dashboard_id=dashboard_id,
            parameter_name=param_name,
            label=str(data.get("label", "")).strip()[:100],
            filter_type=data.get("filter_type", "dropdown_single"),
            values_source=values_source,
            values_config=values_config,
            default_value=data.get("default_value"),
            position_order=data.get("position_order", next_order),
        )

        errors = new_filter.validate()
        if errors:
            raise ValueError("; ".join(errors))

        session.add(new_filter)
        await session.flush()
        result_dict = new_filter.to_dict()
        await session.commit()

        logger.info(
            "Filtre créé: id=%s, dashboard=%s, param=%s",
            result_dict["id"],
            dashboard_id,
            param_name,
        )
        return result_dict

    async def update_filter(
        self,
        session: AsyncSession,
        filter_id: int,
        dashboard_id: int,
        user_id: int,
        updates: dict,
    ) -> Optional[dict]:
        """Met à jour un filtre (owner only). parameter_name est immutable."""
        from app.models.dashboard import Dashboard, DashboardFilter

        stmt = (
            select(DashboardFilter)
            .join(Dashboard)
            .where(
                DashboardFilter.id == filter_id,
                DashboardFilter.dashboard_id == dashboard_id,
                Dashboard.user_id == user_id,
            )
        )
        result = await session.execute(stmt)
        db_filter = result.scalar_one_or_none()
        if not db_filter:
            return None

        # parameter_name is immutable after creation
        allowed = {
            "label",
            "filter_type",
            "values_source",
            "values_config",
            "default_value",
            "position_order",
        }
        for field, value in updates.items():
            if field not in allowed:
                continue
            if field == "label":
                value = str(value).strip()[:100]
            elif field == "position_order":
                try:
                    value = int(value) if value is not None else 0
                except (ValueError, TypeError):
                    value = 0
            setattr(db_filter, field, value)

        errors = db_filter.validate()
        if errors:
            raise ValueError("; ".join(errors))

        result_dict = db_filter.to_dict()
        await session.commit()

        logger.info("Filtre mis à jour: id=%s", filter_id)
        return result_dict

    async def delete_filter(
        self,
        session: AsyncSession,
        filter_id: int,
        dashboard_id: int,
        user_id: int,
    ) -> bool:
        """Supprime un filtre (owner only)."""
        from app.models.dashboard import Dashboard, DashboardFilter

        stmt = (
            select(DashboardFilter)
            .join(Dashboard)
            .where(
                DashboardFilter.id == filter_id,
                DashboardFilter.dashboard_id == dashboard_id,
                Dashboard.user_id == user_id,
            )
        )
        result = await session.execute(stmt)
        db_filter = result.scalar_one_or_none()
        if not db_filter:
            return False

        await session.delete(db_filter)
        await session.commit()

        logger.info("Filtre supprimé: id=%s", filter_id)
        return True

    async def reorder_filters(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        filter_order: list[int],
    ) -> bool:
        """Réordonne les filtres d'un dashboard (owner only)."""
        from app.models.dashboard import DashboardFilter

        dashboard = await self._check_dashboard_access(
            session, dashboard_id, user_id
        )
        if not dashboard:
            return False

        for position, fid in enumerate(filter_order):
            stmt = select(DashboardFilter).where(
                DashboardFilter.id == fid,
                DashboardFilter.dashboard_id == dashboard_id,
            )
            result = await session.execute(stmt)
            db_filter = result.scalar_one_or_none()
            if db_filter:
                db_filter.position_order = position

        await session.commit()
        logger.info("Filtres réordonnés: dashboard=%s", dashboard_id)
        return True

    async def get_filters_with_options(
        self,
        session: AsyncSession,
        dashboard_id: int,
        user_id: int,
        user: Any = None,
    ) -> Optional[list[dict]]:
        """Retourne les filtres avec leurs options résolues (pour les dropdowns).

        date_range, numeric_range et text_search n'ont pas d'options.

        ``user`` (ORM User object) est propagé jusqu'à l'exécution SQL pour
        appliquer les règles RLS configurées (data_access). Si ``None``,
        comportement legacy avec un WARNING log côté enforcer.
        """
        filters = await self.list_filters(session, dashboard_id, user_id)
        if filters is None:
            return None

        result = []
        for f in filters:
            entry = dict(f)
            if f["filter_type"] in ("dropdown_single", "dropdown_multi"):
                entry["options"] = await self._resolve_options(f, user=user)
            else:
                entry["options"] = []
            result.append(entry)

        return result

    async def _resolve_options(self, filter_def: dict, user: Any = None) -> list[dict]:
        """Résout les options d'un filtre dropdown.

        Retourne [] en cas d'erreur (dropdown vide, pas de crash).
        """
        source = filter_def.get("values_source", "static")
        config = filter_def.get("values_config") or {}

        if source == "static":
            options = config.get("options", [])
            if isinstance(options, list):
                return options
            return []

        elif source == "sql":
            query = (config.get("query") or "").strip()
            if not query:
                return []
            from app.services.ai.sql_validator import check_sql_dangerous

            upper = query.upper()
            if not upper.startswith("SELECT") and not upper.startswith("WITH"):
                return []
            if check_sql_dangerous(query):
                return []

            try:
                from app.services.data_access.enforcer import DataAccessDeniedError
                from app.services.database.query_executor import QueryExecutor

                executor = QueryExecutor()
                # execute() returns QueryResult, supports params
                qr = await executor.execute(
                    query,
                    max_rows=100,
                    user=user,
                    rls_source="dashboard_filter_options",
                    require_user=True,
                )

                columns = qr.columns or []
                rows = qr.to_dicts()
                if not rows or not columns:
                    return []

                # First column = value, second = label (or first for both)
                val_col = columns[0]
                lbl_col = columns[1] if len(columns) > 1 else columns[0]
                options = []
                for row in rows:
                    val = row.get(val_col)
                    if val is None:
                        continue
                    options.append(
                        {
                            "value": str(val),
                            "label": str(row.get(lbl_col, val)),
                        }
                    )
                return options
            except DataAccessDeniedError:
                # Le fail-closed ``require_user`` (ou une règle data-access) a
                # refusé l'exécution. NE PAS masquer en dropdown vide silencieux :
                # le guard doit être BRUYANT (sinon un oubli de propagation de
                # ``user`` — la classe de bug #86 — passe inaperçu). On logue
                # ERROR (greppable) ; l'UX reste un dropdown vide (gracieux côté
                # user, observable côté ops).
                logger.error(
                    "Filtre dropdown: enforcement RLS a refusé l'exécution "
                    "(dashboard_id=%s, param=%s) — vérifier la propagation de "
                    "``user`` jusqu'à _resolve_options.",
                    filter_def.get("dashboard_id"),
                    filter_def.get("parameter_name"),
                )
                return []
            except Exception:
                logger.warning(
                    "Erreur résolution options filtre SQL (dashboard_id=%s, param=%s)",
                    filter_def.get("dashboard_id"),
                    filter_def.get("parameter_name"),
                    exc_info=True,
                )
                return []

        return []


def build_sql_filter_clause(
    filter_state: dict,
    filter_definitions: list[dict],
) -> tuple[str, list]:
    """Construit une clause WHERE paramétrée pour les filtres sur SQL widgets.

    Le parameter_name (validé ^[a-zA-Z_][a-zA-Z0-9_]{0,49}$) est utilisé comme nom
    de colonne dans un bracket-quoted identifier [col]. Les valeurs utilisent des
    placeholders ? pour pyodbc.

    Args:
        filter_state: {parameter_name: value_or_list}
        filter_definitions: liste de filter.to_dict()

    Returns:
        (where_clause_string, params_list). ("", []) si aucun filtre applicable.
    """
    clauses = []
    params = []
    filter_defs_by_name = {f["parameter_name"]: f for f in filter_definitions}
    param_re = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,49}$")

    for param_name, value in filter_state.items():
        # Skip empty values (but 0 and False are valid)
        if value is None or value == "" or value == []:
            continue
        if param_name not in filter_defs_by_name:
            continue
        # Safety: re-validate parameter_name even though it was validated at creation
        if not param_re.match(param_name):
            continue

        fdef = filter_defs_by_name[param_name]
        ftype = fdef["filter_type"]
        col = param_name  # Safe: validated

        if ftype == "dropdown_single":
            clauses.append(f"[{col}] = ?")
            params.append(value)

        elif ftype == "dropdown_multi" and isinstance(value, list) and value:
            # #47 — lier TOUTES les valeurs sélectionnées (plus de cap silencieux
            # à 50 qui faussait les agrégats). Fail-loud au-delà de la borne large.
            if len(value) > _MAX_FILTER_IN_VALUES:
                raise ValueError(
                    f"Filtre « {col} » : trop de valeurs sélectionnées "
                    f"({len(value)} > {_MAX_FILTER_IN_VALUES}). Affinez la sélection."
                )
            placeholders = ", ".join(["?"] * len(value))
            clauses.append(f"[{col}] IN ({placeholders})")
            params.extend(value)

        elif ftype == "date_range" and isinstance(value, dict):
            if value.get("from"):
                clauses.append(f"[{col}] >= ?")
                params.append(value["from"])
            if value.get("to"):
                clauses.append(f"[{col}] <= ?")
                params.append(value["to"])

        elif ftype == "numeric_range" and isinstance(value, dict):
            if value.get("min") is not None:
                clauses.append(f"[{col}] >= ?")
                params.append(value["min"])
            if value.get("max") is not None:
                clauses.append(f"[{col}] <= ?")
                params.append(value["max"])

        elif ftype == "text_search" and isinstance(value, str) and value.strip():
            # Escape LIKE wildcards in the value
            escaped = value.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(f"[{col}] LIKE ? ESCAPE '\\'")
            params.append(f"%{escaped}%")

    if not clauses:
        return "", []
    return " AND ".join(clauses), params


def build_drill_down_clause(
    drill_filters: dict,
) -> tuple[str, list]:
    """Construit une clause WHERE paramétrée pour le drill-down interactif.

    Utilisé quand l'utilisateur clique sur un élément de graphique pour filtrer
    les autres widgets. Plus simple que build_sql_filter_clause car pas besoin
    de définitions de filtre — juste column=value.

    Args:
        drill_filters: {column_name: scalar_value} — typiquement un seul entry.

    Returns:
        (where_clause_string, params_list). ("", []) si aucun filtre applicable.
    """
    clauses = []
    params = []
    param_re = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,49}$")

    for col, value in drill_filters.items():
        if value is None or value == "":
            continue
        if isinstance(value, list) and not value:
            continue
        # Safety: validate column name (same regex as filter parameter_name)
        if not param_re.match(col):
            continue

        if isinstance(value, list):
            # #47 — idem build_sql_filter_clause : toutes les valeurs, fail-loud.
            if len(value) > _MAX_FILTER_IN_VALUES:
                raise ValueError(
                    f"Drill-down « {col} » : trop de valeurs "
                    f"({len(value)} > {_MAX_FILTER_IN_VALUES})."
                )
            placeholders = ", ".join(["?"] * len(value))
            clauses.append(f"[{col}] IN ({placeholders})")
            params.extend(value)
        else:
            clauses.append(f"[{col}] = ?")
            params.append(value)

    if not clauses:
        return "", []
    return " AND ".join(clauses), params
