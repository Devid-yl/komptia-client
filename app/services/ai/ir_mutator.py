"""
T20 — Mutation de l'IR (Intermediate Representation) pour les conversations
multi-tour.

Module pur :
- aucun I/O, aucun appel LLM, aucune dépendance BDD
- chaque opération retourne un NOUVEAU IR (deep-copy, jamais de mutation
  in-place)
- chaque opération revalide via ``_ir_validate`` AVANT de retourner
- lève ``IRMutationError`` sur input invalide

Generic Komptia : aucun nom de table/colonne, aucune connaissance BDD —
les concepts sont des chaînes opaques manipulées par le code applicatif.

Cf. ``.claude/anon-impl-loop/MANIFEST.json#T20`` pour la spec et
``CLAUDE.md`` pour la règle GÉNÉRICITÉ.
"""

from __future__ import annotations

import copy
from types import MappingProxyType
from typing import Any, Callable, Optional


def _get_ir_validate() -> Callable[[dict], None]:
    """Import paresseux pour éviter une dépendance circulaire au load time.

    ``scripts/pipeline.py`` fait ~15 000 lignes et embarque un parser SQL — on
    ne veut pas le charger uniquement parce que l'on a importé ``ir_mutator``.
    """
    from scripts.pipeline import _ir_validate

    return _ir_validate


def _get_ir_constants() -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    from scripts.pipeline import _IR_VALID_OPS, _IR_VALID_AGGS, _IR_VALID_DIRECTIONS

    return _IR_VALID_OPS, _IR_VALID_AGGS, _IR_VALID_DIRECTIONS


class IRMutationError(ValueError):
    """L'opération de mutation est invalide ou refusée.

    Sous-classe de ``ValueError`` (et non ``IRValidationError``) pour
    rester découplé de ``scripts.pipeline`` côté types — l'import lazy
    n'instancie pas les classes au load time.
    """


_OP_MAX_PER_CALL: int = 10
_LIMIT_MAX: int = 10**6
_FILTERS_MAX: int = 50
_GROUP_BY_MAX: int = 30
_ORDER_BY_MAX: int = 30


def is_mutable(ir: Any) -> tuple[bool, str]:
    """Détecte si l'IR est mutable via ce module (MVP).

    **Refus en MVP — safe-by-default** :

    - IR multi-CTE (``ir["ctes"]`` ou ``ir["with_ctes"]`` truthy) : les
      mutations globales sont ambiguës (quelle CTE viser ?).
    - IR avec **n'importe quelle** ``derivation`` dans ``select`` (subtract,
      add, multiply, divide, full_outer, cte_ref, ...) : la sémantique
      multi-source d'une derivation rend les mutations dangereuses
      (un ``add_filter`` global s'appliquerait à la ``FROM`` principale
      mais pas aux opérandes de la derivation). En MVP, refuser large.

    L'agent doit relancer ``run_pipeline`` pour ces cas.

    Returns:
        (True, "") si mutable, sinon (False, "raison FR actionnable").
    """
    if not isinstance(ir, dict):
        return False, f"ir doit être un dict, got {type(ir).__name__}"
    if ir.get("ctes") or ir.get("with_ctes"):
        return False, (
            "IR multi-CTE non mutable en MVP — relance `run_pipeline` avec " "la requête modifiée."
        )
    for i, item in enumerate(ir.get("select", []) or []):
        if not isinstance(item, dict):
            continue
        deriv = item.get("derivation")
        if deriv:  # tout dict/list non-vide = derivation présente
            # FULL_OUTER reçoit un message dédié (cas le plus fréquent).
            if isinstance(deriv, dict) and deriv.get("semantic") == "full_outer":
                return False, (
                    "IR avec FULL_OUTER derivation non mutable en MVP — "
                    "relance `run_pipeline` avec la requête modifiée."
                )
            return False, (
                f"IR avec derivation dans select[{i}] (alias="
                f"{item.get('alias')!r}) non mutable en MVP — les mutations "
                "globales ne sauraient pas dans quel opérande appliquer. "
                "Relance `run_pipeline`."
            )
    return True, ""


def _check_mutable(ir: Any) -> None:
    ok, reason = is_mutable(ir)
    if not ok:
        raise IRMutationError(reason)


def _deep_copy_ir(ir: dict) -> dict:
    """Deep-copy pour garantir l'immutabilité de l'input.

    L'IR contient des dicts/lists imbriqués (select items avec derivation,
    filters compound all_of/any_of/not, etc.) — un copy.copy ne suffit pas.
    """
    return copy.deepcopy(ir)


# ----------------------------------------------------------------------
# Opérations primitives
# ----------------------------------------------------------------------


def add_filter(
    ir: dict,
    concept: str,
    op: str,
    val: Any,
) -> dict:
    """Ajoute un filtre à ``filters_global``.

    Args:
        ir : IR source (non mutée).
        concept : nom de concept (str non vide).
        op : opérateur SQL (cf. ``_IR_VALID_OPS``).
        val : valeur (peut être ``None`` pour ``IS_NULL`` / ``IS_NOT_NULL``).

    Returns:
        Nouveau IR avec filtre ajouté.

    Raises:
        IRMutationError : input invalide, IR non mutable, ou cap atteint.
    """
    _check_mutable(ir)
    if not isinstance(concept, str) or not concept.strip():
        raise IRMutationError(f"add_filter: concept doit être str non vide, got {concept!r}")
    valid_ops, _, _ = _get_ir_constants()
    if op not in valid_ops:
        raise IRMutationError(f"add_filter: op '{op}' invalide. Valides: {valid_ops}")

    # Validation sémantique op⟷val (anti-LLM-hostile).
    # ``_ir_validate`` ne croise pas op/val (responsabilité du composer
    # qui voit le ``value_type`` réel) — on attrape ici les cas évidents.
    if op in ("IN", "NOT_IN"):
        if not isinstance(val, list) or len(val) == 0:
            raise IRMutationError(
                f"add_filter: op '{op}' nécessite val=list non vide, "
                f"got {type(val).__name__}={val!r}"
            )
    elif op in ("LIKE", "NOT_LIKE"):
        if not isinstance(val, str) or not val:
            raise IRMutationError(
                f"add_filter: op '{op}' nécessite val=str non vide, "
                f"got {type(val).__name__}={val!r}"
            )
    elif op in ("IS_NULL", "IS_NOT_NULL"):
        # val est ignorée — pas de check, on accepte None ou n'importe quoi.
        pass
    elif op in ("EXISTS", "NOT_EXISTS"):
        # EXISTS/NOT_EXISTS attendent une sous-requête (dict ou structure
        # spécifique côté composer). En MVP : refuser (le LLM doit utiliser
        # run_pipeline pour ces patterns rares).
        raise IRMutationError(
            f"add_filter: op '{op}' non supporté en mutation (utiliser "
            "`run_pipeline` pour les sous-requêtes EXISTS/NOT_EXISTS)."
        )
    else:
        # Ops scalaires (=, !=, <>, <, >, <=, >=) : val doit être scalaire
        # (pas list/dict).
        if isinstance(val, (list, dict, set, tuple)):
            raise IRMutationError(
                f"add_filter: op '{op}' nécessite val scalaire (str/int/float/None), "
                f"got {type(val).__name__}={val!r}"
            )

    new_ir = _deep_copy_ir(ir)
    fg = new_ir.setdefault("filters_global", [])
    if not isinstance(fg, list):
        raise IRMutationError(
            f"add_filter: filters_global doit être une list, got {type(fg).__name__}"
        )
    if len(fg) >= _FILTERS_MAX:
        raise IRMutationError(f"add_filter: cap atteint ({len(fg)} ≥ {_FILTERS_MAX} max)")
    entry: dict[str, Any] = {"concept": concept, "op": op}
    # Pour IS_NULL/IS_NOT_NULL, la val est techniquement inutile — on l'omet.
    if op not in ("IS_NULL", "IS_NOT_NULL"):
        entry["val"] = val
    fg.append(entry)
    _get_ir_validate()(new_ir)
    return new_ir


def remove_filter(
    ir: dict,
    concept: str,
    op: Optional[str] = None,
) -> dict:
    """Supprime les filtres ``filters_global`` qui matchent ``concept``.

    Si ``op`` est fourni, ne matche que les filtres avec cet opérateur.

    **Lève si aucun match** (anti-silent-noop — l'utilisateur doit savoir
    que sa demande de retrait n'a pas eu d'effet, sinon il croit que le
    SQL est filtré différemment alors qu'il est inchangé).
    """
    _check_mutable(ir)
    if not isinstance(concept, str) or not concept.strip():
        raise IRMutationError(f"remove_filter: concept doit être str non vide, got {concept!r}")
    new_ir = _deep_copy_ir(ir)
    fg = new_ir.get("filters_global", []) or []
    if not isinstance(fg, list):
        raise IRMutationError(
            f"remove_filter: filters_global doit être une list, got {type(fg).__name__}"
        )
    before = len(fg)

    def _matches(f: Any) -> bool:
        if not isinstance(f, dict):
            return False
        if f.get("concept") != concept:
            return False
        if op is not None and f.get("op") != op:
            return False
        return True

    keep = [f for f in fg if not _matches(f)]
    if len(keep) == before:
        raise IRMutationError(
            f"remove_filter: aucun filtre 'concept={concept}'"
            + (f" op={op}" if op else "")
            + " trouvé dans filters_global"
        )
    new_ir["filters_global"] = keep
    _get_ir_validate()(new_ir)
    return new_ir


def add_group_by(ir: dict, concept: str) -> dict:
    """Ajoute un concept à ``group_by_concepts`` (idempotent : pas de doublon).

    Si déjà présent → no-op explicite (deep-copy returned but pas
    d'erreur). Ce n'est pas un cas dangereux : ajouter deux fois le
    même group-by donne le même résultat SQL.
    """
    _check_mutable(ir)
    if not isinstance(concept, str) or not concept.strip():
        raise IRMutationError(f"add_group_by: concept doit être str non vide, got {concept!r}")
    new_ir = _deep_copy_ir(ir)
    gb = new_ir.setdefault("group_by_concepts", [])
    if not isinstance(gb, list):
        raise IRMutationError(
            f"add_group_by: group_by_concepts doit être list, got {type(gb).__name__}"
        )
    if concept in gb:
        return new_ir  # idempotent
    if len(gb) >= _GROUP_BY_MAX:
        raise IRMutationError(f"add_group_by: cap atteint ({len(gb)} ≥ {_GROUP_BY_MAX} max)")
    gb.append(concept)
    _get_ir_validate()(new_ir)
    return new_ir


def remove_group_by(ir: dict, concept: str) -> dict:
    """Supprime un concept de ``group_by_concepts``.

    **Lève si absent** (anti-silent-noop, cohérent avec ``remove_filter``).
    """
    _check_mutable(ir)
    if not isinstance(concept, str) or not concept.strip():
        raise IRMutationError(f"remove_group_by: concept doit être str non vide, got {concept!r}")
    new_ir = _deep_copy_ir(ir)
    gb = new_ir.get("group_by_concepts", []) or []
    if not isinstance(gb, list):
        raise IRMutationError(
            f"remove_group_by: group_by_concepts doit être list, got {type(gb).__name__}"
        )
    if concept not in gb:
        raise IRMutationError(f"remove_group_by: concept '{concept}' absent de group_by_concepts")
    new_ir["group_by_concepts"] = [c for c in gb if c != concept]
    _get_ir_validate()(new_ir)
    return new_ir


def set_limit(ir: dict, n: Optional[int]) -> dict:
    """Set/clear le ``limit`` IR.

    Args:
        n : entier > 0 et <= ``_LIMIT_MAX``, ou ``None`` pour supprimer.

    Raises:
        IRMutationError : type invalide, valeur ≤ 0, ou cap dépassé.
    """
    _check_mutable(ir)
    if n is not None:
        # Exclut explicitement bool (sous-classe int en Python — un True
        # ne doit pas devenir LIMIT 1 par accident).
        if isinstance(n, bool) or not isinstance(n, int):
            raise IRMutationError(f"set_limit: n doit être int ou None, got {type(n).__name__}")
        if n <= 0:
            raise IRMutationError(f"set_limit: n doit être > 0, got {n}")
        if n > _LIMIT_MAX:
            raise IRMutationError(f"set_limit: n trop grand ({n} > {_LIMIT_MAX} max)")
    new_ir = _deep_copy_ir(ir)
    if n is None:
        new_ir.pop("limit", None)
    else:
        new_ir["limit"] = n
    _get_ir_validate()(new_ir)
    return new_ir


def set_order_by(ir: dict, order_list: list[dict]) -> dict:
    """Remplace ``order_by`` par la liste fournie.

    Chaque entrée : ``{"concept_or_alias": str, "direction": "ASC"|"DESC"}``.

    Passer ``[]`` pour clear l'ordre.
    """
    _check_mutable(ir)
    if not isinstance(order_list, list):
        raise IRMutationError(
            f"set_order_by: order_list doit être list, got {type(order_list).__name__}"
        )
    if len(order_list) > _ORDER_BY_MAX:
        raise IRMutationError(
            f"set_order_by: trop d'entrées ({len(order_list)} > {_ORDER_BY_MAX} max)"
        )
    _, _, valid_dirs = _get_ir_constants()
    cleaned: list[dict] = []
    seen: set[str] = set()
    for i, entry in enumerate(order_list):
        if not isinstance(entry, dict):
            raise IRMutationError(
                f"set_order_by: entry[{i}] doit être dict, got {type(entry).__name__}"
            )
        coa = entry.get("concept_or_alias")
        direction = entry.get("direction")
        if not isinstance(coa, str) or not coa.strip():
            raise IRMutationError(f"set_order_by: entry[{i}].concept_or_alias manquant ou vide")
        if direction not in valid_dirs:
            raise IRMutationError(
                f"set_order_by: entry[{i}].direction '{direction}' invalide. "
                f"Valides: {valid_dirs}"
            )
        if coa in seen:
            raise IRMutationError(f"set_order_by: entry[{i}].concept_or_alias '{coa}' dupliqué")
        seen.add(coa)
        cleaned.append({"concept_or_alias": coa, "direction": direction})
    new_ir = _deep_copy_ir(ir)
    if cleaned:
        new_ir["order_by"] = cleaned
    else:
        new_ir.pop("order_by", None)
    _get_ir_validate()(new_ir)
    return new_ir


# ----------------------------------------------------------------------
# Dispatch frozen — empêche un caller d'enregistrer une op malveillante
# au runtime (defense-in-depth).
# ----------------------------------------------------------------------


def _op_add_filter(ir: dict, params: dict) -> dict:
    return add_filter(
        ir,
        concept=params.get("concept"),
        op=params.get("operator", params.get("op_filter")),
        val=params.get("val"),
    )


def _op_remove_filter(ir: dict, params: dict) -> dict:
    return remove_filter(
        ir,
        concept=params.get("concept"),
        op=params.get("operator", params.get("op_filter")),
    )


def _op_add_group_by(ir: dict, params: dict) -> dict:
    return add_group_by(ir, concept=params.get("concept"))


def _op_remove_group_by(ir: dict, params: dict) -> dict:
    return remove_group_by(ir, concept=params.get("concept"))


def _op_set_limit(ir: dict, params: dict) -> dict:
    return set_limit(ir, n=params.get("n"))


def _op_set_order_by(ir: dict, params: dict) -> dict:
    return set_order_by(ir, order_list=params.get("order_by") or [])


_OP_DISPATCH = MappingProxyType(
    {
        "add_filter": _op_add_filter,
        "remove_filter": _op_remove_filter,
        "add_group_by": _op_add_group_by,
        "remove_group_by": _op_remove_group_by,
        "set_limit": _op_set_limit,
        "set_order_by": _op_set_order_by,
    }
)


def supported_ops() -> tuple[str, ...]:
    """Retourne le tuple des ops supportées (déterministe, trié)."""
    return tuple(sorted(_OP_DISPATCH.keys()))


def apply_operations(ir: dict, ops: list[dict]) -> dict:
    """Applique une liste d'opérations séquentiellement.

    **Atomique** : si une op échoue, ``IRMutationError`` est levée et
    l'IR initial est inchangé (chaque op deep-copy son input, donc on
    travaille toujours sur des copies). L'erreur indique l'index de l'op
    qui a fail pour faciliter le debug.

    Args:
        ir : IR initial (non muté).
        ops : liste de dicts ``{"op": str, ...params}`` (1 à
              ``_OP_MAX_PER_CALL`` entrées).

    Returns:
        Nouveau IR après application séquentielle de toutes les ops.

    Raises:
        IRMutationError : ops vide, trop long, ou si une op fail.
    """
    if not isinstance(ops, list):
        raise IRMutationError(f"apply_operations: ops doit être list, got {type(ops).__name__}")
    if len(ops) == 0:
        raise IRMutationError("apply_operations: ops doit contenir au moins 1 op")
    if len(ops) > _OP_MAX_PER_CALL:
        raise IRMutationError(f"apply_operations: trop d'ops ({len(ops)} > {_OP_MAX_PER_CALL} max)")

    current = ir
    for i, op_spec in enumerate(ops):
        if not isinstance(op_spec, dict):
            raise IRMutationError(
                f"apply_operations: ops[{i}] doit être dict, got {type(op_spec).__name__}"
            )
        op_name = op_spec.get("op")
        if op_name not in _OP_DISPATCH:
            raise IRMutationError(
                f"apply_operations: ops[{i}] op '{op_name}' non supporté. "
                f"Valides: {supported_ops()}"
            )
        try:
            current = _OP_DISPATCH[op_name](current, op_spec)
        except IRMutationError as exc:
            # Préfixe par l'index pour faciliter le debug côté agent.
            raise IRMutationError(f"ops[{i}] ({op_name}): {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            # Wrap toute exception en IRMutationError pour ne PAS exposer
            # de stack trace interne au LLM agent.
            raise IRMutationError(
                f"ops[{i}] ({op_name}): erreur inattendue {type(exc).__name__}: {exc}"
            ) from exc
    return current
