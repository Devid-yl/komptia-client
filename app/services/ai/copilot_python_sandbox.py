"""Sandbox Python restreint pour ``emit_via_code`` du grid-copilot.

Le LLM écrit du Python qui utilise des boucles pour générer massivement des
``cellDetails`` (via ``add_cell``) et des ``rows_overrides`` (via
``add_override``). Ce fichier contient la validation AST + l'exécution
restreinte + la collecte des résultats.

**Pourquoi un sandbox ?** Le LLM est smart mais PAS fiable pour énumérer 135
entrées JSON à la main sans en oublier. Donner "3 boucles for" compact = même
LLM, output 30 lignes, couverture 100%. C'est le pattern qu'un agent
Claude Code utilise naturellement (Python + Bash).

**Sécurité** : l'app tourne en local mono-utilisateur (déploiement client),
le seul "attaquant" possible = un LLM qui hallucine. Défense en profondeur :
1. AST walk qui rejette import, dunder attribute access, noms interdits.
2. ``__builtins__`` réduit à une whitelist (range, len, sum, str, int, …).
3. ``sys.settrace`` pour plafond d'instructions + timeout coopératif.
4. Cap sur la taille de la sortie collectée.

Pas de subprocess pour éviter overhead + complexité IPC. Si des risques
multi-tenant apparaissent plus tard, upgrade vers ``subprocess.run`` avec
``resource.setrlimit`` est trivial — la signature publique reste la même.
"""

from __future__ import annotations

import ast
import logging
import sys
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SandboxError(Exception):
    """Erreur d'exécution dans le sandbox — validation ou runtime."""


def _enforce_session_budget(session: Dict[str, Any]) -> None:
    """Vérifie que ``session`` ne dépasse pas les caps après exécution.

    Évite qu'un LLM accumule de la data sur les 30 tours jusqu'à épuiser
    la RAM. Check par nombre de clés + taille estimée via sys.getsizeof
    (imprécis pour les nested, mais suffisant pour catcher un accumulateur
    abusif).
    """
    if not session:
        return
    if len(session) > _MAX_SESSION_KEYS:
        raise SandboxError(
            f"`session` dépasse la limite de {_MAX_SESSION_KEYS} clés "
            f"({len(session)} actuellement). Nettoie les clés devenues "
            "inutiles avec `del session['key']`."
        )
    try:
        import sys as _sys

        total = _sys.getsizeof(session)
        for k, v in session.items():
            total += _sys.getsizeof(k) + _sys.getsizeof(v)
            # Parcours complet pour catcher les grosses listes accumulées.
            # Pour un dict de 200 clés × 10k items = 2M getsizeof calls,
            # coût ~100ms. Acceptable pour un check post-turn.
            if isinstance(v, (list, tuple)):
                for x in v:
                    total += _sys.getsizeof(x)
                    if total > _MAX_SESSION_BYTES:
                        break
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    total += _sys.getsizeof(kk) + _sys.getsizeof(vv)
                    if total > _MAX_SESSION_BYTES:
                        break
            if total > _MAX_SESSION_BYTES:
                break
        if total > _MAX_SESSION_BYTES:
            raise SandboxError(
                f"`session` trop volumineux ({total // 1024} KB > "
                f"{_MAX_SESSION_BYTES // 1024} KB). Stocke moins, ou "
                "utilise des structures plus compactes."
            )
    except SandboxError:
        raise
    except Exception:
        # getsizeof peut lever sur des objets weird. Ne pas planter la
        # requête pour un check défensif.
        pass


# Noms jamais exposés dans le namespace d'exécution. Sont interdits même si
# le LLM tente de les référencer (ex: ``open("/etc/passwd")``). La liste
# couvre les primitives I/O, metaprog, et les réflexes qu'un LLM pourrait
# utiliser pour tenter une échappée (``__import__``, ``getattr`` sur des
# objets pour remonter à leur module, etc.).
_DISALLOWED_NAMES = frozenset(
    {
        "__builtins__",
        "__import__",
        "exec",
        "eval",
        "compile",
        "open",
        "input",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
        "hasattr",
        "breakpoint",
        "help",
        "memoryview",
        "bytearray",
        "bytes",  # accès bas-niveau
        "object",
        "type",
        "super",  # metaprog pour remonter la MRO
        "__class__",
        "__dict__",
        "__globals__",
        "__subclasses__",
        "__mro__",
        "__bases__",
    }
)


# Modules Python standard autorisés à l'import depuis le sandbox. Choix basé
# sur l'usage attendu (exploration de structures, agrégation, parsing) sans
# exposer I/O ni syscalls. Un LLM qui écrit ``import math`` ou
# ``from collections import Counter`` passe la validation ; ``import os`` ne
# passe PAS (même module standard).
#
# Les modules de cette liste sont PRÉ-IMPORTÉS dans le namespace d'exécution
# à chaque run (pas d'I/O disque au runtime) pour que l'instruction ``import``
# soit effectivement un no-op côté LLM — on n'exécute PAS ``importlib.import_module``
# pendant le sandbox. Voir :func:`_build_sandbox_namespace`.
_ALLOWED_IMPORT_MODULES = frozenset(
    {
        "math",
        "json",
        "itertools",
        "collections",
        "re",
        "datetime",
        "statistics",
        "copy",
    }
)


def _make_capped_math_module(original_math: Any) -> Any:
    """Enveloppe le module ``math`` pour plafonner les fonctions qui peuvent
    produire des entiers/floats massifs bypassant ``_MAX_INT_LITERAL``.

    Sans cap : ``"x" * int(math.pow(10, 7))`` alloue 10 MB, enchaîné avec
    une multiplication par 1000 → 10 GB → OOM du process Tornado.

    Les fonctions sensibles sont wrappées : ``pow``, ``factorial``,
    ``exp``, ``perm``, ``comb``. Leur résultat est refusé (``ValueError``)
    si la magnitude dépasse ``_MAX_INT_LITERAL``. Les autres fonctions
    (``sqrt``, ``sin``, ``log``, etc.) sont conservées telles quelles —
    leur domaine de sortie est borné ou raisonnable.
    """
    import types

    proxy = types.SimpleNamespace()
    # Recopier tous les attributs publics du vrai module math
    for attr_name in dir(original_math):
        if attr_name.startswith("_"):
            continue
        setattr(proxy, attr_name, getattr(original_math, attr_name))

    # Wrappers cappés pour les fonctions à risque
    _CAP = _MAX_INT_LITERAL

    def _capped_pow(x: Any, y: Any, *args: Any) -> Any:
        result = original_math.pow(x, y, *args)
        if abs(result) > _CAP:
            raise ValueError(
                f"math.pow({x}, {y}) = {result} dépasse la limite sandbox "
                f"({_CAP}). Utilise un littéral plus petit."
            )
        return result

    def _capped_factorial(n: Any) -> Any:
        if isinstance(n, (int, float)) and n > 20:
            raise ValueError(
                f"math.factorial({n}) : n > 20 produit un entier massif. " "Limite sandbox."
            )
        return original_math.factorial(n)

    def _capped_exp(x: Any) -> Any:
        result = original_math.exp(x)
        if abs(result) > _CAP:
            raise ValueError(f"math.exp({x}) = {result} dépasse la limite sandbox ({_CAP}).")
        return result

    def _capped_perm(n: Any, k: Any = None) -> Any:
        result = original_math.perm(n, k) if k is not None else original_math.perm(n)
        if result > _CAP:
            raise ValueError(f"math.perm : résultat {result} dépasse la limite sandbox ({_CAP}).")
        return result

    def _capped_comb(n: Any, k: Any) -> Any:
        result = original_math.comb(n, k)
        if result > _CAP:
            raise ValueError(f"math.comb : résultat {result} dépasse la limite sandbox ({_CAP}).")
        return result

    proxy.pow = _capped_pow
    proxy.factorial = _capped_factorial
    proxy.exp = _capped_exp
    if hasattr(original_math, "perm"):
        proxy.perm = _capped_perm
    if hasattr(original_math, "comb"):
        proxy.comb = _capped_comb
    return proxy


def _inject_allowed_modules(namespace: Dict[str, Any]) -> None:
    """Pré-importe les modules whitelist et les injecte dans le namespace
    d'exécution du sandbox, sous leur nom top-level.

    Deux effets complémentaires :

    1. Le module est directement disponible par son nom dans le namespace
       (``namespace["math"] = math``). Ça permet à un code LLM sans
       ``import`` explicite d'utiliser ``math.sqrt(x)`` directement.

    2. L'instruction ``import math`` et ``from math import sqrt`` doivent
       fonctionner au runtime. Python exécute ces instructions en appelant
       ``__import__`` depuis ``__builtins__`` — comme le sandbox a une
       whitelist de builtins sans ``__import__``, un import lèverait
       ``ImportError``. On fournit donc un ``__import__`` contrôlé qui
       résout UNIQUEMENT les modules whitelistés (depuis le namespace
       déjà peuplé) et lève ``ImportError`` sinon. Double barrière :
       l'AST validation refuse déjà les imports non-whitelistés au parse,
       ce ``__import__`` est la defense-in-depth au runtime.

    **Sécurité** : ``__import__`` reçoit le nom comme string au runtime.
    Si un code malicieux parvenait à passer l'AST validation (pas de cas
    connu mais défense en profondeur), il ne pourrait quand même pas
    importer ``os``/``subprocess``/etc. depuis la sandbox.
    """
    import importlib

    builtins: Dict[str, Any] = namespace.get("__builtins__") or {}

    for module_name in _ALLOWED_IMPORT_MODULES:
        try:
            module = importlib.import_module(module_name)
            # Pour ``math`` : wrapper les fonctions qui peuvent produire des
            # entiers/floats massifs (``pow``, ``factorial``, ``exp``, ``perm``,
            # ``comb``). Sans ça, ``int(math.pow(10, 7))`` bypass la limite
            # ``_MAX_INT_LITERAL`` et permet ``"x" * <big>`` → DoS OOM.
            if module_name == "math":
                module = _make_capped_math_module(module)
            namespace[module_name] = module
        except Exception as exc:  # noqa: BLE001 — defensive, stdlib modules should always import
            # Log au niveau module, pas au niveau par-run (un échec stdlib
            # est un signal infrastructure, pas une erreur user).
            import logging

            logging.getLogger(__name__).warning(
                "Sandbox : module `%s` indisponible à l'import (%s). "
                "Le LLM ne pourra pas l'utiliser même s'il le référence.",
                module_name,
                exc,
            )

    def _sandbox_import(
        name: str,
        _globals: Optional[Dict[str, Any]] = None,
        _locals: Optional[Dict[str, Any]] = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> Any:
        """__import__ contrôlé : ne résout que les modules whitelistés."""
        if level != 0:
            raise ImportError("Les imports relatifs ne sont pas supportés dans le sandbox.")
        root = name.split(".", 1)[0] if isinstance(name, str) else ""
        if root not in _ALLOWED_IMPORT_MODULES:
            raise ImportError(
                f"Le module `{name}` n'est pas dans la whitelist du sandbox. "
                f"Modules autorisés : {sorted(_ALLOWED_IMPORT_MODULES)}."
            )
        module = namespace.get(root)
        if module is None:
            raise ImportError(
                f"Module `{root}` whitelisté mais non chargé (erreur infrastructure)."
            )
        # ``from math import sqrt`` : Python attend qu'on retourne le module
        # math ; l'accès à sqrt se fait ensuite via getattr. Si `fromlist`
        # est non-vide, on retourne aussi le module parent — Python ira
        # chercher les noms demandés dessus.
        return module

    builtins["__import__"] = _sandbox_import
    # Ré-attacher au namespace (si __builtins__ était un dict partagé, l'assignment
    # précédent a muté en place ; si c'était manquant, on le fournit).
    namespace["__builtins__"] = builtins


# Attributs d'introspection frame/generator/coroutine/traceback qui NE
# commencent PAS par `_` et qui permettraient de remonter aux globals
# parents (porte d'évasion du sandbox quand on autorise GeneratorExp,
# comprehensions async, etc.). On les blackliste explicitement.
_DISALLOWED_ATTRIBUTES = frozenset(
    {
        # Generators
        "gi_frame",
        "gi_code",
        "gi_running",
        "gi_yieldfrom",
        "gi_suspended",
        # Coroutines
        "cr_frame",
        "cr_code",
        "cr_running",
        "cr_await",
        "cr_origin",
        "cr_suspended",
        # Async generators
        "ag_frame",
        "ag_code",
        "ag_running",
        "ag_await",
        "ag_suspended",
        # Frames
        "f_back",
        "f_globals",
        "f_locals",
        "f_code",
        "f_lineno",
        "f_builtins",
        "f_lasti",
        "f_trace",
        # Tracebacks
        "tb_frame",
        "tb_next",
        "tb_lasti",
        "tb_lineno",
        # Code objects
        "co_consts",
        "co_names",
        "co_varnames",
        "co_cellvars",
        "co_freevars",
        "co_code",
        "co_filename",
    }
)


# Whitelist des builtins Python exposés dans le sandbox. Pas de magie — on
# liste EXPLICITEMENT tout ce qu'on autorise pour que l'ajout futur soit un
# choix délibéré. Les fonctions arithmétiques, les collections, les
# conversions de type, les itertools-likes : tout ce dont une énumération
# structurelle a besoin.
_ALLOWED_BUILTINS: Dict[str, Any] = {
    "range": range,
    "len": len,
    "sum": sum,
    "min": min,
    "max": max,
    "abs": abs,
    "round": round,
    "divmod": divmod,
    "pow": pow,
    "enumerate": enumerate,
    "zip": zip,
    "sorted": sorted,
    "reversed": reversed,
    "list": list,
    "dict": dict,
    "set": set,
    "tuple": tuple,
    "frozenset": frozenset,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "any": any,
    "all": all,
    "filter": filter,
    "map": map,
    "isinstance": isinstance,
    "True": True,
    "False": False,
    "None": None,
    # Exceptions utiles pour que le code LLM puisse try/except proprement
    "Exception": Exception,
    "ValueError": ValueError,
    "KeyError": KeyError,
    "TypeError": TypeError,
    "IndexError": IndexError,
    "AttributeError": AttributeError,
    "ZeroDivisionError": ZeroDivisionError,
}


# Caps de sortie — un payload raisonnable est ~1000 cellules (template 64×17
# max ~1088 positions) ; 5000 couvre des cas plus grands sans permettre un DoS.
_MAX_CELLS = 5000
_MAX_OVERRIDES = 5000
_MAX_LOG_LINES = 200
_MAX_LOG_LINE_LEN = 500

# Plafonds d'exécution. Le trace-based timeout est APPROXIMATIF : il vérifie
# le temps à chaque `call`/`line` event, donc pour des opérations C-pures
# (grosse list comprehension, string mult, …) la vérification peut tarder.
# Suffisant ici parce que les boucles LLM sont du Python pur ET que les
# littéraux entiers sont cappés à _MAX_INT_LITERAL (via AST) pour empêcher
# l'allocation runtime de structures massives.
_DEFAULT_TIMEOUT_S = 60.0
_MAX_INSTRUCTIONS = 10_000_000
_MAX_INT_LITERAL = 1_000_000
# Cap sur les littéraux string/bytes — combiné avec _MAX_INT_LITERAL,
# borne `"x" * 999_999` à ~1MB. Chaînage possible mais chaque étape
# intermédiaire reste sous contrôle raisonnable.
# NOTE : le risque de DoS via chaînage `"x" * N * M` (explosion 1TB en 2 ops)
# reste théorique sur ce deployment (local, single-user, LLM non malveillant).
# Mitigation future : subprocess avec resource.setrlimit.
_MAX_STR_LITERAL = 10_000
# Cap sur la taille du dict `session` — empêche l'accumulation de données
# sur les 30 tours du turn-loop. Compté par clés et par taille estimée via
# sys.getsizeof. Check post-exec (simple, imprécis mais suffisant).
_MAX_SESSION_KEYS = 200
_MAX_SESSION_BYTES = 16 * 1024 * 1024  # 16MB


def validate_code(code: str) -> None:
    """Parse et vérifie l'AST. Rejette tout ce qui n'est pas un programme
    "pur énumération de cellules".

    Règles (défense en profondeur) :
        - Syntaxe valide (sinon ``SandboxError`` avec la ligne).
        - Pas de ``import`` / ``from ... import`` (le sandbox fournit déjà tout).
        - Pas de `def`/`async def`/`lambda`/`yield`/`await`/generator-expression :
          empêche l'escape classique via ``generator.gi_frame.f_back.f_globals``
          qui remonte aux builtins non-restreints du parent. Pour l'usage
          "pure énumération de cellules", on n'a PAS besoin de functions
          utilisateur — juste des boucles et des conditions.
        - Pas d'attribut commençant par ``_`` (bloque les dunders type
          ``__class__``, ``__globals__``).
        - Pas de nom dans ``_DISALLOWED_NAMES``.
        - Pas d'opérateur ``**`` (Pow) : empêche l'écriture compacte de gros
          littéraux (``10**9`` → 2GB string via ``"x"*10**9``).
        - Littéraux entiers plafonnés à 1M.
        - Pas de ``global`` / ``nonlocal`` : empêche de muter le namespace
          parent même si une fonction était autorisée.

    Raises:
        SandboxError: avec un message explicite (ligne) si violation.
    """
    try:
        tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise SandboxError(f"Syntaxe Python invalide : {exc.msg} (ligne {exc.lineno})") from exc

    for node in ast.walk(tree):
        # Imports : autorisés pour la whitelist _ALLOWED_IMPORT_MODULES
        # UNIQUEMENT, refusés pour tout le reste. Les star-imports
        # (``from X import *``) sont toujours refusés même sur module
        # whitelisted car ils polluent le namespace avec des noms qu'on
        # ne peut pas contrôler au parse. Les imports DOTTÉS (``import
        # collections.abc``) sont refusés aussi : l'API `_sandbox_import`
        # résout seulement le root, un submodule peut exposer des types
        # inattendus (information disclosure via __mro__).
        if isinstance(node, ast.Import):
            for alias in node.names:
                if "." in alias.name:
                    raise SandboxError(
                        f"Import dotté `{alias.name}` interdit (ligne "
                        f"{getattr(node, 'lineno', '?')}). Seuls les modules "
                        f"top-level de la whitelist sont autorisés. Modules : "
                        f"{sorted(_ALLOWED_IMPORT_MODULES)}."
                    )
                if alias.name not in _ALLOWED_IMPORT_MODULES:
                    raise SandboxError(
                        f"Import du module `{alias.name}` interdit (ligne "
                        f"{getattr(node, 'lineno', '?')}). Modules autorisés : "
                        f"{sorted(_ALLOWED_IMPORT_MODULES)}."
                    )
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            # Refuser les imports dottés (from collections.abc import …)
            if "." in module_name:
                raise SandboxError(
                    f"Import `from {module_name}` dotté interdit (ligne "
                    f"{getattr(node, 'lineno', '?')}). Seuls les modules "
                    f"top-level de la whitelist sont autorisés."
                )
            if module_name not in _ALLOWED_IMPORT_MODULES:
                raise SandboxError(
                    f"Import `from {module_name or '?'}` interdit (ligne "
                    f"{getattr(node, 'lineno', '?')}). Modules autorisés : "
                    f"{sorted(_ALLOWED_IMPORT_MODULES)}."
                )
            # Refuser star-imports même pour modules whitelistés
            for alias in node.names:
                if alias.name == "*":
                    raise SandboxError(
                        f"Star-import `from {node.module} import *` interdit "
                        f"(ligne {getattr(node, 'lineno', '?')}) — liste "
                        "explicitement les noms nécessaires."
                    )
        # Coroutines, lambdas, générateurs-fonctions : toujours interdits
        # (escape via .cr_frame / .__globals__ / gi_frame). FunctionDef
        # (``def``) est maintenant autorisé pour permettre au LLM d'extraire
        # une logique réutilisable (ex: helper de calcul, key de sort) ; la
        # sécurité est garantie par la blacklist exhaustive sur les noms
        # (_DISALLOWED_NAMES) et attributs (_DISALLOWED_ATTRIBUTES, y compris
        # __globals__, __code__, gi_frame, etc.). Une fonction définie ne
        # peut donc pas introspecter son scope parent.
        if isinstance(
            node,
            (
                ast.AsyncFunctionDef,
                ast.Lambda,
                ast.Yield,
                ast.YieldFrom,
                ast.Await,
                ast.AsyncFor,
                ast.AsyncWith,
            ),
        ):
            kind = type(node).__name__
            raise SandboxError(
                f"Construction `{kind}` interdite (ligne "
                f"{getattr(node, 'lineno', '?')}). Utilise `def` classique "
                "si tu as besoin d'une fonction, ou une boucle à plat."
            )
        # Global/nonlocal : empêche de remonter les scopes
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            raise SandboxError(
                f"`{type(node).__name__}` interdit (ligne " f"{getattr(node, 'lineno', '?')})."
            )
        # Opérateur puissance : permet `10**9` → combiné avec `*` sur string
        # donne une allocation gigaoctets. Inutile pour l'énumération.
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            raise SandboxError(
                f"Opérateur `**` interdit (ligne "
                f"{getattr(node, 'lineno', '?')}). Utilise un littéral "
                "explicite (1024 au lieu de 2**10)."
            )
        # Littéraux numériques plafonnés — prévient `list(range(10**10))`
        # qui consommerait toute la RAM avant que le trace ne coupe.
        # Couvre int ET float : `1e9` (float) → `int(1e9)` = 10**9
        # contournait le cap si on ne checkait que les int.
        if isinstance(node, ast.Constant):
            v = node.value
            if isinstance(v, int) and not isinstance(v, bool):
                if abs(v) > _MAX_INT_LITERAL:
                    raise SandboxError(
                        f"Littéral entier trop grand ({v}) à la ligne "
                        f"{getattr(node, 'lineno', '?')} — max "
                        f"{_MAX_INT_LITERAL}."
                    )
            elif isinstance(v, float):
                # inf/nan rejetés (éviter d'injecter des poisons float via
                # 1e400 → inf). Sinon cap sur la magnitude pour prévenir
                # int(1e12) qui explose en runtime.
                import math

                if not math.isfinite(v):
                    raise SandboxError(
                        f"Littéral float non-fini ({v}) à la ligne "
                        f"{getattr(node, 'lineno', '?')}."
                    )
                if abs(v) > _MAX_INT_LITERAL:
                    raise SandboxError(
                        f"Littéral float trop grand ({v}) à la ligne "
                        f"{getattr(node, 'lineno', '?')} — max magnitude "
                        f"{_MAX_INT_LITERAL}."
                    )
            elif isinstance(v, str):
                # Cap sur string literals — combiné avec `*` sur entier
                # cappé, ça borne `"x" * 999_999` à ~1MB. Chaînage
                # `"x" * 999 * 999` reste possible mais la première étape
                # ne peut produire qu'une string sous le cap.
                if len(v) > _MAX_STR_LITERAL:
                    raise SandboxError(
                        f"Littéral string trop long ({len(v)} chars) à la "
                        f"ligne {getattr(node, 'lineno', '?')} — max "
                        f"{_MAX_STR_LITERAL}."
                    )
            elif isinstance(v, bytes):
                if len(v) > _MAX_STR_LITERAL:
                    raise SandboxError(
                        f"Littéral bytes trop long à la ligne " f"{getattr(node, 'lineno', '?')}."
                    )
        # Accès aux attributs dunders — porte d'évasion classique
        if isinstance(node, ast.Attribute):
            if isinstance(node.attr, str) and node.attr.startswith("_"):
                raise SandboxError(
                    f"Accès à l'attribut `{node.attr}` interdit (ligne "
                    f"{getattr(node, 'lineno', '?')}) — les attributs "
                    "commençant par `_` peuvent permettre d'échapper au sandbox."
                )
            # Attributs d'introspection frame/gen/coroutine sans `_` préfixe.
            # Indispensable pour fermer l'escape via genexp.gi_frame.f_back…
            if node.attr in _DISALLOWED_ATTRIBUTES:
                raise SandboxError(
                    f"Accès à l'attribut `{node.attr}` interdit (ligne "
                    f"{getattr(node, 'lineno', '?')}) — accès réservé à "
                    "l'introspection interne Python."
                )
            # ``str.format`` : les format specs sont parsées au RUNTIME, pas
            # au parse-time. ``"{0.__class__.__mro__[1].__subclasses__}".format(x)``
            # passe l'AST validation (pas d'attribut `_` visible dans l'AST —
            # ils sont dans la string) mais fuite la structure de classes au
            # runtime. Les f-strings sont parsées au compile-time → déjà
            # bloquées par la validation AST. On force l'usage des f-strings
            # en refusant ``.format()`` tout court — simple, efficace, zéro
            # faux positif utile (le LLM n'a jamais besoin de ``.format``).
            if node.attr == "format":
                raise SandboxError(
                    f"Appel `.format()` interdit (ligne "
                    f"{getattr(node, 'lineno', '?')}) — utilise une f-string "
                    'à la place (``f"total: {{x}}"`` au lieu de '
                    '``"total: {{}}".format(x)``). Les f-strings sont '
                    "parsées au compile-time et passent l'AST validation ; "
                    "``.format`` parse au runtime et bypass la défense."
                )
        # Noms explicitement interdits
        if isinstance(node, ast.Name):
            if node.id in _DISALLOWED_NAMES:
                raise SandboxError(
                    f"Nom `{node.id}` interdit dans le sandbox "
                    f"(ligne {getattr(node, 'lineno', '?')})."
                )


def run_code_with_helpers(
    code: str,
    tabs: List[Dict[str, Any]],
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    session: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Exécute ``code`` dans un namespace restreint et retourne les cellules
    collectées.

    Helpers exposés au code :
        - ``add_cell(r, c, match=None, match_exclude=None, value_column=None,
          source_tab_index=None, derived_formula=None, label=None)`` :
          ajoute une entrée cellDetails à la position (r, c). Validation
          légère des types — le pipeline ``_validate_emit_tab`` fait la
          validation complète ensuite.
        - ``add_override(r, c, value)`` : ajoute un rows_overrides (texte).
        - variable ``tabs`` : liste de dicts ``{index, label, columns,
          row_count, is_active, sql?, sheet_content?}`` — le LLM peut
          itérer ``for tab in tabs: for cell in tab['sheet_content']: ...``.
        - variable ``session`` : dict partagé avec les appels ``run_python``
          précédents du même turn (agrégats pré-calculés réutilisables).

    Args:
        code: Python source à exécuter.
        tabs: snapshot de ``ctx.tabs_context`` déjà enrichi (voir handler).
        timeout_s: plafond d'exécution coopératif.
        session: dict partagé (mutations persistent côté caller).

    Returns:
        ``{cells, overrides, logs}`` où cells/overrides sont des dicts keyed
        par ``"R,C"`` et logs est la liste des chaînes ``print(...)``.

    Raises:
        SandboxError: validation AST, timeout, cap dépassé, ou exception
        durant l'exécution (message préserve le type d'erreur Python).
    """
    validate_code(code)

    collected_cells: Dict[str, Dict[str, Any]] = {}
    collected_overrides: Dict[str, Any] = {}
    logs: List[str] = []

    def add_cell(
        r: int,
        c: int,
        match: Optional[Dict[str, Any]] = None,
        match_exclude: Optional[Dict[str, List[Any]]] = None,
        value_column: Optional[str] = None,
        source_tab_index: Optional[int] = None,
        derived_formula: Optional[Dict[str, Any]] = None,
        label: Optional[str] = None,
    ) -> None:
        # Types stricts — empêche le LLM de passer un float ou une string
        # qui plantent plus tard dans _validate_emit_tab avec un message
        # moins clair.
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError(f"add_cell: r doit être int, reçu {type(r).__name__}")
        if not isinstance(c, int) or isinstance(c, bool):
            raise TypeError(f"add_cell: c doit être int, reçu {type(c).__name__}")
        if r < 0 or c < 0:
            raise ValueError(f"add_cell: r, c doivent être >= 0 (reçu {r}, {c})")
        if len(collected_cells) >= _MAX_CELLS:
            raise SandboxError(
                f"add_cell: limite atteinte ({_MAX_CELLS} cellules max). "
                "Simplifie le code ou découpe en plusieurs onglets."
            )
        entry: Dict[str, Any] = {}
        if match is not None:
            entry["match"] = match
        if match_exclude is not None:
            entry["match_exclude"] = match_exclude
        if value_column is not None:
            entry["value_column"] = value_column
        if source_tab_index is not None:
            entry["source_tab_index"] = source_tab_index
        if derived_formula is not None:
            entry["derived_formula"] = derived_formula
        if label is not None:
            entry["label"] = label
        collected_cells[f"{r},{c}"] = entry

    def add_override(r: int, c: int, value: Any) -> None:
        if not isinstance(r, int) or isinstance(r, bool):
            raise TypeError("add_override: r doit être int")
        if not isinstance(c, int) or isinstance(c, bool):
            raise TypeError("add_override: c doit être int")
        if r < 0 or c < 0:
            raise ValueError(f"add_override: r, c doivent être >= 0")
        if len(collected_overrides) >= _MAX_OVERRIDES:
            raise SandboxError(f"add_override: limite atteinte ({_MAX_OVERRIDES} overrides max).")
        # value doit être un scalaire sérialisable (string, number, bool, None).
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise TypeError(
                f"add_override: value doit être scalaire "
                f"(str/int/float/bool/None), reçu {type(value).__name__}"
            )
        collected_overrides[f"{r},{c}"] = value

    def _sandbox_print(*args: Any, **_kwargs: Any) -> None:
        if len(logs) >= _MAX_LOG_LINES:
            return
        try:
            line = " ".join(str(a) for a in args)
        except Exception:
            line = "<unprintable>"
        if len(line) > _MAX_LOG_LINE_LEN:
            line = line[:_MAX_LOG_LINE_LEN] + "…"
        logs.append(line)

    # Namespace d'exécution : pas de __builtins__ par défaut → on fournit la
    # whitelist. `print` est remplacé pour capturer les logs côté helpers.
    sandbox_builtins = dict(_ALLOWED_BUILTINS)
    sandbox_builtins["print"] = _sandbox_print

    namespace = {
        "__builtins__": sandbox_builtins,
        "add_cell": add_cell,
        "add_override": add_override,
        "tabs": tabs,
        "session": session if session is not None else {},
    }
    # Pré-imports whitelist : les modules sont chargés UNE fois côté serveur
    # et injectés dans le namespace. Le code LLM écrit ``import math`` qui
    # devient un no-op effectif (le module est déjà disponible via le
    # namespace parent) — l'AST validation a autorisé l'instruction.
    _inject_allowed_modules(namespace)

    # Plafond coopératif : le trace function est appelé à chaque `call`/`line`.
    # Pour du code pur Python (boucles), ça suffit à couper un while-True.
    deadline = time.monotonic() + timeout_s
    instruction_count = [0]

    def _trace(_frame: Any, _event: str, _arg: Any) -> Any:
        instruction_count[0] += 1
        if instruction_count[0] > _MAX_INSTRUCTIONS:
            raise SandboxError(
                f"Limite d'instructions atteinte ({_MAX_INSTRUCTIONS}). "
                "Le code boucle trop longtemps — simplifie."
            )
        if time.monotonic() > deadline:
            raise SandboxError(
                f"Timeout dépassé ({timeout_s}s). Le code prend trop de temps " "à s'exécuter."
            )
        return _trace

    try:
        compiled = compile(code, "<copilot_sandbox>", "exec")
    except SyntaxError as exc:
        # Théoriquement déjà attrapé par validate_code, mais ceinture +
        # bretelles : compile peut révéler des erreurs plus tardives.
        raise SandboxError(f"Compilation échouée : {exc}") from exc

    sys.settrace(_trace)
    try:
        exec(compiled, namespace, namespace)
    except SandboxError:
        raise
    except Exception as exc:
        # Toute autre exception = erreur runtime du code LLM — on la renvoie
        # dans le message pour qu'il puisse la corriger au tour suivant.
        raise SandboxError(f"Erreur runtime dans le code : {type(exc).__name__}: {exc}") from exc
    finally:
        sys.settrace(None)

    # Check budget session après exec (même si emit_via_code est typiquement
    # le terminal call, le caller peut enchaîner run_python après)
    if session is not None:
        _enforce_session_budget(session)

    logger.info(
        "emit_via_code sandbox : %d cells, %d overrides, %d log lines, " "%d instructions",
        len(collected_cells),
        len(collected_overrides),
        len(logs),
        instruction_count[0],
    )
    return {
        "cells": collected_cells,
        "overrides": collected_overrides,
        "logs": logs,
    }


def run_exploration(
    code: str,
    tabs: List[Dict[str, Any]],
    session: Dict[str, Any],
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> Dict[str, Any]:
    """Exécute du Python d'EXPLORATION (pas d'émission de cellules).

    Même sandbox que ``run_code_with_helpers`` (AST validator, restricted
    builtins, settrace timeout) mais sans exposer ``add_cell`` / ``add_override``.
    L'objectif : permettre au LLM de faire des analyses, cross-sums,
    détections de patterns AVANT d'écrire son code d'émission — comme un
    Claude Code utilise Bash+Python en exploration.

    Helpers exposés :
        - ``tabs`` (list) : même structure que dans ``run_code_with_helpers``.
        - ``session`` (dict) : PARTAGÉ entre appels successifs dans le même
          turn loop. Le LLM peut y stocker des agrégats pour les réutiliser
          plus tard (équivalent du pickle que j'utilise entre scripts Python).
        - ``print(...)`` : capturé dans ``stdout``.

    Args:
        code: source Python à exécuter.
        tabs: snapshot des onglets (déjà deep-copié par le caller).
        session: dict partagé (mutated in-place).
        timeout_s: timeout coopératif.

    Returns:
        ``{stdout, session_keys}`` — pas de cellules, juste de l'output.

    Raises:
        SandboxError: même contrat que ``run_code_with_helpers``.
    """
    validate_code(code)

    logs: List[str] = []

    def _sandbox_print(*args: Any, **_kwargs: Any) -> None:
        if len(logs) >= _MAX_LOG_LINES:
            return
        try:
            line = " ".join(str(a) for a in args)
        except Exception:
            line = "<unprintable>"
        if len(line) > _MAX_LOG_LINE_LEN:
            line = line[:_MAX_LOG_LINE_LEN] + "…"
        logs.append(line)

    sandbox_builtins = dict(_ALLOWED_BUILTINS)
    sandbox_builtins["print"] = _sandbox_print

    namespace = {
        "__builtins__": sandbox_builtins,
        "tabs": tabs,
        "session": session,
    }
    _inject_allowed_modules(namespace)

    deadline = time.monotonic() + timeout_s
    instruction_count = [0]

    def _trace(_frame: Any, _event: str, _arg: Any) -> Any:
        instruction_count[0] += 1
        if instruction_count[0] > _MAX_INSTRUCTIONS:
            raise SandboxError(f"Limite d'instructions atteinte ({_MAX_INSTRUCTIONS}).")
        if time.monotonic() > deadline:
            raise SandboxError(f"Timeout dépassé ({timeout_s}s).")
        return _trace

    try:
        compiled = compile(code, "<copilot_exploration>", "exec")
    except SyntaxError as exc:
        raise SandboxError(f"Compilation échouée : {exc}") from exc

    sys.settrace(_trace)
    try:
        exec(compiled, namespace, namespace)
    except SandboxError:
        raise
    except Exception as exc:
        raise SandboxError(f"Erreur runtime : {type(exc).__name__}: {exc}") from exc
    finally:
        sys.settrace(None)

    _enforce_session_budget(session)

    logger.info(
        "run_python exploration : %d log lines, %d session keys, %d instr",
        len(logs),
        len(session),
        instruction_count[0],
    )
    return {
        "stdout": logs,
        "session_keys": sorted(session.keys()),
    }
