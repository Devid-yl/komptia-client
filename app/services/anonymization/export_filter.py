"""Filtre d'anonymisation pour les EXPORTS de classeurs/feuilles.

Source unique de vérité pour TOUTES les surfaces d'export Komptia (grille
Iris, /datastore, dashboards, automations, reports) quand l'utilisateur
choisit d'exporter « avec les valeurs anonymisées » plutôt qu'« en clair ».

Différence fondamentale avec :func:`anonymize_for_llm` (module ``proxy``) :

- ``anonymize_for_llm`` fait un **round-trip** clair→token→clair : le LLM
  voit ``§CLIENT_A§`` puis on restaure la vraie valeur dans la réponse.
- Ce module produit une copie **finale** destinée à un fichier remis à
  l'utilisateur. Pas de restauration. Les délimiteurs internes ``§`` sont
  retirés pour afficher un pseudonyme propre (``§CLIENT_A§`` → ``CLIENT_A``).

**Doctrine** (CLAUDE.md ; mémoires ``project_value_mapping_removed_2026_05_22``
et ``feedback_no_real_names_in_code``) : ``/data-privacy`` (table
``anonymization_terms``) est la SEULE source de vérité. Un terme que
l'utilisateur n'a PAS configuré reste **en clair** — on n'invente aucune
abréviation, et on n'applique **aucune** détection PII automatique ici (choix
délibéré, cohérent avec le reste de l'app : sans pseudo configuré, pas
d'anonymisation).

**Fail-closed** : si l'utilisateur a demandé l'export anonymisé mais qu'un
terme configuré ne peut pas être chargé (collision de pseudo_middle), on
RAISE plutôt que de livrer un fichier où la vraie valeur fuiterait
silencieusement. Le caller (handler d'export) doit remonter une erreur
actionnable, jamais servir un fichier partiellement anonymisé. La garde est
portée par :func:`proxy._load_user_pseudonymizer` (réutilisé tel quel — une
seule implémentation du chargement fail-closed dans tout le package).

**Périmètre d'anonymisation** : on réécrit les **valeurs de cellules**
(``rows`` de chaque onglet + ``rows`` des ``cellDetails`` de drill-down).
On laisse intacts les **en-têtes de colonnes** (= schéma, niveau 1
non-sensible dans la doctrine multi-niveaux) ainsi que ``sql`` et les
métadonnées structurelles — strictement cohérent avec le contrat
:meth:`Pseudonymizer.anonymize` qui n'altère jamais les clés de dict.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, Optional

from app.services.anonymization.pseudonymizer import Pseudonymizer

# ``§`` est un délimiteur volontairement rare (cf. ``pseudonymizer._SENTINEL``)
# choisi pour ne jamais apparaître dans des données métier réelles. Le strip
# ``§X§`` → ``X`` est donc sûr : il ne peut pas corrompre une valeur légitime.
_SENTINEL_RE = re.compile(r"§([^§]*)§")


def _strip_sentinels(obj: Any) -> Any:
    """Retire récursivement les délimiteurs ``§`` d'un payload anonymisé.

    Transforme ``§CLIENT_A§`` → ``CLIENT_A`` dans toutes les strings. Les
    structures (dict/list/tuple) sont reconstruites à neuf (non-mutation) ;
    les scalaires non-string passent tels quels.
    """
    if isinstance(obj, str):
        # ``§`` interne uniquement — ``\1`` = contenu entre délimiteurs.
        return _SENTINEL_RE.sub(lambda m: m.group(1), obj)
    if isinstance(obj, dict):
        return {k: _strip_sentinels(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_sentinels(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_strip_sentinels(v) for v in obj)
    return obj


def _anonymize_rows(rows: Any, pseudo: Pseudonymizer) -> Any:
    """Anonymise une collection de lignes (format array OU dict).

    ``pseudo.anonymize`` gère les deux formats : pour un dict-row il conserve
    les clés (= colonnes) et n'anonymise que les valeurs ; pour un array-row
    il anonymise chaque élément. On retire ensuite les délimiteurs ``§`` pour
    obtenir des valeurs propres dans le fichier final.
    """
    return _strip_sentinels(pseudo.anonymize(rows))


def _anon_text(value: Any, pseudo: Pseudonymizer) -> Any:
    """Anonymise une string libre (label, en-tête, valeur de filtre). Seuls les
    termes configurés changent ; non-string → inchangé."""
    if isinstance(value, str):
        return _strip_sentinels(pseudo.anonymize_text(value))
    return value


def _anon_columns(columns: Any, pseudo: Pseudonymizer):
    """Anonymise une liste d'en-têtes et retourne ``(anon_list, col_map)``.

    Adversarial review 2026-06-01 (FUITE pivot) : un en-tête de colonne PEUT
    être une valeur métier (tableau croisé « CA par client » → en-têtes = noms
    de clients). On anonymise donc les en-têtes ; les VRAIS noms de colonnes SQL
    ne matchent aucun terme configuré → restent en clair. ``col_map`` (orig →
    anonymisé, uniquement les changés) sert à réaligner les clés des rows
    dict-format pour que la sérialisation reste cohérente.
    """
    if not isinstance(columns, list):
        return columns, {}
    anon = [_anon_text(c, pseudo) for c in columns]
    col_map = {c: a for c, a in zip(columns, anon) if isinstance(c, str) and c != a}
    return anon, col_map


def _remap_dict_row_keys(rows: Any, col_map: Dict[str, str]) -> Any:
    """Réaligne les clés des rows dict-format sur les en-têtes anonymisés.

    Indispensable quand on anonymise les ``columns`` : sinon le sérialiseur
    (qui écrit l'en-tête anonymisé puis cherche ``row.get(en-tête)``) ne
    trouverait plus la valeur (clé restée en clair). Pour les array-rows
    (positionnels) ce remap est un no-op.
    """
    if not col_map or not isinstance(rows, list):
        return rows
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append({col_map.get(k, k): v for k, v in r.items()})
        else:
            out.append(r)
    return out


def anonymize_tab_for_export(tab: Dict[str, Any], pseudo: Pseudonymizer) -> Dict[str, Any]:
    """Retourne une copie anonymisée d'UN onglet, sans muter l'entrée.

    Anonymise les **valeurs métier** où qu'elles se trouvent :
    - ``label`` (= nom de feuille Excel / titre d'onglet, souvent nommé d'après
      un client) ;
    - ``columns`` (en-têtes — cas pivot où l'en-tête EST une valeur ; seuls les
      termes configurés changent, les vrais noms SQL restent clairs) ;
    - ``rows`` (cellules) + réalignement des clés dict-format sur les en-têtes ;
    - ``cellDetails`` (drill-down) : ``rows``, ``columns``, ``label`` et les
      filtres ``match``/``match_exclude`` (réécrits de façon cohérente avec les
      rows pour que la reconstruction des feuilles de détail matche encore).

    Copie superficielle (les autres clés — ``sql``, métadonnées — restent
    partagées par référence, jamais mutées). Évite un ``deepcopy`` du classeur
    entier (économie mémoire sur 100k lignes).
    """
    if not isinstance(tab, dict):
        return tab

    new_tab: Dict[str, Any] = dict(tab)  # shallow — non-mutation de l'original

    if isinstance(tab.get("label"), str):
        new_tab["label"] = _anon_text(tab["label"], pseudo)

    columns = tab.get("columns")
    anon_cols, col_map = _anon_columns(columns, pseudo)
    if isinstance(columns, list):
        new_tab["columns"] = anon_cols

    rows = tab.get("rows")
    if isinstance(rows, list):
        new_tab["rows"] = _remap_dict_row_keys(_anonymize_rows(rows, pseudo), col_map)

    # externalSource (feuille importée) : peut contenir un nom de fichier/source
    # dérivé d'un client. On anonymise toutes ses VALEURS string (clés = type/
    # structure préservées). Cf. re-review adversariale it.11.
    ext = tab.get("externalSource")
    if isinstance(ext, dict):
        new_tab["externalSource"] = _strip_sentinels(pseudo.anonymize(ext))

    cell_details = tab.get("cellDetails")
    if isinstance(cell_details, dict):
        new_cd: Dict[str, Any] = dict(cell_details)
        for key, detail in cell_details.items():
            if not isinstance(detail, dict):
                continue
            new_detail = dict(detail)
            d_cols = detail.get("columns")
            d_anon_cols, d_col_map = _anon_columns(d_cols, pseudo)
            if isinstance(d_cols, list):
                new_detail["columns"] = d_anon_cols
            if isinstance(detail.get("rows"), list):
                new_detail["rows"] = _remap_dict_row_keys(
                    _anonymize_rows(detail["rows"], pseudo), d_col_map
                )
            for txt_field in ("label", "description"):
                if isinstance(detail.get(txt_field), str):
                    new_detail[txt_field] = _anon_text(detail[txt_field], pseudo)
            # match/match_exclude : {colonne_du_tab_SOURCE: valeur}. La
            # reconstruction du détail filtre les rows du tab SOURCE (≠ tab
            # parent) par ces couples. On anonymise CLÉ et VALEUR avec
            # l'anonymiseur DÉTERMINISTE (``_anon_text``/``pseudo.anonymize``) —
            # PAS le ``col_map`` local du parent : un même terme produit toujours
            # le même pseudonyme (bijection), donc la clé anonymisée s'aligne sur
            # l'en-tête anonymisé du tab source quel qu'il soit. (Bug it.10 :
            # le col_map parent ratait une clé absente du parent → détail perdu
            # silencieusement. Cf. re-review adversariale it.11.)
            for mk in ("match", "match_exclude"):
                mv = detail.get(mk)
                if isinstance(mv, dict):
                    new_detail[mk] = {
                        _anon_text(k, pseudo): _strip_sentinels(pseudo.anonymize(v))
                        for k, v in mv.items()
                    }
            new_cd[key] = new_detail
        new_tab["cellDetails"] = new_cd

    return new_tab


def anonymize_tabs_with_pseudonymizer(
    tabs: Any,
    pseudo: Optional[Pseudonymizer],
) -> Any:
    """Variante SYNCHRONE : le caller fournit un ``Pseudonymizer`` déjà construit.

    Utile quand un pipeline charge le pseudonymizer une seule fois puis
    sérialise plusieurs onglets/fichiers. Si ``pseudo`` est ``None`` ou vide
    (aucun terme configuré dans /data-privacy), renvoie une **copie inchangée**
    des tabs : « rien de configuré = tout en clair » (doctrine SSoT).
    """
    if not isinstance(tabs, list):
        return tabs
    if pseudo is None or len(pseudo) == 0:
        # Copie défensive : le caller peut sérialiser/modifier librement sans
        # risque de muter le classeur source en mémoire.
        return copy.deepcopy(tabs)
    return [anonymize_tab_for_export(t, pseudo) for t in tabs]


async def anonymize_tabs_for_export_meta(user_id: Optional[int], tabs: Any) -> Dict[str, Any]:
    """Comme :func:`anonymize_tabs_for_export` mais retourne aussi le nombre de
    termes effectivement chargés (``term_count``).

    ``term_count == 0`` signifie qu'AUCUN terme n'était configuré/activé sur
    ``/data/privacy`` pour cet utilisateur : le résultat est alors identique à
    un export en clair. Le caller peut s'en servir pour AVERTIR l'utilisateur
    (« vous avez demandé l'anonymisation mais aucun terme n'est configuré → le
    fichier est identique au clair ») et éviter une fausse impression de
    sécurité. Ce n'est PAS une fuite (0 terme = clair = comportement correct),
    juste une clarté UX.

    Returns:
        dict ``{"tabs": <liste anonymisée>, "term_count": <int>}``.

    Raises:
        RuntimeError / Exception : voir :func:`anonymize_tabs_for_export`
        (fail-closed, propagé).
    """
    if not isinstance(tabs, list):
        return {"tabs": tabs, "term_count": 0}
    if user_id is None:
        return {"tabs": copy.deepcopy(tabs), "term_count": 0}

    # Réutilisation de l'UNIQUE chargeur fail-closed du package (pas de
    # duplication : single source of truth pour « charger le pseudonymizer
    # user depuis la BDD en refusant toute perte silencieuse de terme »).
    from app.services.anonymization.proxy import _load_user_pseudonymizer

    pseudo = await _load_user_pseudonymizer(user_id)
    return {
        "tabs": anonymize_tabs_with_pseudonymizer(tabs, pseudo),
        "term_count": len(pseudo),
    }


async def anonymize_tabs_for_export(user_id: Optional[int], tabs: Any) -> Any:
    """Façade async — charge le ``Pseudonymizer`` user puis anonymise les tabs.

    C'est le point d'entrée que les handlers d'export appellent quand le mode
    « anonymisé » est choisi. Délègue à :func:`anonymize_tabs_for_export_meta`
    (chargement BDD unique) et n'en renvoie que les tabs — pour les callers qui
    n'ont pas besoin du ``term_count``.

    Args:
        user_id: propriétaire de l'export. ``None`` = appel système sans
            contexte utilisateur → aucune config /data-privacy applicable →
            copie inchangée (jamais de fuite, mais pas d'anonymisation
            inventée non plus).
        tabs: liste d'onglets au format classeur (``{"columns", "rows", …}``).

    Returns:
        Nouvelle liste de tabs anonymisés (valeurs cellules → pseudonymes
        propres). Les tabs d'entrée ne sont pas mutés.

    Raises:
        RuntimeError: pseudonymizer incomplet (un terme configuré n'a pas pu
            être chargé) — fail-closed, propagé par
            :func:`proxy._load_user_pseudonymizer`. Le handler doit renvoyer
            une erreur à l'utilisateur, pas un fichier potentiellement fuité.
        Exception: lecture BDD échouée (timeout, OperationalError) — pas de
            fail-open silencieux.
    """
    result = await anonymize_tabs_for_export_meta(user_id, tabs)
    return result["tabs"]


__all__ = [
    "anonymize_tabs_for_export",
    "anonymize_tabs_for_export_meta",
    "anonymize_tabs_with_pseudonymizer",
    "anonymize_tab_for_export",
]
