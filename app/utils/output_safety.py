"""Helpers de sécurité pour la production de sorties utilisateur.

Regroupe les protections « sortie » qui doivent être appliquées de manière
homogène partout dans la codebase, pour éviter la dérive entre handlers.

Contenu :

- :func:`safe_json_for_script` — sérialisation JSON injectable dans une balise
  ``<script>`` inline sans risque d'évasion de contexte (``</script>``) ni de
  cassure de chaîne JS via ``U+2028`` / ``U+2029``.
- :func:`csv_safe_cell` — échappement des cellules CSV commençant par un
  caractère déclencheur de formule (``=+-@`` + tabulation / retour chariot),
  conformément aux recommandations OWASP CSV-Injection 2024/2025.

Tous les helpers sont purs (aucun état, aucun I/O), pour être testables
unitairement sans fixture.
"""

from __future__ import annotations

import json
from typing import Any, Final

# ---------------------------------------------------------------------------
# JSON injectable dans un <script> (XSS defense-in-depth)
# ---------------------------------------------------------------------------

# Caractères qui peuvent casser un contexte ``<script>`` si laissés tels quels
# dans une chaîne JSON :
#
# - ``<`` / ``>`` : ouvrir un ``</script>`` imbriqué dans une chaîne.
# - ``&``         : défense-en-profondeur contre les parseurs HTML relâchés.
# - ``U+2028``    : line separator, casse une chaîne JS (pas JSON).
# - ``U+2029``    : paragraph separator, idem.
#
# ``json.dumps`` **ne les échappe pas** par défaut (sauf ``U+2028/2029`` avec
# ``ensure_ascii=True``), donc le remplacement explicite est obligatoire en
# defense-in-depth — même si Tornado sert le payload via ``{% raw %}``.
_SCRIPT_ESCAPES: Final[tuple[tuple[str, str], ...]] = (
    ("<", "\\u003c"),
    (">", "\\u003e"),
    ("&", "\\u0026"),
    ("\u2028", "\\u2028"),
    ("\u2029", "\\u2029"),
)


def safe_json_for_script(payload: Any, *, ensure_ascii: bool = False) -> str:
    """Sérialise ``payload`` pour être injecté sans évasion dans un ``<script>``.

    ``ensure_ascii=False`` par défaut produit une sortie plus compacte et
    lisible (caractères unicode comme ``é`` conservés tels quels), tout en
    restant parfaitement valide pour ``JSON.parse`` / assignement direct côté
    JavaScript une fois les 5 séquences dangereuses échappées.

    Le remplacement est appliqué **après** ``json.dumps`` — il ne peut donc
    jamais produire de JSON invalide, puisque ``\\u003c`` & co. sont des
    escapes JSON légitimes qui s'auto-décodent en ``<``/``>``/``&``/U+2028…
    côté client.
    """
    encoded = json.dumps(payload, ensure_ascii=ensure_ascii)
    for needle, replacement in _SCRIPT_ESCAPES:
        encoded = encoded.replace(needle, replacement)
    return encoded


# ---------------------------------------------------------------------------
# CSV Formula Injection (OWASP Top 10 A05 Injection — 2021/2025)
# ---------------------------------------------------------------------------

# Caractères qui, en première position d'une cellule CSV, déclenchent
# l'évaluation d'une formule par Excel / LibreOffice / Google Sheets.
#
# - ``=`` / ``+`` / ``-`` / ``@`` : opérateurs de formule standard.
# - ``\t`` (tabulation)           : certaines versions d'Excel la traitent
#                                    comme espace et évaluent le reste.
# - ``\r`` (retour chariot)       : idem, risque de line-split imprévu.
#
# Source : https://owasp.org/www-community/attacks/CSV_Injection
CSV_FORMULA_PREFIXES: Final[tuple[str, ...]] = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value: Any) -> str:
    """Retourne ``value`` échappée pour écriture CSV sans risque de formule.

    Politique :

    - ``None`` → chaîne vide (permet ``writer.writerow([csv_safe_cell(...)])``
      sans branchement appelant).
    - Non-string → conversion ``str(value)``.
    - Si la valeur résultante commence par un préfixe de formule, on la
      préfixe d'un ``'`` (convention OWASP / Tableau / Google Sheets) pour
      forcer le tableur à la traiter comme texte.

    ``csv.QUOTE_ALL`` (ou ``QUOTE_MINIMAL``) côté ``csv.writer`` complète la
    défense — cette fonction ne gère que la neutralisation des formules.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text and text[0] in CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def excel_safe_cell(value: Any) -> Any:
    """Variante de :func:`csv_safe_cell` pour une cellule **Excel** (openpyxl).

    Différence clé : on **préserve le type natif**. ``csv_safe_cell`` produit
    toujours du texte (correct pour un CSV, qui n'a pas de types), mais une
    feuille Excel doit garder ses nombres / dates / booléens comme tels —
    sinon le destinataire légitime ne peut plus sommer, trier ou grapher, et
    on introduit une régression d'usage en voulant corriger la sécurité.

    Seules les **chaînes** commençant par un préfixe de formule
    (:data:`CSV_FORMULA_PREFIXES`) sont préfixées d'un ``'`` : openpyxl écrit
    sinon ``"=..."`` comme une **formule** évaluée à l'ouverture du classeur
    (CSV/formula-injection via le tableur — OWASP). Tout le reste (int, float,
    ``Decimal``, ``datetime``, ``None``, chaîne inoffensive) passe inchangé.

    Source unique des préfixes dangereux partagée avec :func:`csv_safe_cell`
    pour éviter toute dérive entre les deux formats d'export.
    """
    if isinstance(value, str) and value and value[0] in CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


__all__ = [
    "CSV_FORMULA_PREFIXES",
    "csv_safe_cell",
    "excel_safe_cell",
    "safe_json_for_script",
]
