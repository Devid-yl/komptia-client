"""Formatage numérique des rapports — anti-zéro-trompeur (SSoT #142).

Un float NON NUL mais petit (ex. 0.004) formaté à 2 décimales devient « 0.00 »,
ce qu'un lecteur (comptable) interprète comme ZÉRO → perte de donnée silencieuse.
``format_number_preserving_nonzero`` garantit qu'une valeur non nulle révèle
TOUJOURS son premier chiffre significatif (bascule sur ``%g``), tout en gardant
l'affichage usuel à N décimales pour les magnitudes normales.

Partagé par ``pdf_generator._format_cell_value`` (tableaux PDF bruts) et
``template_manager._apply_format`` (colonnes de rapport configurées : currency,
percentage, decimal) — pour fixer la classe de bug, pas un seul call-site.
"""
from __future__ import annotations


def format_number_preserving_nonzero(
    value: float, decimals: int = 2, *, grouping: bool = False
) -> str:
    """Formate ``value`` à ``decimals`` décimales sans jamais afficher « 0 » pour
    un non-zéro.

    - ``grouping`` : ajoute le séparateur de milliers en espace fine (convention
      FR — « 1 234.50 »), le point décimal reste un point.
    - Si l'arrondi à ``decimals`` décimales collapse une valeur NON NULLE en zéro,
      on bascule sur ``%.3g`` (3 chiffres significatifs) qui révèle le premier
      chiffre non nul sans bruit flottant (ex. 0.004 → « 0.004 » au lieu de
      « 0.00 »). Un zéro authentique reste « 0.00 » (pas trompeur).

    NB : avec ``decimals=0``, une valeur sous-unitaire non nulle (ex. 0.4) est
    quand même RÉVÉLÉE (« 0.4 ») et non rendue « 0 » — c'est le cœur de l'anti-
    zéro-trompeur. Pour une vraie troncature entière (0.4 → « 0 »), utiliser le
    format ``integer`` dédié (``str(int(...))``), pas ``decimal`` à 0 décimale.
    """
    spec = f",.{decimals}f" if grouping else f".{decimals}f"
    formatted = format(value, spec)
    if grouping:
        # Le format ',' utilise la virgule comme séparateur de milliers : on la
        # remplace par une espace fine (la partie décimale garde son point).
        formatted = formatted.replace(",", " ")

    if value != 0.0:
        plain = formatted.replace(" ", "")
        try:
            collapsed = float(plain) == 0.0
        except ValueError:  # "nan"/"inf" — non numérique après format
            collapsed = False
        if collapsed:
            return f"{value:.3g}"
    return formatted
