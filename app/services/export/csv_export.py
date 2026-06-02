"""Service unifié d'export CSV.

**Pourquoi ce module**

Avant ce service, l'export CSV était réimplémenté ad-hoc dans 8+ fichiers
(handlers `datastore`, `automations`, `ai_admin`, services
`agent_tools`, `report_generator`, `workbook_export`, `executor`,
`dashboard_builder_service`). Trois axes de dérive constatés :

1. **BOM UTF-8** — 4 sites l'ajoutaient (Excel double-clic), 4 l'omettaient
   (mojibake côté utilisateur final).
2. **CSV Formula Injection** (OWASP A05 / CWE-1236) — 3 sites
   sanitisaient les cellules, 5 ne le faisaient pas. Un alias SQL
   `=cmd|...` retourné par un user pouvait s'exécuter au double-clic
   dans Excel chez un autre user.
3. **Line terminator** — par défaut `\\r\\n` côté `csv.DictWriter` (Excel
   historique), mais plusieurs sites forçaient `\\n` (cohérence Unix).

Le helper :func:`to_csv_bytes` fixe le contrat :

* Bytes UTF-8 en sortie (jamais ``str`` — évite la confusion encoding).
* BOM UTF-8 par défaut (Excel double-clic OK).
* Sanitisation par défaut sur **headers ET valeurs** (defense-in-depth :
  un nom de colonne SQL `AS "=cmd|"` pouvait leak dans la 1ère ligne).
* `\\n` terminator (cohérent serveur Linux et anciens call sites).
* `extrasaction='ignore'` (silently drop extra keys) — replicate du
  comportement historique des 5 sites DictWriter.

**Quand l'utiliser**

Pour tout export CSV qui produit une liste de lignes homogènes
(``list[dict]`` avec mêmes colonnes). Pour des sections hétérogènes
(ex : dashboard multi-widgets), continuer avec `csv.writer` direct —
le contrat homogène ne s'y applique pas.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Iterable, Mapping, Optional, Sequence

from app.utils.output_safety import csv_safe_cell

__all__ = ("to_csv_bytes",)

_UTF8_BOM: bytes = "﻿".encode("utf-8")


def to_csv_bytes(
    rows: Iterable[Mapping[str, Any]],
    columns: Optional[Sequence[str]] = None,
    *,
    sanitize: bool = True,
    with_bom: bool = True,
    empty_placeholder: Optional[str] = None,
) -> bytes:
    """Sérialise ``rows`` en bytes CSV UTF-8.

    Parameters
    ----------
    rows
        Itérable de mappings (typiquement ``list[dict[str, Any]]``). Les
        clés absentes d'un dict donné deviennent des cellules vides ;
        les clés présentes mais non listées dans ``columns`` sont
        silencieusement ignorées (``extrasaction='ignore'``).
    columns
        Ordre + filtrage explicites des colonnes. Si ``None``, on
        utilise les keys du premier dict de ``rows`` (ordre
        d'insertion). Si ``rows`` est vide et ``columns`` aussi, on
        n'écrit pas de header — seul le BOM (et le placeholder
        éventuel) sont émis.

        ⚠️ Comportement silencieux assumé : toute clé présente dans un
        dict mais absente de ``columns`` est ignorée (équivalent
        ``extrasaction='ignore'`` de ``csv.DictWriter``). Si vous
        voulez fail-fast sur drift de schéma, validez les keys côté
        appelant avant d'invoquer ``to_csv_bytes``.
    sanitize
        Si vrai (défaut), préfixe d'une apostrophe ``'`` toute cellule,
        tout header et le ``empty_placeholder`` qui commence par un
        caractère déclencheur de formule (``=``/``+``/``-``/``@``/
        ``\\t``/``\\r``). Voir
        :func:`app.utils.output_safety.csv_safe_cell`.
    with_bom
        Si vrai (défaut), préfixe le payload du BOM UTF-8 ``\\ufeff``.
        Activer pour les fichiers téléchargés (Excel double-clic) ;
        désactiver pour les flux streamés vers un parser strict.
    empty_placeholder
        Texte à écrire (suivi de ``\\n``) si **et seulement si** ``rows``
        ET ``columns`` sont tous deux vides. Replicate le fallback
        ``(vide)`` historique de ``workbook_export.write_csv_single_tab``
        et ``Aucun résultat`` de ``report_generator.generate_csv``.
        Si ``columns`` est fourni, le header est écrit et le placeholder
        est ignoré (on ne mélange pas ligne pseudo-data + header).

    Returns
    -------
    bytes
        Payload CSV encodé UTF-8 (avec BOM si demandé), prêt à être
        écrit sur disque ou envoyé via ``self.write()``.
    """
    # Cas trivial 1 : caller a fourni ``columns`` explicites mais pas de
    # rows → on écrit BOM + header (et on n'évalue pas ``rows`` pour
    # préserver le mode générateur streaming).
    has_explicit_columns = columns is not None
    if has_explicit_columns and not rows:
        return _emit(columns, [], sanitize, with_bom)

    # Pour le cas auto-detect ``columns is None``, on a besoin du 1er
    # dict pour les keys — on matérialise UNIQUEMENT si nécessaire.
    if columns is None:
        rows_iter = iter(rows)
        try:
            first_row = next(rows_iter)
        except StopIteration:
            # rows vide ET columns vide → BOM + placeholder éventuel.
            head = _UTF8_BOM if with_bom else b""
            if empty_placeholder is not None:
                safe_placeholder = (
                    csv_safe_cell(empty_placeholder) if sanitize else empty_placeholder
                )
                return head + (safe_placeholder + "\n").encode("utf-8")
            return head
        columns = list(first_row.keys())
        # Re-chain le 1er row avec le reste pour streaming.
        from itertools import chain

        rows_to_emit = chain((first_row,), rows_iter)
    else:
        rows_to_emit = rows

    return _emit(columns, rows_to_emit, sanitize, with_bom)


def _emit(
    columns: Sequence[str],
    rows_to_emit: Iterable[Mapping[str, Any]],
    sanitize: bool,
    with_bom: bool,
) -> bytes:
    """Sérialisation effective une fois ``columns`` connu.

    Itère ``rows_to_emit`` une seule fois — compatible avec un générateur
    issu d'un cursor SQL streamé. Le buffer ``StringIO`` reste
    in-memory : pour des exports massifs, prévoir un futur
    ``to_csv_stream(rows, fh)`` qui écrit incrémentalement sur ``fh``.
    """
    buffer = io.StringIO()
    # ``lineterminator='\n'`` pour rester cohérent avec les call sites
    # historiques (automations.py forçait ``\\n``) — Excel lit les deux,
    # mais Linux/grep/diff préfèrent ``\\n``.
    writer = csv.writer(buffer, lineterminator="\n")

    # Sanitisation des headers — un alias SQL ``AS "=cmd|"`` qui passe
    # en nom de colonne devient ``'=cmd|`` dans le fichier, neutralisé.
    header_row: Sequence[str] = [csv_safe_cell(h) for h in columns] if sanitize else list(columns)
    writer.writerow(header_row)

    # On itère explicitement sur ``columns`` (pas sur les keys du dict) :
    # toute clé en plus dans un row est silencieusement droppée — voir
    # warning dans la docstring de ``to_csv_bytes``.
    if sanitize:
        for row in rows_to_emit:
            writer.writerow([csv_safe_cell(row.get(col)) for col in columns])
    else:
        for row in rows_to_emit:
            writer.writerow(["" if row.get(col) is None else row.get(col) for col in columns])

    payload = buffer.getvalue().encode("utf-8")
    return (_UTF8_BOM + payload) if with_bom else payload
