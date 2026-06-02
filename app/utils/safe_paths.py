"""Helper unifié anti path-traversal (CWE-22 / CWE-59).

Centralise la résolution sécurisée d'un chemin relatif sous un répertoire
autorisé. Avant cycle 12 APEX, 5 implémentations différentes existaient
dans la codebase :

* ``executor._safe_output_path`` (automation reports dir)
* ``datastore._safe_path`` (datastore user dir)
* ``template_library`` (filesystem templates)
* ``preview_service.resolve_preview_output_path`` (tmp preview dir)
* ``AutomationDownloadHandler`` (allowed_dir inline)

Chacune avec des subtilités : `is_symlink` avant ou après `resolve`,
`relative_to` vs `is_relative_to`, gestion des exceptions différente.
Risque : un fix sécu dans une variante ne se propage pas aux autres.

Cette factorisation (Q1 cycle 12) introduit ``safe_resolve_within`` comme
single source of truth POUR LE MODÈLE « chemin relatif fourni par le user,
multi-segments, dotfiles légitimes autorisés, symlink interdit ».

⚠️ **Migration NON mécanique (vérifié #94, 2026-06-02)** : les 5 call sites
historiques n'ont PAS tous ce modèle d'input, donc ils ne sont PAS des
drop-in de ce helper :
* ``AutomationDownloadHandler`` valide un chemin **ABSOLU** lu en BDD et
  check le symlink **APRÈS** ``resolve()`` (TOCTOU délibéré) — incompatible :
  ce helper REJETTE les chemins absolus (→ ``None``).
* ``resolve_preview_output_path`` impose un **filename single-segment** sans
  dotfile (plus STRICT que ce helper, qui autorise sous-dossiers + dotfiles).
* ``report_storage`` fait confiance à un path relatif BDD + containment seul
  (PAS de blocage symlink — ce helper l'ajouterait = changement de posture).
Migrer un site = **changer son comportement sécu** (plus laxiste ou plus
strict), pas une simple factorisation. Le site qui matche vraiment ce modèle
(``datastore._safe_path``, filename user) est le candidat naturel. Décider
au cas par cas avec tests de non-régression — ne PAS migrer à l'aveugle.

Doctrine défense-in-depth (ordre = celui du code ci-dessous) :
1. Refuser les filenames absolus, null-byte, traversal markers (`..`, `.`).
2. ``is_symlink()`` **AVANT** ``resolve()`` (CRITIQUE) : après
   ``resolve(strict=True)``, ``is_symlink()`` retourne TOUJOURS ``False`` car
   ``resolve()`` matérialise les liens. Pour bloquer effectivement les
   symlinks (CWE-59), on teste le candidat brut AVANT de le matérialiser.
3. ``Path.resolve(strict=True)`` pour matérialiser le chemin réel (fail si
   le fichier n'existe pas).
4. ``is_relative_to(allowed_dir)`` pour le containment final.
5. Retourner ``None`` sur tout échec — caller décide quoi faire (404
   silencieux pour les handlers HTTP, ValueError pour le code métier).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def safe_resolve_within(
    base_dir: Path,
    relative: str,
    *,
    follow_symlinks: bool = False,
) -> Optional[Path]:
    """Résout ``relative`` sous ``base_dir`` ou retourne None.

    Args:
        base_dir: Racine autorisée (sera resolve() pour suivre les liens
            de la racine elle-même — c'est attendu, le root peut être un
            symlink légitime côté admin).
        relative: Chemin relatif fourni par le user/contrôleur.
        follow_symlinks: Si False (défaut), refuse les liens dans le path
            résolu. Aligné avec ``AutomationDownloadHandler`` qui interdit.
            Mettre True UNIQUEMENT si le caller assume le risque de TOCTOU
            sur des liens internes (ex: tmp dir sous-utilisateur trusted).

    Returns:
        ``Path`` résolu et vérifié, OU ``None`` si tout échec
        (refus traversal, ne pas exister, hors root, symlink interdit).
        Le caller distingue 404 vs autres causes via le retour None
        uniformément (anti-oracle CWE-203).
    """
    # 1. Refus type/empty/null-byte/separateurs absolus
    if not isinstance(relative, str) or not relative:
        return None
    if (
        relative.startswith("/")
        or relative.startswith("\\")
        or "\x00" in relative  # NULL byte injection
    ):
        return None
    # Refus du leading `.` SEULEMENT s'il s'agit de `.`/`..` purs ou
    # d'un traversal masque type `./..`. Les dotfiles legitimes
    # (.gitignore, .env.local, .config.json) restent autorises — ils
    # n'ont rien d'un traversal et sont des filenames usuels.
    # Note adversarial cycle 12 : avant, `startswith(".")` strict
    # rejetait tous les dotfiles → bug fonctionnel.
    if relative in (".", "..") or relative.startswith("./") or relative.startswith("../"):
        return None
    # `..` n'importe où dans le segment est interdit (defense-in-depth).
    parts = relative.replace("\\", "/").split("/")
    if any(p == ".." for p in parts):
        return None

    candidate = base_dir / relative

    # 2. Symlink check AVANT resolve (CRITIQUE adversarial cycle 12)
    # Apres `resolve(strict=True)`, `is_symlink()` retourne TOUJOURS False
    # car resolve() matérialise les liens. Pour bloquer effectivement les
    # symlinks (defense CWE-59), on vérifie sur le path candidat brut
    # AVANT de matérialiser.
    if not follow_symlinks:
        try:
            if candidate.is_symlink():
                return None
        except OSError:
            return None
        # Vérifier aussi les composants intermédiaires : un symlink dans
        # un parent du candidat sortirait potentiellement du root.
        # ``Path.resolve()`` puis comparaison containment couvre ce cas.

    # 3. Resolve strict — fail si le fichier n'existe pas
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None

    # 4. Containment : le résolu doit être sous le root résolu (cohérent strict).
    try:
        # Resolve symétrique des deux côtés : si base_dir est un symlink
        # vers /opt/komptia/data, on veut comparer le résolu candidat à
        # /opt/komptia/data, pas à `base_dir` brut.
        root_resolved = base_dir.resolve(strict=False)
        resolved.relative_to(root_resolved)
    except (ValueError, OSError):
        return None

    return resolved
