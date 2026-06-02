"""Service ``data_access`` — gestion des règles d'accès aux données BDD source.

Contenu :

- :mod:`app.services.data_access.repository` — CRUD async sur ``DataAccessRule``.
- :mod:`app.services.data_access.enforcer` — application runtime des règles
  (validation pre-flight, injection de filtres ``WHERE`` via sqlglot,
  filtrage du contexte LLM).
- :mod:`app.services.data_access.schema_utils` — helpers de parsing
  schéma (autocomplete colonnes pour l'UI admin).

Voir :class:`app.models.data_access_rule.DataAccessRule` pour le modèle
de données et le contrat des règles.
"""

from __future__ import annotations
