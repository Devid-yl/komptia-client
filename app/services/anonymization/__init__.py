"""Service d'anonymisation Komptia — source unique de vérité.

Ce package centralise toute la stratégie de confidentialité Komptia.

**API publique** — un seul point d'entrée :

- :func:`anonymize_for_llm` (depuis :mod:`proxy`) — façade unique pour
  anonymiser un payload avant envoi à un LLM cloud, et restaurer la
  réponse en sortie. Couplage BDD-driven implémenté tâche #4.

**Sous-modules internes** (importables directement si besoin spécifique) :

- :mod:`patterns` — regex PII built-in (email, SIRET, IBAN, etc.).
- :mod:`pseudonymizer` — table bijective cleartext ↔ token, scope user.
- :mod:`extract` — tokenisation + reconciliation du dictionnaire utilisateur
  (anciennement ``app.services.ai.anon_terms``).
- :mod:`strategies` — :class:`ConfidentialityManager` legacy + helper
  ``filter_tool_results`` (pass-through), en cours de migration vers
  :func:`anonymize_for_llm`.
- :mod:`auto_classify` — proposition automatique de termes PII via LLM local.
- :mod:`repository` — CRUD async sur ``anonymization_terms``.
- :mod:`audit` — journalisation des modifications du dictionnaire.
- :mod:`cleanup_job` — nettoyage périodique des termes obsolètes.

**Anti-pattern import** : ``from app.services.anonymization import X``
ne fonctionne PAS pour les classes/fonctions des sous-modules
(:class:`ConfidentialityManager`, :class:`Pseudonymizer`, etc.). Le seul
symbole exposé au niveau package est :func:`anonymize_for_llm`. Pour
tout le reste, cibler explicitement le sous-module — par exemple
``from app.services.anonymization.strategies import ConfidentialityManager``.
"""

from app.services.anonymization.proxy import anonymize_for_llm

__all__ = ["anonymize_for_llm"]
