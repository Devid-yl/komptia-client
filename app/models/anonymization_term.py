"""Modèle ``AnonymizationTerm`` — liste pilotée utilisateur des termes
que le copilot doit anonymiser avant envoi au LLM.

Source de vérité pour l'anonymisation copilot : remplace le stockage "par
classeur" expérimenté en v1 (``anonymization_state`` dans le JSON du
classeur). La BDD locale évite la re-saisie cross-classeur et cross-session.

**Sémantique des flags** (décision David 2026-05-19) :

- ``enabled=True`` → le terme est anonymisé (remplacé par un token ``§…§``)
  avant l'envoi à n'importe quel LLM cloud (copilot, Iris, widget planner,
  report planner, etc.). **Seuls les termes ``enabled=True`` sont anonymisés.**
- ``enabled=False`` → le terme passe en clair vers le LLM cloud (à part
  la couche PII regex toujours appliquée : email/phone/SIRET/SIREN/IBAN/AMOUNT).
- ``confirmed`` → l'utilisateur a explicitement statué sur ce terme via
  le panneau ``/data/privacy`` (peu importe la valeur de ``enabled``).
  ``confirmed=False`` = terme auto-détecté en attente de décision user.

**Lifecycle des entrées** :

- **Création** : un nouveau token apparaît dans un classeur de l'utilisateur.
  Le système (via ``anon_terms.reconcile_state``) upsert l'entrée avec
  ``confirmed=False, enabled=False``. Le terme passe en clair tant que
  l'utilisateur ne l'a pas activé via ``/data/privacy`` — la couche PII
  regex couvre les cas RGPD majeurs en attendant. (**Note historique** :
  pré-2026-05-08 ce terme déclenchait un gate 409 ``ANON_PENDING_REVIEW``,
  bloquant le copilot ; pré-2026-05-19 il était force-anonymisé via mute
  du state à `enabled=True`. Les deux comportements ont été supprimés.)
- **Édition** : l'utilisateur (re)configure via le panneau ``GET/PUT
  /api/anonymization/terms``. ``enabled`` et ``pseudo_middle`` sont mis à
  jour ; ``confirmed`` passe à ``True`` (acte explicite).
- **Suppression** : job quotidien ``cleanup_unused_anonymization_terms``
  scanne le datastore + applique 4 TTL distincts : termes hors classeurs >
  7j, termes ``confirmed=0 enabled=0`` > 30j (bloat), termes structurellement
  invalides, audit > 90j. ``source="user_added"`` exempt de toutes ces purges.

**Pourquoi pas un `UserPreference` générique ?** Trois raisons :

1. Volume potentiel — 1 user × 5000 termes = 5000 rangées. Le pattern
   ``UserPreference`` est une table clé/valeur flat, pas calibrée pour ça.
2. Requêtes ciblées — le job de cleanup fait ``WHERE term NOT IN (...)``,
   impossible sans colonne typée.
3. Contraintes d'intégrité — unicité ``(user_id, term)`` explicite,
   pseudo_middle validé en amont.
"""

import json
from datetime import datetime
from typing import TYPE_CHECKING, Final, List

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, ensure_utc

if TYPE_CHECKING:
    from app.models.user import User


# Énumération des catégories sémantiques (générique, pas spécifique Sage).
# Utilisée pour grouper la liste dans la page /data/privacy et calculer
# le risk_level par défaut.
ANONYMIZATION_CATEGORIES = (
    "pii_email",
    "pii_phone",
    "pii_iban",
    "pii_siret",
    "pii_amount",
    "pii_name",
    "business_code",
    "unclassified",
)

# Sources d'extraction du terme — d'où on l'a vu pour la première fois.
#
# Distinction sémantique IMPORTANTE entre ``manual`` et ``user_added``
# (2026-05-19) : ``manual`` est le **placeholder par défaut** appliqué par
# l'ORM (``default="manual"`` ligne ~158) quand un chemin de code n'a pas
# propagé sa source à l'INSERT (ex: PUT panneau ``replace_state``, migration
# historique). L'UI ``/data/privacy`` l'affiche comme « Origine inconnue ».
# ``user_added`` est réservé aux **saisies volontaires** via l'endpoint
# ``POST /api/anonymization/terms/manual`` (page Confidentialité). L'UI les
# affiche comme « Ajouts manuels ». Le cleanup nightly NE purge JAMAIS
# ``user_added`` (cf. ``cleanup_job._delete_missing_for_user``) — un acte
# explicite de l'utilisateur ne doit pas disparaître silencieusement.
ANONYMIZATION_SOURCES = (
    "workbook",  # extract_terms d'un classeur .afz.json
    "iris_message",  # message user dans une conversation Iris
    "sql_result",  # résultat SQL (à venir)
    "contact",  # carnet de contacts (à venir)
    "manual",  # default ORM — placeholder quand source non propagée
    "user_added",  # saisie volontaire utilisateur via /data/privacy
    # Champs textuels admin-éditables d'un dashboard (nom, description,
    # titres widgets, labels filtres, sujets/messages des envois email
    # planifiés). Scanné par le bouton "Scanner mes données" sur
    # /data/privacy via ``scan_datastore_tokens`` → ``scan_dashboard_terms``.
    # NE scanne PAS les requêtes SQL des widgets (noms de tables/colonnes
    # techniques Sage = pas PII utilisateur, source de bruit). Cf. ajout
    # 2026-05-20.
    "dashboard",
)

#: Mapping nom → valeur pour accès keyed sans hardcoder le string littéral
#: dans les call sites (règle DYNAMIQUE Komptia : pas de string ``"iris_message"``
#: éparpillé dans le code applicatif). Identité ``s: s`` — la valeur métier
#: est le nom canonique. ``ANONYMIZATION_SOURCES_BY_NAME["iris_message"]``
#: ⇒ ``"iris_message"`` ; ``KeyError`` fail-fast si un nom disparaît du
#: tuple (la propriété "single source of truth" reste préservée).
ANONYMIZATION_SOURCES_BY_NAME: Final[dict[str, str]] = {s: s for s in ANONYMIZATION_SOURCES}

# Niveaux de risque (calculé selon category, override possible par user).
ANONYMIZATION_RISK_LEVELS = ("critical", "high", "low")

# Stratégies de remplacement : comment le terme est masqué pour le LLM.
# - "pseudo" (default) : tokens §…§ déterministes via Pseudonymizer
# - "mask" : XXX-**** (premier prefix visible)
# - "hash" : abc123de (8 chars md5)
# - "redact" : [REDACTED] complet
ANONYMIZATION_REPLACEMENT_STRATEGIES = ("pseudo", "mask", "hash", "redact")


class AnonymizationTerm(BaseModel):
    """Un terme du classeur d'un utilisateur, et sa décision d'anonymisation.

    Composite key métier : ``(user_id, term)`` unique. Le ``term`` est la
    chaîne cleartext (telle qu'extraite par le tokenizer partagé Py/JS —
    cf. ``app.services.anonymization.extract``). Le ``pseudo_middle`` est optionnel
    (null = auto-généré par le ``Pseudonymizer`` lors du build) ; s'il est
    fourni, il est encadré en ``§{middle}§`` par ``add_mapping``.

    ``enabled`` : ce terme sera-t-il réellement substitué ? ``False`` = on
    le laisse en clair (le LLM le voit, l'utilisateur l'a assumé).

    ``confirmed`` : l'utilisateur a-t-il tranché ? ``False`` = nouveau
    terme détecté → gate 409 côté copilot tant que ``True`` absent.

    **Champs étendus (2026-05-06)** — pour piloter la page /data/privacy :

    - ``category`` : catégorie sémantique générique (pii_email, pii_name, …).
      Calculée par auto_classify ou laissée à "unclassified" pour ajout manuel.
    - ``source`` / ``source_ref`` : d'où vient le terme (workbook + id, ou
      iris_message + conversation_id, etc.). Permet la coverage cliquable.
    - ``last_seen_at`` : dernière fois qu'on l'a vu dans une extraction
      (TTL pour purger les termes orphelins).
    - ``usage_count`` : nombre cumulé d'apparitions (heat).
    - ``auto_proposed`` : ``True`` si proposé par auto_classifier, attente
      validation user (~ ``confirmed=False``).
    - ``risk_level`` : criticité du terme (alimentation badge global).
    - ``replacement_strategy`` : comment masquer (pseudo / mask / hash / redact).
    """

    __tablename__ = "anonymization_terms"

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    #: Token cleartext extrait du classeur. Cap à 500 chars (miroir de
    #: ``anon_terms.MAX_VALUE_LEN``). Au-delà : skippé en amont par le
    #: tokenizer (pollution regex + perte de pertinence).
    term: Mapped[str] = mapped_column(String(500), nullable=False)
    #: Middle du pseudo-token (``§middle§``). ``None`` ⇒ auto-généré par
    #: ``Pseudonymizer._make_token`` (consonnes + md5[:3]). Rester court
    #: (cap 128) pour éviter d'exploser la taille des prompts LLM.
    pseudo_middle: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: ``True`` = anonymiser (substitue en ``§pseudo§`` dans les payloads).
    #: ``False`` = laisser clair.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: ``True`` = l'utilisateur a tranché. ``False`` = nouveau terme à
    #: reviewer → déclenche le gate ``ANON_PENDING_REVIEW``.
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # --- Champs étendus 2026-05-06 (page /data/privacy) ---
    #: Catégorie sémantique générique. cf. ``ANONYMIZATION_CATEGORIES``.
    #: Default ``"unclassified"`` — l'auto_classifier ou l'utilisateur peut
    #: la préciser. Permet de grouper la liste par type plutôt que par nom
    #: de colonne (qui serait spécifique à la BDD source).
    category: Mapped[str] = mapped_column(String(50), nullable=False, default="unclassified")
    #: D'où le terme a été vu pour la première fois. cf.
    #: ``ANONYMIZATION_SOURCES``. Permet d'afficher la coverage utilisateur.
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    #: Référence de la source (id du classeur, conversation_id, etc.).
    #: Format libre, max 200 chars.
    #:
    #: **Contrat sécurité PII (task #26)** : ce champ peut contenir le
    #: nom de fichier d'un classeur (ex: ``"Bilan_Dupont_Marie_2024.afz.json"``)
    #: qui est potentiellement une identifiant client = **PII**. Invariants
    #: maintenus par la codebase :
    #:
    #: - **JAMAIS envoyé au LLM cloud** : ``build_user_pseudonymizer``
    #:   (extract.py) consomme uniquement ``term`` et ``pseudo_middle`` ;
    #:   ``source_ref`` n'entre pas dans le pseudonymizer. Test de garde :
    #:   ``test_source_ref_never_in_pseudonymizer_payload``.
    #: - **JAMAIS logué** : aucun ``logger.info/warn/error`` n'inclut
    #:   ``source_ref`` ou ``classeur_ref`` (vérifié par grep).
    #: - **Visibilité owner-only** : exposé via ``to_dict()`` ⇒ API
    #:   ``/api/anonymization/terms?detailed=1`` (authentifié + owner).
    #: - **Audit admin-only** : ``anonymization_audit.classeur_ref`` stocké
    #:   pour traçabilité forensic, consultation réservée admin.
    #:
    #: Si un futur refactor envoie ``source_ref`` au LLM ou aux logs, il
    #: DOIT préalablement l'anonymiser via le pseudonymizer user-scoped.
    source_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    #: Dernière fois que le terme a été vu dans une extraction (workbook
    #: ouvert, message Iris envoyé). Permet TTL et tri "récents".
    #: Critical #37 review : ``timezone=True`` pour empêcher le drift TZ
    #: silencieux. Cohérent avec ``value_mapping_archive.archived_at``
    #: et le helper ``ensure_utc`` côté Python.
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Compteur d'apparitions cumulées (heat — affichage badge "X occurrences").
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: ``True`` = proposé par auto_classifier (Ollama), pas encore validé
    #: par le user. Distingue d'un ajout manuel (``False``).
    auto_proposed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: Niveau de risque calculé. cf. ``ANONYMIZATION_RISK_LEVELS``.
    #: Alimente le badge global "X termes critiques en clair".
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    #: Stratégie de remplacement. cf. ``ANONYMIZATION_REPLACEMENT_STRATEGIES``.
    #: Default ``"pseudo"`` — substitution bijective via Pseudonymizer.
    replacement_strategy: Mapped[str] = mapped_column(String(50), nullable=False, default="pseudo")
    #: Origines du token dans les classeurs du user (task #20 — groupement
    #: par colonne d'origine dans /data/privacy). Format JSON sérialisé :
    #: ``[{"classeur": "Bilan.afz.json", "col": "Nom"}, ...]``. ``col`` peut
    #: être ``null`` pour les origines sans colonne associée (tab label,
    #: drill-down). ``classeur`` peut être ``null`` si la source n'est pas
    #: un classeur (scan-workbook sans classeur_ref, sql_result, etc.).
    #:
    #: Stocké en TEXT (JSON sérialisé) plutôt que JSON natif pour rester
    #: agnostique du dialect (SQLite/PostgreSQL). Tronquage à 5000 chars
    #: cap raisonnable : 100 origines × ~50 chars/origine ≈ 5000. Au-delà,
    #: on tronque alphabétiquement pour rester déterministe.
    #:
    #: ``None`` = pas d'info d'origine (rows historiques pré-task #20 OU
    #: terme ajouté manuellement via panneau /data/privacy).
    #:
    #: **Contrat sécurité PII (task #26)** : ``origins[].classeur`` contient
    #: le MÊME nom de fichier potentiellement-PII que :data:`source_ref`.
    #: Les MÊMES 4 invariants s'appliquent :
    #:
    #: - **JAMAIS envoyé au LLM cloud** : ``get_state_for_user`` ne le
    #:   propage pas au state v1, donc ``build_user_pseudonymizer`` ne
    #:   le voit pas. Test de garde :
    #:   ``test_origins_classeur_never_in_pseudonymizer_payload``.
    #: - **JAMAIS logué** : aucun ``logger.*`` n'inclut les origines.
    #: - **Visibilité owner-only** : exposé via ``to_dict()`` (parsé en
    #:   list de dicts par ``_origins_decoded``).
    #: - **Purgé au cleanup nightly** (task #24) quand le classeur
    #:   disparaît du datastore — bornage du risque de fuite historique.
    origins: Mapped[str | None] = mapped_column(String(5000), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="anonymization_terms")

    __table_args__ = (
        #: Unicité métier : un user ne peut avoir qu'UNE ligne par terme.
        #: Les upserts utilisent cette contrainte comme cible
        #: (``ON CONFLICT (user_id, term) DO UPDATE``).
        UniqueConstraint("user_id", "term", name="uq_anonymization_term_user_term"),
        #: Index combiné pour accélérer la lecture du state complet d'un
        #: user (``SELECT * WHERE user_id = ? ORDER BY term``).
        Index("ix_anonymization_term_user_enabled", "user_id", "enabled"),
        #: Critical #37 review : index pour le gate 409 ANON_PENDING_REVIEW
        #: (``WHERE user_id = ? AND confirmed = ?``) — lecture chaude au
        #: copilot reconcile et au PUT panneau.
        Index("ix_anonymization_term_user_confirmed", "user_id", "confirmed"),
        #: Critical #37 review : CHECK constraints sur les enums textuels.
        #: Defense-in-depth : un INSERT direct via SQL ad-hoc ou script
        #: avec ``risk_level="MAXIMUM"`` (typo, valeur inventée) cassait
        #: silencieusement l'UI qui pilote le badge global. Désormais la
        #: BDD refuse au niveau contrainte.
        #:
        #: ⚠️ **BDD existante** : modifier les tuples ANONYMIZATION_*
        #: étend le CHECK pour les BDD VIERGES (créées via ``create_all``
        #: après le change), mais les BDD existantes gardent le CHECK
        #: d'origine — un INSERT avec une nouvelle valeur (ex:
        #: ``source='dashboard'`` ajouté 2026-05-20) lèvera
        #: ``IntegrityError: CHECK constraint failed: ck_anon_term_source``.
        #: Sur SQLite, la rectification propre est : (a) ``CREATE TABLE
        #: anonymization_terms_new ...`` avec le nouveau CHECK, (b)
        #: ``INSERT INTO ..._new SELECT * FROM anonymization_terms``,
        #: (c) ``DROP TABLE anonymization_terms``, (d) ``ALTER TABLE
        #: ..._new RENAME TO anonymization_terms``. Le hack
        #: ``PRAGMA writable_schema=ON; UPDATE sqlite_master ...`` est
        #: une alternative mais NON portable au mécanisme ``_Migration``
        #: qui exécute un statement à la fois.
        CheckConstraint(
            "category IN (" + ",".join(f"'{c}'" for c in ANONYMIZATION_CATEGORIES) + ")",
            name="ck_anon_term_category",
        ),
        CheckConstraint(
            "source IN (" + ",".join(f"'{s}'" for s in ANONYMIZATION_SOURCES) + ")",
            name="ck_anon_term_source",
        ),
        CheckConstraint(
            "risk_level IN (" + ",".join(f"'{r}'" for r in ANONYMIZATION_RISK_LEVELS) + ")",
            name="ck_anon_term_risk_level",
        ),
        CheckConstraint(
            "replacement_strategy IN ("
            + ",".join(f"'{s}'" for s in ANONYMIZATION_REPLACEMENT_STRATEGIES)
            + ")",
            name="ck_anon_term_replacement_strategy",
        ),
    )

    def __repr__(self) -> str:
        # Ne JAMAIS logger ``term`` en clair dans __repr__ (potentiellement
        # PII). On expose juste la longueur + les flags.
        return (
            f"<AnonymizationTerm(id={self.id}, user_id={self.user_id}, "
            f"term_len={len(self.term) if self.term else 0}, "
            f"enabled={self.enabled}, confirmed={self.confirmed})>"
        )

    def to_state_entry(self) -> dict:
        """Convertit le model en dict au format ``anon_terms`` v1 (pour
        injection dans ``state.terms[term]``). Ne PAS utiliser pour une
        sortie API générique : expose ``term`` en clair, réservé à la
        communication copilot ↔ front (déjà autorisés à voir le cleartext)."""
        entry: dict = {
            "enabled": bool(self.enabled),
            "confirmed": bool(self.confirmed),
        }
        if self.pseudo_middle:
            entry["pseudo"] = self.pseudo_middle
        return entry

    def to_dict(self) -> dict:
        """Représentation complète (debug/audit/page /data/privacy)."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "term": self.term,
            "pseudo_middle": self.pseudo_middle,
            "enabled": bool(self.enabled),
            "confirmed": bool(self.confirmed),
            "category": self.category,
            "source": self.source,
            "source_ref": self.source_ref,
            "last_seen_at": (
                ensure_utc(self.last_seen_at).isoformat() if self.last_seen_at else None
            ),
            "usage_count": int(self.usage_count or 0),
            "auto_proposed": bool(self.auto_proposed),
            "risk_level": self.risk_level,
            "replacement_strategy": self.replacement_strategy,
            "origins": self._origins_decoded(),
            "created_at": (ensure_utc(self.created_at).isoformat() if self.created_at else None),
            "updated_at": (ensure_utc(self.updated_at).isoformat() if self.updated_at else None),
        }

    def _origins_decoded(self) -> List[dict] | None:
        """Décoder ``origins`` (string JSON sérialisé) en liste pour l'API.

        Applique les MÊMES règles de normalisation que le path d'écriture
        (``repository._normalize_origin_entry``) en réutilisant le helper
        directement. Sans cette double passe, un dict avec types non-strings
        ou clés étrangères (``[{"classeur": 42, ...}]`` posé via SQL ad-hoc)
        sortirait au frontend qui compare ``o.classeur === groupClasseur``
        en strict equality JS → mismatch silencieux fix finding #10 review.

        Tolérant : JSON corrompu / vides / non-list ⇒ ``None``.
        """
        if not self.origins or not isinstance(self.origins, str):
            return None
        try:
            decoded = json.loads(self.origins)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(decoded, list):
            return None
        # Import tardif pour casser le cycle module models ↔ services.
        from app.services.anonymization.repository import _normalize_origin_entry

        out: list[dict] = []
        for entry in decoded:
            normalized = _normalize_origin_entry(entry)
            if normalized is not None:
                out.append({"classeur": normalized[0], "col": normalized[1]})
        return out if out else None
