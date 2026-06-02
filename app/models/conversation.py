"""
Modèles Conversation et ConversationMessage — Historique des échanges avec Iris
"""

import enum
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Enum as SQLEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text as sa_text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, ensure_utc

if TYPE_CHECKING:
    from app.models.user import User


class MessageRole(str, enum.Enum):
    """Rôles possibles pour un message dans une conversation"""

    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"


class ConversationSource(str, enum.Enum):
    """Entry point d'origine d'une Conversation Iris.

    Discrimine la conv ouverte depuis la page complète ``/iris`` de celle
    ouverte depuis le widget flottant global, ou de celle invoquée en
    backend par un step d'automatisation. Trois entry points = trois
    contextes UX/runtime distincts ; sans cette colonne,
    ``get_or_create_active_conversation`` retournait la même conv active
    aux trois et leurs messages se mélangeaient (bug 2026-05-21).

    Valeurs :
        - ``PAGE`` : conv créée/utilisée par la page ``/iris`` (chat plein écran).
        - ``WIDGET`` : conv créée/utilisée par le floating widget (``iris-widget.js``).
        - ``AUTOMATION`` : conv invoquée depuis un step ``iris`` d'une
          automatisation backend (cron / scheduler / déclenchement manuel).
          Distinguée pour : (a) anti-pollution mémoire user (cf. Task #31 —
          ``IrisUserMemory.add()`` ignore source=automation), (b) audit log
          dédié (cf. Task #33), (c) UX panneau "Décisions Iris" /runs/M
          (cf. Task #17). Introduite 2026-05-27 (Task #7 P2.2).

    Rétrocompat : les rows BDD pré-migration ont ``source = 'page'`` par
    défaut (cf. migration ``_Migration("conversations", "source", ...)``
    dans ``app/core/database.py``). Sémantique : avant le fix, toutes les
    conv passaient par le même SSOT — les classer comme ``page`` est le
    bon choix par défaut puisque la page est l'entry point historique.
    """

    PAGE = "page"
    WIDGET = "widget"
    AUTOMATION = "automation"


class Conversation(BaseModel):
    """
    Conversation Iris — regroupe une série de messages échangés avec l'agent.

    Attributs:
        user_id: Propriétaire de la conversation
        title: Titre auto-généré depuis le premier message (nullable)
        agent_role: Persona actif lors de la conversation (défaut : "iris")
        source: Entry point d'origine (``page`` ou ``widget``) — sépare la
            conv ouverte depuis ``/iris`` de celle ouverte depuis le
            floating widget global, pour qu'elles n'interfèrent pas.
        is_active: Conversation en cours ou archivée
        message_count: Nombre de messages (dénormalisé pour performance)
        total_tokens: Total de tokens consommés (dénormalisé)
    """

    __tablename__ = "conversations"

    # Propriétaire
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Métadonnées
    title: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    agent_role: Mapped[str] = mapped_column(String(50), nullable=False, default="iris")

    # Entry point d'origine (cf. enum ``ConversationSource``). Discrimine
    # widget vs page complète — sans cette colonne, le SSOT retournait la
    # même conv aux deux et les messages se mélangeaient. ``server_default``
    # = ``page`` pour que les rows BDD pré-migration s'auto-classent.
    source: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=ConversationSource.PAGE.value,
        insert_default=ConversationSource.PAGE.value,
        server_default=ConversationSource.PAGE.value,
        index=True,
    )

    # Statut
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, insert_default=True, nullable=False
    )

    # Compteurs dénormalisés
    message_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Cahier de découvertes — résumé compact des tables, colonnes, FK, valeurs
    # et SQL découverts pendant la conversation. Injecté dans le system prompt
    # pour que le LLM ne perde pas le contexte entre les messages.
    discoveries: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Résumé fin-de-run — produit par un LLM léger à la clôture de la
    # conversation (terminal_kind == "done") et réinjecté en system prompt
    # quand l'utilisateur reprend la conversation plus tard. Distinct de
    # ``discoveries`` (qui collecte les découvertes schéma) : ``summary``
    # capture les **décisions** (interprétations métier validées, joins
    # retenues, conventions établies). Parité avec ``copilot_memory`` du
    # côté Iris (P2.1).
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Dernière taille de contexte (input tokens) envoyée au LLM pour cette
    # conversation. Persisté à chaque ``done`` event de l'agent. Sert à
    # rétablir l'indicateur ``context-window`` côté UI **au reload** de
    # la page : sans cette colonne, l'estimation initiale (cf.
    # ``_estimate_history_tokens``) n'inclut PAS le system prompt ni les
    # tool definitions ni le RAG context — la barre tombe alors de ~50k
    # à ~20k au refresh, ce qui est trompeur pour l'utilisateur. Avec ce
    # champ, le rehydration restaure la vraie dernière valeur ;
    # l'estimation reste le fallback pour les conversations legacy
    # (NULL = jamais persisté).
    last_input_tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # **Phase 2.5.quinquies (#98)** — Compteur de refus data_access consécutifs.
    # Si l'user pose 3+ questions toutes refusées dans la même conversation
    # (typiquement parce que son admin vient de poser un deny qui couvre
    # son domaine principal), on court-circuite le LLM et on affiche un
    # message statique "Vos N dernières requêtes ont été refusées. Contactez
    # votre admin." au lieu de gaspiller des tokens à répéter le même
    # message générique. Reset à 0 dès qu'une question passe avec succès.
    #
    # ⚠️ État actuel : **colonne BDD + migration en place**, mais le
    # branchement runtime dans ``agent_service.run()`` est tracké
    # séparément en task #121 (intercepter les events ``tool_result``
    # avec ``blocked_by="data_access_rule"`` pour increment, reset sur
    # réponse réussie, court-circuit au seuil). Tant que la task n'est
    # pas faite, le compteur reste à 0 pour toutes les conversations —
    # la colonne est prête à être branchée sans nouvelle migration.
    consecutive_denied_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
        comment=(
            "Nombre de refus data_access CONSÉCUTIFS dans cette conversation. "
            "Reset à 0 sur réponse réussie. Court-circuit LLM au seuil "
            "MAX_CONSECUTIVE_DENIED. Branchement runtime en task #121."
        ),
    )

    # Relations
    user: Mapped["User"] = relationship("User", back_populates="conversations")
    # Tri par id (pas created_at) : les messages d'un meme tour ont le meme
    # timestamp, seul l'id auto-incremente preserve l'ordre d'insertion
    # (streaming order : text → tool → text).
    messages: Mapped[List["ConversationMessage"]] = relationship(
        "ConversationMessage",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="ConversationMessage.id",
    )

    # **Partial unique index** sur (user_id, agent_role, source) limité aux
    # rows ``is_active = 1``. Ferme la race TOCTOU dans
    # ``get_or_create_active_conversation`` : sans cet index, deux WS
    # concurrents du même user qui passent le SELECT à vide peuvent
    # créer 2 conv ``is_active=True`` pour le même scope — l'orphelin
    # que le SSOT était censé empêcher (cf. adversarial #1 du 2026-05-21
    # sur fix #22). Avec l'index, l'INSERT concurrent perd lève
    # ``IntegrityError`` et le SSOT re-SELECT pour récupérer la conv
    # créée par le winner.
    #
    # Partial index : SQLite et PostgreSQL le supportent natifs depuis
    # longtemps. La clause ``WHERE is_active = 1`` est CRITIQUE — sans
    # elle, on bloquerait la création d'une nouvelle conv après un
    # « Effacer » (qui hard-delete) suivi d'un re-create immédiat.
    __table_args__ = (
        Index(
            "uq_conversations_active_scope",
            "user_id",
            "agent_role",
            "source",
            unique=True,
            sqlite_where=sa_text("is_active = 1"),
            postgresql_where=sa_text("is_active = true"),
        ),
    )

    def __repr__(self) -> str:
        return f"<Conversation(id={self.id}, user_id={self.user_id}, title='{self.title}')>"

    def to_dict(self) -> dict:
        """Convertit la conversation en dictionnaire sérialisable"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "agent_role": self.agent_role,
            "source": self.source,
            "is_active": self.is_active,
            "message_count": self.message_count,
            "total_tokens": self.total_tokens,
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
            "updated_at": ensure_utc(self.updated_at).isoformat() if self.updated_at else None,
        }


class ConversationMessage(BaseModel):
    """
    Message individuel dans une conversation Iris.

    Attributs:
        conversation_id: Conversation parente
        role: Émetteur du message (user, assistant, tool, system)
        content: Texte du message ou JSON pour contenu complexe
        tool_name: Nom de l'outil appelé (si role == TOOL)
        tool_input: Paramètres envoyés à l'outil (JSON)
        tool_result: Résultat retourné par l'outil (JSON)
        tokens_used: Tokens consommés pour ce message
        duration_seconds: Durée de génération côté LLM
    """

    __tablename__ = "conversation_messages"

    # Conversation parente
    conversation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Contenu
    role: Mapped[MessageRole] = mapped_column(SQLEnum(MessageRole), nullable=False)
    content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Informations outil (si role == TOOL)
    tool_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tool_input: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Métriques
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Feedback (positive/negative)
    feedback: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    # Journal des événements visuels d'un tour (JSON).
    # Stocké sur le dernier message ASSISTANT d'un tour. Contient la séquence
    # ordonnée de tous les événements UI (element_start, element_end,
    # sql_build_start, sql_build_end, suggestions, verification, rag_sources,
    # report_ready, error) pour reproduction fidèle au refresh.
    turn_events: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relations
    conversation: Mapped["Conversation"] = relationship("Conversation", back_populates="messages")

    # Index composite pour récupération efficace des messages d'une conversation
    __table_args__ = (
        Index("ix_conversation_messages_conv_created", "conversation_id", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ConversationMessage(id={self.id}, conversation_id={self.conversation_id},"
            f" role={self.role.value})>"
        )

    def to_dict(self) -> dict:
        """Convertit le message en dictionnaire sérialisable"""
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "role": self.role.value,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_result": self.tool_result,
            "tokens_used": self.tokens_used,
            "duration_seconds": self.duration_seconds,
            "feedback": self.feedback,
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
            "updated_at": ensure_utc(self.updated_at).isoformat() if self.updated_at else None,
        }


class ConversationEvent(BaseModel):
    """Journal append-only des événements WebSocket d'une conversation Iris.

    **But** : permettre un refresh de ``/iris`` strictement IDENTIQUE au DOM
    live juste avant le rafraîchissement. Le restore loop frontend rejoue
    cette séquence d'events via le MÊME dispatcher que le live (pas de chemin
    de rendu parallèle qui dérive). Cf. APEX 2026-05-09 (Solution B).

    **Différence avec ``ConversationMessage.turn_events``** : ``turn_events``
    est un blob JSON stocké sur le DERNIER msg ASSISTANT du tour, qui contient
    seulement un sous-ensemble d'events (pas ``text_delta``, pas
    ``thinking_delta``, etc.) et perd l'ordre relatif avec les ``tool`` msgs
    séparés. ``ConversationEvent`` est UNE ligne par event WS, ordonnée par
    ``seq`` monotone par conversation, source de vérité pour le replay
    fidèle.

    Backward compat : les conversations créées AVANT cette table (events ==
    [] au refresh) tombent automatiquement sur le restore loop legacy côté
    frontend.

    Attributs:
        conversation_id : conversation parente, CASCADE DELETE
        turn_index      : 1-based, le N-ième échange user→assistant. Permet
                          de regrouper les events d'un même tour.
        seq             : monotone par conversation (toutes turns confondues).
                          Garantit l'ordre absolu de replay.
        event_type      : ``text_delta`` / ``tool_use`` / ``tool_result`` /
                          ``thinking_delta`` / ``exploration_*`` / etc. Mirror
                          du champ ``"type"`` du dict yieldé par ``IrisAgent.run()``.
        payload         : JSON serialisé du dict event complet (incluant ``type``).
        created_at      : auto via TimestampMixin.
    """

    __tablename__ = "conversation_events"

    conversation_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("conversations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    turn_index: Mapped[int] = mapped_column(Integer, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)

    conversation: Mapped["Conversation"] = relationship(
        "Conversation",
        # Pas de back_populates — `Conversation.events` n'est pas exposé
        # (lecture toujours via `get_events_for_conversation` pour pagination
        # / filter `after_seq` futurs).
    )

    __table_args__ = (
        # Idempotence : double-write d'un même event ne crée pas de doublon.
        UniqueConstraint(
            "conversation_id",
            "turn_index",
            "seq",
            name="uq_conversation_events_conv_turn_seq",
        ),
        # Lecture rapide : SELECT WHERE conversation_id=? ORDER BY seq.
        Index("ix_conversation_events_conv_seq", "conversation_id", "seq"),
    )

    def __repr__(self) -> str:
        return (
            f"<ConversationEvent(id={self.id}, conv={self.conversation_id},"
            f" turn={self.turn_index}, seq={self.seq}, type={self.event_type!r})>"
        )

    def to_dict(self) -> dict:
        """Sérialisation pour endpoint API + injection template iris.html."""
        return {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "turn_index": self.turn_index,
            "seq": self.seq,
            "event_type": self.event_type,
            "payload": self.payload,  # JSON string — frontend fait JSON.parse
            "created_at": ensure_utc(self.created_at).isoformat() if self.created_at else None,
        }
