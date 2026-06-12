"""LOT 11 — Auto-anonymisation des classeurs via LLM local.

**But** : compléter le panneau d'anonymisation utilisateur. L'utilisateur
choisit toujours en dernier ressort quels tokens sont vraiment sensibles
(human-in-the-loop), mais le système peut **proposer** une liste initiale
extraite par un LLM local, ce qui élimine le travail répétitif.

**Architecture** :

1. ``extract_terms()`` (dans ``anon_terms.py``) découpe le classeur en
   tokens bruts — toutes les valeurs textuelles, déduplicées. C'est
   exhaustif mais aveugle au sens (token = mot, sans distinction nom de
   famille / nom de fichier / mot technique).
2. ``auto_classify_terms()`` (ce module) prend cette liste de tokens et
   demande au LLM local de marquer ceux qui sont **PII probables**
   (noms de personnes, emails, n° SIREN, IBAN, adresses, …). Le LLM
   reçoit la liste de tokens sans contexte (pas le classeur lui-même
   ni les noms de colonnes — confidentialité Niveau 3 du CLAUDE.md :
   « données décontextualisées »).
3. La sortie est merged dans le state ``anonymization_terms`` avec
   ``enabled=True, confirmed=False`` — le flag ``confirmed=False`` force
   l'utilisateur à valider via le panneau avant le 1er appel LLM cloud.
   Aucun bypass : le LLM local PROPOSE, l'utilisateur DISPOSE.

**Pourquoi un LLM local et pas un regex** :

Un regex ne peut pas distinguer ``DUPONT`` (nom de famille à anonymiser)
de ``RUBRIQUE`` (libellé comptable non sensible). Le LLM local fait
cette distinction sémantique avec ~95% de précision sur des modèles
3B-7B (Phi-3-mini, Llama-3.2-3B, Qwen2.5-3B), suffisant comme première
proposition à valider par l'humain.

**Best-effort** : si le LLM local est down / non configuré / lent, on
retourne ``set()`` — l'utilisateur fait la sélection 100% manuelle
comme avant. Aucune dégradation, juste pas d'aide automatique.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, Set

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AutoClassifyResult:
    """Résultat structuré d'un appel ``auto_classify_chunk``.

    Distingue les 4 cas (au lieu d'un ``set()`` opaque retourné
    silencieusement à chaque échec) pour permettre au handler de propager
    une vraie information au frontend qui peut alors afficher un toast
    non-bloquant. L'app continue normalement même en cas d'erreur (PAS de
    blocage cloud — task #10).

    Statuts (``status``) :

    - ``"ok"`` : LLM a répondu, ``flagged`` contient les tokens identifiés
      comme PII probables.
    - ``"not_configured"`` : Ollama local pas activé via /admin/ai-config.
      ``flagged`` est vide. L'user peut activer le LLM local ou faire la
      sélection manuelle.
    - ``"timeout"`` : Ollama a répondu trop lentement. ``flagged`` est vide.
      Retenter ou cap plus court.
    - ``"error"`` : autre erreur (parse JSON, providers indisponibles, etc.).
      ``flagged`` est vide. ``message`` contient la description courte.
    """

    flagged: Set[str] = field(default_factory=set)
    status: str = "ok"  # "ok" | "not_configured" | "timeout" | "unreachable" | "error"
    message: Optional[str] = None


# Taille d'un chunk traité en un seul appel LLM. Volontairement petit
# (200 tokens) pour : (1) tenir dans le context window des modèles 3B
# (typiquement 4K context), (2) garder un temps de réponse acceptable
# (~5s sur GPU consumer) et donner une vraie progression UI au client.
# **Pas de borne totale** : le frontend chunke en autant d'appels que
# nécessaire — la taille du classeur ne limite plus l'auto-anonymisation.
_AUTO_ANON_BATCH_SIZE = 200

# Cap output tokens — fallback UNIQUEMENT si le modèle local actif n'a
# pas son ``max_output_tokens`` renseigné dans le registre BDD (cas rare,
# modèle Ollama jamais sync). Le bon comportement = lire dynamiquement
# via ``get_max_tokens_for_model(manager.get_local_fallback_model())``,
# fait dans :func:`_resolve_max_output_tokens` ci-dessous. **Règle Komptia
# (CLAUDE.md)** : pas de ``max_tokens=<int>`` hardcodé sur call-site —
# toujours via le registre, fallback explicite seulement.
_AUTO_ANON_MAX_OUTPUT_FALLBACK = 4096


def _resolve_max_output_tokens() -> int:
    """Lit le ``max_output_tokens`` du modèle local actif depuis le registre.

    Source de vérité : ``LlmModel.max_output_tokens`` (admin-éditable via
    ``/admin/ai-models``). Le bouton « Mettre à jour fenêtres & tarifs »
    sync automatiquement ce champ depuis Ollama ``/api/show``. Fallback
    sur ``_AUTO_ANON_MAX_OUTPUT_FALLBACK`` UNIQUEMENT si le registre n'a
    pas l'info (modèle pas encore sync). Loggue un warning dans ce cas
    pour que l'admin sache quoi sync.
    """
    try:
        from app.constants_ai import get_max_tokens_for_model
        from app.services.ai.llm_providers import get_llm_manager

        manager = get_llm_manager()
        model_name = manager.get_local_fallback_model() or ""
        if not model_name:
            return _AUTO_ANON_MAX_OUTPUT_FALLBACK
        value = get_max_tokens_for_model(model_name)
        if value and value > 0:
            return int(value)
        logger.warning(
            "auto_classify: max_output_tokens absent du registre pour %r — "
            "fallback %d. Sync via /admin/ai-models pour fixer.",
            model_name,
            _AUTO_ANON_MAX_OUTPUT_FALLBACK,
        )
    except Exception:  # noqa: BLE001 — defense-in-depth, ne JAMAIS bloquer le LLM
        pass
    return _AUTO_ANON_MAX_OUTPUT_FALLBACK


# Probe pour calibration : 10 tokens factices, mesure ``duration_ms``
# pour permettre au frontend d'afficher une estimation avant le run.
# Volontairement très petit (warm-up + 1 round de generation).
_PROBE_TOKEN_COUNT = 10


# Filtre déterministe pré-LLM : les tokens **purement numériques** ne sont
# JAMAIS auto-classifiés. Raison architecturale : les opérations
# arithmétiques de copilot_agent (SUM, ratios, CASE WHEN, comparaisons)
# ne se restaurent pas correctement si une valeur est remplacée par un
# pseudo. La traduction bidirectionnelle peut restaurer une référence
# (ex: ``WHERE expert = '[PSEUDO_42]'``), pas le résultat d'un calcul
# fait sur des pseudos. L'auto-classification se contente donc de ce
# qu'elle peut anonymiser sans casser l'analytique : le textuel.
#
# L'utilisateur peut toujours flagger un nombre manuellement via le
# panneau de confidentialité (ex: un salaire qui identifie une personne
# dans une petite équipe — décision contextuelle qu'aucun LLM 3B-7B
# ne peut prendre sans connaître la taille de l'équipe).
#
# **Ce que ce filtre laisse passer au LLM** : tous les tokens qui ne
# sont PAS purement numériques. Ça inclut les vrais PII numériques
# habituels qui sont presque toujours formatés avec des lettres ou
# espaces non-standards : RIB ("FR76 1234…"), emails, mots avec digits
# ("USER_42"), etc. Reste un trou connu : téléphones français écrits
# en pur numérique ("0612345678", "06 12 34 56 78", "06.12.34.56.78")
# — l'utilisateur doit les flagger manuellement, ou on ajoute une
# passe regex dédiée si le besoin est récurrent.
# Caractères acceptés en plus des chiffres dans un "pur numérique" :
# - espaces (normal, tab, insécable) → "1 234"
# - séparateurs décimaux/milliers → "1,234.56"
# - underscore → tokens "ID_42"
# - signes → "-1234", "+1234"
# - "/" → exercices fiscaux ("2023/2024"), dates ("26/04/2023")
# - ":" → heures ("12:30:45")
# Avec "/" et ":" inclus, les libellés temporels du type "2023/2024",
# "2024/25", "26/04/2023", "12:30" sont skippés du LLM (donc préservés
# tels quels pour copilot_agent qui en a besoin pour les filtres période).
_NUMERIC_ALLOWED_CHARS = frozenset(" \t\u00a00123456789+-_.,/:")


def _is_pure_numeric(token: str) -> bool:
    """True si ``token`` est un pur nombre (chiffres + séparateurs/signes).

    Critère :
    - Au moins un chiffre présent (sinon "...,..." passerait — pas un nombre).
    - Tous les caractères sont chiffres, séparateurs (``,`` ``.`` ``_``),
      espaces (normal, tab, insécable) ou signes (``+`` ``-``).

    Exemples :
    - ``"1234"`` → True
    - ``"1234.56"`` → True
    - ``"-1234.56"`` → True
    - ``"1 234,56"`` → True (format européen)
    - ``"1\u00a0234"`` → True (espace insécable)
    - ``"FR76 1234"`` → False (contient des lettres → vrai PII)
    - ``"anne"`` → False (pas de chiffre)
    - ``"1234€"`` → False (devise → texte)
    - ``""`` / ``None`` / ``"   "`` → False
    """
    if not token or not isinstance(token, str):
        return False
    s = token.strip()
    if not s:
        return False
    has_digit = False
    for c in s:
        if c.isdigit():
            has_digit = True
            continue
        if c not in _NUMERIC_ALLOWED_CHARS:
            return False
    return has_digit


_PROMPT_TEMPLATE = """\
Tu es un classifieur PII (Personally Identifiable Information). Tu reçois \
une liste de tokens extraits d'un classeur Excel.

**Ta tâche** : identifier les tokens qui sont **probablement** des données \
sensibles à anonymiser avant un envoi à un LLM externe. Sois conservateur \
— en cas de doute, marque comme sensible (l'utilisateur validera ensuite).

**À MARQUER comme sensible** :
- Noms de personnes (DUPONT, Marie Curie, …)
- Noms d'entreprises clientes / fournisseurs spécifiques (PIXEL SARL, …)
- Adresses postales / villes spécifiques
- Numéros : SIREN/SIRET, IBAN, RIB, téléphone, sécu, TVA
- Emails complets
- Identifiants opaques pouvant rattacher à une personne (ex: matricule)

**À NE PAS marquer (laisser passer)** :
- Mots techniques / comptables : RUBRIQUE, COMPTE, SOLDE, DEBIT, CREDIT, TVA
- Mots génériques : Total, Sous-total, Charges, Produits, Recettes
- Dates au format standard (2026-04-26, 26/04/2026)
- Valeurs monétaires (1234.56, 1 000 €)
- Booléens, énumérations standards (oui/non, actif/inactif)
- Noms de colonnes / champs techniques

**Format de réponse** : JSON strict, sans markdown ni texte autour. Une \
liste des tokens À ANONYMISER (uniquement ceux du tableau d'entrée, \
copiés tels quels) :

```json
{{"sensitive": ["TOKEN1", "TOKEN2", ...]}}
```

**Tokens à classer** :
{tokens_json}
"""


def _chunk(items: list, size: int) -> Iterable[list]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


async def auto_classify_chunk(
    candidate_tokens: Set[str],
    *,
    timeout_seconds: float = 60.0,
) -> AutoClassifyResult:
    """Classe UN chunk (≤ ``_AUTO_ANON_BATCH_SIZE`` tokens) en 1 appel LLM.

    Retourne un :class:`AutoClassifyResult` avec ``flagged`` (sous-ensemble
    de ``candidate_tokens`` — ne crée jamais un nouveau token, sécurité
    anti-hallucination) ET un ``status`` qui distingue les 4 cas d'échec
    (task #10) pour permettre une vraie notification UI non-bloquante au
    lieu d'un silence opaque.

    **Stateless / chunked** : ce helper traite UN chunk. Pour traiter un
    classeur de taille infinie, le caller (frontend ou orchestrateur)
    boucle en envoyant les tokens par paquets de
    ``_AUTO_ANON_BATCH_SIZE``. Chaque appel = 1 requête HTTP, ce qui
    permet à l'UI d'afficher une vraie progression et de cancel proprement.

    Best-effort (task #10 — notif UI sans blocage cloud) :
    - LLM local non configuré → status="not_configured"
    - LLM local timeout → status="timeout"
    - Autre erreur (providers / parse) → status="error" + message
    - OK → status="ok" + flagged peuplé
    """
    if not candidate_tokens:
        return AutoClassifyResult()

    # Filtre déterministe pré-LLM : exclut les purs numériques. Voir
    # ``_is_pure_numeric`` — préserve les opérations arithmétiques de
    # copilot_agent (la traduction bidirectionnelle ne peut pas restaurer
    # le résultat d'un calcul fait sur des pseudos). L'utilisateur peut
    # toujours flagger un nombre manuellement via le panneau si besoin.
    non_numeric = [t for t in candidate_tokens if not _is_pure_numeric(t)]
    if not non_numeric:
        # Chunk 100% numérique → rien à envoyer au LLM (et donc pas de
        # consommation d'Ollama / latence pour zéro résultat possible).
        return AutoClassifyResult()

    try:
        from app.services.ai.llm_providers import (
            LLMRequest,
            ensure_providers_from_db,
            get_llm_manager,
        )
        from app.services.ai.llm_runtime import (
            CallProfile,
            ModelKind,
            RetryPolicy,
            call_llm,
        )
    except ImportError as exc:
        logger.warning("auto_classify_chunk: providers indisponibles : %s", exc)
        return AutoClassifyResult(
            status="error",
            message="Providers LLM indisponibles (import).",
        )

    # Early return discret si le LOCAL n'est pas configuré (call_llm raise
    # sinon — on préserve le comportement legacy "silent skip").
    await ensure_providers_from_db()
    manager = get_llm_manager()
    if manager.get_local_fallback() is None:
        logger.debug(
            "auto_classify_chunk: LLM local non configuré "
            "(/admin/ai-config → Anonymisation locale)"
        )
        return AutoClassifyResult(status="not_configured")

    # Cap dur sur le chunk : si le caller envoie plus que la taille
    # batch, on tronque. Sécurité côté serveur (le frontend doit
    # respecter la limite, mais on ne fait pas confiance aveuglément).
    tokens_list = non_numeric[:_AUTO_ANON_BATCH_SIZE]
    candidate_set = set(tokens_list)

    # Température lue de la config admin (slider /admin/ai-config).
    # Default 0.0 = déterministe (recommandé pour anonymisation).
    local_temp = 0.0
    try:
        from app.services.ai.config_service import get_ai_config_service

        cs = get_ai_config_service()
        raw = await cs.get("local_llm_temperature")
        if raw is not None:
            local_temp = float(raw)
    except Exception:  # noqa: BLE001
        pass

    prompt = _PROMPT_TEMPLATE.format(tokens_json=json.dumps(tokens_list, ensure_ascii=False))
    try:
        # ModelKind.LOCAL résout automatiquement model_name + provider_name
        # vers Ollama, et call_llm gère le timeout via wait_for.
        from app.services.ai.llm_runtime import LLMCallError as _LLMErr

        response = await call_llm(
            CallProfile(
                caller="anonymizer_classify",
                model_kind=ModelKind.LOCAL,
                timeout_seconds=timeout_seconds,
                retry=RetryPolicy.NONE,
            ),
            LLMRequest(
                prompt=prompt,
                system="",
                temperature=local_temp,
                max_tokens=_resolve_max_output_tokens(),
            ),
        )
    except _LLMErr as exc:
        # Discriminer timeout vs injoignable vs autre pour préserver
        # l'observabilité ciblée (ops a besoin de savoir si Ollama est lent
        # vs ARRÊTÉ — message + status distincts, pas de « timeout » trompeur).
        if exc.kind == "unreachable":
            logger.warning(
                "auto_classify_chunk: LLM local injoignable (service arrêté ?) "
                "sur chunk de %d tokens — abandon immédiat.",
                len(tokens_list),
            )
            # status="unreachable" DISTINCT : le frontend STOPPE la boucle de
            # scan + affiche un message actionnable (« démarre le LLM local »),
            # au lieu de continuer à marteler un service éteint chunk par chunk.
            return AutoClassifyResult(
                status="unreachable",
                message=(
                    "Le LLM local est configuré mais ne répond pas "
                    "(service arrêté ?). Démarre-le puis réessaie."
                ),
            )
        if exc.kind == "network":
            logger.warning(
                "auto_classify_chunk: timeout LLM local (%.0fs) sur chunk de %d tokens",
                timeout_seconds,
                len(tokens_list),
            )
            return AutoClassifyResult(
                status="timeout",
                message=f"LLM local n'a pas répondu en {timeout_seconds:.0f}s.",
            )
        logger.warning("auto_classify_chunk: erreur LLM local : %s", exc)
        return AutoClassifyResult(
            status="error",
            message=f"Erreur LLM local : {exc}",
        )
    except Exception as exc:  # noqa: BLE001 — parse / autre → skip
        logger.warning("auto_classify_chunk: erreur LLM local : %s", exc)
        return AutoClassifyResult(
            status="error",
            message=f"Erreur inattendue : {exc.__class__.__name__}",
        )

    return AutoClassifyResult(
        flagged=_parse_response(response.content, candidate_set),
        status="ok",
    )


# Alias rétro-compat — l'API publique historique. Utilise un chunk unique.
async def auto_classify_terms(
    candidate_tokens: Set[str],
    *,
    timeout_seconds: float = 60.0,
) -> Set[str]:
    """Classe ``candidate_tokens`` (≤ batch_size) — alias rétrocompat de
    ``auto_classify_chunk``. Retourne uniquement ``flagged`` (Set[str])
    pour préserver l'ancienne signature. Les callers qui ont besoin du
    statut d'erreur (notif UI task #10) doivent utiliser
    ``auto_classify_chunk`` directement."""
    result = await auto_classify_chunk(candidate_tokens, timeout_seconds=timeout_seconds)
    return result.flagged


async def probe_local_llm() -> Optional[float]:
    """Mesure le temps d'un appel LLM local **et valide** que la réponse
    est exploitable (parseable JSON).

    Sans cette validation (review #1 BLOCKING), un LLM qui répond du vide
    ou un message d'erreur produit un faux signal : le frontend lance N
    chunks qui retournent tous ``[]`` silencieusement → minutes perdues.

    Retourne le temps en ms si OK, ou ``None`` si :
    - LLM local non configuré
    - Timeout (60s, aligné avec ``auto_classify_chunk``)
    - Réponse vide / non-JSON / sans champ ``sensitive``
    """
    try:
        from app.services.ai.llm_providers import (
            LLMRequest,
            ensure_providers_from_db,
            get_llm_manager,
        )
        from app.services.ai.llm_runtime import (
            CallProfile,
            ModelKind,
            RetryPolicy,
            call_llm,
        )
    except ImportError:
        return None

    # Early return discret si le LOCAL n'est pas configuré.
    await ensure_providers_from_db()
    manager = get_llm_manager()
    if manager.get_local_fallback() is None:
        return None

    # Tokens factices neutres (mots techniques, pas de PII)
    fake_tokens = [
        "alpha",
        "beta",
        "gamma",
        "delta",
        "epsilon",
        "zeta",
        "eta",
        "theta",
        "iota",
        "kappa",
    ]
    prompt = _PROMPT_TEMPLATE.format(tokens_json=json.dumps(fake_tokens))

    # Timeout généreux : 1er appel après cold start = chargement modèle
    # en RAM/VRAM (30-90s pour 3B sur CPU, 5-15s sur Apple Silicon).
    # Le probe sert AUSSI à warm-up Ollama — donc on accepte 180s.
    # Les chunks suivants sont rapides (modèle déjà chargé).
    import time

    PROBE_TIMEOUT_SECONDS = 180.0
    try:
        from app.services.ai.llm_runtime import LLMCallError as _LLMErr

        start = time.monotonic()
        response = await call_llm(
            CallProfile(
                caller="probe",
                model_kind=ModelKind.LOCAL,
                timeout_seconds=PROBE_TIMEOUT_SECONDS,
                retry=RetryPolicy.NONE,
            ),
            LLMRequest(
                prompt=prompt,
                system="",
                temperature=0.0,
                max_tokens=_resolve_max_output_tokens(),
            ),
        )
        duration_ms = (time.monotonic() - start) * 1000.0
    except _LLMErr as exc:
        if exc.kind == "unreachable":
            logger.warning(
                "probe_local_llm: LLM local injoignable (connexion refusée) — "
                "Ollama arrêté ? Vérifier `ollama serve` + `ollama list`.",
            )
        elif exc.kind == "network":
            logger.warning(
                "probe_local_llm: timeout %.0fs — Ollama très lent ou bloqué. "
                "Vérifier `pkill -9 ollama && ollama serve` + `ollama list` "
                "pour confirmer le modèle.",
                PROBE_TIMEOUT_SECONDS,
            )
        else:
            logger.warning("probe_local_llm: erreur : %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001 — provider down / parse → skip
        logger.warning("probe_local_llm: erreur : %s", exc)
        return None

    # Validation contenu : la réponse DOIT être un JSON parseable avec
    # un champ ``sensitive`` (même si la liste est vide, c'est OK : le LLM
    # a compris le format). Sinon → faux signal, retourne None.
    content = (response.content or "").strip()
    if not content:
        logger.warning("probe_local_llm: réponse vide — modèle non fonctionnel pour cette tâche")
        return None
    _parse_response(content, set(fake_tokens))
    # parsed peut être set() légitime (aucun fake token n'est sensible),
    # mais _parse_response a internement validé la structure JSON via
    # un side-effect logger — on vérifie ici que le content contient bien
    # le champ "sensitive" pour ne pas faire confiance au _parse_response
    # silencieux.
    if '"sensitive"' not in content:
        logger.warning(
            "probe_local_llm: réponse sans champ 'sensitive' (%.200s) — "
            "modèle ne respecte pas le format. Tenter un autre modèle.",
            content,
        )
        return None
    return duration_ms


def _parse_response(content: str, candidate_set: Set[str]) -> Set[str]:
    """Parse la réponse JSON du LLM local et filtre par ``candidate_set``.

    Pattern de parsing tolérant à 3 niveaux (review #3 — la regex naïve
    cassait dès qu'un token contenait ``{`` ou ``}``) :

    1. ``json.loads`` direct sur le content stripped.
    2. Strip markdown fences (```json ... ```) et retry.
    3. ``raw_decode`` qui scanne ``content`` à la recherche du 1er JSON
       valide (gère les préambules type "Voici le résultat :").

    Filtre anti-hallucination : retourne UNIQUEMENT les tokens présents
    dans ``candidate_set`` (sécurité — si le LLM invente un token, ignoré).
    """
    if not content:
        return set()
    raw_strip = content.strip()
    data = None
    # 1. JSON direct
    try:
        data = json.loads(raw_strip)
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    # 2. Strip fences markdown
    if data is None:
        cleaned = re.sub(
            r"^```(?:json)?\s*|\s*```\s*$",
            "",
            raw_strip,
            flags=re.MULTILINE,
        )
        try:
            data = json.loads(cleaned.strip())
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    # 3. raw_decode — scanne pour trouver le 1er JSON valide
    if data is None:
        decoder = json.JSONDecoder()
        for idx in range(len(raw_strip)):
            if raw_strip[idx] != "{":
                continue
            try:
                obj, _ = decoder.raw_decode(raw_strip[idx:])
                if isinstance(obj, dict) and "sensitive" in obj:
                    data = obj
                    break
            except json.JSONDecodeError:
                continue
    if not isinstance(data, dict):
        logger.warning("auto_classify_chunk: réponse non-JSON parseable : %.200s", content)
        return set()
    sensitive = data.get("sensitive")
    if not isinstance(sensitive, list):
        return set()
    # Anti-hallucination : retient UNIQUEMENT les tokens du candidate_set
    return {str(s) for s in sensitive if str(s) in candidate_set}


