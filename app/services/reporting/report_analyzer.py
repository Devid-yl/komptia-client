"""
Analyseur de rapports avec IA
Génération d'analyses textuelles professionnelles pour rapports comptables
"""

from typing import Dict, Any, Optional, List
from decimal import Decimal, InvalidOperation
import html
import json
import math
import asyncio

from app.services.ai.llm_providers import get_llm_manager, LLMRequest
from app.services.ai.config_service import get_ai_config_service
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _coerce_numeric(value: Any) -> Optional[float]:
    """Coercition numérique unique (SSoT interne, axe 7) du module d'analyse.

    Partagée par ``_get_numeric_columns`` (détection des colonnes) ET les
    extracteurs ``detect_trends`` / ``detect_anomalies``. AVANT cette
    factorisation les deux divergeaient : la détection retirait ``€``/``%``/
    espaces avant ``float()`` mais l'extraction faisait un ``float(raw)`` brut →
    une colonne « 1 000 € » était *détectée* numérique puis ses valeurs étaient
    *silencieusement jetées* au calcul (avg/écart-type sur un sous-ensemble
    biaisé). Pire, ``decimal.Decimal`` (colonnes MONEY/NUMERIC Sage renvoyées
    par pyodbc) n'était NI détecté NI extrait → les colonnes de montants, le
    cœur d'une app comptable, échappaient à toute analyse (mêmes symptômes que
    #139). Une seule règle ici garantit détection == extraction.

    Gère : ``int``/``float`` finis, ``decimal.Decimal`` finis, et chaînes
    formatées (espaces fine U+202F / insécable U+00A0 / normale, ``€``, ``%``).
    Le ``%`` est retiré et la magnitude conservée en FACE VALUE (« 50% » → 50.0,
    PAS 0.5) — cohérent avec l'ancienne détection ; la détection d'anomalies
    reste valide intra-colonne (invariante d'échelle). Ne PAS réinterpréter
    ``value`` comme une fraction côté consommateur.
    Exclut ``bool`` (sous-type de ``int`` : ``True`` n'est pas une métrique) et
    rejette NaN/inf (un seul NaN empoisonnerait silencieusement avg/écart-type
    → 0 anomalie détectée sur toute la colonne).

    Retourne ``None`` si non convertible (fail-soft : la valeur est ignorée, le
    calcul continue sur le reste de la colonne).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        f = float(value)
        return f if math.isfinite(f) else None
    if isinstance(value, Decimal):
        try:
            f = float(value)
        except (ValueError, InvalidOperation, OverflowError):
            return None
        return f if math.isfinite(f) else None
    if isinstance(value, str):
        cleaned = (
            value.replace(" ", "")  # espace insécable
            .replace(" ", "")  # espace fine insécable
            .replace(" ", "")
            .replace("€", "")
            .replace("%", "")
        )
        if not cleaned:
            return None
        try:
            f = float(cleaned)
        except ValueError:
            return None
        return f if math.isfinite(f) else None
    return None


class ReportAnalyzer:
    """
    Génère des analyses textuelles professionnelles pour rapports comptables
    Utilise un LLM pour détecter tendances, anomalies et insights
    """

    def __init__(self):
        """
        Initialise l'analyseur
        Utilise la configuration centralisée de l'IA
        """
        self.llm_manager = get_llm_manager()
        self.config_service = get_ai_config_service()
        logger.info("📊 ReportAnalyzer initialisé")

    async def analyze_data(
        self,
        data: List[Dict[str, Any]],
        template_name: str,
        context: Optional[Dict[str, Any]] = None,
        user_id: Optional[int] = None,
    ) -> str:
        """
        Génère une analyse complète des données via LLM (async).
        Retombe sur une analyse statistique si le LLM est indisponible.

        Args:
            data: Données à analyser
            template_name: Nom du template de rapport
            context: Contexte additionnel (période, filtres, etc.)
            user_id: identifiant utilisateur pour le proxy d'anonymisation
                (pseudonymizer user-scoped). ``None`` (défaut) pour les
                appels système / batch — la couche PII regex s'applique
                quand même.

        Returns:
            Texte d'analyse professionnel formaté
        """
        logger.info("🔍 Analyse données pour template: %s", template_name)

        if not data or len(data) == 0:
            return "Aucune donnée disponible pour l'analyse."

        # Préparer le contexte
        context = context or {}
        num_rows = len(data)

        # Détecter tendances et anomalies
        trends = self.detect_trends(data)
        anomalies = self.detect_anomalies(data)

        # Construire le prompt
        prompt = self._build_analysis_prompt(
            template_name=template_name,
            num_rows=num_rows,
            trends=trends,
            anomalies=anomalies,
            sample_data=data[:5],  # Premiers 5 enregistrements
            context=context,
        )

        # Générer l'analyse via LLM (async)
        try:
            from app.services.ai.llm_runtime import (
                CallProfile,
                LLMCallError,
                call_llm,
                resolve_active_model,
            )

            # Délégation à :func:`resolve_active_model` — source de vérité
            # unique (avant : check inline avec ValueError sans fallback
            # manager.default_*). Le helper combine has_any_provider_configured
            # + config DB + fallback manager. ``LLMCallError(kind="not_configured")``
            # est traité par le ``except`` global ci-dessous (→ fallback statistique).
            provider_name, model_name = await resolve_active_model()
            from app.services.anonymization import anonymize_for_llm
            from app.services.anonymization.proxy import (
                get_confidentiality_prompt,
            )

            # Proxy d'anonymisation single source of truth. Le payload
            # contient ``sample_data`` (5 lignes brutes), ``trends`` et
            # ``anomalies`` (stats + libellés) — données réelles user.
            # Si ``user_id`` fourni, le pseudonymizer user-scoped tokenise
            # les termes ``enabled=True`` ; couche PII regex défensive
            # active dans tous les cas (emails / SIRET / IBAN dans les
            # cellules d'un rapport comptable).
            prompt_anon, restore_fn = await anonymize_for_llm(user_id, prompt, "REPORT")

            # call_llm route via le manager (donc tracking AIPerformanceLog),
            # pose llm_call_context, gère retry STANDARD sur 429/5xx/network.
            response = await call_llm(
                CallProfile(
                    caller="report_analyzer",
                    provider_name_override=provider_name,
                ),
                LLMRequest(
                    prompt=prompt_anon,
                    system=(
                        get_confidentiality_prompt("REPORT")
                        + "\n\n"
                        + "Tu es un expert-comptable expérimenté. "
                        "Rédige des analyses claires et professionnelles en français. "
                        "Sois concis (max 300 mots), factuel et orienté action."
                    ),
                    model=model_name,
                    temperature=0.3,
                ),
            )
            # Dé-anonymisation : l'analyse retourne au PDF / template final
            # affiché à l'utilisateur — il doit voir les vraies valeurs et
            # libellés (pas ``[EMAIL_1]`` ou ``§CLIENT_A§``).
            raw_text = response.content or ""
            analysis = restore_fn(raw_text).strip() if raw_text else ""

            # **Phase 2.5.bis.10 (#110) — Garde-fou mode invisible sur analyse PDF.**
            # L'analyse retourne TEXTE NARRATIF directement au PDF user-facing
            # + l'email envoyé via les automations. Le LLM peut halluciner un
            # nom de table denied dans cette narration (par exemple en faisant
            # référence à une source de données qu'il n'aurait pas dû connaître).
            # On **fail-closed** via ``DataAccessLeakDetectedError`` ; le caller
            # catche les exceptions LLM/Connection et retourne le fallback —
            # mais DataAccessLeakDetectedError n'est PAS dans le tuple catché
            # (lignes 144-146), donc propagation au caller du caller. Décision
            # assumée : un PDF user-facing avec un nom denied = inacceptable,
            # mieux vaut faire fail le rapport entier.
            if user_id is not None and analysis:
                from types import SimpleNamespace as _SimpleNamespace

                from app.services.data_access.error_messages import (
                    DataAccessLeakDetectedError,
                    assert_safe_llm_response,
                )

                _user_stub = _SimpleNamespace(id=user_id, role=None)
                _leak_msg = await assert_safe_llm_response(
                    analysis,
                    _user_stub,
                    context_label="report_analyzer.analyze_data",
                    strict_when_no_user=True,
                )
                if _leak_msg is not None:
                    logger.critical(
                        "report_analyzer: analyse LLM fuite un nom denied "
                        "user_id=%s analysis_len=%d",
                        user_id,
                        len(analysis),
                    )
                    raise DataAccessLeakDetectedError(_leak_msg)

            if analysis and len(analysis) > 50:
                logger.info("✅ Analyse LLM générée: %s caractères", len(analysis))
                return analysis

            # Réponse LLM trop courte → fallback
            logger.warning("Réponse LLM trop courte, utilisation fallback")
            return self._generate_fallback_analysis(trends, anomalies)

        except (LLMCallError, ConnectionError, asyncio.TimeoutError, ValueError, OSError) as e:
            logger.warning("⚠️ LLM indisponible, utilisation fallback: %s", e)
            return self._generate_fallback_analysis(trends, anomalies)

    def detect_trends(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Détecte les tendances dans les données

        Args:
            data: Données à analyser

        Returns:
            Liste de tendances détectées
        """
        trends = []

        if len(data) < 2:
            return trends

        # Analyser colonnes numériques pour détecter évolutions
        numeric_columns = self._get_numeric_columns(data)

        for col in numeric_columns:
            # Coercition via la SSoT (_coerce_numeric) — MÊME règle que la
            # détection : gère Decimal (MONEY Sage) + chaînes formatées
            # « 1 000 € ». Avant, le float(raw) brut jetait ces valeurs alors
            # que la colonne avait été détectée numérique (divergence #139).
            values = [num for row in data if (num := _coerce_numeric(row.get(col))) is not None]

            if len(values) < 2:
                continue

            # NB (caveats connus, hors scope de ce fix données-fausses, à
            # arbitrer côté produit — il n'y a ici aucune métadonnée de colonne
            # pour distinguer une métrique d'un identifiant) :
            #  (1) la « tendance » compare la 1re et la dernière valeur DANS
            #      L'ORDRE des lignes reçues ; sans tri temporel ce n'est pas une
            #      vraie évolution dans le temps (le gate >10% filtre l'essentiel).
            #  (2) une colonne d'identifiants numériques (année 2023/2024, n° de
            #      compte, code postal, id) passe la détection et peut générer du
            #      bruit — surtout dans le COMPTE d'anomalies de detect_anomalies.
            first_val = values[0]
            last_val = values[-1]

            if first_val != 0:
                variation_pct = ((last_val - first_val) / abs(first_val)) * 100

                # Déterminer type de tendance
                if abs(variation_pct) > 10:
                    trend_type = "hausse" if variation_pct > 0 else "baisse"
                    significance = "forte" if abs(variation_pct) > 30 else "modérée"

                    trends.append(
                        {
                            "column": col,
                            "type": trend_type,
                            "significance": significance,
                            "variation_pct": round(variation_pct, 1),
                            "first_value": first_val,
                            "last_value": last_val,
                        }
                    )

        logger.debug("🔍 %s tendances détectées", len(trends))
        return trends

    def detect_anomalies(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Détecte les anomalies dans les données

        Args:
            data: Données à analyser

        Returns:
            Liste d'anomalies détectées
        """
        anomalies = []

        if len(data) < 5:
            return anomalies

        # Analyser colonnes numériques
        numeric_columns = self._get_numeric_columns(data)

        for col in numeric_columns:
            # Fail-soft : valeur non-convertible (ex: "N/A", "NULL", "-",
            # "#DIV/0!") ignorée silencieusement, n'arrête pas le calcul
            # sur le reste de la colonne. Coercition via la SSoT _coerce_numeric
            # (single source of truth, axe 7 CLAUDE.md) — même règle que la
            # détection et detect_trends : gère Decimal (MONEY Sage) + chaînes
            # formatées, exclut bool, rejette NaN/inf.
            values = []
            for row in data:
                num = _coerce_numeric(row.get(col))
                if num is not None:
                    values.append(num)

            if len(values) < 5:
                continue

            # Calculer statistiques
            avg = sum(values) / len(values)
            variance = sum((x - avg) ** 2 for x in values) / len(values)
            std_dev = variance**0.5

            # Détecter valeurs aberrantes (>2 écart-types)
            for i, val in enumerate(values):
                if abs(val - avg) > 2 * std_dev:
                    anomalies.append(
                        {
                            "row_index": i,
                            "column": col,
                            "value": val,
                            "average": round(avg, 2),
                            "deviation": round(abs(val - avg) / std_dev, 1),
                        }
                    )

        logger.debug("⚠️ %s anomalies détectées", len(anomalies))
        return anomalies

    #: Nombre de lignes échantillonnées pour décider si une colonne est
    #: numérique. Borne le coût sur de très gros datasets tout en regardant
    #: bien au-delà de la 1re ligne (cf. bug du sampling row-0).
    _NUMERIC_DETECTION_SAMPLE = 200

    def _get_numeric_columns(self, data: List[Dict[str, Any]]) -> List[str]:
        """Identifie les colonnes numériques dans les données.

        Échantillonne plusieurs lignes (pas seulement ``data[0]``) : une colonne
        de montants dont la 1re ligne est ``None``/``"N/A"`` était auparavant
        classée non-numérique → AUCUNE analyse de tendance/anomalie dessus
        (données fausses silencieuses). On classe numérique si, parmi les
        valeurs non-nulles échantillonnées, la majorité se coerce en nombre via
        :func:`_coerce_numeric` — la MÊME règle que l'extraction (axe 7 : plus
        de divergence détection/extraction).
        """
        if not data:
            return []

        sample = data[: self._NUMERIC_DETECTION_SAMPLE]
        if len(data) > self._NUMERIC_DETECTION_SAMPLE:
            # Pas de cap silencieux (axe 21) : on trace que la décision
            # numérique s'appuie sur un échantillon, pas tout le dataset.
            logger.debug(
                "Détection colonnes numériques sur un échantillon de %s/%s lignes",
                self._NUMERIC_DETECTION_SAMPLE,
                len(data),
            )

        # Union des clés vues dans l'échantillon (défensif : listes de dicts
        # hétérogènes ; pour un résultat SQL les colonnes sont stables).
        keys: List[str] = []
        seen_keys = set()
        for row in sample:
            if not isinstance(row, dict):
                continue
            for key in row.keys():
                if key not in seen_keys:
                    seen_keys.add(key)
                    keys.append(key)

        numeric_cols: List[str] = []
        for key in keys:
            numeric_count = 0
            non_numeric_count = 0
            for row in sample:
                if not isinstance(row, dict):
                    continue
                raw = row.get(key)
                if raw is None:
                    continue  # NULL ignoré (ni pour ni contre)
                if _coerce_numeric(raw) is not None:
                    numeric_count += 1
                else:
                    non_numeric_count += 1
            # Numérique s'il existe ≥1 valeur numérique ET que la majorité des
            # valeurs non-nulles sont numériques (évite de classer une colonne
            # de réfs « ABC-12 » en numérique à cause de quelques « 42 »).
            if numeric_count > 0 and numeric_count >= non_numeric_count:
                numeric_cols.append(key)

        return numeric_cols

    def _build_analysis_prompt(
        self,
        template_name: str,
        num_rows: int,
        trends: List[Dict],
        anomalies: List[Dict],
        sample_data: List[Dict],
        context: Dict,
    ) -> str:
        """Construit le prompt pour le LLM"""

        prompt = f"""En tant qu'expert comptable, analysez ce rapport "{template_name}" de manière professionnelle.

DONNÉES:
- Nombre d'enregistrements: {num_rows}
- Période: {context.get('period', 'non spécifiée')}

TENDANCES DÉTECTÉES:
"""

        if trends:
            for trend in trends[:3]:  # Max 3 tendances
                prompt += f"- {trend['column']}: {trend['type']} {trend['significance']} de {trend['variation_pct']}%\n"
        else:
            prompt += "- Aucune tendance significative détectée\n"

        prompt += "\nANOMALIES:\n"

        if anomalies:
            prompt += f"- {len(anomalies)} valeur(s) aberrante(s) détectée(s)\n"
        else:
            prompt += "- Aucune anomalie détectée\n"

        # #18e (triage caps 2026-06-10) — tronquer PAR LIGNES, pas par chars :
        # l'ancien ``[:500]`` coupait le JSON en plein objet → le LLM analysait
        # un échantillon syntaxiquement corrompu (accolades orphelines,
        # dernière ligne amputée) sans le savoir. On retire des lignes
        # entières jusqu'à tenir le budget — JSON toujours valide, et la
        # réduction est ANNONCÉE dans le prompt.
        _sample_items = list(sample_data) if isinstance(sample_data, list) else [sample_data]
        _total_sample = len(_sample_items)
        sample_json = json.dumps(_sample_items, indent=2, ensure_ascii=False, default=str)
        while len(_sample_items) > 1 and len(sample_json) > 500:
            _sample_items.pop()
            sample_json = json.dumps(_sample_items, indent=2, ensure_ascii=False, default=str)
        if len(_sample_items) < _total_sample:
            sample_json += (
                f"\n(échantillon réduit à {len(_sample_items)} ligne(s) "
                f"sur {_total_sample} pour tenir le budget)"
            )

        prompt += f"""
ÉCHANTILLON DE DONNÉES:
{sample_json}

INSTRUCTIONS:
Rédigez une analyse professionnelle en 2-3 paragraphes (max 300 mots) incluant:
1. Synthèse des données clés
2. Interprétation des tendances principales
3. Points d'attention ou recommandations

Ton: Professionnel comptable, factuel, orienté action.
Format: Paragraphes fluides sans bullet points.
"""

        return prompt

    def _generate_fallback_analysis(self, trends: List[Dict], anomalies: List[Dict]) -> str:
        """Génère une analyse de secours en cas d'échec LLM"""

        analysis = "Analyse des données:\n\n"

        if trends:
            analysis += "Les données révèlent les tendances suivantes : "
            trend_texts = []
            for trend in trends[:3]:
                trend_texts.append(
                    f"{trend['column']} en {trend['type']} {trend['significance']} "
                    f"({trend['variation_pct']:+.1f}%)"
                )
            analysis += ", ".join(trend_texts) + ". "
        else:
            analysis += "Les données présentent une stabilité relative. "

        if anomalies:
            analysis += f"\n\n{len(anomalies)} anomalie(s) détectée(s) nécessitant une attention particulière. "
            analysis += "Une vérification manuelle est recommandée pour ces valeurs aberrantes."
        else:
            analysis += "\n\nAucune anomalie significative n'a été détectée dans les données."

        return analysis


class AnalysisFormatter:
    """
    Formate les analyses pour intégration dans les rapports
    """

    @staticmethod
    def format_for_pdf(analysis: str, title: str = "Analyse") -> Dict[str, Any]:
        """
        Formate l'analyse pour intégration PDF

        Args:
            analysis: Texte d'analyse
            title: Titre de la section

        Returns:
            Dictionnaire avec title, content, style
        """
        return {
            "title": title,
            "content": analysis,
            "style": {"font_size": 10, "italic": False, "color": "black", "alignment": "justify"},
        }

    @staticmethod
    def format_for_html(analysis: str, title: str = "Analyse") -> str:
        """
        Formate l'analyse en HTML

        Args:
            analysis: Texte d'analyse
            title: Titre de la section

        Returns:
            HTML formaté
        """
        paragraphs = analysis.split("\n\n")
        safe_title = html.escape(title)
        out = "<div class='report-analysis'>\n"
        out += f"  <h3>{safe_title}</h3>\n"

        for para in paragraphs:
            if para.strip():
                out += f"  <p>{html.escape(para.strip())}</p>\n"

        out += "</div>"

        return out

    @staticmethod
    def extract_key_insights(analysis: str) -> List[str]:
        """
        Extrait les insights clés de l'analyse

        Args:
            analysis: Texte d'analyse

        Returns:
            Liste d'insights (phrases importantes)
        """
        insights = []

        # Chercher phrases avec mots-clés importants
        keywords = [
            "recommand",
            "attention",
            "important",
            "significatif",
            "augmentation",
            "diminution",
            "anomalie",
            "tendance",
        ]

        sentences = analysis.replace("\n", " ").split(".")

        for sentence in sentences:
            sentence = sentence.strip()
            if any(keyword in sentence.lower() for keyword in keywords):
                if len(sentence) > 20:
                    insights.append(sentence + ".")

        return insights[:5]  # Max 5 insights
