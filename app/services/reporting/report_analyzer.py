"""
Analyseur de rapports avec IA
Génération d'analyses textuelles professionnelles pour rapports comptables
"""

from typing import Dict, Any, Optional, List
import html
import json
import asyncio

from app.services.ai.llm_providers import get_llm_manager, LLMRequest
from app.services.ai.config_service import get_ai_config_service
from app.utils.logger import get_logger

logger = get_logger(__name__)


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
            values = [row.get(col) for row in data if row.get(col) is not None]

            if len(values) < 2:
                continue

            # Calculer variation
            try:
                first_val = float(values[0])
                last_val = float(values[-1])
            except (ValueError, TypeError):
                continue

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
            # sur le reste de la colonne. Aligné sur detect_trends:211
            # (single source of truth, axe 7 CLAUDE.md).
            values = []
            for row in data:
                raw = row.get(col)
                if raw is None:
                    continue
                try:
                    values.append(float(raw))
                except (ValueError, TypeError):
                    continue

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

    def _get_numeric_columns(self, data: List[Dict[str, Any]]) -> List[str]:
        """Identifie les colonnes numériques dans les données"""
        if not data:
            return []

        first_row = data[0]
        numeric_cols = []

        for key, value in first_row.items():
            if isinstance(value, (int, float)):
                numeric_cols.append(key)
            elif isinstance(value, str):
                # Tenter de convertir
                try:
                    float(value.replace(" ", "").replace("€", "").replace("%", ""))
                    numeric_cols.append(key)
                except ValueError:
                    pass

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

        prompt += f"""
ÉCHANTILLON DE DONNÉES:
{json.dumps(sample_data, indent=2, ensure_ascii=False, default=str)[:500]}

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
