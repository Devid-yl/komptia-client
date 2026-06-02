"""
Exécuteur de plans de rapports LLM.

Prend un ReportPlan (déjà validé et dé-anonymisé) + les vraies données de
chaque dataset, et construit le PDF multi-sections final via PDFGenerator.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List

from app.services.reporting.pdf_generator import PDFGenerator
from app.services.reporting.llm_report_planner import ReportPlan
from app.utils.logger import get_logger

logger = get_logger(__name__)


def build_pdf_from_plan(
    plan: ReportPlan,
    datasets_by_id: Dict[int, Dict[str, Any]],
    user: Any,
) -> bytes:
    """Execute a report plan and return the PDF bytes.

    Args:
        plan: Validated and de-anonymized report plan.
        datasets_by_id: Mapping dataset_id → {columns, rows (REAL), label, ...}
            Rows MUST be list of dicts at this point (already normalized).
        user: Current user (used for company_name).

    Returns:
        PDF file content as bytes.
    """
    # Build sections in the format PDFGenerator.generate_multi_section_report expects
    sections_for_pdf: List[Dict[str, Any]] = []
    for section in plan.sections:
        ds_id = section.get("dataset_id")
        ds = datasets_by_id.get(ds_id)
        if ds is None:
            # Shouldn't happen — the planner validated dataset_id already,
            # but be defensive so a stale plan doesn't crash execution.
            logger.warning(
                "Section '%s' skipped: dataset %s not in datasets_by_id",
                section.get("title"),
                ds_id,
            )
            continue

        real_rows = ds.get("rows") or []
        sections_for_pdf.append(
            {
                "title": section.get("title", "Section"),
                "description": section.get("description"),
                # `chart_data` feeds the charts WITHOUT rendering a raw table.
                # The user already has the classeur — the report is ANALYSIS,
                # not a data dump.
                "chart_data": real_rows,
                "charts": section.get("charts") or [],
                "commentary": section.get("commentary"),
            }
        )

    if not sections_for_pdf:
        raise RuntimeError("Aucune section exécutable (plan vide ou datasets manquants)")

    # Generate the PDF using the extended multi-section method.
    # Si l'utilisateur a une ``company.name``, on l'utilise (cas multi-tenant
    # par utilisateur si jamais ça arrivait). Sinon ``PDFGenerator``
    # tombera sur le branding global (``services.branding.get_company_name``)
    # — pas de hardcode "Cabinet Comptable" ici (axe 6 : généricité).
    user_company_name = getattr(getattr(user, "company", None), "name", None)
    generator = PDFGenerator(company_name=user_company_name)

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        generator.generate_multi_section_report(
            output_path=tmp_path,
            title=plan.title,
            introduction=plan.introduction,
            sections=sections_for_pdf,
        )
        return tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)
