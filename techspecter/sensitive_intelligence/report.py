"""Sensitive intelligence console reporting."""

from __future__ import annotations

import logging

from rich.console import Console

from techspecter.reporting.models import (
    ReportSection,
    ReportSensitiveFinding,
    ReportSensitiveIntelligence,
)
from techspecter.sensitive_intelligence.cli_render import (
    SECTION_TITLE,
    render_grouped_findings,
    render_section_header,
    render_summary_from_report_summary,
)
from techspecter.sensitive_intelligence.evidence import (
    byte_offsets,
    evidence_count,
    line_numbers,
)
from techspecter.sensitive_intelligence.models import (
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
)

logger = logging.getLogger(__name__)


def render_sensitive_intelligence(
    report: SensitiveIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render secret and sensitive intelligence summary and evidence."""
    if not report.findings and report.summary.assets_analyzed == 0:
        return

    render_section_header(console)
    render_summary_from_report_summary(console, report.summary)
    render_grouped_findings(
        console,
        report.findings,
        max_detail_blocks=20,
        include_contact=True,
    )
    console.print("")


def build_report_sensitive_intelligence(
    report: SensitiveIntelligenceReport,
) -> ReportSensitiveIntelligence:
    """Convert sensitive intelligence to export-ready report model."""
    return ReportSensitiveIntelligence(
        target_url=report.target_url,
        summary=report.summary.model_dump(mode="json"),
        total_findings=report.summary.total_findings,
        assets_analyzed=report.summary.assets_analyzed,
        findings=[_map_finding(item) for item in report.findings],
        elapsed_ms=report.elapsed_ms,
    )


def build_report_section(report: SensitiveIntelligenceReport) -> ReportSection:
    """Build export section for sensitive intelligence."""
    export_model = build_report_sensitive_intelligence(report)
    return ReportSection(
        id="sensitive-intelligence",
        title=SECTION_TITLE,
        summary=(
            f"{export_model.total_findings} findings across "
            f"{export_model.assets_analyzed} assets"
        ),
        metadata=export_model.model_dump(mode="json"),
    )


def _map_finding(finding: SensitiveFindingRecord) -> ReportSensitiveFinding:
    return ReportSensitiveFinding(
        finding_id=finding.finding_id,
        finding_type=finding.finding_type.value,
        subtype=finding.subtype,
        severity=finding.severity.value,
        confidence=finding.confidence,
        confidence_level=finding.confidence_level.value,
        matched_value=finding.matched_value,
        matched_pattern=finding.matched_pattern,
        detector_name=finding.detector_name,
        source_files=finding.source_files,
        occurrence_count=finding.occurrence_count,
        evidence_count=evidence_count(finding),
        line_numbers=line_numbers(finding),
        byte_offsets=byte_offsets(finding),
        locations=[item.model_dump(mode="json") for item in finding.locations],
        evidence=finding.evidence,
    )
