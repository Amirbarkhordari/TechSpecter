"""Sensitive intelligence console reporting."""

from __future__ import annotations

import logging
import shutil
from collections import defaultdict

from rich.console import Console
from rich.table import Table

from techspecter.reporting.models import (
    ReportSection,
    ReportSensitiveFinding,
    ReportSensitiveIntelligence,
)
from techspecter.sensitive_intelligence.evidence import (
    byte_offsets,
    evidence_count,
    line_numbers,
)
from techspecter.sensitive_intelligence.models import (
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
)

logger = logging.getLogger(__name__)

_SECTION_WIDTH = 50
_CATEGORY_ORDER = (
    FindingType.EMAIL,
    FindingType.PHONE,
    FindingType.URL,
    FindingType.DOMAIN,
    FindingType.IP,
    FindingType.UUID,
    FindingType.COMMENT,
    FindingType.SECRET,
    FindingType.CREDENTIAL,
)


def render_sensitive_intelligence(
    report: SensitiveIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render sensitive data intelligence summary and evidence."""
    if not report.findings and report.summary.assets_analyzed == 0:
        return

    console.print("\n" + "=" * _SECTION_WIDTH)
    console.print("[bold]Sensitive Data Intelligence[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")
    _render_summary(report, console=console)
    console.print()

    grouped = _group_findings(report.findings)
    for finding_type in _CATEGORY_ORDER:
        findings = grouped.get(finding_type, [])
        if not findings:
            continue
        console.print(f"[bold]{finding_type.value.title()} Findings[/bold]")
        console.print(_build_findings_table(findings))
        console.print()

    other_types = [
        finding_type
        for finding_type in grouped
        if finding_type not in _CATEGORY_ORDER and grouped[finding_type]
    ]
    for finding_type in sorted(other_types, key=lambda item: item.value):
        console.print(f"[bold]{finding_type.value.title()} Findings[/bold]")
        console.print(_build_findings_table(grouped[finding_type]))
        console.print()

    for finding in report.findings[:20]:
        _render_evidence_block(finding, console=console)
    if len(report.findings) > 20:
        console.print(f"[dim]... and {len(report.findings) - 20} more findings[/dim]\n")


def _render_summary(report: SensitiveIntelligenceReport, *, console: Console) -> None:
    summary = report.summary
    console.print("[bold]Summary[/bold]")
    console.print(f"  Emails: {summary.emails}")
    console.print(f"  Phones: {summary.phones}")
    console.print(f"  URLs: {summary.urls}")
    console.print(f"  Domains: {summary.domains}")
    console.print(f"  IPs: {summary.ips}")
    console.print(f"  UUIDs: {summary.uuids}")
    console.print(f"  Comments: {summary.comments}")
    console.print(f"  Secrets: {summary.secrets}")
    console.print(f"  Credentials: {summary.credentials}")
    console.print(f"  High Severity: {summary.high_severity}")
    console.print(f"  Medium Severity: {summary.medium_severity}")
    console.print(f"  Low Severity: {summary.low_severity}")


def _group_findings(
    findings: list[SensitiveFindingRecord],
) -> dict[FindingType, list[SensitiveFindingRecord]]:
    grouped: dict[FindingType, list[SensitiveFindingRecord]] = defaultdict(list)
    for finding in findings:
        grouped[finding.finding_type].append(finding)
    return grouped


def _build_findings_table(findings: list[SensitiveFindingRecord]) -> Table:
    width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(show_header=True, header_style="bold", expand=False, width=min(width, 120))
    table.add_column("Type", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_column("Severity", overflow="fold")
    table.add_column("Confidence", justify="right")
    table.add_column("Files", justify="right")
    table.add_column("Occurrences", justify="right")
    table.add_column("Detector", overflow="fold")

    for finding in findings:
        table.add_row(
            f"{finding.finding_type.value}/{finding.subtype}",
            finding.matched_value,
            finding.severity.value,
            f"{finding.confidence:.0f}%",
            str(len(finding.source_files)),
            str(finding.occurrence_count),
            finding.detector_name,
        )
    return table


def _render_evidence_block(finding: SensitiveFindingRecord, *, console: Console) -> None:
    console.print("-" * _SECTION_WIDTH)
    console.print(f"[bold]Type:[/bold] {finding.finding_type.value} / {finding.subtype}")
    console.print(f"[bold]Matched Value:[/bold] {finding.matched_value}")
    console.print(f"[bold]Matched Pattern:[/bold] {finding.matched_pattern}")
    console.print("[bold]Files:[/bold]")
    for filename in finding.source_files:
        console.print(f"  {filename}")
    lines = line_numbers(finding)
    if lines:
        console.print(f"[bold]Line Numbers:[/bold] {', '.join(str(item) for item in lines)}")
    offsets = byte_offsets(finding)
    if offsets:
        console.print(f"[bold]Offsets:[/bold] {', '.join(str(item) for item in offsets)}")
    console.print(f"[bold]Evidence Count:[/bold] {evidence_count(finding)}")
    console.print(f"[bold]Confidence:[/bold] {finding.confidence:.0f}%\n")


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
        title="Sensitive Data Intelligence",
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
