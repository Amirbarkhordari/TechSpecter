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
from techspecter.sensitive_intelligence.display_utils import escape_rich_markup, print_label_value
from techspecter.sensitive_intelligence.evidence import (
    byte_offsets,
    evidence_count,
    line_numbers,
)
from techspecter.sensitive_intelligence.models import (
    FindingCategory,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
)

logger = logging.getLogger(__name__)

_SECTION_WIDTH = 50
_SECTION_TITLE = "Secret & Sensitive Intelligence"
_CATEGORY_ORDER = (
    FindingCategory.SECRETS,
    FindingCategory.CREDENTIALS,
    FindingCategory.SENSITIVE_CONFIGURATION,
    FindingCategory.DEVELOPER_ARTIFACTS,
    FindingCategory.CONTACT_INFORMATION,
    FindingCategory.OTHER,
)
_MAX_DETAIL_BLOCKS = 20


def render_sensitive_intelligence(
    report: SensitiveIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render secret and sensitive intelligence summary and evidence."""
    if not report.findings and report.summary.assets_analyzed == 0:
        return

    console.print("\n" + "=" * _SECTION_WIDTH)
    console.print(f"[bold]{_SECTION_TITLE}[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")
    _render_category_summary(report, console=console)
    console.print()

    grouped = _group_by_category(report.findings)
    for category in _CATEGORY_ORDER:
        findings = grouped.get(category, [])
        if not findings:
            continue
        console.print(f"[bold]{_category_label(category)}[/bold]")
        console.print(_build_findings_table(findings))
        console.print()

    for finding in report.findings[:_MAX_DETAIL_BLOCKS]:
        _render_detail_block(finding, console=console)
    if len(report.findings) > _MAX_DETAIL_BLOCKS:
        console.print(
            f"[dim]... and {len(report.findings) - _MAX_DETAIL_BLOCKS} more findings[/dim]\n"
        )


def _render_category_summary(report: SensitiveIntelligenceReport, *, console: Console) -> None:
    summary = report.summary
    console.print("[bold]Summary[/bold]")
    console.print(f"  Secrets: {summary.secrets}")
    console.print(f"  Credentials: {summary.credentials}")
    console.print(f"  Sensitive Configuration: {summary.sensitive_configuration}")
    console.print(f"  Developer Artifacts: {summary.developer_artifacts}")
    console.print(f"  Critical: {summary.critical_severity}")
    console.print(f"  High: {summary.high_severity}")
    console.print(f"  Medium: {summary.medium_severity}")
    console.print(f"  Low: {summary.low_severity}")
    console.print(f"  Informational: {summary.informational_severity}")
    console.print(f"  Assets Analyzed: {summary.assets_analyzed}")


def _group_by_category(
    findings: list[SensitiveFindingRecord],
) -> dict[FindingCategory, list[SensitiveFindingRecord]]:
    grouped: dict[FindingCategory, list[SensitiveFindingRecord]] = defaultdict(list)
    for finding in findings:
        grouped[finding.category].append(finding)
    return grouped


def _build_findings_table(findings: list[SensitiveFindingRecord]) -> Table:
    width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(show_header=True, header_style="bold", expand=False, width=min(width, 120))
    table.add_column("Type", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_column("Severity", overflow="fold")
    table.add_column("Confidence", justify="right")
    table.add_column("Source", overflow="fold")
    table.add_column("Count", justify="right")

    for finding in findings:
        source = finding.source_files[0] if finding.source_files else "-"
        table.add_row(
            escape_rich_markup(f"{finding.subtype}"),
            escape_rich_markup(finding.matched_value),
            finding.severity.value,
            f"{finding.confidence:.0f}%",
            escape_rich_markup(source),
            str(finding.occurrence_count),
        )
    return table


def _render_detail_block(finding: SensitiveFindingRecord, *, console: Console) -> None:
    console.print("-" * _SECTION_WIDTH)
    print_label_value(console, "What:", finding.description or finding.subtype)
    source = finding.source_files[0] if finding.source_files else "-"
    rel_path = finding.relative_paths[0] if finding.relative_paths else source
    print_label_value(console, "Where:", f"{source} ({rel_path})")
    if finding.locations and finding.locations[0].asset_id:
        print_label_value(console, "Asset ID:", finding.locations[0].asset_id)
    print_label_value(console, "Why it matters:", finding.description or finding.subtype)
    print_label_value(console, "Matched Pattern:", finding.matched_pattern)
    print_label_value(console, "Matched Value:", finding.matched_value)
    if finding.evidence:
        print_label_value(console, "Evidence:", finding.evidence[:240])
    if finding.recommendation:
        print_label_value(console, "Recommendation:", finding.recommendation)
    lines = line_numbers(finding)
    if lines:
        console.print(f"[bold]Line Numbers:[/bold] {', '.join(str(item) for item in lines[:5])}")
    offsets = byte_offsets(finding)
    if offsets:
        console.print(f"[bold]Offsets:[/bold] {', '.join(str(item) for item in offsets[:5])}")
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
        title=_SECTION_TITLE,
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


def _category_label(category: FindingCategory) -> str:
    labels = {
        FindingCategory.SECRETS: "Secrets",
        FindingCategory.CREDENTIALS: "Credentials",
        FindingCategory.SENSITIVE_CONFIGURATION: "Sensitive Configuration",
        FindingCategory.DEVELOPER_ARTIFACTS: "Developer Artifacts",
        FindingCategory.CONTACT_INFORMATION: "Contact Information",
        FindingCategory.OTHER: "Other Findings",
    }
    return labels.get(category, category.value.title())
