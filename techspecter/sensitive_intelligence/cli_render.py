"""Shared CLI rendering for Secret & Sensitive Intelligence."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable

from rich.console import Console

from techspecter.reporting.cli_format import (
    format_metric_line,
    normalize_display_value,
    print_context_snippet,
    print_label_value,
)
from techspecter.sensitive_intelligence.evidence import line_numbers
from techspecter.sensitive_intelligence.models import (
    FindingCategory,
    SensitiveFindingRecord,
    SensitiveIntelligenceSummary,
    SeverityLevel,
)

SECTION_WIDTH = 50
SECTION_TITLE = "Secret & Sensitive Intelligence"
CATEGORY_ORDER = (
    FindingCategory.SECRETS,
    FindingCategory.CREDENTIALS,
    FindingCategory.SENSITIVE_CONFIGURATION,
    FindingCategory.DEVELOPER_ARTIFACTS,
    FindingCategory.CONTACT_INFORMATION,
    FindingCategory.OTHER,
)
CATEGORY_LABELS = {
    FindingCategory.SECRETS: "Secrets",
    FindingCategory.CREDENTIALS: "Credentials",
    FindingCategory.SENSITIVE_CONFIGURATION: "Sensitive Configuration",
    FindingCategory.DEVELOPER_ARTIFACTS: "Developer Artifacts",
    FindingCategory.CONTACT_INFORMATION: "Contact Information",
    FindingCategory.OTHER: "Other Findings",
}


def render_section_header(console: Console) -> None:
    console.print("\n" + "=" * SECTION_WIDTH)
    console.print(f"[bold]{SECTION_TITLE}[/bold]")
    console.print("=" * SECTION_WIDTH)


def render_summary_from_counts(
    console: Console,
    *,
    secrets: int,
    credentials: int,
    sensitive_configuration: int,
    developer_artifacts: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    informational: int,
) -> None:
    """Render dot-aligned category and severity summary."""
    console.print("")
    console.print(format_metric_line("Secrets", secrets, width=30))
    console.print(format_metric_line("Credentials", credentials, width=30))
    console.print(format_metric_line("Sensitive Configuration", sensitive_configuration, width=30))
    console.print(format_metric_line("Developer Artifacts", developer_artifacts, width=30))
    console.print("")
    console.print(format_metric_line("Critical", critical, width=30))
    console.print(format_metric_line("High", high, width=30))
    console.print(format_metric_line("Medium", medium, width=30))
    console.print(format_metric_line("Low", low, width=30))
    console.print(format_metric_line("Informational", informational, width=30))


def render_summary_from_report_summary(
    console: Console, summary: SensitiveIntelligenceSummary
) -> None:
    render_summary_from_counts(
        console,
        secrets=summary.secrets,
        credentials=summary.credentials,
        sensitive_configuration=summary.sensitive_configuration,
        developer_artifacts=summary.developer_artifacts,
        critical=summary.critical_severity,
        high=summary.high_severity,
        medium=summary.medium_severity,
        low=summary.low_severity,
        informational=summary.informational_severity,
    )


def render_summary_from_findings(console: Console, findings: list[SensitiveFindingRecord]) -> None:
    render_summary_from_counts(
        console,
        secrets=sum(1 for item in findings if item.category == FindingCategory.SECRETS),
        credentials=sum(1 for item in findings if item.category == FindingCategory.CREDENTIALS),
        sensitive_configuration=sum(
            1 for item in findings if item.category == FindingCategory.SENSITIVE_CONFIGURATION
        ),
        developer_artifacts=sum(
            1 for item in findings if item.category == FindingCategory.DEVELOPER_ARTIFACTS
        ),
        critical=sum(1 for item in findings if item.severity == SeverityLevel.CRITICAL),
        high=sum(1 for item in findings if item.severity == SeverityLevel.HIGH),
        medium=sum(1 for item in findings if item.severity == SeverityLevel.MEDIUM),
        low=sum(1 for item in findings if item.severity == SeverityLevel.LOW),
        informational=sum(1 for item in findings if item.severity == SeverityLevel.INFORMATIONAL),
    )


def group_findings_by_category(
    findings: list[SensitiveFindingRecord],
) -> dict[FindingCategory, list[SensitiveFindingRecord]]:
    grouped: dict[FindingCategory, list[SensitiveFindingRecord]] = defaultdict(list)
    for finding in findings:
        grouped[finding.category].append(finding)
    return grouped


def render_grouped_findings(
    console: Console,
    findings: list[SensitiveFindingRecord],
    *,
    detail_filter: Callable[[SensitiveFindingRecord], bool] | None = None,
    max_detail_blocks: int = 10,
    include_contact: bool = True,
) -> None:
    """Render findings grouped by category with optional detail blocks."""
    grouped = group_findings_by_category(findings)
    categories = list(CATEGORY_ORDER)
    if not include_contact:
        categories = [item for item in categories if item != FindingCategory.CONTACT_INFORMATION]

    for category in categories:
        category_findings = grouped.get(category, [])
        if not category_findings:
            continue
        label = CATEGORY_LABELS.get(category, category.value.title())
        console.print(f"\n[bold]{label}[/bold]")
        console.print("-" * SECTION_WIDTH)
        for finding in category_findings:
            _render_compact_finding(finding, console=console)

    detail_candidates = (
        findings if detail_filter is None else [item for item in findings if detail_filter(item)]
    )
    if not detail_candidates:
        return

    console.print("\n[bold]Detailed Findings[/bold]")
    console.print("-" * SECTION_WIDTH)
    for finding in detail_candidates[:max_detail_blocks]:
        render_detail_block(finding, console=console)
    remaining = len(detail_candidates) - max_detail_blocks
    if remaining > 0:
        console.print(f"[dim]... and {remaining} more detailed findings[/dim]")


def _render_compact_finding(finding: SensitiveFindingRecord, *, console: Console) -> None:
    source = finding.source_files[0] if finding.source_files else "-"
    value = normalize_display_value(finding.matched_value)
    console.print(
        f"  [{finding.severity.value}] {finding.subtype} "
        f"({finding.confidence:.0f}%) — {value} — {source}"
    )
    if finding.occurrence_count > 1:
        files = ", ".join(finding.source_files[:3])
        extra = len(finding.source_files) - 3
        suffix = f" +{extra} more" if extra > 0 else ""
        console.print(f"    Occurrences: {finding.occurrence_count} | Files: {files}{suffix}")


def render_detail_block(finding: SensitiveFindingRecord, *, console: Console) -> None:
    """Render a full detailed finding block."""
    console.print("")
    print_label_value(console, "Severity:", finding.severity.value.title())
    print_label_value(console, "Confidence:", f"{finding.confidence:.0f}%")
    print_label_value(
        console, "Category:", CATEGORY_LABELS.get(finding.category, finding.category.value)
    )
    print_label_value(console, "What:", finding.description or finding.subtype)
    source = finding.source_files[0] if finding.source_files else "-"
    rel_path = finding.relative_paths[0] if finding.relative_paths else source
    print_label_value(console, "Where:", rel_path)
    print_label_value(console, "Source File:", source)
    if finding.locations and finding.locations[0].asset_id:
        print_label_value(console, "Asset ID:", finding.locations[0].asset_id)
    lines = line_numbers(finding)
    if lines:
        print_label_value(console, "Line Number:", str(lines[0]))
    print_label_value(console, "Matched Value:", finding.matched_value)
    if finding.evidence:
        print_context_snippet(console, finding.evidence, finding.matched_value)
    if finding.recommendation:
        print_label_value(console, "Recommendation:", finding.recommendation)
    if finding.occurrence_count > 1:
        print_label_value(console, "Occurrence Count:", str(finding.occurrence_count))
        print_label_value(console, "Affected Files:", ", ".join(finding.source_files[:5]))
    console.print("-" * SECTION_WIDTH)
