"""Fingerprint CLI display filters for sensitive intelligence."""

from __future__ import annotations

import logging
import shutil

from rich.console import Console
from rich.table import Table

from techspecter.sensitive_intelligence.evidence import line_numbers
from techspecter.sensitive_intelligence.models import (
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

_SECTION_WIDTH = 50
_MAX_EVIDENCE_BLOCKS = 10

_CLI_EXCLUDED_TYPES = frozenset(
    {
        FindingType.EMAIL,
        FindingType.PHONE,
        FindingType.URL,
        FindingType.DOMAIN,
        FindingType.HOSTNAME,
        FindingType.IP,
        FindingType.UUID,
        FindingType.USERNAME,
        FindingType.APPLICATION,
        FindingType.ENVIRONMENT,
    },
)

_SECURITY_COMMENT_SUBTYPES = frozenset(
    {
        "todo-comment",
        "fixme-comment",
        "hack-comment",
        "bug-comment",
        "debug-marker",
        "deprecated-marker",
    },
)


def is_fingerprint_cli_relevant(finding: SensitiveFindingRecord) -> bool:
    """Return True when a finding should appear in the fingerprint CLI report."""
    if finding.finding_type in {FindingType.SECRET, FindingType.CREDENTIAL}:
        return True
    if finding.finding_type == FindingType.COMMENT:
        return finding.subtype in _SECURITY_COMMENT_SUBTYPES
    return finding.finding_type not in _CLI_EXCLUDED_TYPES


def filter_fingerprint_cli_findings(
    findings: list[SensitiveFindingRecord],
) -> list[SensitiveFindingRecord]:
    """Filter sensitive findings for fingerprint CLI output."""
    return [item for item in findings if is_fingerprint_cli_relevant(item)]


def render_fingerprint_sensitive_intelligence(
    report: SensitiveIntelligenceReport,
    *,
    console: Console,
) -> None:
    """Render security-relevant sensitive intelligence for the fingerprint CLI."""
    findings = filter_fingerprint_cli_findings(report.findings)
    if not findings:
        return

    console.print("\n" + "=" * _SECTION_WIDTH)
    console.print("[bold]Sensitive Data Intelligence[/bold]")
    console.print("=" * _SECTION_WIDTH + "\n")
    _render_summary(findings, console=console)
    console.print()
    console.print(_build_findings_table(findings))
    console.print()

    detail_candidates = [
        item for item in findings if item.severity in {SeverityLevel.HIGH, SeverityLevel.MEDIUM}
    ]
    for finding in detail_candidates[:_MAX_EVIDENCE_BLOCKS]:
        _render_evidence_block(finding, console=console)
    remaining = len(detail_candidates) - _MAX_EVIDENCE_BLOCKS
    if remaining > 0:
        console.print(f"[dim]... and {remaining} more security findings[/dim]\n")


def _render_summary(findings: list[SensitiveFindingRecord], *, console: Console) -> None:
    secrets = sum(1 for item in findings if item.finding_type == FindingType.SECRET)
    credentials = sum(1 for item in findings if item.finding_type == FindingType.CREDENTIAL)
    comments = sum(1 for item in findings if item.finding_type == FindingType.COMMENT)
    high = sum(1 for item in findings if item.severity == SeverityLevel.HIGH)
    medium = sum(1 for item in findings if item.severity == SeverityLevel.MEDIUM)
    low = sum(1 for item in findings if item.severity == SeverityLevel.LOW)

    console.print("[bold]Summary[/bold]")
    console.print(f"  Secrets: {secrets}")
    console.print(f"  Credentials: {credentials}")
    console.print(f"  Security Markers: {comments}")
    console.print(f"  High Severity: {high}")
    console.print(f"  Medium Severity: {medium}")
    console.print(f"  Low Severity: {low}")


def _build_findings_table(findings: list[SensitiveFindingRecord]) -> Table:
    width = shutil.get_terminal_size(fallback=(120, 24)).columns
    table = Table(show_header=True, header_style="bold", expand=False, width=min(width, 120))
    table.add_column("Category", overflow="fold")
    table.add_column("Value", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", justify="right")
    table.add_column("Source", overflow="fold")

    for finding in findings:
        source = finding.source_files[0] if finding.source_files else "-"
        table.add_row(
            f"{finding.finding_type.value}/{finding.subtype}",
            finding.matched_value,
            finding.severity.value,
            f"{finding.confidence:.0f}%",
            source,
        )
    return table


def _render_evidence_block(finding: SensitiveFindingRecord, *, console: Console) -> None:
    console.print("-" * _SECTION_WIDTH)
    console.print(f"[bold]{finding.finding_type.value}[/bold] / {finding.subtype}")
    console.print(f"[bold]Value:[/bold] {finding.matched_value}")
    if finding.source_files:
        console.print(f"[bold]Source:[/bold] {finding.source_files[0]}")
    lines = line_numbers(finding)
    if lines:
        console.print(f"[bold]Lines:[/bold] {', '.join(str(item) for item in lines[:5])}")
    console.print(f"[bold]Confidence:[/bold] {finding.confidence:.0f}%\n")
