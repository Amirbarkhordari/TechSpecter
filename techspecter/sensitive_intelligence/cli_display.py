"""Fingerprint CLI display filters for sensitive intelligence."""

from __future__ import annotations

import logging

from rich.console import Console

from techspecter.reporting.cli_format import format_metric_line
from techspecter.sensitive_intelligence.cli_render import (
    render_grouped_findings,
    render_section_header,
    render_summary_from_findings,
)
from techspecter.sensitive_intelligence.models import (
    FindingCategory,
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
    SeverityLevel,
)

logger = logging.getLogger(__name__)

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
        "stack-trace",
    },
)


def is_fingerprint_cli_relevant(finding: SensitiveFindingRecord) -> bool:
    """Return True when a finding should appear in the fingerprint CLI report."""
    if finding.category in {
        FindingCategory.SECRETS,
        FindingCategory.CREDENTIALS,
        FindingCategory.SENSITIVE_CONFIGURATION,
    }:
        return True
    if finding.finding_type in {FindingType.SECRET, FindingType.CREDENTIAL}:
        return True
    if finding.finding_type == FindingType.SENSITIVE_CONFIG:
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

    render_section_header(console)
    render_summary_from_findings(console, findings)
    render_grouped_findings(
        console,
        findings,
        detail_filter=_is_detail_candidate,
        max_detail_blocks=_MAX_EVIDENCE_BLOCKS,
        include_contact=False,
    )
    console.print("")


def render_security_summary_lines(findings: list[SensitiveFindingRecord]) -> list[str]:
    """Build concise security summary lines for the Security Summary section."""
    if not findings:
        return []
    lines = [
        format_metric_line("Secret & Sensitive Findings", len(findings), width=30),
        format_metric_line(
            "Critical",
            sum(1 for item in findings if item.severity == SeverityLevel.CRITICAL),
            width=30,
        ),
        format_metric_line(
            "High", sum(1 for item in findings if item.severity == SeverityLevel.HIGH), width=30
        ),
        format_metric_line(
            "Medium", sum(1 for item in findings if item.severity == SeverityLevel.MEDIUM), width=30
        ),
    ]
    by_category = {
        FindingCategory.SECRETS: sum(
            1 for item in findings if item.category == FindingCategory.SECRETS
        ),
        FindingCategory.CREDENTIALS: sum(
            1 for item in findings if item.category == FindingCategory.CREDENTIALS
        ),
        FindingCategory.SENSITIVE_CONFIGURATION: sum(
            1 for item in findings if item.category == FindingCategory.SENSITIVE_CONFIGURATION
        ),
    }
    for category, count in by_category.items():
        if count:
            label = category.value.replace("_", " ").title()
            lines.append(format_metric_line(label, count, width=30))
    return lines


def _is_detail_candidate(finding: SensitiveFindingRecord) -> bool:
    return finding.severity in {
        SeverityLevel.CRITICAL,
        SeverityLevel.HIGH,
        SeverityLevel.MEDIUM,
    }
