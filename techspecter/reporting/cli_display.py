"""Shared CLI display helpers for fingerprint reporting."""

from __future__ import annotations

from techspecter.sensitive_intelligence.cli_display import (
    filter_fingerprint_cli_findings,
    is_fingerprint_cli_relevant,
)
from techspecter.sensitive_intelligence.models import SensitiveIntelligenceReport

__all__ = [
    "count_fingerprint_security_findings",
    "filter_fingerprint_cli_findings",
    "is_fingerprint_cli_relevant",
]


def count_fingerprint_security_findings(report: SensitiveIntelligenceReport | None) -> int:
    """Count security-relevant findings for fingerprint CLI summaries."""
    if report is None:
        return 0
    return len(filter_fingerprint_cli_findings(report.findings))
