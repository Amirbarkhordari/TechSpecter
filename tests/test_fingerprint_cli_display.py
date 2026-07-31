"""Tests for fingerprint CLI sensitive display filters."""

from __future__ import annotations

from techspecter.sensitive_intelligence.cli_display import (
    filter_fingerprint_cli_findings,
    is_fingerprint_cli_relevant,
)
from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingType,
    SensitiveFindingRecord,
    SeverityLevel,
)


def _finding(
    finding_type: FindingType,
    subtype: str,
    *,
    severity: SeverityLevel = SeverityLevel.LOW,
) -> SensitiveFindingRecord:
    return SensitiveFindingRecord(
        finding_id=f"{finding_type.value}-{subtype}",
        finding_type=finding_type,
        subtype=subtype,
        severity=severity,
        confidence=80.0,
        confidence_level=ConfidenceLevel.HIGH,
        matched_value="sample",
        matched_pattern="pattern",
        detector_name="test-detector",
        source_files=["main.js"],
    )


def test_cli_filter_excludes_domains_and_phones() -> None:
    """Verify domain and phone findings are excluded from fingerprint CLI."""
    findings = [
        _finding(FindingType.DOMAIN, "domain"),
        _finding(FindingType.PHONE, "us-phone"),
        _finding(FindingType.SECRET, "jwt-token", severity=SeverityLevel.HIGH),
    ]
    filtered = filter_fingerprint_cli_findings(findings)
    assert len(filtered) == 1
    assert filtered[0].finding_type == FindingType.SECRET


def test_cli_filter_includes_security_comments() -> None:
    """Verify TODO and debug comments remain visible in fingerprint CLI."""
    assert is_fingerprint_cli_relevant(_finding(FindingType.COMMENT, "todo-comment"))
    assert is_fingerprint_cli_relevant(_finding(FindingType.COMMENT, "debug-marker"))
    assert not is_fingerprint_cli_relevant(_finding(FindingType.COMMENT, "note-comment"))
