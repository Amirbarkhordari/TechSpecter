"""Tests for CLI report rendering improvements."""

from __future__ import annotations

from rich.console import Console

from techspecter.asset_discovery.download_status import build_failure_breakdown
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDownloadStatus,
    AssetDownloadSummary,
    AssetInventory,
    AssetInventorySummary,
    AssetRecord,
)
from techspecter.asset_discovery.report import render_fingerprint_asset_inventory
from techspecter.reporting.cli_format import format_metric_line, normalize_display_value
from techspecter.reporting.fingerprint_report import render_fingerprint_report
from techspecter.sensitive_intelligence.cli_display import (
    filter_fingerprint_cli_findings,
    render_fingerprint_sensitive_intelligence,
    render_security_summary_lines,
)
from techspecter.sensitive_intelligence.cli_render import render_summary_from_findings
from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingCategory,
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
    SensitiveIntelligenceSummary,
    SeverityLevel,
)
from tests.report_fixtures import sample_detection_result


def _finding(**updates: object) -> SensitiveFindingRecord:
    data = {
        "finding_id": "f-1",
        "finding_type": FindingType.SENSITIVE_CONFIG,
        "category": FindingCategory.SENSITIVE_CONFIGURATION,
        "subtype": "internal-ip",
        "severity": SeverityLevel.MEDIUM,
        "confidence": 80.0,
        "confidence_level": ConfidenceLevel.HIGH,
        "matched_value": "10.0.0.12",
        "matched_pattern": r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "detector_name": "rule-engine",
        "description": "Private RFC1918 IP address detected.",
        "recommendation": "Avoid exposing internal network addresses.",
        "evidence": 'const host = "10.0.0.12";',
        "source_files": ["config.js"],
        "relative_paths": ["/config.js"],
        "occurrence_count": 1,
    }
    data.update(updates)
    return SensitiveFindingRecord(**data)  # type: ignore[arg-type]


def test_format_metric_line_alignment() -> None:
    """Verify dot-aligned metric lines."""
    line = format_metric_line("Secrets", 3, width=24)
    assert "Secrets" in line
    assert line.endswith("3")
    assert "." in line


def test_normalize_display_value_truncates_long_values() -> None:
    """Verify long values are trimmed and truncated."""
    value = "  secret-" + ("x" * 200) + "\x00"
    rendered = normalize_display_value(value, max_length=100)
    assert len(rendered) <= 100
    assert rendered.endswith("...")
    assert "\x00" not in rendered


def test_failure_breakdown_groups_by_reason() -> None:
    """Verify failed downloads are grouped by reason."""
    assets = [
        AssetRecord(
            asset_id="a1",
            url="https://example.com/a.js",
            filename="a.js",
            category=AssetCategory.JAVASCRIPT,
            http_status=404,
            download_success=False,
            download_status=AssetDownloadStatus.FAILED,
        ),
        AssetRecord(
            asset_id="a2",
            url="https://example.com/b.js",
            filename="b.js",
            category=AssetCategory.JAVASCRIPT,
            http_status=404,
            download_success=False,
            download_status=AssetDownloadStatus.FAILED,
        ),
        AssetRecord(
            asset_id="a3",
            url="https://example.com/c.js",
            filename="c.js",
            category=AssetCategory.JAVASCRIPT,
            download_success=False,
            download_status=AssetDownloadStatus.TIMEOUT,
        ),
    ]
    breakdown = build_failure_breakdown(assets)
    assert breakdown["404"] == 2
    assert breakdown["Timeout"] == 1


def test_asset_inventory_summary_only_by_default() -> None:
    """Verify asset table is hidden unless show_assets is enabled."""
    inventory = AssetInventory(
        target_url="https://example.com/",
        summary=AssetInventorySummary(javascript=2, total_assets=2),
        download_summary=AssetDownloadSummary(downloaded=1, failed=1, total_attempted=2),
        assets=[
            AssetRecord(
                asset_id="a1",
                url="https://example.com/a.js",
                filename="a.js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
            AssetRecord(
                asset_id="a2",
                url="https://example.com/b.js",
                filename="b.js",
                category=AssetCategory.JAVASCRIPT,
                http_status=404,
                download_success=False,
                download_status=AssetDownloadStatus.FAILED,
            ),
        ],
    )
    console = Console(record=True, width=100)
    render_fingerprint_asset_inventory(inventory, console=console, show_assets=False)
    output = console.export_text()
    assert "Total Assets" in output
    assert "Download Summary" in output
    assert "Failed Downloads" in output
    assert "Asset ID" not in output

    console_full = Console(record=True, width=120)
    render_fingerprint_asset_inventory(inventory, console=console_full, show_assets=True)
    full_output = console_full.export_text()
    assert "Asset ID" in full_output


def test_sensitive_summary_uses_dot_alignment() -> None:
    """Verify sensitive intelligence summary formatting."""
    findings = [_finding(), _finding(finding_id="f-2", subtype="debug-endpoint")]
    console = Console(record=True, width=100)
    render_summary_from_findings(console, findings)
    output = console.export_text()
    assert "Sensitive Configuration" in output
    assert "Medium" in output
    assert "....." in output or "..." in output


def test_sensitive_findings_grouped_by_category() -> None:
    """Verify findings are grouped under category headings."""
    report = SensitiveIntelligenceReport(
        target_url="https://example.com/",
        summary=SensitiveIntelligenceSummary(
            sensitive_configuration=1,
            total_findings=1,
            assets_analyzed=1,
        ),
        findings=[_finding()],
    )
    console = Console(record=True, width=120)
    render_fingerprint_sensitive_intelligence(report, console=console)
    output = console.export_text()
    assert "Secret & Sensitive Intelligence" in output
    assert "Sensitive Configuration" in output
    assert "Detailed Findings" in output
    assert "Severity:" in output
    assert "Recommendation:" in output


def test_duplicate_findings_show_occurrence_count() -> None:
    """Verify merged duplicate findings display occurrence metadata."""
    finding = _finding(
        occurrence_count=3,
        source_files=["a.js", "b.js", "c.js"],
    )
    console = Console(record=True, width=120)
    from techspecter.sensitive_intelligence.cli_render import render_detail_block

    render_detail_block(finding, console=console)
    output = console.export_text()
    assert "Occurrence Count:" in output
    assert "3" in output
    assert "Affected Files:" in output


def test_security_summary_reflects_sensitive_findings() -> None:
    """Verify security summary lines are generated for sensitive findings."""
    findings = filter_fingerprint_cli_findings([_finding()])
    lines = render_security_summary_lines(findings)
    assert lines
    assert any("Secret & Sensitive Findings" in line for line in lines)


def test_fingerprint_security_summary_not_empty_when_sensitive_exists() -> None:
    """Verify Security Summary section reports sensitive findings."""
    from techspecter.fingerprinting.models import FingerprintAnalysisResult
    from techspecter.reporting.service import ReportService

    detection = sample_detection_result()
    report = ReportService().generate_report(detection)
    result = FingerprintAnalysisResult(
        target_url="https://example.com/",
        discovery_elapsed_ms=10.0,
        detection=detection,
        elapsed_ms=20.0,
        sensitive_intelligence=SensitiveIntelligenceReport(
            target_url="https://example.com/",
            summary=SensitiveIntelligenceSummary(
                sensitive_configuration=1,
                medium_severity=1,
                total_findings=1,
                assets_analyzed=1,
            ),
            findings=[_finding()],
        ),
    )
    console = Console(record=True, width=120)
    render_fingerprint_report(result, report, console=console)
    output = console.export_text()
    assert "Security Summary" in output
    assert "Sensitive Intelligence" in output
    assert "No passive security findings reported" not in output
