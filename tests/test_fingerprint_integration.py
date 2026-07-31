"""Regression tests for Phase 7 fingerprint integration."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import respx
from rich.console import Console
from typer.testing import CliRunner

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetRecord
from techspecter.cli import app
from techspecter.fingerprinting.models import (
    DetectionResult,
    FingerprintAnalysisResult,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.providers.evidence import ProviderEvidenceAggregator
from techspecter.providers.models import ProviderEvidenceItem, ProviderMatch
from techspecter.reporting.fingerprint_report import render_fingerprint_report
from techspecter.reporting.service import ReportService
from techspecter.sensitive_intelligence.cli_display import (
    filter_fingerprint_cli_findings,
    is_fingerprint_cli_relevant,
)
from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingCategory,
    FindingType,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
    SensitiveIntelligenceSummary,
    SeverityLevel,
)
from techspecter.sensitive_intelligence.report import build_report_sensitive_intelligence
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.engine import TechnologyIntelligenceEngine
from techspecter.technology_intelligence.evidence import build_evidence_from_match
from techspecter.technology_intelligence.report import render_technology_evidence
from tests.http_fixtures import mock_well_known_http_requests

runner = CliRunner()


def _sample_inventory() -> AssetInventory:
    from techspecter.asset_discovery.models import AssetInventorySummary

    return AssetInventory(
        target_url="https://example.com/",
        summary=AssetInventorySummary(javascript=1, total_assets=1),
        assets=[
            AssetRecord(
                asset_id="asset-main",
                url="https://example.com/_next/static/chunks/main.js",
                relative_path="/_next/static/chunks/main.js",
                filename="main.js",
                extension=".js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
        ],
    )


def _sample_sensitive_report() -> SensitiveIntelligenceReport:
    return SensitiveIntelligenceReport(
        target_url="https://example.com/",
        summary=SensitiveIntelligenceSummary(
            emails=1,
            phones=1,
            domains=2,
            secrets=1,
            credentials=1,
            total_findings=6,
            assets_analyzed=1,
        ),
        findings=[
            SensitiveFindingRecord(
                finding_id="f-secret",
                finding_type=FindingType.SECRET,
                category=FindingCategory.SECRETS,
                subtype="jwt-token",
                severity=SeverityLevel.HIGH,
                confidence=94.0,
                confidence_level=ConfidenceLevel.HIGH,
                matched_value="jwt-token [redacted]",
                matched_pattern="jwt",
                detector_name="secret-detector",
                source_files=["main.js"],
            ),
            SensitiveFindingRecord(
                finding_id="f-cred",
                finding_type=FindingType.CREDENTIAL,
                category=FindingCategory.CREDENTIALS,
                subtype="mongodb-uri",
                severity=SeverityLevel.HIGH,
                confidence=95.0,
                confidence_level=ConfidenceLevel.HIGH,
                matched_value="mongodb-uri [redacted]",
                matched_pattern="mongodb",
                detector_name="credential-detector",
                source_files=["config.js"],
            ),
            SensitiveFindingRecord(
                finding_id="f-email",
                finding_type=FindingType.EMAIL,
                subtype="standard",
                severity=SeverityLevel.LOW,
                confidence=80.0,
                confidence_level=ConfidenceLevel.HIGH,
                matched_value="admin@example.com",
                matched_pattern=r"[a-z]+@[a-z]+\.[a-z]+",
                detector_name="email-detector",
                source_files=["main.js"],
            ),
            SensitiveFindingRecord(
                finding_id="f-phone",
                finding_type=FindingType.PHONE,
                subtype="us-phone",
                severity=SeverityLevel.LOW,
                confidence=70.0,
                confidence_level=ConfidenceLevel.MEDIUM,
                matched_value="+1-555-0100",
                matched_pattern="phone",
                detector_name="phone-detector",
                source_files=["main.js"],
            ),
            SensitiveFindingRecord(
                finding_id="f-domain",
                finding_type=FindingType.DOMAIN,
                subtype="domain",
                severity=SeverityLevel.LOW,
                confidence=65.0,
                confidence_level=ConfidenceLevel.MEDIUM,
                matched_value="example.com",
                matched_pattern="domain",
                detector_name="domain-detector",
                source_files=["main.js"],
            ),
        ],
    )


def _react_match(**updates: object) -> TechnologyMatch:
    data = {
        "technology": Technology(id="nextjs", name="Next.js", category="framework"),
        "version": "15.0.0",
        "confidence": 85.0,
        "source_url": "https://example.com/_next/static/chunks/main.js",
        "filename": "main.js",
        "matched_patterns": ["filename:next"],
        "evidence": [
            PatternEvidence(
                matcher="filename",
                pattern="next",
                weight=80.0,
                detail="main.js",
            ),
        ],
        "matched_resources": ["https://example.com/_next/static/chunks/main.js"],
    }
    data.update(updates)
    return TechnologyMatch(**data)  # type: ignore[arg-type]


def _analysis_result() -> FingerprintAnalysisResult:
    detection = DetectionResult(
        target_url="https://example.com/",
        matches=[_react_match()],
        scripts_analyzed=1,
        elapsed_ms=25.0,
    )
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        asset_inventory=_sample_inventory(),
        downloads=[
            DownloadResult(
                url="https://example.com/_next/static/chunks/main.js",
                filename="main.js",
                download_success=True,
                content='__NEXT_DATA__={"buildId":"abc"};',
            ),
        ],
    )
    intelligence = TechnologyIntelligenceEngine().build(discovery, detection)
    return FingerprintAnalysisResult(
        target_url="https://example.com/",
        discovery_elapsed_ms=100.0,
        detection=detection,
        elapsed_ms=125.0,
        asset_inventory=_sample_inventory(),
        sensitive_intelligence=_sample_sensitive_report(),
        technology_intelligence=intelligence,
    )


def test_fingerprint_report_section_order() -> None:
    """Verify unified report renders sections in the required order."""
    result = _analysis_result()
    report = ReportService().generate_report(result.detection, scan_duration_ms=result.elapsed_ms)
    console = Console(record=True, width=120)
    render_fingerprint_report(result, report, console=console)
    output = console.export_text()

    sections = [
        "Target Summary",
        "Asset Inventory",
        "Technology Detection",
        "Technology Intelligence",
        "Technology Evidence",
        "Secret & Sensitive Intelligence",
        "Security Summary",
    ]
    indices = [output.index(section) for section in sections]
    assert indices == sorted(indices)
    assert all(index >= 0 for index in indices)


def test_asset_inventory_report_includes_required_columns() -> None:
    """Verify asset inventory table includes attribution columns."""
    result = _analysis_result()
    report = ReportService().generate_report(result.detection)
    console = Console(record=True, width=200)
    render_fingerprint_report(result, report, console=console)
    output = console.export_text()
    assert "asset-main" in output
    assert "main.js" in output


def test_fingerprint_hides_domains_phones_and_emails_from_cli() -> None:
    """Verify informational sensitive findings are hidden from fingerprint CLI."""
    result = _analysis_result()
    report = ReportService().generate_report(result.detection)
    console = Console(record=True, width=140)
    render_fingerprint_report(result, report, console=console)
    output = console.export_text()

    assert "Secret & Sensitive Intelligence" in output
    assert "jwt-token" in output
    assert "mongodb-uri" in output
    assert "Domains:" not in output
    assert "Phones:" not in output
    assert "Emails:" not in output
    assert "admin@example.com" not in output
    assert "+1-555-0100" not in output
    assert "Domain Findings" not in output
    assert "Email Findings" not in output


def test_internal_sensitive_models_preserve_all_findings() -> None:
    """Verify export models still contain hidden CLI findings."""
    report = _sample_sensitive_report()
    export = build_report_sensitive_intelligence(report)
    assert export.total_findings == 6
    assert len(export.findings) == 5
    types = {item.finding_type for item in export.findings}
    assert "email" in types
    assert "phone" in types
    assert "domain" in types


def test_fingerprint_cli_filter_keeps_security_relevant_findings() -> None:
    """Verify CLI filter keeps secrets and credentials."""
    report = _sample_sensitive_report()
    filtered = filter_fingerprint_cli_findings(report.findings)
    assert len(filtered) == 2
    assert all(is_fingerprint_cli_relevant(item) for item in filtered)
    assert all(
        item.finding_type in {FindingType.SECRET, FindingType.CREDENTIAL} for item in filtered
    )


def test_technology_attribution_avoids_unknown_when_asset_known() -> None:
    """Verify technology evidence shows source asset details."""
    match = _react_match()
    attributor = AssetAttributor(inventory=_sample_inventory())
    records = build_evidence_from_match(match, attributor=attributor)
    assert records
    assert records[0].source_asset_id == "asset-main"
    assert records[0].source_file == "main.js"

    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        asset_inventory=_sample_inventory(),
    )
    detection = DetectionResult(target_url="https://example.com/", matches=[match])
    intelligence = TechnologyIntelligenceEngine().build(discovery, detection)
    console = Console(record=True, width=140)
    render_technology_evidence(intelligence, console=console)
    output = console.export_text()
    assert "(unknown)" not in output
    assert "asset-main" in output
    assert "main.js" in output


def test_evidence_resolution_strips_internal_labels() -> None:
    """Verify provider evidence no longer surfaces internal labels."""
    aggregator = ProviderEvidenceAggregator()
    _strings, structured = aggregator.aggregate(
        [
            ProviderMatch(
                technology_id="nextjs",
                name="Next.js",
                provider="techspecter",
                evidence_items=[
                    ProviderEvidenceItem(
                        source="techspecter",
                        category="javascript",
                        detail="filename:next",
                        location="https://example.com/_next/static/chunks/main.js",
                    ),
                ],
            ),
        ],
    )
    assert structured
    assert structured[0].pattern == "next"
    assert structured[0].detail == "next"


def test_provider_evidence_uses_meaningful_matched_text() -> None:
    """Verify merged pattern evidence resolves to readable matched text."""
    match = TechnologyMatch(
        technology=Technology(id="react", name="React", category="framework"),
        version="19.0.0",
        confidence=90.0,
        source_url="https://example.com/react.js",
        filename="react.js",
        evidence=[
            PatternEvidence(
                matcher="global",
                pattern="React.version",
                weight=90.0,
                detail="19.0.0",
            ),
        ],
    )
    records = build_evidence_from_match(match, attributor=AssetAttributor())
    assert records[0].matched_text == "19.0.0"
    assert records[0].matched_pattern == "React.version"


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_cli_renders_integrated_sections(mock_analyze: AsyncMock) -> None:
    """Verify fingerprint CLI uses the integrated report renderer."""
    mock_analyze.return_value = _analysis_result()
    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0
    assert "Asset Inventory" in result.stdout
    assert "Secret & Sensitive Intelligence" in result.stdout
    assert "Technology Evidence" in result.stdout
    assert "Domains:" not in result.stdout
    assert "Phones:" not in result.stdout


@respx.mock
def test_fingerprint_cli_end_to_end_with_inventory_and_attribution() -> None:
    """Verify end-to-end fingerprint output includes inventory and attribution."""
    html = '<html><head><script src="/react.js"></script></head></html>'
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html),
    )
    respx.get("https://example.com/react.js").mock(
        return_value=httpx.Response(
            200,
            text='React.version="18.2.0"; React.createElement("div");',
        ),
    )
    mock_well_known_http_requests()
    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0
    assert "Target Summary" in result.stdout
    assert "Technology Detection" in result.stdout
    assert "React" in result.stdout
