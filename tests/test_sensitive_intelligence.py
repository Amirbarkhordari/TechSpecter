"""Tests for Phase 7.3 sensitive data and secrets intelligence."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.asset_discovery.inventory import inventory_key
from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetRecord
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.detectors.base import DetectorMatch
from techspecter.sensitive_intelligence.detectors.comments import CommentDetector
from techspecter.sensitive_intelligence.detectors.credentials import CredentialDetector
from techspecter.sensitive_intelligence.detectors.emails import EmailDetector
from techspecter.sensitive_intelligence.detectors.secrets import SecretDetector
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import ConfidenceLevel, FindingType, SeverityLevel
from techspecter.sensitive_intelligence.report import build_report_sensitive_intelligence
from techspecter.sensitive_intelligence.sources import TextAssetSource, collect_text_assets
from techspecter.sensitive_intelligence.tracker import FindingTracker

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsWPU"
)


def test_email_detector_finds_addresses() -> None:
    """Verify email detector finds valid addresses."""
    detector = EmailDetector()
    matches = detector.detect("Contact support@example.com or admin@corp.local")
    assert matches
    assert all(match.finding_type == FindingType.EMAIL for match in matches)


def test_secret_detector_finds_jwt_and_redacts() -> None:
    """Verify JWT detection and redaction."""
    token = JWT_SAMPLE
    detector = SecretDetector()
    matches = detector.detect(f'const token = "{token}";')
    assert any(match.subtype == "jwt-token" for match in matches)
    assert all(
        "[redacted]" in match.matched_value or "jwt" in match.matched_value
        for match in matches
        if match.subtype == "jwt-token"
    )


def test_credential_detector_finds_mongodb_uri() -> None:
    """Verify MongoDB URI detection."""
    detector = CredentialDetector()
    content = 'const uri = "mongodb://user:pass@localhost:27017/app";'
    matches = detector.detect(content)
    assert any(match.subtype == "mongodb-uri" for match in matches)


def test_comment_detector_finds_todo_and_fixme() -> None:
    """Verify developer comment markers."""
    detector = CommentDetector()
    matches = detector.detect("// TODO: remove before release\n/* FIXME: broken */")
    subtypes = {match.subtype for match in matches}
    assert "todo-comment" in subtypes
    assert "fixme-comment" in subtypes


def test_finding_tracker_deduplicates_across_files() -> None:
    """Verify identical findings merge with multiple file references."""
    tracker = FindingTracker()
    detector = EmailDetector()
    match = DetectorMatch(
        finding_type=FindingType.EMAIL,
        subtype="email",
        matched_value="user@example.com",
        matched_pattern="email",
        confidence=85.0,
        severity=SeverityLevel.MEDIUM,
    )
    tracker.add_match(
        match,
        detector=detector,
        source=TextAssetSource(url="https://example.com/a.js", filename="a.js", content=""),
    )
    tracker.add_match(
        match,
        detector=detector,
        source=TextAssetSource(url="https://example.com/b.js", filename="b.js", content=""),
    )
    findings = tracker.all()
    assert len(findings) == 1
    assert len(findings[0].source_files) == 2
    assert findings[0].occurrence_count == 2


def test_confidence_level_mapping() -> None:
    """Verify confidence level bands."""
    detector = EmailDetector()
    assert detector.confidence_level(96) == ConfidenceLevel.VERY_HIGH
    assert detector.confidence_level(85) == ConfidenceLevel.HIGH
    assert detector.confidence_level(65) == ConfidenceLevel.MEDIUM
    assert detector.confidence_level(40) == ConfidenceLevel.LOW


def test_collect_text_assets_from_inventory() -> None:
    """Verify textual asset bodies are collected from inventory."""
    url = "https://example.com/app.js"
    key = inventory_key(url)
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        asset_inventory=AssetInventory(
            target_url="https://example.com/",
            assets=[
                AssetRecord(
                    asset_id="asset-1",
                    url=url,
                    filename="app.js",
                    extension=".js",
                    category=AssetCategory.JAVASCRIPT,
                    download_success=True,
                ),
            ],
            text_bodies={key: "support@example.com"},
        ),
    )
    assets = collect_text_assets(discovery)
    assert len(assets) == 1
    assert assets[0].asset_id == "asset-1"


def test_engine_builds_report() -> None:
    """Verify engine produces findings with asset attribution."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/config.js",
                filename="config.js",
                download_success=True,
                content=(
                    "export const cfg = { email: 'admin@example.com', "
                    f"token: '{JWT_SAMPLE}' }};"
                    "// TODO: rotate credentials"
                ),
            ),
        ],
    )
    report = SensitiveIntelligenceEngine().build(discovery)
    assert report.summary.assets_analyzed >= 1
    assert report.findings
    assert report.summary.total_findings >= 1


def test_report_models_for_export() -> None:
    """Verify export-ready report models."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",
                filename="app.js",
                download_success=True,
                content="const email = 'dev@example.com';",
            ),
        ],
    )
    report = SensitiveIntelligenceEngine().build(discovery)
    export_model = build_report_sensitive_intelligence(report)
    assert export_model.total_findings >= 1
    assert export_model.findings
