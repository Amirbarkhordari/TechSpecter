"""Tests for Phase 7.2 technology intelligence and evidence."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.asset_discovery.models import AssetCategory, AssetInventory, AssetRecord
from techspecter.fingerprinting.models import (
    DetectionResult,
    PatternEvidence,
    Technology,
    TechnologyMatch,
)
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.technology_intelligence.attribution import AssetAttributor
from techspecter.technology_intelligence.correlation import EvidenceCorrelationEngine
from techspecter.technology_intelligence.engine import TechnologyIntelligenceEngine
from techspecter.technology_intelligence.evidence import build_evidence_from_match
from techspecter.technology_intelligence.models import (
    IntelligenceEvidenceType,
    TechnologyEvidenceRecord,
)
from techspecter.technology_intelligence.report import (
    build_report_technology_intelligence,
    render_technology_intelligence,
)
from techspecter.technology_intelligence.tracker import EvidenceTracker


def _react_match(**updates: object) -> TechnologyMatch:
    data = {
        "technology": Technology(id="react", name="React", category="framework"),
        "version": "19.3.0",
        "confidence": 85.0,
        "source_url": "https://example.com/_next/static/chunks/framework.js",
        "filename": "framework.js",
        "matched_patterns": ["React.version"],
        "evidence": [
            PatternEvidence(
                matcher="global",
                pattern="React.version",
                weight=90.0,
                detail="19.3.0",
            ),
        ],
        "matched_resources": [
            "https://example.com/_next/static/chunks/framework.js",
            "https://example.com/_next/static/chunks/vendor.js",
        ],
        "detection_methods": ["global"],
    }
    data.update(updates)
    return TechnologyMatch(**data)  # type: ignore[arg-type]


def _sample_inventory() -> AssetInventory:
    return AssetInventory(
        target_url="https://example.com/",
        assets=[
            AssetRecord(
                asset_id="asset-framework",
                url="https://example.com/_next/static/chunks/framework.js",
                filename="framework.js",
                extension=".js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
            AssetRecord(
                asset_id="asset-vendor",
                url="https://example.com/_next/static/chunks/vendor.js",
                filename="vendor.js",
                extension=".js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
        ],
    )


def test_asset_attributor_resolves_asset_ids() -> None:
    """Verify URLs map to asset inventory IDs."""
    attributor = AssetAttributor(inventory=_sample_inventory())
    assert attributor.asset_id("https://example.com/_next/static/chunks/framework.js") == (
        "asset-framework"
    )
    assert attributor.source_file("https://example.com/_next/static/chunks/vendor.js") == (
        "vendor.js"
    )


def test_build_evidence_from_match_includes_asset_attribution() -> None:
    """Verify evidence records include source asset IDs."""
    match = _react_match()
    attributor = AssetAttributor(inventory=_sample_inventory())
    records = build_evidence_from_match(match, attributor=attributor)
    assert records
    assert any(item.source_asset_id == "asset-framework" for item in records)
    assert any(item.source_file == "framework.js" for item in records)
    assert records[0].evidence_type == IntelligenceEvidenceType.RUNTIME_CONSTANT


def test_evidence_tracker_deduplicates() -> None:
    """Verify duplicate evidence is not stored twice."""
    tracker = EvidenceTracker()
    record = TechnologyEvidenceRecord(
        evidence_id="e1",
        technology_name="React",
        category="framework",
        confidence=90.0,
        detector_name="test",
        evidence_type=IntelligenceEvidenceType.PATTERN_MATCH,
        matched_pattern="React.version",
        source_file="framework.js",
    )
    tracker.add(record)
    tracker.add(record.model_copy(update={"confidence": 95.0}))
    assert tracker.count() == 1
    assert tracker.all()[0].confidence == 95.0


def test_correlation_boosts_confidence_for_multiple_files() -> None:
    """Verify confidence increases with multiple asset evidence."""
    engine = EvidenceCorrelationEngine()
    match = _react_match()
    attributor = AssetAttributor(inventory=_sample_inventory())
    evidence = build_evidence_from_match(match, attributor=attributor)
    entry = engine.correlate(match, evidence)
    assert entry.confidence > match.confidence
    assert len(entry.found_in_files) >= 2
    assert entry.metadata.evidence_count >= 2


def test_correlation_resolves_nextjs_react_relationship() -> None:
    """Verify known technology relationships are inferred."""
    engine = EvidenceCorrelationEngine()
    react = TechnologyIntelligenceEngine().build(
        DiscoveryResult(
            target=Target(url="https://example.com/", original_url="https://example.com"),
            downloads=[
                DownloadResult(
                    url="https://example.com/react.js",
                    filename="react.js",
                    download_success=True,
                    content='React.version="19.0.0"',
                ),
            ],
        ),
        DetectionResult(
            target_url="https://example.com/",
            matches=[
                TechnologyMatch(
                    technology=Technology(id="nextjs", name="Next.js", category="framework"),
                    version="15.0.0",
                    confidence=80.0,
                    filename="build-manifest.js",
                ),
                _react_match(),
            ],
        ),
    )
    relationships = engine.resolve_relationships(react.technologies)
    assert any(
        rel.source_technology_id == "nextjs" and rel.target_technology_id == "react"
        for rel in relationships
    )


def test_engine_builds_intelligence_report() -> None:
    """Verify intelligence engine produces a complete report."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        asset_inventory=_sample_inventory(),
        downloads=[
            DownloadResult(
                url="https://example.com/_next/static/chunks/framework.js",
                filename="framework.js",
                download_success=True,
                content='React.version="19.3.0"; React.createElement("div");',
            ),
        ],
    )
    detection = DetectionResult(
        target_url="https://example.com/",
        matches=[_react_match()],
        scripts_analyzed=1,
    )
    report = TechnologyIntelligenceEngine().build(discovery, detection)
    assert report.technologies
    react = report.technologies[0]
    assert react.technology.id == "react"
    assert react.version == "19.3.0"
    assert react.evidence
    assert react.found_in_files
    assert report.total_evidence >= 1


def test_merge_entries_avoids_duplicate_technologies() -> None:
    """Verify duplicate technology entries are merged."""
    engine = EvidenceCorrelationEngine()
    match = _react_match()
    attributor = AssetAttributor(inventory=_sample_inventory())
    evidence = build_evidence_from_match(match, attributor=attributor)
    left = engine.correlate(match, evidence)
    right = engine.correlate(match, evidence)
    merged = engine.merge_entries([left, right])
    assert len(merged) == 1
    assert merged[0].metadata.evidence_count >= left.metadata.evidence_count


def test_report_models_for_export() -> None:
    """Verify export-ready report models are populated."""
    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/react.js",
                filename="react.js",
                download_success=True,
                content='React.version="19.3.0";',
            ),
        ],
    )
    detection = DetectionResult(
        target_url="https://example.com/",
        matches=[_react_match(source_url="https://example.com/react.js", filename="react.js")],
    )
    intelligence = TechnologyIntelligenceEngine().build(discovery, detection)
    export_model = build_report_technology_intelligence(intelligence)
    assert export_model.total_technologies == 1
    assert export_model.technologies[0].evidence
    assert export_model.technologies[0].evidence[0].matched_pattern == "React.version"


def test_render_technology_intelligence_smoke() -> None:
    """Verify console renderer runs without error."""
    from rich.console import Console

    discovery = DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/react.js",
                filename="react.js",
                download_success=True,
                content='React.version="19.3.0";',
            ),
        ],
    )
    detection = DetectionResult(
        target_url="https://example.com/",
        matches=[_react_match(source_url="https://example.com/react.js", filename="react.js")],
    )
    report = TechnologyIntelligenceEngine().build(discovery, detection)
    console = Console(record=True, width=120)
    render_technology_intelligence(report, console=console)
    output = console.export_text()
    assert "Technology Intelligence" in output
    assert "React" in output
