"""Integration tests for detection and sensitive finding propagation."""

from __future__ import annotations

from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer
from techspecter.fingerprinting.pipeline.analysis_contexts import iter_analysis_contexts
from techspecter.fingerprinting.pipeline.detection_pipeline import FingerprintPipeline
from techspecter.fingerprinting.pipeline.result_merger import merge_detection_results
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetInventory,
    AssetInventorySummary,
    AssetRecord,
)
from techspecter.models.discovery import DiscoveryResult, DownloadResult, Target
from techspecter.sensitive_intelligence.cli_display import filter_fingerprint_cli_findings
from techspecter.sensitive_intelligence.engine import SensitiveIntelligenceEngine
from techspecter.sensitive_intelligence.models import (
    ConfidenceLevel,
    FindingCategory,
    FindingType,
    SeverityLevel,
    SensitiveFindingRecord,
    SensitiveIntelligenceReport,
)
from techspecter.reporting.fingerprint_report import render_fingerprint_report
from techspecter.reporting.service import ReportService
from techspecter.fingerprinting.models import FingerprintAnalysisResult, DetectionResult
from rich.console import Console
import io


def _discovery_with_inventory(*, js_content: str, css_content: str, generic_js: str) -> DiscoveryResult:
    inventory = AssetInventory(
        target_url="https://example.com/",
        assets=[
            AssetRecord(
                asset_id="js1",
                url="https://example.com/static/main.js",
                filename="main.js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
            AssetRecord(
                asset_id="css1",
                url="https://example.com/static/app.css",
                filename="app.css",
                category=AssetCategory.CSS,
                download_success=True,
            ),
            AssetRecord(
                asset_id="noise",
                url="https://example.com/static/chunk.js",
                filename="chunk.js",
                category=AssetCategory.JAVASCRIPT,
                download_success=True,
            ),
        ],
        summary=AssetInventorySummary(total_assets=3, javascript=2, css=1),
        text_bodies={
            "https://example.com/static/main.js": js_content,
            "https://example.com/static/app.css": css_content,
            "https://example.com/static/chunk.js": generic_js,
        },
    )
    return DiscoveryResult(
        target=Target(url="https://example.com/", original_url="https://example.com"),
        downloads=[
            DownloadResult(
                url="https://example.com/static/main.js",
                filename="main.js",
                content=js_content,
                download_success=True,
                status_code=200,
                content_type="application/javascript",
                content_length=len(js_content),
                download_duration_ms=1.0,
            ),
        ],
        inline_scripts=[],
        asset_inventory=inventory,
    )


def test_analysis_contexts_include_asset_inventory_text_bodies() -> None:
    """Fingerprint analysis must include asset inventory textual assets."""
    discovery = _discovery_with_inventory(
        js_content='React.createElement("div");',
        css_content="@tailwind base;",
        generic_js="var ng = true;",
    )
    contexts = iter_analysis_contexts(discovery)
    filenames = {item.filename for item in contexts}
    assert "main.js" in filenames
    assert "app.css" in filenames
    assert "chunk.js" in filenames


def test_inventory_assets_produce_confirmed_technologies() -> None:
    """Technologies referenced in inventory assets must reach confirmed output."""
    discovery = _discovery_with_inventory(
        js_content='React.version="19.0.0"; React.createElement("div");',
        css_content='@tailwind utilities;\n[data-bs-toggle="modal"]{}',
        generic_js="var Bootstrap = 'text'; var ng = true;",
    )
    pipeline = FingerprintPipeline()
    result = pipeline.run(discovery)
    confirmed = {item.technology.id for item in result.matches}
    assert "react" in confirmed
    assert "angular" not in confirmed

    raw = pipeline.run(discovery, apply_quality_gate=False)
    raw_ids = {item.technology.id for item in raw.matches}
    assert "tailwindcss" in raw_ids, "Inventory CSS must be analyzed for framework markers"
    assert "bootstrap" not in confirmed, "Generic bootstrap string must not confirm technology"


def test_unified_service_merges_evidence_and_provider_detection() -> None:
    """Collected JavaScript evidence must contribute to confirmed technologies."""
    discovery = _discovery_with_inventory(
        js_content='ReactDOM.createRoot(document.getElementById("root")); React.version="19.0.0";',
        css_content="body{}",
        generic_js="console.log('hello');",
    )
    from techspecter.fingerprinting.compatibility import FingerprintCompatibilityLayer

    layer = FingerprintCompatibilityLayer()
    evidence = layer.collect_evidence(discovery)
    legacy = layer.detect(discovery)
    explainable = layer.detect_from_evidence(evidence)
    merged = merge_detection_results(
        legacy.model_copy(update={"matches": legacy.matches}),
        explainable.detection,
        apply_quality_gate=True,
    )
    assert evidence.summary.total_items > 0
    assert any(item.technology.id == "react" for item in merged.matches)


def test_sensitive_findings_reach_fingerprint_cli_renderer() -> None:
    """Security-relevant sensitive findings must appear in fingerprint CLI output."""
    finding = SensitiveFindingRecord(
        finding_id="test-1",
        finding_type=FindingType.SECRET,
        subtype="api-key",
        category=FindingCategory.SECRETS,
        severity=SeverityLevel.HIGH,
        confidence=90.0,
        confidence_level=ConfidenceLevel.HIGH,
        matched_value="api_key=[REDACTED]",
        matched_pattern="api[_-]?key",
        detector_name="rule-engine",
        source_files=["config.js"],
    )
    report = SensitiveIntelligenceReport(
        target_url="https://example.com/",
        findings=[finding],
    )
    assert filter_fingerprint_cli_findings(report.findings)

    analysis = FingerprintAnalysisResult(
        target_url="https://example.com/",
        detection=DetectionResult(target_url="https://example.com/", matches=[]),
        sensitive_intelligence=report,
    )
    console = Console(file=io.StringIO(), width=120, force_terminal=True)
    render_fingerprint_report(
        analysis,
        ReportService().generate_report(analysis.detection),
        console=console,
    )
    output = console.file.getvalue()
    assert "Secret" in output or "Sensitive" in output
    assert "api-key" in output or "api_key" in output.lower()


def test_sensitive_engine_findings_survive_to_filtered_cli_set() -> None:
    """Sensitive engine output must remain available to CLI filtering."""
    discovery = _discovery_with_inventory(
        js_content='const config = { apiKey: "sk-live-abcdefghijklmnopqrstuvwxyz123456" };',
        css_content="body{}",
        generic_js="https://example.com/contact",
    )
    sensitive = SensitiveIntelligenceEngine().build(discovery)
    assert sensitive.summary.total_findings > 0
    security_relevant = filter_fingerprint_cli_findings(sensitive.findings)
    assert security_relevant, "Expected at least one security-relevant finding in fixture"


def test_merge_detection_results_applies_single_quality_gate() -> None:
    """Merged detections should apply one quality gate without dropping attributed evidence."""
    discovery = _discovery_with_inventory(
        js_content='React.createElement("div"); reconcilerVersion:"19.0.0";',
        css_content="body{}",
        generic_js="console.log('x');",
    )
    legacy = FingerprintPipeline().run(discovery, apply_quality_gate=False)
    merged = merge_detection_results(legacy, apply_quality_gate=True)
    assert any(item.technology.id == "react" for item in merged.matches)
