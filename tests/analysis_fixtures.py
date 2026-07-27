"""Shared fixtures for analysis framework tests."""

from __future__ import annotations

from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.fingerprinting.models import DetectionResult, Technology, TechnologyMatch
from techspecter.models.discovery import DiscoveryResult, Target


def sample_finding(**overrides: object) -> Finding:
    """Build a sample finding with optional overrides."""
    data = {
        "id": "finding-1",
        "analyzer": "test-analyzer",
        "category": FindingCategory.INFORMATION,
        "title": "Sample Finding",
        "description": "A sample passive analysis finding.",
        "severity": Severity.INFO,
        "confidence": 75.0,
        "evidence": [Evidence(url="https://example.com/app.js", snippet="example")],
        "location": "https://example.com/app.js",
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def sample_discovery_result() -> DiscoveryResult:
    """Return a minimal discovery result for analyzer tests."""
    return DiscoveryResult(
        target=Target(original_url="https://example.com", url="https://example.com/"),
        elapsed_ms=10.0,
    )


def sample_detection_result() -> DetectionResult:
    """Return a representative detection result."""
    return DetectionResult(
        target_url="https://example.com",
        matches=[
            TechnologyMatch(
                technology=Technology(
                    id="react",
                    name="React",
                    category="framework",
                ),
                version="18.2.0",
                confidence=90.0,
                filename="react.js",
                source_url="https://example.com/react.js",
            )
        ],
        scripts_analyzed=1,
        elapsed_ms=50.0,
    )
