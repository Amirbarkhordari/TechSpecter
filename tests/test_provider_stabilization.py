"""Tests for Phase 5.5 provider stabilization."""

from __future__ import annotations

from techspecter.fingerprinting.models import UNKNOWN_VERSION
from techspecter.providers.evidence import ProviderEvidenceAggregator
from techspecter.providers.health import format_health_report
from techspecter.providers.manager import ProviderManager
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import (
    ProviderDetectionResult,
    ProviderEvidenceItem,
    ProviderHealthState,
    ProviderHealthStatus,
    ProviderMatch,
)
from techspecter.providers.naming import normalize_technology_name
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.validation import ProviderOutputValidator
from techspecter.providers.version_metadata import ProviderVersionMetadataBuilder


def _match(**kwargs: object) -> ProviderMatch:
    defaults = {
        "technology_id": "react",
        "name": "React",
        "category": "frontend-frameworks",
        "version": "19.1.0",
        "confidence": 85.0,
        "evidence": ["runtime:ReactDOM.createRoot"],
        "evidence_items": [
            ProviderEvidenceItem(
                source="techspecter",
                category="runtime",
                detail="ReactDOM.createRoot",
                location="https://example.com/framework.js",
                detection_method="fingerprint-engine",
            )
        ],
        "metadata": {
            "filename": "framework.js",
            "source_url": "https://example.com/framework.js",
        },
        "provider": "techspecter",
        "detection_method": "fingerprint-engine",
    }
    defaults.update(kwargs)
    return ProviderMatch(**defaults)  # type: ignore[arg-type]


def test_normalize_technology_name_aliases() -> None:
    """Technology names should normalize consistently across providers."""
    assert normalize_technology_name("ReactJS") == "React"
    assert normalize_technology_name("AngularJS") == "Angular"
    assert normalize_technology_name("Vue.js") == "Vue"


def test_provider_output_validator_rejects_invalid_match() -> None:
    """Malformed provider matches must be rejected before merge."""
    validator = ProviderOutputValidator()
    invalid = ProviderMatch.model_construct(
        technology_id="react",
        name="React",
        confidence=150.0,
        provider="wappalyzer",
        detection_method="test",
    )
    empty = ProviderMatch.model_construct(
        technology_id="",
        name="",
        confidence=50.0,
        provider="wappalyzer",
        detection_method="test",
    )
    outcome = validator.validate_matches([invalid, empty], provider="wappalyzer")
    assert outcome.rejected_count == 2
    assert outcome.matches == []


def test_provider_output_validator_deduplicates() -> None:
    """Duplicate technologies within one provider should be suppressed."""
    outcome = ProviderOutputValidator().validate_matches(
        [_match(), _match(evidence=["other"])],
        provider="wappalyzer",
    )
    assert len(outcome.matches) == 1
    assert outcome.warnings


def test_version_metadata_builder_unknown_version() -> None:
    """Version metadata should mark unknown versions explicitly."""
    metadata = ProviderVersionMetadataBuilder().build(_match(version=UNKNOWN_VERSION))
    assert metadata.is_known is False
    assert metadata.version == UNKNOWN_VERSION


def test_version_metadata_builder_known_version() -> None:
    """Known versions should populate structured metadata."""
    metadata = ProviderVersionMetadataBuilder().build(_match(version="19.1.0"))
    assert metadata.is_known is True
    assert metadata.version == "19.1.0"
    assert metadata.provider == "techspecter"


def test_evidence_aggregator_merges_providers() -> None:
    """Evidence from all providers should aggregate with attribution."""
    matches = [
        _match(
            provider="techspecter",
            evidence=["runtime:ReactDOM.createRoot"],
            evidence_items=[
                ProviderEvidenceItem(
                    source="techspecter",
                    category="runtime",
                    detail="ReactDOM.createRoot",
                ),
            ],
        ),
        _match(
            provider="wappalyzer",
            evidence=["wappalyzer:React"],
            evidence_items=[
                ProviderEvidenceItem(
                    source="wappalyzer",
                    category="wappalyzer",
                    detail="React",
                ),
            ],
        ),
    ]
    strings, structured = ProviderEvidenceAggregator().aggregate(matches)
    assert len(strings) == 2
    assert len(structured) == 2
    assert {item.matcher for item in structured} == {"runtime", "wappalyzer"}


def test_merger_populates_confidence_breakdown() -> None:
    """Merged matches should include explainable confidence breakdown."""
    builder = ProviderVersionMetadataBuilder()
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[builder.build_all(_match(provider="techspecter"))],
        ),
        ProviderDetectionResult(
            provider="wappalyzer",
            target_url="https://example.com",
            matches=[builder.build_all(_match(provider="wappalyzer", confidence=80.0))],
        ),
    ]
    merged = ProviderMerger().merge(results, target_url="https://example.com")
    match = merged.matches[0]
    assert match.confidence_breakdown
    assert match.evidence
    assert match.provider_metadata.get("version_metadata_by_provider")


def test_health_report_formatting() -> None:
    """Health report should show availability and skip reasons."""
    report = format_health_report(
        [
            ProviderHealthStatus(
                provider_id="techspecter",
                display_name="TechSpecter",
                state=ProviderHealthState.AVAILABLE,
                backend_id="fingerprint-engine",
            ),
            ProviderHealthStatus(
                provider_id="wappalyzer",
                display_name="Wappalyzer",
                state=ProviderHealthState.SKIPPED,
                reason="CLI unavailable",
            ),
        ],
    )
    assert "TechSpecter" in report
    assert "Available" in report
    assert "Skipped" in report
    assert "CLI unavailable" in report


def test_wappalyzer_compatibility_layer_selects_adapter() -> None:
    """Compatibility layer should select first available adapter."""
    from techspecter.providers.backends.wappalyzer_compat import WappalyzerCompatibilityLayer

    class _FakeAdapter:
        adapter_id = "fake"
        display_name = "Fake"

        def is_available(self) -> bool:
            return True

        def detect(self, target_url: str, *, timeout_seconds: int) -> list[dict[str, str]]:
            return [{"url": target_url, "technologies": []}]

        def version(self) -> str | None:
            return "1.0.0"

    layer = WappalyzerCompatibilityLayer(adapters=[_FakeAdapter()])  # type: ignore[list-item]
    assert layer.is_available() is True
    assert layer.backend_id() == "fake"


def test_manager_health_check_all() -> None:
    """Manager should expose health checks for enabled providers."""
    manager = ProviderManager()
    health = manager.check_health_all()
    assert len(health) == 3
    assert health[0].provider_id == "techspecter"
    assert health[0].state == ProviderHealthState.AVAILABLE


def test_normalizer_applies_name_aliases() -> None:
    """Normalizer should canonicalize ReactJS to React."""
    from techspecter.fingerprinting.models import DetectionResult, Technology, TechnologyMatch

    detection = TechnologyMatch(
        technology=Technology(id="reactjs", name="ReactJS", category="frontend-frameworks"),
        version="19.1.0",
        confidence=88.0,
    )
    result = ProviderNormalizer().from_techspecter(
        DetectionResult(target_url="https://example.com", matches=[detection]),
    )
    assert result.matches[0].name == "React"
    assert result.matches[0].technology_id == "react"
    assert result.matches[0].version_metadata is not None
