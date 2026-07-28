"""Tests for unified detection provider framework."""

from __future__ import annotations

from techspecter.configuration.models import ProvidersConfig
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Technology, TechnologyMatch
from techspecter.providers.confidence import ProviderConfidenceEngine
from techspecter.providers.manager import ProviderManager
from techspecter.providers.merger import ProviderMerger
from techspecter.providers.models import ProviderDetectionResult, ProviderMatch, ProviderTarget
from techspecter.providers.normalizer import ProviderNormalizer
from techspecter.providers.version_resolver import ProviderVersionResolver


def _provider_match(
    *,
    tech_id: str = "react",
    name: str = "React",
    provider: str = "techspecter",
    version: str = "19.1.0",
    confidence: float = 85.0,
    evidence: list[str] | None = None,
) -> ProviderMatch:
    """Build a test provider match."""
    return ProviderMatch(
        technology_id=tech_id,
        name=name,
        category="frontend-frameworks",
        version=version,
        confidence=confidence,
        evidence=evidence or ["runtime:ReactDOM.createRoot"],
        provider=provider,
        detection_method=f"{provider}-method",
    )


def test_provider_manager_default_enabled() -> None:
    """Manager should enable all configured providers by default."""
    manager = ProviderManager()
    enabled = manager.enabled_provider_ids()
    assert enabled == ["techspecter", "wappalyzer", "retirejs"]


def test_provider_manager_select_specific_providers() -> None:
    """Manager should honor --provider selection."""
    manager = ProviderManager()
    enabled = manager.enabled_provider_ids(selected=["techspecter", "wappalyzer"])
    assert enabled == ["techspecter", "wappalyzer"]


def test_provider_manager_disable_providers() -> None:
    """Manager should honor disabled providers."""
    manager = ProviderManager()
    enabled = manager.enabled_provider_ids(disabled=["wappalyzer", "retirejs"])
    assert enabled == ["techspecter"]


def test_provider_config_disables_provider() -> None:
    """Configuration should disable providers."""
    from techspecter.configuration.models import ProviderEntryConfig

    config = ProvidersConfig(
        wappalyzer=ProviderEntryConfig(enabled=False),
    )
    manager = ProviderManager(config=config)
    enabled = manager.enabled_provider_ids()
    assert "wappalyzer" not in enabled
    assert "techspecter" in enabled


def test_normalizer_from_techspecter_match() -> None:
    """TechSpecter detection should normalize to provider matches."""
    detection = TechnologyMatch(
        technology=Technology(id="react", name="React", category="frontend-frameworks"),
        version="19.1.0",
        confidence=88.0,
        detection_reason="runtime evidence",
        matched_patterns=["runtime:ReactDOM.createRoot"],
        evidence_count=2,
    )
    from techspecter.fingerprinting.models import DetectionResult

    result = ProviderNormalizer().from_techspecter(
        DetectionResult(target_url="https://example.com", matches=[detection]),
    )
    assert result.provider == "techspecter"
    assert result.matches[0].technology_id == "react"


def test_merger_deduplicates_technologies() -> None:
    """Merger should produce one unified match per technology."""
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[_provider_match(provider="techspecter", confidence=85.0)],
        ),
        ProviderDetectionResult(
            provider="wappalyzer",
            target_url="https://example.com",
            matches=[_provider_match(provider="wappalyzer", confidence=80.0)],
        ),
    ]
    merged = ProviderMerger().merge(results, target_url="https://example.com")
    assert len(merged.matches) == 1
    match = merged.matches[0]
    assert set(match.providers) == {"techspecter", "wappalyzer"}
    assert match.confidence >= 97.0


def test_version_resolver_prefers_techspecter() -> None:
    """Version resolver should prefer TechSpecter over other providers."""
    outcome = ProviderVersionResolver().resolve(
        [
            _provider_match(provider="techspecter", version="19.1.0"),
            _provider_match(provider="wappalyzer", version="18.2.0"),
        ],
    )
    assert outcome.version == "19.1.0"
    assert outcome.source_provider == "techspecter"


def test_version_resolver_uses_wappalyzer_when_techspecter_unknown() -> None:
    """Unknown TechSpecter version should fall back to Wappalyzer."""
    outcome = ProviderVersionResolver().resolve(
        [
            _provider_match(provider="techspecter", version=UNKNOWN_VERSION),
            _provider_match(provider="wappalyzer", version="19.1.0"),
        ],
    )
    assert outcome.version == "19.1.0"
    assert outcome.source_provider == "wappalyzer"


def test_version_resolver_records_conflicts() -> None:
    """Conflicting versions should be recorded."""
    outcome = ProviderVersionResolver().resolve(
        [
            _provider_match(provider="techspecter", version="19.1.0"),
            _provider_match(provider="retirejs", version="18.0.0"),
        ],
    )
    assert outcome.conflict is True
    assert outcome.rejected_versions


def test_confidence_single_provider() -> None:
    """Single provider agreement should target ~90% confidence."""
    confidence = ProviderConfidenceEngine().calculate(
        [_provider_match(confidence=70.0)],
        provider_count=1,
    )
    assert confidence >= 90.0


def test_confidence_three_providers() -> None:
    """Three providers should reach ~99% confidence."""
    confidence = ProviderConfidenceEngine().calculate(
        [
            _provider_match(provider="techspecter"),
            _provider_match(provider="wappalyzer"),
            _provider_match(provider="retirejs"),
        ],
        provider_count=3,
    )
    assert confidence >= 99.0


def test_retirejs_normalizer_vulnerability_metadata() -> None:
    """Retire.js vulnerabilities should normalize into security findings."""
    payload = [
        {
            "file": "https://example.com/jquery.js",
            "results": [
                {
                    "component": "jquery",
                    "version": "1.12.4",
                    "vulnerabilities": [
                        {
                            "severity": "medium",
                            "identifiers": [{"type": "CVE", "value": "CVE-2020-11022"}],
                            "info": ["https://example.com/advisory"],
                            "summary": "XSS vulnerability",
                        },
                    ],
                },
            ],
        },
    ]
    result = ProviderNormalizer().from_retirejs(payload, target_url="https://example.com")
    assert result.matches[0].technology_id == "jquery"
    assert result.matches[0].security_findings
    assert result.matches[0].security_findings[0].cve_ids == ["CVE-2020-11022"]


def test_techspecter_provider_requires_discovery() -> None:
    """TechSpecter provider should fail gracefully without discovery."""
    from techspecter.providers.techspecter_provider import TechSpecterProvider

    result = TechSpecterProvider().detect(ProviderTarget(url="https://example.com"))
    assert result.success is False
    assert result.error


def test_provider_failure_does_not_block_merge() -> None:
    """Failed providers should not prevent merging successful ones."""
    results = [
        ProviderDetectionResult(
            provider="techspecter",
            target_url="https://example.com",
            matches=[_provider_match()],
        ),
        ProviderDetectionResult(
            provider="wappalyzer",
            target_url="https://example.com",
            success=False,
            error="not available",
        ),
    ]
    merged = ProviderMerger().merge(results, target_url="https://example.com")
    assert len(merged.matches) == 1
