"""Tests for analyzer base classes."""

from __future__ import annotations

import pytest

from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.analyzers.registry import AnalyzerRegistry
from techspecter.analysis.analyzers.registry import AnalyzerNotFoundError
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.discovery import DiscoveryResult
from tests.analysis_fixtures import sample_discovery_result, sample_finding


class _StubAnalyzer(Analyzer):
    """Minimal analyzer for testing."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="stub-analyzer",
            name="Stub Analyzer",
            version="1.0.0",
            description="Test analyzer",
            category=FindingCategory.INFORMATION.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer_id="stub-analyzer",
            findings=[sample_finding(analyzer="stub-analyzer")],
        )


class _FailingAnalyzer(Analyzer):
    """Analyzer that raises during execution."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="failing-analyzer",
            name="Failing Analyzer",
            version="1.0.0",
            description="Fails on execute",
            category=FindingCategory.INFORMATION.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        raise RuntimeError("analyzer failure")


def test_analyzer_metadata() -> None:
    """Verify analyzer metadata fields."""
    analyzer = _StubAnalyzer()
    metadata = analyzer.metadata
    assert metadata.id == "stub-analyzer"
    assert metadata.name == "Stub Analyzer"
    assert metadata.version == "1.0.0"


def test_analyzer_run_returns_findings() -> None:
    """Verify analyzer.run executes and returns findings."""
    result = _StubAnalyzer().run(sample_discovery_result())
    assert result.analyzer_id == "stub-analyzer"
    assert len(result.findings) == 1


def test_analyzer_run_handles_failures() -> None:
    """Verify analyzer.run catches execution errors."""
    result = _FailingAnalyzer().run(sample_discovery_result())
    assert result.findings == []
    assert result.errors


def test_analyzer_registry() -> None:
    """Verify analyzer registry operations."""
    registry = AnalyzerRegistry()
    analyzer = _StubAnalyzer()
    registry.register(analyzer)
    assert registry.get("stub-analyzer") is analyzer
    assert registry.list_analyzers() == ["stub-analyzer"]
    registry.unregister("stub-analyzer")
    with pytest.raises(AnalyzerNotFoundError):
        registry.get("stub-analyzer")


def test_analyzer_registry_prevents_duplicates() -> None:
    """Verify duplicate analyzer IDs are rejected."""
    registry = AnalyzerRegistry()
    registry.register(_StubAnalyzer())
    with pytest.raises(ValueError, match="already registered"):
        registry.register(_StubAnalyzer())
