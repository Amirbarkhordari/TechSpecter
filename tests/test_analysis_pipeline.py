"""Tests for the analysis pipeline."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from techspecter.analysis.analyzers.technology import TechnologyFingerprintAnalyzer
from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from tests.analysis_fixtures import sample_detection_result, sample_discovery_result


@pytest.mark.asyncio
async def test_pipeline_runs_discovery_and_analyzers() -> None:
    """Verify the pipeline orchestrates discovery and analyzers."""
    discovery = sample_discovery_result()
    detection = sample_detection_result()
    pipeline = AnalysisPipeline(analyzers=[TechnologyFingerprintAnalyzer()])

    with (
        patch.object(pipeline._discovery_pipeline, "run", AsyncMock(return_value=discovery)),
        patch(
            "techspecter.analysis.analyzers.technology.FingerprintPipeline.run",
            return_value=detection,
        ),
    ):
        result = await pipeline.run("https://example.com")

    assert result.target_url == "https://example.com/"
    assert len(result.findings) == 1
    assert result.detection is not None
    assert result.statistics.total_findings == 1


def test_analyze_discovery_without_network() -> None:
    """Verify analyzers can run against an existing discovery result."""
    discovery = sample_discovery_result()
    detection = sample_detection_result()
    pipeline = AnalysisPipeline(analyzers=[TechnologyFingerprintAnalyzer()])

    with patch(
        "techspecter.analysis.analyzers.technology.FingerprintPipeline.run",
        return_value=detection,
    ):
        result = pipeline.analyze_discovery(discovery)

    assert result.findings[0].title == "React"
    assert result.metadata.analyzers == ["technology-fingerprint"]


def test_pipeline_register_analyzer() -> None:
    """Verify additional analyzers can be registered."""
    pipeline = AnalysisPipeline(analyzers=[])
    analyzer = TechnologyFingerprintAnalyzer()
    pipeline.register_analyzer(analyzer)
    assert analyzer in pipeline._analyzers
