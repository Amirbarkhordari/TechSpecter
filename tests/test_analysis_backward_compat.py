"""Backward compatibility tests for the analysis framework refactor."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from techspecter.analysis.converters import (
    detection_result_to_findings,
    findings_to_detection_result,
    technology_match_to_finding,
)
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.service import AnalysisService
from techspecter.fingerprinting.models import FingerprintAnalysisResult
from techspecter.fingerprinting.service import FingerprintService
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.service import ReportService
from tests.analysis_fixtures import sample_detection_result, sample_discovery_result
from tests.report_fixtures import sample_detection_result as report_detection


def test_fingerprint_service_still_available() -> None:
    """Verify FingerprintService remains the fingerprint entry point."""
    discovery = sample_discovery_result()
    detection = sample_detection_result()
    service = FingerprintService()

    with patch(
        "techspecter.fingerprinting.service.FingerprintPipeline.run",
        return_value=detection,
    ):
        result = service.detect_from_discovery(discovery)

    assert len(result.matches) == 1
    assert result.matches[0].technology.name == "React"


def test_detection_result_to_findings_round_trip() -> None:
    """Verify detection results convert to findings and back."""
    detection = report_detection()
    findings = detection_result_to_findings(detection, analyzer_id="technology-fingerprint")
    assert len(findings) == 2
    assert all(item.category == FindingCategory.TECHNOLOGY for item in findings)

    restored = findings_to_detection_result(
        findings,
        target_url=detection.target_url,
        scripts_analyzed=detection.scripts_analyzed,
        elapsed_ms=detection.elapsed_ms,
    )
    assert restored.target_url == detection.target_url
    assert len(restored.matches) == 2
    assert restored.matches[0].technology.name == "React"


def test_technology_match_to_finding_preserves_metadata() -> None:
    """Verify technology matches map to rich findings."""
    match = sample_detection_result().matches[0]
    finding = technology_match_to_finding(match, analyzer_id="technology-fingerprint")
    assert finding.id == "technology:react"
    assert finding.metadata["version"] == "18.2.0"


def test_report_engine_detection_path_unchanged() -> None:
    """Verify legacy DetectionResult reporting still works."""
    detection = report_detection()
    report = ReportEngine().generate(detection)
    assert len(report.technologies) == 2
    assert report.summary.technologies_detected == 2
    assert report.findings == []


@pytest.mark.asyncio
async def test_analysis_service_to_fingerprint_result() -> None:
    """Verify analysis results can convert to legacy fingerprint results."""
    discovery = sample_discovery_result()
    detection = sample_detection_result()
    service = AnalysisService()

    with patch(
        "techspecter.analysis.analyzers.technology.FingerprintPipeline.run",
        return_value=detection,
    ):
        result = service.analyze_discovery(discovery)

    fingerprint_result = service.to_fingerprint_analysis_result(result)
    assert isinstance(fingerprint_result, FingerprintAnalysisResult)
    assert fingerprint_result.detection.matches[0].technology.name == "React"


def test_report_service_supports_analysis_results() -> None:
    """Verify reports can be generated from analysis results."""
    detection = report_detection()
    findings = detection_result_to_findings(detection, analyzer_id="technology-fingerprint")
    from techspecter.analysis.results.analysis_result import AnalysisMetadata, AnalysisResult
    from techspecter.analysis.statistics.statistics import AnalysisStatistics
    from techspecter import __version__

    analysis = AnalysisResult(
        target_url=detection.target_url,
        findings=findings,
        statistics=AnalysisStatistics(total_findings=len(findings), analyzers_run=1),
        metadata=AnalysisMetadata(target_url=detection.target_url, tool_version=__version__),
        detection=detection,
    )
    report = ReportService().generate_report_from_analysis(analysis)
    assert len(report.technologies) == 2
    assert len(report.findings) == 2
