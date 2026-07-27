"""Tests for result aggregation."""

from __future__ import annotations

from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.aggregator import ResultAggregator
from techspecter.analysis.results.analysis_result import AnalyzerResult
from tests.analysis_fixtures import sample_finding


def test_aggregate_merges_findings() -> None:
    """Verify aggregator merges findings from multiple analyzers."""
    aggregator = ResultAggregator()
    results = [
        AnalyzerResult(
            analyzer_id="a1",
            findings=[sample_finding(id="finding-1", confidence=50.0)],
        ),
        AnalyzerResult(
            analyzer_id="a2",
            findings=[
                sample_finding(
                    id="finding-2",
                    analyzer="a2",
                    category=FindingCategory.HTTP,
                )
            ],
        ),
    ]
    findings = aggregator.aggregate(results)
    assert len(findings) == 2


def test_aggregate_keeps_highest_confidence_duplicate() -> None:
    """Verify duplicate finding IDs keep the highest confidence."""
    aggregator = ResultAggregator()
    results = [
        AnalyzerResult(
            analyzer_id="a1",
            findings=[sample_finding(id="dup", confidence=40.0)],
        ),
        AnalyzerResult(
            analyzer_id="a2",
            findings=[sample_finding(id="dup", confidence=90.0, analyzer="a2")],
        ),
    ]
    findings = aggregator.aggregate(results)
    assert len(findings) == 1
    assert findings[0].confidence == 90.0


def test_calculate_statistics() -> None:
    """Verify statistics are calculated from findings."""
    aggregator = ResultAggregator()
    findings = [
        sample_finding(id="f1", confidence=80.0),
        sample_finding(id="f2", confidence=60.0, category=FindingCategory.HTTP),
    ]
    stats = aggregator.calculate_statistics(
        findings,
        analyzer_results=[
            AnalyzerResult(analyzer_id="a1", findings=findings),
        ],
        scripts_analyzed=3,
    )
    assert stats.total_findings == 2
    assert stats.average_confidence == 70.0
    assert stats.highest_confidence == 80.0
    assert stats.scripts_analyzed == 3
