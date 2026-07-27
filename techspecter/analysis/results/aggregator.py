"""Result aggregation for multi-analyzer analysis runs."""

from __future__ import annotations

import logging
from collections import defaultdict

from techspecter.analysis.converters import _is_technology_category
from techspecter.analysis.models.finding import Finding
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.analysis.statistics.statistics import AnalysisStatistics

logger = logging.getLogger(__name__)


class ResultAggregator:
    """Merge findings from multiple analyzers into a unified result."""

    def aggregate(self, analyzer_results: list[AnalyzerResult]) -> list[Finding]:
        """Merge analyzer results into a deduplicated finding list."""
        merged: dict[str, Finding] = {}

        for result in analyzer_results:
            for finding in result.findings:
                existing = merged.get(finding.id)
                if existing is None or finding.confidence > existing.confidence:
                    merged[finding.id] = finding

        findings = sorted(
            merged.values(),
            key=lambda item: (-item.confidence, str(item.category).lower(), item.title.lower()),
        )
        logger.info(
            "Aggregated %d findings from %d analyzers",
            len(findings),
            len(analyzer_results),
        )
        return findings

    def calculate_statistics(
        self,
        findings: list[Finding],
        *,
        analyzer_results: list[AnalyzerResult],
        scripts_analyzed: int = 0,
    ) -> AnalysisStatistics:
        """Calculate statistics from aggregated findings."""
        if not findings:
            return AnalysisStatistics(
                scripts_analyzed=scripts_analyzed,
                analyzers_run=len(analyzer_results),
            )

        by_category: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        by_analyzer: dict[str, int] = defaultdict(int)
        confidences: list[float] = []

        for finding in findings:
            by_category[str(finding.category)] += 1
            by_severity[finding.severity.value] += 1
            by_analyzer[finding.analyzer] += 1
            confidences.append(finding.confidence)

        return AnalysisStatistics(
            total_findings=len(findings),
            findings_by_category=dict(sorted(by_category.items())),
            findings_by_severity=dict(sorted(by_severity.items())),
            findings_by_analyzer=dict(sorted(by_analyzer.items())),
            average_confidence=round(sum(confidences) / len(confidences), 2),
            highest_confidence=max(confidences),
            scripts_analyzed=scripts_analyzed,
            analyzers_run=len(analyzer_results),
        )

    def technology_findings(self, findings: list[Finding]) -> list[Finding]:
        """Return findings in the Technology category."""
        return [finding for finding in findings if _is_technology_category(finding.category)]
