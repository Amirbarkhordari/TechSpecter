"""Passive web application analysis pipeline."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from techspecter import __version__
from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.analyzers.registry import AnalyzerRegistry, analyzer_registry
from techspecter.analysis.analyzers.technology import TechnologyFingerprintAnalyzer
from techspecter.analysis.converters import findings_to_detection_result
from techspecter.analysis.results.aggregator import ResultAggregator
from techspecter.analysis.results.analysis_result import AnalysisMetadata, AnalysisResult, AnalyzerResult
from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.fingerprinting.models import DetectionResult
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """Orchestrate discovery and multi-analyzer passive analysis."""

    def __init__(
        self,
        *,
        discovery_pipeline: DiscoveryPipeline | None = None,
        analyzers: list[Analyzer] | None = None,
        analyzer_registry_instance: AnalyzerRegistry | None = None,
        aggregator: ResultAggregator | None = None,
    ) -> None:
        """Initialize the analysis pipeline."""
        self._discovery_pipeline = discovery_pipeline or DiscoveryPipeline()
        self._analyzer_registry = analyzer_registry_instance or analyzer_registry
        self._aggregator = aggregator or ResultAggregator()
        if analyzers is not None:
            self._analyzers = analyzers
        else:
            self._analyzers = self._default_analyzers()

    async def run(self, target_url: str) -> AnalysisResult:
        """Discover resources and run all configured analyzers."""
        started = time.perf_counter()
        discovery_started = time.perf_counter()
        discovery = await self._discovery_pipeline.run(target_url)
        discovery_elapsed_ms = (time.perf_counter() - discovery_started) * 1000

        analysis_started = time.perf_counter()
        analyzer_results = self._run_analyzers(discovery)
        findings = self._aggregator.aggregate(analyzer_results)
        statistics = self._aggregator.calculate_statistics(
            findings,
            analyzer_results=analyzer_results,
            scripts_analyzed=_scripts_analyzed(analyzer_results),
        )
        analysis_elapsed_ms = (time.perf_counter() - analysis_started) * 1000
        total_elapsed_ms = (time.perf_counter() - started) * 1000

        detection = _extract_detection(analyzer_results, discovery, findings)
        metadata = AnalysisMetadata(
            target_url=str(discovery.target.url),
            tool_version=__version__,
            discovery_elapsed_ms=discovery_elapsed_ms,
            analysis_elapsed_ms=analysis_elapsed_ms,
            total_elapsed_ms=total_elapsed_ms,
            analyzers=[result.analyzer_id for result in analyzer_results],
            timestamp=datetime.now(UTC),
        )
        logger.info(
            "Analysis complete for %s: %d findings from %d analyzers (%.0f ms)",
            metadata.target_url,
            len(findings),
            len(analyzer_results),
            total_elapsed_ms,
        )
        return AnalysisResult(
            target_url=metadata.target_url,
            findings=findings,
            statistics=statistics,
            metadata=metadata,
            discovery=discovery,
            detection=detection,
            elapsed_ms=total_elapsed_ms,
        )

    def analyze_discovery(self, discovery: DiscoveryResult) -> AnalysisResult:
        """Run analyzers against an existing discovery result."""
        started = time.perf_counter()
        analyzer_results = self._run_analyzers(discovery)
        findings = self._aggregator.aggregate(analyzer_results)
        statistics = self._aggregator.calculate_statistics(
            findings,
            analyzer_results=analyzer_results,
            scripts_analyzed=_scripts_analyzed(analyzer_results),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        detection = _extract_detection(analyzer_results, discovery, findings)
        metadata = AnalysisMetadata(
            target_url=str(discovery.target.url),
            tool_version=__version__,
            analysis_elapsed_ms=elapsed_ms,
            total_elapsed_ms=elapsed_ms,
            analyzers=[result.analyzer_id for result in analyzer_results],
            timestamp=datetime.now(UTC),
        )
        return AnalysisResult(
            target_url=metadata.target_url,
            findings=findings,
            statistics=statistics,
            metadata=metadata,
            discovery=discovery,
            detection=detection,
            elapsed_ms=elapsed_ms,
        )

    def register_analyzer(self, analyzer: Analyzer) -> None:
        """Register an analyzer for future pipeline runs."""
        self._analyzer_registry.register(analyzer)
        if analyzer not in self._analyzers:
            self._analyzers.append(analyzer)

    def _run_analyzers(self, discovery: DiscoveryResult) -> list[AnalyzerResult]:
        """Execute all configured analyzers."""
        results: list[AnalyzerResult] = []
        for analyzer in self._analyzers:
            logger.info("Running analyzer '%s'", analyzer.metadata.id)
            results.append(analyzer.run(discovery))
        return results

    def _default_analyzers(self) -> list[Analyzer]:
        """Return the default analyzer set."""
        if self._analyzer_registry.list_instances():
            return self._analyzer_registry.list_instances()
        default = TechnologyFingerprintAnalyzer()
        return [default]


def _extract_detection(
    analyzer_results: list[AnalyzerResult],
    discovery: DiscoveryResult,
    findings: list,
) -> DetectionResult | None:
    """Extract a detection result from analyzer output for backward compatibility."""
    for result in analyzer_results:
        if result.analyzer_id != "technology-fingerprint":
            continue
        raw_detection = result.metadata.get("detection")
        if isinstance(raw_detection, DetectionResult):
            return raw_detection
        if isinstance(raw_detection, dict):
            return DetectionResult.model_validate(raw_detection)
    technology_findings = [
        finding for finding in findings if finding.id.startswith("technology:")
    ]
    if not technology_findings:
        return None
    elapsed_ms = next(
        (result.elapsed_ms for result in analyzer_results if result.analyzer_id == "technology-fingerprint"),
        0.0,
    )
    return findings_to_detection_result(
        technology_findings,
        target_url=str(discovery.target.url),
        scripts_analyzed=_scripts_analyzed(analyzer_results),
        elapsed_ms=elapsed_ms,
    )


def _scripts_analyzed(analyzer_results: list[AnalyzerResult]) -> int:
    """Return scripts analyzed count from technology analyzer metadata when available."""
    for result in analyzer_results:
        if result.analyzer_id != "technology-fingerprint":
            continue
        raw_detection = result.metadata.get("detection")
        if isinstance(raw_detection, DetectionResult):
            return raw_detection.scripts_analyzed
        if isinstance(raw_detection, dict):
            return int(raw_detection.get("scripts_analyzed", 0))
    return 0
