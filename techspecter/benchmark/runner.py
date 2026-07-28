"""Benchmark orchestration."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from techspecter.benchmark.comparator import ComparisonEngine
from techspecter.benchmark.gap_analysis import GapAnalyzer
from techspecter.benchmark.models import ComparisonReport
from techspecter.benchmark.normalizer import ResultNormalizer
from techspecter.benchmark.statistics import StatisticsCalculator
from techspecter.benchmark.wappalyzer import WappalyzerExecutor

logger = logging.getLogger(__name__)


class TechSpecterScanner(Protocol):
    """Protocol for scanning a URL with TechSpecter."""

    async def analyze_url(self, target_url: str) -> object:
        """Analyze a target URL and return fingerprint results."""


@dataclass(slots=True)
class BenchmarkRunner:
    """Run TechSpecter and Wappalyzer independently and compare outputs."""

    fingerprint_service: TechSpecterScanner | None = None
    normalizer: ResultNormalizer = field(default_factory=ResultNormalizer)
    comparator: ComparisonEngine = field(default_factory=ComparisonEngine)
    statistics: StatisticsCalculator = field(default_factory=StatisticsCalculator)
    gap_analyzer: GapAnalyzer = field(default_factory=GapAnalyzer)
    wappalyzer: WappalyzerExecutor = field(default_factory=WappalyzerExecutor)

    async def run_async(
        self,
        target_url: str,
        *,
        wappalyzer_result: Path | str | None = None,
        wappalyzer_timeout_seconds: int = 120,
    ) -> ComparisonReport:
        """Execute benchmark asynchronously."""
        started = time.perf_counter()

        ts_result = await self._scan_techspecter(target_url)
        from techspecter.fingerprinting.models import FingerprintAnalysisResult

        if not isinstance(ts_result, FingerprintAnalysisResult):
            msg = "TechSpecter scanner returned unexpected result type"
            raise TypeError(msg)

        wap_payload, wap_execution = self._obtain_wappalyzer(
            target_url,
            wappalyzer_result=wappalyzer_result,
            timeout_seconds=wappalyzer_timeout_seconds,
        )

        ts_normalized = self.normalizer.normalize_techspecter(
            ts_result.detection,
            elapsed_ms=ts_result.elapsed_ms,
        )
        wap_normalized = self.normalizer.normalize_wappalyzer(
            wap_payload,
            target_url=target_url,
        )

        matched, ts_only, wap_only = self.comparator.compare(ts_normalized, wap_normalized)
        version_comparisons = self.comparator.compare_versions(matched)
        stats = self.statistics.calculate(
            matched=matched,
            techspecter_only=ts_only,
            wappalyzer_only=wap_only,
            version_comparisons=version_comparisons,
        )
        gaps = self.gap_analyzer.analyze(
            wappalyzer_only=wap_only,
            techspecter_only=ts_only,
            version_comparisons=version_comparisons,
        )

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Benchmark for %s complete: %d matched, %d missing, %d extra (%.0f ms)",
            target_url,
            stats.matched_technologies,
            stats.missing_detections,
            stats.extra_detections,
            elapsed_ms,
        )

        return ComparisonReport(
            target_url=target_url,
            techspecter=ts_normalized,
            wappalyzer=wap_normalized,
            matched=matched,
            techspecter_only=ts_only,
            wappalyzer_only=wap_only,
            version_comparisons=version_comparisons,
            statistics=stats,
            gap_analysis=gaps,
            wappalyzer_execution=wap_execution,
            elapsed_ms=elapsed_ms,
        )

    def run(
        self,
        target_url: str,
        *,
        wappalyzer_result: Path | str | None = None,
        wappalyzer_timeout_seconds: int = 120,
    ) -> ComparisonReport:
        """Execute benchmark synchronously."""
        return asyncio.run(
            self.run_async(
                target_url,
                wappalyzer_result=wappalyzer_result,
                wappalyzer_timeout_seconds=wappalyzer_timeout_seconds,
            ),
        )

    def run_from_results(
        self,
        *,
        target_url: str,
        techspecter: object,
        wappalyzer_payload: dict[str, Any] | list[Any],
        wappalyzer_execution: str = "imported",
        techspecter_elapsed_ms: float = 0.0,
    ) -> ComparisonReport:
        """Compare precomputed TechSpecter and Wappalyzer results."""
        from techspecter.fingerprinting.models import DetectionResult

        if not isinstance(techspecter, DetectionResult):
            msg = "techspecter argument must be a DetectionResult"
            raise TypeError(msg)
        ts_normalized = self.normalizer.normalize_techspecter(
            techspecter,
            elapsed_ms=techspecter_elapsed_ms,
        )
        wap_normalized = self.normalizer.normalize_wappalyzer(
            wappalyzer_payload,
            target_url=target_url,
        )
        matched, ts_only, wap_only = self.comparator.compare(ts_normalized, wap_normalized)
        version_comparisons = self.comparator.compare_versions(matched)
        stats = self.statistics.calculate(
            matched=matched,
            techspecter_only=ts_only,
            wappalyzer_only=wap_only,
            version_comparisons=version_comparisons,
        )
        gaps = self.gap_analyzer.analyze(
            wappalyzer_only=wap_only,
            techspecter_only=ts_only,
            version_comparisons=version_comparisons,
        )
        return ComparisonReport(
            target_url=target_url,
            techspecter=ts_normalized,
            wappalyzer=wap_normalized,
            matched=matched,
            techspecter_only=ts_only,
            wappalyzer_only=wap_only,
            version_comparisons=version_comparisons,
            statistics=stats,
            gap_analysis=gaps,
            wappalyzer_execution=wappalyzer_execution,
        )

    async def _scan_techspecter(self, target_url: str) -> object:
        """Run TechSpecter fingerprint analysis."""
        if self.fingerprint_service is not None:
            return await self.fingerprint_service.analyze_url(target_url)
        from techspecter.fingerprinting.service import FingerprintService

        return await FingerprintService().analyze_url(target_url)

    def _obtain_wappalyzer(
        self,
        target_url: str,
        *,
        wappalyzer_result: Path | str | None,
        timeout_seconds: int,
    ) -> tuple[dict[str, Any] | list[Any], str]:
        """Obtain Wappalyzer results via import or CLI execution."""
        if wappalyzer_result is not None:
            payload = self.wappalyzer.load_json(wappalyzer_result)
            return payload, "imported"

        if self.wappalyzer.is_available():
            payload = self.wappalyzer.run(target_url, timeout_seconds=timeout_seconds)
            return payload, "cli"

        msg = (
            "Wappalyzer is not available and no --wappalyzer-result file was provided. "
            "Install Wappalyzer CLI or pass an existing JSON report."
        )
        raise RuntimeError(msg)
