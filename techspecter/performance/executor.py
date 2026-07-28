"""Concurrent analyzer execution utilities."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class AnalyzerExecutor:
    """Execute analyzers sequentially or concurrently with deterministic ordering."""

    def __init__(self, *, max_workers: int = 4, parallel: bool = False) -> None:
        """Initialize analyzer executor settings."""
        self._max_workers = max(1, max_workers)
        self._parallel = parallel

    def run(
        self,
        analyzers: list[Analyzer],
        discovery: DiscoveryResult,
    ) -> list[AnalyzerResult]:
        """Run analyzers and return results in original analyzer order."""
        if not analyzers:
            return []
        if not self._parallel or len(analyzers) == 1:
            return self._run_sequential(analyzers, discovery)
        return self._run_parallel(analyzers, discovery)

    def _run_sequential(
        self,
        analyzers: list[Analyzer],
        discovery: DiscoveryResult,
    ) -> list[AnalyzerResult]:
        results: list[AnalyzerResult] = []
        for analyzer in analyzers:
            logger.info("Running analyzer '%s'", analyzer.metadata.id)
            result = analyzer.run(discovery)
            if result.errors:
                logger.warning(
                    "Analyzer '%s' completed with errors: %s",
                    analyzer.metadata.id,
                    "; ".join(result.errors),
                )
            results.append(result)
        return results

    def _run_parallel(
        self,
        analyzers: list[Analyzer],
        discovery: DiscoveryResult,
    ) -> list[AnalyzerResult]:
        indexed: dict[str, AnalyzerResult] = {}
        order = [analyzer.metadata.id for analyzer in analyzers]
        workers = min(self._max_workers, len(analyzers))
        logger.info("Running %d analyzers concurrently (%d workers)", len(analyzers), workers)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(analyzer.run, discovery): analyzer.metadata.id for analyzer in analyzers
            }
            for future in as_completed(future_map):
                analyzer_id = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.exception("Analyzer '%s' failed", analyzer_id)
                    result = AnalyzerResult(
                        analyzer_id=analyzer_id,
                        findings=[],
                        errors=[str(exc)],
                    )
                if result.errors:
                    logger.warning(
                        "Analyzer '%s' completed with errors: %s",
                        analyzer_id,
                        "; ".join(result.errors),
                    )
                indexed[analyzer_id] = result

        return [indexed[analyzer_id] for analyzer_id in order if analyzer_id in indexed]
