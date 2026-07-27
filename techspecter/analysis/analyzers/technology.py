"""Technology fingerprinting analyzer."""

from __future__ import annotations

import logging
import time

from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.converters import detection_result_to_findings
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.fingerprinting.pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)
_ANALYZER_ID = "technology-fingerprint"
_ANALYZER_VERSION = "1.0.0"


class TechnologyFingerprintAnalyzer(Analyzer):
    """Passive JavaScript technology fingerprinting analyzer."""

    def __init__(self, pipeline: FingerprintPipeline | None = None) -> None:
        """Initialize the analyzer with an optional fingerprint pipeline."""
        self._pipeline = pipeline or FingerprintPipeline()

    @property
    def metadata(self) -> AnalyzerMetadata:
        """Return analyzer metadata."""
        return AnalyzerMetadata(
            id=_ANALYZER_ID,
            name="Technology Fingerprint Analyzer",
            version=_ANALYZER_VERSION,
            description="Identifies JavaScript technologies from downloaded resources.",
            category=FindingCategory.TECHNOLOGY.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        """Run fingerprint detection and convert matches to findings."""
        started = time.perf_counter()
        detection = self._pipeline.run(discovery)
        findings = detection_result_to_findings(detection, analyzer_id=_ANALYZER_ID)
        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Technology fingerprint analyzer found %d technologies for %s",
            len(findings),
            discovery.target.url,
        )
        return AnalyzerResult(
            analyzer_id=_ANALYZER_ID,
            findings=findings,
            elapsed_ms=elapsed_ms,
            metadata={"detection": detection.model_dump(mode="python")},
        )
