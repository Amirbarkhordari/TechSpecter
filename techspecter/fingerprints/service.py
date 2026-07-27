"""High-level fingerprint analysis service."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.fingerprints.models import DetectionResult, FingerprintAnalysisResult
from techspecter.fingerprints.pipeline import FingerprintPipeline
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FingerprintService:
    """Orchestrate discovery and JavaScript technology fingerprinting."""

    discovery_pipeline: DiscoveryPipeline | None = None
    fingerprint_pipeline: FingerprintPipeline | None = None

    async def analyze_url(self, target_url: str) -> FingerprintAnalysisResult:
        """Discover and fingerprint JavaScript technologies for a target URL.

        Args:
            target_url: Raw target URL provided by the caller.

        Returns:
            Combined discovery and detection result.
        """
        started = time.perf_counter()
        discovery = await self._discovery().run(target_url)
        detection = self._fingerprint().run(discovery)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return FingerprintAnalysisResult(
            target_url=str(discovery.target.url),
            discovery_elapsed_ms=discovery.elapsed_ms,
            detection=detection,
            elapsed_ms=elapsed_ms,
        )

    def detect_from_discovery(self, discovery: DiscoveryResult) -> DetectionResult:
        """Run fingerprint detection against an existing discovery result.

        Args:
            discovery: Completed JavaScript discovery result.

        Returns:
            Detection result produced by the fingerprint pipeline.
        """
        return self._fingerprint().run(discovery)

    def detect_source(
        self,
        *,
        content: str,
        filename: str,
        url: str = "memory://script.js",
    ) -> DetectionResult:
        """Fingerprint a single in-memory JavaScript resource.

        Args:
            content: JavaScript source text.
            filename: Resource filename used for filename-based matchers.
            url: Logical source URL used in match metadata.

        Returns:
            Detection result for the provided JavaScript source.
        """
        from techspecter.fingerprints.context import MatchContext

        started = time.perf_counter()
        context = MatchContext(content=content, filename=filename, url=url)
        matches = self._fingerprint().detect_context(context)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return DetectionResult(
            target_url=url,
            matches=matches,
            scripts_analyzed=1,
            elapsed_ms=elapsed_ms,
        )

    def _discovery(self) -> DiscoveryPipeline:
        """Return the configured discovery pipeline."""
        if self.discovery_pipeline is None:
            self.discovery_pipeline = DiscoveryPipeline()
        return self.discovery_pipeline

    def _fingerprint(self) -> FingerprintPipeline:
        """Return the configured fingerprint pipeline."""
        if self.fingerprint_pipeline is None:
            self.fingerprint_pipeline = FingerprintPipeline()
        return self.fingerprint_pipeline
