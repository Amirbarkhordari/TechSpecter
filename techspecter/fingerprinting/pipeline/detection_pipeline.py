"""Legacy fingerprint detection pipeline (backward compatible)."""

from __future__ import annotations

import logging
import time

from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.engine import FingerprintEngine
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.match_quality import apply_match_quality_gate
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch
from techspecter.fingerprinting.pipeline.analysis_contexts import iter_analysis_contexts
from techspecter.models.discovery import DiscoveryResult
from techspecter.versioning.engine import VersionDetectionEngine

logger = logging.getLogger(__name__)


class FingerprintPipeline:
    """Run fingerprint detection against discovery results."""

    def __init__(
        self,
        engine: FingerprintEngine | None = None,
        *,
        signature_loader: SignatureLoader | None = None,
        merger: TechnologyMerger | None = None,
        version_engine: VersionDetectionEngine | None = None,
    ) -> None:
        """Initialize the fingerprint pipeline."""
        self._signature_loader = signature_loader or SignatureLoader()
        self._engine = engine or FingerprintEngine(self._signature_loader.load_all())
        self._merger = merger or TechnologyMerger()
        self._version_engine = version_engine or VersionDetectionEngine()

    def detect_context(self, context) -> list[TechnologyMatch]:
        """Detect technologies in a single resource context."""
        return self._engine.detect(context)

    def run(
        self,
        discovery: DiscoveryResult,
        *,
        apply_quality_gate: bool = True,
    ) -> DetectionResult:
        """Detect technologies from a discovery result."""
        started = time.perf_counter()
        target_url = str(discovery.target.url)
        contexts = list(iter_analysis_contexts(discovery))
        all_matches: list[TechnologyMatch] = []

        for context in contexts:
            all_matches.extend(self._engine.detect(context))

        logger.info(
            "Fingerprint engine produced %d raw matches from %d analysis contexts for %s",
            len(all_matches),
            len(contexts),
            target_url,
        )

        matches = self._merger.merge_matches(all_matches)
        elapsed_ms = (time.perf_counter() - started) * 1000
        detection = DetectionResult(
            target_url=target_url,
            matches=matches,
            scripts_analyzed=len(contexts),
            elapsed_ms=elapsed_ms,
        )
        detection = self._version_engine.enrich(detection, discovery)

        if not apply_quality_gate:
            return detection

        confirmed, ignored = apply_match_quality_gate(detection.matches)
        prior_ignored = list(detection.ignored_matches)
        ignored.extend(prior_ignored)
        detection = detection.model_copy(update={"matches": confirmed, "ignored_matches": ignored})
        logger.info(
            "Fingerprint detection complete for %s: %d confirmed technologies "
            "(%d ignored weak matches) from %d contexts (%.0f ms)",
            target_url,
            len(detection.matches),
            len(ignored),
            len(contexts),
            elapsed_ms,
        )
        return detection
