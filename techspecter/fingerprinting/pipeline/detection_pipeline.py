"""Legacy fingerprint detection pipeline (backward compatible)."""

from __future__ import annotations

import logging
import time

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.detection.merger import TechnologyMerger
from techspecter.fingerprinting.engine import FingerprintEngine
from techspecter.fingerprinting.loader import SignatureLoader
from techspecter.fingerprinting.models import DetectionResult, TechnologyMatch
from techspecter.models.discovery import DiscoveryResult, DownloadResult, InlineScript

logger = logging.getLogger(__name__)


class FingerprintPipeline:
    """Run fingerprint detection against discovery results."""

    def __init__(
        self,
        engine: FingerprintEngine | None = None,
        *,
        signature_loader: SignatureLoader | None = None,
        merger: TechnologyMerger | None = None,
    ) -> None:
        """Initialize the fingerprint pipeline.

        Args:
            engine: Optional preconfigured fingerprint engine.
            signature_loader: Optional signature loader for dependency injection.
            merger: Optional technology merger for duplicate suppression.
        """
        self._signature_loader = signature_loader or SignatureLoader()
        self._engine = engine or FingerprintEngine(self._signature_loader.load_all())
        self._merger = merger or TechnologyMerger()

    def detect_context(self, context: MatchContext) -> list[TechnologyMatch]:
        """Detect technologies in a single JavaScript resource context.

        Args:
            context: JavaScript resource context.

        Returns:
            Technology matches for the resource.
        """
        return self._engine.detect(context)

    def run(self, discovery: DiscoveryResult) -> DetectionResult:
        """Detect technologies from a discovery result.

        Args:
            discovery: Completed JavaScript discovery result.

        Returns:
            Aggregated detection result.
        """
        started = time.perf_counter()
        target_url = str(discovery.target.url)
        contexts = list(_iter_analysis_contexts(discovery))
        all_matches: list[TechnologyMatch] = []

        for context in contexts:
            all_matches.extend(self._engine.detect(context))

        matches = self._merger.merge_matches(all_matches)

        elapsed_ms = (time.perf_counter() - started) * 1000
        logger.info(
            "Fingerprint detection complete for %s: %d technologies from %d scripts (%.0f ms)",
            target_url,
            len(matches),
            len(contexts),
            elapsed_ms,
        )
        return DetectionResult(
            target_url=target_url,
            matches=matches,
            scripts_analyzed=len(contexts),
            elapsed_ms=elapsed_ms,
        )


def _iter_analysis_contexts(discovery: DiscoveryResult) -> list[MatchContext]:
    """Build analysis contexts from discovery results."""
    contexts: list[MatchContext] = []

    for download in discovery.downloads:
        context = _context_from_download(download)
        if context is not None:
            contexts.append(context)

    for inline in discovery.inline_scripts:
        contexts.append(_context_from_inline(inline))

    return contexts


def _context_from_download(download: DownloadResult) -> MatchContext | None:
    """Create a match context from a download result."""
    if not download.download_success or not download.content:
        return None
    return MatchContext(
        content=download.content,
        filename=download.filename,
        url=str(download.url),
        source_map_url=download.source_map_url,
    )


def _context_from_inline(inline: InlineScript) -> MatchContext:
    """Create a match context from an inline script block."""
    return MatchContext(
        content=inline.content,
        filename=f"inline-script-{inline.index}.js",
        url=f"inline://script/{inline.index}",
        source_map_url=inline.source_map_url,
    )
