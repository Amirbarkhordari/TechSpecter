"""Bundle artifact evidence collector."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceResult,
    EvidenceSource,
    EvidenceType,
)
from techspecter.models.discovery import DiscoveryResult

_BUNDLE_FILENAME = re.compile(
    r"(?i)(?:\.min\.js$|\.bundle\.js$|\.chunk\.js$|/chunk[-.]?\d+\.js$)",
)


class BundleAnalyzer(EvidenceCollector):
    """Collect bundle and minified artifact filename evidence."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "bundle-analyzer"

    @property
    def priority(self) -> int:
        """Run after JavaScript resource collection."""
        return 40

    def supports(self, discovery: DiscoveryResult) -> bool:
        """Support discovery with downloaded script filenames."""
        return bool(discovery.downloads)

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect bundle filename markers without identifying technologies."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)

        for download in discovery.downloads:
            if not download.filename:
                continue
            if not _BUNDLE_FILENAME.search(download.filename):
                continue
            items.append(
                Evidence(
                    source=EvidenceSource.BUNDLE,
                    evidence_type=EvidenceType.BUNDLE_MARKER,
                    collector=self.name,
                    url=str(download.url),
                    file=download.filename,
                    matched_value=download.filename,
                    matched_pattern=_BUNDLE_FILENAME.pattern,
                    category="bundle",
                    reason="Filename matches bundle/minified/chunk naming convention",
                    timestamp=timestamp,
                ),
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
