"""JavaScript resource evidence collector."""

from __future__ import annotations

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


class JavaScriptAnalyzer(EvidenceCollector):
    """Collect JavaScript download and inline content evidence."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "javascript-analyzer"

    @property
    def priority(self) -> int:
        """Run after HTML reference collection."""
        return 30

    def supports(self, discovery: DiscoveryResult) -> bool:
        """Support discovery with downloadable or inline JavaScript."""
        return bool(discovery.downloads or discovery.inline_scripts)

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect script body and source map evidence."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)

        for download in discovery.downloads:
            if not download.download_success or not download.content:
                continue
            items.append(
                Evidence(
                    source=EvidenceSource.JAVASCRIPT,
                    evidence_type=EvidenceType.SCRIPT_CONTENT,
                    collector=self.name,
                    url=str(download.url),
                    file=download.filename,
                    matched_value=str(len(download.content)),
                    category="javascript",
                    reason="Downloaded JavaScript resource available for analysis",
                    timestamp=timestamp,
                    metadata={
                        "content_length": len(download.content),
                        "content_type": download.content_type,
                    },
                ),
            )
            if download.source_map_url:
                items.append(
                    Evidence(
                        source=EvidenceSource.JAVASCRIPT,
                        evidence_type=EvidenceType.SOURCE_MAP,
                        collector=self.name,
                        url=str(download.url),
                        file=download.filename,
                        matched_value=download.source_map_url,
                        category="javascript",
                        reason="Source map reference detected in JavaScript resource",
                        timestamp=timestamp,
                    ),
                )

        for inline in discovery.inline_scripts:
            items.append(
                Evidence(
                    source=EvidenceSource.JAVASCRIPT,
                    evidence_type=EvidenceType.SCRIPT_CONTENT,
                    collector=self.name,
                    url=f"inline://script/{inline.index}",
                    file=f"inline-script-{inline.index}.js",
                    matched_value=str(len(inline.content)),
                    category="javascript",
                    reason="Inline JavaScript content available for analysis",
                    timestamp=timestamp,
                    metadata={"index": inline.index},
                ),
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
