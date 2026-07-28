"""HTML evidence collector."""

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


class HTMLAnalyzer(EvidenceCollector):
    """Collect HTML-derived script and document evidence."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "html-analyzer"

    @property
    def priority(self) -> int:
        """Run after network metadata collection."""
        return 20

    def supports(self, discovery: DiscoveryResult) -> bool:
        """HTML analyzer supports all discovery results."""
        return True

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect script references and inline script markers."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)
        target_url = str(discovery.target.url)

        for script in discovery.external_scripts:
            items.append(
                Evidence(
                    source=EvidenceSource.HTML,
                    evidence_type=EvidenceType.SCRIPT_REFERENCE,
                    collector=self.name,
                    url=str(script.url),
                    file=script.original_url,
                    matched_value=str(script.url),
                    category="html",
                    reason="Discovered external script reference",
                    timestamp=timestamp,
                    metadata={"original_url": script.original_url},
                ),
            )

        for inline in discovery.inline_scripts:
            items.append(
                Evidence(
                    source=EvidenceSource.HTML,
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    collector=self.name,
                    url=target_url,
                    file=f"inline-script-{inline.index}.js",
                    matched_value=str(len(inline.content)),
                    category="html",
                    reason="Discovered inline script block",
                    timestamp=timestamp,
                    metadata={
                        "index": inline.index,
                        "source_map_url": inline.source_map_url,
                    },
                ),
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
