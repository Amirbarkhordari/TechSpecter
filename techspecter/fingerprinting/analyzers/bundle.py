"""Bundle artifact evidence collector."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceResult
from techspecter.fingerprinting.javascript.evidence_builder import build_evidence
from techspecter.fingerprinting.javascript.extractors.bundle import extract_bundle_findings
from techspecter.fingerprinting.javascript.models import JavaScriptResource, ParseStrategy
from techspecter.fingerprinting.javascript.normalizer import normalize_javascript
from techspecter.models.discovery import DiscoveryResult


class BundleAnalyzer(EvidenceCollector):
    """Collect bundle structure evidence using shared bundle intelligence extractors."""

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
        """Collect bundle markers via shared bundle intelligence extractors."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)

        for download in discovery.downloads:
            if not download.download_success or not download.content:
                continue
            normalized = normalize_javascript(download.content)
            resource = JavaScriptResource(
                url=str(download.url),
                filename=download.filename,
                content=normalized.content,
                content_length=normalized.original_length,
                is_minified=normalized.is_minified,
                parse_strategy=ParseStrategy.FULL,
            )
            findings = extract_bundle_findings(resource)
            items.extend(
                build_evidence(
                    findings=findings,
                    resource=resource,
                    collector=self.name,
                    timestamp=timestamp,
                ),
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
