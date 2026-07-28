"""Package marker evidence collector."""

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

_PACKAGE_MARKERS = (
    re.compile(r"\brequire\s*\(\s*['\"]"),
    re.compile(r"\bimport\s+.+\s+from\s+['\"]"),
    re.compile(r"\bexport\s+(?:default\s+)?(?:function|class|const|let|var)\b"),
    re.compile(r"__webpack_require__"),
    re.compile(r"System\.register\s*\("),
)


class PackageAnalyzer(EvidenceCollector):
    """Collect module system markers from JavaScript content."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "package-analyzer"

    @property
    def priority(self) -> int:
        """Run after bundle filename analysis."""
        return 50

    def supports(self, discovery: DiscoveryResult) -> bool:
        """Support discovery with analyzable JavaScript content."""
        return bool(discovery.downloads or discovery.inline_scripts)

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect package/module markers as raw evidence only."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)

        sources: list[tuple[str, str, str]] = []
        for download in discovery.downloads:
            if download.download_success and download.content:
                sources.append((str(download.url), download.filename, download.content))
        for inline in discovery.inline_scripts:
            sources.append(
                (
                    f"inline://script/{inline.index}",
                    f"inline-script-{inline.index}.js",
                    inline.content,
                ),
            )

        for url, filename, content in sources:
            for pattern in _PACKAGE_MARKERS:
                match = pattern.search(content)
                if match is None:
                    continue
                items.append(
                    Evidence(
                        source=EvidenceSource.PACKAGE,
                        evidence_type=EvidenceType.PACKAGE_MARKER,
                        collector=self.name,
                        url=url,
                        file=filename,
                        matched_value=match.group(0),
                        matched_pattern=pattern.pattern,
                        category="package",
                        reason="Observed JavaScript module system marker",
                        timestamp=timestamp,
                    ),
                )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
