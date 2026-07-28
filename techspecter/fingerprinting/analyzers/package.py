"""Package marker evidence collector."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceResult
from techspecter.fingerprinting.javascript.cache import get_parse_cache
from techspecter.fingerprinting.javascript.evidence_builder import build_evidence
from techspecter.fingerprinting.javascript.extractors.package import extract_package_findings
from techspecter.fingerprinting.javascript.models import JavaScriptResource, ParseStrategy
from techspecter.fingerprinting.javascript.normalizer import normalize_javascript
from techspecter.fingerprinting.javascript.parser import TokenJavaScriptParser
from techspecter.models.discovery import DiscoveryResult


class PackageAnalyzer(EvidenceCollector):
    """Collect package markers using shared package intelligence extractors."""

    def __init__(self) -> None:
        """Initialize package analyzer with shared parser and cache."""
        self._parser = TokenJavaScriptParser()
        self._cache = get_parse_cache()

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
        """Collect package markers via shared package intelligence extractors."""
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
            normalized = normalize_javascript(content)
            resource = JavaScriptResource(
                url=url,
                filename=filename,
                content=normalized.content,
                content_length=normalized.original_length,
                is_minified=normalized.is_minified,
                parse_strategy=ParseStrategy.FULL,
            )
            cache_key = self._cache.cache_key(url=url, content=resource.content)
            parsed = self._cache.get(cache_key)
            if parsed is None:
                parsed = self._parser.parse(resource)
                self._cache.set(cache_key, parsed)
            findings = extract_package_findings(parsed, content=resource.content)
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
