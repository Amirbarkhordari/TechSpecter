"""JavaScript Intelligence Engine orchestrator."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from techspecter.fingerprinting.evidence.models import Evidence
from techspecter.fingerprinting.javascript.cache import ParseCache, get_parse_cache
from techspecter.fingerprinting.javascript.evidence_builder import (
    build_evidence,
    build_script_content_evidence,
    build_source_map_reference_evidence,
)
from techspecter.fingerprinting.javascript.extractors import (
    extract_banner_findings,
    extract_bundle_findings,
    extract_import_export_findings,
    extract_metadata_findings,
    extract_package_findings,
    extract_runtime_findings,
    extract_string_findings,
    extract_version_candidates,
)
from techspecter.fingerprinting.javascript.models import (
    ExtractionFinding,
    JavaScriptAnalysisResult,
    JavaScriptResource,
    ParsedScript,
    ParseStrategy,
)
from techspecter.fingerprinting.javascript.normalizer import normalize_javascript
from techspecter.fingerprinting.javascript.parser import JavaScriptParser, TokenJavaScriptParser
from techspecter.fingerprinting.javascript.sourcemap.analyzer import extract_source_map_findings
from techspecter.fingerprinting.javascript.sourcemap.fetcher import fetch_source_map
from techspecter.fingerprinting.javascript.sourcemap.parser import parse_source_map
from techspecter.parser.sourcemap import detect_source_map_url

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class JavaScriptIntelligenceConfig:
    """Configuration for the JavaScript intelligence engine."""

    max_bytes: int = 5_242_880
    fetch_source_maps: bool = True
    source_map_timeout: float = 10.0
    collector_name: str = "javascript-intelligence"


@dataclass
class JavaScriptIntelligenceEngine:
    """Production-grade passive JavaScript intelligence engine."""

    parser: JavaScriptParser = field(default_factory=TokenJavaScriptParser)
    cache: ParseCache = field(default_factory=get_parse_cache)
    config: JavaScriptIntelligenceConfig = field(default_factory=JavaScriptIntelligenceConfig)

    def analyze_resource(
        self,
        *,
        url: str,
        filename: str,
        content: str | bytes,
        source_map_url: str | None = None,
    ) -> JavaScriptAnalysisResult:
        """Analyze a single JavaScript resource and return structured findings."""
        started = time.perf_counter()
        errors: list[str] = []

        try:
            normalized = normalize_javascript(content, max_bytes=self.config.max_bytes)
            resource = JavaScriptResource(
                url=url,
                filename=filename,
                content=normalized.content,
                source_map_url=source_map_url,
                content_length=normalized.original_length,
                is_minified=normalized.is_minified,
                parse_strategy=(
                    ParseStrategy.REGEX_FALLBACK if normalized.truncated else ParseStrategy.FULL
                ),
            )
            parsed = self._parse(resource)
            findings = self._extract_all(parsed, resource)
            if self.config.fetch_source_maps:
                findings += self._analyze_source_maps(resource)
        except Exception as exc:
            logger.exception("JavaScript intelligence analysis failed for %s", filename)
            errors.append(str(exc))
            resource = JavaScriptResource(
                url=url,
                filename=filename,
                content=str(content)[:1024] if content else "",
                source_map_url=source_map_url,
            )
            findings = ()

        elapsed_ms = (time.perf_counter() - started) * 1000
        return JavaScriptAnalysisResult(
            resource=resource,
            findings=findings,
            elapsed_ms=elapsed_ms,
            errors=tuple(errors),
        )

    def analyze_to_evidence(
        self,
        *,
        url: str,
        filename: str,
        content: str | bytes,
        source_map_url: str | None = None,
        timestamp: datetime | None = None,
    ) -> tuple[Evidence, ...]:
        """Analyze a resource and return Evidence objects."""
        ts = timestamp or datetime.now(UTC)
        result = self.analyze_resource(
            url=url,
            filename=filename,
            content=content,
            source_map_url=source_map_url,
        )
        items: list[Evidence] = [
            build_script_content_evidence(
                resource=result.resource,
                collector=self.config.collector_name,
                timestamp=ts,
            ),
        ]
        if source_map_url:
            items.append(
                build_source_map_reference_evidence(
                    resource=result.resource,
                    source_map_url=source_map_url,
                    collector=self.config.collector_name,
                    timestamp=ts,
                ),
            )
        items.extend(
            build_evidence(
                findings=result.findings,
                resource=result.resource,
                collector=self.config.collector_name,
                timestamp=ts,
            ),
        )
        return tuple(items)

    def _parse(self, resource: JavaScriptResource) -> ParsedScript:
        """Parse with cache to avoid duplicate work."""
        key = self.cache.cache_key(url=resource.url, content=resource.content)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        parsed = self.parser.parse(resource)
        self.cache.set(key, parsed)
        return parsed

    def _extract_all(
        self,
        parsed: ParsedScript,
        resource: JavaScriptResource,
    ) -> tuple[ExtractionFinding, ...]:
        """Run all extractors and merge findings."""
        content = resource.content
        chunks = (
            extract_banner_findings(resource),
            extract_version_candidates(resource),
            extract_bundle_findings(resource),
            extract_metadata_findings(resource),
            extract_import_export_findings(parsed),
            extract_string_findings(parsed),
            extract_runtime_findings(parsed, content=content),
            extract_package_findings(parsed, content=content),
        )
        merged: list[ExtractionFinding] = []
        for chunk in chunks:
            merged.extend(chunk)
        return tuple(merged)

    def _analyze_source_maps(self, resource: JavaScriptResource) -> tuple[ExtractionFinding, ...]:
        """Fetch and analyze source maps when available."""
        map_url = resource.source_map_url or detect_source_map_url(
            resource.content,
            base_url=resource.url,
        )
        if not map_url:
            return ()

        content = fetch_source_map(map_url, timeout=self.config.source_map_timeout)
        if not content:
            return ()

        parsed = parse_source_map(content)
        if parsed.errors:
            logger.debug("Source map parse errors for %s: %s", map_url, parsed.errors)
        return extract_source_map_findings(source_map_url=map_url, parsed=parsed)
