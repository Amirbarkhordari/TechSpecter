"""JavaScript resource evidence collector."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceResult
from techspecter.fingerprinting.javascript.engine import (
    JavaScriptIntelligenceConfig,
    JavaScriptIntelligenceEngine,
)
from techspecter.models.discovery import DiscoveryResult


class JavaScriptAnalyzer(EvidenceCollector):
    """Collect deep JavaScript intelligence evidence for every script resource."""

    def __init__(
        self,
        *,
        engine: JavaScriptIntelligenceEngine | None = None,
        fetch_source_maps: bool = True,
    ) -> None:
        """Initialize analyzer with injectable intelligence engine."""
        self._engine = engine or JavaScriptIntelligenceEngine(
            config=JavaScriptIntelligenceConfig(
                collector_name=self.name,
                fetch_source_maps=fetch_source_maps,
            ),
        )

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
        """Collect comprehensive JavaScript intelligence evidence."""
        started = time.perf_counter()
        items: list[Evidence] = []
        errors: list[str] = []
        timestamp = datetime.now(UTC)

        for download in discovery.downloads:
            if not download.download_success or not download.content:
                continue
            try:
                items.extend(
                    self._engine.analyze_to_evidence(
                        url=str(download.url),
                        filename=download.filename,
                        content=download.content,
                        source_map_url=download.source_map_url,
                        timestamp=timestamp,
                    ),
                )
            except Exception as exc:
                errors.append(f"{download.filename}: {exc}")

        for inline in discovery.inline_scripts:
            try:
                items.extend(
                    self._engine.analyze_to_evidence(
                        url=f"inline://script/{inline.index}",
                        filename=f"inline-script-{inline.index}.js",
                        content=inline.content,
                        source_map_url=inline.source_map_url,
                        timestamp=timestamp,
                    ),
                )
            except Exception as exc:
                errors.append(f"inline-script-{inline.index}: {exc}")

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(
            collector=self.name,
            items=tuple(items),
            elapsed_ms=elapsed_ms,
            errors=tuple(errors),
        )
