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

# SSR / hydration markers that establish framework identity.
_SSR_MARKER_TO_FAMILY: dict[str, str] = {
    "next-data-ssr": "next.js",
    "nuxt-ssr": "nuxt",
}


class HTMLAnalyzer(EvidenceCollector):
    """Collect HTML-derived script and framework marker evidence."""

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
        """Collect script references and structured HTML technology markers."""
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

        html_meta = (
            discovery.metadata_observation.html
            if discovery.metadata_observation is not None
            else None
        )
        if html_meta is not None:
            page_url = html_meta.url or target_url
            if html_meta.generator:
                items.append(
                    Evidence(
                        source=EvidenceSource.HTML,
                        evidence_type=EvidenceType.HTML_MARKER,
                        collector=self.name,
                        url=page_url,
                        file=page_url,
                        matched_value=html_meta.generator,
                        matched_pattern="meta[name=generator]",
                        category="html",
                        reason="HTML generator meta tag",
                        confidence_hint=85.0,
                        timestamp=timestamp,
                        metadata={
                            "kind": "generator",
                            "html_family": html_meta.generator.split()[0].lower(),
                        },
                    ),
                )

            for hint in html_meta.framework_hints:
                if hint.lower().startswith("generator:"):
                    continue
                items.append(
                    Evidence(
                        source=EvidenceSource.HTML,
                        evidence_type=EvidenceType.HTML_MARKER,
                        collector=self.name,
                        url=page_url,
                        file=page_url,
                        matched_value=hint,
                        matched_pattern="framework_hint",
                        category="html",
                        reason=f"HTML framework marker '{hint}'",
                        confidence_hint=80.0,
                        timestamp=timestamp,
                        metadata={"kind": "framework_hint", "html_family": hint.lower()},
                    ),
                )

            for indicator in html_meta.ssr_indicators:
                family = _SSR_MARKER_TO_FAMILY.get(indicator)
                if family is None:
                    continue
                items.append(
                    Evidence(
                        source=EvidenceSource.HTML,
                        evidence_type=EvidenceType.HTML_MARKER,
                        collector=self.name,
                        url=page_url,
                        file=page_url,
                        matched_value=indicator,
                        matched_pattern="ssr_indicator",
                        category="html",
                        reason=f"HTML SSR/hydration marker '{indicator}'",
                        confidence_hint=90.0,
                        timestamp=timestamp,
                        metadata={"kind": "ssr_marker", "html_family": family},
                    ),
                )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
