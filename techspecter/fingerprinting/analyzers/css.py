"""CSS evidence collector for fingerprint candidate discovery."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from techspecter.asset_discovery.inventory import inventory_key
from techspecter.asset_discovery.models import AssetCategory
from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.analyzers.css_extract import extract_css_findings
from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceResult,
    EvidenceSource,
    EvidenceType,
)
from techspecter.models.discovery import DiscoveryResult


class CSSAnalyzer(EvidenceCollector):
    """Collect structured CSS technology markers from stylesheet assets."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "css-analyzer"

    @property
    def priority(self) -> int:
        """Run after HTML/JS collectors."""
        return 35

    def supports(self, discovery: DiscoveryResult) -> bool:
        """Support discovery results that may include CSS assets."""
        if discovery.asset_inventory is not None:
            return True
        return any(
            item.download_success and item.content and _looks_like_css(item.filename, item.content_type)
            for item in discovery.downloads
        )

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect CSS marker evidence from downloaded stylesheet bodies."""
        started = time.perf_counter()
        items: list[Evidence] = []
        timestamp = datetime.now(UTC)
        seen_urls: set[str] = set()

        inventory = discovery.asset_inventory
        if inventory is not None:
            for record in inventory.assets:
                if record.category != AssetCategory.CSS:
                    continue
                key = inventory_key(record.url)
                content = inventory.text_bodies.get(key)
                if not content:
                    continue
                if record.url in seen_urls:
                    continue
                seen_urls.add(record.url)
                items.extend(
                    self._findings_to_evidence(
                        content,
                        filename=record.filename,
                        url=record.url,
                        timestamp=timestamp,
                        asset_id=record.asset_id,
                    ),
                )

        for download in discovery.downloads:
            if not download.download_success or not download.content:
                continue
            url = str(download.url)
            if url in seen_urls:
                continue
            if not _looks_like_css(download.filename, download.content_type):
                continue
            seen_urls.add(url)
            items.extend(
                self._findings_to_evidence(
                    download.content,
                    filename=download.filename,
                    url=url,
                    timestamp=timestamp,
                ),
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)

    def _findings_to_evidence(
        self,
        content: str,
        *,
        filename: str,
        url: str,
        timestamp: datetime,
        asset_id: str | None = None,
    ) -> list[Evidence]:
        evidence: list[Evidence] = []
        for finding in extract_css_findings(content, filename=filename):
            metadata = dict(finding.metadata)
            if asset_id:
                metadata["asset_id"] = asset_id
            evidence.append(
                Evidence(
                    source=EvidenceSource.CSS,
                    evidence_type=EvidenceType.CSS_MARKER,
                    collector=self.name,
                    file=filename,
                    url=url,
                    matched_value=finding.matched_value,
                    matched_pattern=finding.matched_pattern,
                    category="css",
                    reason=finding.reason,
                    confidence_hint=finding.confidence_hint,
                    timestamp=timestamp,
                    metadata=metadata,
                ),
            )
        # Structured CDN path markers (e.g. Cloudflare challenge assets).
        if "/cdn-cgi/" in url.replace("\\", "/").lower():
            evidence.append(
                Evidence(
                    source=EvidenceSource.CSS,
                    evidence_type=EvidenceType.CSS_MARKER,
                    collector=self.name,
                    file=filename,
                    url=url,
                    matched_value="/cdn-cgi/",
                    matched_pattern="/cdn-cgi/",
                    category="css",
                    reason="Cloudflare CDN path marker observed on stylesheet URL",
                    confidence_hint=85.0,
                    timestamp=timestamp,
                    metadata={
                        "css_family": "cloudflare",
                        "kind": "cdn_path",
                        **({"asset_id": asset_id} if asset_id else {}),
                    },
                ),
            )
        return evidence


def _looks_like_css(filename: str, content_type: str | None) -> bool:
    lowered = filename.lower()
    if lowered.endswith(".css"):
        return True
    if content_type and "css" in content_type.lower():
        return True
    return False
