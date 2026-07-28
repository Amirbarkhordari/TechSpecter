"""Network evidence collector."""

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


class NetworkAnalyzer(EvidenceCollector):
    """Collect HTTP and transport-layer evidence from discovery observations."""

    @property
    def name(self) -> str:
        """Return analyzer identifier."""
        return "network-analyzer"

    @property
    def priority(self) -> int:
        """Run early to capture transport metadata."""
        return 10

    def supports(self, discovery: DiscoveryResult) -> bool:
        """Support discovery results with HTTP observations."""
        return discovery.http_response is not None

    def collect(self, discovery: DiscoveryResult) -> EvidenceResult:
        """Collect header and response metadata evidence."""
        started = time.perf_counter()
        items: list[Evidence] = []
        http = discovery.http_response
        if http is None:
            return EvidenceResult(collector=self.name, elapsed_ms=0.0)

        timestamp = datetime.now(UTC)
        for header, value in http.headers.items():
            items.append(
                Evidence(
                    source=EvidenceSource.NETWORK,
                    evidence_type=EvidenceType.HTTP_HEADER,
                    collector=self.name,
                    url=str(http.final_url or http.url),
                    matched_value=value,
                    matched_pattern=header,
                    category="http",
                    reason=f"Observed response header '{header}'",
                    timestamp=timestamp,
                    metadata={"header": header},
                ),
            )

        items.append(
            Evidence(
                source=EvidenceSource.NETWORK,
                evidence_type=EvidenceType.HTTP_METADATA,
                collector=self.name,
                url=str(http.final_url or http.url),
                matched_value=str(http.status_code),
                category="http",
                reason="Observed HTTP status code",
                timestamp=timestamp,
                metadata={
                    "status_code": http.status_code,
                    "content_type": http.content_type,
                },
            ),
        )

        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvidenceResult(collector=self.name, items=tuple(items), elapsed_ms=elapsed_ms)
