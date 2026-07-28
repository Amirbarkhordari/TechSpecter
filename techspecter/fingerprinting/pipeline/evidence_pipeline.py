"""Evidence collection pipeline for next-generation fingerprinting."""

from __future__ import annotations

import logging
import time

from techspecter.fingerprinting.analyzers.base import EvidenceCollector
from techspecter.fingerprinting.collectors.registry import CollectorRegistry, collector_registry
from techspecter.fingerprinting.evidence.models import Evidence, EvidenceCollection
from techspecter.fingerprinting.pipeline.aggregator import aggregate_evidence
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)


class EvidencePipeline:
    """Collect and aggregate fingerprint evidence without technology detection."""

    def __init__(
        self,
        *,
        registry: CollectorRegistry | None = None,
        collectors: list[EvidenceCollector] | None = None,
    ) -> None:
        """Initialize the evidence pipeline with injectable collectors."""
        self._registry = registry or collector_registry
        self._collectors = collectors

    def collect(self, discovery: DiscoveryResult) -> EvidenceCollection:
        """Collect evidence from all supported collectors and aggregate results."""
        started = time.perf_counter()
        target_url = str(discovery.target.url)
        items: list[Evidence] = []
        collectors = self._resolve_collectors()

        for collector in collectors:
            if not collector.supports(discovery):
                logger.debug("Collector '%s' skipped (unsupported discovery)", collector.name)
                continue
            try:
                result = collector.collect(discovery)
            except Exception:
                logger.exception("Collector '%s' failed", collector.name)
                continue
            if result.errors:
                logger.warning(
                    "Collector '%s' completed with errors: %s",
                    collector.name,
                    "; ".join(result.errors),
                )
            items.extend(result.items)
            logger.info(
                "Collector '%s' produced %d evidence items (%.2f ms)",
                collector.name,
                len(result.items),
                result.elapsed_ms,
            )

        elapsed_ms = (time.perf_counter() - started) * 1000
        collection = aggregate_evidence(
            target_url=target_url,
            items=items,
            elapsed_ms=elapsed_ms,
        )
        logger.info(
            "Evidence collection complete for %s: %d items (%.0f ms)",
            target_url,
            collection.summary.total_items,
            elapsed_ms,
        )
        return collection

    def _resolve_collectors(self) -> list[EvidenceCollector]:
        """Return configured collectors from explicit list or registry."""
        if self._collectors is not None:
            return sorted(self._collectors, key=lambda item: (item.priority, item.name))
        return self._registry.resolve()


# Alias requested by architecture docs; evidence-only in Phase 1.
FingerprintEvidencePipeline = EvidencePipeline
