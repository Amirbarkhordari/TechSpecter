"""Evidence aggregation utilities."""

from __future__ import annotations

import logging

from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    summarize_evidence,
)

logger = logging.getLogger(__name__)


def aggregate_evidence(
    *,
    target_url: str,
    items: list[Evidence],
    elapsed_ms: float,
) -> EvidenceCollection:
    """Aggregate evidence items into an immutable collection."""
    summary = summarize_evidence(items)
    logger.debug(
        "Aggregated %d evidence items from %d collectors for %s",
        summary.total_items,
        len(summary.collectors),
        target_url,
    )
    return EvidenceCollection(
        target_url=target_url,
        items=tuple(items),
        summary=summary,
        elapsed_ms=elapsed_ms,
    )
