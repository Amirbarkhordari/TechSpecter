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
    deduped = _dedupe_evidence(items)
    summary = summarize_evidence(deduped)
    logger.debug(
        "Aggregated %d evidence items from %d collectors for %s",
        summary.total_items,
        len(summary.collectors),
        target_url,
    )
    return EvidenceCollection(
        target_url=target_url,
        items=tuple(deduped),
        summary=summary,
        elapsed_ms=elapsed_ms,
    )


def _dedupe_evidence(items: list[Evidence]) -> list[Evidence]:
    """Remove duplicate evidence observations produced by overlapping collectors."""
    seen: set[tuple[str | None, str | None, str, str | None, int | None]] = set()
    deduped: list[Evidence] = []
    for item in items:
        key = (
            item.url,
            item.file,
            item.evidence_type.value,
            item.matched_value,
            item.line_number,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped
