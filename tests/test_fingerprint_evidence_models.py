"""Tests for fingerprint evidence models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from techspecter.fingerprinting.evidence.models import (
    Evidence,
    EvidenceCollection,
    EvidenceSource,
    EvidenceType,
    summarize_evidence,
)


def test_evidence_is_immutable() -> None:
    """Evidence instances should be frozen."""
    item = Evidence(
        source=EvidenceSource.HTML,
        evidence_type=EvidenceType.SCRIPT_REFERENCE,
        collector="test",
        url="https://example.com/app.js",
    )
    with pytest.raises(ValidationError):
        item.collector = "other"  # type: ignore[misc]


def test_evidence_collection_summary() -> None:
    """Evidence collections should include aggregated summaries."""
    items = [
        Evidence(
            source=EvidenceSource.HTML,
            evidence_type=EvidenceType.SCRIPT_REFERENCE,
            collector="html-analyzer",
        ),
        Evidence(
            source=EvidenceSource.JAVASCRIPT,
            evidence_type=EvidenceType.SCRIPT_CONTENT,
            collector="javascript-analyzer",
        ),
    ]
    summary = summarize_evidence(items)
    assert summary.total_items == 2
    assert summary.collectors["html-analyzer"] == 1
    assert summary.sources["html"] == 1

    collection = EvidenceCollection(
        target_url="https://example.com/",
        items=tuple(items),
        summary=summary,
    )
    assert collection.summary.total_items == 2


def test_evidence_collection_with_items_updates_summary() -> None:
    """with_items should rebuild summary statistics."""
    base = EvidenceCollection(target_url="https://example.com/")
    updated = base.with_items(
        [
            Evidence(
                source=EvidenceSource.NETWORK,
                evidence_type=EvidenceType.HTTP_HEADER,
                collector="network-analyzer",
            ),
        ],
    )
    assert updated.summary.total_items == 1
