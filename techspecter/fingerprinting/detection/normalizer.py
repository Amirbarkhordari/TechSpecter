"""Evidence normalization for detection."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from techspecter.fingerprinting.detection.models import NormalizedEvidence
from techspecter.fingerprinting.detection.weights import ScoringWeights
from techspecter.fingerprinting.evidence.models import EvidenceCollection

_WHITESPACE = re.compile(r"\s+")


def normalize_evidence(
    collection: EvidenceCollection,
    *,
    weights: ScoringWeights | None = None,
) -> tuple[NormalizedEvidence, ...]:
    """Normalize evidence items for rule evaluation and scoring."""
    scoring = weights or ScoringWeights()
    normalized: list[NormalizedEvidence] = []
    for item in collection.items:
        value = _normalize_text(item.matched_value or "")
        resource_key = item.file or item.url or "unknown"
        domain_key = _domain_from_url(item.url)
        normalized.append(
            NormalizedEvidence(
                evidence=item,
                normalized_value=value,
                resource_key=resource_key,
                domain_key=domain_key,
                base_weight=scoring.weight_for(item.evidence_type.value),
            ),
        )
    return tuple(normalized)


def _normalize_text(value: str) -> str:
    """Normalize text for case-insensitive matching."""
    return _WHITESPACE.sub(" ", value.strip()).lower()


def _domain_from_url(url: str | None) -> str:
    """Extract domain key from a resource URL."""
    if not url or url.startswith(("inline://", "memory://")):
        return "inline"
    parsed = urlparse(url)
    return parsed.netloc.lower() or "unknown"
