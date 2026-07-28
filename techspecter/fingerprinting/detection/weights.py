"""Configurable evidence type weights for confidence calculation."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.fingerprinting.evidence.models import EvidenceType

DEFAULT_EVIDENCE_WEIGHTS: dict[str, float] = {
    EvidenceType.PACKAGE_REFERENCE.value: 100.0,
    EvidenceType.PACKAGE_MARKER.value: 95.0,
    EvidenceType.MANIFEST.value: 95.0,
    EvidenceType.RUNTIME_PATTERN.value: 90.0,
    EvidenceType.METADATA.value: 85.0,
    EvidenceType.HTML_ELEMENT.value: 80.0,
    EvidenceType.SCRIPT_REFERENCE.value: 80.0,
    EvidenceType.BANNER.value: 80.0,
    EvidenceType.BUNDLE_RUNTIME.value: 70.0,
    EvidenceType.BUNDLE_MARKER.value: 70.0,
    EvidenceType.SOURCE_MAP_METADATA.value: 65.0,
    EvidenceType.IMPORT_EXPORT.value: 60.0,
    EvidenceType.AST_EXTRACTION.value: 55.0,
    EvidenceType.STRING_LITERAL.value: 40.0,
    EvidenceType.FILENAME.value: 50.0,
    EvidenceType.HTTP_HEADER.value: 80.0,
    EvidenceType.HTTP_METADATA.value: 75.0,
    EvidenceType.SOURCE_MAP.value: 60.0,
    EvidenceType.SCRIPT_CONTENT.value: 30.0,
    EvidenceType.VERSION_CANDIDATE.value: 25.0,
    EvidenceType.CUSTOM.value: 20.0,
}

CORRELATION_BONUS_PER_SOURCE: float = 5.0
CORRELATION_BONUS_PER_RESOURCE: float = 3.0
MAX_CORRELATION_BONUS: float = 25.0


@dataclass(frozen=True, slots=True)
class ScoringWeights:
    """Weight configuration for the scoring and confidence engines."""

    evidence_weights: dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_EVIDENCE_WEIGHTS)
    )
    correlation_per_source: float = CORRELATION_BONUS_PER_SOURCE
    correlation_per_resource: float = CORRELATION_BONUS_PER_RESOURCE
    max_correlation_bonus: float = MAX_CORRELATION_BONUS
    weak_evidence_threshold: float = 15.0
    min_detection_confidence: float = 25.0

    def weight_for(self, evidence_type: str) -> float:
        """Return configured weight for an evidence type."""
        return self.evidence_weights.get(evidence_type, 20.0)
