"""Version extraction confidence scoring."""

from __future__ import annotations

from techspecter.versioning.models import VersionConfidenceLevel, VersionEvidenceType

_METHOD_WEIGHTS: dict[VersionEvidenceType, float] = {
    VersionEvidenceType.RUNTIME_CONSTANT: 95.0,
    VersionEvidenceType.FRAMEWORK_OBJECT: 92.0,
    VersionEvidenceType.PACKAGE_IDENTIFIER: 90.0,
    VersionEvidenceType.PACKAGE_MANIFEST: 89.0,
    VersionEvidenceType.BUILD_METADATA: 88.0,
    VersionEvidenceType.TECHNOLOGY_MARKER: 86.0,
    VersionEvidenceType.METADATA: 85.0,
    VersionEvidenceType.BANNER: 80.0,
    VersionEvidenceType.SOURCE_MAP: 75.0,
    VersionEvidenceType.ASSET_FILENAME: 70.0,
    VersionEvidenceType.REFERENCE: 50.0,
    VersionEvidenceType.GENERIC_LITERAL: 55.0,
    VersionEvidenceType.UNKNOWN: 40.0,
}


def score_method(method: VersionEvidenceType) -> tuple[float, VersionConfidenceLevel]:
    """Return numeric confidence and level for an extraction method."""
    confidence = _METHOD_WEIGHTS.get(method, 60.0)
    if confidence >= 90.0:
        level = VersionConfidenceLevel.HIGH
    elif confidence >= 75.0:
        level = VersionConfidenceLevel.MEDIUM
    else:
        level = VersionConfidenceLevel.LOW
    return confidence, level
