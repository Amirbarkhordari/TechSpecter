"""JavaScript version detection engine (Phase 6)."""

from techspecter.versioning.engine import VersionDetectionEngine
from techspecter.versioning.models import (
    ExtractedVersion,
    TechnologyVersionResult,
    VersionConfidenceLevel,
    VersionEvidence,
    VersionEvidenceType,
)
from techspecter.versioning.registry import VersionExtractorRegistry
from techspecter.versioning.validator import (
    is_placeholder_version,
    is_valid_version,
    normalize_version,
    validate_and_normalize,
)

__all__ = [
    "ExtractedVersion",
    "TechnologyVersionResult",
    "VersionConfidenceLevel",
    "VersionDetectionEngine",
    "VersionEvidence",
    "VersionEvidenceType",
    "VersionExtractorRegistry",
    "is_placeholder_version",
    "is_valid_version",
    "normalize_version",
    "validate_and_normalize",
]
