"""JavaScript version detection engine (Phase 6)."""

from techspecter.versioning.attribution import (
    confirm_or_keep_candidate,
    independent_confidence_axes,
)
from techspecter.versioning.engine import VersionDetectionEngine
from techspecter.versioning.models import (
    ExtractedVersion,
    TechnologyVersionResult,
    VersionAttributionState,
    VersionConfidenceLevel,
    VersionEvidence,
    VersionEvidenceType,
    VersionOwnershipClass,
)
from techspecter.versioning.ownership import (
    VersionOwnershipAssessment,
    classify_version_evidence_ownership,
    evidence_owned_by_technology,
    ownership_supports_confirmation,
    version_evidence_relevant,
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
    "VersionAttributionState",
    "VersionConfidenceLevel",
    "VersionDetectionEngine",
    "VersionEvidence",
    "VersionEvidenceType",
    "VersionExtractorRegistry",
    "VersionOwnershipAssessment",
    "VersionOwnershipClass",
    "classify_version_evidence_ownership",
    "confirm_or_keep_candidate",
    "evidence_owned_by_technology",
    "independent_confidence_axes",
    "is_placeholder_version",
    "is_valid_version",
    "normalize_version",
    "ownership_supports_confirmation",
    "validate_and_normalize",
    "version_evidence_relevant",
]
