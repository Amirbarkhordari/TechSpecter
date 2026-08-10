"""Version attribution confirmation helpers (Phase 6 Step 1 foundation)."""

from __future__ import annotations

from techspecter.versioning.models import (
    VersionAttributionState,
    VersionOwnershipClass,
)
from techspecter.versioning.ownership import (
    VersionOwnershipAssessment,
    ownership_supports_confirmation,
)


def confirm_or_keep_candidate(
    assessment: VersionOwnershipAssessment,
    *,
    version_confidence: float,
) -> VersionAttributionState:
    """Decide whether a version candidate may become a confirmed attribution.

    Technology confidence is intentionally independent of this decision. Strong
    technology detection does not automatically confirm a version.
    """
    _ = version_confidence
    if ownership_supports_confirmation(assessment):
        return VersionAttributionState.CONFIRMED
    if assessment.ownership_class in {
        VersionOwnershipClass.INCIDENTAL,
        VersionOwnershipClass.UNKNOWN,
    }:
        return VersionAttributionState.REJECTED
    return VersionAttributionState.CANDIDATE


def independent_confidence_axes(
    *,
    technology_confidence: float | None,
    version_confidence: float,
    ownership_confidence: float,
) -> dict[str, float | None]:
    """Expose independent confidence axes for attribution diagnostics."""
    return {
        "technology_confidence": technology_confidence,
        "version_confidence": version_confidence,
        "ownership_confidence": ownership_confidence,
    }
