"""JavaScript version detection engine (Phase 6)."""

from __future__ import annotations

__all__ = [
    "ExtractedVersion",
    "PrimaryVersionResolution",
    "TechnologyVersionResult",
    "VersionAttributionState",
    "VersionConfidenceLevel",
    "VersionConflictClass",
    "VersionDetectionEngine",
    "VersionEvidence",
    "VersionEvidenceType",
    "VersionExtractorRegistry",
    "VersionOwnershipAssessment",
    "VersionOwnershipClass",
    "classify_version_evidence_ownership",
    "confirm_or_keep_candidate",
    "evidence_owned_by_technology",
    "extracted_versions_to_candidates",
    "independent_confidence_axes",
    "is_placeholder_version",
    "is_valid_version",
    "normalize_version",
    "ownership_supports_confirmation",
    "resolve_extracted_versions",
    "resolve_primary_version",
    "score_version_groups",
    "technology_version_result_from_resolution",
    "validate_and_normalize",
    "version_evidence_relevant",
]

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ExtractedVersion": ("techspecter.versioning.models", "ExtractedVersion"),
    "PrimaryVersionResolution": ("techspecter.versioning.resolution", "PrimaryVersionResolution"),
    "TechnologyVersionResult": ("techspecter.versioning.models", "TechnologyVersionResult"),
    "VersionAttributionState": ("techspecter.versioning.models", "VersionAttributionState"),
    "VersionConfidenceLevel": ("techspecter.versioning.models", "VersionConfidenceLevel"),
    "VersionConflictClass": ("techspecter.versioning.models", "VersionConflictClass"),
    "VersionDetectionEngine": ("techspecter.versioning.engine", "VersionDetectionEngine"),
    "VersionEvidence": ("techspecter.versioning.models", "VersionEvidence"),
    "VersionEvidenceType": ("techspecter.versioning.models", "VersionEvidenceType"),
    "VersionExtractorRegistry": ("techspecter.versioning.registry", "VersionExtractorRegistry"),
    "VersionOwnershipAssessment": ("techspecter.versioning.ownership", "VersionOwnershipAssessment"),
    "VersionOwnershipClass": ("techspecter.versioning.models", "VersionOwnershipClass"),
    "classify_version_evidence_ownership": (
        "techspecter.versioning.ownership",
        "classify_version_evidence_ownership",
    ),
    "confirm_or_keep_candidate": ("techspecter.versioning.attribution", "confirm_or_keep_candidate"),
    "evidence_owned_by_technology": (
        "techspecter.versioning.ownership",
        "evidence_owned_by_technology",
    ),
    "extracted_versions_to_candidates": (
        "techspecter.versioning.adapters",
        "extracted_versions_to_candidates",
    ),
    "independent_confidence_axes": (
        "techspecter.versioning.attribution",
        "independent_confidence_axes",
    ),
    "is_placeholder_version": ("techspecter.versioning.validator", "is_placeholder_version"),
    "is_valid_version": ("techspecter.versioning.validator", "is_valid_version"),
    "normalize_version": ("techspecter.versioning.validator", "normalize_version"),
    "ownership_supports_confirmation": (
        "techspecter.versioning.ownership",
        "ownership_supports_confirmation",
    ),
    "resolve_extracted_versions": (
        "techspecter.versioning.adapters",
        "resolve_extracted_versions",
    ),
    "resolve_primary_version": ("techspecter.versioning.resolution", "resolve_primary_version"),
    "score_version_groups": ("techspecter.versioning.resolution", "score_version_groups"),
    "technology_version_result_from_resolution": (
        "techspecter.versioning.adapters",
        "technology_version_result_from_resolution",
    ),
    "validate_and_normalize": ("techspecter.versioning.validator", "validate_and_normalize"),
    "version_evidence_relevant": ("techspecter.versioning.ownership", "version_evidence_relevant"),
}


def __getattr__(name: str):
    """Lazily resolve exports to avoid circular imports with fingerprinting."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = target
    from importlib import import_module

    value = getattr(import_module(module_name), attr_name)
    globals()[name] = value
    return value
