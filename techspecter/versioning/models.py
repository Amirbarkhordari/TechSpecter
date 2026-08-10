"""Version detection models and attribution foundation types."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class VersionEvidenceType(StrEnum):
    """How a version string was obtained."""

    BANNER = "banner"
    RUNTIME_CONSTANT = "runtime_constant"
    METADATA = "metadata"
    PACKAGE_IDENTIFIER = "package_identifier"
    PACKAGE_MANIFEST = "package_manifest"
    FRAMEWORK_OBJECT = "framework_object"
    BUILD_METADATA = "build_metadata"
    SOURCE_MAP = "source_map"
    ASSET_FILENAME = "asset_filename"
    TECHNOLOGY_MARKER = "technology_marker"
    REFERENCE = "reference"
    GENERIC_LITERAL = "generic_literal"
    UNKNOWN = "unknown"


class VersionConfidenceLevel(StrEnum):
    """Human-readable confidence band."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VersionOwnershipClass(StrEnum):
    """Whether version evidence is attributable to a technology."""

    OWNED = "owned"
    ASSOCIATED = "associated"
    INCIDENTAL = "incidental"
    UNKNOWN = "unknown"


class VersionAttributionState(StrEnum):
    """Lifecycle state of a version observation."""

    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class VersionConflictClass(StrEnum):
    """Conflict classification for technology-scoped version resolution."""

    NO_CONFLICT = "no_conflict"
    WEAK_ALTERNATE = "weak_alternate"
    STRONG_CONFLICT = "strong_conflict"
    AMBIGUOUS = "ambiguous"
    WEAK_ONLY = "weak_only"


class VersionEvidence(TechSpecterModel):
    """Evidence supporting a detected version."""

    evidence_type: VersionEvidenceType
    matched_value: str
    pattern: str | None = None
    source_url: str | None = None
    filename: str | None = None
    snippet: str | None = None
    ownership_class: VersionOwnershipClass = VersionOwnershipClass.UNKNOWN
    ownership_confidence: float = Field(default=0.0, ge=0.0, le=100.0)


class ExtractedVersion(TechSpecterModel):
    """A version extracted from JavaScript content (still a candidate until confirmed)."""

    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    confidence_level: VersionConfidenceLevel
    method: VersionEvidenceType
    evidence: list[VersionEvidence] = Field(default_factory=list)
    extractor_id: str
    source_url: str | None = None
    filename: str | None = None
    technology_id: str | None = None
    version_confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    ownership_confidence: float = Field(default=95.0, ge=0.0, le=100.0)
    ownership_class: VersionOwnershipClass = VersionOwnershipClass.OWNED
    attribution_state: VersionAttributionState = VersionAttributionState.CANDIDATE
    matched_pattern: str | None = None
    matched_value: str | None = None
    asset_id: str | None = None
    evidence_id: str | None = None


class TechnologyVersionResult(TechSpecterModel):
    """Best version outcome for one technology after confirmation policy."""

    technology_id: str
    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    confidence_level: VersionConfidenceLevel
    method: VersionEvidenceType
    reason: str
    evidence: list[VersionEvidence] = Field(default_factory=list)
    candidates_considered: int = 0
    rejected_candidates: list[str] = Field(default_factory=list)
    attribution_state: VersionAttributionState = VersionAttributionState.CONFIRMED
    ownership_confidence: float = Field(default=95.0, ge=0.0, le=100.0)
    ownership_class: VersionOwnershipClass = VersionOwnershipClass.OWNED
    version_confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    alternate_versions: list[str] = Field(default_factory=list)
    conflict_class: str | None = None
