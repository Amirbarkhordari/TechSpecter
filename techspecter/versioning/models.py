"""Version detection models."""

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
    FRAMEWORK_OBJECT = "framework_object"
    BUILD_METADATA = "build_metadata"
    SOURCE_MAP = "source_map"
    GENERIC_LITERAL = "generic_literal"


class VersionConfidenceLevel(StrEnum):
    """Human-readable confidence band."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VersionEvidence(TechSpecterModel):
    """Evidence supporting a detected version."""

    evidence_type: VersionEvidenceType
    matched_value: str
    pattern: str | None = None
    source_url: str | None = None
    filename: str | None = None
    snippet: str | None = None


class ExtractedVersion(TechSpecterModel):
    """A version extracted from JavaScript content."""

    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    confidence_level: VersionConfidenceLevel
    method: VersionEvidenceType
    evidence: list[VersionEvidence] = Field(default_factory=list)
    extractor_id: str
    source_url: str | None = None
    filename: str | None = None


class TechnologyVersionResult(TechSpecterModel):
    """Best version outcome for one technology."""

    technology_id: str
    version: str
    confidence: float = Field(ge=0.0, le=100.0)
    confidence_level: VersionConfidenceLevel
    method: VersionEvidenceType
    reason: str
    evidence: list[VersionEvidence] = Field(default_factory=list)
    candidates_considered: int = 0
    rejected_candidates: list[str] = Field(default_factory=list)
