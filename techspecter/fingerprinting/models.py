"""Pydantic models for fingerprint signatures and detection results."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from techspecter.models.base import TechSpecterModel

MatcherType = Literal["string", "regex", "filename", "sourcemap", "global"]
UNKNOWN_VERSION = "Unknown"


class FingerprintPattern(TechSpecterModel):
    """Single detection pattern within a technology fingerprint."""

    model_config = ConfigDict(extra="allow")

    matcher: MatcherType
    pattern: str
    weight: float = Field(default=10.0, ge=0.0, le=100.0)
    flags: str | None = None


Pattern = FingerprintPattern


class VersionPattern(TechSpecterModel):
    """Regular expression used to extract a technology version string."""

    model_config = ConfigDict(extra="allow")

    pattern: str
    weight: float = Field(default=15.0, ge=0.0, le=100.0)
    flags: str | None = None


class Fingerprint(TechSpecterModel):
    """Technology fingerprint definition loaded from JSON."""

    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    category: str
    website: str | None = None
    description: str | None = None
    patterns: list[FingerprintPattern] = Field(default_factory=list)
    version_patterns: list[VersionPattern] = Field(default_factory=list)
    priority: int = Field(default=50, ge=0)
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)
    tags: list[str] = Field(default_factory=list)


class Technology(TechSpecterModel):
    """Resolved technology metadata derived from a fingerprint."""

    id: str
    name: str
    category: str
    website: str | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)


class TechnologyMatch(TechSpecterModel):
    """A detected technology match for a JavaScript resource."""

    technology: Technology
    version: str = UNKNOWN_VERSION
    confidence: float = Field(ge=0.0, le=100.0)
    matched_patterns: list[str] = Field(default_factory=list)
    source_url: str | None = None
    filename: str | None = None


class DetectionResult(TechSpecterModel):
    """Aggregated fingerprint detection results for a scan target."""

    target_url: str
    matches: list[TechnologyMatch] = Field(default_factory=list)
    scripts_analyzed: int = 0
    elapsed_ms: float = 0.0


class FingerprintAnalysisResult(TechSpecterModel):
    """Combined discovery and fingerprint analysis output."""

    target_url: str
    discovery_elapsed_ms: float = 0.0
    detection: DetectionResult
    elapsed_ms: float = 0.0
