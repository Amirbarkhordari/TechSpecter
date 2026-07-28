"""Provider framework models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from techspecter.fingerprinting.models import UNKNOWN_VERSION, SecurityFinding
from techspecter.models.base import TechSpecterModel


class ProviderHealthState(StrEnum):
    """Health state for a detection provider."""

    AVAILABLE = "available"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class ProviderHealthStatus(TechSpecterModel):
    """Pre-execution health report for a provider."""

    provider_id: str
    display_name: str
    state: ProviderHealthState = ProviderHealthState.UNAVAILABLE
    backend_id: str | None = None
    backend_version: str | None = None
    reason: str | None = None


class ProviderVersionMetadata(TechSpecterModel):
    """Structured version metadata for Phase 6 version intelligence."""

    version: str = UNKNOWN_VERSION
    confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    evidence: list[str] = Field(default_factory=list)
    provider: str
    detection_method: str = "passive"
    location: str | None = None
    raw_version: str | None = None
    is_known: bool = False


class ProviderEvidenceItem(TechSpecterModel):
    """Structured evidence from a single provider."""

    source: str
    category: str
    detail: str
    location: str | None = None
    detection_method: str | None = None


class ProviderMatch(TechSpecterModel):
    """Normalized technology detection from a single provider."""

    technology_id: str
    name: str
    category: str = "unknown"
    version: str = UNKNOWN_VERSION
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)
    evidence: list[str] = Field(default_factory=list)
    evidence_items: list[ProviderEvidenceItem] = Field(default_factory=list)
    provider: str
    detection_method: str = "passive"
    metadata: dict[str, object] = Field(default_factory=dict)
    security_findings: list[SecurityFinding] = Field(default_factory=list)
    version_metadata: ProviderVersionMetadata | None = None


class ProviderDetectionResult(TechSpecterModel):
    """Output from a single detection provider."""

    provider: str
    target_url: str
    matches: list[ProviderMatch] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    success: bool = True
    error: str | None = None
    health: ProviderHealthStatus | None = None
    backend_id: str | None = None
    validation_warnings: list[str] = Field(default_factory=list)


class ProviderTarget(TechSpecterModel):
    """Target context shared across providers."""

    url: str
    discovery: object | None = None


class MergeSummary(TechSpecterModel):
    """Summary of provider merge operations."""

    technologies_merged: int = 0
    providers_succeeded: list[str] = Field(default_factory=list)
    providers_failed: list[str] = Field(default_factory=list)
    evidence_items_total: int = 0
    version_conflicts: int = 0


class UnifiedDetectionResult(TechSpecterModel):
    """Merged multi-provider detection output."""

    target_url: str
    provider_results: list[ProviderDetectionResult] = Field(default_factory=list)
    failed_providers: list[str] = Field(default_factory=list)
    provider_health: list[ProviderHealthStatus] = Field(default_factory=list)
    merge_summary: MergeSummary | None = None
    elapsed_ms: float = 0.0
