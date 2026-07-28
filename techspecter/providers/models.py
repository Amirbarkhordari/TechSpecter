"""Provider framework models."""

from __future__ import annotations

from pydantic import Field

from techspecter.fingerprinting.models import UNKNOWN_VERSION, SecurityFinding
from techspecter.models.base import TechSpecterModel


class ProviderMatch(TechSpecterModel):
    """Normalized technology detection from a single provider."""

    technology_id: str
    name: str
    category: str = "unknown"
    version: str = UNKNOWN_VERSION
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)
    evidence: list[str] = Field(default_factory=list)
    provider: str
    detection_method: str = "passive"
    metadata: dict[str, object] = Field(default_factory=dict)
    security_findings: list[SecurityFinding] = Field(default_factory=list)


class ProviderDetectionResult(TechSpecterModel):
    """Output from a single detection provider."""

    provider: str
    target_url: str
    matches: list[ProviderMatch] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    success: bool = True
    error: str | None = None


class ProviderTarget(TechSpecterModel):
    """Target context shared across providers."""

    url: str
    discovery: object | None = None


class UnifiedDetectionResult(TechSpecterModel):
    """Merged multi-provider detection output."""

    target_url: str
    provider_results: list[ProviderDetectionResult] = Field(default_factory=list)
    failed_providers: list[str] = Field(default_factory=list)
    elapsed_ms: float = 0.0
