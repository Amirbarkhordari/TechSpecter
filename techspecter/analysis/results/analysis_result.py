"""Top-level analysis result models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from techspecter.analysis.models.finding import Finding
from techspecter.analysis.statistics.statistics import AnalysisStatistics
from techspecter.fingerprinting.models import DetectionResult
from techspecter.models.base import TechSpecterModel
from techspecter.models.discovery import DiscoveryResult


class AnalysisMetadata(TechSpecterModel):
    """Metadata describing an analysis run."""

    target_url: str
    tool_name: str = "TechSpecter"
    tool_version: str
    discovery_elapsed_ms: float = 0.0
    analysis_elapsed_ms: float = 0.0
    total_elapsed_ms: float = 0.0
    analyzers: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    extra: dict[str, Any] = Field(default_factory=dict)


class AnalyzerResult(TechSpecterModel):
    """Result produced by a single analyzer execution."""

    analyzer_id: str
    findings: list[Finding] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisResult(TechSpecterModel):
    """Combined output from the passive analysis pipeline."""

    target_url: str
    findings: list[Finding] = Field(default_factory=list)
    statistics: AnalysisStatistics
    metadata: AnalysisMetadata
    discovery: DiscoveryResult | None = None
    detection: DetectionResult | None = None
    analyzer_results: list[AnalyzerResult] = Field(default_factory=list)
    elapsed_ms: float = 0.0
