"""Benchmark & Validation data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from techspecter.models.base import TechSpecterModel

UNKNOWN_VERSION = "Unknown"


class DetectionSource(StrEnum):
    """Origin engine for a normalized detection."""

    TECHSPECTER = "techspecter"
    WAPPALYZER = "wappalyzer"


class NormalizedTechnology(TechSpecterModel):
    """Engine-neutral technology detection record."""

    id: str
    name: str
    category: str = "unknown"
    version: str = UNKNOWN_VERSION
    confidence: float | None = Field(default=None, ge=0.0, le=100.0)
    evidence: list[str] = Field(default_factory=list)
    source: DetectionSource
    raw_metadata: dict[str, object] = Field(default_factory=dict)


class NormalizedScanResult(TechSpecterModel):
    """Normalized scan output from any supported engine."""

    target_url: str
    source: DetectionSource
    technologies: list[NormalizedTechnology] = Field(default_factory=list)
    elapsed_ms: float = 0.0
    scripts_analyzed: int = 0


class VersionComparison(TechSpecterModel):
    """Version comparison for a matched technology."""

    technology_id: str
    technology_name: str
    techspecter_version: str
    wappalyzer_version: str
    status: Literal[
        "match",
        "unknown_techspecter",
        "unknown_wappalyzer",
        "different",
        "both_unknown",
    ]
    reason: str | None = None
    suggested_improvement: str | None = None


class TechnologyComparison(TechSpecterModel):
    """Side-by-side comparison for one technology."""

    technology_id: str
    technology_name: str
    category: str = "unknown"
    detected_by: Literal["both", "techspecter_only", "wappalyzer_only"]
    techspecter: NormalizedTechnology | None = None
    wappalyzer: NormalizedTechnology | None = None
    version_comparison: VersionComparison | None = None
    confidence_delta: float | None = None
    category_match: bool | None = None


class GapRecommendation(TechSpecterModel):
    """Actionable recommendation derived from benchmark gaps."""

    technology_id: str
    technology_name: str
    gap_type: str
    severity: Literal["low", "medium", "high"] = "medium"
    reason: str
    suggested_improvement: str


class BenchmarkStatistics(TechSpecterModel):
    """Aggregated benchmark statistics."""

    technology_precision: float = 0.0
    technology_recall: float = 0.0
    version_match_rate: float = 0.0
    version_accuracy: float = 0.0
    coverage_percent: float = 0.0
    extra_detections: int = 0
    missing_detections: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    matched_technologies: int = 0
    techspecter_total: int = 0
    wappalyzer_total: int = 0
    version_comparisons: int = 0
    version_matches: int = 0


class ComparisonReport(TechSpecterModel):
    """Full TechSpecter vs Wappalyzer comparison report."""

    target_url: str
    techspecter: NormalizedScanResult
    wappalyzer: NormalizedScanResult
    matched: list[TechnologyComparison] = Field(default_factory=list)
    techspecter_only: list[TechnologyComparison] = Field(default_factory=list)
    wappalyzer_only: list[TechnologyComparison] = Field(default_factory=list)
    version_comparisons: list[VersionComparison] = Field(default_factory=list)
    statistics: BenchmarkStatistics = Field(default_factory=BenchmarkStatistics)
    gap_analysis: list[GapRecommendation] = Field(default_factory=list)
    wappalyzer_execution: str = "imported"
    elapsed_ms: float = 0.0
