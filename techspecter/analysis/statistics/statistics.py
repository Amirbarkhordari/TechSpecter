"""Aggregated statistics for analysis results."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class AnalysisStatistics(TechSpecterModel):
    """Statistics calculated from aggregated analysis findings."""

    total_findings: int = 0
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_analyzer: dict[str, int] = Field(default_factory=dict)
    average_confidence: float = 0.0
    highest_confidence: float = 0.0
    scripts_analyzed: int = 0
    analyzers_run: int = 0
