"""Benchmark framework models."""

from __future__ import annotations

from pydantic import Field

from techspecter.models.base import TechSpecterModel


class BenchmarkMetrics(TechSpecterModel):
    """Detection benchmark metrics."""

    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    version_accuracy: float = 0.0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    coverage: int = 0
    explainability_score: float = 0.0


class CompetitorComparison(TechSpecterModel):
    """Comparison against a competitor baseline."""

    name: str
    precision: float
    recall: float
    coverage: int
    notes: str = ""


class BenchmarkSampleResult(TechSpecterModel):
    """Result for one regression/benchmark sample."""

    sample_id: str
    expected: tuple[str, ...]
    detected: tuple[str, ...]
    false_positives: tuple[str, ...] = Field(default_factory=tuple)
    false_negatives: tuple[str, ...] = Field(default_factory=tuple)
    version_matches: dict[str, bool] = Field(default_factory=dict)


class BenchmarkReport(TechSpecterModel):
    """Aggregated benchmark report."""

    metrics: BenchmarkMetrics
    samples: tuple[BenchmarkSampleResult, ...] = Field(default_factory=tuple)
    comparisons: tuple[CompetitorComparison, ...] = Field(default_factory=tuple)
    signature_count: int = 0
    category_coverage: dict[str, int] = Field(default_factory=dict)
