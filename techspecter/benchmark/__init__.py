"""Benchmark & Validation subsystem for TechSpecter vs Wappalyzer comparison."""

from techspecter.benchmark.models import (
    BenchmarkStatistics,
    ComparisonReport,
    GapRecommendation,
    NormalizedScanResult,
    NormalizedTechnology,
)

__all__ = [
    "BenchmarkStatistics",
    "ComparisonReport",
    "GapRecommendation",
    "NormalizedScanResult",
    "NormalizedTechnology",
]


def __getattr__(name: str) -> object:
    """Lazy-load runner to avoid importing fingerprint services at package import."""
    if name == "BenchmarkRunner":
        from techspecter.benchmark.runner import BenchmarkRunner

        return BenchmarkRunner
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
