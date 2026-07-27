"""Analysis result models and aggregation."""

from techspecter.analysis.results.aggregator import ResultAggregator
from techspecter.analysis.results.analysis_result import (
    AnalysisMetadata,
    AnalysisResult,
    AnalyzerResult,
)

__all__ = [
    "AnalysisMetadata",
    "AnalysisResult",
    "AnalyzerResult",
    "ResultAggregator",
]
