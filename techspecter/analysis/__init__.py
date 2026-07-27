"""Passive Web Application Analysis Framework."""

from techspecter.analysis.analyzers import (
    Analyzer,
    AnalyzerMetadata,
    AnalyzerRegistry,
    TechnologyFingerprintAnalyzer,
    analyzer_registry,
)
from techspecter.analysis.models import Evidence, Finding, FindingCategory, Severity
from techspecter.analysis.pipeline import AnalysisPipeline
from techspecter.analysis.results import AnalysisMetadata, AnalysisResult, AnalyzerResult, ResultAggregator
from techspecter.analysis.service import AnalysisService
from techspecter.analysis.statistics import AnalysisStatistics

__all__ = [
    "AnalysisMetadata",
    "AnalysisPipeline",
    "AnalysisResult",
    "AnalysisService",
    "AnalysisStatistics",
    "Analyzer",
    "AnalyzerMetadata",
    "AnalyzerRegistry",
    "AnalyzerResult",
    "Evidence",
    "Finding",
    "FindingCategory",
    "ResultAggregator",
    "Severity",
    "TechnologyFingerprintAnalyzer",
    "analyzer_registry",
]
