"""Tests for Phase 8 production hardening."""

from __future__ import annotations

import time
from unittest.mock import patch

from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.analysis.pipeline.pipeline import AnalysisPipeline
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.configuration.manager import ConfigurationManager, set_configuration_manager
from techspecter.configuration.models import AnalysisConfig, PerformanceConfig
from techspecter.models.discovery import DiscoveryResult
from techspecter.performance.cache import AnalysisCache, get_analysis_cache
from techspecter.performance.executor import AnalyzerExecutor
from techspecter.performance.plugin_cache import get_shared_plugin_manager
from techspecter.performance.timing import PipelineTiming
from techspecter.reporting.engine import ReportEngine
from techspecter.reporting.performance_sections import build_performance_report_sections
from techspecter.rules.shared import get_shared_regex_cache
from techspecter.utils.errors import format_user_error
from tests.analysis_fixtures import sample_discovery_result
from tests.artifact_fixtures import sample_artifact_observation


class SlowAnalyzer(Analyzer):
    """Analyzer that sleeps briefly to test parallel execution."""

    def __init__(self, analyzer_id: str, delay: float = 0.05) -> None:
        self._id = analyzer_id
        self._delay = delay

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id=self._id,
            name=self._id,
            version="1.0.0",
            description="Slow test analyzer",
            category=FindingCategory.INFORMATION.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        time.sleep(self._delay)
        finding = Finding(
            id=f"{self._id}:1",
            analyzer=self._id,
            category=FindingCategory.INFORMATION,
            title=self._id,
            description="slow",
            severity=Severity.INFO,
            confidence=50.0,
        )
        return AnalyzerResult(analyzer_id=self._id, findings=[finding])


def test_analysis_cache_tracks_hits_and_misses() -> None:
    """Verify artifact cache records hit/miss statistics."""
    cache = AnalysisCache(enabled=True, max_entries=8)
    key = "artifact:test"
    observation = sample_artifact_observation()

    assert cache.get_artifact_observation(key) is None
    cache.set_artifact_observation(key, observation)
    cached = cache.get_artifact_observation(key)
    assert cached is not None
    stats = cache.stats_summary()
    assert stats["artifact_hits"] == 1
    assert stats["artifact_misses"] == 1


def test_pipeline_does_not_double_enrich_artifacts() -> None:
    """Verify artifact enrichment runs once per analysis."""
    discovery = sample_discovery_result()
    pipeline = AnalysisPipeline(
        analyzers=[],
        analysis_config=AnalysisConfig(),
        load_builtin_plugins=False,
    )

    with patch.object(
        pipeline,
        "_enrich_with_artifacts",
        wraps=pipeline._enrich_with_artifacts,
    ) as enrich:
        pipeline.analyze_discovery(discovery)

    enrich.assert_called_once()


def test_parallel_analyzer_executor_preserves_order() -> None:
    """Verify concurrent analyzers return deterministic ordering."""
    discovery = sample_discovery_result()
    analyzers = [SlowAnalyzer("a"), SlowAnalyzer("b"), SlowAnalyzer("c")]
    executor = AnalyzerExecutor(max_workers=3, parallel=True)

    started = time.perf_counter()
    results = executor.run(analyzers, discovery)
    elapsed = time.perf_counter() - started

    assert [result.analyzer_id for result in results] == ["a", "b", "c"]
    assert elapsed < 0.14


def test_pipeline_records_timing_metadata() -> None:
    """Verify pipeline stores timing metadata for reporting."""
    discovery = sample_discovery_result()
    pipeline = AnalysisPipeline(
        analyzers=[SlowAnalyzer("timing-test", delay=0.0)],
        analysis_config=AnalysisConfig(),
        load_builtin_plugins=False,
    )
    result = pipeline.analyze_discovery(discovery)
    timing = result.metadata.extra.get("timing", {})
    assert isinstance(timing, dict)
    assert "analyzers" in timing.get("stages", {})
    assert "timing-test" in timing.get("analyzer_timings", {})


def test_performance_report_sections_include_execution_summary() -> None:
    """Verify performance sections are generated from analysis metadata."""
    discovery = sample_discovery_result()
    pipeline = AnalysisPipeline(
        analyzers=[SlowAnalyzer("report-test", delay=0.0)],
        analysis_config=AnalysisConfig(),
        load_builtin_plugins=False,
    )
    analysis = pipeline.analyze_discovery(discovery)
    sections = build_performance_report_sections(analysis)
    section_ids = {section.id for section in sections}
    assert "execution-summary" in section_ids
    assert "timing-summary" in section_ids
    assert "finding-statistics" in section_ids

    report = ReportEngine().generate_from_analysis(analysis)
    report_ids = {section.id for section in report.sections}
    assert "execution-summary" in report_ids


def test_shared_regex_cache_reuses_compiled_patterns() -> None:
    """Verify shared regex cache avoids duplicate compilation."""
    cache = get_shared_regex_cache(maxsize=16)
    first = cache.compile(r"example-\d+", 0)
    second = cache.compile(r"example-\d+", 0)
    assert first is second


def test_format_user_error_hides_internals_by_default() -> None:
    """Verify user-facing errors hide internal details unless debug is enabled."""
    exc = RuntimeError("secret internals")
    assert "secret" not in format_user_error(exc, debug=False)
    assert "secret" in format_user_error(exc, debug=True)


def test_pipeline_timing_total_ms() -> None:
    """Verify pipeline timing aggregates stage durations."""
    timing = PipelineTiming()
    with timing.stage("one"):
        pass
    with timing.stage("two"):
        pass
    timing.record_analyzer("test", 12.5)
    metadata = timing.as_metadata()
    assert metadata["total_stage_ms"] >= 0
    assert metadata["analyzer_timings"]["test"] == 12.5


def test_shared_plugin_manager_loads_once() -> None:
    """Verify shared plugin manager reuses loaded plugins."""
    first = get_shared_plugin_manager(load_builtins=False)
    second = get_shared_plugin_manager(load_builtins=False)
    assert first is second


def test_performance_config_applied_to_analysis_cache() -> None:
    """Verify performance configuration controls cache sizing."""
    manager = ConfigurationManager.load(
        cli_overrides={
            "performance": PerformanceConfig(
                cache_enabled=True,
                max_cache_entries=64,
            ).model_dump(mode="python"),
        },
    )
    set_configuration_manager(manager)
    cache = get_analysis_cache(
        enabled=manager.config.performance.cache_enabled,
        max_entries=manager.config.performance.max_cache_entries,
    )
    assert cache.enabled is True
    assert cache.max_entries == 64
