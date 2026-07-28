"""Passive web application analysis pipeline."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from techspecter import __version__
from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.analyzers.registry import AnalyzerRegistry, analyzer_registry
from techspecter.analysis.artifact.extractor import ArtifactExtractor
from techspecter.analysis.artifact.sensitive_extractor import SensitiveArtifactExtractor
from techspecter.analysis.converters import findings_to_detection_result
from techspecter.analysis.models.finding import Finding
from techspecter.analysis.pipeline.analyzer_resolution import resolve_analyzers
from techspecter.analysis.results.aggregator import ResultAggregator
from techspecter.analysis.results.analysis_result import (
    AnalysisMetadata,
    AnalysisResult,
    AnalyzerResult,
)
from techspecter.configuration.manager import get_configuration_manager
from techspecter.configuration.models import (
    AnalysisConfig,
    ArtifactAnalysisConfig,
    HttpAnalysisConfig,
    MetadataAnalysisConfig,
    PerformanceConfig,
)
from techspecter.crawler.discovery import DiscoveryPipeline, DiscoveryPipelineConfig
from techspecter.fingerprinting.models import DetectionResult
from techspecter.models.discovery import DiscoveryResult
from techspecter.performance.cache import AnalysisCache, get_analysis_cache
from techspecter.performance.executor import AnalyzerExecutor
from techspecter.performance.plugin_cache import get_shared_plugin_manager
from techspecter.performance.timing import PipelineTiming
from techspecter.plugins.hooks import HookName
from techspecter.plugins.manager import PluginManager

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    """Orchestrate discovery and multi-analyzer passive analysis."""

    def __init__(
        self,
        *,
        discovery_pipeline: DiscoveryPipeline | None = None,
        analyzers: list[Analyzer] | None = None,
        analyzer_registry_instance: AnalyzerRegistry | None = None,
        aggregator: ResultAggregator | None = None,
        plugin_manager: PluginManager | None = None,
        analysis_config: AnalysisConfig | None = None,
        http_config: HttpAnalysisConfig | None = None,
        metadata_config: MetadataAnalysisConfig | None = None,
        artifact_config: ArtifactAnalysisConfig | None = None,
        load_builtin_plugins: bool = True,
    ) -> None:
        """Initialize the analysis pipeline."""
        self._discovery_pipeline = discovery_pipeline or DiscoveryPipeline(
            DiscoveryPipelineConfig(collect_metadata=True),
        )
        self._analyzer_registry = analyzer_registry_instance or analyzer_registry
        self._aggregator = aggregator or ResultAggregator()
        self._plugin_manager = plugin_manager
        self._artifact_extractor = ArtifactExtractor()
        self._analysis_config = (
            analysis_config
            if analysis_config is not None or analyzers is None
            else AnalysisConfig()
        )
        self._http_config = (
            http_config if http_config is not None or analyzers is None else HttpAnalysisConfig()
        )
        self._metadata_config = (
            metadata_config
            if metadata_config is not None or analyzers is None
            else MetadataAnalysisConfig()
        )
        self._artifact_config = (
            artifact_config
            if artifact_config is not None or analyzers is None
            else ArtifactAnalysisConfig()
        )
        self._load_builtin_plugins = load_builtin_plugins
        self._analyzers = resolve_analyzers(
            explicit_analyzers=analyzers,
            plugin_manager=self._ensure_plugin_manager(),
            analysis_config=self._resolved_analysis_config(),
            http_config=self._resolved_http_config(),
            metadata_config=self._resolved_metadata_config(),
            artifact_config=self._resolved_artifact_config(),
        )

    async def run(self, target_url: str) -> AnalysisResult:
        """Discover resources and run all configured analyzers."""
        started = time.perf_counter()
        timing = PipelineTiming()
        plugin_manager = self._ensure_plugin_manager()
        if plugin_manager is not None:
            plugin_manager.run_hook(
                HookName.BEFORE_DISCOVERY,
                target_url=target_url,
            )

        with timing.stage("discovery"):
            discovery = await self._discovery_pipeline.run(target_url)
        discovery_elapsed_ms = timing.stages[-1].elapsed_ms if timing.stages else 0.0

        if plugin_manager is not None:
            plugin_manager.run_hook(
                HookName.AFTER_DISCOVERY,
                target_url=target_url,
                data={"discovery": discovery},
            )
            plugin_manager.run_hook(
                HookName.BEFORE_ANALYSIS,
                target_url=target_url,
                data={"discovery": discovery},
            )

        analysis_started = time.perf_counter()
        with timing.stage("artifact_enrichment"):
            enriched_discovery = self._enrich_with_artifacts(discovery)
        with timing.stage("analyzers"):
            analyzer_results = self._run_analyzers(enriched_discovery, timing=timing)
        findings = self._aggregator.aggregate(analyzer_results)
        statistics = self._aggregator.calculate_statistics(
            findings,
            analyzer_results=analyzer_results,
            scripts_analyzed=_scripts_analyzed(analyzer_results),
        )
        analysis_elapsed_ms = (time.perf_counter() - analysis_started) * 1000
        total_elapsed_ms = (time.perf_counter() - started) * 1000

        detection = _extract_detection(analyzer_results, enriched_discovery, findings)
        metadata_extra = _build_metadata_extra(
            timing=timing,
            plugin_manager=plugin_manager,
            performance=self._resolved_performance_config(),
        )
        metadata = AnalysisMetadata(
            target_url=str(enriched_discovery.target.url),
            tool_version=__version__,
            discovery_elapsed_ms=discovery_elapsed_ms,
            analysis_elapsed_ms=analysis_elapsed_ms,
            total_elapsed_ms=total_elapsed_ms,
            analyzers=[result.analyzer_id for result in analyzer_results],
            timestamp=datetime.now(UTC),
            extra=metadata_extra,
        )
        logger.info(
            "Analysis complete for %s: %d findings from %d analyzers (%.0f ms)",
            metadata.target_url,
            len(findings),
            len(analyzer_results),
            total_elapsed_ms,
        )
        result = AnalysisResult(
            target_url=metadata.target_url,
            findings=findings,
            statistics=statistics,
            metadata=metadata,
            discovery=enriched_discovery,
            detection=detection,
            analyzer_results=analyzer_results,
            elapsed_ms=total_elapsed_ms,
        )

        if plugin_manager is not None:
            plugin_manager.run_hook(
                HookName.AFTER_ANALYSIS,
                target_url=metadata.target_url,
                data={"analysis": result},
            )

        return result

    def analyze_discovery(self, discovery: DiscoveryResult) -> AnalysisResult:
        """Run analyzers against an existing discovery result."""
        started = time.perf_counter()
        timing = PipelineTiming()
        plugin_manager = self._ensure_plugin_manager()
        target_url = str(discovery.target.url)
        if plugin_manager is not None:
            plugin_manager.run_hook(
                HookName.BEFORE_ANALYSIS,
                target_url=target_url,
                data={"discovery": discovery},
            )

        with timing.stage("artifact_enrichment"):
            enriched_discovery = self._enrich_with_artifacts(discovery)
        with timing.stage("analyzers"):
            analyzer_results = self._run_analyzers(enriched_discovery, timing=timing)
        findings = self._aggregator.aggregate(analyzer_results)
        statistics = self._aggregator.calculate_statistics(
            findings,
            analyzer_results=analyzer_results,
            scripts_analyzed=_scripts_analyzed(analyzer_results),
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        detection = _extract_detection(analyzer_results, enriched_discovery, findings)
        metadata = AnalysisMetadata(
            target_url=target_url,
            tool_version=__version__,
            analysis_elapsed_ms=elapsed_ms,
            total_elapsed_ms=elapsed_ms,
            analyzers=[result.analyzer_id for result in analyzer_results],
            timestamp=datetime.now(UTC),
            extra=_build_metadata_extra(
                timing=timing,
                plugin_manager=plugin_manager,
                performance=self._resolved_performance_config(),
            ),
        )
        result = AnalysisResult(
            target_url=metadata.target_url,
            findings=findings,
            statistics=statistics,
            metadata=metadata,
            discovery=enriched_discovery,
            detection=detection,
            analyzer_results=analyzer_results,
            elapsed_ms=elapsed_ms,
        )

        if plugin_manager is not None:
            plugin_manager.run_hook(
                HookName.AFTER_ANALYSIS,
                target_url=target_url,
                data={"analysis": result},
            )

        return result

    def register_analyzer(self, analyzer: Analyzer) -> None:
        """Register an analyzer for future pipeline runs."""
        self._analyzer_registry.register(analyzer)
        if analyzer not in self._analyzers:
            self._analyzers.append(analyzer)

    def _run_analyzers(
        self,
        discovery: DiscoveryResult,
        *,
        timing: PipelineTiming | None = None,
    ) -> list[AnalyzerResult]:
        """Execute all configured analyzers with failure isolation."""
        performance = self._resolved_performance_config()
        executor = AnalyzerExecutor(
            max_workers=performance.max_analyzer_workers,
            parallel=performance.parallel_analyzers,
        )
        results = executor.run(self._analyzers, discovery)
        if timing is not None:
            for result in results:
                timing.record_analyzer(result.analyzer_id, result.elapsed_ms)
        return results

    def _enrich_with_artifacts(self, discovery: DiscoveryResult) -> DiscoveryResult:
        """Extract passive artifact observations from collected discovery data."""
        artifact_config = self._resolved_artifact_config()
        if not artifact_config.enabled or not artifact_config.artifact_analysis:
            return discovery
        if discovery.artifact_observation is not None:
            return discovery

        performance = self._resolved_performance_config()
        cache = get_analysis_cache(
            enabled=performance.cache_enabled,
            max_entries=performance.max_cache_entries,
        )
        cache_key = AnalysisCache.discovery_fingerprint(
            target_url=str(discovery.target.url),
            inline_count=len(discovery.inline_scripts),
            download_count=len(discovery.downloads),
            metadata_present=discovery.metadata_observation is not None,
        )
        if performance.cache_artifact_extraction:
            cached = cache.get_artifact_observation(cache_key)
            if cached is not None:
                logger.debug("Using cached artifact observation for %s", discovery.target.url)
                return discovery.model_copy(update={"artifact_observation": cached})

        observation = self._artifact_extractor.extract(discovery)
        if artifact_config.sensitive_analysis:
            sensitive_extractor = SensitiveArtifactExtractor(
                entropy_threshold=artifact_config.entropy_threshold,
            )
            sensitive_refs = sensitive_extractor.extract(discovery)
            merged_sources = list(
                dict.fromkeys([*observation.sources_scanned, *("sensitive",)]),
            )
            observation = observation.model_copy(
                update={
                    "references": observation.references + sensitive_refs,
                    "sources_scanned": merged_sources,
                },
            )
        if performance.cache_artifact_extraction:
            cache.set_artifact_observation(cache_key, observation)
        return discovery.model_copy(update={"artifact_observation": observation})

    def _ensure_plugin_manager(self) -> PluginManager | None:
        """Return a plugin manager with built-in plugins loaded."""
        if self._plugin_manager is not None:
            return self._plugin_manager
        if not self._load_builtin_plugins:
            return None

        performance = self._resolved_performance_config()
        if performance.cache_plugin_manager:
            self._plugin_manager = get_shared_plugin_manager(load_builtins=True)
        else:
            manager = PluginManager()
            manager.load_plugins(load_builtins=True)
            self._plugin_manager = manager
        return self._plugin_manager

    def _resolved_analysis_config(self) -> AnalysisConfig:
        """Return analysis configuration from constructor or global manager."""
        if self._analysis_config is not None:
            return self._analysis_config
        return get_configuration_manager().config.analysis

    def _resolved_http_config(self) -> HttpAnalysisConfig:
        """Return HTTP analysis configuration from constructor or global manager."""
        if self._http_config is not None:
            return self._http_config
        return get_configuration_manager().config.http_analysis

    def _resolved_metadata_config(self) -> MetadataAnalysisConfig:
        """Return metadata analysis configuration from constructor or global manager."""
        if self._metadata_config is not None:
            return self._metadata_config
        return get_configuration_manager().config.metadata_analysis

    def _resolved_artifact_config(self) -> ArtifactAnalysisConfig:
        """Return artifact analysis configuration from constructor or global manager."""
        if self._artifact_config is not None:
            return self._artifact_config
        return get_configuration_manager().config.artifact_analysis

    def _resolved_performance_config(self) -> PerformanceConfig:
        """Return performance configuration from the global manager."""
        return get_configuration_manager().config.performance


def _build_metadata_extra(
    *,
    timing: PipelineTiming,
    plugin_manager: PluginManager | None,
    performance: PerformanceConfig,
) -> dict[str, object]:
    """Build extended metadata for reporting and diagnostics."""
    cache = get_analysis_cache(
        enabled=performance.cache_enabled,
        max_entries=performance.max_cache_entries,
    )
    plugin_summary: dict[str, object] = {}
    if plugin_manager is not None:
        plugin_summary = {
            "loaded_count": len(plugin_manager.registry.list_plugins()),
            "plugin_ids": sorted(plugin_manager.registry.list_plugins()),
        }
    return {
        "timing": timing.as_metadata(),
        "cache": cache.stats_summary(),
        "performance": {
            "parallel_analyzers": performance.parallel_analyzers,
            "max_analyzer_workers": performance.max_analyzer_workers,
            "cache_enabled": performance.cache_enabled,
            "cache_artifact_extraction": performance.cache_artifact_extraction,
            "cache_plugin_manager": performance.cache_plugin_manager,
        },
        "plugins": plugin_summary,
    }


def _extract_detection(
    analyzer_results: list[AnalyzerResult],
    discovery: DiscoveryResult,
    findings: list[Finding],
) -> DetectionResult | None:
    """Extract a detection result from analyzer output for backward compatibility."""
    for result in analyzer_results:
        if result.analyzer_id != "technology-fingerprint":
            continue
        raw_detection = result.metadata.get("detection")
        if isinstance(raw_detection, DetectionResult):
            return raw_detection
        if isinstance(raw_detection, dict):
            return DetectionResult.model_validate(raw_detection)
    technology_findings = [finding for finding in findings if finding.id.startswith("technology:")]
    if not technology_findings:
        return None
    elapsed_ms = next(
        (
            result.elapsed_ms
            for result in analyzer_results
            if result.analyzer_id == "technology-fingerprint"
        ),
        0.0,
    )
    return findings_to_detection_result(
        technology_findings,
        target_url=str(discovery.target.url),
        scripts_analyzed=_scripts_analyzed(analyzer_results),
        elapsed_ms=elapsed_ms,
    )


def _scripts_analyzed(analyzer_results: list[AnalyzerResult]) -> int:
    """Return scripts analyzed count from technology analyzer metadata when available."""
    for result in analyzer_results:
        if result.analyzer_id != "technology-fingerprint":
            continue
        raw_detection = result.metadata.get("detection")
        if isinstance(raw_detection, DetectionResult):
            return raw_detection.scripts_analyzed
        if isinstance(raw_detection, dict):
            return int(raw_detection.get("scripts_analyzed", 0))
    return 0
