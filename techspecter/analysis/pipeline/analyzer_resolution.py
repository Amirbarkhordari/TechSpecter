"""Analysis pipeline wiring for analyzer plugins."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from techspecter.analysis.analyzers.base import Analyzer
from techspecter.analysis.analyzers.technology import TechnologyFingerprintAnalyzer
from techspecter.analysis.artifact.analyzer_ids import ARTIFACT_ANALYZER_IDS
from techspecter.analysis.http.analyzer_ids import HTTP_ANALYZER_IDS
from techspecter.analysis.metadata.analyzer_ids import METADATA_ANALYZER_IDS
from techspecter.configuration.models import (
    AnalysisConfig,
    ArtifactAnalysisConfig,
    HttpAnalysisConfig,
    MetadataAnalysisConfig,
)

if TYPE_CHECKING:
    from techspecter.plugins.manager import PluginManager

logger = logging.getLogger(__name__)


def resolve_analyzers(
    *,
    explicit_analyzers: list[Analyzer] | None,
    plugin_manager: PluginManager | None,
    analysis_config: AnalysisConfig | None,
    http_config: HttpAnalysisConfig | None,
    metadata_config: MetadataAnalysisConfig | None = None,
    artifact_config: ArtifactAnalysisConfig | None = None,
) -> list[Analyzer]:
    """Resolve analyzers from explicit input, plugins, and configuration."""
    config = analysis_config or AnalysisConfig()
    http_settings = http_config or HttpAnalysisConfig()
    metadata_settings = metadata_config or MetadataAnalysisConfig()
    artifact_settings = artifact_config or ArtifactAnalysisConfig()

    if explicit_analyzers is not None:
        return _filter_analyzers(
            explicit_analyzers,
            config,
            http_settings,
            metadata_settings,
            artifact_settings,
        )

    analyzers: list[Analyzer] = []
    if plugin_manager is not None:
        analyzers.extend(plugin_manager.collect_analyzers())

    if config.is_analyzer_enabled("technology-fingerprint"):
        technology = TechnologyFingerprintAnalyzer()
        if not any(item.metadata.id == technology.metadata.id for item in analyzers):
            analyzers.append(technology)

    if not analyzers:
        return [TechnologyFingerprintAnalyzer()]

    return _filter_analyzers(analyzers, config, http_settings, metadata_settings, artifact_settings)


def _filter_analyzers(
    analyzers: list[Analyzer],
    config: AnalysisConfig,
    http_config: HttpAnalysisConfig,
    metadata_config: MetadataAnalysisConfig,
    artifact_config: ArtifactAnalysisConfig,
) -> list[Analyzer]:
    """Filter analyzers using analysis, HTTP, metadata, and artifact configuration."""
    filtered: list[Analyzer] = []
    for analyzer in analyzers:
        analyzer_id = analyzer.metadata.id
        if not config.is_analyzer_enabled(analyzer_id):
            continue
        if analyzer_id in HTTP_ANALYZER_IDS and not http_config.is_analyzer_enabled(analyzer_id):
            continue
        if analyzer_id in METADATA_ANALYZER_IDS and not metadata_config.is_analyzer_enabled(
            analyzer_id
        ):
            continue
        if analyzer_id in ARTIFACT_ANALYZER_IDS and not artifact_config.is_analyzer_enabled(
            analyzer_id
        ):
            continue
        filtered.append(analyzer)
    return filtered
