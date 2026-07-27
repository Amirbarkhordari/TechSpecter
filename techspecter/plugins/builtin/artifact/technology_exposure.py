"""Built-in Technology Exposure Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.technology_exposure import TechnologyExposureAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="technology-exposure-analyzer-plugin",
    name="Technology Exposure Analyzer Plugin",
    description="Built-in plugin for passive technology exposure analyzer analysis.",
    analyzer_factory=TechnologyExposureAnalyzer,
)
