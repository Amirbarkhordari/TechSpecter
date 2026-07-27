"""Built-in Exposure Classification Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.exposure_classification import (
    ExposureClassificationAnalyzer,
)
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="exposure-classification-analyzer-plugin",
    name="Exposure Classification Analyzer Plugin",
    description="Built-in plugin for passive exposure classification analyzer analysis.",
    analyzer_factory=ExposureClassificationAnalyzer,
)
