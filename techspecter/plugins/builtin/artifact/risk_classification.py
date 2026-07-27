"""Built-in Risk Classification Analyzer Plugin."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.risk_classification import RiskClassificationAnalyzer
from techspecter.plugins.builtin.http._factory import create_analyzer_plugin

plugin = create_analyzer_plugin(
    plugin_id="risk-classification-analyzer-plugin",
    name="Risk Classification Analyzer Plugin",
    description="Built-in plugin for passive risk classification analyzer analysis.",
    analyzer_factory=RiskClassificationAnalyzer,
)
