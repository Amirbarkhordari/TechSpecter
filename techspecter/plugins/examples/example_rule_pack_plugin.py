"""Example rule pack plugin for plugin developers."""

from __future__ import annotations

from pathlib import Path

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import ScanResult
from techspecter.plugins.developer import metadata_for
from techspecter.plugins.interfaces import RulePackPlugin
from techspecter.plugins.metadata import PluginMetadata, PluginType


class ExampleRulePackPlugin(RulePackPlugin):
    """Example plugin that contributes a rule directory."""

    @property
    def plugin_metadata(self) -> PluginMetadata:
        return metadata_for(
            "example-rule-pack-plugin",
            "Example Rule Pack Plugin",
            plugin_type=PluginType.RULE_PACK,
            description="Demonstrates rule pack plugin development.",
        )

    def rule_directories(self) -> list[Path]:
        return [Path(__file__).resolve().parent / "rules"]

    def execute(self, context: ScanContext) -> ScanResult:
        return super().execute(context)


plugin = ExampleRulePackPlugin()
