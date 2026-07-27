"""Tests for artifact analyzer plugin registration."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzer_ids import ARTIFACT_ANALYZER_IDS
from techspecter.plugins.manager import PluginManager


def test_artifact_plugins_register() -> None:
    """Built-in artifact plugins should register all artifact analyzers."""
    manager = PluginManager()
    manager.load_plugins(load_builtins=True)
    analyzer_ids = {analyzer.metadata.id for analyzer in manager.collect_analyzers()}
    for analyzer_id in ARTIFACT_ANALYZER_IDS:
        assert analyzer_id in analyzer_ids
