"""Tests for evidence collector registry."""

from __future__ import annotations

from techspecter.fingerprinting.analyzers.network import NetworkAnalyzer
from techspecter.fingerprinting.collectors.registry import CollectorRegistry


def test_registry_registers_and_resolves_by_priority() -> None:
    """Registry should resolve collectors sorted by priority."""
    registry = CollectorRegistry()
    registry.register(NetworkAnalyzer())
    resolved = registry.resolve()
    assert len(resolved) == 1
    assert resolved[0].name == "network-analyzer"


def test_builtin_collectors_are_registered() -> None:
    """Built-in collectors should auto-register on pipeline import."""
    from techspecter.fingerprinting.collectors import collector_registry

    names = collector_registry.list_collectors()
    assert "network-analyzer" in names
    assert "html-analyzer" in names
    assert "javascript-analyzer" in names
    assert "bundle-analyzer" in names
    assert "package-analyzer" in names
