"""Register built-in evidence collectors."""

from __future__ import annotations

from techspecter.fingerprinting.analyzers.bundle import BundleAnalyzer
from techspecter.fingerprinting.analyzers.html import HTMLAnalyzer
from techspecter.fingerprinting.analyzers.javascript import JavaScriptAnalyzer
from techspecter.fingerprinting.analyzers.network import NetworkAnalyzer
from techspecter.fingerprinting.analyzers.package import PackageAnalyzer
from techspecter.fingerprinting.collectors.registry import CollectorRegistry, collector_registry

_BUILTIN_COLLECTORS = (
    NetworkAnalyzer(),
    HTMLAnalyzer(),
    JavaScriptAnalyzer(),
    BundleAnalyzer(),
    PackageAnalyzer(),
)


def register_builtin_collectors(registry: CollectorRegistry | None = None) -> None:
    """Register default evidence collectors."""
    target = registry or collector_registry
    for collector in _BUILTIN_COLLECTORS:
        target.register(collector)


register_builtin_collectors()
