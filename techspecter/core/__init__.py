"""Core application interfaces and orchestration primitives."""

from techspecter.core.context import ScanContext
from techspecter.core.interfaces import Plugin, PluginMetadata, ScanResult

__all__ = [
    "Plugin",
    "PluginMetadata",
    "ScanContext",
    "ScanResult",
]
