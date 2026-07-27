"""Typing aliases for plugin developers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

from techspecter.core.interfaces import Plugin as LegacyPlugin
from techspecter.plugins.context import PluginContext
from techspecter.plugins.hooks import HookCallback, HookContext
from techspecter.plugins.interfaces import Plugin
from techspecter.plugins.metadata import PluginMetadata

PluginFactory: TypeAlias = Callable[[], Plugin | LegacyPlugin]
PluginInstance: TypeAlias = Plugin | LegacyPlugin
MetadataOverrides: TypeAlias = dict[str, object]
HookHandler: TypeAlias = HookCallback
LifecycleHandler: TypeAlias = Callable[[PluginContext], None]

__all__ = [
    "HookContext",
    "HookHandler",
    "LifecycleHandler",
    "MetadataOverrides",
    "PluginContext",
    "PluginFactory",
    "PluginInstance",
    "PluginMetadata",
]
