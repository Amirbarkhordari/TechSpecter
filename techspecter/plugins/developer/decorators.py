"""Registration decorators for plugin developers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from techspecter.plugins.developer.metadata_builder import metadata_for
from techspecter.plugins.hooks import HookCallback, HookName, HookRegistry
from techspecter.plugins.interfaces import Plugin
from techspecter.plugins.metadata import PluginType

PluginT = TypeVar("PluginT", bound=Plugin)


def plugin(
    plugin_id: str,
    *,
    name: str | None = None,
    version: str = "1.0.0",
    description: str | None = None,
    plugin_type: PluginType = PluginType.LIFECYCLE,
) -> Callable[[type[PluginT]], type[PluginT]]:
    """Attach default metadata to a plugin class."""

    def decorator(cls: type[PluginT]) -> type[PluginT]:
        built = metadata_for(
            plugin_id,
            name or plugin_id,
            plugin_type=plugin_type,
            version=version,
            description=description,
        )
        cls.plugin_metadata = property(lambda self, metadata=built: metadata)  # type: ignore[misc, assignment]
        abstract_methods = getattr(cls, "__abstractmethods__", None)
        if abstract_methods is not None:
            remaining = set(abstract_methods)
            remaining.discard("plugin_metadata")
            cls.__abstractmethods__ = frozenset(remaining)
        return cls

    return decorator


def hook(
    hook_name: HookName,
    *,
    plugin_id: str | None = None,
) -> Callable[[HookCallback], HookCallback]:
    """Mark a function as a pipeline hook callback."""

    def decorator(callback: HookCallback) -> HookCallback:
        callback._hook_name = hook_name  # type: ignore[attr-defined]
        callback._hook_plugin_id = plugin_id  # type: ignore[attr-defined]
        return callback

    return decorator


def register_hooks(
    plugin: Plugin,
    registry: HookRegistry,
    callbacks: list[HookCallback],
) -> None:
    """Register decorated hook callbacks for a plugin."""
    plugin_identifier = plugin.plugin_metadata.id
    for callback in callbacks:
        hook_name = getattr(callback, "_hook_name", None)
        if hook_name is None:
            continue
        registry.register(
            hook_name,
            callback,
            plugin_id=getattr(callback, "_hook_plugin_id", None) or plugin_identifier,
        )
