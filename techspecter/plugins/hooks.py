"""Pipeline hook system for plugin extensions."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from techspecter.plugins.safety import safe_call

logger = logging.getLogger(__name__)

HookCallback = Callable[["HookContext"], None]


class HookName(StrEnum):
    """Supported pipeline hook points."""

    BEFORE_DISCOVERY = "before_discovery"
    AFTER_DISCOVERY = "after_discovery"
    BEFORE_ANALYSIS = "before_analysis"
    AFTER_ANALYSIS = "after_analysis"
    BEFORE_REPORTING = "before_reporting"
    AFTER_REPORTING = "after_reporting"
    BEFORE_EXPORT = "before_export"
    AFTER_EXPORT = "after_export"


@dataclass(slots=True)
class HookContext:
    """Context passed to pipeline hook callbacks."""

    hook: HookName
    target_url: str | None = None
    plugin_id: str | None = None
    data: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RegisteredHook:
    """Registered hook callback metadata."""

    hook: HookName
    callback: HookCallback
    plugin_id: str | None = None


class HookRegistry:
    """Register and execute pipeline hooks with failure isolation."""

    def __init__(self) -> None:
        """Initialize an empty hook registry."""
        self._hooks: dict[HookName, list[RegisteredHook]] = defaultdict(list)

    def register(
        self,
        hook: HookName,
        callback: HookCallback,
        *,
        plugin_id: str | None = None,
    ) -> None:
        """Register a hook callback."""
        self._hooks[hook].append(
            RegisteredHook(hook=hook, callback=callback, plugin_id=plugin_id),
        )

    def unregister_plugin(self, plugin_id: str) -> None:
        """Remove all hooks registered by a plugin."""
        for hook in HookName:
            self._hooks[hook] = [
                registered for registered in self._hooks[hook] if registered.plugin_id != plugin_id
            ]

    def run(self, hook: HookName, context: HookContext | None = None) -> None:
        """Execute all callbacks for a hook without stopping on failure."""
        hook_context = context or HookContext(hook=hook)
        for registered in list(self._hooks.get(hook, [])):
            safe_call(
                registered.callback,
                hook_context,
                label=f"hook '{hook.value}'",
                plugin_id=registered.plugin_id,
            )

    def list_hooks(self, hook: HookName | None = None) -> tuple[RegisteredHook, ...]:
        """Return immutable registered hooks."""
        if hook is not None:
            return tuple(self._hooks.get(hook, []))
        combined: list[RegisteredHook] = []
        for hook_name in HookName:
            combined.extend(self._hooks.get(hook_name, []))
        return tuple(combined)

    def clear(self) -> None:
        """Remove all registered hooks."""
        self._hooks.clear()
