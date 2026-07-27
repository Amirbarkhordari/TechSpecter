"""Lightweight plugin event system."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from techspecter.plugins.safety import safe_call

logger = logging.getLogger(__name__)

EventHandler = Callable[["PluginEvent"], None]


@dataclass(slots=True)
class PluginEvent:
    """Base class for plugin and pipeline events."""

    name: ClassVar[str] = "plugin.event"
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    plugin_id: str | None = None
    data: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class PluginLoaded(PluginEvent):
    """Emitted when a plugin is loaded and registered."""

    name: ClassVar[str] = "plugin.loaded"


@dataclass(slots=True)
class PluginEnabled(PluginEvent):
    """Emitted when a plugin is enabled."""

    name: ClassVar[str] = "plugin.enabled"


@dataclass(slots=True)
class PluginDisabled(PluginEvent):
    """Emitted when a plugin is disabled."""

    name: ClassVar[str] = "plugin.disabled"


@dataclass(slots=True)
class PluginInitialized(PluginEvent):
    """Emitted when a plugin completes initialization."""

    name: ClassVar[str] = "plugin.initialized"


@dataclass(slots=True)
class PluginShutdown(PluginEvent):
    """Emitted when a plugin shuts down."""

    name: ClassVar[str] = "plugin.shutdown"


@dataclass(slots=True)
class AnalysisStarted(PluginEvent):
    """Emitted before analysis begins."""

    name: ClassVar[str] = "analysis.started"


@dataclass(slots=True)
class AnalysisCompleted(PluginEvent):
    """Emitted after analysis completes."""

    name: ClassVar[str] = "analysis.completed"


@dataclass(slots=True)
class ReportGenerated(PluginEvent):
    """Emitted when a report is generated."""

    name: ClassVar[str] = "report.generated"


@dataclass(slots=True)
class ExportCompleted(PluginEvent):
    """Emitted when an export completes."""

    name: ClassVar[str] = "export.completed"


class EventBus:
    """Publish and subscribe to plugin events with failure isolation."""

    def __init__(self) -> None:
        """Initialize an empty event bus."""
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, event_type: type[PluginEvent], handler: EventHandler) -> None:
        """Register a handler for an event type."""
        self._handlers[event_type.name].append(handler)

    def unsubscribe(self, event_type: type[PluginEvent], handler: EventHandler) -> None:
        """Remove a handler for an event type."""
        handlers = self._handlers.get(event_type.name, [])
        if handler in handlers:
            handlers.remove(handler)

    def publish(self, event: PluginEvent) -> None:
        """Publish an event to all subscribers without raising on handler failure."""
        for handler in list(self._handlers.get(event.name, [])):
            safe_call(
                handler,
                event,
                label=f"event handler for '{event.name}'",
                plugin_id=event.plugin_id,
            )

    def clear(self) -> None:
        """Remove all event handlers."""
        self._handlers.clear()
