"""Tests for plugin events."""

from __future__ import annotations

from techspecter.plugins.events import EventBus, PluginLoaded
from tests.plugin_fixtures import RecordingLifecyclePlugin


def test_event_bus_publishes_to_subscribers() -> None:
    """Verify event subscribers receive published events."""
    bus = EventBus()
    received: list[str] = []

    def handler(event: PluginLoaded) -> None:
        received.append(event.plugin_id or "")

    bus.subscribe(PluginLoaded, handler)
    bus.publish(PluginLoaded(plugin_id="sample-plugin"))
    assert received == ["sample-plugin"]


def test_event_bus_isolates_handler_failures() -> None:
    """Verify one failing handler does not stop others."""
    bus = EventBus()
    received: list[str] = []

    def failing_handler(event: PluginLoaded) -> None:
        raise RuntimeError("handler failed")

    def success_handler(event: PluginLoaded) -> None:
        received.append("ok")

    bus.subscribe(PluginLoaded, failing_handler)
    bus.subscribe(PluginLoaded, success_handler)
    bus.publish(PluginLoaded(plugin_id="sample-plugin"))
    assert received == ["ok"]


def test_manager_emits_loaded_event() -> None:
    """Verify manager emits plugin loaded events."""
    from unittest.mock import patch

    from techspecter.plugins.manager import PluginManager

    plugin = RecordingLifecyclePlugin()
    manager = PluginManager()
    received: list[str] = []

    def handler(event: PluginLoaded) -> None:
        received.append(event.plugin_id or "")

    manager.events.subscribe(PluginLoaded, handler)
    with patch(
        "techspecter.plugins.manager.PluginLoader",
    ) as loader_cls:
        loader_cls.return_value.load_all.return_value = [plugin]
        loaded = manager.load_plugins(load_entry_points=False)
    assert loaded == ["sample-plugin"]
    assert received == ["sample-plugin"]
    manager.shutdown()


def test_event_bus_unsubscribe_and_clear() -> None:
    """Verify event bus supports unsubscribe and clear."""
    bus = EventBus()
    received: list[str] = []

    def handler(event: PluginLoaded) -> None:
        received.append("called")

    bus.subscribe(PluginLoaded, handler)
    bus.unsubscribe(PluginLoaded, handler)
    bus.publish(PluginLoaded(plugin_id="sample-plugin"))
    assert received == []
    bus.subscribe(PluginLoaded, handler)
    bus.clear()
    bus.publish(PluginLoaded(plugin_id="sample-plugin"))
    assert received == []
