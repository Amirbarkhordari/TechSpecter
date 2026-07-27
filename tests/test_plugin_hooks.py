"""Tests for plugin hooks."""

from __future__ import annotations

from techspecter.plugins.hooks import HookContext, HookName, HookRegistry


def test_hook_registry_runs_callbacks_in_order() -> None:
    """Verify hook callbacks execute in registration order."""
    registry = HookRegistry()
    calls: list[str] = []

    def first(context: HookContext) -> None:
        calls.append("first")

    def second(context: HookContext) -> None:
        calls.append("second")

    registry.register(HookName.BEFORE_ANALYSIS, first, plugin_id="p1")
    registry.register(HookName.BEFORE_ANALYSIS, second, plugin_id="p2")
    registry.run(HookName.BEFORE_ANALYSIS, HookContext(hook=HookName.BEFORE_ANALYSIS))
    assert calls == ["first", "second"]


def test_hook_registry_isolates_failures() -> None:
    """Verify one failing hook does not stop remaining hooks."""
    registry = HookRegistry()
    calls: list[str] = []

    def failing(context: HookContext) -> None:
        raise RuntimeError("hook failed")

    def success(context: HookContext) -> None:
        calls.append("ok")

    registry.register(HookName.AFTER_DISCOVERY, failing, plugin_id="bad")
    registry.register(HookName.AFTER_DISCOVERY, success, plugin_id="good")
    registry.run(HookName.AFTER_DISCOVERY)
    assert calls == ["ok"]


def test_manager_run_hook() -> None:
    """Verify manager executes hooks through run_hook."""
    from techspecter.plugins.manager import PluginManager

    manager = PluginManager()
    calls: list[str] = []

    def callback(context: HookContext) -> None:
        calls.append(context.hook.value)

    manager.hooks.register(HookName.BEFORE_REPORTING, callback, plugin_id="test")
    manager.run_hook(HookName.BEFORE_REPORTING, target_url="https://example.com")
    assert calls == ["before_reporting"]


def test_hook_registry_unregister_and_list() -> None:
    """Verify hook registry supports unregister and listing."""
    from techspecter.plugins.hooks import HookRegistry

    registry = HookRegistry()

    def callback(context: HookContext) -> None:
        return None

    registry.register(HookName.BEFORE_EXPORT, callback, plugin_id="demo")
    assert len(registry.list_hooks()) == 1
    registry.unregister_plugin("demo")
    assert registry.list_hooks() == ()
    registry.clear()
