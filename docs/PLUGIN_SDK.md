# Plugin SDK

This document describes the TechSpecter Plugin SDK architecture for developers extending the framework with analyzers, reporters, exporters, and rule packs.

## Overview

The plugin system follows clean architecture principles:

- **Discovery** finds plugin modules from directories, entry points, and built-in packages.
- **Loader** imports plugin instances without touching the registry.
- **Validator** checks metadata, compatibility, and required interfaces.
- **Lifecycle** runs optional initialization and shutdown hooks.
- **Registry** stores registered plugins with immutable metadata snapshots.
- **Manager** orchestrates loading, validation, lifecycle, and contribution collection.

Core application code depends on abstractions (`Plugin`, `PluginRegistry`, `PluginManager`) rather than concrete plugin implementations.

## Plugin Types

| Type | Base Class | Contributes |
|------|------------|-------------|
| Analyzer | `AnalyzerPlugin` | `analyzers()` |
| Reporter | `ReporterPlugin` | `report_engines()` |
| Exporter | `ExporterPlugin` | `exporters()` |
| Rule Pack | `RulePackPlugin` | `rule_directories()` |
| Lifecycle | `LifecyclePlugin` | Lifecycle hooks only |

Future plugin categories can be added by extending `PluginType` and introducing a new base class without redesigning the registry.

## Plugin Metadata

Every SDK plugin exposes immutable metadata through `plugin_metadata`:

```python
from techspecter.plugins import PluginMetadata, PluginType

metadata = PluginMetadata(
    id="example-plugin",
    name="Example Plugin",
    version="1.0.0",
    description="Demonstrates plugin metadata.",
    author="Author",
    homepage="https://example.com",
    license="MIT",
    plugin_type=PluginType.ANALYZER,
    minimum_core_version="0.7.0",
    minimum_python_version="3.11",
)
```

Metadata is frozen at registration time and exposed through `PluginRegistry.metadata_view()`.

## Creating a Plugin

```python
from techspecter.plugins import AnalyzerPlugin, PluginMetadata, PluginType

class ExampleAnalyzerPlugin(AnalyzerPlugin):
    @property
    def plugin_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            id="example-analyzer",
            name="Example Analyzer",
            version="1.0.0",
            description="Adds a custom passive analyzer.",
            plugin_type=PluginType.ANALYZER,
        )

    def analyzers(self):
        return [MyAnalyzer()]

plugin = ExampleAnalyzerPlugin()
```

Export the instance as `plugin` or provide a `create_plugin()` factory in the module.

## Lifecycle Hooks

All lifecycle hooks are optional:

| Hook | Purpose |
|------|---------|
| `initialize(context)` | Allocate resources |
| `register(context)` | Register contributions |
| `start(context)` | Start background work |
| `enable(context)` | Re-enable after disable |
| `disable(context)` | Temporarily disable |
| `shutdown(context)` | Begin shutdown |
| `cleanup(context)` | Release resources |

Legacy plugins continue to use `setup()` and `teardown()` through the basic registry API.

## Discovery Sources

`PluginLoader` discovers plugins from:

1. **Built-in package** — `techspecter.plugins.builtin` (opt-in)
2. **Filesystem directories** — configured via `plugins.directories`
3. **Entry points** — group `techspecter.plugins` in `pyproject.toml`
4. **Namespace packages** — future pip-installed plugins

The loader is isolated from the registry. Use `PluginManager.load_plugins()` to load, validate, initialize, and register plugins.

## Configuration

Root configuration supports plugin settings without breaking existing files:

```yaml
plugins:
  enabled: true
  directories:
    - ./plugins
  load_entry_points: true
  disabled_plugins:
    - legacy-plugin
  enabled_plugins: []
  plugins:
    example-plugin:
      enabled: true
      settings:
        mode: fast
```

Environment variables for other sections remain unchanged. Plugin settings are read through `PluginConfiguration.from_plugins_config()`.

## Registry API

| Method | Description |
|--------|-------------|
| `register(plugin)` | Register and validate a plugin |
| `unregister(name)` | Remove a plugin |
| `get(name)` | Retrieve a plugin (raises if missing) |
| `find(name)` | Retrieve a plugin or `None` |
| `exists(name)` | Check registration |
| `list()` | Immutable tuple of plugin IDs |
| `list_by_type(type)` | Filter by `PluginType` |
| `metadata_view()` | Immutable metadata mapping |

## Developer SDK Package

Third-party developers should import from `techspecter.plugins.developer`:

```python
from techspecter.plugins.developer import (
    AnalyzerPlugin,
    MetadataBuilder,
    hook,
    metadata_for,
    plugin,
    validate_plugin,
)
```

Utilities include metadata builders, registration decorators, validation helpers, diagnostics, and typing aliases.

## PluginContext and Services

`PluginContext` is the standard dependency passed into lifecycle methods. Part 2 adds a stable `services` facade:

| Service | Purpose |
|---------|---------|
| `services.version` | Active TechSpecter version |
| `services.configuration` | Read-only configuration manager |
| `services.registry` | Read-only plugin registry |
| `services.manager` | Read-only plugin manager |
| `services.hooks` | Pipeline hook registry |
| `services.create_report_service()` | Report service factory |
| `services.create_analysis_service()` | Analysis service factory |

Existing context fields (`metadata`, `settings`, `resources`, `logger`, `data`) remain unchanged.

## Pipeline Hooks

Plugins can register pipeline hooks through `HookPlugin.register_hooks()` or the `@hook` decorator:

| Hook | When |
|------|------|
| `before_discovery` | Before discovery starts |
| `after_discovery` | After discovery completes |
| `before_analysis` | Before analysis starts |
| `after_analysis` | After analysis completes |
| `before_reporting` | Before report generation |
| `after_reporting` | After report generation |
| `before_export` | Before export |
| `after_export` | After export |

Hook failures are isolated and logged. One failing plugin never stops the pipeline.

## Event System

`PluginManager.events` publishes lifecycle and pipeline events:

- `PluginLoaded`, `PluginEnabled`, `PluginDisabled`, `PluginInitialized`, `PluginShutdown`
- `AnalysisStarted`, `AnalysisCompleted`, `ReportGenerated`, `ExportCompleted`

Subscribe with `EventBus.subscribe()` and publish with `EventBus.publish()`.

## Execution Safety

Use `safe_call()` and `safe_call_or_raise()` from `techspecter.plugins.safety` to isolate plugin failures. Hook and event handlers use these utilities automatically.

## CLI

```bash
techspecter plugins list [--load]
techspecter plugins show <plugin-id> [--load]
techspecter plugins validate [--directory PATH]
techspecter plugins doctor [--load]
techspecter plugins info
```

## Example Plugins

Reference implementations live under `techspecter/plugins/examples/`:

- `example_analyzer_plugin.py`
- `example_reporter_plugin.py`
- `example_rule_pack_plugin.py`

## Best Practices

- Use lowercase kebab-case plugin IDs.
- Declare accurate `minimum_core_version` and `minimum_python_version`.
- Keep lifecycle hooks fast and failure-free.
- Use `PluginContext.services` instead of importing internal modules.
- Follow semantic versioning for plugin releases.

## Version Compatibility

- Match `minimum_core_version` to the lowest TechSpecter version you support.
- Use `validate_plugin()` and `plugins doctor` before publishing.
- Prefer additive changes within the same major plugin version.

## Migration Guidance

Part 2 extends Part 1 without breaking changes:

- Existing plugins continue to work unchanged.
- `PluginContext.services` is optional and populated by `PluginManager`.
- New hooks, events, and diagnostics are opt-in.

## Extension Points

- Register analyzers through `AnalyzerPlugin.analyzers()`
- Register report engines through `ReporterPlugin.report_engines()`
- Register exporters through `ExporterPlugin.exporters()`
- Register rule directories through `RulePackPlugin.rule_directories()`
- Register pipeline hooks through `HookPlugin.register_hooks()`
- Collect contributions via `PluginManager.collect_*()` methods

Pipeline hook execution is available through `PluginManager.run_hook()`. Full pipeline wiring remains a future phase.

## Exceptions

| Exception | When |
|-----------|------|
| `PluginLoadError` | Module import or coercion failure |
| `PluginValidationError` | Invalid metadata or interfaces |
| `PluginCompatibilityError` | Version or platform mismatch |
| `PluginConfigurationError` | Invalid plugin configuration |
| `PluginDependencyError` | Missing plugin dependencies |
| `PluginExecutionError` | Runtime plugin execution failure |
| `PluginRegistrationError` | Registration failure |
| `PluginNotFoundError` | Unknown plugin identifier |

## Backward Compatibility

- Legacy `techspecter.core.interfaces.Plugin` continues to work with `PluginRegistry`.
- Existing `tests/test_plugins.py` scenarios remain valid.
- Root configuration files without plugin extensions load unchanged.
- No existing public APIs were removed or modified incompatibly.
