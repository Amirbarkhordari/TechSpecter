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

## CLI

```bash
techspecter plugins list [--load]
techspecter plugins show <plugin-id> [--load]
techspecter plugins validate [--directory PATH]
```

## Extension Points

- Register analyzers through `AnalyzerPlugin.analyzers()`
- Register report engines through `ReporterPlugin.report_engines()`
- Register exporters through `ExporterPlugin.exporters()`
- Register rule directories through `RulePackPlugin.rule_directories()`
- Collect contributions via `PluginManager.collect_*()` methods

Pipeline integration is deferred to future phases. This milestone establishes the SDK foundation only.

## Exceptions

| Exception | When |
|-----------|------|
| `PluginLoadError` | Module import or coercion failure |
| `PluginValidationError` | Invalid metadata or interfaces |
| `PluginCompatibilityError` | Version or platform mismatch |
| `PluginConfigurationError` | Invalid plugin configuration |
| `PluginDependencyError` | Missing plugin dependencies |
| `PluginNotFoundError` | Unknown plugin identifier |

## Backward Compatibility

- Legacy `techspecter.core.interfaces.Plugin` continues to work with `PluginRegistry`.
- Existing `tests/test_plugins.py` scenarios remain valid.
- Root configuration files without plugin extensions load unchanged.
- No existing public APIs were removed or modified incompatibly.
