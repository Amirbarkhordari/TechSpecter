# Migration Guide

This guide covers upgrades between TechSpecter versions.

## Upgrading to v1.0.0-rc1

### Version

TechSpecter now uses semantic versioning with centralized version metadata in `techspecter/_version.py` and dynamic packaging via Hatch.

```bash
techspecter --version
# TechSpecter 1.0.0-rc1
```

### Breaking Changes

**None.** v1.0.0-rc1 maintains backward compatibility with 0.7.x CLI commands, APIs, and report formats.

### New Features

- `techspecter doctor` — installation and environment diagnostics
- `--quiet` CLI flag for minimal output
- Performance configuration (`performance.*`) wired to caching and parallel analyzers
- Performance and execution sections in analysis reports
- SBOM generation tooling (`tools/generate_sbom.py`)

### Configuration

New optional `performance` and `logging.quiet` fields use safe defaults. Existing configuration files require no changes.

### Tests and Imports

```python
from techspecter import __version__, version_display

assert __version__ == "1.0.0rc1"
assert version_display() == "1.0.0-rc1"
```

### From 0.6.x / 0.7.x

1. Update your installation: `pip install -U techspecter` (or reinstall from source)
2. Run `techspecter doctor` to verify the environment
3. Re-run your existing commands — behavior is unchanged
4. Optionally enable performance tuning in configuration

## Upgrading from Pre-0.6 Fingerprint-Only Usage

If you used TechSpecter primarily for `fingerprint`:

- `techspecter fingerprint` continues to work unchanged
- Consider `techspecter analyze` for HTTP and artifact intelligence
- Reports support both legacy technology sections and generic findings

## Plugin Authors

- Minimum core version for new plugins: `1.0.0rc1`
- Use `PluginMetadata.minimum_core_version` compatible with PEP 440
- See [PLUGIN_SDK.md](PLUGIN_SDK.md)

## Reporting Integrations

SARIF, JSON, and Markdown exporters remain compatible. New report sections (execution summary, timing) are additive.

## Getting Help

See [SUPPORT.md](../SUPPORT.md) and [CHANGELOG.md](../CHANGELOG.md).
