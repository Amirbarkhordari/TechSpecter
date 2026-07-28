# Configuration Guide

TechSpecter uses a layered configuration model:

```
Defaults → File (YAML/JSON) → Environment → CLI overrides
```

## Configuration File

```bash
techspecter --config examples/config/techspecter.yaml analyze https://example.com
```

See [examples/config/techspecter.yaml](../examples/config/techspecter.yaml) for a annotated sample.

## Environment Variables

All variables use the `TECHSPECTER_` prefix with nested keys separated by `__`:

```bash
export TECHSPECTER_LOGGING__LEVEL=DEBUG
export TECHSPECTER_PERFORMANCE__PARALLEL_ANALYZERS=true
export TECHSPECTER_ANALYSIS__MIN_CONFIDENCE=50
```

## Sections

| Section | Purpose |
|---|---|
| `crawler` | Discovery and redirect behavior |
| `downloader` | HTTP timeouts, retries, concurrency |
| `analysis` | Global analyzer enablement |
| `http_analysis` | HTTP/header/cookie analyzers |
| `metadata_analysis` | HTML meta, robots, sitemap, well-known |
| `artifact_analysis` | Cloud, identity, API, sensitive artifacts |
| `reporting` | Export formats and output paths |
| `logging` | Console/file logging, quiet mode |
| `performance` | Caching and parallel execution |
| `plugins` | Plugin directories and enable/disable lists |

## Performance Tuning

```yaml
performance:
  cache_enabled: true
  cache_artifact_extraction: true
  cache_plugin_manager: true
  parallel_analyzers: false
  max_analyzer_workers: 4
  max_cache_entries: 128
  max_regex_cache_size: 512
```

Enable parallel analyzers only when analyzers are independent and deterministic output ordering is acceptable.

## Logging

```yaml
logging:
  level: INFO
  console: true
  debug: false
  quiet: false
  structured: false
```

CLI flags:

- `--debug` / `--verbose` — DEBUG logging
- `--quiet` / `-q` — minimal console output

## Export Configuration

```python
from techspecter.configuration.manager import ConfigurationManager

manager = ConfigurationManager.load()
print(manager.export())
manager.export("active-config.yaml")
```

## Validation

Invalid configuration raises `ConfigurationError` at startup with descriptive messages.

See [DEVELOPER.md](DEVELOPER.md) for programmatic access patterns.
