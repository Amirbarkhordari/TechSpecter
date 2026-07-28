# TechSpecter Examples

Runnable examples and sample assets for documentation and validation.

## Configuration

| File | Description |
|---|---|
| [config/techspecter.yaml](config/techspecter.yaml) | Annotated configuration file |

```bash
techspecter --config examples/config/techspecter.yaml doctor
```

## Sample Reports

| File | Description |
|---|---|
| [reports/sample-analysis-report.json](reports/sample-analysis-report.json) | Minimal report JSON structure |

## Plugin Examples

Built-in plugin examples live in the package:

```
techspecter/plugins/examples/
├── example_analyzer_plugin.py
├── example_reporter_plugin.py
├── example_rule_pack_plugin.py
└── rules/example_rule.yaml
```

Study these when authoring custom plugins. See [docs/PLUGIN_SDK.md](../docs/PLUGIN_SDK.md).

## CLI Examples

```bash
# Diagnostics
techspecter doctor
techspecter doctor --json

# Discovery
techspecter discover https://example.com

# Analysis with report export
techspecter analyze https://example.com --format markdown --output report.md
```

## Python API

```python
import asyncio
from techspecter.analysis import AnalysisService

async def main() -> None:
    result = await AnalysisService().run("https://example.com")
    print(result.statistics.total_findings)

asyncio.run(main())
```
