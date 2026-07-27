# TechSpecter Developer Guide

This guide explains how to work with the TechSpecter Analysis Framework as a developer.

## Quick Start

```python
import asyncio
from techspecter.analysis import AnalysisService

async def main() -> None:
    service = AnalysisService()
    result = await service.run("https://example.com")
    print(f"Findings: {result.statistics.total_findings}")
    for finding in result.findings:
        print(f"- [{finding.severity.value}] {finding.title} ({finding.confidence}%)")

asyncio.run(main())
```

## Public API

### AnalysisService

| Method | Description |
|---|---|
| `run(target)` | Discover and analyze a target URL |
| `analyze_url(target_url)` | Alias for `run()` |
| `analyze_discovery(discovery)` | Run analyzers against an existing `DiscoveryResult` |
| `to_fingerprint_analysis_result(result)` | Convert to legacy `FingerprintAnalysisResult` |
| `detection_from_analysis(result)` | Extract `DetectionResult` from analysis output |

### AnalysisResult

| Field | Description |
|---|---|
| `target_url` | Analyzed target |
| `findings` | Aggregated findings from all analyzers |
| `statistics` | Category, severity, and confidence statistics |
| `metadata` | Tool version, timing, analyzer list |
| `discovery` | Optional discovery result |
| `detection` | Optional fingerprint detection (backward compat) |

## Creating an Analyzer

Implement the `Analyzer` base class:

```python
from techspecter.analysis.analyzers.base import Analyzer, AnalyzerMetadata
from techspecter.analysis.models.finding import Finding, FindingCategory, Severity
from techspecter.analysis.models.evidence import Evidence
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.discovery import DiscoveryResult


class ExampleAnalyzer(Analyzer):
    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="example-analyzer",
            name="Example Analyzer",
            version="1.0.0",
            description="Demonstrates a custom passive analyzer.",
            category=FindingCategory.INFORMATION.value,
        )

    def execute(self, discovery: DiscoveryResult) -> AnalyzerResult:
        findings = [
            Finding(
                id="example:1",
                analyzer=self.metadata.id,
                category=FindingCategory.INFORMATION,
                title="Example Finding",
                description="Demonstrates the finding model.",
                severity=Severity.INFO,
                confidence=50.0,
                evidence=[Evidence(url=str(discovery.target.url))],
            )
        ]
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
```

Register and run:

```python
from techspecter.analysis.pipeline import AnalysisPipeline

pipeline = AnalysisPipeline(analyzers=[ExampleAnalyzer()])
result = pipeline.analyze_discovery(discovery)
```

Or register at runtime:

```python
pipeline = AnalysisPipeline()
pipeline.register_analyzer(ExampleAnalyzer())
```

## Finding Model

```python
Finding(
    id="unique-finding-id",
    analyzer="analyzer-id",
    category=FindingCategory.TECHNOLOGY,
    title="Short title",
    description="Detailed description",
    severity=Severity.INFO,
    confidence=85.0,
    evidence=[Evidence(file="app.js", snippet="pattern")],
    location="https://example.com/app.js",
    recommendation="Optional guidance",
    metadata={"custom": "data"},
)
```

### Severity Levels

`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

### Categories

`Technology`, `HTTP`, `Headers`, `Cookies`, `Metadata`, `Endpoint`, `Sensitive Artifact`, `Configuration`, `Infrastructure`, `Information`, `Custom`

## Reporting

Generate reports from analysis results:

```python
from techspecter.reporting import ReportService

service = ReportService()
report = service.generate_report_from_analysis(result)
export = service.generate_and_export_from_analysis(result, "json")
```

Legacy fingerprint reporting still works:

```python
report = service.generate_report(result.detection)
```

## Testing

Run the full suite:

```bash
pytest
```

Static analysis targets:

```bash
ruff check .
black --check .
mypy techspecter
```

Analysis-specific tests:

- `tests/test_finding_model.py`
- `tests/test_analyzer_base.py`
- `tests/test_analysis_pipeline.py`
- `tests/test_result_aggregator.py`
- `tests/test_analysis_backward_compat.py`

## Constraints

TechSpecter is **passive only**. Analyzers must:

- Operate on resources already downloaded by the framework
- Never perform intrusive or active security testing
- Never attempt exploitation, authentication bypass, or brute force

Future analyzers should classify observations as findings with appropriate severity and confidence, not as vulnerability verdicts unless explicitly scoped to passive information disclosure.

## Configuration Framework

All components read settings from the centralized `ConfigurationManager`:

```python
from techspecter.configuration import ConfigurationManager, get_configuration_manager

manager = ConfigurationManager.load(config_path="techspecter.yaml")
config = manager.config
```

### Configuration Layers

1. Built-in defaults
2. YAML or JSON configuration file
3. Environment variables (`TECHSPECTER_*`)
4. CLI overrides (`--config`, `--min-confidence`, `--disable-analyzer`, etc.)

### Sections

| Section | Purpose |
|---|---|
| `crawler` | Discovery behavior |
| `downloader` | HTTP timeouts, retries, concurrency |
| `analysis` | Analyzer enablement and thresholds |
| `reporting` | Export formats, output directory, theme |
| `logging` | Console/file logging, structured output |
| `performance` | Rule caching and regex compilation |
| `plugins` | Plugin SDK: directories, enable/disable lists, per-plugin settings |
| `analyzers` | Reserved future analyzer directories |

Export the active configuration:

```python
yaml_content = manager.export()
manager.export("active-config.yaml")
```

## Rule Engine

Rules are stored outside Python code in YAML or JSON files under `techspecter/rules/data/` or custom directories.

### Rule Lifecycle

```
Rule files (YAML/JSON)
        ↓
RuleLoader (discovery + cache)
        ↓
RuleValidator
        ↓
RuleRunner
        ↓
Finding
```

### Rule Types

| Type | Executor | Target |
|---|---|---|
| `string` | `StringRuleExecutor` | content, filename, url |
| `regex` | `RegexRuleExecutor` | content, filename, url |
| `header` | `HeaderRuleExecutor` | response headers |

### Example Rule

```yaml
id: example-marker
name: Example Marker
description: Detects a passive marker string.
category: Information Disclosure
severity: INFO
confidence: 40
enabled: true
type: string
pattern: "ExampleMarker"
target: content
recommendation: Review whether the marker should be public.
references:
  - https://example.com/docs
```

### Running Rules

```python
from techspecter.rules import RuleExecutionContext, RuleRunner

context = RuleExecutionContext(
    target_url="https://example.com/app.js",
    content="ExampleMarker",
    headers={"Server": "nginx"},
)
result = RuleRunner(min_confidence=0).run(context)
```

Future analyzers should load rules through `RuleLoader` and execute them with `RuleRunner` rather than hardcoding detection logic.

## Plugin SDK

TechSpecter provides a typed plugin SDK for analyzers, reporters, exporters, and rule packs. See [Plugin SDK Guide](PLUGIN_SDK.md) for architecture, lifecycle, discovery, and extension points.

```bash
techspecter plugins list --load
techspecter plugins show example-plugin --load
techspecter plugins validate --directory ./plugins
```

## Related Documentation

- [Plugin SDK Guide](PLUGIN_SDK.md)
- [Architecture Overview](ARCHITECTURE.md)
- [README](../README.md)
- [Contributing](../CONTRIBUTING.md)
