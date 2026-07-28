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
| `logging` | Console/file logging, structured output, quiet mode |
| `performance` | Rule caching, regex compilation, analysis cache, parallel analyzers |
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
techspecter plugins doctor --load
techspecter plugins info
```

## Passive HTTP Analysis

Phase 6 introduces production-ready passive HTTP analyzer plugins. Every analyzer is shipped as an independent plugin under `techspecter.plugins.builtin.http`.

### Architecture

1. Discovery captures HTTP metadata into `DiscoveryResult.http_response` (`HttpResponseObservation`).
2. Built-in analyzer plugins register through `PluginManager.load_plugins(load_builtins=True)`.
3. `AnalysisPipeline` collects analyzers via `PluginManager.collect_analyzers()` and filters them with `AnalysisConfig` and `HttpAnalysisConfig`.
4. Each analyzer extends `PassiveHttpAnalyzer` and emits normalized `Finding` objects through `build_http_finding()`.
5. `ReportEngine.generate_from_analysis()` adds HTTP-focused report sections.

### Built-in HTTP Analyzer Plugins

| Analyzer ID | Plugin ID |
|---|---|
| `http-header-analyzer` | `http-header-analyzer-plugin` |
| `security-header-analyzer` | `security-header-analyzer-plugin` |
| `cookie-analyzer` | `cookie-analyzer-plugin` |
| `csp-analyzer` | `csp-analyzer-plugin` |
| `cors-analyzer` | `cors-analyzer-plugin` |
| `cache-control-analyzer` | `cache-control-analyzer-plugin` |
| `content-type-analyzer` | `content-type-analyzer-plugin` |
| `server-fingerprint-analyzer` | `server-fingerprint-analyzer-plugin` |
| `redirect-analyzer` | `redirect-analyzer-plugin` |
| `http-response-metadata-analyzer` | `http-response-metadata-analyzer-plugin` |

### Finding Generation

HTTP analyzers should use `build_http_finding()` so every finding includes:

- unique `id`
- `analyzer` id
- `category`, `title`, `description`
- `severity`, `confidence`, `recommendation`
- `evidence`
- `metadata.source` and optional `metadata.references`

### Configuration

```yaml
http_analysis:
  enabled: true
  http_analysis: true
  headers: true
  cookies: true
  security_headers: true
  redirects: true
  analyzers:
    cookie-analyzer:
      enabled: true

analysis:
  disabled_analyzers:
    - redirect-analyzer
```

### CLI Usage

```bash
techspecter analyze https://example.com
techspecter analyze https://example.com --headers --cookies
techspecter analyze https://example.com --security-headers --redirects
techspecter analyze https://example.com --disable-analyzer cookie-analyzer
techspecter analyze https://example.com --json
```

### Extension Points

- Implement `PassiveHttpAnalyzer` for new passive HTTP analyzers.
- Wrap the analyzer in an `AnalyzerPlugin` and export `plugin`.
- Place the plugin module under a configured plugin directory or register an entry point in `techspecter.plugins`.
- Use pipeline hooks (`before_analysis`, `after_analysis`) for cross-cutting behavior.

## Passive Metadata & Well-Known Resource Analysis

Phase 6 Part 2 extends passive analysis with metadata and well-known resource intelligence. Every analyzer is an independent plugin under `techspecter.plugins.builtin.metadata`.

### Architecture

1. Discovery parses HTML metadata via `HtmlMetadataParser` and collects well-known resources through `WellKnownResourceCollector` (fixed public paths and HTML-linked resources only — no brute force).
2. Results are stored on `DiscoveryResult.metadata_observation` (`MetadataDiscoveryObservation`).
3. Metadata analyzers extend `PassiveMetadataAnalyzer` and emit findings via `build_metadata_finding()`.
4. `ReportEngine.generate_from_analysis()` adds metadata report sections via `build_metadata_report_sections()`.

### Built-in Metadata Analyzer Plugins (24)

| Category | Analyzer IDs |
|---|---|
| Well-known | `robots-analyzer`, `sitemap-analyzer`, `security-txt-analyzer`, `humans-txt-analyzer`, `ads-txt-analyzer`, `assetlinks-analyzer`, `apple-app-site-association-analyzer` |
| Manifest | `manifest-analyzer`, `web-app-manifest-analyzer`, `browserconfig-analyzer` |
| HTML metadata | `html-metadata-analyzer`, `html-comment-analyzer`, `opengraph-analyzer`, `twitter-card-analyzer`, `canonical-link-analyzer`, `alternate-link-analyzer`, `generator-meta-analyzer`, `theme-color-analyzer`, `application-metadata-analyzer`, `language-analyzer`, `favicon-analyzer` |
| Framework/PWA | `framework-metadata-analyzer`, `service-worker-analyzer`, `sourcemap-analyzer` |

### Configuration

```yaml
metadata_analysis:
  enabled: true
  metadata_analysis: true
  well_known: true
  manifest: true
  robots: true
  sitemap: true
  security_txt: true
  html_meta: true
  framework_meta: true
  sourcemaps: true
  service_workers: true
  analyzers:
    robots-analyzer:
      enabled: true
```

### CLI Usage

```bash
techspecter metadata https://example.com
techspecter metadata https://example.com --robots --sitemap --security-txt
techspecter metadata https://example.com --html-meta --framework-meta
techspecter metadata https://example.com --sourcemaps --service-workers
techspecter metadata https://example.com --disable-analyzer html-comment-analyzer
techspecter metadata https://example.com --json
```

### Extension Points

- Implement `PassiveMetadataAnalyzer` for new passive metadata analyzers.
- Extend `HtmlMetadataParser` to extract additional normalized fields.
- Add well-known resource types to `WELL_KNOWN_PATHS` in `metadata_collector.py` (fixed paths only).
- Wrap analyzers in `AnalyzerPlugin` modules under `techspecter.plugins.builtin.metadata`.

## Passive Cloud, Identity & API Artifact Analysis

Phase 7 Part 1 extends passive analysis with cloud, identity, API, and third-party artifact intelligence. Every analyzer is an independent plugin under `techspecter.plugins.builtin.artifact`.

### Architecture

1. Discovery collects HTTP responses, HTML metadata, well-known resources, and script content (Phase 6).
2. `ArtifactExtractor` scans **already-collected** data only — no new HTTP requests, no validation, no brute force.
3. Extracted indicators are stored on `DiscoveryResult.artifact_observation` (`ArtifactDiscoveryObservation`).
4. Artifact analyzers extend `PassiveArtifactAnalyzer` and emit findings via `build_artifact_finding()`.
5. `ReportEngine.generate_from_analysis()` adds artifact report sections via `build_artifact_report_sections()`.

### Built-in Artifact Analyzer Plugins (15)

| Category | Analyzer IDs |
|---|---|
| Identity / Tokens | `api-key-analyzer`, `jwt-analyzer`, `oauth-metadata-analyzer`, `openid-connect-analyzer` |
| API | `graphql-metadata-analyzer`, `openapi-analyzer` |
| Cloud | `firebase-analyzer`, `aws-metadata-analyzer`, `azure-metadata-analyzer`, `google-cloud-metadata-analyzer`, `cdn-analyzer` |
| Third-party | `third-party-service-analyzer`, `analytics-service-analyzer`, `monitoring-service-analyzer` |
| Technology | `technology-exposure-analyzer` |

### Configuration

```yaml
artifact_analysis:
  enabled: true
  artifact_analysis: true
  cloud_analysis: true
  identity_analysis: true
  graphql: true
  openapi: true
  firebase: true
  oauth: true
  third_party: true
  analytics: true
  monitoring: true
  min_confidence: 0.0
  severity_threshold: INFO
  analyzers:
    jwt-analyzer:
      enabled: true
      min_confidence: 50.0
```

### CLI Usage

```bash
techspecter artifacts https://example.com
techspecter artifacts https://example.com --cloud-analysis --identity-analysis
techspecter artifacts https://example.com --graphql --openapi
techspecter artifacts https://example.com --firebase --oauth
techspecter artifacts https://example.com --third-party --analytics --monitoring
techspecter artifacts https://example.com --disable-analyzer jwt-analyzer
techspecter artifacts https://example.com --json
```

### Extension Points

- Implement `PassiveArtifactAnalyzer` or `TypedArtifactAnalyzer` for new passive artifact analyzers.
- Add detection patterns to `ArtifactExtractor` in `extractor.py` (passive pattern matching only).
- Wrap analyzers in `AnalyzerPlugin` modules under `techspecter.plugins.builtin.artifact`.

## Passive Secret, Configuration & Build Artifact Analysis

Phase 7 Part 2 extends artifact intelligence with secret pattern detection, configuration/build/debug/backup artifact analysis, classification, and risk prioritization.

### Architecture

1. `ArtifactExtractor` collects cloud/identity/API indicators (Part 1).
2. `SensitiveArtifactExtractor` scans the same collected data for secrets, configuration, build, debug, and backup patterns.
3. `ClassificationEngine` maps references to standard exposure buckets.
4. `RiskEngine` assigns passive severity, confidence, and risk level (no CVSS, no exploitation claims).
5. Twelve additional analyzers extend `PassiveArtifactAnalyzer` under `techspecter.plugins.builtin.artifact`.

### Built-in Sensitive Artifact Analyzer Plugins (12)

| Category | Analyzer IDs |
|---|---|
| Secrets | `secret-pattern-analyzer` |
| Configuration | `configuration-artifact-analyzer`, `environment-artifact-analyzer`, `client-configuration-analyzer` |
| Build / Debug / Backup | `build-artifact-analyzer`, `debug-artifact-analyzer`, `backup-artifact-analyzer` |
| Source / Dev / Infra | `source-artifact-analyzer`, `development-artifact-analyzer`, `infrastructure-metadata-analyzer` |
| Classification | `exposure-classification-analyzer`, `risk-classification-analyzer` |

### Configuration

```yaml
artifact_analysis:
  sensitive_analysis: true
  secret_analysis: true
  config_analysis: true
  build_analysis: true
  debug_analysis: true
  backup_analysis: true
  classification: true
  risk_summary: true
  entropy_threshold: 3.5
  min_confidence: 0.0
```

### CLI Usage

```bash
techspecter sensitive https://example.com
techspecter sensitive https://example.com --secret-analysis --config-analysis
techspecter sensitive https://example.com --build-analysis --debug-analysis --backup-analysis
techspecter sensitive https://example.com --classification --risk-summary
techspecter artifacts https://example.com --secret-analysis --risk-summary
techspecter sensitive https://example.com --json
```

### Extension Points

- Add passive patterns to `SensitiveArtifactExtractor` (never validate secrets).
- Extend `ClassificationEngine` mapping for new artifact types.
- Extend `RiskEngine` severity rules for new classifications.
- Implement `CategoryArtifactAnalyzer` subclasses for new analyzers.

## Performance Architecture (Phase 8)

TechSpecter includes production hardening for RC readiness without changing the passive analysis architecture.

### Execution Flow

```
DiscoveryPipeline
        ↓
Artifact enrichment (cached when enabled)
        ↓
AnalyzerExecutor (sequential or parallel)
        ↓
ResultAggregator
        ↓
ReportEngine (+ performance sections)
```

### Caching

| Cache | Location | Purpose |
|---|---|---|
| Rule cache | `RuleLoader` + `RuleCache` | Avoid reloading YAML/JSON rules |
| Regex cache | `RegexCache` (shared) | Reuse compiled patterns |
| Analysis cache | `AnalysisCache` | Cache artifact extraction per discovery fingerprint |
| Plugin manager | `get_shared_plugin_manager()` | Load built-in plugins once per process |

Configure via `performance` in YAML/JSON or environment overrides:

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

### Parallel Analyzers

When `performance.parallel_analyzers` is `true`, analyzers run in a `ThreadPoolExecutor`. Results remain ordered deterministically by analyzer registration order.

### CLI UX

- `--quiet` / `-q` — minimal output (one-line summary)
- `--verbose` / `--debug` — detailed logging and full error messages
- Analysis summaries include discovery/analysis timing and slowest analyzer

### Reporting

Analysis metadata includes `timing`, `cache`, `performance`, and `plugins` in `metadata.extra`. Reports add execution, timing, performance, plugin, and finding statistics sections.

### Migration Notes

- No breaking API changes; new configuration fields use safe defaults.
- Existing configs without `performance` extensions continue to work.
- Parallel analyzers are opt-in (`parallel_analyzers: false` by default).

## Related Documentation

- [Plugin SDK Guide](PLUGIN_SDK.md)
- [Architecture Overview](ARCHITECTURE.md)
- [README](../README.md)
- [Contributing](../CONTRIBUTING.md)
