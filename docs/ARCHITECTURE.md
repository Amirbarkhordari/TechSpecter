# TechSpecter Architecture

TechSpecter is a **passive** Web Application Analysis Framework. It downloads and analyzes publicly accessible resources only. It does not perform active security testing, exploitation, or intrusive scanning.

## High-Level Pipeline

```
Target URL
    ↓
Crawler / Discovery
    ↓
Downloader
    ↓
Parser
    ↓
Analysis Pipeline
    ↓
Result Aggregation
    ↓
Reporting
```

Each stage is isolated behind clear interfaces so new analyzers and exporters can be added without modifying the core.

## Package Layout

```
techspecter/
├── analysis/              # Generic analysis framework
├── configuration/         # Centralized configuration framework
├── rules/                 # Generic passive rule engine
│   ├── analyzers/         # Analyzer abstractions and implementations
│   ├── models/            # Finding, Evidence, Severity, Category
│   ├── pipeline/          # AnalysisPipeline orchestration
│   ├── results/           # AnalysisResult, ResultAggregator
│   └── statistics/        # AnalysisStatistics
├── crawler/               # Discovery orchestration
├── downloader/            # HTTP resource fetching
├── parser/                # HTML and source map parsing
├── fingerprinting/        # JavaScript technology fingerprint engine
├── fingerprints/          # JSON fingerprint database
├── reporting/             # Report generation and export
├── plugins/               # Plugin SDK (extensibility)
└── models/                # Shared discovery models
```

## Analysis Framework

### Analyzer

Every analyzer implements the `Analyzer` base class:

| Field / Method | Purpose |
|---|---|
| `metadata.id` | Unique analyzer identifier |
| `metadata.name` | Human-readable name |
| `metadata.version` | Analyzer version |
| `metadata.description` | Capability description |
| `metadata.category` | Analyzer category |
| `execute(discovery)` | Run analysis and return findings |

Analyzers are registered through `AnalyzerRegistry` and executed by `AnalysisPipeline`.

### Finding

All analyzers produce standardized `Finding` objects:

- `id`, `analyzer`, `category`, `title`, `description`
- `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- `confidence` (0–100)
- `evidence`, `location`, `recommendation`, `metadata`

### Evidence

Findings include structured `Evidence` supporting multiple artifact types:

- URL, file, line, column, snippet
- Header, cookie, HTML element, JavaScript location

### Result Aggregation

`ResultAggregator` merges findings from all analyzers, deduplicates by finding ID (keeping the highest confidence), and calculates `AnalysisStatistics`.

## Current Analyzers

| Analyzer | ID | Description |
|---|---|---|
| Technology Fingerprint Analyzer | `technology-fingerprint` | Identifies JavaScript technologies from downloaded scripts |

Future analyzers (HTTP, Headers, Cookies, Metadata, Endpoint, Sensitive Artifact) will plug into the same pipeline without core changes.

## Backward Compatibility

The fingerprinting engine remains unchanged. Existing APIs continue to work:

- `FingerprintService.analyze_url()` — legacy fingerprint entry point
- `DetectionResult` — fingerprint-specific result model
- `ReportEngine.generate(detection)` — technology-centric reports

The new framework wraps existing functionality:

- `AnalysisService.run(target)` → `AnalysisResult`
- `TechnologyFingerprintAnalyzer` converts `DetectionResult` → `Finding`
- `ReportEngine.generate_from_analysis()` supports generic findings while preserving technology report sections

## Plugin Readiness

The architecture is designed for future plugin integration:

- `AnalyzerRegistry` can accept externally registered analyzers
- `AnalysisPipeline.register_analyzer()` adds analyzers at runtime
- Plugin SDK (`techspecter/plugins/`) provides lifecycle, loading, and validation infrastructure

Plugins are not required for the core analysis path today, but the registry and pipeline composition model is in place.

## Reporting

Reports support both legacy technology output and generic findings:

```
AnalysisResult / DetectionResult
        ↓
ReportEngine
        ↓
Report (technologies + findings + statistics)
        ↓
Exporter (json | markdown | html | csv | sarif)
```

Technology findings are mapped to both `ReportTechnology` (backward compatible) and `ReportFinding` (generic).

## Fingerprinting: Knowledge Catalog vs Evidence-Driven Detection

TechSpecter separates **technology knowledge** from **technology detection**:

| Concept | Role |
|---|---|
| **Knowledge catalog** | JSON fingerprints (`techspecter/fingerprints/`) and signature catalog provide patterns, metadata, version rules, and matcher definitions |
| **Evidence collection** | Analyzers observe target assets and emit technology-agnostic `Evidence` |
| **Detection** | Technologies appear in output only when evidence satisfies signature rules |

The registry is **not** a hard whitelist of allowed output technologies. Catalog membership alone never produces a confirmed match. A technology absent from the catalog is not rejected merely for being unknown — it lacks predefined signatures until added. Detection quality gates evaluate **evidence strength**, not catalog membership.

```
Target assets
    ↓
Evidence collection (technology=None)
    ↓
┌──────────────────────────────┬─────────────────────────────┐
│ Fingerprint / signature path │ Candidate discovery path    │
│ (closed-world knowledge)     │ EvidenceIndexer             │
│                              │ → TechnologyCandidate       │
│                              │ → CandidateValidator        │
└──────────────┬───────────────┴──────────────┬──────────────┘
               └──────────────┬───────────────┘
                              ↓
               Evidence-backed TechnologyMatch
                              ↓
               Quality gate + merge
                              ↓
               Technology Intelligence / Reporting
```

**Candidate ≠ confirmed technology.** Only validated candidates with strong structured evidence (package, runtime, import, bundle, CSS, HTML, technology-specific HTTP) become confirmed matches. Generic `STRING_LITERAL` values never generate or confirm technologies by themselves.

### Evidence-driven expansion (Phase 4)

```
Asset
  ↓
Evidence (JS / CSS / HTML / HTTP / source-map / package)
  ↓
Identity discovery (catalog enrichment OR evidence-native id)
  ↓
TechnologyCandidate
  ↓
Multi-source correlation (same technology_id)
  ↓
CandidateValidator + MatchQualityGate
  ↓
Confirmed TechnologyMatch
  ↓
Technology-scoped version + provenance
  ↓
Reporting
```

| Channel | Known identity | Open identity (when structured) |
|---|---|---|
| Package | catalog (e.g. React) | `package:<name>` |
| Runtime | catalog | `runtime:<name>` |
| Bundler | catalog | `bundle:<name>` |
| CSS | catalog | `css:<name>` |
| HTML | catalog | `html:<name>` |
| HTTP | catalog | `http:<product>` |

**Knowledge = enrichment.** Catalog metadata enriches known identities; it is not required for evidence-backed discovery.

**Evidence = detection basis.** Technologies appear only from structured evidence, never from generic keywords, CSS classes (`.btn`, `.container`), HTML tags (`div`), or filenames (`chunk.js`) alone.

**Validation = confirmation boundary.** CandidateValidator and MatchQualityGate remain mandatory for all channels.

### Open package identity (Phase 3)

Structured package evidence can produce identities without a prior catalog entry:

```
PACKAGE_REFERENCE / import / source-map node_modules path
    ↓
normalize package root
    ↓
known in knowledge map? ──yes──► catalog technology (e.g. React)
    │
    no
    ↓
package:<normalized-name>  (evidence-native candidate)
    ↓
CandidateValidator + MatchQualityGate
    ↓
confirmed TechnologyMatch  OR  rejected (candidate-only / noise)
```

Relative imports (`./`, `../`) never become package identities. Ambiguous names (`utils`, `core`, …) require multi-signal evidence before confirmation. Prose, CSS utility classes, path segments (`chunks`, `_next`), and bare filenames are rejected as package identities. Missing catalog metadata does not invalidate evidence-backed discovery.

Asset discovery skips downloading binary/media assets (images, fonts, video, wasm) that cannot contribute text technology evidence.

Each `TechnologyMatch` retains provenance: source file, matcher, matched pattern/value, structured evidence, and optional version attribution scoped per technology.

## Configuration Architecture

TechSpecter uses a layered configuration model managed by `ConfigurationManager`:

```
Defaults → File (YAML/JSON) → Environment → CLI overrides → Validated TechSpecterConfig
```

All runtime components should read from `get_configuration_manager().config`. Legacy code continues to use `get_settings()`, which maps downloader and logging values from the centralized configuration.

## Rule Engine Architecture

The rule engine decouples passive detection logic from analyzer implementations:

```
Rule files
    ↓
RuleLoader (cached)
    ↓
RuleValidator
    ↓
RuleRunner
    ↓
Executors (regex | string | header)
    ↓
Finding
```

Rules are validated for duplicate IDs, severity, confidence bounds, and regex correctness. Regex patterns are compiled once and cached for performance.

Future analyzers will consume rules through the rule runner instead of embedding pattern logic directly.

## Performance Architecture

Phase 8 production hardening adds caching, optional parallel analyzer execution, and execution telemetry without changing the discovery → analysis → reporting flow.

```
AnalysisPipeline
    ↓
AnalysisCache (artifact extraction)
    ↓
AnalyzerExecutor (sequential | ThreadPoolExecutor)
    ↓
PipelineTiming → AnalysisMetadata.extra
    ↓
ReportEngine performance sections
```

Shared resources:

- `techspecter/performance/cache.py` — analysis derivation cache
- `techspecter/performance/executor.py` — concurrent analyzer dispatch
- `techspecter/performance/plugin_cache.py` — shared plugin manager
- `techspecter/rules/shared.py` — shared rule and regex caches

Configuration is controlled through `TechSpecterConfig.performance` and `logging.quiet`.

## Design Principles

- **Passive only** — analyze downloaded public resources
- **SOLID** — single-responsibility analyzers, injectable dependencies
- **Open/closed** — extend via analyzers and plugins, not core edits
- **Backward compatible** — existing CLI commands and tests remain valid
- **Typed** — Pydantic models and full type hints throughout
