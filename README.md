# TechSpecter

[![CI](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TechSpecter** is a professional, cross-platform **Passive Web Application Analysis Framework**. It discovers and analyzes publicly accessible web resources to identify technologies, metadata, and other observable artifacts — without performing active security testing or exploitation.

---

## Vision

TechSpecter aims to become the go-to open-source toolkit for **passive** web application intelligence — combining technology fingerprinting, HTTP observation, metadata extraction, and structured reporting into a single, extensible analysis platform that works seamlessly on **Windows** and **Linux**.

TechSpecter analyzes only resources it downloads itself. It does **not** perform vulnerability scanning, penetration testing, brute force, port scanning, or any form of active exploitation.

---

## Features

| Capability | Status |
|---|---|
| Generic analysis framework | ✅ Phase 4.5 |
| Analyzer pipeline with finding aggregation | ✅ Phase 4.5 |
| Modular plugin architecture | ✅ Phase 1 |
| Cross-platform CLI | ✅ Phase 1 |
| JavaScript discovery & download | ✅ Phase 2 |
| URL validation & resolution | ✅ Phase 2 |
| Async HTTP client with retries | ✅ Phase 2 |
| HTML script parsing | ✅ Phase 2 |
| Source map reference detection | ✅ Phase 2 |
| JavaScript technology fingerprinting | ✅ Phase 3 |
| Version extraction | ✅ Phase 3 |
| Expanded fingerprint database (64 technologies) | ✅ Phase 3B |
| Fingerprint validation tooling | ✅ Phase 3B |
| Enhanced confidence scoring | ✅ Phase 3B |
| Multi-format reporting engine | ✅ Phase 4 |
| HTTP / Header / Cookie analyzers | 🔜 Future |
| Plugin SDK integration | 🔜 Phase 5 |

---

## Current Status

**Phase 4.5 — Generic Analysis Framework** (current, v0.6.0)

TechSpecter now includes a generic passive analysis pipeline with standardized `Finding` models, an `Analyzer` abstraction, result aggregation, and plugin-ready analyzer registration. JavaScript technology fingerprinting runs as the first built-in analyzer. All existing CLI commands, fingerprinting behavior, and reports remain backward compatible.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/DEVELOPER.md](docs/DEVELOPER.md) for details.

---

## Roadmap

### Phase 1 — Project Bootstrap ✅
- Project structure and packaging
- CLI with Typer
- Plugin-friendly architecture
- CI/CD with GitHub Actions
- Initial test suite

### Phase 2 — JavaScript Discovery Engine ✅
- URL validation and normalization
- Async HTTP client with retries
- HTML downloader and script parser
- JavaScript downloader with concurrency control
- Source map reference detection
- `techspecter discover` CLI command

### Phase 3A — JavaScript Fingerprinting Core Engine ✅
- Dedicated `techspecter/fingerprinting/` engine package
- JSON fingerprint database in `techspecter/fingerprints/`
- Signature loader with schema validation
- Multi-matcher fingerprint engine (string, regex, filename, source map, global)
- Version extraction and confidence scoring
- `techspecter fingerprint` CLI command

### Phase 3B — Fingerprint Database & Detection Expansion ✅
- Expanded fingerprint database (64 technologies)
- `FingerprintValidator` for schema and quality checks
- Multi-source version extraction with highest-confidence selection
- Matcher-type confidence weighting and weak-detection filtering
- Structured `PatternEvidence` in detection results
- CLI: `--compact`, `--group-by-category`, `--verbose-output`

### Phase 4 — Reporting Engine ✅
- Dedicated `techspecter/reporting/` package
- `ReportEngine`, `ReportService`, and Pydantic report models
- Exporters: JSON, Markdown, HTML, CSV, SARIF
- CLI: `--format`, `--output`, enhanced console rendering

### Phase 4.5 — Generic Analysis Framework ✅
- `techspecter/analysis/` package with analyzer pipeline
- Standardized `Finding`, `Evidence`, `Severity`, and category models
- `AnalysisService` public API (`run(target)` → `AnalysisResult`)
- `TechnologyFingerprintAnalyzer` as first built-in analyzer
- `ResultAggregator` for multi-analyzer finding merge
- Generic findings in reports with full backward compatibility
- Architecture and developer documentation

### Phase 5 — Plugin SDK & Extended Analyzers
- Plugin SDK integration with analyzer registration
- HTTP, Header, Cookie, Metadata analyzers
- Sensitive artifact and endpoint analyzers
- Custom analyzer authoring via plugins

---

## Installation

### Requirements

- Python 3.11 or later
- pip

### Install from source

```bash
git clone https://github.com/Amirbarkhordari/TechSpecter.git
cd techspecter
pip install -e ".[dev]"
```

### Install runtime dependencies only

```bash
pip install -r requirements.txt
pip install -e .
```

---

## Usage

### Show help

```bash
python -m techspecter --help
python -m techspecter.cli --help
techspecter --help
```

### Show version

```bash
techspecter --version
python -m techspecter --version
```

### Enable debug logging

```bash
techspecter --debug --help
techspecter --verbose discover https://example.com
```

### Discover JavaScript resources

```bash
techspecter discover https://example.com
techspecter discover example.com --json
techspecter discover https://example.com --verbose
```

The `discover` command:

1. Validates and normalizes the target URL
2. Downloads the HTML document
3. Discovers external and inline JavaScript resources
4. Resolves and deduplicates script URLs
5. Downloads external scripts asynchronously
6. Detects `sourceMappingURL` references (without downloading maps)
7. Displays a summary or JSON output

### Fingerprint JavaScript technologies

```bash
techspecter fingerprint https://example.com
techspecter fingerprint example.com --json
techspecter fingerprint https://example.com --format html --output report.html
techspecter fingerprint https://example.com --format markdown
techspecter fingerprint https://example.com --format sarif --output results.sarif
techspecter fingerprint https://example.com --compact
techspecter fingerprint https://example.com --group-by-category
techspecter fingerprint https://example.com --verbose-output
```

Supported `--format` values: `json`, `markdown`, `html`, `csv`, `sarif`

Legacy `--json` outputs raw analysis results. `--format json` outputs the structured report model.

The `fingerprint` command chains discovery with technology detection:

1. Discovers and downloads JavaScript resources
2. Loads fingerprint signatures from `techspecter/fingerprints/`
3. Runs matcher plugins against each script
4. Extracts version strings when available
5. Calculates confidence scores (0–100)
6. Displays detected technologies or JSON output

---

## Analysis Framework

TechSpecter uses a generic passive analysis pipeline:

```
Target URL → Discovery → Download → Parse → Analysis Pipeline → Aggregation → Reporting
```

### Public API

```python
import asyncio
from techspecter.analysis import AnalysisService

async def main() -> None:
    result = await AnalysisService().run("https://example.com")
    print(result.statistics.total_findings)

asyncio.run(main())
```

### Analyzer Model

Each analyzer exposes metadata (`id`, `name`, `version`, `description`, `category`) and implements `execute(discovery) → findings`.

Built-in analyzers:

| Analyzer | ID |
|---|---|
| Technology Fingerprint Analyzer | `technology-fingerprint` |

Future analyzers (HTTP, Headers, Cookies, Metadata, Endpoint, Sensitive Artifact) will register through the same `AnalyzerRegistry`.

### Finding Model

Every finding includes:

- `id`, `analyzer`, `category`, `title`, `description`
- `severity` (CRITICAL → INFO)
- `confidence` (0–100)
- `evidence`, `location`, `recommendation`, `metadata`

See [docs/DEVELOPER.md](docs/DEVELOPER.md) for analyzer authoring guidance.

---

## Fingerprint Architecture

### Repository Layout

Fingerprint definitions live in `techspecter/fingerprints/` as individual JSON files.
The detection engine lives in `techspecter/fingerprinting/`. Adding a new technology
requires **only a new JSON file** — no Python changes.

```
techspecter/
├── fingerprinting/          # Core engine (loaders, matchers, scoring)
│   ├── engine.py
│   ├── loader.py
│   ├── extractor.py
│   ├── scoring.py
│   ├── service.py
│   └── matchers/
└── fingerprints/            # JSON fingerprint database
    ├── schema.json
    ├── react.json
    ├── vue.json
    └── ...
```

### JSON Schema

Each fingerprint supports:

| Field | Description |
|---|---|
| `id` | Unique technology identifier |
| `name` | Display name |
| `category` | Technology category |
| `website` | Official website |
| `description` | Short description |
| `patterns` | Detection patterns with matcher type and weight |
| `version_patterns` | Regex patterns with capture groups; optional `source` (`inline`, `global`, `metadata`, `sourcemap`, `minified`, `bundle`) |
| `priority` | Match sorting priority |
| `confidence` | Base confidence score |
| `tags` | Optional classification tags |

Pattern matcher types: `string`, `regex`, `filename`, `sourcemap`, `global`

Example pattern:

```json
{
  "matcher": "string",
  "pattern": "React.createElement",
  "weight": 40
}
```

### Detection Pipeline

```
Downloaded JavaScript
        ↓
SignatureLoader (cached)
        ↓
FingerprintEngine
        ↓
Pattern Matchers
        ↓
VersionExtractor
        ↓
ConfidenceScorer
        ↓
DetectionResult
```

### Adding a New Technology

1. Create `techspecter/fingerprints/my-tech.json` following `techspecter/fingerprints/schema.json`
2. Define `patterns` and optional `version_patterns`
3. Run `techspecter fingerprint <url>` — no code changes required

Environment variable `TECHSPECTER_SIGNATURES_DIR` can point to a custom fingerprints directory.

Validate the bundled database:

```python
from techspecter.fingerprinting import FingerprintValidator

report = FingerprintValidator().validate_all()
assert report.is_valid
```

---

## Reporting Architecture

The reporting engine supports both legacy technology reports and generic findings.

```
AnalysisResult / DetectionResult
        ↓
ReportEngine
        ↓
Report (technologies + findings + statistics)
        ↓
Exporter (json | markdown | html | csv | sarif)
```

### Supported Report Formats

| Format | Description |
|---|---|
| `json` | Structured report model with metadata, statistics, and evidence |
| `markdown` | Professional Markdown document for documentation and sharing |
| `html` | Responsive standalone HTML report (pure HTML/CSS template) |
| `csv` | One row per detected technology |
| `sarif` | SARIF 2.1.0 output for CI/CD integration |

### Custom Exporters

Implement `BaseExporter` and register it with `ReportService`:

```python
from techspecter.reporting import ReportService, ReportEngine
from techspecter.reporting.exporters.base import BaseExporter

class MyExporter(BaseExporter):
    format = "json"

    def export(self, report):
        return report.model_dump_json()

service = ReportService(exporters={"json": MyExporter()})
```

---

## Project Architecture

```
TechSpecter/
├── techspecter/           # Main Python package
│   ├── analysis/          # Generic analysis framework (Phase 4.5)
│   ├── core/              # Core interfaces & orchestration
│   ├── crawler/           # Web crawling (Phase 2)
│   ├── downloader/        # HTTP resource fetching (Phase 2)
│   ├── parser/            # Content parsing (Phase 2)
│   ├── fingerprinting/    # Fingerprinting engine (Phase 3A)
│   ├── fingerprints/      # JSON fingerprint database (Phase 3A)
│   ├── reporting/         # Reporting engine (Phase 4)
│   ├── detector/          # Detection service facade
│   ├── report/            # Backward-compatible reporting re-exports
│   ├── models/            # Pydantic data models
│   ├── utils/             # Shared utilities
│   └── plugins/           # Plugin registry & discovery
├── tests/                 # Test suite
├── docs/                  # Architecture & developer documentation
└── .github/workflows/     # CI/CD pipelines
```

### Analysis Architecture

TechSpecter uses an **analyzer registry** pattern. Analyzers implement the `Analyzer` interface and register with `AnalyzerRegistry`. The `AnalysisPipeline` orchestrates discovery and analyzer execution:

```python
from techspecter.analysis import AnalysisPipeline, TechnologyFingerprintAnalyzer

pipeline = AnalysisPipeline(analyzers=[TechnologyFingerprintAnalyzer()])
result = pipeline.analyze_discovery(discovery)
```

Future plugins will register additional analyzers without modifying core code. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Development

### Run tests

```bash
pytest
```

### Run tests with coverage

```bash
pytest --cov=techspecter
```

### Build the package

```bash
pip install build
python -m build
```

---

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started, our code of conduct expectations, and the pull request process.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Acknowledgments

Built with [Typer](https://typer.tiangolo.com/), [Rich](https://rich.readthedocs.io/), [httpx](https://www.python-httpx.org/), [Pydantic](https://docs.pydantic.dev/), and other excellent open-source libraries.
