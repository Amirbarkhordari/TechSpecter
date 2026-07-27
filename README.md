# TechSpecter

[![CI](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TechSpecter** is a professional, cross-platform Web Technology Fingerprinting and JavaScript Intelligence framework. It is designed to help security researchers, penetration testers, and developers identify technologies, libraries, frameworks, vulnerabilities, and sensitive artifacts in modern web applications.

---

## Vision

TechSpecter aims to become the go-to open-source toolkit for deep web application intelligence — combining accurate technology fingerprinting, JavaScript analysis, CVE correlation, secret discovery, and API endpoint mapping into a single, extensible platform that works seamlessly on **Windows** and **Linux**.

---

## Features

| Capability | Status |
|---|---|
| Modular plugin architecture | ✅ Phase 1 |
| Cross-platform CLI | ✅ Phase 1 |
| JavaScript discovery & download | ✅ Phase 2 |
| URL validation & resolution | ✅ Phase 2 |
| Async HTTP client with retries | ✅ Phase 2 |
| HTML script parsing | ✅ Phase 2 |
| Source map reference detection | ✅ Phase 2 |
| JavaScript technology fingerprinting | ✅ Phase 3 |
| Version extraction | ✅ Phase 3 |
| JSON fingerprint repository | ✅ Phase 3 |
| CVE intelligence | 🔜 Phase 4 |
| Secret discovery | 🔜 Phase 4 |
| API endpoint discovery | 🔜 Phase 4 |
| Report generation engine | 🔜 Phase 4 |

---

## Current Status

**Phase 3 — JavaScript Fingerprinting Engine** (current, v0.3.0)

TechSpecter discovers JavaScript resources, downloads them, and identifies technologies using an extensible JSON fingerprint database. Supported capabilities include multi-matcher detection, version extraction, confidence scoring, and CLI-driven analysis with JSON output. CVE matching, secret scanning, and endpoint discovery are not implemented yet.

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

### Phase 3 — JavaScript Fingerprinting Engine ✅
- JSON fingerprint repository (`signatures/`)
- Signature loader with schema validation
- Multi-matcher fingerprint engine (string, regex, filename, source map, global)
- Version extraction and confidence scoring
- `techspecter fingerprint` CLI command

### Phase 4 — Security Intelligence
- CVE correlation engine
- Secret & credential discovery
- API endpoint discovery
- Rich reporting (JSON, HTML, SARIF)
- Plugin marketplace
- Custom signature authoring
- Integration with security tooling (Burp, Nuclei, etc.)

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
techspecter fingerprint https://example.com --verbose
```

The `fingerprint` command chains discovery with technology detection:

1. Discovers and downloads JavaScript resources
2. Loads fingerprint signatures from `signatures/`
3. Runs matcher plugins against each script
4. Extracts version strings when available
5. Calculates confidence scores (0–100)
6. Displays detected technologies or JSON output

---

## Fingerprint Architecture

### Repository Layout

Fingerprint definitions live in the `signatures/` directory as individual JSON files.
Adding a new technology requires **only a new JSON file** — no Python changes.

```
signatures/
├── schema.json      # JSON schema reference
├── react.json
├── vue.json
├── jquery.json
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
| `version_patterns` | Regex patterns with capture groups for versions |
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

1. Create `signatures/my-tech.json` following the schema in `signatures/schema.json`
2. Define `patterns` and optional `version_patterns`
3. Run `techspecter fingerprint <url>` — no code changes required

Environment variable `TECHSPECTER_SIGNATURES_DIR` can point to a custom signatures directory.

---

## Project Architecture

```
TechSpecter/
├── techspecter/           # Main Python package
│   ├── core/              # Core interfaces & orchestration
│   ├── crawler/           # Web crawling (Phase 2)
│   ├── downloader/        # HTTP resource fetching (Phase 2)
│   ├── parser/            # Content parsing (Phase 2)
│   ├── detector/          # Technology detection (Phase 2)
│   ├── fingerprints/      # Signature definitions (Phase 2)
│   ├── report/            # Report generation (Phase 3)
│   ├── models/            # Pydantic data models
│   ├── utils/             # Shared utilities
│   └── plugins/           # Plugin registry & discovery
├── signatures/            # Technology fingerprint signatures
├── tests/                 # Test suite
├── docs/                  # Documentation
└── .github/workflows/     # CI/CD pipelines
```

### Plugin Architecture

TechSpecter uses a **plugin registry** pattern. Future modules (JavaScript Discovery, CVE Intelligence, Secret Discovery, etc.) implement the `Plugin` interface and register themselves without modifying core code:

```python
from techspecter.core.interfaces import Plugin, PluginMetadata, ScanResult
from techspecter.core.context import ScanContext
from techspecter.plugins import registry

class MyPlugin(Plugin):
    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my-plugin",
            version="1.0.0",
            description="Custom analysis plugin",
        )

    def execute(self, context: ScanContext) -> ScanResult:
        return ScanResult(plugin_name="my-plugin")

registry.register(MyPlugin())
```

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
