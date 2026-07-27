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
| Web crawling & URL discovery | 🔜 Phase 2 |
| JavaScript parsing & analysis | 🔜 Phase 2 |
| Technology fingerprinting | 🔜 Phase 2 |
| CVE intelligence | 🔜 Phase 3 |
| Secret discovery | 🔜 Phase 3 |
| API endpoint discovery | 🔜 Phase 3 |
| Report generation engine | 🔜 Phase 3 |

---

## Current Status

**Phase 1 — Project Bootstrap** (current)

This release establishes the production-ready project foundation: package structure, CLI, configuration, plugin registry, testing infrastructure, and CI/CD pipeline. No crawling, parsing, fingerprinting, or detection logic is implemented yet.

---

## Roadmap

### Phase 1 — Project Bootstrap ✅
- Project structure and packaging
- CLI with Typer
- Plugin-friendly architecture
- CI/CD with GitHub Actions
- Initial test suite

### Phase 2 — Core Engine
- HTTP downloader with httpx
- Web crawler with scope management
- HTML & JavaScript parser
- Technology fingerprint matcher
- Signature database loader

### Phase 3 — Intelligence Modules
- JavaScript library & framework detection
- Version identification
- CVE correlation engine
- Secret & credential discovery
- API endpoint discovery
- Rich reporting (JSON, HTML, SARIF)

### Phase 4 — Ecosystem
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
```

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
