# TechSpecter

[![CI](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/codeql.yml/badge.svg)](https://github.com/Amirbarkhordari/TechSpecter/actions/workflows/codeql.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0--rc1-blue.svg)](https://github.com/Amirbarkhordari/TechSpecter/releases)

**TechSpecter** is a production-grade, cross-platform **Passive Web Application Analysis Framework**. It discovers and analyzes publicly accessible web resources to identify technologies, HTTP characteristics, metadata, cloud/identity/API artifacts, and sensitive exposure indicators — without active exploitation.

> **Release Candidate:** v1.0.0-rc1 — stable v1.0.0 coming soon.

---

## Features

| Capability | Status |
|---|---|
| JavaScript discovery and download | ✅ |
| Technology fingerprinting (64+ technologies) | ✅ |
| Passive HTTP/header/cookie analysis | ✅ |
| Metadata and well-known resource intelligence | ✅ |
| Cloud, identity, and API artifact analysis | ✅ |
| Sensitive artifact and classification analysis | ✅ |
| Plugin SDK (61 built-in plugins) | ✅ |
| Multi-format reporting (JSON, Markdown, HTML, CSV, SARIF) | ✅ |
| Performance caching and optional parallel analyzers | ✅ |
| Centralized configuration (YAML/JSON/env/CLI) | ✅ |

TechSpecter is **passive only** — no vulnerability scanning, brute force, port scanning, or exploitation.

---

## Quick Start

```bash
pip install -e ".[dev]"   # from source until PyPI stable release

techspecter --version
techspecter doctor
techspecter fingerprint https://example.com
techspecter analyze https://example.com --format html --output report.html
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full guide.

---

## Installation

| Method | Command |
|---|---|
| Source (recommended for RC) | `git clone ... && pip install -e ".[dev]"` |
| Runtime only | `pip install .` |
| PyPI (stable) | `pip install techspecter` *(available after v1.0.0)* |

Requirements: Python 3.11+. See [docs/INSTALLATION.md](docs/INSTALLATION.md).

---

## CLI Commands

| Command | Description |
|---|---|
| `discover` | Download and enumerate JavaScript resources |
| `fingerprint` | Technology fingerprinting with reporting |
| `analyze` | Passive HTTP analysis |
| `metadata` | HTML meta, robots, sitemap, well-known resources |
| `artifacts` | Cloud, identity, and API artifact intelligence |
| `sensitive` | Secret, configuration, and build artifact analysis |
| `doctor` | Installation and environment diagnostics |
| `plugins` | Plugin management and developer tools |

```bash
techspecter --help
techspecter doctor --json
techspecter analyze https://example.com --quiet
```

---

## Python API

```python
import asyncio
from techspecter.analysis import AnalysisService

async def main() -> None:
    result = await AnalysisService().run("https://example.com")
    print(f"Findings: {result.statistics.total_findings}")

asyncio.run(main())
```

---

## Architecture

```
Target URL → Discovery → Analysis Pipeline → Aggregation → Reporting
                              ↓
                    Analyzers + Plugin SDK
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/DEVELOPER.md](docs/DEVELOPER.md).

---

## Configuration

```bash
techspecter --config examples/config/techspecter.yaml analyze https://example.com
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) and [examples/](examples/).

---

## Documentation

| Document | Description |
|---|---|
| [Quick Start](docs/QUICKSTART.md) | Get running in minutes |
| [Installation](docs/INSTALLATION.md) | Install options |
| [Configuration](docs/CONFIGURATION.md) | Settings reference |
| [Developer Guide](docs/DEVELOPER.md) | API and analyzer authoring |
| [JavaScript Discovery](docs/JAVASCRIPT_DISCOVERY.md) | Phase 5.7 discovery and preprocessing |
| [Version Detection](docs/VERSION_DETECTION.md) | Phase 6 JavaScript version engine |
| [Plugin SDK](docs/PLUGIN_SDK.md) | Plugin development |
| [Migration Guide](docs/MIGRATION.md) | Version upgrades |
| [Release Notes](docs/RELEASE_NOTES.md) | v1.0.0-rc1 notes |
| [SBOM](docs/SBOM.md) | Supply chain transparency |
| [Roadmap](ROADMAP.md) | Project roadmap |
| [Security](SECURITY.md) | Vulnerability reporting |
| [Support](SUPPORT.md) | Getting help |

---

## Development

```bash
pip install -e ".[dev]"
ruff check .
black --check .
mypy techspecter
python -m pytest -v
python -m build
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Security

- [SECURITY.md](SECURITY.md) — responsible disclosure policy
- Dependabot, CodeQL, Dependency Review, and SBOM workflows enabled
- No telemetry or phone-home behavior

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

Built with [Typer](https://typer.tiangolo.com/), [Rich](https://rich.readthedocs.io/), [httpx](https://www.python-httpx.org/), [Pydantic](https://docs.pydantic.dev/), and the open-source community.
