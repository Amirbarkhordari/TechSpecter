# Quick Start

Get TechSpecter running in under five minutes.

## Install

```bash
pip install techspecter
```

Or from source:

```bash
git clone https://github.com/Amirbarkhordari/TechSpecter.git
cd TechSpecter
pip install -e ".[dev]"
```

## Verify Installation

```bash
techspecter --version
techspecter doctor
```

## Analyze a Target

### Discover JavaScript resources

```bash
techspecter discover https://example.com
```

### Fingerprint technologies

```bash
techspecter fingerprint https://example.com
```

### Full passive analysis (HTTP + metadata + artifacts)

```bash
techspecter analyze https://example.com
techspecter metadata https://example.com
techspecter artifacts https://example.com
techspecter sensitive https://example.com
```

## Export a Report

```bash
techspecter fingerprint https://example.com --format html --output report.html
techspecter analyze https://example.com --format sarif --output results.sarif
```

## Python API

```python
import asyncio
from techspecter.analysis import AnalysisService

async def main() -> None:
    result = await AnalysisService().run("https://example.com")
    print(f"Findings: {result.statistics.total_findings}")

asyncio.run(main())
```

## Next Steps

- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](CONFIGURATION.md)
- [Developer Guide](DEVELOPER.md)
- [Plugin SDK](PLUGIN_SDK.md)
