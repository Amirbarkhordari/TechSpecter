# Installation Guide

## Requirements

- Python **3.11**, **3.12**, or **3.13**
- pip (latest recommended)
- Network access to target URLs (passive HTTP/S only)

## Install from PyPI (Recommended)

```bash
python -m pip install --upgrade pip
pip install techspecter
```

> **Note:** PyPI publication begins with the v1.0.0 stable release. Until then, install from source or Git tags.

## Install from Source

```bash
git clone https://github.com/Amirbarkhordari/TechSpecter.git
cd TechSpecter
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

## Install a Release Candidate

```bash
git clone https://github.com/Amirbarkhordari/TechSpecter.git
cd TechSpecter
git checkout v1.0.0-rc1   # when tagged
pip install .
```

## Development Installation

```bash
pip install -e ".[dev]"
```

Development extras include pytest, ruff, black, mypy, and respx.

## Release Engineering Extras

```bash
pip install -e ".[release]"   # build + twine
pip install -e ".[sbom]"        # CycloneDX SBOM generation
```

## Verify Installation

```bash
techspecter --version
techspecter --help
techspecter doctor
python -c "import techspecter; print(techspecter.__version__)"
```

## Entry Points

| Command | Description |
|---|---|
| `techspecter` | Main CLI (console script) |
| `python -m techspecter` | Module invocation |

## Platform Notes

TechSpecter is tested on **Ubuntu** and **Windows** in CI. macOS is expected to work but is not in the primary CI matrix.

## Troubleshooting

| Issue | Solution |
|---|---|
| `techspecter: command not found` | Ensure your virtualenv `Scripts`/`bin` is on `PATH` |
| SSL errors | Verify system CA certificates; check corporate proxy settings |
| Import errors | Reinstall with `pip install -e .` from repository root |
| Plugin load failures | Run `techspecter doctor` and `techspecter plugins doctor` |

See [SUPPORT.md](../SUPPORT.md) for additional help.
