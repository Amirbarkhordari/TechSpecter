# Contributing to TechSpecter

Thank you for your interest in contributing to TechSpecter! This document provides guidelines and instructions for contributing to the project.

---

## Getting Started

See [docs/INSTALLATION.md](docs/INSTALLATION.md) and [docs/QUICKSTART.md](docs/QUICKSTART.md) for detailed setup instructions.

### Prerequisites

- Python 3.11 or later
- Git
- A GitHub account

### Development Setup

1. Fork the repository on GitHub.
2. Clone your fork locally:

   ```bash
   git clone https://github.com/<your-username>/techspecter.git
   cd techspecter
   ```

3. Create a virtual environment and install dependencies:

   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate

   pip install -e ".[dev]"
   ```

4. Verify the setup:

   ```bash
   pytest
   techspecter --version
   ```

---

## Development Workflow

1. Create a feature branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the coding standards below.
3. Add or update tests for your changes.
4. Run the test suite and ensure all tests pass:

   ```bash
   pytest
   ```

5. Commit your changes with a clear, descriptive message.
6. Push to your fork and open a Pull Request against `main`.

---

## Related Documentation

- [Developer Guide](docs/DEVELOPER.md)
- [Plugin SDK](docs/PLUGIN_SDK.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Coding Standards

### Python Style

- Target **Python 3.11+**
- Use **type hints** on all function signatures and class attributes
- Write **Google-style docstrings** for all public modules, classes, and functions
- Follow **SOLID principles** and **Clean Architecture** patterns
- Keep modules focused and single-responsibility
- Avoid code duplication — extract shared logic into utilities

### Formatting & Linting

We use [Ruff](https://docs.astral.sh/ruff/) for linting:

```bash
ruff check .
black --check .
mypy techspecter
python -m pytest -v
```

### Type Checking

We use [mypy](https://mypy.readthedocs.io/) for static type analysis:

```bash
mypy techspecter
```

---

## Project Structure Guidelines

When adding new functionality:

| Module | Purpose |
|---|---|
| `techspecter/core/` | Interfaces, context objects, orchestration |
| `techspecter/crawler/` | URL discovery and navigation |
| `techspecter/downloader/` | HTTP fetching and caching |
| `techspecter/parser/` | HTML, JS, and content parsing |
| `techspecter/detector/` | Technology matching engines |
| `techspecter/fingerprints/` | Signature loading and validation |
| `techspecter/report/` | Output formatting and export |
| `techspecter/models/` | Pydantic data schemas |
| `techspecter/plugins/` | Plugin registry and third-party plugins |
| `techspecter/utils/` | Shared helpers |

### Plugin Development

New features should be implemented as plugins implementing the `Plugin` interface in `techspecter/core/interfaces.py`. Register plugins via `techspecter.plugins.registry` without modifying core application code.

---

## Testing

- All new features must include tests
- Tests live in the `tests/` directory
- Use pytest conventions (`test_*.py`, `Test*` classes, `test_*` functions)
- Aim for meaningful coverage of business logic

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=techspecter --cov-report=term-missing
```

---

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add JavaScript parser module
fix: resolve timeout handling in downloader
docs: update installation instructions
test: add plugin registry unit tests
refactor: extract HTTP client into downloader module
```

---

## Pull Request Process

1. Ensure your branch is up to date with `main`
2. Fill out the PR template with a clear description of changes
3. Link any related issues
4. Ensure CI checks pass (tests on Ubuntu and Windows, package build)
5. Request review from maintainers

---

## Reporting Issues

When reporting bugs, please include:

- Python version and operating system
- Steps to reproduce the issue
- Expected vs. actual behavior
- Relevant logs or error messages

For feature requests, describe the use case and proposed behavior.

---

## Code of Conduct

Be respectful, inclusive, and constructive in all project interactions. Harassment, discrimination, and toxic behavior will not be tolerated.

---

## Questions?

Open a [GitHub Discussion](https://github.com/Amirbarkhordari/TechSpecter/discussions) or file an issue if you have questions about contributing.

Thank you for helping make TechSpecter better!
