# Release Notes — v1.0.0-rc1

**Release date:** 2026-07-28  
**Status:** Release Candidate

TechSpecter v1.0.0-rc1 is the first release candidate for the stable 1.0 open-source launch.

## Highlights

- **Passive analysis framework** — discovery, fingerprinting, HTTP, metadata, cloud/identity/API, and sensitive artifact intelligence
- **61 built-in plugins** and extensible Plugin SDK
- **Multi-format reporting** — JSON, Markdown, HTML, CSV, SARIF
- **Production hardening** — caching, optional parallel analyzers, timing telemetry
- **Open-source readiness** — CI/CD, security workflows, SBOM support, comprehensive documentation

## What's New in RC1

### Release Engineering

- Semantic versioning with centralized `techspecter/_version.py`
- Enhanced GitHub Actions: lint, format, mypy, pytest, multi-Python matrix, package build
- CodeQL, Dependency Review, Dependabot, and SBOM workflows
- PyPI-ready packaging metadata and classifiers

### CLI

- `techspecter doctor` diagnostics command
- `--quiet` / `-q` for minimal output
- Improved help text and user-facing error messages

### Documentation

- Installation, configuration, quick start, migration, and SBOM guides
- SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, ROADMAP.md
- Sample configuration and reports in `examples/`

## Upgrade Notes

No breaking changes from 0.7.x. See [MIGRATION.md](MIGRATION.md).

## Known Limitations (RC)

- PyPI publication pending stable v1.0.0
- Parallel analyzers are opt-in
- macOS is not in the primary CI matrix

## Validation

This release candidate was validated with:

- Ruff, Black, MyPy
- 395+ automated tests
- Wheel and sdist build verification
- CLI installation smoke tests

## Feedback

Report issues: https://github.com/Amirbarkhordari/TechSpecter/issues

Security: see [SECURITY.md](../SECURITY.md)
