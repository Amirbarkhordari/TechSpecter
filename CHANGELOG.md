# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet.

## [0.1.0] - 2026-07-27

### Added
- Initial project bootstrap (Phase 1)
- Modular package structure with plugin-friendly architecture
- Typer-based CLI with `--version` and `--debug` flags
- Configuration management via environment variables
- Custom exception hierarchy
- Plugin registry for extensible module loading
- Core interfaces: `Plugin`, `ScanContext`, `ScanResult`
- Pydantic base model for data schemas
- Logging utilities with configurable log levels
- GitHub Actions CI pipeline (Ubuntu + Windows)
- Initial test suite
- Project documentation (README, CONTRIBUTING, LICENSE)

[Unreleased]: https://github.com/techspecter/techspecter/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/techspecter/techspecter/releases/tag/v0.1.0
