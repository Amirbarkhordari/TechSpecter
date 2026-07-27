# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet.

## [0.2.0] - 2026-07-27

### Added
- JavaScript Discovery Engine (Phase 2)
- URL validation, normalization, and resolution utilities
- Reusable asynchronous HTTP client with retry support
- HTML downloader and HTML script parser
- External JavaScript downloader with configurable concurrency
- Source map reference detection (`sourceMappingURL`)
- Pydantic discovery models: `Target`, `ScriptResource`, `InlineScript`, `DownloadResult`, `DiscoveryResult`
- Modular discovery pipeline orchestrator
- CLI command: `techspecter discover <url>` with `--json` and `--verbose`
- Comprehensive unit tests for discovery components

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

[Unreleased]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Amirbarkhordari/TechSpecter/releases/tag/v0.1.0
