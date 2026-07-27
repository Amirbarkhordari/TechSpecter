# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet.

## [0.6.0] - 2026-07-28

### Added
- Generic passive analysis framework in `techspecter/analysis/`
- `Analyzer` base class and `AnalyzerRegistry` for extensible analysis modules
- `TechnologyFingerprintAnalyzer` wrapping the existing fingerprint engine
- Standardized `Finding`, `Evidence`, `Severity`, and category models
- `AnalysisPipeline`, `AnalysisService`, and `AnalysisResult` public API
- `ResultAggregator` for multi-analyzer finding merge and statistics
- Generic `ReportFinding` support in reporting models and `ReportEngine.generate_from_analysis()`
- Architecture documentation (`docs/ARCHITECTURE.md`) and developer guide (`docs/DEVELOPER.md`)
- 22 new analysis framework tests

### Changed
- TechSpecter repositioned as a Passive Web Application Analysis Framework
- Reports now support generic findings alongside legacy technology sections
- README updated with analysis framework overview and revised roadmap

## [0.5.0] - 2026-07-27

### Added
- Reporting Engine (Phase 4) in `techspecter/reporting/`
- `ReportEngine`, `ReportService`, and Pydantic report models
- Exporters: JSON, Markdown, HTML, CSV, SARIF 2.1.0
- Responsive HTML report template (`reporting/templates/report.html`)
- Console renderer with statistics, grouping, and evidence output
- CLI options: `--format`, `--output`
- Reporting exceptions: `ExportError`, `TemplateError`, `InvalidReportError`
- 18 new reporting tests

### Changed
- Default fingerprint console output now uses the reporting renderer
- Legacy `--json` preserved for raw analysis output

## [0.4.0] - 2026-07-27

### Added
- Expanded fingerprint database with 64 technologies across 8 categories (Phase 3B)
- `FingerprintValidator` for schema, duplicate, and regex validation
- `PatternEvidence` model for structured detection evidence
- Multi-source version extraction with highest-confidence selection
- CLI options: `--compact`, `--group-by-category`, `--verbose-output`
- Fingerprint catalog build tools in `tools/`
- 16 new tests (validator, database, accuracy, performance)

### Changed
- Matcher enhancements: filename chunk/vendor heuristics, source map regex, bootstrap globals
- Confidence scoring uses matcher-type multipliers and weak-detection filtering
- Version patterns support optional `source` field for bundle/metadata extraction

## [0.3.1] - 2026-07-27

### Added
- Dedicated `techspecter/fingerprinting/` core engine package (Phase 3A)
- `FingerprintPattern` model and spec-aligned matcher module names

### Changed
- Fingerprint JSON database relocated to `techspecter/fingerprints/`
- `SignatureLoader` resolves bundled fingerprints first, with legacy `signatures/` fallback
- `techspecter/fingerprints/` Python modules are backward-compatible re-exports

## [0.3.0] - 2026-07-27

### Added
- JavaScript Fingerprinting Engine (Phase 3)
- JSON fingerprint repository with 10 bundled technologies
- `SignatureLoader` with schema validation, caching, and graceful error handling
- `FingerprintEngine` with pluggable matchers: string, regex, filename, sourcemap, global
- `VersionExtractor` with regex-based version detection
- `ConfidenceScorer` with normalized 0–100 scoring
- `FingerprintPipeline` and `FingerprintService` orchestration layer
- CLI command: `techspecter fingerprint <url>` with `--json` support
- Fingerprint-specific exception hierarchy
- Comprehensive fingerprint test suite (26 new tests)

### Changed
- `DownloadResult` now optionally stores downloaded JavaScript content for analysis
- Package bundles `signatures/` directory in wheel distributions

## [0.2.1] - 2026-07-27

### Fixed
- CLI help output now displays TechSpecter branding consistently
- Source map references are preserved through the discovery pipeline and resolved to absolute URLs
- Pydantic validation errors are converted to TechSpecter validation exceptions
- Logging configuration no longer attaches duplicate handlers or writes to closed stdout streams during tests

### Changed
- HTTP client source map detection reads response bytes directly for reliable parsing
- Third-party HTTP library log noise suppressed during normal operation

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

[Unreleased]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.4.0...v0.5.0
[0.3.1]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Amirbarkhordari/TechSpecter/releases/tag/v0.1.0
