# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `py.typed` marker for PEP 561 inline type-checking support
- pytest-cov coverage reporting in CI workflow
- `_export_or_display_analysis_report()` CLI helper to deduplicate report export logic

### Changed
- CLI `doctor --json` suppresses INFO logging to produce clean JSON output
- `FingerprintEngine._priority_for()` uses dict lookup (O(1)) instead of linear scan (O(n))
- Settings.version default updated from `0.7.0` to `1.0.0rc1`

### Fixed
- 14 Ruff lint errors: unused imports, unsorted import blocks, long lines, SIM103 violations
- 8 MyPy errors: added `bs4.*` ignore_missing_imports override in pyproject.toml
- Failing `test_doctor_json_output` caused by INFO log lines leaking into JSON stdout
- Redundant return patterns in `match_quality.py` and `match_attribution.py`

## [1.0.0-rc1] - 2026-07-28

### Added
- Release candidate packaging for v1.0.0 with semantic versioning (`techspecter/_version.py`)
- Production GitHub Actions: lint, format, mypy, multi-Python pytest, package build artifacts
- CodeQL, Dependency Review, Dependabot, and SBOM workflows
- `techspecter doctor` CLI diagnostics command
- Documentation: INSTALLATION, CONFIGURATION, QUICKSTART, MIGRATION, RELEASE_NOTES, SBOM guides
- SECURITY.md, CODE_OF_CONDUCT.md, SUPPORT.md, ROADMAP.md
- Examples: sample configuration, sample report, examples README
- SBOM generator (`tools/generate_sbom.py`) with CycloneDX and SPDX output
- Release engineering and packaging validation tests

### Changed
- Project status updated to v1.0.0 Release Candidate
- README refreshed for open-source release readiness
- PyPI metadata: classifiers, keywords, project URLs, dynamic versioning
- CLI help text and version display (`1.0.0-rc1`)

## [0.7.0] - 2026-07-28

### Added
- Centralized configuration framework in `techspecter/configuration/`
- YAML/JSON configuration loading, environment mapping, CLI overrides, and export
- Analyzer, reporting, logging, performance, and reserved plugin configuration sections
- Generic passive rule engine in `techspecter/rules/`
- Rule types: regex, string, header with validation, caching, and finding generation
- CLI options: `--config`, `--min-confidence`, `--disable-analyzer`, `--enable-analyzer`
- Structured and file logging support via configuration
- 33 new configuration and rule engine tests

### Changed
- `get_settings()` now derives from `ConfigurationManager` for backward compatibility
- CLI initializes centralized configuration on startup

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

[Unreleased]: https://github.com/Amirbarkhordari/TechSpecter/compare/v1.0.0-rc1...HEAD
[1.0.0-rc1]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.7.0...v1.0.0-rc1
[0.7.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.4.0...v0.5.0
[0.3.1]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Amirbarkhordari/TechSpecter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Amirbarkhordari/TechSpecter/releases/tag/v0.1.0
