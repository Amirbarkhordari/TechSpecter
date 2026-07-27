"""Configuration section models."""

from __future__ import annotations

from pydantic import Field, field_validator

from techspecter.models.base import TechSpecterModel


class CrawlerConfig(TechSpecterModel):
    """Crawler and discovery configuration."""

    enabled: bool = True
    follow_redirects: bool = True
    max_redirects: int = Field(default=10, ge=0)


class DownloaderConfig(TechSpecterModel):
    """HTTP downloader configuration."""

    request_timeout: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    max_concurrency: int = Field(default=10, ge=1)
    max_response_size: int = Field(default=10_485_760, ge=1)
    user_agent: str = "TechSpecter/0.6.0 (+https://github.com/Amirbarkhordari/TechSpecter)"


class AnalyzerOptions(TechSpecterModel):
    """Per-analyzer configuration options."""

    enabled: bool = True
    timeout: float = Field(default=30.0, gt=0)
    max_file_size: int = Field(default=10_485_760, ge=1)
    max_response_size: int = Field(default=10_485_760, ge=1)
    min_confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    severity_threshold: str = "INFO"
    include_patterns: list[str] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(default_factory=list)


class AnalysisConfig(TechSpecterModel):
    """Analysis pipeline configuration."""

    enabled: bool = True
    min_confidence: float = Field(default=0.0, ge=0.0, le=100.0)
    disabled_analyzers: list[str] = Field(default_factory=list)
    enabled_analyzers: list[str] = Field(default_factory=list)
    analyzers: dict[str, AnalyzerOptions] = Field(default_factory=dict)

    def is_analyzer_enabled(self, analyzer_id: str) -> bool:
        """Return whether an analyzer is enabled."""
        if analyzer_id in self.disabled_analyzers:
            return False
        if self.enabled_analyzers and analyzer_id not in self.enabled_analyzers:
            return False
        options = self.analyzers.get(analyzer_id)
        if options is None:
            return True
        return options.enabled

    def analyzer_options(self, analyzer_id: str) -> AnalyzerOptions:
        """Return options for an analyzer."""
        return self.analyzers.get(analyzer_id, AnalyzerOptions())


class ReportConfig(TechSpecterModel):
    """Reporting configuration."""

    html_enabled: bool = True
    json_enabled: bool = True
    markdown_enabled: bool = True
    csv_enabled: bool = True
    sarif_enabled: bool = True
    output_directory: str = "."
    filename: str | None = None
    theme: str = "default"
    default_format: str | None = None

    def is_format_enabled(self, report_format: str) -> bool:
        """Return whether a report format is enabled."""
        mapping = {
            "html": self.html_enabled,
            "json": self.json_enabled,
            "markdown": self.markdown_enabled,
            "csv": self.csv_enabled,
            "sarif": self.sarif_enabled,
        }
        return mapping.get(report_format, True)


class LoggingConfig(TechSpecterModel):
    """Logging configuration."""

    level: str = "INFO"
    console: bool = True
    file: bool = False
    file_path: str | None = None
    structured: bool = False
    debug: bool = False

    @field_validator("level")
    @classmethod
    def _validate_level(cls, value: str) -> str:
        """Ensure the log level is a known logging level name."""
        normalized = value.upper()
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in valid:
            msg = f"Invalid log level: {value}"
            raise ValueError(msg)
        return normalized


class PerformanceConfig(TechSpecterModel):
    """Performance tuning configuration."""

    cache_rules: bool = True
    compile_regex: bool = True
    max_cached_rules: int = Field(default=1000, ge=1)
    rule_batch_size: int = Field(default=100, ge=1)


class PluginsConfig(TechSpecterModel):
    """Reserved plugin configuration section."""

    enabled: bool = True
    directories: list[str] = Field(default_factory=list)
    load_entry_points: bool = True


class AnalyzersConfig(TechSpecterModel):
    """Reserved future analyzer configuration section."""

    rule_directories: list[str] = Field(default_factory=list)


class TechSpecterConfig(TechSpecterModel):
    """Root configuration model for TechSpecter."""

    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    downloader: DownloaderConfig = Field(default_factory=DownloaderConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportConfig = Field(default_factory=ReportConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    analyzers: AnalyzersConfig = Field(default_factory=AnalyzersConfig)
