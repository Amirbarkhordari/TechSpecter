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


class PluginEntryConfig(TechSpecterModel):
    """Per-plugin configuration entry."""

    enabled: bool = True
    settings: dict[str, object] = Field(default_factory=dict)


class PluginsConfig(TechSpecterModel):
    """Plugin configuration section."""

    enabled: bool = True
    directories: list[str] = Field(default_factory=list)
    load_entry_points: bool = True
    disabled_plugins: list[str] = Field(default_factory=list)
    enabled_plugins: list[str] = Field(default_factory=list)
    plugins: dict[str, PluginEntryConfig] = Field(default_factory=dict)

    def is_plugin_enabled(self, plugin_id: str) -> bool:
        """Return whether a plugin is enabled."""
        if not self.enabled:
            return False
        if plugin_id in self.disabled_plugins:
            return False
        if self.enabled_plugins and plugin_id not in self.enabled_plugins:
            return False
        entry = self.plugins.get(plugin_id)
        if entry is None:
            return True
        return entry.enabled


class AnalyzersConfig(TechSpecterModel):
    """Reserved future analyzer configuration section."""

    rule_directories: list[str] = Field(default_factory=list)


class HttpAnalysisConfig(TechSpecterModel):
    """Passive HTTP analysis configuration."""

    enabled: bool = True
    http_analysis: bool = True
    headers: bool = True
    cookies: bool = True
    security_headers: bool = True
    redirects: bool = True
    analyzers: dict[str, AnalyzerOptions] = Field(default_factory=dict)

    def is_analyzer_enabled(self, analyzer_id: str) -> bool:
        """Return whether an HTTP analyzer is enabled."""
        if not self.enabled or not self.http_analysis:
            return False

        group_enabled = {
            "http-header-analyzer": self.headers,
            "cookie-analyzer": self.cookies,
            "security-header-analyzer": self.security_headers,
            "csp-analyzer": self.security_headers,
            "redirect-analyzer": self.redirects,
        }
        if analyzer_id in group_enabled and not group_enabled[analyzer_id]:
            return False

        options = self.analyzers.get(analyzer_id)
        if options is None:
            return True
        return options.enabled


class MetadataAnalysisConfig(TechSpecterModel):
    """Passive metadata and well-known resource analysis configuration."""

    enabled: bool = True
    metadata_analysis: bool = True
    well_known: bool = True
    manifest: bool = True
    robots: bool = True
    sitemap: bool = True
    security_txt: bool = True
    html_meta: bool = True
    framework_meta: bool = True
    sourcemaps: bool = True
    service_workers: bool = True
    analyzers: dict[str, AnalyzerOptions] = Field(default_factory=dict)

    def is_analyzer_enabled(self, analyzer_id: str) -> bool:
        """Return whether a metadata analyzer is enabled."""
        if not self.enabled or not self.metadata_analysis:
            return False

        group_enabled = {
            "robots-analyzer": self.robots,
            "sitemap-analyzer": self.sitemap,
            "security-txt-analyzer": self.security_txt,
            "humans-txt-analyzer": self.well_known,
            "ads-txt-analyzer": self.well_known,
            "assetlinks-analyzer": self.well_known,
            "apple-app-site-association-analyzer": self.well_known,
            "manifest-analyzer": self.manifest,
            "web-app-manifest-analyzer": self.manifest,
            "browserconfig-analyzer": self.manifest,
            "html-metadata-analyzer": self.html_meta,
            "html-comment-analyzer": self.html_meta,
            "opengraph-analyzer": self.html_meta,
            "twitter-card-analyzer": self.html_meta,
            "canonical-link-analyzer": self.html_meta,
            "alternate-link-analyzer": self.html_meta,
            "generator-meta-analyzer": self.html_meta,
            "theme-color-analyzer": self.html_meta,
            "application-metadata-analyzer": self.html_meta,
            "language-analyzer": self.html_meta,
            "favicon-analyzer": self.html_meta,
            "framework-metadata-analyzer": self.framework_meta,
            "sourcemap-analyzer": self.sourcemaps,
            "service-worker-analyzer": self.service_workers,
        }
        if analyzer_id in group_enabled and not group_enabled[analyzer_id]:
            return False

        options = self.analyzers.get(analyzer_id)
        if options is None:
            return True
        return options.enabled


class TechSpecterConfig(TechSpecterModel):
    """Root configuration model for TechSpecter."""

    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    downloader: DownloaderConfig = Field(default_factory=DownloaderConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    http_analysis: HttpAnalysisConfig = Field(default_factory=HttpAnalysisConfig)
    metadata_analysis: MetadataAnalysisConfig = Field(default_factory=MetadataAnalysisConfig)
    reporting: ReportConfig = Field(default_factory=ReportConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    plugins: PluginsConfig = Field(default_factory=PluginsConfig)
    analyzers: AnalyzersConfig = Field(default_factory=AnalyzersConfig)
