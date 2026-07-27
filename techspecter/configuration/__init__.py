"""Centralized configuration framework."""

from techspecter.configuration.defaults import DEFAULT_USER_AGENT, default_config
from techspecter.configuration.manager import (
    ConfigurationManager,
    get_configuration_manager,
    reset_configuration_manager,
    set_configuration_manager,
)
from techspecter.configuration.models import (
    AnalysisConfig,
    AnalyzerOptions,
    AnalyzersConfig,
    CrawlerConfig,
    DownloaderConfig,
    LoggingConfig,
    PerformanceConfig,
    PluginsConfig,
    ReportConfig,
    TechSpecterConfig,
)

__all__ = [
    "AnalysisConfig",
    "AnalyzerOptions",
    "AnalyzersConfig",
    "ConfigurationManager",
    "CrawlerConfig",
    "DEFAULT_USER_AGENT",
    "DownloaderConfig",
    "LoggingConfig",
    "PerformanceConfig",
    "PluginsConfig",
    "ReportConfig",
    "TechSpecterConfig",
    "default_config",
    "get_configuration_manager",
    "reset_configuration_manager",
    "set_configuration_manager",
]
