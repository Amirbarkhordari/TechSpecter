"""Custom exception hierarchy for TechSpecter."""

from __future__ import annotations


class TechSpecterError(Exception):
    """Base exception for all TechSpecter errors."""


class ConfigurationError(TechSpecterError):
    """Raised when application configuration is invalid or incomplete."""


class ValidationError(TechSpecterError):
    """Raised when input validation fails."""


class PluginError(TechSpecterError):
    """Raised when a plugin fails to load, register, or execute."""


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin cannot be found in the registry."""


class CrawlerError(TechSpecterError):
    """Raised when web crawling operations fail."""


class DownloaderError(TechSpecterError):
    """Raised when resource download operations fail."""


class ParserError(TechSpecterError):
    """Raised when content parsing operations fail."""


class DetectorError(TechSpecterError):
    """Raised when technology detection operations fail."""


class ReportError(TechSpecterError):
    """Raised when report generation or export fails."""
