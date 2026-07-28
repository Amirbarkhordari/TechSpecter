"""Custom exception hierarchy for TechSpecter."""

from __future__ import annotations


class TechSpecterError(Exception):
    """Base exception for all TechSpecter errors."""

    def user_message(self) -> str:
        """Return a safe user-facing message."""
        return str(self)


class ConfigurationError(TechSpecterError):
    """Raised when application configuration is invalid or incomplete."""


class RuleError(TechSpecterError):
    """Raised when rule loading or execution fails."""


class RuleLoadError(RuleError):
    """Raised when rules cannot be loaded from storage."""


class RuleValidationError(RuleError):
    """Raised when a rule definition fails validation."""


class ValidationError(TechSpecterError):
    """Raised when input validation fails."""


class InvalidTargetUrlError(ValidationError):
    """Raised when a target URL fails validation."""


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


class FingerprintError(DetectorError):
    """Base exception for fingerprinting operations."""


class FingerprintLoadError(FingerprintError):
    """Raised when fingerprint signatures cannot be loaded."""


class InvalidFingerprintError(FingerprintError):
    """Raised when a fingerprint definition is invalid."""


class PatternMatchError(FingerprintError):
    """Raised when pattern matching fails unexpectedly."""


class VersionExtractionError(FingerprintError):
    """Raised when version extraction fails unexpectedly."""


class ReportError(TechSpecterError):
    """Raised when report generation or export fails."""


class AnalysisError(TechSpecterError):
    """Raised when passive analysis operations fail."""


class ExportError(ReportError):
    """Raised when a report export operation fails."""


class TemplateError(ReportError):
    """Raised when a report template cannot be loaded or rendered."""


class InvalidReportError(ReportError):
    """Raised when a report model fails validation."""
