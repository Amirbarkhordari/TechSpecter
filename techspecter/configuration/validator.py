"""Configuration validation utilities."""

from __future__ import annotations

from dataclasses import dataclass, field

from techspecter.configuration.models import TechSpecterConfig


@dataclass(slots=True)
class ConfigurationValidationReport:
    """Validation results for configuration."""

    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ConfigurationValidator:
    """Validate TechSpecter configuration."""

    def validate(self, config: TechSpecterConfig) -> ConfigurationValidationReport:
        """Validate a configuration instance."""
        report = ConfigurationValidationReport()
        if config.analysis.min_confidence < 0 or config.analysis.min_confidence > 100:
            report.errors.append("analysis.min_confidence must be between 0 and 100.")

        for analyzer_id, options in config.analysis.analyzers.items():
            if options.min_confidence < 0 or options.min_confidence > 100:
                report.errors.append(
                    f"analysis.analyzers.{analyzer_id}.min_confidence must be between 0 and 100.",
                )
            if options.severity_threshold.upper() not in {
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO",
            }:
                report.warnings.append(
                    f"analysis.analyzers.{analyzer_id}.severity_threshold may be invalid.",
                )

        enabled_formats = [
            config.reporting.html_enabled,
            config.reporting.json_enabled,
            config.reporting.markdown_enabled,
            config.reporting.csv_enabled,
            config.reporting.sarif_enabled,
        ]
        if not any(enabled_formats):
            report.warnings.append("All report formats are disabled.")

        report.is_valid = not report.errors
        return report

    def validate_or_raise(self, config: TechSpecterConfig) -> ConfigurationValidationReport:
        """Validate configuration and raise when invalid."""
        report = self.validate(config)
        if not report.is_valid:
            from techspecter.exceptions import ConfigurationError

            msg = "; ".join(report.errors)
            raise ConfigurationError(msg)
        return report
