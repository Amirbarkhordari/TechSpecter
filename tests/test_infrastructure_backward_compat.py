"""Backward compatibility tests for configuration and rules infrastructure."""

from __future__ import annotations

from techspecter.config import Settings, get_settings
from techspecter.configuration.manager import ConfigurationManager, reset_configuration_manager
from techspecter.fingerprinting.service import FingerprintService
from techspecter.reporting.engine import ReportEngine
from tests.report_fixtures import sample_detection_result


def test_legacy_settings_type_preserved() -> None:
    """Verify Settings dataclass remains available."""
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.app_name == "TechSpecter"


def test_fingerprint_service_still_instantiates() -> None:
    """Verify fingerprint service remains usable."""
    service = FingerprintService()
    assert service is not None


def test_report_engine_still_generates_technology_reports() -> None:
    """Verify reporting engine behavior is unchanged."""
    report = ReportEngine().generate(sample_detection_result())
    assert len(report.technologies) == 2


def test_default_configuration_manager_is_valid() -> None:
    """Verify default configuration loads and validates."""
    reset_configuration_manager()
    manager = ConfigurationManager.load(apply_env=False)
    assert manager.config.downloader.max_retries == 3
