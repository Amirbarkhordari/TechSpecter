"""Tests for configuration validation and merging."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from techspecter.configuration.manager import ConfigurationManager
from techspecter.configuration.merge import deep_merge
from techspecter.configuration.models import AnalyzerOptions, TechSpecterConfig
from techspecter.configuration.validator import ConfigurationValidator


def test_deep_merge_nested_sections() -> None:
    """Verify nested configuration sections merge correctly."""
    base = {"logging": {"level": "INFO", "debug": False}, "analysis": {"min_confidence": 0}}
    override = {"logging": {"debug": True}, "analysis": {"min_confidence": 50}}
    merged = deep_merge(base, override)
    assert merged["logging"]["level"] == "INFO"
    assert merged["logging"]["debug"] is True
    assert merged["analysis"]["min_confidence"] == 50


def test_configuration_validator_accepts_defaults() -> None:
    """Verify default configuration passes validation."""
    report = ConfigurationValidator().validate(TechSpecterConfig())
    assert report.is_valid


def test_analyzer_options_validate_confidence_bounds() -> None:
    """Verify analyzer option confidence bounds are enforced."""
    with pytest.raises(ValidationError):
        AnalyzerOptions(min_confidence=150)


def test_analyzer_options_and_enablement() -> None:
    """Verify analyzer enablement respects configuration."""
    config = TechSpecterConfig(
        analysis={
            "disabled_analyzers": ["blocked"],
            "enabled_analyzers": ["allowed"],
            "analyzers": {
                "custom": AnalyzerOptions(enabled=False),
            },
        },
    )
    assert not config.analysis.is_analyzer_enabled("blocked")
    assert config.analysis.is_analyzer_enabled("allowed")
    assert not config.analysis.is_analyzer_enabled("custom")


def test_report_format_enablement() -> None:
    """Verify report format toggles."""
    config = TechSpecterConfig(reporting={"html_enabled": False})
    assert not config.reporting.is_format_enabled("html")
    assert config.reporting.is_format_enabled("json")


def test_manager_apply_cli_overrides() -> None:
    """Verify CLI overrides merge into active configuration."""
    manager = ConfigurationManager.load(apply_env=False)
    manager.apply_cli_overrides({"analysis": {"min_confidence": 75}})
    assert manager.config.analysis.min_confidence == 75
