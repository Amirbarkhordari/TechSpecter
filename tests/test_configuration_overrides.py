"""Tests for environment and CLI configuration overrides."""

from __future__ import annotations

from techspecter.config import get_settings
from techspecter.configuration.env import load_env_overrides
from techspecter.configuration.manager import ConfigurationManager, reset_configuration_manager


def test_env_overrides(monkeypatch) -> None:
    """Verify environment variables map to configuration overrides."""
    monkeypatch.setenv("TECHSPECTER_LOG_LEVEL", "ERROR")
    monkeypatch.setenv("TECHSPECTER_DEBUG", "true")
    monkeypatch.setenv("TECHSPECTER_MIN_CONFIDENCE", "30")
    monkeypatch.setenv("TECHSPECTER_DISABLED_ANALYZERS", "a1,a2")
    overrides = load_env_overrides()
    assert overrides["logging"]["level"] == "ERROR"
    assert overrides["logging"]["debug"] is True
    assert overrides["analysis"]["min_confidence"] == 30.0
    assert overrides["analysis"]["disabled_analyzers"] == ["a1", "a2"]


def test_get_settings_uses_configuration_manager(monkeypatch) -> None:
    """Verify legacy get_settings reads from the configuration manager."""
    reset_configuration_manager()
    monkeypatch.setenv("TECHSPECTER_MAX_CONCURRENCY", "7")
    manager = ConfigurationManager.load()
    from techspecter.configuration.manager import set_configuration_manager

    set_configuration_manager(manager)
    settings = get_settings()
    assert settings.max_concurrency == 7


def test_cli_help_includes_config_option() -> None:
    """Verify CLI exposes configuration override options."""
    from typer.testing import CliRunner

    from techspecter.cli import app

    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--config" in result.stdout


def test_fingerprint_help_includes_analyzer_options() -> None:
    """Verify fingerprint command exposes analyzer configuration flags."""
    from typer.testing import CliRunner

    from techspecter.cli import app

    result = CliRunner().invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "--min-confidence" in result.stdout
    assert "--disable-analyzer" in result.stdout
    assert "--enable-analyzer" in result.stdout
