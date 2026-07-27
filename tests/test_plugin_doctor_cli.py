"""Tests for plugin doctor/info CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from techspecter.cli import app

runner = CliRunner()


def test_plugins_doctor_runs_successfully() -> None:
    """Verify doctor command reports healthy environment."""
    result = runner.invoke(app, ["plugins", "doctor"])
    assert result.exit_code == 0
    assert "Plugin Doctor" in result.stdout
    assert "No plugin issues detected" in result.stdout


def test_plugins_info_displays_sdk_details() -> None:
    """Verify info command displays SDK runtime details."""
    result = runner.invoke(app, ["plugins", "info"])
    assert result.exit_code == 0
    assert "Plugin SDK" in result.stdout
    assert "techspecter.plugins.developer" in result.stdout
