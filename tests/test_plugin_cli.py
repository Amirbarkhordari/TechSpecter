"""Tests for plugin CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from techspecter.cli import app
from techspecter.plugins.validator import PluginValidationReport
from tests.plugin_fixtures import write_directory_plugin

runner = CliRunner()


def test_plugins_list_without_load() -> None:
    """Verify plugins list reports empty registry by default."""
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "No plugins registered" in result.stdout


def test_plugins_list_with_load(tmp_path: Path) -> None:
    """Verify plugins list loads and displays directory plugins."""
    write_directory_plugin(tmp_path, plugin_id="cli-plugin")
    config_yaml = tmp_path / "config.yaml"
    config_yaml.write_text(
        f"plugins:\n  directories:\n    - {tmp_path.as_posix()}\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        ["--config", str(config_yaml), "plugins", "list", "--load"],
    )
    assert result.exit_code == 0
    assert "cli-plugin" in result.stdout


def test_plugins_show_missing_plugin() -> None:
    """Verify show exits with error for unknown plugins."""
    result = runner.invoke(app, ["plugins", "show", "missing-plugin"])
    assert result.exit_code == 1
    assert "not found" in result.stdout


def test_plugins_validate_directory(tmp_path: Path) -> None:
    """Verify validate reports plugin validation results."""
    write_directory_plugin(tmp_path, plugin_id="valid-plugin")
    result = runner.invoke(
        app,
        ["plugins", "validate", "--directory", str(tmp_path)],
    )
    assert result.exit_code == 0
    assert "valid-plugin" in result.stdout
    assert "valid" in result.stdout


def test_plugins_validate_invalid_plugin(tmp_path: Path) -> None:
    """Verify validate reports invalid plugins."""
    write_directory_plugin(tmp_path, plugin_id="invalid-plugin")
    invalid_report = PluginValidationReport(
        plugin_id="invalid-plugin",
        is_valid=False,
        errors=["broken"],
    )
    with patch(
        "techspecter.plugins.cli.PluginValidator.validate",
        return_value=invalid_report,
    ):
        result = runner.invoke(
            app,
            ["plugins", "validate", "--directory", str(tmp_path)],
        )
    assert result.exit_code == 1
