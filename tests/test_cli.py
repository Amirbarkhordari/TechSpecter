"""Tests for the TechSpecter CLI."""

from __future__ import annotations

from typer.testing import CliRunner

from techspecter import version_display
from techspecter.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    """Verify the CLI renders help output."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "TechSpecter" in result.stdout
    assert "--version" in result.stdout
    assert "doctor" in result.stdout


def test_cli_version() -> None:
    """Verify the --version flag prints the current version."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert f"TechSpecter {version_display()}" in result.stdout


def test_cli_version_short_flag() -> None:
    """Verify the -V short flag prints the current version."""
    result = runner.invoke(app, ["-V"])
    assert result.exit_code == 0
    assert version_display() in result.stdout
