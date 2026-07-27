"""Tests for the discover CLI command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import respx
from typer.testing import CliRunner

from techspecter.cli import app
from techspecter.models.discovery import (
    DiscoveryResult,
    DownloadResult,
    InlineScript,
    ScriptResource,
    Target,
)

runner = CliRunner()


def test_discover_command_help() -> None:
    """Verify discover command appears in CLI help."""
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0
    assert "Discover and download JavaScript resources" in result.stdout
    assert "--json" in result.stdout


@patch("techspecter.cli.DiscoveryPipeline.run", new_callable=AsyncMock)
def test_discover_command_renders_summary(mock_run: AsyncMock) -> None:
    """Verify discover command renders a human-readable summary."""
    mock_run.return_value = DiscoveryResult(
        target=Target(url="https://example.com", original_url="https://example.com"),  # type: ignore[arg-type]
        external_scripts=[
            ScriptResource(url="https://example.com/app.js", original_url="/app.js"),  # type: ignore[arg-type]
        ],
        inline_scripts=[InlineScript(index=0, content="console.log(1);")],
        downloads=[
            DownloadResult(
                url="https://example.com/app.js",  # type: ignore[arg-type]
                filename="app.js",
                status_code=200,
                content_length=12,
                download_success=True,
                download_duration_ms=25.0,
            )
        ],
        elapsed_ms=100.0,
    )

    result = runner.invoke(app, ["discover", "https://example.com"])
    assert result.exit_code == 0
    assert "https://example.com" in result.stdout
    assert "app.js" in result.stdout
    assert "100 ms" in result.stdout


@patch("techspecter.cli.DiscoveryPipeline.run", new_callable=AsyncMock)
def test_discover_command_json_output(mock_run: AsyncMock) -> None:
    """Verify discover command supports JSON output."""
    mock_run.return_value = DiscoveryResult(
        target=Target(url="https://example.com", original_url="https://example.com"),  # type: ignore[arg-type]
        external_scripts=[],
        inline_scripts=[],
        downloads=[],
        elapsed_ms=50.0,
    )

    result = runner.invoke(app, ["discover", "https://example.com", "--json"])
    assert result.exit_code == 0
    assert '"elapsed_ms": 50' in result.stdout
    assert '"target"' in result.stdout


@respx.mock
def test_discover_command_integration_with_mocked_http() -> None:
    """Verify discover command executes against mocked HTTP responses."""
    html = '<html><head><script src="/app.js"></script></head></html>'
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=html,
        )
    )
    respx.get("https://example.com/app.js").mock(
        return_value=httpx.Response(200, text="console.log('ok');")
    )

    result = runner.invoke(app, ["discover", "https://example.com"])
    assert result.exit_code == 0
    assert "app.js" in result.stdout


def test_discover_command_reports_validation_errors() -> None:
    """Verify validation errors are reported to the user."""
    result = runner.invoke(app, ["discover", "ftp://example.com"])
    assert result.exit_code == 1
    assert "Validation error" in result.stdout
