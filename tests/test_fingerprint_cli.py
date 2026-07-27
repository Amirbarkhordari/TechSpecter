"""Tests for the fingerprint CLI command."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import respx
from typer.testing import CliRunner

from techspecter.cli import app
from techspecter.fingerprints.models import (
    DetectionResult,
    FingerprintAnalysisResult,
    Technology,
    TechnologyMatch,
)

runner = CliRunner()


def test_fingerprint_command_help() -> None:
    """Verify fingerprint command appears in CLI help."""
    result = runner.invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "Discover JavaScript resources and identify technologies" in result.stdout
    assert "--json" in result.stdout
    assert "--compact" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_compact_output(mock_analyze: AsyncMock) -> None:
    """Verify fingerprint command supports compact output."""
    mock_analyze.return_value = FingerprintAnalysisResult(
        target_url="https://example.com",
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[
                TechnologyMatch(
                    technology=Technology(id="react", name="React", category="framework"),
                    version="18.2.0",
                    confidence=92.5,
                )
            ],
            scripts_analyzed=1,
            elapsed_ms=25.0,
        ),
        elapsed_ms=125.0,
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--compact"])
    assert result.exit_code == 0
    assert "React 18.2.0" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_grouped_output(mock_analyze: AsyncMock) -> None:
    """Verify fingerprint command supports category grouping."""
    mock_analyze.return_value = FingerprintAnalysisResult(
        target_url="https://example.com",
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[
                TechnologyMatch(
                    technology=Technology(id="react", name="React", category="framework"),
                    version="18.2.0",
                    confidence=92.5,
                )
            ],
            scripts_analyzed=1,
            elapsed_ms=25.0,
        ),
        elapsed_ms=125.0,
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--group-by-category"])
    assert result.exit_code == 0
    assert "framework" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_renders_summary(mock_analyze: AsyncMock) -> None:
    """Verify fingerprint command renders detected technologies."""
    mock_analyze.return_value = FingerprintAnalysisResult(
        target_url="https://example.com",
        discovery_elapsed_ms=100.0,
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[
                TechnologyMatch(
                    technology=Technology(
                        id="react",
                        name="React",
                        category="framework",
                    ),
                    version="18.2.0",
                    confidence=92.5,
                    filename="react.js",
                )
            ],
            scripts_analyzed=1,
            elapsed_ms=25.0,
        ),
        elapsed_ms=125.0,
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0
    assert "React" in result.stdout
    assert "18.2.0" in result.stdout


@patch("techspecter.cli.FingerprintService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_json_output(mock_analyze: AsyncMock) -> None:
    """Verify fingerprint command supports JSON output."""
    mock_analyze.return_value = FingerprintAnalysisResult(
        target_url="https://example.com",
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[],
            scripts_analyzed=0,
            elapsed_ms=10.0,
        ),
        elapsed_ms=50.0,
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--json"])
    assert result.exit_code == 0
    assert '"target_url": "https://example.com"' in result.stdout
    assert '"detection"' in result.stdout


@respx.mock
def test_fingerprint_command_integration_with_mocked_http() -> None:
    """Verify fingerprint command runs discovery and detection end-to-end."""
    html = '<html><head><script src="/react.js"></script></head></html>'
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html)
    )
    respx.get("https://example.com/react.js").mock(
        return_value=httpx.Response(
            200,
            text='React.version="18.2.0"; React.createElement("div");',
        )
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0
    assert "React" in result.stdout
