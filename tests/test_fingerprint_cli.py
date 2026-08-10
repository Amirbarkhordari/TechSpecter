"""Tests for the fingerprint CLI command."""

from __future__ import annotations

from pathlib import Path
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
from tests.http_fixtures import mock_well_known_http_requests

runner = CliRunner()


def test_fingerprint_command_help() -> None:
    """Verify fingerprint command appears in CLI help."""
    result = runner.invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "Discover JavaScript resources and identify technologies" in result.stdout
    assert "--json" in result.stdout
    assert "--compact" in result.stdout
    assert "--debug-fingerprint" in result.stdout


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
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


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
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


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
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
                    source_file="react.js",
                    matched_patterns=["string:React.createElement"],
                    detection_reason="string:React.createElement @ react.js",
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
    assert "Evidence" in result.stdout


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_debug_fingerprint_flag(mock_analyze: AsyncMock) -> None:
    """Verify --debug-fingerprint renders diagnostics section."""
    mock_analyze.return_value = FingerprintAnalysisResult(
        target_url="https://example.com",
        detection=DetectionResult(
            target_url="https://example.com",
            matches=[
                TechnologyMatch(
                    technology=Technology(id="react", name="React", category="framework"),
                    version="18.2.0",
                    confidence=92.5,
                    filename="react.js",
                    source_file="react.js",
                    evidence=[],
                    matched_patterns=["string:React.createElement"],
                    detection_reason="string:React.createElement @ react.js",
                )
            ],
            ignored_matches=[
                TechnologyMatch(
                    technology=Technology(
                        id="bootstrap", name="Bootstrap", category="css-framework"
                    ),
                    confidence=55.0,
                    filename="chunk.js",
                    source_file="chunk.js",
                    evidence=[],
                    matched_patterns=["string:Bootstrap"],
                )
            ],
            scripts_analyzed=1,
            elapsed_ms=25.0,
        ),
        elapsed_ms=125.0,
    )
    result = runner.invoke(app, ["fingerprint", "https://example.com", "--debug-fingerprint"])
    assert result.exit_code == 0
    assert "Fingerprint Debug Diagnostics" in result.stdout
    assert "Rejected / Weak Detections" in result.stdout


@patch("techspecter.cli.UnifiedDetectionService.analyze_url", new_callable=AsyncMock)
def test_fingerprint_command_json_output_to_file(
    mock_analyze: AsyncMock, tmp_path: Path
) -> None:
    """Verify --json --output writes UTF-8 JSON without dumping to stdout."""
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
    output = tmp_path / "out.json"
    result = runner.invoke(
        app,
        ["fingerprint", "https://example.com", "--json", "--output", str(output)],
    )
    assert result.exit_code == 0
    assert output.exists()
    payload = output.read_text(encoding="utf-8")
    assert '"target_url": "https://example.com"' in payload
    assert '"detection"' in payload
    assert '"target_url": "https://example.com"' not in result.stdout


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
    mock_well_known_http_requests()
    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0
    assert "React" in result.stdout
