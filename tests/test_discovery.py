"""Tests for the JavaScript discovery pipeline."""

from __future__ import annotations

import httpx
import pytest
import respx

from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.exceptions import ValidationError
from tests.http_fixtures import mock_well_known_http_requests


@pytest.mark.asyncio
@respx.mock
async def test_discovery_pipeline_end_to_end() -> None:
    """Verify the discovery pipeline discovers and downloads JavaScript resources."""
    html = """
    <html>
      <head>
        <script src="/app.js"></script>
        <script>console.log("inline");</script>
      </head>
    </html>
    """
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text=html,
        )
    )
    respx.get("https://example.com/app.js").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/javascript"},
            text="console.log('app');\n//# sourceMappingURL=app.js.map",
        )
    )
    respx.get("https://example.com/app.js.map").mock(
        return_value=httpx.Response(404, text="Not Found"),
    )
    mock_well_known_http_requests()

    pipeline = DiscoveryPipeline()
    result = await pipeline.run("example.com")

    assert str(result.target.url).startswith("https://example.com")
    assert len(result.external_scripts) == 1
    assert len(result.inline_scripts) == 1
    assert result.downloaded_count == 1
    assert result.downloads[0].source_map_url == "https://example.com/app.js.map"


@pytest.mark.asyncio
async def test_discovery_pipeline_rejects_invalid_url() -> None:
    """Verify invalid target URLs raise ValidationError."""
    pipeline = DiscoveryPipeline()
    with pytest.raises(ValidationError):
        await pipeline.run("not a valid url :::")
