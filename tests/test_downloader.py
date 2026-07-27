"""Tests for downloader components."""

from __future__ import annotations

import httpx
import pytest
import respx

from techspecter.downloader.html_downloader import HtmlDownloader
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.downloader.js_downloader import JsDownloader
from techspecter.exceptions import DownloaderError
from techspecter.models.discovery import ScriptResource


@pytest.mark.asyncio
@respx.mock
async def test_html_downloader_returns_decoded_document() -> None:
    """Verify HTML downloader decodes response content."""
    respx.get("https://example.com").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<html><body>ok</body></html>",
        )
    )

    async with AsyncHttpClient(HttpClientConfig(max_retries=1)) as client:
        downloader = HtmlDownloader(client)
        document = await downloader.download("https://example.com")

    assert document.status_code == 200
    assert "<html>" in document.content
    assert document.encoding == "utf-8"


@pytest.mark.asyncio
@respx.mock
async def test_js_downloader_downloads_all_scripts() -> None:
    """Verify JavaScript downloader fetches all unique scripts."""
    respx.get("https://example.com/a.js").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/javascript"},
            text="console.log('a');\n//# sourceMappingURL=a.js.map",
        )
    )
    respx.get("https://example.com/b.js").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/javascript"},
            text="console.log('b');",
        )
    )

    scripts = [
        ScriptResource(url="https://example.com/a.js", original_url="/a.js"),  # type: ignore[arg-type]
        ScriptResource(url="https://example.com/b.js", original_url="/b.js"),  # type: ignore[arg-type]
    ]

    async with AsyncHttpClient(HttpClientConfig(max_retries=1)) as client:
        downloader = JsDownloader(client)
        results = await downloader.download_all(scripts)

    assert len(results) == 2
    assert all(item.download_success for item in results)
    assert results[0].source_map_url == "https://example.com/a.js.map"


@pytest.mark.asyncio
@respx.mock
async def test_js_downloader_continues_after_failure() -> None:
    """Verify one failed download does not stop remaining downloads."""
    respx.get("https://example.com/a.js").mock(return_value=httpx.Response(404))
    respx.get("https://example.com/b.js").mock(
        return_value=httpx.Response(200, text="console.log('b');")
    )

    scripts = [
        ScriptResource(url="https://example.com/a.js", original_url="/a.js"),  # type: ignore[arg-type]
        ScriptResource(url="https://example.com/b.js", original_url="/b.js"),  # type: ignore[arg-type]
    ]

    async with AsyncHttpClient(HttpClientConfig(max_retries=1)) as client:
        downloader = JsDownloader(client)
        results = await downloader.download_all(scripts)

    assert results[0].download_success is False
    assert results[1].download_success is True


@pytest.mark.asyncio
@respx.mock
async def test_http_client_retries_retryable_status_codes() -> None:
    """Verify retryable HTTP status codes trigger another attempt."""
    route = respx.get("https://example.com/retry.js").mock(
        side_effect=[
            httpx.Response(503, text="unavailable"),
            httpx.Response(200, text="ok"),
        ]
    )

    async with AsyncHttpClient(HttpClientConfig(max_retries=2)) as client:
        response = await client.get("https://example.com/retry.js")

    assert response.status_code == 200
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_http_client_raises_after_exhausting_retries() -> None:
    """Verify DownloaderError is raised after all retries fail."""
    respx.get("https://example.com/fail.js").mock(return_value=httpx.Response(503, text="nope"))

    async with AsyncHttpClient(HttpClientConfig(max_retries=2)) as client:
        with pytest.raises(DownloaderError, match="Failed to download"):
            await client.get("https://example.com/fail.js")
