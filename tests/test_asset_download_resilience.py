"""Regression tests for asset download fault tolerance."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from techspecter.asset_discovery.collector import AssetCollector, AssetCollectorConfig
from techspecter.asset_discovery.download_status import (
    build_download_summary,
    classify_download_outcome,
)
from techspecter.asset_discovery.inventory import AssetInventoryBuilder
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDiscoverySource,
    AssetDownloadStatus,
    AssetReference,
)
from techspecter.asset_discovery.pipeline import (
    AssetDiscoveryPipeline,
    AssetDiscoveryPipelineConfig,
)
from techspecter.cli import app
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.exceptions import DownloaderError
from tests.http_fixtures import mock_well_known_http_requests

runner = CliRunner()


def _reference(url: str, *, category: AssetCategory = AssetCategory.JAVASCRIPT) -> AssetReference:
    return AssetReference(
        url=url,
        original_url=url,
        category_hint=category,
        source=AssetDiscoverySource.HTML,
        referenced_by="https://example.com/",
    )


def _builder_with_assets(*urls: str) -> AssetInventoryBuilder:
    builder = AssetInventoryBuilder()
    for url in urls:
        builder.add_reference(_reference(url))
    return builder


def _mock_response(url: str, *, status: int = 200, text: str = "ok") -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "application/javascript"}, text=text)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"download_success": True}, AssetDownloadStatus.DOWNLOADED),
        ({"download_success": False, "http_status": 429}, AssetDownloadStatus.RATE_LIMITED),
        ({"download_success": False, "http_status": 403}, AssetDownloadStatus.FORBIDDEN),
        ({"download_success": False, "http_status": 404}, AssetDownloadStatus.FAILED),
        ({"download_success": False, "error_message": "timeout"}, AssetDownloadStatus.TIMEOUT),
        (
            {"download_success": False, "error_message": "File exceeds configured size limit"},
            AssetDownloadStatus.SKIPPED,
        ),
    ],
)
def test_classify_download_outcome(
    kwargs: dict[str, object], expected: AssetDownloadStatus
) -> None:
    """Verify download outcomes are classified consistently."""
    assert classify_download_outcome(**kwargs) == expected  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_single_asset_failure_does_not_abort_collector() -> None:
    """Verify one failed asset download does not stop remaining downloads."""
    builder = _builder_with_assets(
        "https://example.com/fail.js",
        "https://example.com/ok.js",
    )
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        side_effect=[
            DownloaderError("Failed to download https://example.com/fail.js after 3 attempts."),
            _mock_response("https://example.com/ok.js", text="console.log('ok');"),
        ],
    )
    collector = AssetCollector(client=client, config=AssetCollectorConfig(max_concurrency=2))

    await collector.enrich_inventory(builder)

    inventory = builder.build(target_url="https://example.com/")
    assert inventory.summary.total_assets == 2
    assert inventory.download_summary.downloaded == 1
    assert inventory.download_summary.failed == 1
    by_url = {asset.url: asset for asset in inventory.assets}
    assert by_url["https://example.com/ok.js"].download_status == AssetDownloadStatus.DOWNLOADED
    assert by_url["https://example.com/fail.js"].download_status == AssetDownloadStatus.FAILED


@pytest.mark.asyncio
async def test_multiple_asset_failures_complete_inventory() -> None:
    """Verify several failed downloads still produce a complete inventory."""
    urls = [
        "https://example.com/a.js",
        "https://example.com/b.js",
        "https://example.com/c.js",
    ]
    builder = _builder_with_assets(*urls)
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        side_effect=[
            DownloaderError("Failed to download https://example.com/a.js after 3 attempts."),
            DownloaderError("Failed to download https://example.com/b.js after 3 attempts."),
            _mock_response("https://example.com/c.js", text="console.log('c');"),
        ],
    )
    collector = AssetCollector(client=client)

    await collector.enrich_inventory(builder)

    inventory = builder.build(target_url="https://example.com/")
    assert inventory.download_summary.downloaded == 1
    assert inventory.download_summary.failed == 2
    assert inventory.download_summary.total_attempted == 3


@pytest.mark.asyncio
async def test_rate_limited_asset_is_classified() -> None:
    """Verify HTTP 429 failures are recorded as rate limited."""
    builder = _builder_with_assets("https://example.com/rate.js")
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        side_effect=DownloaderError(
            "Failed to download https://example.com/rate.js after 3 attempts: "
            "Retryable HTTP status 429 for https://example.com/rate.js",
        ),
    )
    collector = AssetCollector(client=client)

    await collector.enrich_inventory(builder)

    asset = builder.build(target_url="https://example.com/").assets[0]
    assert asset.download_status == AssetDownloadStatus.RATE_LIMITED
    summary = build_download_summary([asset])
    assert summary.rate_limited == 1


@pytest.mark.asyncio
async def test_dns_failure_is_recorded_and_scan_continues() -> None:
    """Verify DNS resolution failures do not abort asset collection."""
    builder = _builder_with_assets(
        "https://missing.example.com/app.js",
        "https://example.com/ok.js",
    )
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        side_effect=[
            DownloaderError(
                "Failed to download https://missing.example.com/app.js after 3 attempts: "
                "[Errno 11001] getaddrinfo failed",
            ),
            _mock_response("https://example.com/ok.js"),
        ],
    )
    collector = AssetCollector(client=client)

    await collector.enrich_inventory(builder)

    inventory = builder.build(target_url="https://example.com/")
    by_url = {asset.url: asset for asset in inventory.assets}
    assert (
        by_url["https://missing.example.com/app.js"].download_status == AssetDownloadStatus.FAILED
    )
    assert by_url["https://example.com/ok.js"].download_status == AssetDownloadStatus.DOWNLOADED


@pytest.mark.asyncio
async def test_relative_asset_urls_are_skipped_without_crash() -> None:
    """Schemeless relative URLs must be skipped, not crash httpx/urllib."""
    builder = AssetInventoryBuilder()
    builder.add_reference(_reference("/_next/static/chunks/37s89-sr5-ttw.js"))
    builder.add_reference(_reference("https://example.com/ok.js"))
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        return_value=_mock_response("https://example.com/ok.js", text="console.log(1)"),
    )
    collector = AssetCollector(client=client)

    await collector.enrich_inventory(builder)

    inventory = builder.build(target_url="https://example.com/")
    by_url = {asset.url: asset for asset in inventory.assets}
    relative = by_url["/_next/static/chunks/37s89-sr5-ttw.js"]
    assert relative.download_status == AssetDownloadStatus.SKIPPED
    assert "non-absolute" in (relative.error_message or "").lower()
    assert by_url["https://example.com/ok.js"].download_status == AssetDownloadStatus.DOWNLOADED
    assert client.get.await_count == 1


def test_javascript_index_source_map_resolved_to_absolute() -> None:
    """Relative sourceMappingURL from JS index must resolve against the script URL."""
    from techspecter.asset_discovery.discovery import _references_from_javascript_index
    from techspecter.javascript.index.javascript_index import JavaScriptIndex
    from techspecter.javascript.models import IndexedJavaScriptResource, JavaScriptResourceMetadata

    index = JavaScriptIndex()
    index.add(
        IndexedJavaScriptResource(
            resource_id="app-js",
            url="https://example.com/_next/static/chunks/app.js",
            original_url="/_next/static/chunks/app.js",
            content="console.log(1);",
            normalized_content="console.log(1);",
            download_success=True,
            metadata=JavaScriptResourceMetadata(
                filename="app.js",
                content_hash="abc",
                source_map_url="app.js.map",
            ),
        ),
    )
    refs = _references_from_javascript_index(index, base_url="https://example.com/")
    map_urls = [ref.url for ref in refs if ref.category_hint == AssetCategory.MAP]
    assert map_urls == ["https://example.com/_next/static/chunks/app.js.map"]


@pytest.mark.asyncio
async def test_non_text_media_assets_are_skipped_without_download() -> None:
    """Binary/media assets must not be downloaded for technology evidence."""
    builder = AssetInventoryBuilder()
    builder.add_reference(
        _reference("https://example.com/video.mp4", category=AssetCategory.IMAGE),
    )
    builder.add_reference(
        _reference("https://example.com/app.js", category=AssetCategory.JAVASCRIPT),
    )
    client = MagicMock(spec=AsyncHttpClient)
    client.get = AsyncMock(
        return_value=_mock_response("https://example.com/app.js", text="console.log(1)"),
    )
    collector = AssetCollector(client=client)

    await collector.enrich_inventory(builder)

    inventory = builder.build(target_url="https://example.com/")
    by_url = {asset.url: asset for asset in inventory.assets}
    assert by_url["https://example.com/video.mp4"].download_status == AssetDownloadStatus.SKIPPED
    assert by_url["https://example.com/app.js"].download_status == AssetDownloadStatus.DOWNLOADED
    assert client.get.await_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_asset_discovery_pipeline_survives_failed_downloads() -> None:
    """Verify the asset discovery pipeline completes when downloads fail."""
    html = (
        '<html><head><script src="/good.js"></script><script src="/bad.js"></script></head></html>'
    )
    respx.get("https://example.com/good.js").mock(
        return_value=httpx.Response(200, text="console.log('good');"),
    )
    respx.get("https://example.com/bad.js").mock(return_value=httpx.Response(503, text="nope"))

    async with AsyncHttpClient(HttpClientConfig(max_retries=1)) as client:
        pipeline = AssetDiscoveryPipeline(
            config=AssetDiscoveryPipelineConfig(
                collect_well_known=False,
                download_assets=True,
            ),
        )
        inventory = await pipeline.run(
            base_url="https://example.com/",
            html=html,
            client=client,
        )

    assert inventory.summary.total_assets == 2
    assert inventory.download_summary.downloaded == 1
    assert inventory.download_summary.failed == 1


@respx.mock
def test_fingerprint_completes_when_asset_download_fails() -> None:
    """Verify fingerprint CLI completes when one discovered asset cannot be downloaded."""
    html = (
        '<html><head><script src="/good.js"></script><script src="/bad.js"></script></head></html>'
    )
    respx.get("https://example.com/").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=html),
    )
    respx.get("https://example.com/good.js").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "application/javascript"},
            text='React.version="18.2.0";',
        ),
    )
    respx.get("https://example.com/bad.js").mock(return_value=httpx.Response(503, text="nope"))
    mock_well_known_http_requests()

    result = runner.invoke(app, ["fingerprint", "https://example.com"])
    assert result.exit_code == 0, result.stdout
    assert "Fingerprint analysis failed" not in result.stdout
    assert "Download Summary" in result.stdout
    assert "Technology Detection" in result.stdout
