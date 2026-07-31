"""Tests for Phase 5.7 JavaScript discovery and preprocessing."""

from __future__ import annotations

import httpx
import pytest
import respx

from techspecter.crawler.discovery import DiscoveryPipeline
from techspecter.downloader.http_client import AsyncHttpClient, HttpClientConfig
from techspecter.javascript.classification.bundler import detect_bundler
from techspecter.javascript.classification.classifier import classify_resource
from techspecter.javascript.discovery.references import extract_references_from_content
from techspecter.javascript.models import (
    BundlerType,
    DiscoverySource,
    JavaScriptResourceKind,
    ModuleType,
)
from techspecter.javascript.normalization.pipeline import JavaScriptNormalizationPipeline
from techspecter.javascript.pipeline.config import JavaScriptPipelineConfig
from techspecter.javascript.pipeline.pipeline import JavaScriptPipeline


@pytest.fixture(autouse=True)
def _clear_javascript_cache() -> None:
    """Clear global JavaScript cache between tests."""
    from techspecter.javascript.cache.resource_cache import get_javascript_cache

    get_javascript_cache().clear_all()


def test_extract_dynamic_import_references() -> None:
    """Verify dynamic import references are extracted from bundle content."""
    content = "import('./lazy-chunk.js'); import('./vendor.js');"
    refs = extract_references_from_content(
        content,
        base_url="https://example.com/assets/main.js",
        source=DiscoverySource.DYNAMIC_IMPORT,
    )
    urls = {str(item.url) for item in refs}
    assert "https://example.com/assets/lazy-chunk.js" in urls
    assert "https://example.com/assets/vendor.js" in urls


def test_webpack_runtime_reference_extraction() -> None:
    """Verify webpack chunk references are extracted."""
    content = "__webpack_require__.p + 'static/chunks/123-abc.chunk.js'"
    refs = extract_references_from_content(
        content,
        base_url="https://example.com/_next/static/chunks/webpack.js",
    )
    assert any("chunk" in str(item.url) for item in refs)


def test_detect_webpack_bundler() -> None:
    """Verify webpack bundler detection."""
    content = "var __webpack_require__ = function() {};"
    assert detect_bundler(content=content, filename="main.js") == BundlerType.WEBPACK


def test_detect_vite_bundler() -> None:
    """Verify Vite bundler detection."""
    content = "const env = import.meta.env;"
    assert detect_bundler(content=content, filename="index.js") == BundlerType.VITE


def test_classify_lazy_chunk() -> None:
    """Verify lazy chunk classification."""
    kind, bundle_class, _ = classify_resource(
        filename="lazy-home-chunk.js",
        content="import('./page.js')",
        discovery_sources=[DiscoverySource.DYNAMIC_IMPORT],
    )
    assert kind == JavaScriptResourceKind.LAZY_CHUNK


def test_classify_service_worker() -> None:
    """Verify service worker classification."""
    kind, _, _ = classify_resource(
        filename="sw.js",
        content="self.addEventListener('install', () => {})",
        module_type=ModuleType.SERVICE_WORKER,
        discovery_sources=[DiscoverySource.SERVICE_WORKER],
    )
    assert kind == JavaScriptResourceKind.SERVICE_WORKER


def test_normalization_preserves_content() -> None:
    """Verify normalization does not alter program logic."""
    pipeline = JavaScriptNormalizationPipeline()
    content = "function add(a,b){return a+b}"
    result = pipeline.normalize(content)
    assert "function add" in result.content
    assert result.normalized_length == len(content)


def test_content_hash_deduplication() -> None:
    """Verify duplicate content is detected by hash."""
    from techspecter.javascript.cache.resource_cache import JavaScriptResourceCache

    cache = JavaScriptResourceCache()
    content = "console.log('duplicate');"
    hash_a = cache.content_hash(content)
    hash_b = cache.content_hash(content)
    assert hash_a == hash_b


def test_metadata_cache_hit() -> None:
    """Verify metadata caching avoids repeated extraction."""
    from techspecter.javascript.cache.resource_cache import JavaScriptResourceCache
    from techspecter.javascript.metadata.extractor import JavaScriptMetadataExtractor

    cache = JavaScriptResourceCache()
    extractor = JavaScriptMetadataExtractor()
    normalized = JavaScriptNormalizationPipeline().normalize("console.log(1);")
    metadata_a = extractor.extract(
        url="https://example.com/a.js",
        filename="a.js",
        content="console.log(1);",
        normalized=normalized,
        cache=cache,
    )
    metadata_b = extractor.extract(
        url="https://example.com/a.js",
        filename="a.js",
        content="console.log(1);",
        normalized=normalized,
        cache=cache,
    )
    assert metadata_a.content_hash == metadata_b.content_hash
    assert cache.metadata_cache.hits >= 1


@pytest.mark.asyncio
@respx.mock
async def test_recursive_discovery_finds_nested_chunks() -> None:
    """Verify recursive discovery follows JavaScript references."""
    html = """
    <html><head>
      <script type="module" src="/main.js"></script>
      <link rel="modulepreload" href="/vendor.js">
    </head></html>
    """
    main_js = "import('./chunk-lazy.js');"
    chunk_js = "console.log('lazy');"

    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/main.js").mock(return_value=httpx.Response(200, text=main_js))
    respx.get("https://example.com/vendor.js").mock(
        return_value=httpx.Response(200, text="console.log('vendor');"),
    )
    respx.get("https://example.com/chunk-lazy.js").mock(
        return_value=httpx.Response(200, text=chunk_js),
    )

    config = JavaScriptPipelineConfig(
        max_concurrency=5,
        enable_recursive_discovery=True,
    )
    client = AsyncHttpClient(HttpClientConfig(timeout=5.0))
    try:
        pipeline = JavaScriptPipeline(config=config)
        result = await pipeline.process_html(
            html=html,
            base_url="https://example.com/",
            client=client,
        )
    finally:
        await client.close()

    urls = {resource.url for resource in result.index.all_resources() if not resource.inline}
    assert "https://example.com/main.js" in urls
    assert "https://example.com/vendor.js" in urls
    assert "https://example.com/chunk-lazy.js" in urls
    assert result.statistics.recursive_rounds >= 1


@pytest.mark.asyncio
@respx.mock
async def test_discovery_pipeline_v2_backward_compat() -> None:
    """Verify DiscoveryPipeline still produces compatible DiscoveryResult."""
    html = """
    <html><head>
      <script src="/app.js"></script>
      <script>console.log("inline");</script>
    </head></html>
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

    pipeline = DiscoveryPipeline()
    result = await pipeline.run("example.com")

    assert str(result.target.url).startswith("https://example.com")
    assert len(result.external_scripts) == 1
    assert len(result.inline_scripts) == 1
    assert result.downloaded_count == 1
    assert result.downloads[0].source_map_url == "https://example.com/app.js.map"
    assert result.javascript_index is not None
    assert result.javascript_index.count >= 2


@pytest.mark.asyncio
@respx.mock
async def test_duplicate_content_skipped_in_pipeline() -> None:
    """Verify identical JavaScript content is deduplicated by hash."""
    html = """
    <html><head>
      <script src="/a.js"></script>
      <script src="/b.js"></script>
    </head></html>
    """
    same_content = "console.log('same');"

    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/a.js").mock(return_value=httpx.Response(200, text=same_content))
    respx.get("https://example.com/b.js").mock(return_value=httpx.Response(200, text=same_content))

    pipeline = DiscoveryPipeline()
    result = await pipeline.run("https://example.com/")

    assert result.javascript_index is not None
    duplicates = [
        item for item in result.javascript_index.all_resources() if item.duplicate_of is not None
    ]
    assert len(duplicates) >= 1


@pytest.mark.asyncio
@respx.mock
async def test_ast_preparation_populates_metadata() -> None:
    """Verify AST preparation extracts import references."""
    html = '<html><head><script src="/module.js"></script></head></html>'
    module_js = "import { createApp } from 'vue'; export default createApp;"

    respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
    respx.get("https://example.com/module.js").mock(
        return_value=httpx.Response(200, text=module_js)
    )

    pipeline = DiscoveryPipeline()
    result = await pipeline.run("https://example.com/")

    indexed = result.javascript_index
    assert indexed is not None
    external = [item for item in indexed.all_resources() if not item.inline]
    assert external
    resource = external[0]
    assert resource.ast is not None
    assert resource.ast.import_count >= 1
    assert "vue" in resource.metadata.import_references
