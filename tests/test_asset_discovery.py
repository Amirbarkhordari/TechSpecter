"""Tests for Phase 7.1 asset discovery and inventory."""

from __future__ import annotations

import techspecter.crawler.discovery  # noqa: F401 — rebuild DiscoveryResult forward refs
from techspecter.asset_discovery.classifier import AssetClassifier
from techspecter.asset_discovery.discovery import AssetDiscoveryEngine
from techspecter.asset_discovery.hash import asset_id_from_url, sha256_hex
from techspecter.asset_discovery.inventory import AssetInventoryBuilder, inventory_key
from techspecter.asset_discovery.models import (
    AssetCategory,
    AssetDiscoverySource,
    AssetReference,
)
from techspecter.asset_discovery.report import build_report_asset_inventory, build_report_section
from techspecter.asset_discovery.sources.css import extract_css_references
from techspecter.asset_discovery.sources.html import extract_html_references
from techspecter.asset_discovery.sources.javascript import extract_javascript_references
from techspecter.asset_discovery.sources.manifest import extract_manifest_references


def test_sha256_hex_and_asset_id() -> None:
    """Verify hashing helpers."""
    digest = sha256_hex(b"hello")
    assert len(digest) == 64
    assert asset_id_from_url("https://example.com/app.js") == asset_id_from_url(
        "https://example.com/app.js",
    )


def test_inventory_key_strips_fragment() -> None:
    """Verify inventory dedup keys ignore fragments."""
    assert inventory_key("https://example.com/a.js#frag") == inventory_key(
        "https://example.com/a.js",
    )


def test_classifier_by_extension() -> None:
    """Verify extension-based classification."""
    classifier = AssetClassifier()
    assert (
        classifier.classify(url="https://x.com/a.js", filename="a.js") == AssetCategory.JAVASCRIPT
    )
    assert classifier.classify(url="https://x.com/a.css", filename="a.css") == AssetCategory.CSS
    assert classifier.classify(url="https://x.com/a.wasm", filename="a.wasm") == AssetCategory.WASM
    assert (
        classifier.classify(url="https://x.com/manifest.json", filename="manifest.json")
        == AssetCategory.MANIFEST
    )


def test_html_reference_extraction() -> None:
    """Verify HTML asset references are discovered."""
    html = """
    <html><head>
      <link rel="stylesheet" href="/styles/main.css">
      <script src="/app.js"></script>
      <link rel="manifest" href="/site.webmanifest">
    </head><body><img src="/logo.png"></body></html>
    """
    refs = extract_html_references(html, base_url="https://example.com/page")
    urls = {item.url for item in refs}
    assert "https://example.com/styles/main.css" in urls
    assert "https://example.com/app.js" in urls
    assert "https://example.com/site.webmanifest" in urls
    assert "https://example.com/logo.png" in urls


def test_css_reference_extraction() -> None:
    """Verify CSS url() references are extracted."""
    css = '@import url("/fonts/inter.woff2"); body { background: url("../img/bg.png"); }'
    refs = extract_css_references(css, base_url="https://example.com/css/app.css")
    urls = {item.url for item in refs}
    assert "https://example.com/fonts/inter.woff2" in urls
    assert "https://example.com/img/bg.png" in urls


def test_javascript_reference_extraction() -> None:
    """Verify JS-derived asset references."""
    js = 'import("./chunk.wasm"); //# sourceMappingURL=app.js.map'
    refs = extract_javascript_references(
        js,
        base_url="https://example.com/js/app.js",
        parent_url="https://example.com/js/app.js",
    )
    categories = {item.category_hint for item in refs}
    assert AssetCategory.WASM in categories
    assert any(item.category_hint == AssetCategory.MAP for item in refs)


def test_manifest_reference_extraction() -> None:
    """Verify manifest icon references."""
    manifest = '{"icons":[{"src":"/icons/icon-192.png","sizes":"192x192"}]}'
    refs = extract_manifest_references(
        manifest,
        base_url="https://example.com/site.webmanifest",
        manifest_url="https://example.com/site.webmanifest",
    )
    assert any("icon-192.png" in item.url for item in refs)


def test_inventory_deduplicates_references() -> None:
    """Verify duplicate URLs merge relationships."""
    builder = AssetInventoryBuilder()
    ref = AssetReference(
        url="https://example.com/app.js",
        original_url="/app.js",
        source=AssetDiscoverySource.HTML,
        referenced_by="https://example.com/",
        detail="script",
    )
    builder.add_reference(ref)
    builder.add_reference(
        ref.model_copy(
            update={
                "source": AssetDiscoverySource.JAVASCRIPT,
                "referenced_by": "https://example.com/other.js",
                "detail": "import",
            },
        ),
    )
    inventory = builder.build(target_url="https://example.com/")
    assert inventory.summary.total_assets == 1
    assert len(inventory.assets[0].relationships) == 2
    assert len(inventory.assets[0].discovery_sources) == 2


def test_discovery_engine_collects_html_and_js() -> None:
    """Verify discovery engine aggregates sources."""
    engine = AssetDiscoveryEngine()
    html = '<script src="/app.js"></script><link rel="stylesheet" href="/app.css">'
    refs = engine.collect_references(html=html, base_url="https://example.com/")
    assert len(refs) >= 2


def test_report_models_for_export() -> None:
    """Verify report export models are populated."""
    builder = AssetInventoryBuilder()
    builder.add_reference(
        AssetReference(
            url="https://example.com/app.js",
            original_url="/app.js",
            category_hint=AssetCategory.JAVASCRIPT,
            source=AssetDiscoverySource.HTML,
            referenced_by="https://example.com/",
        ),
    )
    inventory = builder.build(target_url="https://example.com/")
    report_inventory = build_report_asset_inventory(inventory)
    section = build_report_section(inventory)
    assert report_inventory.total_assets == 1
    assert section.id == "asset-inventory"
    assert "asset_inventory" in section.metadata
