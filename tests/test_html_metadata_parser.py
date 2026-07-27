"""Tests for HTML metadata parser."""

from __future__ import annotations

from techspecter.parser.html_metadata_parser import HtmlMetadataParser

SAMPLE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Example Site</title>
  <meta name="description" content="An example website">
  <meta name="generator" content="Example CMS 1.0">
  <meta name="theme-color" content="#336699">
  <meta property="og:title" content="Example">
  <meta name="twitter:card" content="summary">
  <link rel="canonical" href="https://example.com/">
  <link rel="alternate" type="application/rss+xml" href="/feed">
  <link rel="manifest" href="/manifest.json">
  <link rel="icon" href="/favicon.ico">
</head>
<body>
  <!-- Built with Example CMS -->
  <script>navigator.serviceWorker.register('/sw.js');</script>
  <script>//# sourceMappingURL=app.js.map</script>
</body>
</html>
"""


def test_html_metadata_parser_extracts_core_fields() -> None:
    """Parser should extract title, meta tags, and links."""
    parser = HtmlMetadataParser()
    result = parser.parse(SAMPLE_HTML, base_url="https://example.com")
    html = result.html_metadata
    assert html.title == "Example Site"
    assert html.description == "An example website"
    assert html.generator == "Example CMS 1.0"
    assert html.theme_color == "#336699"
    assert html.language == "en"
    assert html.opengraph["og:title"] == "Example"
    assert html.twitter_cards["twitter:card"] == "summary"
    assert html.canonical_links == ["https://example.com/"]
    assert html.manifest_links == ["https://example.com/manifest.json"]


def test_html_metadata_parser_detects_comments_and_references() -> None:
    """Parser should detect comments, source maps, and service workers."""
    parser = HtmlMetadataParser()
    result = parser.parse(SAMPLE_HTML, base_url="https://example.com")
    assert result.html_metadata.comments
    assert result.sourcemap_references
    assert result.service_worker_references
