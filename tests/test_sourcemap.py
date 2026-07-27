"""Tests for source map detection."""

from __future__ import annotations

from techspecter.parser.sourcemap import detect_source_map_url


def test_detect_source_map_url_from_line_comment() -> None:
    """Verify line-comment source map directives are detected."""
    content = 'console.log("x");\n//# sourceMappingURL=app.js.map\n'
    assert detect_source_map_url(content, base_url="https://example.com/js/app.js") == (
        "https://example.com/js/app.js.map"
    )


def test_detect_source_map_url_returns_none_when_missing() -> None:
    """Verify missing source map directives return None."""
    assert detect_source_map_url("console.log('no map');") is None


def test_detect_source_map_url_preserves_absolute_url() -> None:
    """Verify absolute source map URLs are returned unchanged."""
    content = "//# sourceMappingURL=https://cdn.example.com/app.js.map"
    assert detect_source_map_url(content) == "https://cdn.example.com/app.js.map"
