"""Tests for HTML script parsing."""

from __future__ import annotations

from techspecter.parser.html_parser import HtmlScriptParser


def test_html_parser_discovers_external_scripts() -> None:
    """Verify external script tags are discovered and resolved."""
    html = """
    <html>
      <head>
        <script src="/app.js"></script>
        <script src="https://cdn.example.com/lib.js"></script>
      </head>
    </html>
    """
    parser = HtmlScriptParser()
    result = parser.parse(html, base_url="https://example.com/page")

    assert len(result.external_scripts) == 2
    assert str(result.external_scripts[0].url) == "https://example.com/app.js"
    assert str(result.external_scripts[1].url) == "https://cdn.example.com/lib.js"


def test_html_parser_discovers_inline_scripts() -> None:
    """Verify inline script blocks are captured separately."""
    html = """
    <html>
      <body>
        <script>console.log("one");</script>
        <script src="/app.js"></script>
        <script>console.log("two");</script>
      </body>
    </html>
    """
    parser = HtmlScriptParser()
    result = parser.parse(html, base_url="https://example.com")

    assert len(result.inline_scripts) == 2
    assert result.inline_scripts[0].index == 0
    assert result.inline_scripts[1].index == 1
    assert 'console.log("one")' in result.inline_scripts[0].content


def test_html_parser_detects_inline_source_map_reference() -> None:
    """Verify source map references are detected in inline scripts."""
    html = """
    <html><body>
      <script>
        console.log("x");
        //# sourceMappingURL=inline.js.map
      </script>
    </body></html>
    """
    parser = HtmlScriptParser()
    result = parser.parse(html, base_url="https://example.com/app/")

    assert len(result.inline_scripts) == 1
    assert result.inline_scripts[0].source_map_url == "https://example.com/app/inline.js.map"
