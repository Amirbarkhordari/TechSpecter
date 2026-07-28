"""Source map intelligence tests."""

from __future__ import annotations

from techspecter.fingerprinting.javascript.sourcemap.analyzer import extract_source_map_findings
from techspecter.fingerprinting.javascript.sourcemap.parser import parse_source_map


def test_parse_source_map_extracts_sources() -> None:
    """Parser should extract original source paths from source maps."""
    payload = """
    {
      "version": 3,
      "file": "app.js",
      "sources": ["webpack:///node_modules/react/index.js", "src/main.ts"],
      "names": [],
      "mappings": ""
    }
    """
    parsed = parse_source_map(payload)
    assert parsed.file == "app.js"
    assert "webpack:///node_modules/react/index.js" in parsed.sources


def test_source_map_findings_include_package_reference() -> None:
    """Source map analysis should emit package references from node_modules paths."""
    payload = """
    {
      "version": 3,
      "sources": ["webpack:///node_modules/vue/dist/vue.runtime.esm.js"],
      "names": [],
      "mappings": ""
    }
    """
    parsed = parse_source_map(payload)
    findings = extract_source_map_findings(
        source_map_url="https://example.com/app.js.map",
        parsed=parsed,
    )
    assert any(item.matched_value == "vue/dist/vue.runtime.esm.js" for item in findings)


def test_parse_invalid_source_map_returns_errors() -> None:
    """Invalid source map JSON should return parse errors without raising."""
    parsed = parse_source_map("{not-json")
    assert parsed.errors
