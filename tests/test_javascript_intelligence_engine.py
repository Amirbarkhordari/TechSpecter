"""JavaScript intelligence engine unit tests."""

from __future__ import annotations

from techspecter.fingerprinting.javascript.engine import JavaScriptIntelligenceEngine
from techspecter.fingerprinting.javascript.normalizer import normalize_javascript


def test_normalize_detects_minified_single_line_bundle() -> None:
    """Normalizer should flag large single-line bundles as minified."""
    content = "x" * 600
    result = normalize_javascript(content)
    assert result.is_minified is True


def test_engine_extracts_react_runtime_patterns() -> None:
    """Engine should emit runtime pattern evidence for React APIs."""
    content = "ReactDOM.createRoot(document.getElementById('root')); useState(0);"
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    result = engine.analyze_resource(
        url="https://example.com/app.js",
        filename="app.js",
        content=content,
    )
    values = {item.matched_value for item in result.findings}
    assert "ReactDOM.createRoot" in values
    assert "useState" in values


def test_engine_extracts_version_candidates() -> None:
    """Engine should collect version candidates without choosing one."""
    content = "/* React v19.1.0 */ const v = '16.2.10';"
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    result = engine.analyze_resource(
        url="https://example.com/react.js",
        filename="react.js",
        content=content,
    )
    versions = {
        item.matched_value for item in result.findings if item.evidence_type == "version_candidate"
    }
    assert "19.1.0" in versions
    assert "16.2.10" in versions


def test_engine_extracts_webpack_runtime() -> None:
    """Engine should detect webpack bundle runtime markers."""
    content = "function __webpack_require__(id) { return modules[id]; }"
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    result = engine.analyze_resource(
        url="https://example.com/chunk.js",
        filename="app.chunk.js",
        content=content,
    )
    assert any(item.matched_value == "__webpack_require__" for item in result.findings)


def test_engine_handles_broken_javascript_gracefully() -> None:
    """Malformed JavaScript must not crash the engine."""
    content = "function {{{ broken"
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    result = engine.analyze_resource(
        url="https://example.com/broken.js",
        filename="broken.js",
        content=content,
    )
    assert result.resource.filename == "broken.js"


def test_engine_extracts_imports() -> None:
    """Engine should extract ES module import targets."""
    content = "import React from 'react';\nimport { createApp } from 'vue';"
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    result = engine.analyze_resource(
        url="https://example.com/module.js",
        filename="module.js",
        content=content,
    )
    imports = {
        item.matched_value
        for item in result.findings
        if item.category == "package" and item.metadata.get("kind") == "import"
    }
    assert "react" in imports
    assert "vue" in imports


def test_analyze_to_evidence_never_sets_technology() -> None:
    """Evidence items must remain technology-agnostic in Phase 2."""
    engine = JavaScriptIntelligenceEngine()
    engine.config.fetch_source_maps = False
    items = engine.analyze_to_evidence(
        url="https://example.com/app.js",
        filename="app.js",
        content="import x from 'react';",
    )
    assert items
    assert all(item.technology is None for item in items)
