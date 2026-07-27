"""Tests for the fingerprint matching engine."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.engine import FingerprintEngine
from techspecter.fingerprints.loader import SignatureLoader


def test_fingerprint_engine_detects_react() -> None:
    """Verify the engine detects React in JavaScript content."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content='React.version="18.2.0"; function App() { return React.createElement("div"); }',
        filename="react.production.min.js",
        url="https://example.com/react.production.min.js",
    )
    matches = engine.detect(context)
    react = next((item for item in matches if item.technology.id == "react"), None)
    assert react is not None
    assert react.version == "18.2.0"
    assert react.confidence > 0


def test_fingerprint_engine_detects_multiple_technologies() -> None:
    """Verify multiple technologies can be detected in one script."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content="window.__NUXT__ = {}; __webpack_require__(1);",
        filename="bundle.js",
        url="https://example.com/_nuxt/bundle.js",
    )
    matches = engine.detect(context)
    ids = {item.technology.id for item in matches}
    assert "nuxt" in ids or "webpack" in ids


def test_fingerprint_engine_returns_empty_for_unknown_content() -> None:
    """Verify unknown JavaScript returns no technology matches."""
    engine = FingerprintEngine(SignatureLoader().load_all())
    context = MatchContext(
        content="console.log('hello world');",
        filename="custom.js",
        url="https://example.com/custom.js",
    )
    assert engine.detect(context) == []
