"""Tests for fingerprint pattern matchers."""

from __future__ import annotations

from techspecter.fingerprints.context import MatchContext
from techspecter.fingerprints.matchers.filename import FilenameMatcher
from techspecter.fingerprints.matchers.global_var import GlobalVariableMatcher
from techspecter.fingerprints.matchers.regex import RegexMatcher
from techspecter.fingerprints.matchers.sourcemap import SourceMapMatcher
from techspecter.fingerprints.matchers.string import StringMatcher
from techspecter.fingerprints.models import Pattern


def _context(**overrides: object) -> MatchContext:
    """Build a default match context."""
    values = {
        "content": "",
        "filename": "app.js",
        "url": "https://example.com/app.js",
        "source_map_url": None,
    }
    values.update(overrides)
    return MatchContext(**values)  # type: ignore[arg-type]


def test_string_matcher_finds_literal() -> None:
    """Verify string matcher detects literal substrings."""
    matcher = StringMatcher()
    pattern = Pattern(matcher="string", pattern="React.createElement")
    context = _context(content="var x = React.createElement('div');")
    assert matcher.matches(pattern, context) is True


def test_regex_matcher_compiles_once() -> None:
    """Verify regex matcher caches compiled expressions."""
    matcher = RegexMatcher()
    pattern = Pattern(matcher="regex", pattern="__webpack_require__")
    context = _context(content="function __webpack_require__(id) {}")
    assert matcher.matches(pattern, context) is True
    assert ("__webpack_require__", None) in matcher._cache


def test_filename_matcher_is_case_insensitive() -> None:
    """Verify filename matcher ignores case."""
    matcher = FilenameMatcher()
    pattern = Pattern(matcher="filename", pattern="JQUERY")
    context = _context(filename="jquery.min.js")
    assert matcher.matches(pattern, context) is True


def test_sourcemap_matcher_requires_source_map_url() -> None:
    """Verify source map matcher requires a detected source map URL."""
    matcher = SourceMapMatcher()
    pattern = Pattern(matcher="sourcemap", pattern=".map")
    assert matcher.matches(pattern, _context(source_map_url=None)) is False
    source_map_url = "https://example.com/app.js.map"
    assert matcher.matches(pattern, _context(source_map_url=source_map_url)) is True


def test_global_variable_matcher_detects_window_reference() -> None:
    """Verify global matcher detects window-scoped globals."""
    matcher = GlobalVariableMatcher()
    pattern = Pattern(matcher="global", pattern="React")
    context = _context(content="window.React = {};")
    assert matcher.matches(pattern, context) is True
