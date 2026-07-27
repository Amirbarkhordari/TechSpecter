"""Tests for duplicate removal utilities."""

from __future__ import annotations

from techspecter.models.discovery import ScriptResource
from techspecter.utils.dedup import deduplicate_scripts


def test_deduplicate_scripts_preserves_first_occurrence() -> None:
    """Verify duplicate script URLs are removed while preserving order."""
    scripts = [
        ScriptResource(url="https://example.com/a.js", original_url="/a.js"),  # type: ignore[arg-type]
        ScriptResource(url="https://example.com/a.js", original_url="a.js"),  # type: ignore[arg-type]
        ScriptResource(url="https://example.com/b.js", original_url="/b.js"),  # type: ignore[arg-type]
    ]

    result = deduplicate_scripts(scripts)

    assert len(result) == 2
    assert result[0].original_url == "/a.js"
    assert result[1].original_url == "/b.js"


def test_deduplicate_scripts_returns_empty_for_empty_input() -> None:
    """Verify deduplication of an empty list returns an empty list."""
    assert deduplicate_scripts([]) == []
