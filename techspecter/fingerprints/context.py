"""Shared context passed to fingerprint pattern matchers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MatchContext:
    """JavaScript resource context used during fingerprint matching.

    Attributes:
        content: JavaScript source text.
        filename: Resource filename derived from the URL path.
        url: Absolute resource URL.
        source_map_url: Detected source map reference, if any.
    """

    content: str
    filename: str
    url: str
    source_map_url: str | None = None
