"""Shared context passed to fingerprint pattern matchers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MatchContext:
    """JavaScript resource context used during fingerprint matching."""

    content: str
    filename: str
    url: str
    source_map_url: str | None = None
    asset_id: str | None = None
