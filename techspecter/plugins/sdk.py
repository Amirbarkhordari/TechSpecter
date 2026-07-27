"""Shared SDK helpers for plugin authors."""

from __future__ import annotations

import re
import sys
from collections.abc import Iterable

_VERSION_PART = re.compile(r"^[0-9]+")


def parse_version(version: str) -> tuple[int, ...]:
    """Parse a semantic version string into a comparable tuple."""
    parts: list[int] = []
    for segment in version.strip().split("."):
        match = _VERSION_PART.match(segment)
        parts.append(int(match.group(0)) if match else 0)
    return tuple(parts)


def normalize_platforms(platforms: Iterable[str]) -> list[str]:
    """Normalize platform names to supported identifiers."""
    normalized: list[str] = []
    for platform in platforms:
        value = platform.strip().lower()
        if value in {"windows", "linux", "macos", "any"}:
            normalized.append(value)
    return normalized or ["any"]


def current_python_version() -> str:
    """Return the active Python interpreter version as ``major.minor``."""
    info = sys.version_info
    return f"{info.major}.{info.minor}"


def is_python_version_compatible(minimum: str, current: str | None = None) -> bool:
    """Return whether the current Python version satisfies a minimum."""
    active = parse_version(current or current_python_version())
    required = parse_version(minimum)
    return active >= required
