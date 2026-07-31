"""Semantic version validation and normalization."""

from __future__ import annotations

import re

_SEMVER_RE = re.compile(
    r"^(\d{1,4})(?:\.(\d{1,4}))?(?:\.(\d{1,4}))?(?:-([\w.-]+))?(?:\+([\w.-]+))?$",
)
_VERSION_PREFIX_RE = re.compile(r"^[vV]")


def normalize_version(raw: str) -> str:
    """Normalize a raw version string."""
    cleaned = raw.strip().strip("\"'")
    cleaned = _VERSION_PREFIX_RE.sub("", cleaned)
    return cleaned.strip()


def is_valid_version(value: str) -> bool:
    """Return whether a string is a valid semver-like version."""
    normalized = normalize_version(value)
    if not normalized:
        return False
    match = _SEMVER_RE.match(normalized)
    if match is None:
        return False
    major = match.group(1)
    minor = match.group(2)
    if major is None or not major.isdigit():
        return False
    # Require at least major.minor (x.y) per Phase 6 validation rules.
    return minor is not None and minor.isdigit()


def validate_and_normalize(raw: str) -> str | None:
    """Validate and normalize a version, returning None when invalid."""
    normalized = normalize_version(raw)
    if not is_valid_version(normalized):
        return None
    return normalized
