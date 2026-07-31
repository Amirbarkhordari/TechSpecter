"""Content hashing utilities for asset inventory."""

from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    """Return the SHA256 hex digest of binary content."""
    return hashlib.sha256(data).hexdigest()


def asset_id_from_url(url: str) -> str:
    """Derive a stable asset identifier from a normalized URL."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
