"""Source map reference detection utilities."""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urljoin

from techspecter.utils.url import normalize_url

# Matches //#, //@, and block-comment sourceMappingURL directives.
SOURCE_MAP_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"sourceMappingURL=([^\s\"']+)",
)


def detect_source_map_url(content: str, *, base_url: str | None = None) -> str | None:
    """Detect a ``sourceMappingURL`` reference in JavaScript content.

    Supports line comments (``//#`` and ``//@``) and block comments. Only the
    reference is extracted; source maps are not downloaded. When ``base_url`` is
    provided, relative references are resolved to absolute URLs.

    Args:
        content: JavaScript source text.
        base_url: Optional base URL used to resolve relative source map paths.

    Returns:
        Detected source map URL, or ``None`` when not present.
    """
    matches = list(SOURCE_MAP_PATTERN.finditer(content))
    if not matches:
        return None

    reference = matches[-1].group(1).strip().rstrip("*/;,")
    if not reference:
        return None

    return _resolve_source_map_reference(reference, base_url)


def _resolve_source_map_reference(reference: str, base_url: str | None) -> str:
    """Resolve a raw source map reference to an absolute URL when possible.

    Args:
        reference: Source map reference extracted from JavaScript content.
        base_url: Optional base URL for resolving relative references.

    Returns:
        Resolved source map URL.
    """
    if reference.startswith("data:"):
        return reference

    if reference.startswith(("http://", "https://")):
        return normalize_url(reference)

    if base_url:
        return normalize_url(urljoin(base_url, reference))

    return reference
