"""Source map reference detection utilities."""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urljoin

SOURCE_MAP_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"sourceMappingURL=([^\s\"']+)",
)


def detect_source_map_url(content: str, *, base_url: str | None = None) -> str | None:
    """Detect a ``sourceMappingURL`` reference in JavaScript content.

    Only the reference is extracted; source maps are not downloaded.

    Args:
        content: JavaScript source text.
        base_url: Optional base URL used to resolve relative source map paths.

    Returns:
        Detected source map URL, or ``None`` when not present.
    """
    match = SOURCE_MAP_PATTERN.search(content)
    if match is None:
        return None

    reference = match.group(1).strip().rstrip("*/;,")
    if not reference:
        return None

    if base_url and not reference.startswith(("http://", "https://", "data:")):
        return urljoin(base_url, reference)

    return reference
