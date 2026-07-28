"""Source map JSON parser."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SourceMapParseResult:
    """Parsed source map content."""

    sources: tuple[str, ...] = field(default_factory=tuple)
    sources_content: tuple[str, ...] = field(default_factory=tuple)
    file: str | None = None
    version: int | None = None
    errors: tuple[str, ...] = field(default_factory=tuple)


def parse_source_map(content: str) -> SourceMapParseResult:
    """Parse a source map JSON document passively."""
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        logger.debug("Source map JSON parse failed: %s", exc)
        return SourceMapParseResult(errors=(str(exc),))

    if not isinstance(payload, dict):
        return SourceMapParseResult(errors=("Source map root is not an object",))

    sources_raw = payload.get("sources", [])
    sources = tuple(str(item) for item in sources_raw if isinstance(item, str))
    content_raw = payload.get("sourcesContent", [])
    sources_content = tuple(str(item) for item in content_raw if isinstance(item, str))
    file_value = payload.get("file")
    version_value = payload.get("version")
    version = int(version_value) if isinstance(version_value, int) else None
    file_name = str(file_value) if isinstance(file_value, str) else None
    return SourceMapParseResult(
        sources=sources,
        sources_content=sources_content,
        file=file_name,
        version=version,
    )
