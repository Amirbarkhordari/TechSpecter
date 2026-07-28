"""JavaScript content normalization."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_DEFAULT_MAX_BYTES = 5_242_880
_BANNER_BYTES = 4096
_MINIFIED_LINE_THRESHOLD = 500
_MINIFIED_AVG_LINE_LENGTH = 180


@dataclass(frozen=True, slots=True)
class NormalizedJavaScript:
    """Result of JavaScript normalization."""

    content: str
    original_length: int
    normalized_length: int
    is_minified: bool
    encoding_recovered: bool
    banner: str
    truncated: bool = False


def normalize_javascript(
    content: str | bytes,
    *,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> NormalizedJavaScript:
    """Normalize JavaScript content for passive analysis."""
    encoding_recovered = False
    if isinstance(content, bytes):
        text, encoding_recovered = _decode_bytes(content)
    else:
        text = content

    original_length = len(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    truncated = False
    if len(text.encode("utf-8")) > max_bytes:
        text = text[:max_bytes]
        truncated = True
        logger.debug("Truncated JavaScript content to %d bytes for analysis", max_bytes)

    banner = text[:_BANNER_BYTES]
    is_minified = _detect_minified(text)
    return NormalizedJavaScript(
        content=text,
        original_length=original_length,
        normalized_length=len(text),
        is_minified=is_minified,
        encoding_recovered=encoding_recovered,
        banner=banner,
        truncated=truncated,
    )


def _decode_bytes(content: bytes) -> tuple[str, bool]:
    """Decode bytes using UTF-8 with latin-1 fallback."""
    try:
        return content.decode("utf-8"), False
    except UnicodeDecodeError:
        logger.debug("Recovering JavaScript content using latin-1 fallback decoding")
        return content.decode("latin-1"), True


def _detect_minified(text: str) -> bool:
    """Detect likely minified JavaScript based on line structure."""
    lines = text.split("\n")
    if len(lines) <= 1:
        return len(text) > _MINIFIED_LINE_THRESHOLD
    if len(lines) > 50:
        return False
    avg_line = sum(len(line) for line in lines) / max(len(lines), 1)
    return avg_line >= _MINIFIED_AVG_LINE_LENGTH


_BANNER_COMMENT = re.compile(
    r"^\s*(?://[^\n]*|/\*[\s\S]*?\*/)",
    re.MULTILINE,
)


def extract_banner_comments(content: str, *, limit: int = _BANNER_BYTES) -> str:
    """Preserve leading banner comments from JavaScript content."""
    head = content[:limit]
    matches = _BANNER_COMMENT.findall(head)
    return "\n".join(match.strip() for match in matches)
