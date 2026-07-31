"""JavaScript normalization pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from techspecter.fingerprinting.javascript.normalizer import (
    NormalizedJavaScript,
    normalize_javascript,
)


@dataclass(frozen=True, slots=True)
class NormalizationResult:
    """Result of JavaScript normalization stage."""

    content: str
    is_minified: bool
    truncated: bool
    original_length: int
    normalized_length: int


class JavaScriptNormalizationPipeline:
    """Normalize JavaScript for passive analysis without changing semantics."""

    def __init__(self, *, max_bytes: int = 5_242_880) -> None:
        """Initialize normalization pipeline."""
        self._max_bytes = max_bytes

    def normalize(self, content: str | bytes) -> NormalizationResult:
        """Normalize JavaScript content."""
        normalized: NormalizedJavaScript = normalize_javascript(content, max_bytes=self._max_bytes)
        return NormalizationResult(
            content=normalized.content,
            is_minified=normalized.is_minified,
            truncated=normalized.truncated,
            original_length=normalized.original_length,
            normalized_length=normalized.normalized_length,
        )
