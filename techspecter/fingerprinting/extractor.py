"""Version extraction utilities for fingerprint detection."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from techspecter.fingerprinting.context import MatchContext
from techspecter.fingerprinting.models import UNKNOWN_VERSION, Fingerprint, VersionPattern
from techspecter.versioning.validator import validate_and_normalize

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VersionCandidate:
    """A candidate version extracted from JavaScript context."""

    version: str
    pattern: VersionPattern
    confidence: float


class VersionExtractor:
    """Extract technology version strings from JavaScript content."""

    def __init__(self) -> None:
        """Initialize an empty regex compilation cache."""
        self._cache: dict[tuple[str, str | None], re.Pattern[str]] = {}

    def extract(self, fingerprint: Fingerprint, context: MatchContext | str) -> str:
        """Extract a version string for the given fingerprint.

        Args:
            fingerprint: Technology fingerprint definition.
            context: JavaScript resource context or raw content string.

        Returns:
            Extracted version string, or ``Unknown`` when no version is found.
        """
        resolved = _resolve_context(context)
        version, _ = self.extract_with_pattern(fingerprint, resolved)
        return version

    def extract_with_pattern(
        self,
        fingerprint: Fingerprint,
        context: MatchContext | str,
    ) -> tuple[str, VersionPattern | None]:
        """Extract the highest-confidence version and its matching pattern.

        Args:
            fingerprint: Technology fingerprint definition.
            context: JavaScript resource context or raw content string.

        Returns:
            Tuple of version string and matched version pattern, if any.
        """
        resolved = _resolve_context(context)
        candidates: list[VersionCandidate] = []
        for version_pattern in fingerprint.version_patterns:
            candidate = self._extract_candidate(version_pattern, resolved, fingerprint.id)
            if candidate is not None:
                candidates.append(candidate)

        if not candidates:
            return UNKNOWN_VERSION, None

        best = max(candidates, key=lambda item: (item.confidence, item.pattern.weight))
        validated = validate_and_normalize(best.version)
        if validated is None:
            return UNKNOWN_VERSION, None
        logger.debug(
            "Extracted version '%s' for technology '%s' (source=%s)",
            validated,
            fingerprint.id,
            best.pattern.source or "inline",
        )
        return validated, best.pattern

    def _extract_candidate(
        self,
        version_pattern: VersionPattern,
        context: MatchContext,
        fingerprint_id: str,
    ) -> VersionCandidate | None:
        """Extract a version candidate from the appropriate context source."""
        sources = self._sources_for_pattern(version_pattern, context)
        for source_name, haystack in sources:
            try:
                version = self._extract_with_pattern(version_pattern, haystack)
            except re.error as exc:
                logger.debug(
                    "Skipping invalid version pattern for '%s': %s",
                    fingerprint_id,
                    exc,
                )
                continue
            if not version:
                continue

            confidence = version_pattern.weight * _SOURCE_CONFIDENCE.get(source_name, 1.0)
            return VersionCandidate(
                version=version,
                pattern=version_pattern,
                confidence=confidence,
            )
        return None

    def _sources_for_pattern(
        self,
        version_pattern: VersionPattern,
        context: MatchContext,
    ) -> list[tuple[str, str]]:
        """Return ordered haystacks to search for a version pattern."""
        source = version_pattern.source
        content = context.content
        filename = context.filename
        url_path = urlparse(context.url).path
        source_map = context.source_map_url or ""

        if source == "global":
            return [("global", content)]
        if source == "metadata":
            return [("metadata", content), ("bundle", filename), ("bundle", url_path)]
        if source == "sourcemap":
            return [("sourcemap", source_map), ("sourcemap", content)]
        if source == "minified":
            return [("minified", content)]
        if source == "bundle":
            return [("bundle", filename), ("bundle", url_path), ("bundle", content)]
        return [("inline", content)]

    def _extract_with_pattern(self, version_pattern: VersionPattern, content: str) -> str | None:
        """Extract a version using a single version pattern."""
        if not content:
            return None

        compiled = self._compile(version_pattern.pattern, version_pattern.flags)
        match = compiled.search(content)
        if match is None:
            return None

        if match.lastindex and match.lastindex >= 1:
            return match.group(1).strip()

        return match.group(0).strip()

    def _compile(self, expression: str, flags: str | None) -> re.Pattern[str]:
        """Compile and cache a version extraction regex."""
        cache_key = (expression, flags)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        flag_value = 0
        if flags:
            for flag in flags:
                if flag == "i":
                    flag_value |= re.IGNORECASE
                elif flag == "m":
                    flag_value |= re.MULTILINE
                elif flag == "s":
                    flag_value |= re.DOTALL

        compiled = re.compile(expression, flag_value)
        self._cache[cache_key] = compiled
        return compiled


_SOURCE_CONFIDENCE: dict[str, float] = {
    "inline": 1.0,
    "global": 1.15,
    "metadata": 1.1,
    "sourcemap": 0.95,
    "minified": 0.9,
    "bundle": 0.85,
}


def _resolve_context(context: MatchContext | str) -> MatchContext:
    """Normalize a string or context object into ``MatchContext``."""
    if isinstance(context, MatchContext):
        return context
    return MatchContext(content=context, filename="", url="")
