"""Version extraction utilities for fingerprint detection."""

from __future__ import annotations

import logging
import re

from techspecter.fingerprints.models import UNKNOWN_VERSION, Fingerprint, VersionPattern

logger = logging.getLogger(__name__)


class VersionExtractor:
    """Extract technology version strings from JavaScript content."""

    def __init__(self) -> None:
        """Initialize an empty regex compilation cache."""
        self._cache: dict[tuple[str, str | None], re.Pattern[str]] = {}

    def extract(self, fingerprint: Fingerprint, content: str) -> str:
        """Extract a version string for the given fingerprint.

        Args:
            fingerprint: Technology fingerprint definition.
            content: JavaScript source text.

        Returns:
            Extracted version string, or ``Unknown`` when no version is found.
        """
        version, _ = self.extract_with_pattern(fingerprint, content)
        return version

    def extract_with_pattern(
        self,
        fingerprint: Fingerprint,
        content: str,
    ) -> tuple[str, VersionPattern | None]:
        """Extract a version string and the matching version pattern.

        Args:
            fingerprint: Technology fingerprint definition.
            content: JavaScript source text.

        Returns:
            Tuple of version string and matched version pattern, if any.
        """
        for version_pattern in fingerprint.version_patterns:
            version = self._extract_with_pattern(version_pattern, content)
            if version:
                logger.debug(
                    "Extracted version '%s' for technology '%s'",
                    version,
                    fingerprint.id,
                )
                return version, version_pattern
        return UNKNOWN_VERSION, None

    def _extract_with_pattern(self, version_pattern: VersionPattern, content: str) -> str | None:
        """Extract a version using a single version pattern.

        Args:
            version_pattern: Version extraction pattern.
            content: JavaScript source text.

        Returns:
            Extracted version string, or ``None`` when not found.
        """
        compiled = self._compile(version_pattern.pattern, version_pattern.flags)
        match = compiled.search(content)
        if match is None:
            return None

        if match.lastindex and match.lastindex >= 1:
            return match.group(1).strip()

        return match.group(0).strip()

    def _compile(self, expression: str, flags: str | None) -> re.Pattern[str]:
        """Compile and cache a version extraction regex.

        Args:
            expression: Regular expression source.
            flags: Optional flag string.

        Returns:
            Compiled regular expression.
        """
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
