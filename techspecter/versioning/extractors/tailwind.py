"""Tailwind CSS version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class TailwindVersionExtractor(PatternVersionExtractor):
    """Extract Tailwind CSS versions from JavaScript resources."""

    technology_id = "tailwindcss"
    aliases = frozenset({"tailwind", "tailwind-css"})
    content_markers = frozenset({"tailwindcss", "Tailwind CSS"})
    patterns = (
        ExtractionPattern(
            re.compile(r"tailwindcss@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "tailwindcss package path",
        ),
        ExtractionPattern(
            re.compile(r"Tailwind\s+CSS\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Tailwind CSS banner",
        ),
        ExtractionPattern(
            re.compile(r"tailwindcss[/\s@]+([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BUILD_METADATA,
            "Tailwind build metadata",
        ),
    )
