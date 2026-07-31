"""Next.js version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class NextJsVersionExtractor(PatternVersionExtractor):
    """Extract Next.js versions from JavaScript resources."""

    technology_id = "nextjs"
    aliases = frozenset({"next.js", "next"})
    content_markers = frozenset(
        {
            "next",
            "NEXT_",
            "nextVersion",
            "appDir",
            "appBootstrap",
        },
    )
    patterns = (
        ExtractionPattern(
            re.compile(r'window\.next=\{version:"([\d.]+(?:[-+][\w.-]+)?)"'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "window.next runtime version",
        ),
        ExtractionPattern(
            re.compile(
                r'window\.next\s*=\s*\{[^}]*version\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"',
            ),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "window.next object version",
        ),
        ExtractionPattern(
            re.compile(r'"nextVersion"\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"'),
            VersionEvidenceType.METADATA,
            "Next.js nextVersion manifest field",
        ),
        ExtractionPattern(
            re.compile(r"next@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "next package path",
        ),
        ExtractionPattern(
            re.compile(r"Next\.js\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Next.js banner",
        ),
        ExtractionPattern(
            re.compile(r'"version"\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"[^}]*"next"'),
            VersionEvidenceType.BUILD_METADATA,
            "Next.js build metadata",
        ),
    )
