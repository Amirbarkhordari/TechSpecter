"""Vite version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class ViteVersionExtractor(PatternVersionExtractor):
    """Extract Vite versions from JavaScript resources."""

    technology_id = "vite"
    content_markers = frozenset({"vite", "__vite__"})
    patterns = (
        ExtractionPattern(
            re.compile(r"vite[/\s@]+([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Vite banner",
        ),
        ExtractionPattern(
            re.compile(r"vite@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "vite package path",
        ),
        ExtractionPattern(
            re.compile(r'__vite__[^"\']*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "Vite runtime marker",
        ),
    )
