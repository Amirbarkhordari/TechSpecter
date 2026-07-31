"""Turbopack version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class TurbopackVersionExtractor(PatternVersionExtractor):
    """Extract Turbopack versions from JavaScript resources."""

    technology_id = "turbopack"
    patterns = (
        ExtractionPattern(
            re.compile(r"turbopack[/\s@]+([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Turbopack banner",
        ),
        ExtractionPattern(
            re.compile(r"turbopack@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "turbopack package path",
        ),
        ExtractionPattern(
            re.compile(r'__turbopack__[^"\']*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "Turbopack runtime marker",
        ),
    )
