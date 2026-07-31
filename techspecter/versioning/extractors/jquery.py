"""jQuery version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class JQueryVersionExtractor(PatternVersionExtractor):
    """Extract jQuery versions from JavaScript resources."""

    technology_id = "jquery"
    patterns = (
        ExtractionPattern(
            re.compile(r'jQuery\.fn\.jquery\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "jQuery.fn.jquery runtime constant",
        ),
        ExtractionPattern(
            re.compile(r"jquery@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "jquery package path",
        ),
        ExtractionPattern(
            re.compile(r"jQuery\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "jQuery banner",
        ),
        ExtractionPattern(
            re.compile(r'\$\s*\.\s*fn\s*\.\s*jquery\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "jQuery alias assignment",
        ),
    )
