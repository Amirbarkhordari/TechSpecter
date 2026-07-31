"""Bootstrap version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class BootstrapVersionExtractor(PatternVersionExtractor):
    """Extract Bootstrap versions from JavaScript resources."""

    technology_id = "bootstrap"
    content_markers = frozenset({"Bootstrap", "bootstrap@", "data-bs-", "bootstrap.min"})
    patterns = (
        ExtractionPattern(
            re.compile(r"Bootstrap\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Bootstrap banner",
        ),
        ExtractionPattern(
            re.compile(r"bootstrap@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "bootstrap package path",
        ),
        ExtractionPattern(
            re.compile(r'data-bs-version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.METADATA,
            "Bootstrap data-bs-version attribute",
        ),
    )
