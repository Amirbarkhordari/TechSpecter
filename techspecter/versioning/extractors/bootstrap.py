"""Bootstrap version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class BootstrapVersionExtractor(PatternVersionExtractor):
    """Extract Bootstrap versions from JavaScript resources."""

    technology_id = "bootstrap"
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
            re.compile(r'version\s*:\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\'][^"\']*bootstrap'),
            VersionEvidenceType.METADATA,
            "Bootstrap metadata version",
        ),
    )
