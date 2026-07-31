"""Angular version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class AngularVersionExtractor(PatternVersionExtractor):
    """Extract Angular versions from JavaScript resources."""

    technology_id = "angular"
    aliases = frozenset({"angularjs", "@angular/core"})
    patterns = (
        ExtractionPattern(
            re.compile(r'ng\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "ng.version runtime constant",
        ),
        ExtractionPattern(
            re.compile(r"@angular/core@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "@angular/core package path",
        ),
        ExtractionPattern(
            re.compile(r"Angular\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Angular banner",
        ),
        ExtractionPattern(
            re.compile(r'VERSION\s*:\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.BUILD_METADATA,
            "Angular VERSION constant",
        ),
    )
