"""webpack version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class WebpackVersionExtractor(PatternVersionExtractor):
    """Extract webpack versions from JavaScript resources."""

    technology_id = "webpack"
    patterns = (
        ExtractionPattern(
            re.compile(r"webpack[/\s]+([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "webpack banner",
        ),
        ExtractionPattern(
            re.compile(r"webpack@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "webpack package path",
        ),
        ExtractionPattern(
            re.compile(r"__webpack_require__\.p\s*\+\s*['\"][^'\"]*webpack[^'\"]*([\d.]+)"),
            VersionEvidenceType.BUILD_METADATA,
            "webpack runtime path",
        ),
    )
