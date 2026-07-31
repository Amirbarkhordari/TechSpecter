"""React version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class ReactVersionExtractor(PatternVersionExtractor):
    """Extract React versions from JavaScript resources."""

    technology_id = "react"
    aliases = frozenset({"reactjs", "react-dom"})
    patterns = (
        ExtractionPattern(
            re.compile(r'React\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "React.version runtime constant",
        ),
        ExtractionPattern(
            re.compile(r"react(?:-dom)?@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "react package path",
        ),
        ExtractionPattern(
            re.compile(r"React\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "React banner comment",
        ),
        ExtractionPattern(
            re.compile(r'__VERSION__\s*:\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.BUILD_METADATA,
            "React build __VERSION__",
        ),
    )
