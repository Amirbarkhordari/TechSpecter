"""Vue version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class VueVersionExtractor(PatternVersionExtractor):
    """Extract Vue.js versions from JavaScript resources."""

    technology_id = "vue"
    aliases = frozenset({"vuejs", "vue.js"})
    patterns = (
        ExtractionPattern(
            re.compile(r'Vue\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "Vue.version runtime constant",
        ),
        ExtractionPattern(
            re.compile(r"vue@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "vue package path",
        ),
        ExtractionPattern(
            re.compile(r"Vue\.js\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Vue.js banner",
        ),
        ExtractionPattern(
            re.compile(r'__VUE__[^"\']*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "Vue framework marker",
        ),
    )
