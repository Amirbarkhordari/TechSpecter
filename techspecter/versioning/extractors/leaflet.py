"""Leaflet version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class LeafletVersionExtractor(PatternVersionExtractor):
    """Extract Leaflet versions from JavaScript resources."""

    technology_id = "leaflet"
    patterns = (
        ExtractionPattern(
            re.compile(r'Leaflet\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "Leaflet.version runtime constant",
        ),
        ExtractionPattern(
            re.compile(r"leaflet@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "leaflet package path",
        ),
        ExtractionPattern(
            re.compile(r"Leaflet\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Leaflet banner",
        ),
    )
