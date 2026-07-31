"""Material UI version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class MaterialUiVersionExtractor(PatternVersionExtractor):
    """Extract Material UI versions from JavaScript resources."""

    technology_id = "material-ui"
    aliases = frozenset({"mui", "materialui", "@mui/material"})
    patterns = (
        ExtractionPattern(
            re.compile(r"@mui/material@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "@mui/material package path",
        ),
        ExtractionPattern(
            re.compile(r"material-ui@([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.PACKAGE_IDENTIFIER,
            "material-ui package path",
        ),
        ExtractionPattern(
            re.compile(r"Material[- ]UI\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "Material UI banner",
        ),
        ExtractionPattern(
            re.compile(r"MUI\s+v?([\d.]+(?:[-+][\w.-]+)?)"),
            VersionEvidenceType.BANNER,
            "MUI banner",
        ),
    )
