"""React version extractor."""

from __future__ import annotations

import re

from techspecter.versioning.extractors.base import ExtractionPattern, PatternVersionExtractor
from techspecter.versioning.models import VersionEvidenceType


class ReactVersionExtractor(PatternVersionExtractor):
    """Extract React versions from JavaScript resources."""

    technology_id = "react"
    aliases = frozenset({"reactjs", "react-dom", "reactdom"})
    content_markers = frozenset(
        {
            "React",
            "react-dom",
            "reconcilerVersion",
            "__REACT_DEVTOOLS",
            "React.createElement",
            "react.dev/errors",
        },
    )
    patterns = (
        ExtractionPattern(
            re.compile(r'React\.version\s*=\s*["\']([\d.]+(?:[-+][\w.-]+)?)["\']'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "React.version runtime constant",
        ),
        ExtractionPattern(
            re.compile(r'reconcilerVersion\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"'),
            VersionEvidenceType.RUNTIME_CONSTANT,
            "React reconcilerVersion",
        ),
        ExtractionPattern(
            re.compile(
                r'version\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"[^}]*rendererPackageName\s*:\s*"react-dom"',
            ),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "React DevTools inject version",
        ),
        ExtractionPattern(
            re.compile(
                r'rendererPackageName\s*:\s*"react-dom"[^}]*version\s*:\s*"([\d.]+(?:[-+][\w.-]+)?)"'
            ),
            VersionEvidenceType.FRAMEWORK_OBJECT,
            "React DevTools renderer version",
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
