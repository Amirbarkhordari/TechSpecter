"""Comment and debug marker detector."""

from __future__ import annotations

import re

from techspecter.sensitive_intelligence.detectors.base import BaseSensitiveDetector, DetectorMatch
from techspecter.sensitive_intelligence.models import FindingType, SeverityLevel

_COMMENT_PATTERNS: tuple[tuple[str, re.Pattern[str], float, SeverityLevel], ...] = (
    (
        "todo-comment",
        re.compile(r"(?://|#|/\*|\<!--)\s*TODO\b[^\n\r]*", re.I),
        70.0,
        SeverityLevel.LOW,
    ),
    (
        "fixme-comment",
        re.compile(r"(?://|#|/\*|\<!--)\s*FIXME\b[^\n\r]*", re.I),
        75.0,
        SeverityLevel.LOW,
    ),
    (
        "hack-comment",
        re.compile(r"(?://|#|/\*|\<!--)\s*HACK\b[^\n\r]*", re.I),
        78.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "bug-comment",
        re.compile(r"(?://|#|/\*|\<!--)\s*BUG\b[^\n\r]*", re.I),
        72.0,
        SeverityLevel.LOW,
    ),
    (
        "note-comment",
        re.compile(r"(?://|#|/\*|\<!--)\s*NOTE\b[^\n\r]*", re.I),
        65.0,
        SeverityLevel.LOW,
    ),
    (
        "deprecated-marker",
        re.compile(r"\b@deprecated\b|\bDEPRECATED\b", re.I),
        80.0,
        SeverityLevel.MEDIUM,
    ),
    (
        "debug-marker",
        re.compile(r"\b(?:DEBUG|console\.debug|__DEBUG__)\b"),
        76.0,
        SeverityLevel.MEDIUM,
    ),
)


class CommentDetector(BaseSensitiveDetector):
    """Detect TODO/FIXME/HACK and debug markers."""

    detector_id = "comment-detector"
    finding_type = FindingType.COMMENT

    def detect(self, content: str) -> list[DetectorMatch]:
        """Find developer comments and markers."""
        return self._scan_patterns(content, _COMMENT_PATTERNS)
